use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use log::{debug, info, warn};
use crate::communication_proxy::{CommunicationProxy, PeerIndex, WrappedPBFTEvent};
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;

use crate::service_state::{ServiceState, ServiceStateSummary, StateTransferRequest, StateTransferResponse};

// Aliasing away concrete types to make
// possible refactors easier
// Index of peer in total ordering
pub type ViewstampId = u64;
pub type SequenceNumber = u64;
pub type DigestResult = Vec<u8>;

// Trait allowing cryptographic hash to be computed
pub trait Digestible {
    fn digest(&self) -> DigestResult;
    fn matches(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

pub trait NoOp {
    // Returns element representing no operation
    fn noop() -> Self;
}

// Alias traits required of service operations being replicated
pub trait ServiceOperation:
Clone + Debug + Digestible + NoOp {}

impl<T> ServiceOperation for T
    where T: Clone + Debug + Digestible + NoOp {}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PrepTriple {
    pub sequence_number: SequenceNumber,
    pub digest: DigestResult,
    pub view: ViewstampId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestPayload<O>
    where O: ServiceOperation
{
    pub op: O,
    // TODO: Validate this field
    pub op_digest: DigestResult,
}

impl<O> RequestPayload<O>
    where O: ServiceOperation
{
    pub fn new(op: O) -> Self {
        let op_digest = op.digest();
        RequestPayload {
            op,
            op_digest,
        }
    }
}

pub struct Checkpoint<O>
    where O: ServiceOperation
{
    sequence_number: SequenceNumber,
    service_state: ServiceState<O>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckpointSummary {
    sequence_number: SequenceNumber,
    service_state_summary: ServiceStateSummary,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewChange {
    from: PeerIndex,
    view: ViewstampId,
    log_low_mark: SequenceNumber,
    checkpoints: Vec<CheckpointSummary>,
    // P and Q sets
    prepared: HashSet<PrepTriple>,
    preprepared: HashSet<PrepTriple>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewView<O>
    where O: ServiceOperation
{
    from: PeerIndex,
    view: ViewstampId,
    // We deviate from the PBFT paper by not using view-change acks to convince non-primaries
    // of the existence of view changes. Instead we use digital signatures to prove that a view
    // change was in fact sent.
    view_change_proofs: Vec<WrappedPBFTEvent<O>>,
    selected_checkpoint: CheckpointSummary,
    // This is a list of contiguous, selected messages immediately after the selected_log_low
    selected_messages: Vec<Option<PrepTriple>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PBFTEvent<O>
    where O: ServiceOperation
{
    Request(RequestPayload<O>),
    PrePrepare {
        from: PeerIndex,
        data: PrepTriple,
        // TODO: Validate this field
        request: RequestPayload<O>,
    },
    Prepare {
        from: PeerIndex,
        data: PrepTriple,
    },
    Commit {
        from: PeerIndex,
        data: PrepTriple,
    },
    Checkpoint {
        from: PeerIndex,
        data: CheckpointSummary,
    },
    ViewChange(ViewChange),
    NewView(NewView<O>),
    StateTransferRequest(StateTransferRequest),
    StateTransferResponse(StateTransferResponse<O>),
}

// Represents PBFT replica automata that replicates some service
pub struct PBFTState<O>
    where O: ServiceOperation
{
    // Proxy gives a logical view of all messages received abstracting details
    // of deserialization and validation. It exposes an interface to communicate with
    // peers.
    pub communication_proxy: CommunicationProxy<O>,
    num_participants: PeerIndex,
    my_index: PeerIndex,

    // Determines if replica is under normal operation (true)
    // or if replica is in the process of a view change (false)
    is_view_active: bool,
    // Current viewstamp number
    view: ViewstampId,

    // -------------------- NORMAL OPERATION FIELDS --------------------
    // Message log to keep track of PBFT protocol within some sequence number
    // window [h, h+L]
    message_log: Vec<PBFTEvent<O>>,
    sequence_number: SequenceNumber,
    last_executed: SequenceNumber,

    // The "service state" being replicated is the message log associated with
    // an atomic broadcast protocol, not user's actual service state. Implementing
    // atomic broadcast using PBFT abstracts away details of PBFT from user attempting
    // to replicate their service.
    current_state: ServiceState<O>,

    // Lets you derive the low and high water marks for log compression
    sequence_window_length: u64,

    // Keeps track of committed requests at a regular interval
    pending_committed: Vec<(O, SequenceNumber)>,
    checkpoints: Vec<Checkpoint<O>>,
    checkpoint_interval: u64,

    // Represents the P set in PBFT paper
    // H(n) = (n, d, v) iff the P set contains (n, d, v) where H models the hashmap as a function
    // If (n, d, v) is in P, then this replica has not prepared a message at sequence number n with view
    // strictly greater than v.
    prepared: HashMap<SequenceNumber, PrepTriple>,
    // Represents the Q set in PBFT paper
    // Model the hashmap as a function H: SequenceNumber -> DigestResult -> ViewstampId but
    // (H(n))(d) = v iff the Q set contains (n, d, v)
    // If (n, d, v) is in Q, then the message request characterized by (n, d) has not been
    // preprepared in any view strictly greater than v by this replica.
    preprepared: HashMap<SequenceNumber, HashMap<DigestResult, ViewstampId>>,

    // -------------------- VIEW CHANGE FIELDS --------------------
    view_change_log: Vec<WrappedPBFTEvent<O>>,
    new_view_log: HashMap<ViewstampId, NewView<O>>,
    requested_digests: HashMap<(SequenceNumber, ViewstampId), DigestResult>,

    // -------------------- STATE TRANSFER FIELDS --------------------
    // Lookup table mapping service state log length to a checkpoint sequence number
    // and digest of the service state up to the length
    known_service_state_digests: HashMap<usize, (SequenceNumber, DigestResult)>,
}

impl<O> PBFTState<O>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    pub fn new(
        communication_proxy: CommunicationProxy<O>,
        sequence_window_length: u64,
        checkpoint_interval: u64,
    ) -> PBFTState<O> {
        // Add +1 to include self
        let num_participants = (communication_proxy.num_peers() + 1) as PeerIndex;
        let my_index = communication_proxy.my_index();
        PBFTState {
            communication_proxy,
            my_index,
            num_participants,
            is_view_active: true,
            view: 0,
            message_log: Vec::new(),
            sequence_number: 0,
            last_executed: 0,
            current_state: Default::default(),
            sequence_window_length,
            checkpoints: vec![Checkpoint { // The initial state is stable
                sequence_number: 0,
                service_state: Default::default(),
            }],
            pending_committed: vec![],
            checkpoint_interval,
            prepared: Default::default(),
            preprepared: Default::default(),
            view_change_log: vec![],
            new_view_log: Default::default(),
            requested_digests: Default::default(),
            known_service_state_digests: Default::default(),
        }
    }

    pub fn is_view_active(&self) -> bool {
        self.is_view_active
    }
    pub fn view(&self) -> ViewstampId {
        self.view
    }
    pub fn message_log(&self) -> &Vec<PBFTEvent<O>> {
        &self.message_log
    }
    pub fn last_executed(&self) -> SequenceNumber {
        self.last_executed
    }
    pub fn current_state(&self) -> &ServiceState<O> {
        &self.current_state
    }

    pub async fn step(&mut self) {
        // TODO: Add rebroadcast logic to subvert byzantine peer. Wrapped event has proof that byzantine peer sent message.
        let wrapped_event = self.communication_proxy.recv_event().await;
        if wrapped_event.is_none() {
            info!("Failed to read an event from communication proxy.");
            return;
        }
        let wrapped_event = wrapped_event.unwrap();
        match wrapped_event.event {
            PBFTEvent::Request(payload) => {
                self.process_request(payload);
            }
            PBFTEvent::PrePrepare { from, data, request } => {
                self.process_preprepare(from, data, request);
            }
            PBFTEvent::Prepare { from, data } => {
                self.process_prepare(from, data);
            }
            PBFTEvent::Commit { from, data } => {
                self.process_commit(from, data);
            }
            PBFTEvent::Checkpoint { from, data } => {
                self.process_checkpoint(from, data);
            }
            PBFTEvent::ViewChange(_) => {
                self.process_view_change(wrapped_event);
            }
            PBFTEvent::NewView(data) => {
                self.process_new_view(data);
            }
            PBFTEvent::StateTransferRequest(req) => {
                self.process_state_transfer_request(req);
            }
            PBFTEvent::StateTransferResponse(res) => {
                self.process_state_transfer_response(res);
            }
        }
    }

    pub fn max_faults(&self) -> PeerIndex {
        // Compute biggest integer f such that: n >= 3f + 1
        // Integer division performs floor
        (self.num_participants - 1) / 3
    }

    pub fn quorum_size(&self) -> PeerIndex {
        let n = self.num_participants;
        let f = self.max_faults();
        let sum = n + f + 1;
        // Compute ceil(sum / 2)
        if sum % 2 == 0 {
            sum / 2
        } else {
            sum / 2 + 1
        }
    }

    pub fn weak_certificate_size(&self) -> PeerIndex {
        self.max_faults() + 1
    }

    fn primary(&self, view: ViewstampId) -> PeerIndex {
        let n = self.num_participants;
        (view % (n as ViewstampId)) as PeerIndex
    }

    fn is_primary(&self, participant_index: PeerIndex) -> bool {
        self.primary(self.view) == participant_index
    }

    pub fn log_low_mark(&self) -> SequenceNumber {
        self.checkpoints.iter().map(|c| {
            c.sequence_number
        }).min().unwrap_or(0)
    }

    // Checks that a sequence number does not extend beyond capacity to hold messages to be committed
    fn is_sequence_number_in_window(&self, sequence_number: SequenceNumber) -> bool {
        let h = self.log_low_mark();
        if h > sequence_number {
            return false; // Don't do subtraction overflow
        }
        let offset = sequence_number - h;

        0 < offset && offset <= self.sequence_window_length
    }

    fn check_preprepared(&mut self, data: &PrepTriple) -> bool {
        let is_preprepared_before = self.preprepared
            .get(&data.sequence_number)
            .map_or(false, |digest_map| {
                digest_map
                    .get(&data.digest)
                    .map_or(false, |v| *v == data.view)
            });
        if is_preprepared_before {
            return true;
        }

        let res = self.message_log.iter().any(|e| {
            if let PBFTEvent::PrePrepare { data: other_data, .. } = e {
                data.eq(other_data)
            } else {
                false
            }
        });

        if res {
            // Save this result to speed up future queries
            match self.preprepared.get_mut(&data.sequence_number) {
                None => {
                    let mut digest_map = HashMap::new();
                    digest_map.insert(data.digest.clone(), data.view);
                    self.preprepared.insert(data.sequence_number, digest_map);
                }
                Some(digest_map) => {
                    match digest_map.get(&data.digest) {
                        None => {
                            digest_map.insert(data.digest.clone(), data.view);
                        }
                        Some(other_view) => {
                            if data.view > *other_view {
                                digest_map.insert(data.digest.clone(), data.view);
                            } else {
                                // Validate that preprepared only holds the most recent preprepared message
                                // If the views are equal, then either the digests are equal or not.
                                // In the former case, we should have short circuited at the start.
                                // In the latter case, a safety violation occurred where two different
                                // messages have been preprepared in the same (sequence_number, view).
                                panic!("Preprepare safety violation has been detected.");
                            }
                        }
                    }
                }
            }
        }

        res
    }

    fn check_prepared(&mut self, data: &PrepTriple) -> bool {
        let is_prepared_before = self.prepared
            .get(&data.sequence_number)
            .map_or(false, |other_data| {
                (&data.digest, data.view) == (&other_data.digest, other_data.view)
            });
        if is_prepared_before {
            return true;
        }

        // Count the number peers we have heard execute a prepare
        let certificate_size = self.message_log.iter()
            .filter(|e| {
                if let PBFTEvent::Prepare { data: other_data, .. } = e {
                    data.eq(other_data)
                } else {
                    false
                }
            })
            .map(|e| {
                if let PBFTEvent::Prepare { from, .. } = e {
                    return *from;
                }
                panic!("Impossible case.")
            })
            .collect::<HashSet<PeerIndex>>()
            .len();

        // The replica that sent preprepare is guaranteed to not be in the certificate
        // by sending/receiving prepare precondition (which is why there is a -1).
        // Certificate proves a quorum of replicas have *preprepared* (either send a preprepare or prepare)
        // the message and it is now virtually impossible for two different messages to be prepared at the current
        // view/sequence_number pair.
        let res = self.check_preprepared(data) && certificate_size as PeerIndex >= self.quorum_size() - 1;
        if res {
            // Save this result to speed up future queries
            match self.prepared.get(&data.sequence_number) {
                None => {
                    self.prepared.insert(data.sequence_number, data.clone());
                }
                Some(other_data) => {
                    if data.view > other_data.view {
                        self.prepared.insert(data.sequence_number, data.clone());
                    } else {
                        // Validate that prepared only holds the most recent prepared message
                        // If the views are equal, then either the digests are equal or not.
                        // In the former case, we should have short circuited at the start.
                        // In the latter case, a safety violation occurred where two different
                        // messages have been prepared in the same (sequence_number, view).
                        panic!("Prepare safety violation has been detected. Old: {:?}, New: {:?}", other_data, data);
                    }
                }
            }
        }

        res
    }

    fn check_committed(&mut self, data: &PrepTriple) -> bool {
        // Count the number peers we have heard send a commit
        let certificate_size = self.message_log.iter()
            .filter(|e| {
                if let PBFTEvent::Commit { data: other_data, .. } = e {
                    data.eq(other_data)
                } else {
                    false
                }
            })
            .map(|e| {
                if let PBFTEvent::Commit { from, .. } = e {
                    return *from;
                }
                panic!("Impossible case.")
            })
            .collect::<HashSet<PeerIndex>>()
            .len();

        // Message has been prepared and quorum has sent commit. It is now impossible for a different message
        // to commit in any view at this sequence number!
        self.check_prepared(data) && certificate_size as PeerIndex >= self.quorum_size()
    }

    fn process_request(&mut self, payload: RequestPayload<O>) {
        // TODO: Add timeout logic to detect long waiting for request to get executed ... ensure last execution moves forward to prevent byzantine primary to make excessive gaps
        debug!("Peer {}: Received request: {:?}", self.my_index, payload);

        // As the primary, this replica is responsible for initiating a preprepare request
        if self.is_primary(self.my_index)
            && self.is_view_active
        {
            let proposed_sequence_number = self.sequence_number + 1;
            if !self.is_sequence_number_in_window(proposed_sequence_number) {
                debug!("Peer {}: Dropping the request, the message log is too full!", self.my_index);
                return;
            }

            let request_digest = payload.op_digest.clone();

            let data = PrepTriple {
                view: self.view,
                sequence_number: proposed_sequence_number,
                digest: request_digest,
            };
            let preprepare = PBFTEvent::PrePrepare {
                from: self.my_index,
                data: data.clone(),
                request: payload,
            };
            self.message_log.push(preprepare.clone());
            // Update bookkeeping
            let _ = self.check_preprepared(&data);
            // TODO: Keep broadcasting preprepare until view change or committed
            self.communication_proxy.broadcast(preprepare);

            self.sequence_number += 1;
        }
    }

    fn process_preprepare(&mut self, from: PeerIndex, data: PrepTriple, request: RequestPayload<O>) {
        // Validate event
        if data.view != self.view {
            // Ignore preprepare from different views
            return;
        }
        if !self.is_primary(from) {
            // Byzantine peer detected
            info!("Peer {}: Received invalid preprepare from peer {}, who is not the primary! 🚨", self.my_index, from);
            return;
        }

        let preprepare: PBFTEvent<O> = PBFTEvent::PrePrepare {
            from,
            data: data.clone(),
            request,
        };
        if !self.is_sequence_number_in_window(data.sequence_number) {
            debug!("Peer {}: Ignoring preprepare because log is currently too full. {:?}", self.my_index, preprepare);
            return;
        }
        if !self.is_view_active {
            debug!("Peer {}: Ignoring preprepare because view is currently not active. {:?}", self.my_index, preprepare);
            return;
        }
        if self.message_log.iter().any(|e| {
            if let PBFTEvent::PrePrepare { data: other_data, .. } = e {
                (data.view, data.sequence_number) == (other_data.view, other_data.sequence_number)
            } else {
                false
            }
        }) {
            debug!("Peer {}: Ignoring this preprepare because there is already a preprepare for view={}, sequence_number={}", self.my_index, data.view, data.sequence_number);
            return;
        }

        // All preconditions passed, record this preprepare which also contains a request
        debug!("Peer {}: Got preprepare: {:?}", self.my_index, preprepare);
        self.message_log.push(preprepare);

        // Attempt to send a prepare if possible
        if !self.is_primary(self.my_index) {
            let prepare = PBFTEvent::Prepare {
                from: self.my_index,
                data: data.clone(),
            };
            self.message_log.push(prepare.clone());
            self.communication_proxy.broadcast(prepare);
        }

        // Introduction of this preprepare and prepare may be enough to achieve quorum
        //
        // This call also updates book keeping for the P and Q sets by calling
        // check_prepared() who then calls check_preprepared().
        self.attempt_commit_send(&data);
    }

    fn process_prepare(&mut self, from: PeerIndex, data: PrepTriple) {
        if data.view != self.view {
            debug!("Peer {}: Ignoring prepare from a different view. {:?}", self.my_index, data);
            return;
        }
        if self.is_primary(from) {
            info!("Peer {}: Received invalid prepare from primary. {:?} 🚨", self.my_index, data);
            return;
        }
        if !self.is_sequence_number_in_window(data.sequence_number) {
            debug!("Peer {}: Ignoring prepare because message log is too full. {:?}", self.my_index, data);
            return;
        }
        // Preconditions are satisfied
        let prepare = PBFTEvent::Prepare {
            from,
            data: data.clone(),
        };
        debug!("Peer {}: Received prepare. {:?}", self.my_index, prepare);
        self.message_log.push(prepare);

        // Introduction of this prepare may be enough to achieve quorum
        //
        // This call also updates book keeping for the P and Q sets by calling
        // check_prepared() who then calls check_preprepared().
        self.attempt_commit_send(&data);
    }

    fn attempt_commit_send(&mut self, data: &PrepTriple) {
        let has_committed_before = self.message_log.iter().any(|e| {
            if let PBFTEvent::Commit { from, data: other_data } = e {
                (self.my_index, data.view, data.sequence_number) == (*from, other_data.view, other_data.sequence_number)
            } else {
                false
            }
        });

        if has_committed_before {
            // debug!("Peer {}: Attempted to send commit, but will not commit again. {:?}", self.my_index, data);
            return;
        }

        if !self.check_prepared(data) {
            // debug!("Peer {}: Attempted to send commit, but quorum has not been achieved. {:?}", self.my_index, data);
            return;
        }

        // All preconditions passed
        debug!("Peer {}: Sending commit for {:?}", self.my_index, data);
        let commit = PBFTEvent::Commit {
            from: self.my_index,
            data: data.clone(),
        };
        self.message_log.push(commit.clone());
        self.communication_proxy.broadcast(commit);

        // Introduction of commit may be enough to achieve commit quorum
        self.attempt_execute(data);
    }

    fn process_commit(&mut self, from: PeerIndex, data: PrepTriple) {
        if self.view != data.view {
            // Ignore commit not in current view
            return;
        }
        if !self.is_sequence_number_in_window(data.sequence_number) {
            debug!("Peer {}: Ignoring prepare because message log is too full. {:?}", self.my_index, data);
            return;
        }
        // Preconditions passed
        let commit = PBFTEvent::Commit {
            from,
            data: data.clone(),
        };
        self.message_log.push(commit);

        // Introduction of commit may be enough to achieve commit quorum
        self.attempt_execute(&data);
    }

    fn attempt_execute(&mut self, data: &PrepTriple) {
        if data.sequence_number <= self.last_executed {
            // Don't attempt to execute something already executed
            return;
        }
        if !self.check_committed(data) {
            // debug!("Peer {}: Attempted to perform execution but data has not been committed. {:?}", self.my_index, data);
            return;
        }

        let associated_preprepare = self.message_log.iter().find(|e| {
            if let PBFTEvent::PrePrepare { data: other_data, .. } = e {
                data.eq(other_data)
            } else {
                false
            }
        });
        if let Some(PBFTEvent::PrePrepare { request, .. }) = associated_preprepare {
            self.pending_committed.push((request.op.clone(), data.sequence_number));
        }

        self.attempt_execute_pending_commits();
    }

    fn attempt_execute_pending_commits(&mut self) {
        // Order all committed operation is descending sequence number order
        self.pending_committed.sort_by_key(|(_o, n)| *n);
        self.pending_committed.reverse();

        while let Some((o, n)) = self.pending_committed.pop() {
            // Do -1 check to prevent (unlikely) overflow
            if self.last_executed == n - 1 {
                // We have a pending operation that one ahead the last executed operation
                self.current_state.broadcast_finality(o);
                self.last_executed += 1;
                info!("Peer {}: Executed operation {}! 🎉", self.my_index, n);

                self.create_checkpoint();
                // TODO: Generate high-level signal on execution
                // TODO: Persist execution
            } else if n <= self.last_executed {
                // Supposedly pending committed message has already been executed. Drop the message
                continue;
            } else {
                // No progress can be made so break out of the loop and push back popped item.
                self.pending_committed.push((o, n));
                break;
            }
        }
        debug!("Peer {}: Pending commits {:?}.", self.my_index, self.pending_committed);
    }

    fn create_checkpoint(&mut self) {
        // Only create checkpoints at certain intervals
        if self.last_executed % self.checkpoint_interval != 0 {
            return;
        }

        let current_state_summary = self.current_state.summarize();
        let data = CheckpointSummary {
            sequence_number: self.last_executed,
            service_state_summary: current_state_summary,
        };
        let checkpoint_event = PBFTEvent::Checkpoint {
            from: self.my_index,
            data: data.clone()
        };
        self.message_log.push(checkpoint_event.clone());
        self.communication_proxy.broadcast(checkpoint_event);
        debug!("Peer {}: Created checkpoint at {}.", self.my_index, self.last_executed);

        // TODO: Revisit this and make more space efficient
        self.checkpoints.push(Checkpoint {
            sequence_number: self.last_executed,
            service_state: self.current_state.clone(),
        });

        self.collect_garbage(&data);
    }

    fn process_checkpoint(&mut self, from: PeerIndex, data: CheckpointSummary) {
        if !self.is_sequence_number_in_window(data.sequence_number) {
            debug!("Peer {}: Ignoring checkpoint at {} because message log is too full.", self.my_index, data.sequence_number);
        }

        self.message_log.push(PBFTEvent::Checkpoint {
            from,
            data: CheckpointSummary {
                sequence_number: data.sequence_number,
                service_state_summary: data.service_state_summary.clone(),
            },
        });
        debug!("Peer {}: Received checkpoint at {}.", self.my_index, self.last_executed);
        self.collect_garbage(&data);
    }

    fn collect_garbage(&mut self, checkpoint_summary: &CheckpointSummary) {
        let checkpoint_sequence_number = checkpoint_summary.sequence_number;
        let service_state_digest = &checkpoint_summary.service_state_summary.log_digest;
        let certificate_size = self.message_log.iter()
            .filter(|e| {
                if let PBFTEvent::Checkpoint { data, .. } = e {
                    (&checkpoint_sequence_number, service_state_digest) == (&data.sequence_number, &data.service_state_summary.log_digest)
                } else {
                    false
                }
            })
            .map(|e| {
                if let PBFTEvent::Checkpoint { from, .. } = e {
                    return *from;
                }
                panic!("Impossible case.")
            })
            .collect::<HashSet<PeerIndex>>()
            .len();

        if (certificate_size as PeerIndex) < self.quorum_size() {
            // debug!("Peer {}: Cannot collect garbage because quorum has not been reached on checkpoint {}", self.my_index, checkpoint_sequence_number);
            return;
        }
        // TODO: Checkpoint has been stabilized. Record it.

        // Attempt to synchronize up to the stabilized checkpoint
        if checkpoint_sequence_number > self.last_executed {
            self.synchronize_up_to_checkpoint(checkpoint_summary);
        }

        self.checkpoints.retain(|c| c.sequence_number >= checkpoint_sequence_number);
        self.message_log
            .retain(|e| {
                match e {
                    // Normal operations
                    PBFTEvent::Request(_) => { panic!("Request should not be in message log!") }
                    PBFTEvent::PrePrepare { data, .. } => { data.sequence_number > checkpoint_sequence_number }
                    PBFTEvent::Prepare { data, .. } => { data.sequence_number > checkpoint_sequence_number }
                    PBFTEvent::Commit { data, .. } => { data.sequence_number > checkpoint_sequence_number }
                    PBFTEvent::Checkpoint { data, .. } => { data.sequence_number > checkpoint_sequence_number }
                    // View change
                    PBFTEvent::ViewChange(_) => { panic!("ViewChange should not be in the message log!") }
                    PBFTEvent::NewView(_) => { panic!("NewView should not be in the message log!") }
                    // State transfer
                    PBFTEvent::StateTransferRequest(_) => { panic!("State transfer request should not be in the message log!") }
                    PBFTEvent::StateTransferResponse(_) => { panic!("State transfer response should not be in the message log!") }
                }
            });
        self.prepared.retain(|n, _| *n > checkpoint_sequence_number);
        self.preprepared.retain(|n, _| *n > checkpoint_sequence_number);

        let log_length = self.current_state().log().len();
        self.known_service_state_digests.retain(|l, _| *l > log_length);
        self.requested_digests.retain(|(n, _), _| *n >= checkpoint_sequence_number);

        debug!("Peer {}: Collected garbage before checkpoint {}.", self.my_index, checkpoint_sequence_number);

        // TODO: Clean up state transfer book keeping
    }

    pub fn change_view(&mut self, jump_size: ViewstampId) {
        if jump_size == 0 {
            // View changes should be strictly increasing and doing a jump size of 0
            // would negatively impact liveliness.
            warn!("Ignoring view change with jump size 0!");
            return;
        }

        let new_view = self.view + jump_size;
        debug!("Peer {}: Starting a view change: view {} -> {}.", self.my_index, self.view, new_view);
        self.is_view_active = false;
        self.view = new_view;

        let checkpoints = self.checkpoints.iter()
            .map(|c| {
                CheckpointSummary {
                    sequence_number: c.sequence_number,
                    service_state_summary: c.service_state.summarize(),
                }
            })
            .collect();

        // Assemble the prepared and preprepared indices into a set of tuples for packaging on the network
        let prepared = self.prepared.values().cloned().collect();
        let preprepared = self.preprepared.iter()
            .flat_map(|(n, digest_map)| {
                digest_map.iter().map(|(d, v)| {
                    PrepTriple {
                        sequence_number: *n,
                        digest: d.clone(),
                        view: *v
                    }
                })
            })
            .collect();
        let view_change = PBFTEvent::ViewChange(ViewChange {
            from: self.my_index,
            view: new_view,
            log_low_mark: self.log_low_mark(),
            checkpoints,
            prepared,
            preprepared
        });

        self.process_view_change(self.communication_proxy.wrap(&view_change));

        // TODO: Broadcast view change periodically
        self.communication_proxy.broadcast(view_change);

        debug!("Peer {}: Engaging in a view change into view {}.", self.my_index, new_view);

        // Purge old view data
        self.view_change_log.retain(|e| {
            if let PBFTEvent::ViewChange(data) = &e.event {
                data.view >= self.view
            } else {
                false
            }
        });
        self.new_view_log.retain(|v, _| {
            *v >= self.view
        });
        self.requested_digests = Default::default();

        self.attempt_view_change();
    }

    fn process_view_change(&mut self, view_change: WrappedPBFTEvent<O>) {
        let data = match &view_change.event {
            PBFTEvent::ViewChange(data) => { data }
            _ => {
                warn!("Attempted to process a wrapped event that is not a view change!");
                return;
            }
        };

        if self.primary(data.view) != self.my_index {
            // TODO: Activate timeout after hearing a quorum of view changes in the same current view
            // TODO: Perform a view change when a weak certificate has been made for a strictly higher view
            debug!("Peer {}: Dropping view change as not primary.", self.my_index);
            return;
        }

        if self.view() > data.view {
            debug!("Peer {}: Dropping view change as currently in higher view.", self.my_index);
            return;
        }

        if self.view_change_log.iter().map(convert_to_view_change).any(|change| {
            (change.from, change.view) == (data.from, data.view)
        }) {
            debug!("Peer {}: Dropping view change as already received from change from peer.", self.my_index);
            return;
        }

        // Check that the data in view change is correct
        if !data.prepared.iter().all(|prep| {
            let (n, v) = (prep.sequence_number, prep.view);
            v < data.view
                && data.log_low_mark < n
                && n <= data.log_low_mark + self.sequence_window_length
        }) {
            debug!("Peer {}: Received view change from peer {} with malformed prepared field!", self.my_index, data.from);
            return;
        }
        if !data.preprepared.iter().all(|prep| {
            let (n, v) = (prep.sequence_number, prep.view);
            v < data.view
                && data.log_low_mark < n
                && n <= data.log_low_mark + self.sequence_window_length
        }) {
            debug!("Peer {}: Received view change from peer {} with malformed preprepared field!", self.my_index, data.from);
            return;
        }


        // All preconditions passed
        self.view_change_log.push(view_change);
        self.attempt_new_view();
    }

    fn attempt_new_view(&mut self) {
        // Find all view changes relevant to the current view that this replica is a primary of so
        // that this replica can broadcast a new view change
        let view_changes_iter = self.view_change_log.iter()
            .map(convert_to_view_change)
            .filter(|change| change.view == self.view);

        // Compute the selected checkpoint
        let selected_checkpoint = view_changes_iter.clone()
            .flat_map(|change| change.checkpoints.iter())
            .filter(|candidate| self.is_valid_selected_checkpoint(view_changes_iter.clone(), *candidate))
            .max_by_key(|checkpoint_digest| checkpoint_digest.sequence_number);

        if selected_checkpoint.is_none() {
            // It is not possible to create a new view
            return;
        }

        let selected_checkpoint = selected_checkpoint.unwrap().clone();
        let selected_log_low = selected_checkpoint.sequence_number;

        // Select requests for the new view
        let mut selected_messages = vec![];
        for n in selected_log_low + 1..=selected_log_low + self.sequence_window_length {
            // Attempt to select any previously committed message at sequence number n
            // Look at all prepared messages at the sequence number n
            let committed_msg = view_changes_iter.clone()
                .flat_map(|change| {
                    // Get all prepared messages with sequence number at the target n
                    change.prepared.iter()
                        .filter(|prep| prep.sequence_number == n)
                })
                .find(|candidate| {
                    self.is_justified_by_a1(view_changes_iter.clone(), candidate)
                        && self.is_justified_by_a2(view_changes_iter.clone(), candidate)
                });
            // We were able to select a message!
            if let Some(prep) = committed_msg {
                selected_messages.push(Some(prep.clone()));
                continue;
            }

            if self.is_condition_b_viable(view_changes_iter.clone(), n) {
                // Condition B holds so add a no-op operation
                selected_messages.push(None);
            } else {
                // No message can be selected
                return;
            }
        }

        // View change is possible
        let view_change_proofs = self.view_change_log.iter()
            .filter(|e| {
                let data = convert_to_view_change(e);
                data.view == self.view
            })
            .cloned()
            .collect();
        let new_view = NewView {
            from: self.my_index,
            view: self.view,
            view_change_proofs,
            selected_checkpoint,
            selected_messages,
        };
        self.process_new_view(new_view.clone());
        self.communication_proxy.broadcast(PBFTEvent::NewView(new_view));
        debug!("Peer {}: Generated new view proof for view {}.", self.my_index, self.view);
    }

    fn process_new_view(&mut self, data: NewView<O>) {
        // TODO: Collect garbage on old view data in both the manager and PBFT state
        if data.view == 0 {
            debug!("Peer {}: Dropping new view for view 0", self.my_index);
            return;
        }
        if data.view < self.view {
            debug!("Peer {}: Dropping new view for a previous view.", self.my_index);
            return;
        }
        if self.primary(data.view) != data.from {
            info!("Peer {}: Dropping new view (view = {}) from peer {} who is not the primary.", self.my_index, data.view, data.from);
            return;
        }
        if self.new_view_log.contains_key(&data.view) {
            // Ignore a view we already have
            return;
        }

        // Validate the view change data to ensure proof is not malformed
        let valid_view_change_proofs = data.view_change_proofs.iter()
            .all(|e| {
                match &e.event {
                    PBFTEvent::ViewChange(_) => {
                        // Validate signature of the event
                        e.is_valid()
                    }
                    _ => {
                        false
                    }
                }
            });
        if !valid_view_change_proofs {
            info!("Peer {}: Dropping new view (view = {}) from peer {} who provided invalid new view proofs.", self.my_index, data.view, data.from);
            return;
        }

        let view_changes_iter = data.view_change_proofs.iter().map(convert_to_view_change);

        let num_viewchangers = view_changes_iter.clone()
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len();

        if num_viewchangers < data.view_change_proofs.len() {
            // This check probably does not affect safety of view change protocol but it is a good sanity check to include.
            // Nobody should be submitting two different view change.
            info!("Peer {}: Dropping new view (view = {}) from peer {} who included a double voter!.", self.my_index, data.view, data.from);
            return;
        }

        // Validate selected checkpoint
        if !self.is_valid_selected_checkpoint(view_changes_iter.clone(), &data.selected_checkpoint) {
            info!("Peer {}: Dropping new view (view = {}) from peer {} with invalid log low mark.", self.my_index, data.view, data.from);
            return;
        }

        // Validate selected requests
        if data.selected_messages.len() != self.sequence_window_length as usize {
            info!("Peer {}: Dropping new view (view = {}) from peer {} with not enough selected requests.", self.my_index, data.view, data.from);
            return;
        }

        let h = data.selected_checkpoint.sequence_number;
        for n in h + 1..=h + self.sequence_window_length {
            let selected_message = data.selected_messages.get((n - h - 1) as usize);
            if selected_message.is_none() {
                // This should be impossible
                info!("Peer {}: Dropping new view (view = {}) from peer {} with not enough selected requests.", self.my_index, data.view, data.from);
                return;
            }
            let selected_message = selected_message.unwrap();
            match selected_message {
                None => {
                    if !self.is_condition_b_viable(view_changes_iter.clone(), n) {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose an invalid noop request.", self.my_index, data.view, data.from);
                        return;
                    }
                }
                Some(chosen_prep) => {
                    if chosen_prep.sequence_number != n {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose a request with incorrect sequence number.", self.my_index, data.view, data.from);
                        return;
                    }

                    let chosen_from_prepared = view_changes_iter.clone()
                        .any(|change| {
                            change.prepared.contains(chosen_prep)
                        });

                    if !chosen_from_prepared {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose a request not among those prepared.", self.my_index, data.view, data.from);
                        return;
                    }

                    // Check condition A1
                    if !self.is_justified_by_a1(view_changes_iter.clone(), chosen_prep) {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose a request unsupported by a quorum.", self.my_index, data.view, data.from);
                        return;
                    }

                    // Check condition A2
                    if !self.is_justified_by_a2(view_changes_iter.clone(), chosen_prep) {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose a request unsupported by a weak certificate.", self.my_index, data.view, data.from);
                        return;
                    }
                }
            }
        }

        // The new view message received is valid
        debug!("Peer {}: Accepted new view for view {}.", self.my_index, data.view);
        self.new_view_log.insert(data.view, data);

        self.attempt_view_change();
    }

    fn attempt_view_change(&mut self) {
        if self.is_view_active {
            // Don't view change while in an active view
            return;
        }
        if self.new_view_log.get(&self.view).is_none() {
            // Can't view change. No valid new view message has been received for this view
            return;
        }

        let new_view = self.new_view_log.get(&self.view).unwrap();
        let h = self.log_low_mark();
        if h < new_view.selected_checkpoint.sequence_number {
            debug!("Peer {}: Cannot view change because log low mark is behind.", self.my_index);
            // Attempt to synchronize up to the new view selected checkpoint
            self.synchronize_up_to_checkpoint(&new_view.selected_checkpoint.clone());
            return;
        }
        debug!("Peer {}: Synchronized up to checkpoint for view change!.", self.my_index);

        for selected_message in new_view.selected_messages.iter() {
            match selected_message {
                None => {
                    // All replica have the noop operation
                    continue;
                }
                Some(selected_message) => {
                    match self.find_op_with_digest(&selected_message.digest) {
                        None => {
                            // No such message has been found attempt to synchronize
                            self.requested_digests.insert((selected_message.sequence_number, new_view.view), selected_message.digest.clone());
                            self.communication_proxy.broadcast(PBFTEvent::StateTransferRequest(StateTransferRequest::ViewChangeDigestProof {
                                from: self.my_index,
                                sequence_number: selected_message.sequence_number,
                                digest: selected_message.digest.clone(),
                            }));
                            // TODO: Improve this to obtain many proofs in parallel without generating a lot of traffic
                            // Exit because the replica is not synchronized on the digests
                            return;
                        },
                        Some(op) => {
                            // Check that the message has been prepared and prepared in this view
                            let is_preprepared = self.message_log().iter().any(|e| {
                                if let PBFTEvent::PrePrepare {data, ..} = e {
                                    (data.sequence_number, data.view) == (selected_message.sequence_number, self.view)
                                } else {
                                    false
                                }
                            });
                            let is_prepared = self.message_log().iter().any(|e| {
                                if let PBFTEvent::Prepare {data, ..} = e {
                                    (data.sequence_number, data.view) == (selected_message.sequence_number, self.view)
                                } else {
                                    false
                                }
                            });

                            let data = PrepTriple {
                                sequence_number: selected_message.sequence_number,
                                digest: selected_message.digest.clone(),
                                view: self.view
                            };
                            if !is_preprepared {
                                self.message_log.push(PBFTEvent::PrePrepare {
                                    from: self.primary(new_view.view),
                                    data: data.clone(),
                                    request: RequestPayload { op, op_digest: data.digest.clone() },
                                });
                            }
                            if !is_prepared && self.primary(new_view.view) != self.my_index {
                                let prepare = PBFTEvent::Prepare {
                                    from: self.my_index,
                                    data: data.clone(),
                                };
                                self.message_log.push(prepare.clone());
                                self.communication_proxy.broadcast(prepare)
                            }
                        }
                    }
                }
            }
        }
        debug!("Peer {}: Synchronized! Moving into the new view...", self.my_index);
        // All non noop operations have been preprepared and prepared (if applicable).
        // Preprepare and prepare all noops;
        let noop = O::noop();
        let noop_digest = noop.digest();
        for (i, _) in new_view.selected_messages.iter().enumerate().filter(|(_i, m)| m.is_none()) {
            let n = h + i as SequenceNumber + 1;
            let data = PrepTriple {
                sequence_number: n,
                digest: noop_digest.clone(),
                view: new_view.view,
            };
            self.message_log.push(PBFTEvent::PrePrepare {
                from: self.primary(new_view.view),
                data: data.clone(),
                request: RequestPayload { op: noop.clone(), op_digest: noop_digest.clone() },
            });
            if self.primary(new_view.view) != self.my_index {
                let prepare = PBFTEvent::Prepare {
                    from: self.my_index,
                    data: data.clone(),
                };
                self.message_log.push(prepare.clone());
                self.communication_proxy.broadcast(prepare)
            }
        }

        // All messages have been synchronized
        self.is_view_active = true;

        let synchronized_preps = self.message_log.iter()
            .filter_map(|e| {
                match e {
                    PBFTEvent::PrePrepare { data, .. } => { Some(data) }
                    PBFTEvent::Prepare { data, .. } => { Some(data) }
                    _ => { None }
                }
            })
            .filter(|data| data.view == self.view)
            .collect::<HashSet<&PrepTriple>>();

        // Satisfy the borrow checker by cloning all the synchronized preps
        let synchronized_preps = synchronized_preps.into_iter().cloned().collect::<HashSet<PrepTriple>>();
        // Introduction of new preprepare and prepare could enable a commit
        for prep in synchronized_preps {
            self.attempt_commit_send(&prep);
        }

        self.sequence_number = self.message_log.iter().filter_map(|e| {
            if let PBFTEvent::PrePrepare {data, ..} = e {
                Some(data.sequence_number)
            } else {
                None
            }
        }).max().unwrap_or(0);

        // We just moved into a new view so trash all data less than the current one.
        self.new_view_log.retain(|v, _| *v > self.view);
        self.requested_digests = Default::default();
    }

    fn is_valid_selected_checkpoint<'a, I: Iterator<Item=&'a ViewChange> + Clone>(&self, view_changes: I, candidate: &CheckpointSummary) -> bool {
        let is_stable = view_changes.clone()
            .filter(|change| change.log_low_mark <= candidate.sequence_number)
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.quorum_size() as usize;

        if !is_stable {
            return false;
        }

        // Check liveliness
        view_changes
            .filter(|change| change.checkpoints.contains(candidate))
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.weak_certificate_size() as usize
    }

    fn is_justified_by_a1<'a, I: Iterator<Item=&'a ViewChange>>(&self, view_changes: I, candidate: &PrepTriple) -> bool {
        let n = candidate.sequence_number;
        let v = candidate.view;

        // Fig 4 Condition A1 of PBFT paper
        view_changes
            .filter(|change| {
                change.log_low_mark < n
                    && change.prepared.iter()
                    .filter(|prep| prep.sequence_number == n)
                    .all(|other| {
                        other.view < v || (other.view, &other.digest) == (v, &candidate.digest)
                    })
            })
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.quorum_size() as usize
    }

    fn is_justified_by_a2<'a, I: Iterator<Item=&'a ViewChange>>(&self, view_changes: I, candidate: &PrepTriple) -> bool {
        let n = candidate.sequence_number;
        // Fig 4 Condition A2 of PBFT paper
        view_changes
            .filter(|change| {
                change.preprepared.iter()
                    .any(|other| {
                        (other.sequence_number, &other.digest) == (n, &candidate.digest)
                            && other.view >= candidate.view
                    })
            })
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.weak_certificate_size() as usize
    }

    fn is_condition_b_viable<'a, I: Iterator<Item=&'a ViewChange>>(&self, view_changes: I, sequence_number: SequenceNumber) -> bool {
        let n = sequence_number;
        // Check Fig 4 Condition B
        view_changes
            .filter(|change| {
                change.log_low_mark < n
                    && change.prepared.iter().all(|other| other.sequence_number != n)
            })
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.quorum_size() as usize
    }

    fn find_op_with_digest(&self, digest: &DigestResult) -> Option<O> {
        // Attempt to find an operation matching the requested digest
        let op = self.message_log.iter().find(|e| {
            match e {
                PBFTEvent::PrePrepare { request, .. } => {
                    &request.op_digest == digest
                }
                _ => false
            }
        });

        if let Some(PBFTEvent::PrePrepare { request, .. }) = op {
            Some(request.op.clone())
        } else {
            None
        }
    }

    fn synchronize_up_to_checkpoint(&mut self, checkpoint_summary: &CheckpointSummary) {
        // TODO: Do less naive synchronization
        let current_log_length = self.current_state.log().len();
        self.known_service_state_digests.insert(
            checkpoint_summary.service_state_summary.log_length,
            (checkpoint_summary.sequence_number, checkpoint_summary.service_state_summary.log_digest.clone())
        );

        for n in current_log_length..checkpoint_summary.service_state_summary.log_length {
            self.communication_proxy.broadcast(PBFTEvent::StateTransferRequest(StateTransferRequest::ServiceStateItemProof {
                from: self.my_index,
                log_length: checkpoint_summary.service_state_summary.log_length,
                log_item_index: n,
            }))
        }
    }

    fn process_state_transfer_request(&mut self, req: StateTransferRequest) {
        // Attempt to answer the request
        match req {
            StateTransferRequest::ViewChangeDigestProof { from, sequence_number, digest } => {
                // Attempt to find an operation matching the requested digest
                if let Some(operation) = self.find_op_with_digest(&digest) {
                    // Found an operation satisfying the requested digest
                    self.communication_proxy.send(from, PBFTEvent::StateTransferResponse(StateTransferResponse::ViewChangeDigestProof {
                        sequence_number,
                        operation,
                    }));
                }
            }
            StateTransferRequest::ServiceStateItemProof { from, log_length, log_item_index } => {
                if let Some(op) = self.current_state.log().get(log_item_index as usize) {
                    // Requester presumable has validated that the checkpoint is valid so there should be a committed message
                    // at the requested sequence_number <= checkpoint_number
                    self.communication_proxy.send(from, PBFTEvent::StateTransferResponse(StateTransferResponse::ServiceStateItemProof {
                        log_length,
                        log_item_index,
                        operation: op.clone(),
                        // TODO: Construct actual proof
                        merkle_proof: vec![],
                    }));
                }
            }
        }
    }

    fn process_state_transfer_response(&mut self, res: StateTransferResponse<O>) {
        match res {
            StateTransferResponse::ViewChangeDigestProof { sequence_number, operation } => {
                // Check that the response is relevant to the current view change
                if let Some(digest) = self.requested_digests.get(&(sequence_number, self.view)) {
                    if !operation.digest().eq(digest) {
                        // Peer may be responding to a request digest from a past view
                        debug!("Peer {}: Dropping state transfer request with incorrect digest.", self.my_index);
                        return;
                    }

                    // In the current view, this replica attempted to resolve the operation associated
                    // with a digest. If the replica already has in its record the corresponding operation
                    // there is no point in prepreparing/preparing this newly found operation. This
                    // also prevents spamming the message log with duplicate operations.
                    //
                    // This simply records the newly found operation in the message log so that it can
                    // be found in the future.
                    if self.find_op_with_digest(digest).is_none() {
                        let data = PrepTriple {
                            sequence_number,
                            digest: digest.clone(),
                            view: self.view,
                        };
                        self.message_log.push(PBFTEvent::PrePrepare {
                            from: self.primary(self.view),
                            data: data.clone(),
                            request: RequestPayload { op: operation, op_digest: digest.clone() },
                        });

                        if !self.is_primary(self.my_index) {
                            let prepare = PBFTEvent::Prepare {
                                from: self.my_index,
                                data: data.clone(),
                            };
                            self.message_log.push(prepare.clone());
                            self.communication_proxy.broadcast(prepare);
                        }

                        if !self.is_view_active {
                            // The response comes back while this replica is synchronizing with other for view change
                            // and this replica does not know the operation associated with the digest.
                            //
                            // Enough information may have accumulated to perform view change
                            self.attempt_view_change();
                        } else {
                            self.attempt_commit_send(&data);
                        }
                    }
                }
            }
            StateTransferResponse::ServiceStateItemProof { log_length, log_item_index, operation, merkle_proof } => {
                if let Some((checkpoint_number, service_state_digest)) = self.known_service_state_digests.get(&log_length) {
                    // TODO: Actually validate the proof and index again length
                    self.current_state.insert_operation(log_item_index, operation);
                }
                // Immediately after inserting this operation we synchronized the service state up to a known checkpoint
                if let Some((checkpoint_number, _)) = self.known_service_state_digests.get(&self.current_state.log().len()) {
                    if self.last_executed >= *checkpoint_number {
                        // For safety ensure that we are moving forward in the sequence number
                        return;
                    }

                    self.last_executed = *checkpoint_number;
                    self.create_checkpoint();
                    // Enough information may have accumulated to perform view change
                    self.attempt_view_change();
                }
            }
        }
    }
}

// Helper function to convert wrapped view change into a view change
fn convert_to_view_change<O: ServiceOperation>(event: &WrappedPBFTEvent<O>) -> &ViewChange {
    match &event.event {
        PBFTEvent::ViewChange(data) => { data }
        _ => { panic!("Cannot convert to view change!") }
    }
}