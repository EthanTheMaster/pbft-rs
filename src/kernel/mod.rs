use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use log::{debug, info, warn};
use crate::communication_proxy::*;
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;

use crate::service_state::{ServiceState, ServiceStateSummary, StateTransferRequest, StateTransferResponse};

mod normal_operation;
mod view_change;
mod state_transfer;

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
    pub op_digest: DigestResult,
}

impl<O> RequestPayload<O>
    where O: ServiceOperation
{
    pub fn is_valid(&self) -> bool {
        self.op.digest() == self.op_digest
    }
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
    pub from: PeerIndex,
    view: ViewstampId,
    log_low_mark: SequenceNumber,
    checkpoints: Vec<CheckpointSummary>,
    // P and Q sets
    prepared: HashSet<PrepTriple>,
    preprepared: HashSet<PrepTriple>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewView
{
    pub from: PeerIndex,
    view: ViewstampId,
    // We deviate from the PBFT paper by not using view-change acks to convince non-primaries
    // of the existence of view changes. Instead we use digital signatures to prove that a view
    // change was in fact sent.
    view_change_proofs: Vec<SignedPayload>,
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
    NewView(NewView),
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
    new_view_log: HashMap<ViewstampId, NewView>,
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
        let num_participants = communication_proxy.num_participants() as PeerIndex;
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
}