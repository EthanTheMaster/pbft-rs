use std::collections::HashSet;
use std::fmt::Debug;
use log::{debug, info};
use crate::communication_proxy::CommunicationProxy;

use crate::service_state::ServiceState;

// Aliasing away concrete types to make
// possible refactors easier
pub type PeerId = String;
pub type PeerIndex = u64;
// Index of peer in total ordering
pub type ClientId = String;
pub type ClientRequestTimestamp = u64;

pub type ViewstampId = u64;
pub type SequenceNumber = u64;
pub type DigestResult = Vec<u8>;

#[derive(Clone)]
pub struct Peer {
    // TODO: Make id generic and sortable to assign total order to list of peers
    pub id: PeerId,
    pub hostname: String,
    // TODO: Add fields for cryptographic keys
}

pub struct Configuration {
    peers: Vec<Peer>,
    // TODO: Add fields for cryptographic keys
    // TODO: Add fields for timeout configuration
    // TODO: Add checkpoint management and log compression parameters
    // TODO: Add fields for configuring network listening
}

// Trait allowing cryptographic hash to be computed
pub trait Digestible {
    fn digest(&self) -> DigestResult;
    fn matches(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

impl Digestible for String {
    fn digest(&self) -> DigestResult {
        self.as_bytes().to_vec()
    }
}

// Alias traits required of service operations being replicated
pub trait ServiceOperation:
Clone + Debug + Digestible {}

impl<T> ServiceOperation for T
    where T: Clone + Debug + Digestible {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepTriple {
    sequence_number: SequenceNumber,
    digest: DigestResult,
    view: ViewstampId,
}

#[derive(Clone, Debug)]
pub struct RequestPayload<O>
    where O: ServiceOperation
{
    op: O,
    // TODO: Validate this field
    op_digest: DigestResult,
}

impl<O> RequestPayload<O>
    where O: ServiceOperation
{
    pub fn new(op: O) -> Self {
        let op_digest = op.digest();
        RequestPayload {
            op,
            op_digest
        }
    }
}

#[derive(Clone, Debug)]
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
        sequence_number: SequenceNumber,
        service_state_digest: DigestResult,
    },
    Reply {
        from: PeerIndex,
        sequence_number: SequenceNumber,
        // TODO: Add logic to alert system that message was just committed
        execution_result: (),
    },
}

pub struct Checkpoint<O>
    where O: ServiceOperation
{
    sequence_number: SequenceNumber,
    service_state: ServiceState<O>,
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

    prepared: Vec<PrepTriple>,
    preprepared: Vec<PrepTriple>,
}

impl<O> PBFTState<O>
    where O: ServiceOperation
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
            checkpoints: vec![],
            pending_committed: vec![],
            checkpoint_interval,
            prepared: vec![],
            preprepared: vec![],
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
        let event = self.communication_proxy.recv_event().await;
        match event {
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
            PBFTEvent::Checkpoint { from, sequence_number, service_state_digest } => {
                self.process_checkpoint(from, sequence_number, service_state_digest);
            }
            PBFTEvent::Reply { from, sequence_number, execution_result } => {
                self.process_reply(from, sequence_number, execution_result);
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

    fn is_primary(&self, participant_index: PeerIndex) -> bool {
        let n = self.num_participants;
        let primary = (self.view % (n as ViewstampId)) as PeerIndex;
        primary == participant_index
    }

    // Checks that a sequence number does not extend beyond capacity to hold messages to be committed
    fn is_sequence_number_in_window(&self, sequence_number: SequenceNumber) -> bool {
        let h = self.message_log.iter().map(|e| {
            if let PBFTEvent::Checkpoint { sequence_number, .. } = e {
                *sequence_number
            } else {
                0
            }
        }).min().unwrap_or(0);
        let offset = sequence_number - h;

        0 < offset && offset <= self.sequence_window_length
    }

    fn is_preprepared(&self, data: &PrepTriple) -> bool {
        self.preprepared.contains(data) || self.message_log.iter().any(|e| {
            if let PBFTEvent::PrePrepare { data: other_data, .. } = e {
                data.eq(other_data)
            } else {
                false
            }
        })
    }

    fn is_prepared(&self, data: &PrepTriple) -> bool {
        if self.prepared.contains(data) {
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
        self.is_preprepared(data) && certificate_size as PeerIndex >= self.quorum_size() - 1
    }

    fn is_committed(&self, data: &PrepTriple) -> bool {
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
        self.is_prepared(data) && certificate_size as PeerIndex >= self.quorum_size()
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

            let preprepare = PBFTEvent::PrePrepare {
                from: self.my_index,
                data: PrepTriple {
                    view: self.view,
                    sequence_number: proposed_sequence_number,
                    digest: request_digest,
                },
                request: payload,
            };
            self.message_log.push(preprepare.clone());
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
            debug!("Peer {}: Attempted to send commit, but will not commit again. {:?}", self.my_index, data);
            return;
        }

        if !self.is_prepared(data) {
            debug!("Peer {}: Attempted to send commit, but quorum has not been achieved. {:?}", self.my_index, data);
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
        if !self.is_committed(data) {
            debug!("Peer {}: Attempted to perform execution but data has not been committed. {:?}", self.my_index, data);
            return;
        }

        let associated_preprepare = self.message_log.iter().find(|e| {
            if let PBFTEvent::PrePrepare { data: other_data, .. } = e {
                data.eq(other_data)
            } else {
                false
            }
        });
        if let Some(PBFTEvent::PrePrepare {request, ..}) = associated_preprepare {
            self.pending_committed.push((request.op.clone(), data.sequence_number));
        }

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

        let current_state_digest = self.current_state.digest();
        let checkpoint_event = PBFTEvent::Checkpoint {
            from: self.my_index,
            sequence_number: self.last_executed,
            service_state_digest: current_state_digest.clone()
        };
        self.message_log.push(checkpoint_event.clone());
        self.communication_proxy.broadcast(checkpoint_event);
        debug!("Peer {}: Created checkpoint at {}.", self.my_index, self.last_executed);

        // TODO: Revisit this and make more space efficient
        self.checkpoints.push(Checkpoint {
            sequence_number: self.last_executed,
            service_state: self.current_state.clone()
        });

        self.collect_garbage(self.last_executed, current_state_digest);
    }

    fn process_checkpoint(&mut self, from: PeerIndex, sequence_number: SequenceNumber, service_state_digest: DigestResult) {
        if !self.is_sequence_number_in_window(sequence_number) {
            debug!("Peer {}: Ignoring checkpoint at {} because message log is too full.", self.my_index, sequence_number);
        }

        self.message_log.push(PBFTEvent::Checkpoint {
            from,
            sequence_number,
            service_state_digest: service_state_digest.clone()
        });
        debug!("Peer {}: Received checkpoint at {}.", self.my_index, self.last_executed);
        self.collect_garbage(sequence_number, service_state_digest);
    }

    fn collect_garbage(&mut self, checkpoint_sequence_number: SequenceNumber, service_state_digest: DigestResult) {
        let certificate_size = self.message_log.iter()
            .filter(|e| {
                if let PBFTEvent::Checkpoint {
                    sequence_number: other_sequence_number,
                    service_state_digest: other_service_state_digest,
                    ..
                } = e {
                    (&checkpoint_sequence_number, &service_state_digest) == (other_sequence_number, other_service_state_digest)
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
            debug!("Peer {}: Cannot collect garbage because quorum has not been reached on checkpoint {}", self.my_index, checkpoint_sequence_number);
            return;
        }
        // TODO: Checkpoint has been stabilized. Record it.

        self.checkpoints.retain(|c| c.sequence_number >= checkpoint_sequence_number);
        // TODO: Investigate why PBFT paper does not only look at sequence number for garbage but also digest
        // This does not make sense because checkpoint digest is on the service state where as digest in
        // Preprepare, prepare, and commit have digest over client requests. Exposition in section 4.4
        // even says "replica discards all entries in its log with sequence numbers less than or equal to n".
        //
        // My instinct is that clearing by sequence number only is safe. Achieving quorum on the checkpoint
        // means a quorum has committed and executed all messages up to checkpoint_sequence_number.
        // Messages up to checkpoint_sequence_number are irreversible and so having messages the same
        // or different from the finalized messages are garbage anyways. Any discrepancies from that
        // of the checkpoint must be resolved using state transfer mechanism.
        // TODO: Trigger state transfer if checkpoint is past the current last executed
        self.message_log
            .retain(|e| {
                match e {
                    PBFTEvent::Request(_) => {panic!("Request should not be in message log!")}
                    PBFTEvent::PrePrepare { data, .. } => {data.sequence_number > checkpoint_sequence_number}
                    PBFTEvent::Prepare { data, .. } => {data.sequence_number > checkpoint_sequence_number}
                    PBFTEvent::Commit { data, .. } => {data.sequence_number > checkpoint_sequence_number}
                    PBFTEvent::Checkpoint { sequence_number, .. } => {*sequence_number > checkpoint_sequence_number}
                    PBFTEvent::Reply { .. } => {panic!("Reply should not be in message log!")}
                }
            });
        self.prepared.retain(|data| data.sequence_number > checkpoint_sequence_number);
        self.preprepared.retain(|data| data.sequence_number > checkpoint_sequence_number);

        debug!("Peer {}: Collected garbage before checkpoint {}.", self.my_index, checkpoint_sequence_number);
    }

    fn process_reply(&mut self, from: PeerIndex, sequence_number: SequenceNumber, execution_result: ()) {
        unimplemented!();
    }


    // TODO: Add steps to engage in state transfer / recovery
}