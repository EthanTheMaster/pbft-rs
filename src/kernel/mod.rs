use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::time::Duration;
use log::{debug, info, warn};
use crate::communication_proxy::*;
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use tokio::select;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::watch::Receiver;
use tokio::time::{Interval, interval};
use crate::kernel::view_change_manager::{atomic_update_state, AtomicViewChangeManager};
use crate::pbft_replica::{Digestible, DigestResult, ServiceOperation};

use crate::service_state::{ServiceState, ServiceStateSummary, StateTransferRequest, StateTransferResponse};

mod normal_operation;
mod view_change;
mod state_transfer;
pub mod view_change_manager;

#[cfg(test)]
mod test;

// Aliasing away concrete types to make
// possible refactors easier
// Index of peer in total ordering
type ViewstampId = u64;
pub type SequenceNumber = u64;

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
    pub fn new(op: O) -> Self {
        let op_digest = op.digest();
        RequestPayload {
            op,
            op_digest,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.op.digest() == self.op_digest
    }
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
    preprepared: HashSet<PrepTriple>,
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
    communication_proxy: CommunicationProxy<O>,
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
    execution_timeout: Duration,

    // The "service state" being replicated is the message log associated with
    // an atomic broadcast protocol, not user's actual service state. Implementing
    // atomic broadcast using PBFT abstracts away details of PBFT from user attempting
    // to replicate their service.
    current_state: ServiceState<O>,

    // Lets you derive the low and high water marks for log compression
    sequence_window_length: u64,

    // Keeps track of committed requests at a regular interval
    pending_committed: Vec<(O, SequenceNumber)>,
    checkpoints: Vec<CheckpointSummary>,
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
    // The view change manager is responsible with monitoring the PBFT state for timely
    // progress. It schedules view changes when appropriate. View changes should be scheduled
    // through the view change manager and not through the PBFT state. This is ensure that
    // state transitions happen sequentially, not concurrently.
    view_change_manager: AtomicViewChangeManager,
    // The view manager alerts the PBFT state to view change through this channel
    requested_view_change: Receiver<ViewstampId>,
    view_change_timeout: Duration,
    view_change_retransmission_interval: Interval,
    view_change_log: Vec<WrappedPBFTEvent<O>>,
    // This map tracks who has been seen in a view. That is, let (v, P) be an entry
    // in this map. If some peer is in P, then that peer has been seen in view v.
    view_change_participants: HashMap<ViewstampId, HashSet<PeerIndex>>,
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
        view_change_manager: AtomicViewChangeManager,
        communication_proxy: CommunicationProxy<O>,
        state_change_publisher: UnboundedSender<O>,
        execution_timeout: Duration,
        view_change_timeout: Duration,
        view_change_retransmission_interval: Duration,
        sequence_window_length: u64,
        checkpoint_interval: u64,
    ) -> PBFTState<O> {
        let num_participants = communication_proxy.num_participants() as PeerIndex;
        let my_index = communication_proxy.my_index();
        let current_state: ServiceState<O> = ServiceState::new(state_change_publisher);
        let initial_checkpoint = CheckpointSummary {
            sequence_number: 0,
            service_state_summary: ServiceStateSummary {
                log_length: 0,
                log_digest: current_state.digest(),
            },
        };

        let requested_view_change = view_change_manager.lock().unwrap().requested_view_change_rx();
        PBFTState {
            communication_proxy,
            my_index,
            num_participants,
            is_view_active: true,
            view: 0,
            message_log: Vec::new(),
            sequence_number: 0,
            last_executed: 0,
            execution_timeout,
            current_state,
            sequence_window_length,
            checkpoints: vec![initial_checkpoint],
            pending_committed: vec![],
            checkpoint_interval,
            prepared: Default::default(),
            preprepared: Default::default(),
            view_change_manager,
            requested_view_change,
            view_change_timeout,
            view_change_retransmission_interval: interval(view_change_retransmission_interval),
            view_change_log: vec![],
            view_change_participants: Default::default(),
            new_view_log: Default::default(),
            requested_digests: Default::default(),
            known_service_state_digests: Default::default(),
        }
    }
    fn view(&self) -> ViewstampId {
        self.view
    }
    fn message_log(&self) -> &Vec<PBFTEvent<O>> {
        &self.message_log
    }
    fn current_state(&self) -> &ServiceState<O> {
        &self.current_state
    }

    // We deviate from the PBFT paper in that clients do not broadcast requests to the replicas. Rather,
    // clients must have access to a nonfaulty replica to initiate a request on the client's behalf.
    // This allows replicas to lock down access to the state at the application level.
    pub fn broadcast_request(&mut self, op: O) {
        let payload = RequestPayload::new(op);
        self.process_request(payload.clone());
        self.communication_proxy.broadcast(PBFTEvent::Request(payload));
    }

    pub async fn step(&mut self) {
        // TODO: Add rebroadcast logic to subvert byzantine peer. Wrapped event has proof that byzantine peer sent message.
        select! {
            // Prioritize view change requests before receiving event to prevent denial of service.
            // Where events constantly arrive preventing a view change.
            new_view = self.requested_view_change.changed() => {
                // Attempt to do view change if alerted by the manager
                if new_view.is_err() {
                    return;
                }
                let new_view = *self.requested_view_change.borrow();
                if new_view > self.view {
                    // The jump size is guaranteed to be strictly greater than 0
                    debug!("Peer {}: Changing to view {} as requested by view change manager.", self.my_index, new_view);
                    self.change_view(new_view - self.view);
                    // One view change is considered a single state transition. Do more state transitions
                    // in the next invocation of step.
                    return;
                }
            }
            _ = self.view_change_retransmission_interval.tick(), if !self.is_view_active => {
                // Retransmit the view change while not in an active view
                self.communication_proxy.broadcast(PBFTEvent::ViewChange(self.create_view_change_message()));
            }
            wrapped_event = self.communication_proxy.recv_event() => {
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
        }

        // Update the view change manager on the current PBFT state after state transition
        let update = atomic_update_state(
            self.view_change_manager.clone(),
            self.primary(self.view),
            self.view,
            self.is_view_active,
            self.current_state.log().len()
        );
        if !update {
            warn!("Peer {}: Failed to update view change manager!", self.my_index);
        }
    }

    fn max_faults(&self) -> PeerIndex {
        // Compute biggest integer f such that: n >= 3f + 1
        // Integer division performs floor
        (self.num_participants - 1) / 3
    }

    fn quorum_size(&self) -> PeerIndex {
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

    fn weak_certificate_size(&self) -> PeerIndex {
        self.max_faults() + 1
    }

    fn primary(&self, view: ViewstampId) -> PeerIndex {
        let n = self.num_participants;
        (view % (n as ViewstampId)) as PeerIndex
    }

    fn is_primary(&self, participant_index: PeerIndex) -> bool {
        self.primary(self.view) == participant_index
    }

    fn log_low_mark(&self) -> SequenceNumber {
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
                debug!("Peer {}: Executed operation {}! 🎉", self.my_index, n);

                self.create_checkpoint();
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
        // Count the number of peers who corroborate this checkpoint
        let certificate_size = self.message_log.iter()
            .filter_map(|e| {
                if let PBFTEvent::Checkpoint { from, data} = e {
                    if checkpoint_summary == data {
                        return Some(*from);
                    }
                }
                None
            })
            .collect::<HashSet<PeerIndex>>()
            .len();

        if (certificate_size as PeerIndex) < self.quorum_size() {
            // debug!("Peer {}: Cannot collect garbage because quorum has not been reached on checkpoint {}", self.my_index, checkpoint_sequence_number);
            return;
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

        // The clearing of garbage transition may have enabled a new view change by shifting the low log mark.
        self.attempt_view_change();
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
        // Update view properties then construct the view change message
        self.is_view_active = false;
        self.view = new_view;

        let view_change = PBFTEvent::ViewChange(self.create_view_change_message());

        self.process_view_change(self.communication_proxy.wrap(&view_change));

        self.communication_proxy.broadcast(view_change);

        debug!("Peer {}: Engaging in a view change into view {}.", self.my_index, new_view);


        self.collect_view_garbage();
        // There may currently be enough data to perform a view change
        self.attempt_view_change();
    }

    fn create_view_change_message(&self) -> ViewChange {
        if self.is_view_active {
            // The creation of a view change during an active view is probably an implementation error
            warn!("Peer {}: Detected generation of a view change message while in an active view.", self.my_index);
        }
        let checkpoints = self.checkpoints.clone();

        // Assemble the prepared and preprepared indices into a set of tuples for packaging on the network
        let prepared = self.prepared.values().cloned().collect();
        let preprepared = self.preprepared.iter()
            .flat_map(|(n, digest_map)| {
                digest_map.iter().map(|(d, v)| {
                    PrepTriple {
                        sequence_number: *n,
                        digest: *d,
                        view: *v,
                    }
                })
            })
            .collect();
        ViewChange {
            from: self.my_index,
            view: self.view,
            log_low_mark: self.log_low_mark(),
            checkpoints,
            prepared,
            preprepared,
        }
    }
}