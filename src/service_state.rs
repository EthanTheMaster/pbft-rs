use std::collections::{HashMap, HashSet};
use log::warn;
use crate::communication_proxy::PeerIndex;
use crate::kernel::SequenceNumber;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc::UnboundedSender;
use crate::merkle_tree::{MembershipProof, MerkleIndex, MerkleTree};
use crate::pbft_replica::{Digestible, DigestResult, ServiceOperation};


// High level representation of user service state
// Records a sequence of operations to perform against a *deterministic* state machine
// All operations recorded come from some provided type O
#[derive(Clone)]
pub struct ServiceState<O>
    where O: ServiceOperation
{
    // Save noop digest for quick reference
    noop_digest: DigestResult,
    // List of items awaiting to be placed into the log ... this is internal
    // and should not be reflected in the digest which is based on the finalized log!
    // The log presented should not have gaps.
    buffer: HashMap<usize, O>,
    log: Vec<O>,
    merkle_tree: MerkleTree,
    state_change_publisher: UnboundedSender<O>
}

// Used to aid in state transfer
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceStateSummary {
    pub log_length: usize,
    pub log_digest: DigestResult
}

impl<O> ServiceState<O>
    where O: ServiceOperation
{

    pub fn new(state_change_publisher: UnboundedSender<O>) -> Self {
        ServiceState {
            noop_digest: O::noop().digest(),
            buffer: Default::default(),
            log: Vec::new(),
            merkle_tree: MerkleTree::new(O::noop().digest()),
            state_change_publisher
        }
    }

    pub fn broadcast_finality(&mut self, op: O) {
        let op_digest = op.digest();
        if op_digest == self.noop_digest {
            // Don't process noops
            return;
        }
        // Attempt to include operation into merkle tree
        let successful_append = self.merkle_tree.append(op_digest);
        if successful_append.is_ok() {
            self.log.push(op.clone());
            let _ = self.state_change_publisher.send(op);
        }
    }

    pub fn log(&self) -> &Vec<O> {
        &self.log
    }

    pub fn summarize(&self) -> ServiceStateSummary {
        ServiceStateSummary {
            log_length: self.log.len(),
            log_digest: self.digest()
        }
    }

    // It is sometimes the case that future operations are known but there is some
    // gaps between the current state and the future operation. Queues up this operation
    // for inclusion into the finalized log.
    pub fn insert_operation(&mut self, index: usize, operation: O) {
        let op_digest = operation.digest();
        if  op_digest == self.noop_digest {
            // Don't process noops
            return;
        }
        if index < self.log.len() {
            // There is no point in inserting an already finalized operation
            if &op_digest != self.merkle_tree.items().get(index).unwrap() {
                warn!("Safety violation: Operation being inserted into log has a different digest than current finalized operation.");
            }
            return;
        }
        self.buffer.insert(index, operation);

        while self.buffer.contains_key(&self.log.len()) {
            let next_op = self.buffer.remove(&self.log.len()).unwrap();
            self.broadcast_finality(next_op);
        }
    }

    pub fn construct_membership_proof(&self, indices: &HashSet<MerkleIndex>, size: usize) -> Option<MembershipProof> {
        let right_boundary = (size - 1) as MerkleIndex;
        self.merkle_tree.generate_proof(indices, right_boundary)
    }
}

impl<O> Digestible for ServiceState<O>
    where O: ServiceOperation
{
    fn digest(&self) -> DigestResult {
        self.merkle_tree.root()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StateTransferRequest {
    // Requester already knows the digest so responder must give a valid response matching this digest
    ViewChangeDigestProof {
        from: PeerIndex,
        sequence_number: SequenceNumber,
        digest: DigestResult,
    },
    ServiceStateItemProof {
        from: PeerIndex,
        log_length: usize, // Requester knows the service state digest at this point
        log_item_index: usize // Request wants to know the operation at this point
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StateTransferResponse<O>
    where O: ServiceOperation
{
    ViewChangeDigestProof {
        sequence_number: SequenceNumber,
        operation: O
    },
    ServiceStateItemProof {
        log_length: usize,
        log_item_index: usize,
        operation: O,
        merkle_proof: MembershipProof
    }
}