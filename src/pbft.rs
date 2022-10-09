use std::fmt::Debug;
use crate::communication_proxy::CommunicationProxy;

use crate::service_state::ServiceState;

// Aliasing away concrete types to make
// possible refactors easier
pub type PeerId = String;
pub type ClientId = String;
pub type ClientRequestTimestamp = u64;

pub type ViewstampId = u64;
pub type SequenceNumber = u64;
pub type DigestResult = [u8; 8];

#[derive(Clone)]
pub struct Peer {
    pub id: PeerId,
    pub hostname: String,
    // TODO: Add fields for cryptographic keys
}

pub struct Configuration {
    peers: Vec<Peer>
    // TODO: Add fields for cryptographic keys
    // TODO: Add fields for timeout configuration
    // TODO: Add checkpoint management and log compression parameters
}

impl Configuration {
    pub fn max_faults(&self) -> usize {
        // n >= 3f + 1
        // Integer division performs floor
        (self.peers.len() - 1) / 3
    }
}


#[derive(Clone, Debug)]
pub enum PBFTEvent<O>
where O: Clone + Debug
{
    PrePrepare {
        id: PeerId
    },
    Request {
        op: O
    }
}

pub struct Checkpoint<O> {
    sequence_number: SequenceNumber,
    service_state: ServiceState<O>,
}

pub struct PrepTriple {
    sequence_number: SequenceNumber,
    digest: DigestResult,
    view: ViewstampId,
}

// Represents PBFT replica automata that replicates some service
pub struct PBFTState<O>
where O: Clone + Debug
{
    // Proxy gives a logical view of all messages received abstracting details
    // of deserialization and validation. It exposes an interface to communicate with
    // peers.
    pub communication_proxy: CommunicationProxy<O>,

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
    h: SequenceNumber,
    sequence_window_length: u64,

    // Keeps track of committed requests at a regular interval
    checkpoints: Vec<Checkpoint<O>>,
    checkpoint_interval: u64,

    prepared: Vec<PrepTriple>,
    preprepared: Vec<PrepTriple>
}

impl<O> PBFTState<O>
where O: Clone + Debug
{
    pub fn new (
        communication_proxy: CommunicationProxy<O>,
        sequence_window_length: u64,
        checkpoint_interval: u64
    ) -> PBFTState<O> {
        PBFTState {
            communication_proxy,
            is_view_active: true,
            view: 0,
            message_log: Vec::new(),
            sequence_number: 0,
            last_executed: 0,
            current_state: Default::default(),
            h: 0,
            sequence_window_length,
            checkpoints: vec![],
            checkpoint_interval,
            prepared: vec![],
            preprepared: vec![]
        }
    }

    pub async fn step(&mut self) {
        let event = self.communication_proxy.recv_event().await;
        println!("{:?}", event);
    }
}
