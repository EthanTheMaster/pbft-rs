use std::collections::HashMap;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::pbft::{PBFTEvent, Peer, PeerId, PeerIndex, ServiceOperation};

type SignatureResult = Vec<u8>;

pub struct WrappedPBFTEvent<O>
    where O: ServiceOperation
{
    event: PBFTEvent<O>,
    from: PeerId,
    signature: Option<SignatureResult>,
}

impl<O> WrappedPBFTEvent<O>
    where O: ServiceOperation
{
    pub fn validate(self, _peer: &Peer) -> bool {
        // TODO: Add real signature validation
        true
    }
}

pub struct CommunicationProxy<O>
    where O: ServiceOperation
{
    myself: Peer,
    indexed_participants: Vec<Peer>,
    peer_db: HashMap<PeerId, (Peer, UnboundedSender<WrappedPBFTEvent<O>>)>,
    // Combines all receivers into a single stream
    receiver_multiplexer: UnboundedReceiver<WrappedPBFTEvent<O>>,
}

type Peers<O> = Vec<(Peer, UnboundedSender<WrappedPBFTEvent<O>>)>;

impl<O> CommunicationProxy<O>
    where O: ServiceOperation
{
    pub fn new(myself: Peer, peers: Peers<O>, receiver_multiplexer: UnboundedReceiver<WrappedPBFTEvent<O>>) -> Self {
        // Index peers
        let mut participants = vec![myself.clone()];

        let mut peer_db = HashMap::new();
        for (p, s) in peers.into_iter() {
            // TODO: Validate peer data at this point (eg. check duplication)
            participants.push(p.clone());
            peer_db.insert(p.id.clone(), (p, s));
        }

        participants.sort_by_key(|p| p.id.clone());
        CommunicationProxy {
            myself,
            indexed_participants: participants,
            peer_db,
            receiver_multiplexer,
        }
    }

    pub async fn recv_event(&mut self) -> PBFTEvent<O> {
        match self.receiver_multiplexer.recv().await {
            None => {
                //TODO: Figure out recovery
                panic!("idk");
            }
            Some(e) => {
                //TODO: Add signature validation
                //TODO: Validate from components (Match PeerId with PeerIndex)
                e.event
            }
        }
    }

    pub fn broadcast(&self, event: PBFTEvent<O>) {
        for (p, s) in self.peer_db.values() {
            // TODO: Compute digital signature
            let wrapped_msg = WrappedPBFTEvent {
                event: event.clone(),
                from: "".to_string(),
                signature: None,
            };
            // TODO: Handle send error
            let _ = s.send(wrapped_msg);
        }
    }

    pub fn num_peers(&self) -> usize {
        self.peer_db.len()
    }

    pub fn my_index(&self) -> PeerIndex {
        self.indexed_participants.iter().position(|p| p.id == self.myself.id).unwrap() as PeerIndex
    }
}