use std::collections::HashMap;
use std::fmt::Debug;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::pbft::{PBFTEvent, Peer, PeerId};

type SignatureResult = Vec<u8>;

pub struct WrappedPBFTEvent<O>
where O: Clone + Debug
{
    event: PBFTEvent<O>,
    from: PeerId,
    signature: SignatureResult
}

impl<O> WrappedPBFTEvent<O>
where O: Clone + Debug
{
    pub fn validate(self, _peer: &Peer) -> bool {
        // TODO: Add real signature validation
        true
    }
}

pub struct CommunicationProxy<O>
where O: Clone + Debug
{
    peer_db: HashMap<PeerId, (Peer, UnboundedSender<WrappedPBFTEvent<O>>)>,
    // Combines all receivers into a single stream
    receiver_multiplexer: UnboundedReceiver<WrappedPBFTEvent<O>>
}

type Peers<O> = Vec<(Peer, UnboundedSender<WrappedPBFTEvent<O>>)>;
impl<O> CommunicationProxy<O>
where O: Clone + Debug
{
    pub fn new(peers: Peers<O>, receiver_multiplexer: UnboundedReceiver<WrappedPBFTEvent<O>>) -> Self {
        // Index peers
        let mut peer_db = HashMap::new();
        for (p, s) in peers.into_iter() {
            // TODO: Validate peer data at this point
            peer_db.insert(p.id.clone(), (p, s));
        }

        CommunicationProxy {
            peer_db,
            receiver_multiplexer
        }
    }

    pub async fn recv_event(&mut self) -> PBFTEvent<O> {
        match self.receiver_multiplexer.recv().await {
            None => {
                //TODO: Figure out recovery
                panic!("idk");
            },
            Some(e) => {
                //TODO: Add signature validation
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
                signature: vec![]
            };
            // TODO: Handle send error
            let _ = s.send(wrapped_msg);
        }
    }
}