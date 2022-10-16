use std::collections::HashMap;
use std::time::Duration;
use futures::{SinkExt, TryStreamExt};
use log::{info, warn};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use crate::kernel::{PBFTEvent, ServiceOperation};
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_serde::formats::SymmetricalJson;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

type SignatureResult = Vec<u8>;

pub type PeerId = String;
pub type PeerIndex = u64;
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

// Listens for incoming events and forwards them to the proxy sender
async fn listen_for_events<O>(hostname: String, proxy_sender: UnboundedSender<WrappedPBFTEvent<O>>)
    where O: ServiceOperation + DeserializeOwned + std::marker::Send + 'static
{
    let proxy_sender = proxy_sender.clone();
    let listener = TcpListener::bind(hostname.clone()).await.unwrap();
    info!("Listening on {}", hostname);
    loop {
        let (socket, _) = listener.accept().await.unwrap();

        let length_delimited = FramedRead::new(socket, LengthDelimitedCodec::new());

        let mut deserialized = tokio_serde::SymmetricallyFramed::new(length_delimited, SymmetricalJson::<Value>::default());

        let proxy_sender = proxy_sender.clone();
        tokio::spawn(async move {
            while let Some(msg) = deserialized.try_next().await.unwrap() {
                let event = serde_json::from_value::<WrappedPBFTEvent<O>>(msg);
                if let Ok(event) = event {
                    // Message was successfully read. Route this to the proxy receiver.
                    let _ = proxy_sender.send(event);
                    //TODO: Add signature validation
                    //TODO: Validate from components (Match PeerId with PeerIndex)
                }
            }
        });
    }
}

// Connects to a peer at the given hostname and returns a handle allowing the proxy to send messages
// to this peer
async fn connect_to<'de, O>(hostname: String) -> UnboundedSender<WrappedPBFTEvent<O>>
    where O: ServiceOperation + Serialize + std::marker::Send + 'static
{
    let (peer_sender, mut peer_receiver): (UnboundedSender<WrappedPBFTEvent<O>>, UnboundedReceiver<WrappedPBFTEvent<O>>) = unbounded_channel();
    tokio::spawn(async move {
        let mut last_sent_message: Option<Value> = None;
        loop {
            let socket = TcpStream::connect(hostname.clone()).await;
            // Reconnection logic
            if socket.is_err() {
                warn!("Cannot connect to {}. {:?}", hostname.clone(), socket.err().unwrap());
                // TODO: Use less aggressive reconnection strategy
                sleep(Duration::from_secs(1)).await;
                continue;
            }

            let socket = socket.unwrap();
            let length_delimited = FramedWrite::new(socket, LengthDelimitedCodec::new());
            let mut serialized = tokio_serde::SymmetricallyFramed::new(length_delimited, SymmetricalJson::default());

            // After reconnection resend, the last attempted message
            if let Some(v) = &last_sent_message {
                let send = serialized.send(v.clone()).await;
                if send.is_ok() {
                    last_sent_message = None;
                } else {
                    // Send failed so go back to the reconnection loop
                    continue;
                }
            }

            while let Some(msg) = peer_receiver.recv().await {
                let json = serde_json::to_value(msg.clone());
                match json {
                    Ok(v) => {
                        last_sent_message = Some(v.clone());
                        let send = serialized.send(v).await;
                        if send.is_err() {
                            // Send failed so go back to the reconnection loop
                            break;
                        }
                    }
                    Err(e) => {
                        // This is a critical issue where it is not possible to send a PBFT event
                        // over the network.
                        panic!("Failed to serialize message! {:?}\n{:?}", e, msg);
                    }
                }
            }

        }
    });

    peer_sender
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedPBFTEvent<O>
    where O: ServiceOperation
{
    pub event: PBFTEvent<O>,
    from: PeerId,
    signature: Option<SignatureResult>,
}

impl<O> WrappedPBFTEvent<O>
    where O: ServiceOperation
{
    pub fn is_valid(&self) -> bool {
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

type Peers = Vec<Peer>;

// TODO: Implement rebroadcasting to subvert byzantine peers
impl<O> CommunicationProxy<O>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    pub async fn new(myself: Peer, peers: Peers) -> Self {
        // Index peers
        let mut participants = vec![myself.clone()];
        let (proxy_sender, proxy_receiver) = unbounded_channel();

        // Set up server to listen for incoming messages. These messages are then rerouted to the proxy receiver
        let hostname = myself.hostname.clone();
        tokio::spawn(async move {
            listen_for_events(hostname, proxy_sender).await;
        });

        // Connect to all peers
        let mut peer_db = HashMap::new();
        for p in peers.into_iter() {
            // TODO: Validate peer data at this point (eg. check duplication)
            participants.push(p.clone());

            // Connect to the peer and get a handle on sending messages to this peer
            let peer_sender = connect_to(p.hostname.clone()).await;
            peer_db.insert(p.id.clone(), (p, peer_sender));
        }

        participants.sort_by_key(|p| p.id.clone());
        CommunicationProxy {
            myself,
            indexed_participants: participants,
            peer_db,
            receiver_multiplexer: proxy_receiver,
        }
    }

    pub async fn recv_event(&mut self) -> Option<WrappedPBFTEvent<O>> {
        self.receiver_multiplexer.recv().await
    }

    pub fn wrap(&self, event: &PBFTEvent<O>) -> WrappedPBFTEvent<O> {
        // TODO: Compute digital signature
        WrappedPBFTEvent {
            event: event.clone(),
            from: "".to_string(),
            signature: None,
        }
    }

    pub fn broadcast(&self, event: PBFTEvent<O>) {
        for (p, s) in self.peer_db.values() {
            // TODO: Handle send error
            let _ = s.send(self.wrap(&event));
        }
    }

    pub fn send(&self, to: PeerIndex, event: PBFTEvent<O>) {
        if to as usize >= self.indexed_participants.len() {
            panic!("Peer {} is not valid!", to);
        }
        let peer = self.indexed_participants.get(to as usize).unwrap();
        let sender = &self.peer_db.get(&peer.id).unwrap().1;

        // TODO: Handle send error
        let _ = sender.send(self.wrap(&event));
    }

    pub fn num_peers(&self) -> usize {
        self.peer_db.len()
    }

    pub fn my_index(&self) -> PeerIndex {
        self.indexed_participants.iter().position(|p| p.id == self.myself.id).unwrap() as PeerIndex
    }
}