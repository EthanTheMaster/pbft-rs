use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use ed25519_compact::{Noise, PublicKey, SecretKey, Signature};
use futures::{SinkExt, TryStreamExt};
use log::{debug, info, warn};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use crate::kernel::PBFTEvent;
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_serde::formats::SymmetricalJson;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use crate::pbft_replica::ServiceOperation;
use crate::service_state::StateTransferRequest;

type SignatureResult = Vec<u8>;

pub type PeerId = String;
pub type PeerIndex = u64;

#[derive(Clone)]
pub struct Peer {
    // TODO: Make id generic and sortable to assign total order to list of peers
    pub id: PeerId,
    pub hostname: String,
    pub signature_public_key: PublicKey,
}

pub struct Configuration {
    pub peers: Vec<Peer>,
    pub this_replica: Peer,
    pub signature_secret_key: SecretKey,
    pub reconnection_delay: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPayload {
    pub from: PeerId,
    pub serialized_event: String,
    pub signature: SignatureResult,
}

impl SignedPayload {
    pub fn is_valid(&self, peer_public_key: &PublicKey) -> bool {
        let signature = Signature::from_slice(self.signature.as_slice());
        match signature {
            Ok(signature) => {
                peer_public_key.verify(self.serialized_event.as_bytes(), &signature).is_ok()
            }
            Err(_) => {
                false
            }
        }
    }
}

#[derive(Clone, Debug)]
// A wrapped PBFT event is a wrapper for a PBFT event that also includes
// a proof showing that the contained event was indeed sent by the sender.
//
// Wrapping an event is an abstraction indicating that the wrapped event
// has been validated for correctness.
pub struct WrappedPBFTEvent<O>
    where O: ServiceOperation
{
    witness: SignedPayload,
    pub event: PBFTEvent<O>,
}

impl<O> WrappedPBFTEvent<O>
    where O: ServiceOperation
{
    pub fn witness(&self) -> &SignedPayload {
        &self.witness
    }

    // Signed payload could be adversarially chosen and needs to be thoroughly validated before converted into
    // a wrapped event.
    pub fn from_signed_payload<Op>(
        payload: SignedPayload,
        peer_db: &HashMap<PeerId, (PeerIndex, Peer)>,
    ) -> Result<WrappedPBFTEvent<Op>, String>
        where Op: ServiceOperation + DeserializeOwned
    {
        let peer_info = &peer_db.get(&payload.from);
        if peer_info.is_none() {
            return Err(format!("Received signed payload from unknown peer. {:?}", payload));
        }
        let (peer_index, peer) = &peer_info.unwrap();
        if !payload.is_valid(&peer.signature_public_key) {
            return Err(format!("Received payload with invalid signature! {:?}", payload));
        }

        // Payload is valid ... attempt to deserialize it into an PBFTEvent
        let event = serde_json::from_str::<PBFTEvent<Op>>(&payload.serialized_event);
        if event.is_err() {
            return Err(format!("Failed to deserialize payload event. {:?}", payload));
        }

        // Validate the contents of the event
        let event = event.unwrap();
        match &event {
            PBFTEvent::Request(request) => {
                if !request.is_valid() {
                    return Err(format!("Request operation digest is not valid!. {:?}", event));
                }
            }
            PBFTEvent::PrePrepare { from, data: _data, request } => {
                if from != peer_index {
                    return Err(format!("Preprepare and payload do not have matching sender. {:?}", event));
                }
                if !request.is_valid() {
                    return Err(format!("Request operation digest is not valid!. {:?}", event));
                }
            }
            PBFTEvent::Prepare { from, data: _data } => {
                if from != peer_index {
                    return Err(format!("Prepare and payload do not have matching sender. {:?}", event));
                }
            }
            PBFTEvent::Commit { from, data: _data } => {
                if from != peer_index {
                    return Err(format!("Prepare and payload do not have matching sender. {:?}", event));
                }
            }
            PBFTEvent::Checkpoint { from, data: _data } => {
                if from != peer_index {
                    return Err(format!("Prepare and payload do not have matching sender. {:?}", event));
                }
            }
            PBFTEvent::ViewChange(change) => {
                if &change.from != peer_index {
                    return Err(format!("View change and payload do not have matching sender. {:?}", event));
                }
            }
            PBFTEvent::NewView(new_view) => {
                if &new_view.from != peer_index {
                    return Err(format!("New view and payload do not have matching sender. {:?}", event));
                }
            }
            PBFTEvent::StateTransferRequest(req) => {
                match req {
                    StateTransferRequest::ViewChangeDigestProof { from, sequence_number: _sequence_number, digest: _digest } => {
                        if from != peer_index {
                            return Err(format!("ViewChangeDigestProof and payload do not have matching sender. {:?}", event));
                        }
                    }
                    StateTransferRequest::ServiceStateItemProof { from, log_length: _log_length, log_item_index: _log_item_index } => {
                        if from != peer_index {
                            return Err(format!("ServiceStateItemProof and payload do not have matching sender. {:?}", event));
                        }
                    }
                }
            }
            PBFTEvent::StateTransferResponse(_) => {}
        }

        Ok(WrappedPBFTEvent {
            witness: payload,
            event,
        })
    }
}

// Listens for incoming events and forwards them to the proxy sender
async fn listen_for_events<O>(
    hostname: String,
    proxy_sender: UnboundedSender<WrappedPBFTEvent<O>>,
    peer_db: HashMap<PeerId, (PeerIndex, Peer)>,
)
    where O: ServiceOperation + DeserializeOwned + std::marker::Send + 'static
{
    let proxy_sender = proxy_sender.clone();
    let listener = TcpListener::bind(hostname.clone()).await.unwrap();
    info!("Listening on {}", hostname);

    let acceptable_peer_ip = peer_db.values()
        .filter_map(|(_, peer)| {
            match peer.hostname.to_socket_addrs() {
                Ok(addrs) => { Some(addrs) }
                Err(_) => { None }
            }
        })
        .flatten()
        .map(|addr| {
            addr.ip()
        })
        .collect::<HashSet<IpAddr>>();

    loop {
        if proxy_sender.is_closed() {
            // Channel has been broken ... don't attempt to send data down this channel
            break;
        }

        let (socket, _) = listener.accept().await.unwrap();
        // Only accept incoming connections from peer list. Do not accept connections from non-peers
        let is_peer = socket.peer_addr().map_or(false, |addr| acceptable_peer_ip.contains(&addr.ip()));
        if !is_peer {
            info!("Dropping connection with {:?} who is not registered as a peer.", socket.peer_addr());
            break;
        }

        let length_delimited = FramedRead::new(socket, LengthDelimitedCodec::new());

        let mut deserialized = tokio_serde::SymmetricallyFramed::new(length_delimited, SymmetricalJson::<Value>::default());

        let proxy_sender = proxy_sender.clone();
        let peer_db_clone = peer_db.clone();
        tokio::spawn(async move {
            while let Some(msg) = deserialized.try_next().await.unwrap() {
                let payload = serde_json::from_value::<SignedPayload>(msg);
                if payload.is_err() {
                    debug!("Failed to deserialize signed payload.");
                    continue;
                }
                let payload = payload.unwrap();
                match WrappedPBFTEvent::<O>::from_signed_payload(payload, &peer_db_clone) {
                    Ok(e) => {
                        let send = proxy_sender.send(e);
                        if send.is_err() {
                            // Channel has been broken
                            return;
                        }
                    }
                    Err(err) => {
                        // The payload could not be validated
                        info!("{}", err);
                        continue;
                    }
                }
            }
        });
    }
}

// Connects to a peer at the given hostname and returns a handle allowing the proxy to send messages
// to this peer
async fn connect_to<'de, O>(hostname: String, reconnection_delay: Duration) -> UnboundedSender<WrappedPBFTEvent<O>>
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
                sleep(reconnection_delay).await;
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
                let signed_payload_json = serde_json::to_value(msg.witness());
                match signed_payload_json {
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

pub struct CommunicationProxy<O>
    where O: ServiceOperation
{
    myself: Peer,
    signature_secret_key: SecretKey,

    indexed_participants: Vec<Peer>,
    peer_db: HashMap<PeerId, (PeerIndex, Peer)>,
    peer_senders: HashMap<PeerId, UnboundedSender<WrappedPBFTEvent<O>>>,
    // Combines all receivers into a single stream
    receiver_multiplexer: UnboundedReceiver<WrappedPBFTEvent<O>>,
    dev_is_byzantine: bool
}

// TODO: Implement rebroadcasting to subvert byzantine peers
impl<O> CommunicationProxy<O>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    pub async fn new(configuration: Configuration) -> Self {
        let myself = configuration.this_replica;
        let peers = configuration.peers;

        let (proxy_sender, proxy_receiver) = unbounded_channel();

        // Index peers
        let mut participants = vec![myself.clone()];
        participants.extend_from_slice(&peers);
        participants.sort_by_key(|p| p.id.clone());

        // Set up server to listen for incoming messages. These messages are then rerouted to the proxy receiver
        let hostname = myself.hostname.clone();
        let peer_db: HashMap<PeerId, (PeerIndex, Peer)> = participants.iter()
            .enumerate()
            .map(|(i, p)| {
                (p.id.clone(), (i as PeerIndex, p.clone()))
            })
            .collect();

        let peer_db_clone = peer_db.clone();
        tokio::spawn(async move {
            listen_for_events(hostname, proxy_sender, peer_db_clone).await;
        });

        // Connect to all peers
        let mut peer_senders = HashMap::new();
        for p in peers.iter() {
            // Connect to the peer and get a handle on sending messages to this peer
            let peer_sender = connect_to(
                p.hostname.clone(),
                configuration.reconnection_delay,
            ).await;
            peer_senders.insert(p.id.clone(), peer_sender);
        }

        CommunicationProxy {
            myself,
            signature_secret_key: configuration.signature_secret_key,
            indexed_participants: participants,
            peer_db,
            peer_senders,
            receiver_multiplexer: proxy_receiver,
            dev_is_byzantine: false
        }
    }

    pub async fn recv_event(&mut self) -> Option<WrappedPBFTEvent<O>> {
        self.receiver_multiplexer.recv().await
    }

    // Generates a digital signature of a PBFT event
    pub fn wrap(&self, event: &PBFTEvent<O>) -> WrappedPBFTEvent<O> {
        // If unwrap fails, that is a serious issue that needs to be fixed as protocol can't function without
        // proper serialization of PBFT events
        let serialized_event = serde_json::to_string(event).unwrap();
        let signature = self.signature_secret_key.sign(serialized_event.as_bytes(), Some(Noise::generate()));
        WrappedPBFTEvent {
            witness: SignedPayload {
                from: self.myself.id.clone(),
                serialized_event,
                signature: signature.as_ref().to_vec(),
            },
            event: event.clone(),
        }
    }

    pub fn broadcast(&self, mut event: PBFTEvent<O>) {
        // We don't want to keep recomputing the digital signature which is costly.
        let packaged_event = self.wrap(&event);
        for s in self.peer_senders.values() {
            // Perturb protocol message about to be sent if the replica is configured to be byzantine
            let packaged_event = if !self.dev_is_byzantine {
                packaged_event.clone()
            } else {
                event.mutate();
                self.wrap(&event)
            };
            // TODO: Handle send error
            let _ = s.send(packaged_event);
        }
    }

    pub fn send(&self, to: PeerIndex, mut event: PBFTEvent<O>) {
        if to as usize >= self.indexed_participants.len() {
            panic!("Peer {} is not valid!", to);
        }
        let peer = self.indexed_participants.get(to as usize).unwrap();
        let sender = &self.peer_senders.get(&peer.id).unwrap();

        // Perturb protocol message about to be sent if the replica is configured to be byzantine
        let packaged_event = if !self.dev_is_byzantine {
            self.wrap(&event)
        } else {
            event.mutate();
            self.wrap(&event)
        };
        // TODO: Handle send error
        let _ = sender.send(packaged_event);
    }

    pub fn num_participants(&self) -> usize {
        self.peer_db.len()
    }

    pub fn my_index(&self) -> PeerIndex {
        self.indexed_participants.iter().position(|p| p.id == self.myself.id).unwrap() as PeerIndex
    }

    pub fn validate_signed_payload(&self, payload: SignedPayload) -> Result<WrappedPBFTEvent<O>, String> {
        let res = WrappedPBFTEvent::<O>::from_signed_payload(payload, &self.peer_db);
        if let Err(e) = &res {
            info!("{:?}", e);
        }
        res
    }

    // Developer tool to make a PBFT replica malfunction. This feature must be explictly enabled
    // through this function.
    //
    // This is should only be used for testing not production!
    pub fn dev_is_byzantine(&mut self, is_byzantine: bool) {
        if is_byzantine {
            warn!("BYZANTINE BEHAVIOR FOR THE REPLICA HAS BEEN ENABLED. USE THIS ONLY FOR TESTING.")
        }
        self.dev_is_byzantine = is_byzantine;
    }
}