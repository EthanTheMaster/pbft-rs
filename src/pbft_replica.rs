use std::fmt::Debug;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use ed25519_compact::{KeyPair, PublicKey, SecretKey, Seed};
use serde::de::DeserializeOwned;
use serde::{Serialize, Deserialize};
use tokio::select;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use log::warn;
use crate::communication_proxy::{CommunicationProxy, Configuration, Peer, PeerId};
use crate::kernel::PBFTState;
use crate::kernel::view_change_manager::ViewChangeManager;

const PUBLIC_KEY_PEM: &str = "replica_public_key.pem";
const SECRET_KEY_PEM: &str = "replica_secret_key.pem";
const REPLICA_CONFIG: &str = "replica_config.json";

pub const DIGEST_LENGTH_BYTES: usize = 32;
pub type DigestResult = [u8; DIGEST_LENGTH_BYTES];

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

#[derive(Serialize, Deserialize)]
pub struct PBFTProtocolConfiguration {
    // TODO: Validate log_length >= checkpoint_interval
    log_length: usize,
    checkpoint_interval: usize,
    // Deadline assigned for a request to be executed before a view change occurs
    execution_timeout_ms: usize,
    // The amount of time to remain in an active view before view changing
    view_stay_timeout_ms: usize,
    // Deadline assigned for a view with enough participants to successfully view change
    view_change_timeout_ms: usize,
    // The delay between each view change retransmission
    view_change_retransmission_interval_ms: usize,
    // The delay waited before a reconnection attempt is made to a dropped peer
    reconnection_delay_ms: usize,
}

#[derive(Serialize, Deserialize)]
pub struct Replica {
    id: PeerId,
    hostname: String,
    signature_public_key_pem: String
}

#[derive(Serialize, Deserialize)]
pub struct ReplicaConfiguration {
    peers: Vec<Replica>,
    replica_id: PeerId,
    hostname: String,
    signature_public_key_pem: String,
    signature_secret_key_pem: String,
    pbft_protocol_config: PBFTProtocolConfiguration,
    dev_is_byzantine: bool
}

pub struct PBFTReplica<O>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    request_sender: UnboundedSender<O>,
    state_change_subscriber: UnboundedReceiver<O>
}

fn create_pk_from_pem_files(pk_pem: &Path) -> Option<PublicKey> {
    let f = File::open(pk_pem);
    if f.is_err() {
        return None;
    }
    let mut f = f.unwrap();
    let mut pk_content = String::new();
    let read = f.read_to_string(&mut pk_content);
    if read.is_err() {
        return None;
    }

    let res = PublicKey::from_pem(pk_content.as_str());
    if res.is_err() {
        return None;
    }

    Some(res.unwrap())
}

fn create_sk_from_pem_files(sk_pem: &Path) -> Option<SecretKey> {
    let f = File::open(sk_pem);
    if f.is_err() {
        return None;
    }
    let mut f = f.unwrap();
    let mut sk_content = String::new();
    let read = f.read_to_string(&mut sk_content);
    if read.is_err() {
        return None;
    }

    let res = SecretKey::from_pem(sk_content.as_str());
    if res.is_err() {
        return None;
    }

    Some(res.unwrap())
}

impl<O> PBFTReplica<O>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    // Launches a PBFT replica instance given json replica configuration
    // Returns a handle to send operation requests and a handle to receive
    // operations finalized/"executed" in message log
    pub fn launch(config_json_path: PathBuf) -> PBFTReplica<O> {
        // Read config json
        let mut config_file = File::open(config_json_path.as_path()).unwrap();
        let mut config_json = String::new();
        config_file.read_to_string(&mut config_json).unwrap();

        // Deserialize the configuration
        let config = serde_json::from_str::<ReplicaConfiguration>(config_json.as_str()).unwrap();

        // Validate the configuration
        if config.pbft_protocol_config.log_length < config.pbft_protocol_config.checkpoint_interval {
            panic!("The log length must be at least the checkpoint interval.");
        }

        // This channel is used to forward incoming message requests to the PBFT state being driven
        // by a tokio task
        let (request_sender, request_receiver) = unbounded_channel();

        // This channel is used to listen for included, finalized messages
        let (state_change_publisher, state_change_subscriber) = unbounded_channel();

        tokio::spawn(async move {
            let peers = config.peers.iter()
                .map(|r| {
                    Peer {
                        id: r.id.clone(),
                        hostname: r.hostname.clone(),
                        signature_public_key: create_pk_from_pem_files(Path::new(&r.signature_public_key_pem)).unwrap()
                    }
                })
                .collect();
            let mut communication_proxy: CommunicationProxy<O> = CommunicationProxy::new(Configuration {
                peers,
                this_replica: Peer {
                    id: config.replica_id.clone(),
                    hostname: config.hostname.clone(),
                    signature_public_key: create_pk_from_pem_files(Path::new(&config.signature_public_key_pem)).unwrap()
                },
                signature_secret_key: create_sk_from_pem_files(Path::new(&config.signature_secret_key_pem)).unwrap(),
                reconnection_delay: Duration::from_millis(config.pbft_protocol_config.reconnection_delay_ms as u64),
            }).await;
            // Configuration to be byzantine must be explicitly enabled and will generate a warning
            communication_proxy.dev_is_byzantine(config.dev_is_byzantine);

            let view_change_manager = ViewChangeManager::new(Duration::from_millis(config.pbft_protocol_config.view_stay_timeout_ms as u64));
            let mut pbft = PBFTState::new(
                view_change_manager,
                communication_proxy,
                state_change_publisher,
                Duration::from_millis(config.pbft_protocol_config.execution_timeout_ms as u64),
                Duration::from_millis(config.pbft_protocol_config.view_change_timeout_ms as u64),
                Duration::from_millis(config.pbft_protocol_config.view_change_retransmission_interval_ms as u64),
                config.pbft_protocol_config.log_length as u64,
                config.pbft_protocol_config.checkpoint_interval as u64
            );

            // Drive the PBFT state
            let mut request_receiver = request_receiver;
            loop {
                select! {
                    req = request_receiver.recv() => {
                        if req.is_none() {
                            warn!("Request receiver closed.");
                            break;
                        }
                        let req = req.unwrap();
                        pbft.broadcast_request(req);
                    }
                    _ = pbft.step() => {}
                }
            }

        });


        PBFTReplica {
            request_sender,
            state_change_subscriber
        }
    }

    pub fn send(&self, op: O) {
        self.request_sender.send(op).unwrap();
    }

    pub async fn recv(&mut self) -> O {
        self.state_change_subscriber.recv().await.unwrap()
    }
}

pub fn generate_config_skeleton(destination_dir: PathBuf) {
    let keypair = KeyPair::from_seed(Seed::generate());
    let pk_pem = keypair.pk.to_pem();
    let sk_pem = keypair.sk.to_pem();

    // Generate key pair files
    let mut pk_pem_path = destination_dir.clone();
    pk_pem_path.push(PUBLIC_KEY_PEM);
    let mut pk_pem_file = File::create(pk_pem_path.as_path()).unwrap();
    pk_pem_file.write_all(pk_pem.as_bytes()).unwrap();

    let mut sk_pem_path = destination_dir.clone();
    sk_pem_path.push(SECRET_KEY_PEM);
    let mut sk_pem_file = File::create(sk_pem_path.as_path()).unwrap();
    sk_pem_file.write_all(sk_pem.as_bytes()).unwrap();

    // Generate configuration template
    let skeleton = ReplicaConfiguration {
        peers: vec![Replica {
            id: "PeerId".to_string(),
            hostname: "peer_address:port".to_string(),
            signature_public_key_pem: "path_to_peer_public_key_pem".to_string()
        }],
        replica_id: "replica_id".to_string(),
        hostname: "127.0.0.1:8888".to_string(),
        signature_public_key_pem: pk_pem_path.to_str().unwrap().to_string(),
        signature_secret_key_pem: sk_pem_path.to_str().unwrap().to_string(),
        pbft_protocol_config: PBFTProtocolConfiguration {
            log_length: 50,
            checkpoint_interval: 10,
            execution_timeout_ms: 5000,
            view_stay_timeout_ms: 30000,
            view_change_timeout_ms: 10000,
            view_change_retransmission_interval_ms: 2000,
            reconnection_delay_ms: 2000
        },
        // To make a replica byzantine, the user must explicitly enable this dangerous feature
        dev_is_byzantine: false
    };

    let skeleton_json = serde_json::to_string_pretty(&skeleton).unwrap();

    let mut config_path = destination_dir;
    config_path.push(REPLICA_CONFIG);
    let mut config_file = File::create(config_path.as_path()).unwrap();
    config_file.write_all(skeleton_json.as_bytes()).unwrap();
}
