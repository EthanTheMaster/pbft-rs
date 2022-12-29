use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use pbft_library::pbft_replica::*;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use tokio::select;
use tokio::time::interval;

const TARGET_NUMBER_OPS: usize = 1000;

const NUMBER_REPLICA: usize = 4;
const CONFIG_LOCATION: &str = "/tmp/pbft-benchmark";
const BIND_ADDR: &str = "127.0.0.1";
const PORT_BASE: usize = 8000;

#[tokio::main]
async fn main() {
    // simple_logger::SimpleLogger::new().env().init().unwrap();
    println!("Setting up configuration files...");
    setup_config_files();
    println!("Networking the replicas...");
    network_replicas();
    println!("Launching replicas ...");
    run_benchmark().await;
}

fn setup_config_files() {
    let config_location = PathBuf::from(CONFIG_LOCATION);
    // Remove any past benchmarks
    let _ = fs::remove_dir_all(config_location.as_path());
    // Make the replica configuration directory
    let _ = fs::create_dir(config_location.as_path());
    // Generate replica configuration skeletons
    for i in 0..NUMBER_REPLICA {
        let mut peer_path = config_location.clone();
        peer_path.push(format!("Peer{}", i));
        let _ = fs::create_dir(peer_path.as_path());

        generate_config_skeleton(peer_path);
    }
}

fn deserialize_config(config: &Path) -> ReplicaConfiguration {
    let mut config_file = File::open(config).unwrap();
    let mut config_json = String::new();
    config_file.read_to_string(&mut config_json).unwrap();
    return serde_json::from_str::<ReplicaConfiguration>(config_json.as_str()).unwrap();
}

fn serialize_config(config_path: &Path, config: &ReplicaConfiguration) {
    let mut config_file = File::options()
        .write(true)
        .append(false)
        .open(config_path).unwrap();
    let json = serde_json::to_string_pretty(&config).unwrap();
    config_file.write_all(json.as_bytes()).unwrap();
}

fn network_replicas() {
    // Import the replica data
    let config_location = PathBuf::from(CONFIG_LOCATION);
    let mut configurations: Vec<ReplicaConfiguration> = (0..NUMBER_REPLICA)
        .map(|i| {
            let mut peer_config = config_location.clone();
            peer_config.push(format!("Peer{}/replica_config.json", i));
            deserialize_config(&peer_config)
        })
        .collect();

    // Configure all the replicas
    for (i, config) in configurations.iter_mut().enumerate() {
        config.replica_id = format!("Peer{}", i);
        config.hostname = format!("{}:{}", BIND_ADDR, PORT_BASE + i);
        // Adjust these parameters as see fit for benchmarking
        config.pbft_protocol_config = PBFTProtocolConfiguration {
            log_length: 50,
            checkpoint_interval: 10,
            execution_timeout_ms: 5000,
            view_stay_timeout_ms: 30000,
            view_change_timeout_ms: 5000,
            view_change_retransmission_interval_ms: 2000,
            reconnection_delay_ms: 2000
        };

        // Network with the peers
        config.peers = Vec::new();
        for j in 0..NUMBER_REPLICA {
            if j != i {
                let mut peer_config = config_location.clone();
                peer_config.push(format!("Peer{}/replica_public_key.pem", j));
                config.peers.push(Replica {
                    id: format!("Peer{}", j),
                    hostname: format!("{}:{}", BIND_ADDR, PORT_BASE + j),
                    signature_public_key_pem: peer_config.to_str().unwrap().to_string()
                })
            }
        }

        // Serialize back the configuration information
        let mut peer_config = config_location.clone();
        peer_config.push(format!("Peer{}/replica_config.json", i));
        serialize_config(&peer_config, config);
    }

}

// Mock custom operation for state machine to be replicated
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Operation {
    Some,
    None
}

impl Digestible for Operation {
    fn digest(&self) -> DigestResult {
        let mut res = [0; DIGEST_LENGTH_BYTES];
        let mut hasher = Sha3_256::new();
        match self {
            Operation::Some => {
                hasher.update(b"Some");
                let hash = &hasher.finalize()[..];
                res.copy_from_slice(hash);

            },
            Operation::None => {
                hasher.update(b"None");
                let hash = &hasher.finalize()[..];
                res.copy_from_slice(hash);

            }
        }
        res
    }
}

impl NoOp for Operation {
    fn noop() -> Self {
        Operation::None
    }
}

async fn run_benchmark() {
    let config_location = PathBuf::from(CONFIG_LOCATION);

    // Launch all the replicas
    let mut monitor: Option<PBFTReplica<Operation>> = None;
    for i in 0..NUMBER_REPLICA {
        let mut peer_config = config_location.clone();
        peer_config.push(format!("Peer{}/replica_config.json", i));
        let replica: PBFTReplica<Operation> = PBFTReplica::launch(peer_config);
        monitor = Some(replica);
    }

    let mut monitor = monitor.unwrap();
    let mut interval = interval(Duration::from_secs(1));

    let start = Instant::now();
    // Send an operation to kick start the test
    monitor.send(Operation::Some);
    let mut commit_times = Vec::new();
    loop {
        select! {
            _ = monitor.recv() => {
                commit_times.push(Instant::now());
                if commit_times.len() == TARGET_NUMBER_OPS {
                    break
                }
                // Send an operation after detecting a message has been committed
                monitor.send(Operation::Some);
            }
            _ = interval.tick() => {
                // Ensure liveliness in case some operations are dropped
                monitor.send(Operation::Some);
            }
        }
    }

    analyze_commit_times(&start, &commit_times);
}

fn analyze_commit_times(start: &Instant, commit_times: &Vec<Instant>) {
    println!("Total Number Of Operations Executed: {}", commit_times.len());
    let test_duration = *commit_times.last().unwrap() - *start;
    println!("Total Time: {} ms", test_duration.as_millis());
    let avg_execution_time_secs = test_duration.as_secs_f64() / commit_times.len() as f64;
    println!("Average Operation Execution Time: {} ms", avg_execution_time_secs * 1000.0);

    let mut deltas = Vec::new();
    let mut prev = start;
    for t in commit_times.iter() {
        deltas.push(*t - *prev);
        prev = t;
    }
    deltas.sort();

    println!("Execution Time 1%-tile: {} ms", deltas[deltas.len() / 100].as_millis());
    println!("Execution Time 25%-tile: {} ms", deltas[deltas.len() * 25 / 100].as_millis());
    println!("Execution Time 50%-tile: {} ms", deltas[deltas.len() * 50 / 100].as_millis());
    println!("Execution Time 75%-tile: {} ms", deltas[deltas.len() * 75 / 100].as_millis());
    println!("Execution Time 99%-tile: {} ms", deltas[deltas.len() * 99 / 100].as_millis());

}