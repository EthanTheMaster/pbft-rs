use std::env;
use std::path::PathBuf;
use std::time::Duration;
use log::{info, LevelFilter};
use pbft_library::pbft_replica::*;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use tokio::select;
use tokio::time::interval;

// Mock custom operation for state machine to be replicated
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Operation {
    Some(String),
    None
}

impl Digestible for Operation {
    fn digest(&self) -> DigestResult {
        let mut res = [0; DIGEST_LENGTH_BYTES];
        let mut hasher = Sha3_256::new();
        match self {
            Operation::Some(m) => {
                hasher.update(b"Some");
                hasher.update(m.as_bytes());
                let hash = &hasher.finalize()[..];
                res.copy_from_slice(hash);
            }
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

// cargo run --release --example spawn_test_instance ./replica-test-config/replicaN/replica_config.json REPLICA-NAME
#[tokio::main]
async fn main() {
    // Enable logging
    simple_logger::SimpleLogger::new().env().with_level(LevelFilter::Info).init().unwrap();
    // simple_logger::SimpleLogger::new().env().init().unwrap();

    let args: Vec<String> = env::args().collect();
    if args.len() <= 2 {
        panic!("Usage: path-to-replica-config replica-name")
    }

    let config_path = args.get(1).unwrap();
    let replica_name = args.get(2).unwrap();
    let mut replica: PBFTReplica<Operation> = PBFTReplica::launch(PathBuf::from(config_path));

    let mut counter = 0;
    let mut interval = interval(Duration::from_millis(10000));
    loop {
        select! {
            _ = interval.tick() => {
                replica.send(Operation::Some(format!("{}:{}", replica_name, counter)));
                counter += 1;
            }
            op = replica.recv() => {
                info!("📝 Received: {:?}", op);
            }
        };
    }
}