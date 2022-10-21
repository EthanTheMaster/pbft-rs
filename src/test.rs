use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use crate::pbft_replica::{DIGEST_LENGTH_BYTES, Digestible, DigestResult, NoOp, PBFTReplica};

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

#[tokio::test]
async fn test_replica_normal_operation() {
    let replica0: PBFTReplica<Operation> = PBFTReplica::launch(PathBuf::from("./replica-test-config/replica0/replica_config.json"));
    let replica1: PBFTReplica<Operation> = PBFTReplica::launch(PathBuf::from("./replica-test-config/replica1/replica_config.json"));
    let replica2: PBFTReplica<Operation> = PBFTReplica::launch(PathBuf::from("./replica-test-config/replica2/replica_config.json"));
    let replica3: PBFTReplica<Operation> = PBFTReplica::launch(PathBuf::from("./replica-test-config/replica3/replica_config.json"));

    let msg0 = "HelloWorld0".to_string();
    let msg1 = "HelloWorld1".to_string();
    let msg2 = "HelloWorld2".to_string();
    let msg3 = "HelloWorld3".to_string();

    replica0.send(Operation::Some(msg0.clone()));
    replica1.send(Operation::Some(msg1.clone()));
    replica2.send(Operation::Some(msg2.clone()));
    replica3.send(Operation::Some(msg3.clone()));

    for mut replica in vec![replica0, replica1, replica2, replica3] {
        assert_eq!(replica.recv().await, Operation::Some(msg0.clone()));
        assert_eq!(replica.recv().await, Operation::Some(msg1.clone()));
        assert_eq!(replica.recv().await, Operation::Some(msg2.clone()));
        assert_eq!(replica.recv().await, Operation::Some(msg3.clone()));
    }
}