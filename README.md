# Introduction
This project is a toy library implementation of the Practical Byzantine Fault Tolerance (PBFT) consensus algorithm for my CS 482 senior project at Christian Brothers University. It follows the description in [Practical Byzantine Fault Tolerance
and Proactive Recovery by Castro and Liskov](https://pmg.csail.mit.edu/papers/bft-tocs.pdf). The implementation was written in Rust with the `tokio` library for asynchronous networking. 

This PBFT library seeks to enable any arbitrary deterministic service to be distributed and replicated in a fault tolerant way even when arbitrarily malicious participants are present. It accomplishes this by replicating a log of operations that can be used to recover the state of a service. Safe replication is possible when the number of faulty participants is no more than 1/3 the total number of participants. 

# Demo
We can build the project with
```bash
cargo build --release
```

The `replica-test-config/` directory contains all the configuration information for 4 participants in a test network. Each participant, which we call a replica, is configured with a public-secret key pair to enable digital signatures and a configuration file to specify how the replica operates within the PBFT protocol. The `examples/spawn_test_instance.rs` binary sets up a toy instance of PBFT where each participant periodically shouts a message to be included into the replicated log of operations. The binary also specifies how these announced "operations" are hashed for proper inclusion into the log. For technical reasons, a no-op operation must also be included and separated from all other operations. 

In 4 separate terminal instances, run
```bash
# Terminal 1
cargo run --release --example spawn_test_instance ./replica-test-config/replica0/replica_config.json Peer0
# Terminal 2
cargo run --release --example spawn_test_instance ./replica-test-config/replica1/replica_config.json Peer1
# Terminal 3
cargo run --release --example spawn_test_instance ./replica-test-config/replica2/replica_config.json Peer2
# Terminal 4
cargo run --release --example spawn_test_instance ./replica-test-config/replica3/replica_config.json Peer3
```
to simulate 4 separate running PBFT participants. Each participant looks to its respective `replica_config.json` file to configure itself into the PBFT protocol. In these 4 windows, you might see something resembling
```
2023-02-16T16:03:05.340Z INFO [pbft_library::kernel::view_change] Peer 0: Successfully moved into view 1.                                                                                            
2023-02-16T16:03:05.368Z INFO [spawn_test_instance] 📝 Received: Some("Peer0:0")                                                                                                                     
2023-02-16T16:03:05.368Z INFO [spawn_test_instance] 📝 Received: Some("Peer1:0")
2023-02-16T16:03:07.074Z INFO [spawn_test_instance] 📝 Received: Some("Peer1:2")
2023-02-16T16:03:10.300Z INFO [spawn_test_instance] 📝 Received: Some("Peer2:1")
2023-02-16T16:03:13.052Z INFO [spawn_test_instance] 📝 Received: Some("Peer0:3")
2023-02-16T16:03:14.279Z INFO [spawn_test_instance] 📝 Received: Some("Peer3:1")
2023-02-16T16:03:17.074Z INFO [spawn_test_instance] 📝 Received: Some("Peer1:3")
2023-02-16T16:03:20.300Z INFO [spawn_test_instance] 📝 Received: Some("Peer2:2")
2023-02-16T16:03:23.051Z INFO [spawn_test_instance] 📝 Received: Some("Peer0:4")
2023-02-16T16:03:24.280Z INFO [spawn_test_instance] 📝 Received: Some("Peer3:2")
2023-02-16T16:03:27.071Z INFO [spawn_test_instance] 📝 Received: Some("Peer1:4")
2023-02-16T16:03:30.301Z INFO [spawn_test_instance] 📝 Received: Some("Peer2:3")
2023-02-16T16:03:33.051Z INFO [spawn_test_instance] 📝 Received: Some("Peer0:5")
2023-02-16T16:03:34.279Z INFO [spawn_test_instance] 📝 Received: Some("Peer3:3")
2023-02-16T16:03:35.387Z INFO [pbft_library::kernel::view_change] Peer 0: Successfully moved into view 2.
2023-02-16T16:03:37.076Z INFO [spawn_test_instance] 📝 Received: Some("Peer1:5")
2023-02-16T16:03:40.299Z INFO [spawn_test_instance] 📝 Received: Some("Peer2:4")
2023-02-16T16:03:43.051Z INFO [spawn_test_instance] 📝 Received: Some("Peer0:6")
2023-02-16T16:03:44.275Z INFO [spawn_test_instance] 📝 Received: Some("Peer3:4")
...
```

Feel free to choose any terminal window and shut down the running participant. You may also reengage that participant any time. Looking into your chosen participant's `replica_config.json`, you can also activate `dev_is_byzantine` to simulate a faulty participant. Note that because we have a test network with only 4 participants, the protocol can handle at most 1 fault, so a protocol failure may occur if you disable too many participants simultaneously. 

Even after you have chosen a participant to corrupt, you should see that the other participants can still come to consensus over the ordering of received "operations" which have the form `Some("PeerN:K")`. If you simply crashed a participant but did not activate the byzantine behavior, you should also notice that the crashed processor can recover back into the protocol. It will eventually learn all published "operations" and their ordering. Once all participants have recovered, the protocol can handle another fault.

## Running tests
To run all tests used to validate the implementation's behavior, run
```bash
cargo test
```

There are many tests to check that the protocol operates correctly and does not violate consensus safety. These test files can be found in the `src/` subdirectories under the name `test.rs`.