use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use futures::future::join_all;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use pbft_library::communication_proxy::{CommunicationProxy, Peer, PeerIndex};
use pbft_library::kernel::{Digestible, PBFTEvent, PBFTState, PrepTriple, RequestPayload, ServiceOperation};

const CHECKPOINT_INTERVAL: u64 = 10;
const SEQUENCE_WINDOW_LENGTH: u64 = 20;

// The amount of time it takes to receive a request before it is determined that there are no
// more messages.
const NETWORK_QUIESCENT_TIMEOUT_SEC: u64 = 3;

static NEXT_PORT_AVAILABLE: AtomicU16 = AtomicU16::new(5000);

pub async fn setup_mock_network<O>(n: usize) -> Vec<PBFTState<O>>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    // Generate peer communication channels
    let mut peers = Vec::new();
    for i in 0..n {
        let port = NEXT_PORT_AVAILABLE.fetch_add(1, Ordering::SeqCst);
        peers.push(Peer {
            id: format!("Peer{}", i),
            hostname: format!("127.0.0.1:{}", port),
        });
    }

    // Generate PBFT machines
    let mut res = Vec::new();
    for i in 0..n {
        let mut peer_channels = Vec::new();
        for j in 0..n {
            // Peers are everybody except ourselves (i)
            if i != j {
                let peer_j = peers.get(j).unwrap();
                peer_channels.push(peer_j.clone())
            }
        }

        let proxy = CommunicationProxy::new(peers[i].clone(), peer_channels).await;
        res.push(PBFTState::new(proxy, SEQUENCE_WINDOW_LENGTH, CHECKPOINT_INTERVAL));
    }

    res
}

#[tokio::test]
async fn test_max_fault() {
    let network = setup_mock_network::<String>(2).await;
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 0, "Test no faults.");

    let network = setup_mock_network::<String>(4).await;
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 1, "Test n = 3f + 1");

    let network = setup_mock_network::<String>(14).await;
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 4, "Test n = 3f + 2");

    let network = setup_mock_network::<String>(36).await;
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 11, "Test n = 3f + 3");
}

#[tokio::test]
async fn test_quorum() {
    // Let Q1 and Q2 be two quorums of size q.
    // Let n and f be the number of replicas and the maximum number of allowable faults, respectively.
    //
    // |Q1 ∪ Q2| = |Q1| + |Q2| - |Q1 ∩ Q2| <= n
    // => 2q - n <= |Q1 ∩ Q2| T
    // To ensure safety, |Q1 ∩ Q2| >= f + 1 so that the intersection always contains some correct replica
    //  If 2q-n >= f + 1, then safety is guaranteed.
    //
    // To ensure liveliness, q <= n - f otherwise quorum can never be achieved if all f processors crash
    let n: PeerIndex = 2;
    let network = setup_mock_network::<String>(n as usize).await;
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for no faults");
    assert!(quorum <= n - f, "Test quorum liveliness for no faults");

    let n: PeerIndex = 4;
    let network = setup_mock_network::<String>(n as usize).await;
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for n = 3f + 1");
    assert!(quorum <= n - f, "Test quorum liveliness for n = 3f + 1");

    let n: PeerIndex = 14;
    let network = setup_mock_network::<String>(n as usize).await;
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for n = 3f + 2");
    assert!(quorum <= n - f, "Test quorum liveliness for n = 3f + 2");

    let n: PeerIndex = 36;
    let network = setup_mock_network::<String>(n as usize).await;
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for n = 3f + 3");
    assert!(quorum <= n - f, "Test quorum liveliness for n = 3f + 3");
}

// Helper function to drive network until no more messages are sent
type Kernels<O> = Vec<Arc<TokioMutex<PBFTState<O>>>>;
async fn drive_until_quiescent<O>(network: &Kernels<O>, nonparticipants: HashSet<usize>)
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    let mut handles = vec![];
    for (i, state) in network.iter().enumerate() {
        if nonparticipants.contains(&i) {
            continue;
        };

        let state = state.clone();
        handles.push(tokio::spawn(async move {
            let state = state;
            loop {
                let mut state = state.lock().await;
                let step = state.step();
                let timeout_res = timeout(Duration::from_secs(NETWORK_QUIESCENT_TIMEOUT_SEC), step).await;
                if timeout_res.is_err() {
                    break;
                }
            }
        }));
    }
    let _ = join_all(handles).await;
}

fn convert_network_to_kernels<O: ServiceOperation>(network: Vec<PBFTState<O>>) -> Kernels<O> {
    network
        .into_iter()
        .map(|p| Arc::new(TokioMutex::new(p)))
        .collect::<Kernels<O>>()
}

async fn normal_operation_runner(n: usize) {
    let network = setup_mock_network::<String>(n).await;
    let network = convert_network_to_kernels(network);

    // Create scopes to drop the tokio mutex
    let f = {
        network.get(0).unwrap().lock().await.max_faults()
    };

    {
        // Simulate 2 requests
        let communication_proxy1 = &network.get(1).unwrap().lock().await.communication_proxy;
        communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload::new("Hello World1".to_string())));
        communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload::new("Hello World2".to_string())));
    }

    // Crash f processors
    drive_until_quiescent(&network, HashSet::from_iter(n-f as usize .. n)).await;

    let target = vec!["Hello World1".to_string(), "Hello World2".to_string()];
    for state in &network[0 .. n-f as usize] {
        let state = state.lock().await;
        assert_eq!(state.current_state().log(), &target);
    }
}

#[tokio::test]
async fn test_normal_operation() {
    let mut tests = vec![];
    tests.push(tokio::spawn(async {
        normal_operation_runner(4).await;
    }));
    tests.push(tokio::spawn(async {
        normal_operation_runner(14).await;
    }));
    tests.push(tokio::spawn(async {
        normal_operation_runner(36).await;
    }));
    join_all(tests).await;
}


#[tokio::test]
async fn test_out_of_order_commits() {
    let n = 4;
    let network = setup_mock_network::<String>(n).await;
    let network = convert_network_to_kernels(network);

    // Create scope to drop the tokio mutex lock on the primary
    {
        // Simulate out of order preprepare by primary 0 ... Because n = 4, 1 faulty primary will not affect consensus
        // of other.
        let communication_proxy0 = &network.get(0).unwrap().lock().await.communication_proxy;
        for i in (1..=5).rev() {
            let msg = format!("HelloWorld{}", i);
            communication_proxy0.broadcast(PBFTEvent::PrePrepare {
                from: 0,
                data: PrepTriple {
                    sequence_number: i,
                    digest: msg.digest(),
                    view: 0
                },
                request: RequestPayload {
                    op: msg.clone(),
                    op_digest: msg.digest()
                }
            });
        }
    }

    drive_until_quiescent(&network, HashSet::from([0])).await;

    let target = (1..=5).map(|i| format!("HelloWorld{}", i)).collect::<Vec<String>>();
    for (i, state) in network.iter().enumerate() {
        if i == 0 {
            // Skip the faulty primary
            continue;
        }
        assert_eq!(state.lock().await.current_state().log(), &target, "Testing out of order");
    }
}

#[tokio::test]
async fn test_checkpoint_garbage_collection() {
    let n = 4;
    let network = setup_mock_network::<String>(n).await;
    let network = convert_network_to_kernels(network);

    let rounds = 5;
    let faulty = 1;
    // Trigger multiple rounds of checkpointing
    for _ in 0..rounds {
        // Create scope to drop the tokio mutex lock
        {
            // Generate enough requests to trigger a checkpoint
            let communication_proxy1 = &network.get(1).unwrap().lock().await.communication_proxy;
            for i in 1..=CHECKPOINT_INTERVAL {
                let msg = format!("HelloWorld{}", i);
                communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload {
                    op_digest: msg.digest(),
                    op: msg,
                }));

            }
        }

        // Because n = 4, network should still reach consensus in the presence of 1 fault.
        // But this faulty processor should not be the primary otherwise view change is needed
        // to ensure liveliness.
        drive_until_quiescent(&network, HashSet::from([faulty])).await;
    }
    for (i, state) in network.iter().enumerate() {
        if i == faulty {
            continue;
        }

        let state = state.lock().await;
        // Garbage collection should purge any old checkpoints
        assert!(state.log_low_mark() >= rounds*CHECKPOINT_INTERVAL, "Test Checkpoint Low Log Mark Update");
    }
}

async fn drain_receiver<O>(communication_proxy: &mut CommunicationProxy<O>)
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    loop {
        let recv = communication_proxy.recv_event();
        let timeout_res = timeout(Duration::from_secs(NETWORK_QUIESCENT_TIMEOUT_SEC), recv).await;
        if timeout_res.is_err() {
            break;
        }
    }
}

#[tokio::test]
async fn test_checkpoint_synchronization() {
    let n = 4;
    let network = setup_mock_network::<String>(n).await;
    let mut network = convert_network_to_kernels(network);

    let rounds = 5;
    let faulty = 3;
    let mut target_log = vec![];
    // Trigger multiple rounds of checkpointing
    for _ in 0..rounds {
        // Create scope to drop the tokio mutex lock
        {
            // Generate enough requests to trigger a checkpoint
            let communication_proxy1 = &network.get(1).unwrap().lock().await.communication_proxy;
            for i in 1..=CHECKPOINT_INTERVAL {
                let msg = format!("HelloWorld{}", i);
                target_log.push(msg.clone());
                communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload {
                    op_digest: msg.digest(),
                    op: msg,
                }));

            }
        }

        // Because n = 4, network should still reach consensus in the presence of 1 fault.
        // But this faulty processor should not be the primary otherwise view change is needed
        // to ensure liveliness.
        drive_until_quiescent(&network, HashSet::from([faulty])).await;
    }
    // Because the faulty replica has not participated, it should have nothing executed
    {
        let faulty_replica = &mut network.get_mut(faulty).unwrap().lock().await;
        assert!(faulty_replica.current_state().log().is_empty());

        // Pretend the faulty process completely crashed. Drain its received messages.
        drain_receiver(&mut faulty_replica.communication_proxy).await;
    }

    // Trigger view change to trigger a checkpoint synchronization
    for state in network.iter() {
        state.lock().await.change_view(1);
    }

    // Pretend the faulty participant rejoined
    drive_until_quiescent(&network, HashSet::new()).await;

    for state in network.iter() {
        let state = state.lock().await;
        assert_eq!(state.current_state().log(), &target_log);
    }
}

async fn view_change_safety_runner(n: usize) {
    // Assume n >= 4 so some faults are allowed
    assert!(n >= 4);

    let network = setup_mock_network::<String>(n).await;
    let network = convert_network_to_kernels(network);
    let f = {
        network.get(1).unwrap().lock().await.max_faults()
    };

    let mut target_log = vec![];
    // Create scope to drop the tokio mutex lock
    {
        let communication_proxy = &network.get(n-1).unwrap().lock().await.communication_proxy;
        let msg = "HelloWorld1".to_string();
        target_log.push(msg.clone());
        communication_proxy.broadcast(PBFTEvent::Request(RequestPayload {
            op_digest: msg.digest(),
            op: msg,
        }));
    }

    drive_until_quiescent(&network, HashSet::from_iter(n-f as usize..n)).await;

    // Trigger multiple view changes giving each replica an opportunity to be a primary
    for _ in 0..2*n {
        for state in network.iter() {
            state.lock().await.change_view(1);
        }
        drive_until_quiescent(&network, HashSet::from_iter(n-f as usize..n)).await;
    }

    // Check that the committed message persist after multiple view changes
    for state in &network[0..n-f as usize] {
        let state = state.lock().await;
        assert_eq!(state.current_state().log(), &vec!["HelloWorld1"]);
    }
}

#[tokio::test]
async fn test_view_change_safety() {
    let mut tests = vec![];
    tests.push(tokio::spawn(async {
        view_change_safety_runner(4).await;
    }));
    tests.push(tokio::spawn(async {
        view_change_safety_runner(5).await;
    }));
    tests.push(tokio::spawn(async {
        view_change_safety_runner(6).await;
    }));
    join_all(tests).await;
}
