use std::sync::{Arc, Mutex};
use std::time::Duration;
use futures::future::join_all;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::timeout;
use pbft_library::communication_proxy::CommunicationProxy;
use pbft_library::kernel::{PBFTEvent, PBFTState, Peer, PeerIndex, RequestPayload, ServiceOperation};

const CHECKPOINT_INTERVAL: u64 = 10;
const SEQUENCE_WINDOW_LENGTH: u64 = 20;
const TEST_DURATION_TIMEOUT_SEC: u64 = 10;

pub fn setup_mock_network<O>(n: usize) -> Vec<PBFTState<O>>
    where O: ServiceOperation
{
    // Generate peer communication channels
    let mut peers = Vec::new();
    let mut txs = Vec::new();
    let mut rxs = Vec::new();
    for i in 0..n {
        peers.push(Peer {
            id: format!("Peer{}", i),
            hostname: format!("Peer{}", i),
        });
        let (tx, rx) = unbounded_channel();
        txs.push(tx);
        rxs.push(rx);
    }

    // Generate PBFT machines
    let mut res = Vec::new();
    for (i, rx_i) in rxs.into_iter().enumerate() {
        let mut peer_channels = Vec::new();
        for j in 0..n {
            // Peers are everybody except ourselves (i)
            if i != j {
                let tx_j = txs.get(j).unwrap();
                let peer_j = peers.get(j).unwrap();
                peer_channels.push((peer_j.clone(), tx_j.clone()))
            }
        }

        let proxy = CommunicationProxy::new(peers[i].clone(), peer_channels, rx_i);
        res.push(PBFTState::new(proxy, SEQUENCE_WINDOW_LENGTH, CHECKPOINT_INTERVAL));
    }

    res
}

#[test]
fn test_max_fault() {
    let network = setup_mock_network::<String>(2);
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 0, "Test no faults.");

    let network = setup_mock_network::<String>(4);
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 1, "Test n = 3f + 1");

    let network = setup_mock_network::<String>(14);
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 4, "Test n = 3f + 2");

    let network = setup_mock_network::<String>(36);
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 11, "Test n = 3f + 3");
}

#[test]
fn test_quorum() {
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
    let network = setup_mock_network::<String>(n as usize);
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for no faults");
    assert!(quorum <= n - f, "Test quorum liveliness for no faults");

    let n: PeerIndex = 4;
    let network = setup_mock_network::<String>(n as usize);
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for n = 3f + 1");
    assert!(quorum <= n - f, "Test quorum liveliness for n = 3f + 1");

    let n: PeerIndex = 14;
    let network = setup_mock_network::<String>(n as usize);
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for n = 3f + 2");
    assert!(quorum <= n - f, "Test quorum liveliness for n = 3f + 2");

    let n: PeerIndex = 36;
    let network = setup_mock_network::<String>(n as usize);
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for n = 3f + 3");
    assert!(quorum <= n - f, "Test quorum liveliness for n = 3f + 3");
}

async fn normal_operation_runner(n: usize) {
    let network = setup_mock_network::<String>(n);
    let results = Arc::new(Mutex::new(vec![false; n]));
    let f = network.get(0).unwrap().max_faults();

    // Simulate 2 requests
    let communication_proxy1 = &network.get(1).unwrap().communication_proxy;
    communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload::new("Hello World1".to_string())));
    communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload::new("Hello World2".to_string())));

    let mut handles = vec![];
    for (i, mut state) in network.into_iter().enumerate() {
        let result_handle = results.clone();
        handles.push(tokio::spawn(async move {
            loop {
                if i < n - f as usize {
                    state.step().await;
                } else {
                    // Peers with id [n-f, n-1] do not make progress and act like they crashed
                    break
                }

                // Check commits, sequencing, and service state
                if state.last_executed() == 2
                    && state.current_state().log().len() == 2
                    && state.current_state().log().get(0).unwrap().eq("Hello World1")
                    && state.current_state().log().get(1).unwrap().eq("Hello World2")
                {
                    *result_handle.lock().unwrap().get_mut(i).unwrap() = true;
                }
            }
        }));
    }
    let _ = timeout(Duration::from_secs(TEST_DURATION_TIMEOUT_SEC), join_all(handles)).await;

    // Check that all replica committed in the presence of f faults
    let non_faulty_result = &results.lock().unwrap().clone()[0..n-f as usize];
    assert_eq!(non_faulty_result, vec![true; n-f as usize], "Test normal operation for n = {}", n);
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

// TODO: Test out of order commits
// TODO: Test checkpointing
// TODO: Test byzantine primary sending different preprepare
// TODO: Test byzantine primary sending prepare