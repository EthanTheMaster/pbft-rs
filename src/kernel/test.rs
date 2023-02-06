use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use ed25519_compact::{KeyPair, Seed};
use futures::future::join_all;
use serde::de::DeserializeOwned;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use tokio::select;
use tokio::sync::{Mutex as TokioMutex, Notify};
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::{sleep, timeout};
use crate::kernel::*;
use crate::kernel::view_change_manager::ViewChangeManager;
use crate::pbft_replica::{DIGEST_LENGTH_BYTES, Digestible, DigestResult, NoOp, ServiceOperation};

const CHECKPOINT_INTERVAL: u64 = 10;
const SEQUENCE_WINDOW_LENGTH: u64 = 20;

// The amount of time it takes to receive a request before it is determined that there are no
// more messages.
const NETWORK_QUIESCENT_TIMEOUT: Duration = Duration::from_secs(3);

// Rust runs tests in parallel and we cannot have tests interfering with each other
// Networks are mocked up and simulated replicas must be assigned an ip uninhabited by
// another process. This ensures that replicas are assigned a unique ip during the test.
static NEXT_PORT_AVAILABLE: AtomicU16 = AtomicU16::new(5000);

// For testing, these timeouts should be higher than the network quiescent timeout to give
// replicas time to process all their messages without getting interrupted.
//
// Timeouts are used as a hack to determine if progress can be made. Making these values lower
// than the quiescent timeout may confuse some tests into thinking that progress can still be made.
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(10);
const VIEW_STAY_TIMEOUT: Duration = Duration::from_secs(30);
const VIEW_CHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const VIEW_CHANGE_RETRANSMISSION_INTERVAL: Duration = Duration::from_secs(10);

// Enum to configure some tests to utilize certain kinds of faults
enum FaultType {
    CrashFault,
    ByzantineFault
}

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

pub async fn setup_mock_network<O>(n: usize) -> Vec<PBFTState<O>>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    // Generate peer communication channels
    let mut peers = Vec::new();
    let mut secret_keys = Vec::new();
    for i in 0..n {
        let signature_key_pair = KeyPair::from_seed(Seed::generate());
        secret_keys.push(signature_key_pair.sk);
        let port = NEXT_PORT_AVAILABLE.fetch_add(1, Ordering::SeqCst);
        peers.push(Peer {
            id: format!("Peer{}", i),
            hostname: format!("127.0.0.1:{}", port),
            signature_public_key: signature_key_pair.pk
        });
    }

    // Generate PBFT machines
    let mut res = Vec::new();
    for i in 0..n {
        let mut peers_i = Vec::new();
        for j in 0..n {
            // Peers are everybody except ourselves (i)
            if i != j {
                let peer_j = peers.get(j).unwrap();
                peers_i.push(peer_j.clone())
            }
        }

        let configuration = Configuration {
            peers: peers_i,
            this_replica: peers.get(i).unwrap().clone(),
            signature_secret_key: secret_keys.get(i).unwrap().clone(),
            reconnection_delay: Duration::from_secs(1),
        };
        let proxy = CommunicationProxy::new(configuration).await;

        let view_change_manager = ViewChangeManager::new(VIEW_STAY_TIMEOUT);
        let (state_change_tx, mut state_change_rx) = unbounded_channel();

        // Just drain the state_change_rx ... don't process broadcasts
        tokio::spawn(async move {
            loop {
                let recv = state_change_rx.recv().await;
                if recv.is_none() {
                    break;
                }
            }
        });

        res.push(PBFTState::new(
            view_change_manager,
            proxy,
            state_change_tx,
            EXECUTION_TIMEOUT,
            VIEW_CHANGE_TIMEOUT,
            VIEW_CHANGE_RETRANSMISSION_INTERVAL,
            SEQUENCE_WINDOW_LENGTH,
            CHECKPOINT_INTERVAL
        ));
    }
    res
}

#[tokio::test]
async fn test_max_fault() {
    let network = setup_mock_network::<Operation>(2).await;
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 0, "Test no faults.");

    let network = setup_mock_network::<Operation>(4).await;
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 1, "Test n = 3f + 1");

    let network = setup_mock_network::<Operation>(14).await;
    let max_faults = network.get(0).unwrap().max_faults();
    assert_eq!(max_faults, 4, "Test n = 3f + 2");

    let network = setup_mock_network::<Operation>(36).await;
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
    let network = setup_mock_network::<Operation>(n as usize).await;
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for no faults");
    assert!(quorum <= n - f, "Test quorum liveliness for no faults");

    let n: PeerIndex = 4;
    let network = setup_mock_network::<Operation>(n as usize).await;
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for n = 3f + 1");
    assert!(quorum <= n - f, "Test quorum liveliness for n = 3f + 1");

    let n: PeerIndex = 14;
    let network = setup_mock_network::<Operation>(n as usize).await;
    let pbft = network.get(0).unwrap();
    let f = pbft.max_faults();
    let quorum = pbft.quorum_size();
    assert!(2*quorum - n >= pbft.weak_certificate_size(), "Test quorum intersection for n = 3f + 2");
    assert!(quorum <= n - f, "Test quorum liveliness for n = 3f + 2");

    let n: PeerIndex = 36;
    let network = setup_mock_network::<Operation>(n as usize).await;
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
            let mut state = state.lock().await;
            loop {
                let step = state.step();
                let timeout_res = timeout(NETWORK_QUIESCENT_TIMEOUT, step).await;
                if timeout_res.is_err() {
                    break;
                }
            }
        }));
    }
    let _ = join_all(handles).await;
}

async fn drive_until_notification<O>(network: &Kernels<O>, nonparticipants: HashSet<usize>) -> Arc<Notify>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    let notification = Arc::new(Notify::new());
    for (i, state) in network.iter().enumerate() {
        if nonparticipants.contains(&i) {
            continue;
        };

        let state = state.clone();
        let notification = notification.clone();
        tokio::spawn(async move {
            let state = state;
            let notification = notification;
            let mut state = state.lock().await;
            loop {
                select! {
                    _ = notification.notified() => {
                        break
                    }
                    _ = state.step() => {}
                };
            }
        });
    }
    notification
}

fn convert_network_to_kernels<O: ServiceOperation>(network: Vec<PBFTState<O>>) -> Kernels<O> {
    network
        .into_iter()
        .map(|p| Arc::new(TokioMutex::new(p)))
        .collect::<Kernels<O>>()
}

async fn normal_operation_runner(n: usize, fault: FaultType) {
    let network = setup_mock_network::<Operation>(n).await;
    let network = convert_network_to_kernels(network);

    // Create scopes to drop the tokio mutex
    let f = {
        network.get(0).unwrap().lock().await.max_faults()
    };

    {
        // Simulate 2 requests
        let communication_proxy1 = &network.get(1).unwrap().lock().await.communication_proxy;
        communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload::new(Operation::Some("Hello World1".to_string()))));
        communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload::new(Operation::Some("Hello World2".to_string()))));
    }

    // Fail last f replica to focus the test on an operating primary in the presence of faulty followers
    match fault {
        FaultType::CrashFault => {
            // Crash f processors
            drive_until_quiescent(&network, HashSet::from_iter(n-f as usize .. n)).await;
        }
        FaultType::ByzantineFault => {
            // Simulate malfunctioning replicas
            for i in n-f as usize .. n {
                let mut replica = network.get(i).unwrap().lock().await;
                replica.communication_proxy.dev_is_byzantine(true);
            }
            drive_until_quiescent(&network, HashSet::new()).await;
        }
    }

    let target = vec![Operation::Some("Hello World1".to_string()), Operation::Some("Hello World2".to_string())];
    for state in &network[0 .. n-f as usize] {
        let state = state.lock().await;
        assert_eq!(state.current_state().log(), &target);

        // Ensure a view change did not happen
        assert_eq!(state.view(), 0);
    }
}

#[tokio::test]
async fn test_normal_operation_mod1_crash() {
    normal_operation_runner(4, FaultType::CrashFault).await;
}
#[tokio::test]
async fn test_normal_operation_mod2_crash() {
    normal_operation_runner(14, FaultType::CrashFault).await;
}
#[tokio::test]
async fn test_normal_operation_mod0_crash() {
    normal_operation_runner(36, FaultType::CrashFault).await;
}

#[tokio::test]
async fn test_normal_operation_mod1_byzantine() {
    normal_operation_runner(4, FaultType::ByzantineFault).await;
}
#[tokio::test]
async fn test_normal_operation_mod2_byzantine() {
    normal_operation_runner(14, FaultType::ByzantineFault).await;
}
#[tokio::test]
async fn test_normal_operation_mod0_byzantine() {
    normal_operation_runner(36, FaultType::ByzantineFault).await;
}

#[tokio::test]
async fn test_out_of_order_commits() {
    let n = 4;
    let network = setup_mock_network::<Operation>(n).await;
    let network = convert_network_to_kernels(network);

    // Create scope to drop the tokio mutex lock on the primary
    {
        // Simulate out of order preprepare by primary 0 ... Because n = 4, 1 faulty primary will not affect consensus
        // of other.
        let communication_proxy0 = &network.get(0).unwrap().lock().await.communication_proxy;
        for i in (1..=5).rev() {
            let msg = Operation::Some(format!("HelloWorld{}", i));
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

    let target = (1..=5).map(|i| Operation::Some(format!("HelloWorld{}", i))).collect::<Vec<Operation>>();
    for (i, state) in network.iter().enumerate() {
        if i == 0 {
            // Skip the faulty primary
            continue;
        }
        assert_eq!(state.lock().await.current_state().log(), &target, "Testing out of order");

        // Ensure a view change did not happen
        assert_eq!(state.lock().await.view(), 0);
    }
}

#[tokio::test]
async fn test_checkpoint_garbage_collection() {
    let n = 4;
    let network = setup_mock_network::<Operation>(n).await;
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
                let msg = Operation::Some(format!("HelloWorld{}", i));
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
        let timeout_res = timeout(NETWORK_QUIESCENT_TIMEOUT, recv).await;
        if timeout_res.is_err() {
            break;
        }
    }
}

#[tokio::test]
async fn test_checkpoint_synchronization() {
    let n = 4;
    let network = setup_mock_network::<Operation>(n).await;
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
                let msg = Operation::Some(format!("HelloWorld{}", i));
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

async fn view_change_safety_runner(n: usize, fault: FaultType) {
    // Assume n >= 4 so some faults are allowed
    assert!(n >= 4);

    let network = setup_mock_network::<Operation>(n).await;
    let network = convert_network_to_kernels(network);
    let f = {
        network.get(1).unwrap().lock().await.max_faults()
    };

    let mut target_log = vec![];
    // Create scope to drop the tokio mutex lock
    {
        let communication_proxy = &network.get(0).unwrap().lock().await.communication_proxy;
        let msg = Operation::Some("CommittedMessage".to_string());
        target_log.push(msg.clone());
        // Primary prepares a message and gets it committed. But this message is not at the start
        // so it will not be executed. View change protocol should still respect all commitments.
        communication_proxy.broadcast(PBFTEvent::PrePrepare {
            from: 0,
            data: PrepTriple {
                sequence_number: SEQUENCE_WINDOW_LENGTH - 1,
                digest: msg.digest(),
                view: 0
            },
            request: RequestPayload {
                op_digest: msg.digest(),
                op: msg,
            }

        });

    }

    // Fail first f replica to focus the test failing view change primary
    match fault {
        FaultType::CrashFault => {
            // Crash f processors
            drive_until_quiescent(&network, HashSet::from_iter(0..f as usize)).await;
        }
        FaultType::ByzantineFault => {
            // Simulate malfunctioning replicas
            for i in 0..f as usize {
                let mut replica = network.get(i).unwrap().lock().await;
                replica.communication_proxy.dev_is_byzantine(true);
            }
            drive_until_quiescent(&network, HashSet::new()).await;
        }
    }

    // Trigger multiple view changes giving each replica an opportunity to be a primary
    for _ in 0..2*n {
        for state in network.iter() {
            state.lock().await.change_view(1);
        }
        drive_until_quiescent(&network, HashSet::from_iter(0..f as usize)).await;
    }

    // Check that the committed message persist after multiple view changes
    for state in &network[f as usize .. n as usize] {
        let state = state.lock().await;
        assert_eq!(state.current_state().log(), &vec![Operation::Some("CommittedMessage".to_string())]);
    }
}

#[tokio::test]
async fn test_view_change_safety_mod1_crash() {
    view_change_safety_runner(4, FaultType::CrashFault).await;
}
#[tokio::test]
async fn test_view_change_safety_mod2_crash() {
    view_change_safety_runner(5, FaultType::CrashFault).await;
}
#[tokio::test]
async fn test_view_change_safety_mod0_crash() {
    view_change_safety_runner(6, FaultType::CrashFault).await;
}
#[tokio::test]
async fn test_view_change_safety_mod1_byzantine() {
    view_change_safety_runner(4, FaultType::ByzantineFault).await;
}
#[tokio::test]
async fn test_view_change_safety_mod2_byzantine() {
    view_change_safety_runner(5, FaultType::ByzantineFault).await;
}
#[tokio::test]
async fn test_view_change_safety_mod0_byzantine() {
    view_change_safety_runner(6, FaultType::ByzantineFault).await;
}

#[tokio::test]
async fn test_inactive_primary_normal_operation_view_change() {
    let n = 4;
    let network = setup_mock_network::<Operation>(n).await;
    let network = convert_network_to_kernels(network);
    {
        // Get all nonfaulty replicas to hear an incoming request.
        let communication_proxy = &network.get(0).unwrap().lock().await.communication_proxy;
        let msg = Operation::Some("HelloWorld".to_string());
        communication_proxy.broadcast(PBFTEvent::Request(RequestPayload {
            op_digest: msg.digest(),
            op: msg,
        }));
    }

    // Drive all nonfaulty replica
    let notification = drive_until_notification(&network, HashSet::from([0])).await;
    sleep(Duration::from_secs(30)).await;
    notification.notify_waiters();

    for state in &network[1..] {
        assert!(state.lock().await.view() > 0);
    }

}

#[tokio::test]
async fn test_inactive_primary_new_view_view_change() {
    let n = 4;
    let network = setup_mock_network::<Operation>(n).await;
    let network = convert_network_to_kernels(network);

    // Change the view for all processors
    for state in &network {
        state.lock().await.change_view(1);
    }

    // Crash processor 1 who is the primary of the view change
    let notification = drive_until_notification(&network, HashSet::from([1])).await;
    sleep(Duration::from_secs(30)).await;
    notification.notify_waiters();

    // All nonfaulty processors should detect a failed view change primary and move to the next view
    for (i, state) in network.iter().enumerate() {
        if i == 1 {
            continue;
        }
        assert_eq!(state.lock().await.view(), 2);
    }

}

#[tokio::test]
async fn test_view_change_to_a_correct_processor() {
    let n = 4;
    let network = setup_mock_network::<Operation>(n).await;
    let network = convert_network_to_kernels(network);

    // Simulate a weak certificate sized number of replica being multiple views ahead
    network[2].lock().await.change_view(1000);
    network[3].lock().await.change_view(1005);

    // Get replicas 2 and 3 to high view number
    let notification = drive_until_notification(&network, HashSet::from([0, 1])).await;
    sleep(Duration::from_secs(5)).await;
    notification.notify_waiters();

    // Trigger view change for 0 and 1 who will detect a weak certificate vouching for a higher view
    for state in &network[0..=1] {
        state.lock().await.change_view(1);
    }

    let notification = drive_until_notification(&network, HashSet::new()).await;
    sleep(Duration::from_secs(5)).await;
    notification.notify_waiters();


    // All processors should be "far ahead" of view 0
    for state in &network {
        assert!(state.lock().await.view() >= 1000);
    }

}

#[tokio::test]
async fn test_view_change_retransmission() {
    let n = 4;
    let network = setup_mock_network::<Operation>(n).await;
    let network = convert_network_to_kernels(network);

    // Jump replica 0 to a future view
    {
        let mut replica = network.get(0).unwrap().lock().await;
        replica.change_view(1234);
    }

    // Drive only replica 0
    let notification = drive_until_notification(&network, HashSet::from([1,2,3])).await;
    // Let replica 0 retransmit the view change 3 times
    for _ in 0..3 {
        sleep(VIEW_CHANGE_RETRANSMISSION_INTERVAL).await;
    }
    notification.notify_waiters();

    {
        let mut num_view_changes = 0;
        let mut replica = network.get(1).unwrap().lock().await;
        while let Ok(Some(event)) = timeout(NETWORK_QUIESCENT_TIMEOUT, replica.communication_proxy.recv_event()).await {
            if let PBFTEvent::ViewChange(change) = event.event {
                if change.from == 0 && change.view == 1234 {
                    num_view_changes += 1;
                }
            }
        }

        // Validate that at least 4 view changes were sent (1 for the view change switch + 3 retransmissions)
        assert!(num_view_changes >= 4);
    }

}

#[tokio::test]
async fn test_view_stay_timeout() {
    let n = 4;
    let network = setup_mock_network::<Operation>(n).await;
    let network = convert_network_to_kernels(network);


    // Drive all replicas but don't don't put any activity on the network
    let notification = drive_until_notification(&network, HashSet::new()).await;
    // Test a view change from view 0 then another view change from view 1
    // Give some extra time for the replicas to execute the view change protocols
    sleep(2*VIEW_STAY_TIMEOUT + NETWORK_QUIESCENT_TIMEOUT).await;
    notification.notify_waiters();

    {
        for replica in network {
            assert!(replica.lock().await.view >= 2);
        }
    }

}

// TODO: Test weak certificate checkpoint synchronization from new view