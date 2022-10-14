use std::sync::Arc;
use std::time::Duration;
use futures::future::join_all;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::Mutex;
use tokio::time::timeout;
use pbft_library::communication_proxy::CommunicationProxy;
use pbft_library::kernel::{PBFTEvent, PBFTState, Peer, RequestPayload, ServiceOperation};

const CHECKPOINT_INTERVAL: u64 = 10;
const SEQUENCE_WINDOW_LENGTH: u64 = 5;
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

#[tokio::main]
async fn main() {
    simple_logger::SimpleLogger::new().env().init().unwrap();

    let n = 4;
    let network = setup_mock_network::<String>(n)
        .into_iter()
        .map(|p| Arc::new(Mutex::new(p)))
        .collect::<Vec<Arc<Mutex<PBFTState<String>>>>>();
    let f = network.get(0).unwrap().lock().await.max_faults();

    // Simulate 2 requests
    {
        let communication_proxy1 = &network.get(1).unwrap().lock().await.communication_proxy;
        communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload::new("Hello World1".to_string())));
        communication_proxy1.broadcast(PBFTEvent::Request(RequestPayload::new("Hello World2".to_string())));
    }

    let mut handles = vec![];
    for (i, state) in network.iter().enumerate() {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            let state = state;
            loop {
                let mut state = state.lock().await;
                let step = state.step();
                let timeout_res = timeout(Duration::from_secs(1), step).await;
                if timeout_res.is_err() {
                    println!("TIMEOUT!");
                    break;
                }
            }
        }));
    }
    let _ = join_all(handles).await;

    // Attempt view change
    println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~CHANGING VIEW~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    for (i, state) in network.iter().enumerate() {
        println!("i: {}", i);
        state.lock().await.change_view(1);
    }
    // Attempt to come to consensus again
    println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~REACH CONSENSUS AGAIN~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    let mut handles = vec![];
    for (i, state) in network.iter().enumerate() {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            let state = state;
            loop {
                let mut state = state.lock().await;
                let step = state.step();
                let timeout_res = timeout(Duration::from_secs(1), step).await;
                if timeout_res.is_err() {
                    break;
                }
            }
        }));
    }
    // Come to consensus
    let _ = join_all(handles).await;
    for (i, state) in network.iter().enumerate() {
        println!("{:?}", state.lock().await.current_state().log());
    }
}