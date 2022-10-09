use std::fmt::Debug;
use tokio::sync::mpsc::unbounded_channel;
use pbft_library::communication_proxy::CommunicationProxy;
use pbft_library::pbft::{PBFTEvent, PBFTState, Peer};

fn setup_mock_network<O>(n: usize) -> Vec<PBFTState<O>>
where O: Clone + Debug
{
    // Generate peer communication channels
    let mut peers = Vec::new();
    let mut txs = Vec::new();
    let mut rxs = Vec::new();
    for i in 0..n {
        peers.push(Peer {
            id: format!("Peer{}", i),
            hostname: format!("Peer{}", i)
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

        let proxy = CommunicationProxy::new(peer_channels, rx_i);
        res.push(PBFTState::new(proxy, 10, 100));
    }

    res
}

#[tokio::test]
async fn my_test() {
    let mut network = setup_mock_network::<String>(3);

    let communication_proxy1 = &network.get(1).unwrap().communication_proxy;
    let communication_proxy2 = &network.get(2).unwrap().communication_proxy;
    communication_proxy1.broadcast(PBFTEvent::Request { op: "Message 1".to_string() });
    communication_proxy2.broadcast(PBFTEvent::Request { op: "Message 2".to_string() });

    let mut pbft0 = network.get_mut(0).unwrap();
    pbft0.step().await;
    pbft0.step().await;
}
