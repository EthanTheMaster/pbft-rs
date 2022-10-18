use std::collections::HashSet;
use pbft_library::merkle_tree::{MerkleIndex, MerkleTree};

#[test]
fn test_root_computation() {
    let padding = [87;32];
    let mut tree = MerkleTree::new(padding);
    // Test computing merkle tree root as tree items are being generated
    for r in 0 .. 1000 {
        // Empty indices forces the prover to simply return the merkle tree root
        let _ = tree.append([(r % 256) as u8;32]);
        let empty_proof = tree.generate_proof(&HashSet::new(), r as MerkleIndex).unwrap();
        assert_eq!(&tree.root(), empty_proof.internal_hashes.get(&String::new()).unwrap());
    }

    let mut ground_truth_slice = MerkleTree::new(padding);

    // Test computing root for sliced portion of the original tree
    for right_boundary in 0 .. 1000 {
        let _ = ground_truth_slice.append([(right_boundary % 256) as u8;32]);

        // Check if supplying a size causes the proof to simulate viewing only a sliced version of the original tree
        let root_sliced_tree = tree.generate_proof(&HashSet::new(), right_boundary as MerkleIndex).unwrap();
        assert_eq!(&ground_truth_slice.root(), root_sliced_tree.internal_hashes.get(&String::new()).unwrap());
    }

    // Test computing root extending beyond list size
    let mut extended_tree = tree.clone();
    for offset in 0 .. 1000 {
        let _ = extended_tree.append(padding);

        let right_boundary = (tree.items().len() + offset) as MerkleIndex;
        let root_simulated_extended_tree = tree.generate_proof(&HashSet::new(), right_boundary).unwrap();
        assert_eq!(&extended_tree.root(), root_simulated_extended_tree.internal_hashes.get(&String::new()).unwrap());
    }
}

#[test]
fn test_proof_validation() {
    let mut tree = MerkleTree::new([87;32]);
    for i in 0..1000 {
        let _ = tree.append([(i % 256) as u8;32]);
    }
    let right_boundary = (tree.items().len() - 1) as MerkleIndex;

    // TODO: Validate proof size falls within cover bound
    let proof = tree.generate_proof(&HashSet::from([200, 3000, 5000]), right_boundary);
    assert!(proof.is_none(), "Proofs should not be generated for indices outside list bound.");
    let proof = tree.generate_proof(&HashSet::from([1337]), right_boundary);
    assert!(proof.is_none(), "Proofs should not be generated for indices outside list bound.");

    let proof = tree.generate_proof(&HashSet::from([0, 4, 700, 876]), right_boundary).unwrap();
    assert!(MerkleTree::is_valid_proof(&tree.root(), &proof));

    let proof = tree.generate_proof(&HashSet::from([9, 10, 11, 12, 13]), right_boundary).unwrap();
    assert!(MerkleTree::is_valid_proof(&tree.root(), &proof));

    let proof = tree.generate_proof(&HashSet::from_iter(0..1000), right_boundary).unwrap();
    assert!(MerkleTree::is_valid_proof(&tree.root(), &proof));

    // Proof should now no longer root because the contents have changed
    let _ = tree.append([111;32]);
    assert!(!MerkleTree::is_valid_proof(&tree.root(), &proof));

}