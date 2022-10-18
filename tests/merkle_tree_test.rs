use std::collections::HashSet;
use pbft_library::merkle_tree::MerkleTree;

#[test]
fn test_root_computation() {
    let mut tree = MerkleTree::new([87;32]);
    for r in 0 .. 1000 {
        // Empty indices forces the prover to simply return the merkle tree root
        tree.append([(r % 256) as u8;32]);
        let empty_proof = tree.generate_proof(&HashSet::new()).unwrap();
        assert_eq!(&tree.root(), empty_proof.internal_hashes.get(&String::new()).unwrap());
    }
}

#[test]
fn test_proof_validation() {
    let mut tree = MerkleTree::new([87;32]);
    for i in 0..1000 {
        tree.append([(i % 256) as u8;32]);
    }

    // TODO: Validate proof size falls within cover bound
    let proof = tree.generate_proof(&HashSet::from([200, 3000, 5000]));
    assert!(proof.is_none(), "Proofs should not be generated for indices outside list bound.");
    let proof = tree.generate_proof(&HashSet::from([1337]));
    assert!(proof.is_none(), "Proofs should not be generated for indices outside list bound.");

    let proof = tree.generate_proof(&HashSet::from([0, 4, 700, 876])).unwrap();
    assert!(MerkleTree::is_valid_proof(&tree.root(), &proof));

    let proof = tree.generate_proof(&HashSet::from([9, 10, 11, 12, 13])).unwrap();
    assert!(MerkleTree::is_valid_proof(&tree.root(), &proof));

    let proof = tree.generate_proof(&HashSet::from_iter(0..1000)).unwrap();
    assert!(MerkleTree::is_valid_proof(&tree.root(), &proof));

    // Proof should now no longer root because the contents have changed
    tree.append([111;32]);
    assert!(!MerkleTree::is_valid_proof(&tree.root(), &proof));

}