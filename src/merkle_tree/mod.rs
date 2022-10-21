use std::collections::{HashMap, HashSet};
use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};
use crate::pbft_replica::{DIGEST_LENGTH_BYTES, DigestResult};

#[cfg(test)]
mod test;

pub type MerkleIndex = u64;

pub const INDEX_BITS: usize = 64;

// Holds the hash of a node in the merkle tree and the height of the subtree rooted at this node.
// The subtree is a complete binary tree and the height is the number of edges between the root
// and any leaf.
#[derive(Copy, Clone, Debug)]
struct Node {
    hash: DigestResult,
    height: usize,
}

#[derive(Hash, Eq, PartialEq, Copy, Clone)]
enum Direction {
    Left,
    Right,
}

// Every internal node can be represented as a sequence of left and right turns starting
// at the root
type InternalNode = Vec<Direction>;

fn serialize_internal_node(node: &InternalNode) -> String {
    String::from_iter(node.iter().map(|d| {
        match d {
            Direction::Left => { "L" }
            Direction::Right => { "R" }
        }
    }))
}

fn deserialize_internal_node(node: &str) -> Option<InternalNode> {
    // The string must only consist of L and R's
    if !node.chars().all(|c| c == 'L' || c == 'R') {
        return None;
    }
    return Some(node.chars().map(|c| {
        if c == 'L' {
            Direction::Left
        } else {
            Direction::Right
        }
    }).collect());
}

// Proof demonstrating the memberships of the listed items at their corresponding index
// for a merkle tree containing `size` items
pub type MerkleProofItem = (MerkleIndex, DigestResult);
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipProof {
    pub internal_hashes: HashMap<String, DigestResult>,
    pub items: HashSet<MerkleProofItem>,
    pub right_boundary: MerkleIndex,
}

// Struct to help build a merkle tree for the service state and to generate/validate proofs
// for the existence of items.
//
// This merkle tree only supports maintaining a list of item with a power of 2 size. Moreover
// items are indexed by MerkleIndex putting an upper limit of items of 2^INDEX_BITS.
#[derive(Clone)]
pub struct MerkleTree {
    // Paddings will be needed to padding the list of items contained to a power of 2
    padding_digest: DigestResult,
    // Contains a precomputed lookup table for the hash of a node holding 2^k padding
    // elements where 0 <= k < INDEX_BITS.
    precomputed_padding: [DigestResult; INDEX_BITS],
    // This merkle tree is designed to be used in a streaming fashion because the service state
    // is a growing log. We don't want to keep recomputing the entire merkle root.
    running_digests: Vec<Node>,
    items: Vec<DigestResult>,
}

impl MerkleTree {
    fn hash(left: DigestResult, right: DigestResult) -> DigestResult {
        let mut res = [0; DIGEST_LENGTH_BYTES];
        let mut hasher = Sha3_256::new();
        hasher.update(left);
        hasher.update(right);
        let hash = &hasher.finalize()[..];
        res.copy_from_slice(hash);
        res
    }

    pub fn new(padding_digest: DigestResult) -> Self {
        let mut precomputed_padding = [[0; 32]; INDEX_BITS];
        precomputed_padding[0] = padding_digest;
        for k in 1..INDEX_BITS {
            let prev = precomputed_padding[0];
            precomputed_padding[k] = MerkleTree::hash(prev, prev);
        }

        MerkleTree {
            padding_digest,
            precomputed_padding,
            running_digests: vec![],
            items: vec![],
        }
    }

    pub fn items(&self) -> &Vec<DigestResult> {
        &self.items
    }

    // Appends an item to the list being validated by the merkle tree
    // Returns an error whenever the append could not be fulfilled
    pub fn append(&mut self, digest: DigestResult) -> Result<(), ()> {
        if self.items.len() == MerkleIndex::MAX as usize {
            // The merkle tree cannot hold anymore data!
            return Err(());
        }

        // This new item is treated as a leaf
        self.running_digests.push(Node {
            hash: digest,
            height: 0,
        });
        self.items.push(digest);
        MerkleTree::merge_partial_digests(&mut self.running_digests);

        Ok(())
    }

    fn merge_partial_digests(running_digests: &mut Vec<Node>) {
        // Keep merging the running digests with the previously computed digests
        // Merged results are between two subtrees of height k yielding a new node
        // with height k+1
        loop {
            if running_digests.len() < 2 {
                // There is nothing to merge
                break;
            }
            let right = running_digests.pop().unwrap();
            let left = running_digests.pop().unwrap();
            if left.height == right.height {
                running_digests.push(Node {
                    hash: MerkleTree::hash(left.hash, right.hash),
                    height: left.height + 1,
                });
            } else {
                // Put back nodes
                running_digests.push(left);
                running_digests.push(right);
                break;
            }
        }
    }

    // Compute the merkle tree root hash
    pub fn root(&self) -> DigestResult {
        if self.running_digests.is_empty() {
            // The merkle tree holds an empty list. Pad it to have 2^0=1 element.
            return self.padding_digest;
        }

        // Take the current running digests and keep adding padding elements until we achieve
        // a power of two sized list which occurs when there is only one running digest left.
        let mut running_digests = self.running_digests.clone();

        // This loops runs at most running_digests.len() times or ceil(log2(count))
        while running_digests.len() > 1 {
            let last = running_digests.last().unwrap();
            let last_height = last.height;
            // Add enough padding elements to merge with the last node
            running_digests.push(Node {
                hash: self.precomputed_padding[last_height],
                height: last_height,
            });
            MerkleTree::merge_partial_digests(&mut running_digests);
        }
        // running_digest.len() == 1 after loop terminates
        running_digests.first().unwrap().hash
    }

    // Computes the hash of a node that is the root of a subtree holding elements with index
    // in [left_index, right_index]. The size of this interval must be 2^height.
    //
    // The right boundary field restricts the elements in the merkle tree list to those with index
    // in [0, right_boundary] simulating a merkle tree spanning a specific initial portion.
    fn compute_node_hash(
        &self,
        right_boundary: MerkleIndex,
        left_index: MerkleIndex,
        right_index: MerkleIndex,
        height: usize
    ) -> DigestResult {
        // The left index and right index must match iff the height is 0
        if (left_index == right_index) != (height == 0) {
            panic!("Correctness error.");
        }
        if left_index > right_index {
            panic!("Correctness error.");
        }
        // The number of elements in the interval must be 2^height
        if (right_index - left_index + 1) != (1 << height) {
            panic!("Correctness error.");
        }

        if height == 0 {
            // Base case
            if left_index > right_boundary {
                return self.padding_digest
            }
            return match self.items.get(left_index as usize) {
                None => {
                    self.padding_digest
                }
                Some(d) => {
                    *d
                }
            }
        } else {
            // We treat the list in the merkle tree to be padded up to a power of two size.
            // The subtree focused on right now contains only padding elements and we can easily
            // compute the hash without further recursion.
            if right_boundary < left_index {
                return self.precomputed_padding[height];
            }

            // Induction
            let mid = left_index + (right_index - left_index) / 2;
            // Compute the hashes of the left and right subtree
            let left = self.compute_node_hash(right_boundary, left_index, mid, height - 1);
            let right = self.compute_node_hash(right_boundary, mid + 1, right_index, height - 1);
            MerkleTree::hash(left, right)
        }
    }

    // Merkle proofs for a set of elements L ⊆ T, where T is the set of all elements in the list,
    // involves recording the hashes of the nodes in cover(T - L). (See Section 8.9 of Boneh and Shoup)
    //
    // To find the cover of T-L, we work inductively starting at a node which is the root of the subtree
    // of height h containing elements with index [left_index, right_index].
    //
    // For this inductive construction to work, the size of [left_index, right_index] must be 2^height.
    //
    // The size field restricts the items in the list to the items with index in [0, size) simulating
    // a merkle tree with only size elements.
    fn record_complement_cover_hashes(
        &self,
        indices: &HashSet<MerkleIndex>,
        current_node: InternalNode,
        right_boundary: MerkleIndex,
        complement_cover_hashes: &mut HashMap<InternalNode, DigestResult>,
        left_index: MerkleIndex,
        right_index: MerkleIndex,
        height: usize,
    ) {
        // The left index and right index must match iff the height is 0
        if (left_index == right_index) != (height == 0) {
            panic!("Correctness error.");
        }
        if left_index > right_index {
            panic!("Correctness error.");
        }
        // The number of elements in the interval must be 2^height
        if (right_index - left_index + 1) != (1 << height) {
            panic!("Correctness error.");
        }

        // Compute the hash at a node inductively on the height
        if height == 0 {
            // Base case
            if !indices.contains(&left_index) {
                // Clearly if we have a singleton binary tree and this node is not a selected
                // index, it must be in the cover of the complement
                let hash = self.compute_node_hash(right_boundary, left_index, right_index, 0);
                complement_cover_hashes.insert(current_node, hash);
            }
        } else {
            // Inductive case
            let exists_index_in_interval = indices.iter().any(|i| {
                left_index <= *i && *i <= right_index
            });

            if !exists_index_in_interval {
                // If the tree has a root not covering any index, the root must be in the cover
                // of the complement.
                let hash = self.compute_node_hash(right_boundary, left_index, right_index, height);
                complement_cover_hashes.insert(current_node, hash);
            } else {
                let mid = left_index + (right_index - left_index) / 2;

                let mut left = current_node.clone();
                left.push(Direction::Left);

                let mut right = current_node;
                right.push(Direction::Right);

                // Computing the cover exhibits optimal substructure so it suffices to
                // record the cover on the left and right subtrees
                //
                // Recursion depth is height. Stack overflowing is very unlikely.

                // Explore the left subtree
                self.record_complement_cover_hashes(
                    indices,
                    left,
                    right_boundary,
                    complement_cover_hashes,
                    left_index, mid, height - 1,
                );

                // Explore the right subtree
                self.record_complement_cover_hashes(
                    indices,
                    right,
                    right_boundary,
                    complement_cover_hashes,
                    mid + 1, right_index, height - 1,
                );
            }
        }
    }

    pub fn largest_index_height_after_pow_two_padding(right_boundary: MerkleIndex) -> (MerkleIndex, usize) {
        let mut res: MerkleIndex = 1;
        for k in 0..INDEX_BITS {
            // INVARIANT: res = 2^k at this point
            // Checking if 2^k is strictly bigger than right_boundary
            if res > right_boundary {
                return (res - 1, k);
            }

            // This condition is made to prevent an overflow
            if k + 1 < INDEX_BITS {
                res <<= 1; // Ensures loops invariant holds
            }
        }

        // 2^(INDEX_BITS - 1) <= right_boundary <= 2^INDEX_BITS
        (MerkleIndex::MAX, INDEX_BITS)
    }

    // Given the current state of the merkle tree, generates a membership proof for the items
    // at the provided indices, but for a modified merkle tree holding a slice of the elements.
    // This slice includes elements with index [0, right_boundary].
    pub fn generate_proof(&self, indices: &HashSet<MerkleIndex>, right_boundary: MerkleIndex) -> Option<MembershipProof> {
        if !indices.iter().all(|i| *i <= right_boundary) {
            return None;
        }

        let (largest_index, height) = MerkleTree::largest_index_height_after_pow_two_padding(right_boundary);
        let mut proof = HashMap::new();

        self.record_complement_cover_hashes(
            indices,
            vec![],
            right_boundary,
            &mut proof,
            0, largest_index, height
        );

        let internal_hashes = proof.into_iter()
            .map(|(k, v)| {
                (serialize_internal_node(&k), v)
            })
            .collect();

        let items = indices.iter()
            .map(|i| {
                if *i > right_boundary {
                    // This should not be possible by initial check
                    return (*i, self.padding_digest);
                }

                match self.items.get(*i as usize) {
                    None => {
                        (*i, self.padding_digest)
                    }
                    Some(d) => {
                        (*i, *d)
                    }
                }
            })
            .collect();

        Some(MembershipProof {
            internal_hashes,
            items,
            right_boundary
        })
    }

    fn compute_root_from_proof(
        index_hashes: &HashMap<MerkleIndex, DigestResult>,
        internal_hashes: &HashMap<InternalNode, DigestResult>,
        current_node: InternalNode,
        left_index: MerkleIndex,
        right_index: MerkleIndex,
        height: usize,
    ) -> Option<DigestResult> {
        return if height == 0 {
            // Base case
            match index_hashes.get(&left_index) {
                None => {
                    // This node must be in the complement cover
                    internal_hashes.get(&current_node).cloned()
                }
                Some(d) => {
                    Some(*d)
                }
            }
        } else {
            let exists_index_in_interval = index_hashes.keys()
                .any(|i| left_index <= *i && *i <= right_index);

            if !exists_index_in_interval {
                // This node must be in the complement cover
                return internal_hashes.get(&current_node).cloned();
            }

            let mid = left_index + (right_index - left_index) / 2;

            let mut left = current_node.clone();
            left.push(Direction::Left);
            let left_hash = MerkleTree::compute_root_from_proof(
                index_hashes,
                internal_hashes,
                left,
                left_index,
                mid,
                height - 1
            )?;
            let mut right = current_node;
            right.push(Direction::Right);
            let right_hash = MerkleTree::compute_root_from_proof(
                index_hashes,
                internal_hashes,
                right,
                mid + 1,
                right_index,
                height - 1
            )?;

            Some(MerkleTree::hash(left_hash, right_hash))
        }
    }

    pub fn is_valid_proof(root_hash: &DigestResult, proof: &MembershipProof) -> bool {
        // Deserialize the internal hashes into a more interpretable form with directions
        // and filter out any malformed directions
        let internal_hashes = proof.internal_hashes.iter()
            .map(|(k, v)| {
                (deserialize_internal_node(k), *v)
            })
            .filter(|(k, _)| k.is_some())
            .map(|(k, v)| (k.unwrap(), v))
            .collect::<HashMap<InternalNode, DigestResult>>();

        let (largest_index, height) = MerkleTree::largest_index_height_after_pow_two_padding(proof.right_boundary);

        let computed_root_hash = MerkleTree::compute_root_from_proof(
            &proof.items.iter().cloned().collect(),
            &internal_hashes,
            vec![],
            0, largest_index, height
        );

        match computed_root_hash {
            None => { false }
            Some(computed_root_hash) => { &computed_root_hash == root_hash }
        }
    }
}