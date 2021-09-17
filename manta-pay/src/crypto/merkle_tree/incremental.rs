// Copyright 2019-2021 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Arkworks Incremental Merkle Tree Implementation

use alloc::vec::Vec;
use ark_crypto_primitives::{
    crh::TwoToOneCRH,
    merkle_tree::{Config, LeafDigest, LeafParam, TwoToOneDigest, TwoToOneParam},
    Error, Path, CRH,
};
use ark_ff::{to_bytes, ToBytes};

/// Incremental Merkle Tree
///
/// This merkle tree implementation has a fixed runtime height `h`, and stores `2^h` leaves.
#[derive(Clone)]
pub struct IncrementalMerkleTree<P>
where
    P: Config,
{
    /// Hashes of leaf nodes from left to right
    leaf_nodes: Vec<LeafDigest<P>>,

    /// Inner Hash Parameters
    two_to_one_hash_param: TwoToOneParam<P>,

    /// Leaf Hash Parameters
    leaf_hash_param: LeafParam<P>,

    /// Fixed Merkle Tree Height
    height: usize,

    /// Path of the Current Leaf
    current_path: Path<P>,

    /// Root of the Merkle Tree
    root: TwoToOneDigest<P>,

    /// Emptiness Flag
    empty: bool,
}

impl<P> IncrementalMerkleTree<P>
where
    P: Config,
{
    /// Checks if `self` is an empty tree.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.empty
    }

    /// Returns the index of the current (right-most) leaf.
    #[inline]
    pub fn current_index(&self) -> Option<usize> {
        if self.is_empty() {
            None
        } else {
            Some(self.current_path.leaf_index)
        }
    }

    /// Returns the next available index for a leaf node.
    #[inline]
    pub fn next_available(&self) -> Option<usize> {
        let current_index = self.current_path.leaf_index;
        if self.is_empty() {
            Some(0)
        } else if current_index < (1 << (self.height - 1)) - 1 {
            Some(current_index + 1)
        } else {
            None
        }
    }

    /// Returns the proof for the current (right-most) leaf.
    #[inline]
    pub fn current_proof(&self) -> &Path<P> {
        &self.current_path
    }

    /// Returns the root of the tree.
    #[inline]
    pub fn root(&self) -> &TwoToOneDigest<P> {
        &self.root
    }

    /// Creates an empty merkle tree with leaves filled with the sentinel value.
    ///
    /// # Panics
    ///
    /// This function panics if the given `height` is less than `2`.
    pub fn blank(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        height: usize,
    ) -> Self {
        assert!(
            height > 1,
            "the height of incremental merkle tree should be at least 2"
        );
        IncrementalMerkleTree {
            current_path: Path {
                leaf_sibling_hash: Default::default(),
                auth_path: Default::default(),
                leaf_index: Default::default(),
            },
            leaf_nodes: Default::default(),
            two_to_one_hash_param: two_to_one_hash_param.clone(),
            leaf_hash_param: leaf_hash_param.clone(),
            root: Default::default(),
            height,
            empty: true,
        }
    }

    /// Asserts that we are inserting into a valid index.
    #[inline]
    fn assert_valid_index(&self) {
        assert!(self.next_available() != None, "index out of range");
    }

    /// Appends `leaf` to the tree at the next available index.
    ///
    /// # Example
    ///
    /// Given the following tree:
    /// ```tree_diagram
    ///         [A]
    ///        /   \
    ///      [B]   ()
    ///     / \   /  \
    ///    D [E] ()  ()
    ///   .. / \ ....
    ///    [I]{leaf}
    /// ```
    /// running `append({leaf})` would insert `leaf` after `[I]` and would trigger a recompute of
    /// `[E]`, `[B]`, and `[A]`.
    pub fn append<L>(&mut self, leaf: L) -> Result<(), Error>
    where
        L: ToBytes,
    {
        self.assert_valid_index();
        let leaf_digest = P::LeafHash::evaluate(&self.leaf_hash_param, &to_bytes!(leaf)?)?;
        let (path, root) = self.next_path(&leaf_digest)?;
        self.leaf_nodes.push(leaf_digest);
        self.current_path = path;
        self.root = root;
        self.empty = false;
        Ok(())
    }

    /// Generates the new path and root of the tree given `new_leaf_digest` as the next inserted
    /// leaf in the tree.
    fn next_path(
        &self,
        new_leaf_digest: &LeafDigest<P>,
    ) -> Result<(Path<P>, TwoToOneDigest<P>), Error> {
        self.assert_valid_index();

        // Calculate tree height and empty hash.
        let tree_height = self.height;
        let hash_of_empty_node = TwoToOneDigest::<P>::default();
        let hash_of_empty_leaf = LeafDigest::<P>::default();

        // Create a new auth path with length two less than the tree height.
        let mut new_auth_path = Vec::with_capacity(tree_height - 2);

        if self.is_empty() {
            // generate auth path and calculate the root
            let mut current_node = P::TwoToOneHash::evaluate(
                &self.two_to_one_hash_param,
                &to_bytes!(new_leaf_digest)?,
                &to_bytes!(LeafDigest::<P>::default())?,
            )?;
            // all the auth path node are empty nodes
            for _ in 0..tree_height - 2 {
                new_auth_path.push(hash_of_empty_node.clone());
                current_node = P::TwoToOneHash::evaluate(
                    &self.two_to_one_hash_param,
                    &to_bytes!(current_node)?,
                    &to_bytes!(hash_of_empty_node.clone())?,
                )?;
            }

            let path = Path {
                leaf_index: 0,
                auth_path: new_auth_path,
                leaf_sibling_hash: hash_of_empty_leaf,
            };
            Ok((path, current_node))
        } else {
            // compute next path of a non-empty tree
            // Get the indices of the previous and propsed (new) leaf node
            let mut new_index = self.next_available().unwrap();
            let mut old_index = self.current_index().unwrap();
            let old_leaf = &self.leaf_nodes[old_index];

            // generate two mutable node: old_current_node, new_current_node to iterate on
            let (old_left_leaf, old_right_leaf) = if is_left_child(old_index) {
                (
                    self.leaf_nodes[old_index].clone(),
                    self.current_path.leaf_sibling_hash.clone(),
                )
            } else {
                (
                    self.current_path.leaf_sibling_hash.clone(),
                    self.leaf_nodes[old_index].clone(),
                )
            };

            let (new_left_leaf, new_right_leaf, leaf_sibling) = if is_left_child(new_index) {
                (new_leaf_digest, &hash_of_empty_leaf, &hash_of_empty_leaf)
            } else {
                (old_leaf, new_leaf_digest, old_leaf)
            };

            let mut old_current_node = P::TwoToOneHash::evaluate(
                &self.two_to_one_hash_param,
                &to_bytes!(old_left_leaf)?,
                &to_bytes!(old_right_leaf)?,
            )?;
            let mut new_current_node = P::TwoToOneHash::evaluate(
                &self.two_to_one_hash_param,
                &to_bytes!(new_left_leaf)?,
                &to_bytes!(new_right_leaf)?,
            )?;

            // reverse the old_auth_path to make it bottom up
            let mut old_auth_path = self.current_path.auth_path.clone();
            old_auth_path.reverse();

            // build new_auth_path and root recursively
            for old_auth_path_point in old_auth_path.iter().take(tree_height - 2) {
                new_index = parent_index_on_level(new_index);
                old_index = parent_index_on_level(old_index);
                if new_index == old_index {
                    // this means the old path and new path are merged,
                    // as a result, no need to update the old_current_node any more

                    // add the auth path node
                    new_auth_path.push(old_auth_path_point.clone());

                    // update the new current node (this is needed to compute the root)
                    let (new_left, new_right) = if is_left_child(new_index) {
                        (new_current_node, hash_of_empty_node.clone())
                    } else {
                        (old_auth_path_point.clone(), new_current_node)
                    };
                    new_current_node = P::TwoToOneHash::evaluate(
                        &self.two_to_one_hash_param,
                        &to_bytes!(new_left)?,
                        &to_bytes!(new_right)?,
                    )?;
                } else {
                    // this means old path and new path haven't been merged,
                    // as a reulst, need to update both the new_current_node and new_current_node
                    let auth_node = if is_left_child(new_index) {
                        hash_of_empty_node.clone()
                    } else {
                        old_current_node.clone()
                    };
                    new_auth_path.push(auth_node);

                    // update both old_current_node and new_current_node
                    // update new_current_node
                    let (new_left, new_right) = if is_left_child(new_index) {
                        (new_current_node.clone(), hash_of_empty_node.clone())
                    } else {
                        (old_current_node.clone(), new_current_node)
                    };
                    new_current_node = P::TwoToOneHash::evaluate(
                        &self.two_to_one_hash_param,
                        &to_bytes!(new_left)?,
                        &to_bytes!(new_right)?,
                    )?;

                    // We only need to update the old_current_node bottom up when it is right child
                    if !is_left_child(old_index) {
                        old_current_node = P::TwoToOneHash::evaluate(
                            &self.two_to_one_hash_param,
                            &to_bytes!(old_auth_path_point.clone())?,
                            &to_bytes!(old_current_node)?,
                        )?;
                    }
                }
            }

            // reverse new_auth_path to top down
            new_auth_path.reverse();
            let path = Path {
                leaf_index: self.next_available().unwrap(),
                auth_path: new_auth_path,
                leaf_sibling_hash: leaf_sibling.clone(),
            };
            Ok((path, new_current_node))
        }
    }
}

/// Returns `true` if and only if the given index on the current level represents a left child.
#[inline]
fn is_left_child(index_on_level: usize) -> bool {
    index_on_level % 2 == 0
}

/// Returns the parent index for the index on the current level.
#[inline]
fn parent_index_on_level(index_on_level: usize) -> usize {
    index_on_level >> 1
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use ark_crypto_primitives::crh::{pedersen, TwoToOneCRH as TwoToOneCRHTrait, CRH as CRHTrait};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::{BigInteger256, UniformRand};
    use rand::{rngs::ThreadRng, thread_rng};

    /// Pedersen Window Parameters
    #[derive(Clone)]
    struct Window4x256;

    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    /// Leaf Hash
    type LeafH = pedersen::CRH<JubJub, Window4x256>;

    /// Two-to-One Pedersen Hash
    type CompressH = pedersen::CRH<JubJub, Window4x256>;

    /// JubJub Merkle Tree Parameters
    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;
    }

    /// Jub Jub Incremental Merkle Tree
    type JubJubIncrementalMerkleTree = IncrementalMerkleTree<JubJubMerkleTreeParams>;

    /// Builds an incremental merkle tree element by element and tests that each generated proof is
    /// valid.
    fn incremental_merkle_tree_test<L: ToBytes>(tree_height: usize, update_query: &[L]) {
        let mut rng = thread_rng();
        let leaf_crh_params = <LeafH as CRHTrait>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHTrait>::setup(&mut rng).unwrap();
        let mut tree =
            JubJubIncrementalMerkleTree::blank(&leaf_crh_params, &two_to_one_params, tree_height);
        for v in update_query {
            let v = to_bytes!(v).unwrap();
            tree.append(v.clone()).unwrap();
            println!("{:?}", tree.next_available());
            println!("{:?}", tree.is_empty());
            let proof = tree.current_proof();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, tree.root(), &v)
                .unwrap());
        }
    }

    /// Tests the emptiness criterion for an incremental merkle tree.
    #[test]
    fn test_emptyness_for_imt() {
        let mut rng = thread_rng();
        let leaf_crh_params = <LeafH as CRHTrait>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHTrait>::setup(&mut rng).unwrap();
        let mut tree = JubJubIncrementalMerkleTree::blank(&leaf_crh_params, &two_to_one_params, 5);
        assert!(tree.is_empty());
        let v = BigInteger256::rand(&mut rng);
        tree.append(to_bytes!(v).unwrap()).unwrap();
        assert!(!tree.is_empty());
    }

    /// Samples merkle tree updates from `rng` and tests them with the
    /// [`incremental_merkle_tree_test`] function.
    #[inline]
    fn sample_updates_and_test_imt(rng: &mut ThreadRng, update_count: usize, tree_height: usize) {
        let mut updates = Vec::new();
        for _ in 0..update_count {
            updates.push(BigInteger256::rand(rng));
        }
        incremental_merkle_tree_test(tree_height, &updates);
    }

    /// Runs tests for well-formed trees.
    #[test]
    fn good_root_test_for_imt() {
        let mut rng = thread_rng();
        sample_updates_and_test_imt(&mut rng, 2, 2);
        sample_updates_and_test_imt(&mut rng, 7, 4);
        sample_updates_and_test_imt(&mut rng, 128, 8);
    }

    /// Runs test for a tree which has exceeded capacity.
    #[test]
    #[should_panic]
    fn out_of_capacity_test_for_imt() {
        let mut rng = thread_rng();
        sample_updates_and_test_imt(&mut rng, 3, 2);
    }
}
