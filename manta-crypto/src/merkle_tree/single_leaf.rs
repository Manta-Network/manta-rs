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

//! Single Leaf Merkle Tree Storage

use crate::merkle_tree::{
    capacity, Configuration, InnerDigest, LeafDigest, MerkleTree, Node, Parameters, Parity, Path,
    Root, Tree,
};
use core::{fmt::Debug, hash::Hash, mem};

/// Single Leaf Merkle Tree Type
pub type SingleLeafMerkleTree<C> = MerkleTree<C, SingleLeaf<C>>;

/// Single Leaf Merkle Tree Backing Structure
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct SingleLeaf<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digest
    leaf_digest: Option<LeafDigest<C>>,

    /// Path
    path: Path<C>,

    /// Root
    root: Root<C>,
}

impl<C> SingleLeaf<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the number of leaves in the merkle tree.
    #[inline]
    fn len(&self) -> usize {
        if self.leaf_digest.is_none() {
            0
        } else {
            self.path.leaf_index.0 + 1
        }
    }

    /// Returns the next avaiable index or `None` if the merkle tree is full.
    #[inline]
    fn next_index(&self) -> Option<Node> {
        let len = self.len();
        if len == 0 {
            Some(Node(0))
        } else if len < capacity::<C>() - 1 {
            Some(Node(len + 1))
        } else {
            None
        }
    }

    /// Returns the current merkle tree root.
    #[inline]
    pub fn root(&self) -> &Root<C> {
        &self.root
    }

    /// Returns the current merkle tree path for the current leaf.
    #[inline]
    pub fn path(&self) -> &Path<C> {
        &self.path
    }

    /// Returns the currently stored leaf digest, returning `None` if the tree is empty.
    #[inline]
    pub fn leaf_digest(&self) -> Option<&LeafDigest<C>> {
        self.leaf_digest.as_ref()
    }

    /// Computes the root of the tree under the assumption that `self.leaf_digest.is_some()`
    /// evaluates to `true`.
    #[inline]
    fn compute_root(&self, parameters: &Parameters<C>) -> Root<C> {
        self.path
            .root_relative_to(parameters, self.leaf_digest.as_ref().unwrap())
    }

    /* TODO:
    pub fn maybe_push_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digest: F,
    ) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
        InnerDigest<C>: Clone,
    {
        // TODO[move]:
        use crate::merkle_tree::path_length;

        let index = match self.next_index() {
            Some(index) => index,
            _ => return Some(false),
        };

        let leaf_digest = leaf_digest()?;

        if index == 0 {
            self.leaf_digest = Some(leaf_digest);
            self.root = self.compute_root(parameters);
        } else {
            match index.parity() {
                Parity::Left => {
                    let default_leaf_digest = Default::default();
                    let default_inner_digest = Default::default();

                    let mut prev_index = index - 1;
                    let mut prev_accumulator = parameters.join_leaves(
                        &self.path.sibling_digest,
                        self.leaf_digest.as_ref().unwrap(),
                    );

                    let mut next_index = index;
                    let mut next_accumulator =
                        parameters.join_leaves(&leaf_digest, &default_leaf_digest);

                    let mut i = 0;
                    loop {
                        if prev_index.into_parent() == next_index.into_parent() {
                            next_accumulator =
                                parameters.join(&prev_accumulator, &next_accumulator);
                            break;
                        } else {
                            self.path.inner_path[i] = prev_accumulator.clone();
                            next_accumulator =
                                parameters.join(&next_accumulator, &default_inner_digest);
                            prev_accumulator = prev_index.join(
                                parameters,
                                &prev_accumulator,
                                &self.path.inner_path[i],
                            );
                        }
                        i += 1;
                    }

                    for j in i..path_length::<C>() {
                        next_accumulator = next_index.into_parent().join(
                            parameters,
                            &next_accumulator,
                            &self.path.inner_path[j],
                        );
                    }

                    self.path.leaf_index = index;
                    self.root = Root(next_accumulator);
                }
                Parity::Right => {
                    self.path.leaf_index = index;
                    self.path.sibling_digest =
                        mem::replace(self.leaf_digest.as_mut().unwrap(), leaf_digest);
                    self.root = self.compute_root(parameters);
                }
            }
        }

        Some(true)
    }
    */
}

impl<C> Tree<C> for SingleLeaf<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: Clone,
    InnerDigest<C>: Clone,
{
    #[inline]
    fn new(parameters: &Parameters<C>) -> Self {
        let _ = parameters;
        Default::default()
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn root(&self, parameters: &Parameters<C>) -> Root<C> {
        let _ = parameters;
        self.root.clone()
    }

    #[inline]
    fn current_path(&self, parameters: &Parameters<C>) -> Path<C> {
        let _ = parameters;
        self.path.clone()
    }

    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        let index = match self.next_index() {
            Some(index) => index,
            _ => return Some(false),
        };

        let leaf_digest = leaf_digest()?;

        if index == 0 {
            self.root = self.path.root_relative_to(parameters, &leaf_digest);
        } else {
            let mut next_index = index;

            let default_leaf_digest = Default::default();
            let default_inner_digest = Default::default();

            let current_leaf_digest = self.leaf_digest.as_ref().unwrap();

            // TODO: Get rid of this clone.

            let (mut accumulator, sibling_digest) = match next_index.parity() {
                Parity::Left => (
                    parameters.join_leaves(&leaf_digest, &default_leaf_digest),
                    default_leaf_digest,
                ),
                Parity::Right => (
                    parameters.join_leaves(current_leaf_digest, &leaf_digest),
                    current_leaf_digest.clone(),
                ),
            };

            let mut prev_index = next_index - 1;
            let mut prev_digest =
                prev_index.join_leaves(parameters, current_leaf_digest, &self.path.sibling_digest);

            // TODO: Mutate the path in place.

            let inner_path = self
                .path
                .inner_path
                .iter()
                .map(|digest| {
                    if prev_index.into_parent() == next_index.into_parent() {
                        accumulator = next_index.join_opposite_pair(
                            parameters,
                            digest,
                            &accumulator,
                            &default_inner_digest,
                        );
                        digest.clone()
                    } else {
                        let next_index_parity = next_index.parity();

                        let next_inner_path_digest = next_index_parity
                            .map(|| default_inner_digest.clone(), || prev_digest.clone());

                        accumulator = next_index_parity.join_opposite_pair(
                            parameters,
                            &prev_digest,
                            &accumulator,
                            &default_inner_digest,
                        );

                        if prev_index.is_right() {
                            prev_digest = parameters.join(digest, &prev_digest);
                        }

                        next_inner_path_digest
                    }
                })
                .collect();

            self.path = Path::new(index, sibling_digest, inner_path);
            self.root = Root(accumulator);
        }

        self.leaf_digest = Some(leaf_digest);

        Some(true)
    }
}
