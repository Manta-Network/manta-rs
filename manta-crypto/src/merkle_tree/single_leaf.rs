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

// TODO: Should we be storing the root? Can we have a version where we don't?

use crate::merkle_tree::{
    capacity, Configuration, CurrentPath, InnerDigest, InnerPath, LeafDigest, MerkleTree, Node,
    Parameters, Parity, Path, Root, Tree,
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

    /// Current Path
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
            self.path.leaf_index().0 + 1
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

    /* TODO:
    /// Returns the current merkle tree path for the current leaf.
    #[inline]
    pub fn current_path(&self) -> &CurrentPath<C> {
        &self.current_path
    }
    */

    /// Returns the currently stored leaf digest, returning `None` if the tree is empty.
    #[inline]
    pub fn leaf_digest(&self) -> Option<&LeafDigest<C>> {
        self.leaf_digest.as_ref()
    }

    /// Returns a shared reference to the current leaf digest.
    #[inline]
    fn leaf_digest_ref(&self) -> &LeafDigest<C> {
        self.leaf_digest().unwrap()
    }

    /// Returns a mutable reference to the current leaf digest.
    #[inline]
    fn leaf_digest_mut_ref(&mut self) -> &mut LeafDigest<C> {
        self.leaf_digest.as_mut().unwrap()
    }

    /// Computes the root of the tree under the assumption that `self.leaf_digest.is_some()`
    /// evaluates to `true`.
    #[inline]
    fn compute_root(&self, parameters: &Parameters<C>) -> Root<C> {
        self.path.root(parameters, self.leaf_digest_ref())
    }
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
    fn current_path(&self, parameters: &Parameters<C>) -> CurrentPath<C> {
        /* TODO:
        let _ = parameters;
        self.current_path.clone()
        */
        todo!()
    }

    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        let mut index = match self.next_index() {
            Some(index) => index,
            _ => return Some(false),
        };

        let leaf_digest = leaf_digest()?;

        if index == 0 {
            self.leaf_digest = Some(leaf_digest);
            self.root = self.compute_root(parameters);
        } else {
            self.path.inner_path.leaf_index = index;
            match index.parity() {
                Parity::Left => {
                    let mut last_index = index - 1;
                    let mut last_accumulator = parameters.join_leaves(
                        &self.path.sibling_digest,
                        &mem::replace(self.leaf_digest.as_mut().unwrap(), leaf_digest),
                    );

                    self.path.sibling_digest = Default::default();

                    let mut accumulator =
                        parameters.join_leaves(self.leaf_digest_ref(), &self.path.sibling_digest);

                    let mut i = 0;
                    while !Node::are_siblings(&last_index.into_parent(), &index.into_parent()) {
                        last_accumulator = last_index.join(
                            parameters,
                            &last_accumulator,
                            &self.path.inner_path.path[i],
                        );
                        self.path.inner_path.path[i] = Default::default();
                        accumulator = parameters.join(&accumulator, &self.path.inner_path.path[i]);
                        i += 1;
                    }

                    self.path.inner_path.path[i] = last_accumulator;
                    accumulator = parameters.join(&self.path.inner_path.path[i], &accumulator);

                    self.root = InnerPath::fold(
                        parameters,
                        index,
                        accumulator,
                        &self.path.inner_path.path[i + 1..],
                    );
                }
                Parity::Right => {
                    self.path.sibling_digest =
                        mem::replace(self.leaf_digest_mut_ref(), leaf_digest);
                    self.root = self.compute_root(parameters);
                }
            }
            /* TODO:
            self.root =
                self.current_path
                    .update(parameters, self.leaf_digest_mut_ref(), leaf_digest);
            */
        }

        Some(true)
    }
}
