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

//! Single Path Merkle Tree Storage

// TODO: Should we be storing the root? Can we have a version where we don't?

use crate::merkle_tree::{
    capacity, Configuration, CurrentPath, InnerDigest, LeafDigest, MerkleTree, Parameters, Root,
    Tree,
};
use core::{fmt::Debug, hash::Hash};

/// Tree Length State
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Length {
    /// Empty Tree
    Empty,

    /// Can Accept Leaves
    CanAccept,

    /// Full Tree
    Full,
}

/// Single Path Merkle Tree Type
pub type SinglePathMerkleTree<C> = MerkleTree<C, SinglePath<C>>;

/// Single Path Merkle Tree Backing Structure
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct SinglePath<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digest
    leaf_digest: Option<LeafDigest<C>>,

    /// Current Path
    current_path: CurrentPath<C>,

    /// Root
    root: Root<C>,
}

impl<C> SinglePath<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the number of leaves in the merkle tree.
    #[inline]
    fn len(&self) -> usize {
        if self.leaf_digest.is_none() {
            0
        } else {
            self.current_path.leaf_index().0 + 1
        }
    }

    /// Returns the state of the length of this tree.
    #[inline]
    pub fn length_state(&self) -> Length {
        if self.leaf_digest.is_none() {
            Length::Empty
        } else if self.current_path.leaf_index().0 < capacity::<C>() - 2 {
            Length::CanAccept
        } else {
            Length::Full
        }
    }

    /// Returns the current merkle tree root.
    #[inline]
    pub fn root(&self) -> &Root<C> {
        &self.root
    }

    /// Returns the current merkle tree path for the current leaf.
    #[inline]
    pub fn current_path(&self) -> &CurrentPath<C> {
        &self.current_path
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
        self.current_path
            .root(parameters, self.leaf_digest().unwrap())
    }
}

impl<C> Tree<C> for SinglePath<C>
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
    fn is_empty(&self) -> bool {
        self.leaf_digest.is_none()
    }

    #[inline]
    fn current_leaf(&self) -> LeafDigest<C> {
        self.leaf_digest.as_ref().cloned().unwrap_or_default()
    }

    #[inline]
    fn root(&self, parameters: &Parameters<C>) -> Root<C> {
        let _ = parameters;
        self.root.clone()
    }

    #[inline]
    fn matching_root(&self, parameters: &Parameters<C>, root: &Root<C>) -> bool {
        let _ = parameters;
        &self.root == root
    }

    #[inline]
    fn current_path(&self, parameters: &Parameters<C>) -> CurrentPath<C> {
        let _ = parameters;
        self.current_path.clone()
    }

    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        match self.length_state() {
            Length::Full => return Some(false),
            Length::Empty => {
                self.leaf_digest = Some(leaf_digest()?);
                self.root = self.compute_root(parameters);
            }
            Length::CanAccept => {
                self.root = self.current_path.update(
                    parameters,
                    self.leaf_digest.as_mut().unwrap(),
                    leaf_digest()?,
                );
            }
        }
        Some(true)
    }
}
