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

//! Merkle Tree Forks

extern crate alloc;

use crate::merkle_tree::{
    capacity, inner_tree::InnerTree, Configuration, InnerDigest, Leaf, LeafDigest, MerkleTree,
    Parameters, Path, Root, Tree,
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};

/// Merkle Tree Delta
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct Delta<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digests
    pub(super) leaf_digests: Vec<LeafDigest<C>>,

    /// Inner Digests
    pub(super) inner_digests: InnerTree<C>,
}

impl<C> Delta<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`Delta`] from `leaf_digests` and `inner_digests`.
    #[inline]
    pub fn new(leaf_digests: Vec<LeafDigest<C>>, inner_digests: InnerTree<C>) -> Self {
        Self {
            leaf_digests,
            inner_digests,
        }
    }

    ///
    #[inline]
    pub fn len(&self) -> usize {
        self.leaf_digests.len()
    }

    ///
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    ///
    #[inline]
    fn root<T>(&self, parameters: &Parameters<C>, trunk: &T) -> Root<C>
    where
        T: Tree<C>,
    {
        todo!()
    }

    ///
    #[inline]
    fn path<T>(
        &self,
        parameters: &Parameters<C>,
        trunk: &T,
        query: ForkQuery<C, T>,
    ) -> Result<Path<C>, T::Error>
    where
        T: Tree<C>,
    {
        todo!()
    }

    ///
    #[inline]
    fn push<T>(&mut self, parameters: &Parameters<C>, trunk: &T, leaf: &Leaf<C>) -> bool
    where
        T: Tree<C>,
    {
        if trunk.len() + self.len() >= capacity::<C>() {
            return false;
        }

        todo!()
    }
}

/// Merkle Tree Fork
#[derive(derivative::Derivative)]
/* TODO:
#[derivative(
    Clone(bound = "Parameters<C>: Clone, T: Clone"),
    Copy(bound = "Parameters<C>: Copy, T: Copy"),
    Debug(bound = "Parameters<C>: Debug, T: Debug"),
    Default(bound = "Parameters<C>: Default, T: Default"),
    Eq(bound = "Parameters<C>: Eq, T: Eq"),
    Hash(bound = "Parameters<C>: Hash, T: Hash"),
    PartialEq(bound = "Parameters<C>: PartialEq, T: PartialEq")
)]
*/
pub struct Fork<'t, C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Original Trunk
    pub(super) trunk: &'t MerkleTree<C, T>,

    /// Delta
    pub(super) delta: Delta<C>,
}

impl<'t, C, T> Fork<'t, C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    ///
    #[inline]
    pub fn new(trunk: &'t MerkleTree<C, T>) -> Self {
        Self {
            trunk,
            delta: Default::default(),
        }
    }

    ///
    #[inline]
    pub fn parameters(&self) -> &Parameters<C> {
        self.trunk.parameters()
    }

    ///
    #[inline]
    pub fn root(&self) -> Root<C> {
        self.delta.root(&self.trunk.parameters, &self.trunk.tree)
    }

    ///
    #[inline]
    pub fn path(&self, query: ForkQuery<C, T>) -> Result<Path<C>, T::Error> {
        self.delta
            .path(&self.trunk.parameters, &self.trunk.tree, query)
    }

    ///
    #[inline]
    pub fn push(&mut self, leaf: &Leaf<C>) -> bool {
        self.delta
            .push(&self.trunk.parameters, &self.trunk.tree, leaf)
    }
}

/// Fork Query Type
pub enum ForkQuery<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Trunk Query
    Trunk(T::Query),

    /// Branch Query
    Branch(usize),
}
