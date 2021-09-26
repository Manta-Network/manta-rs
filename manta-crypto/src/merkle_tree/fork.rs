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
    capacity, inner_tree::InnerTree, Configuration, GetPath, GetPathError, InnerDigest, Leaf,
    LeafDigest, MerkleTree, Parameters, Path, Root, Tree,
};
use alloc::{
    rc::{Rc, Weak},
    vec::Vec,
};
use core::{fmt::Debug, hash::Hash};

/// Fork-able Merkle Tree
pub struct Trunk<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Base Merkle Tree
    base: Rc<MerkleTree<C, T>>,
}

impl<C, T> Trunk<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Builds a new [`Trunk`] from a reference-counted [`MerkleTree`].
    #[inline]
    fn new_inner(base: Rc<MerkleTree<C, T>>) -> Self {
        Self { base }
    }

    /// Builds a new [`Trunk`] from a `base` merkle tree.
    #[inline]
    pub fn new(base: MerkleTree<C, T>) -> Self {
        Self::new_inner(Rc::new(base))
    }

    /// Converts `self` back into its inner [`MerkleTree`].
    ///
    /// # Safety
    ///
    /// This function automatically detaches all of the forks associated to this trunk. To
    /// attach them to another trunk use [`Fork::attach`].
    #[inline]
    pub fn into_tree(self) -> MerkleTree<C, T> {
        Rc::try_unwrap(self.base).ok().unwrap()
    }

    /// Creates a new fork of this trunk.
    #[inline]
    pub fn fork(&self) -> Fork<C, T> {
        Fork::new(self)
    }
}

/// Merkle Tree Fork
pub struct Fork<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Base Merkle Tree
    base: Weak<MerkleTree<C, T>>,

    /// Branch Data
    branch: Branch<C>,
}

impl<C, T> Fork<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Builds a new [`Fork`] from `trunk`.
    #[inline]
    pub fn new(trunk: &Trunk<C, T>) -> Self {
        Self::with_branch(trunk, Default::default())
    }

    /// Builds a new [`Fork`] from `trunk` with a custom `branch`.
    #[inline]
    pub fn with_branch(trunk: &Trunk<C, T>, branch: Branch<C>) -> Self {
        Self {
            base: Rc::downgrade(&trunk.base),
            branch,
        }
    }

    /// Attaches this fork to a new `trunk`.
    #[inline]
    pub fn attach(&mut self, trunk: &Trunk<C, T>) {
        // FIXME: Do we have to do a re-computation of the `branch` inner data?
        self.base = Rc::downgrade(&trunk.base);
    }

    /// Returns `true` if this fork is attached to some `trunk`.
    #[inline]
    pub fn is_attached(&self) -> bool {
        self.base.upgrade().is_some()
    }

    /// Computes the length of this fork of the tree.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn len(&self) -> Option<usize> {
        let base = self.base.upgrade()?;
        Some(base.len() + self.branch.len())
    }

    /// Returns `true` if this fork is empty.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn is_empty(&self) -> Option<bool> {
        Some(self.len()? == 0)
    }

    /// Computes the current root of this fork.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn root(&self) -> Option<Root<C>> {
        let base = self.base.upgrade()?;
        Some(self.branch.root(&base.parameters, &base.tree))
    }

    /// Appends a new `leaf` onto this fork.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn push(&mut self, leaf: &Leaf<C>) -> Option<bool> {
        let base = self.base.upgrade()?;
        Some(self.branch.push(&base.parameters, &base.tree, leaf))
    }
}

/* TODO:
/// Fork Path Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "GetPathError<C, T>: Clone"),
    Copy(bound = "GetPathError<C, T>: Copy"),
    Debug(bound = "GetPathError<C, T>: Debug"),
    Eq(bound = "GetPathError<C, T>: Eq"),
    Hash(bound = "GetPathError<C, T>: Hash"),
    PartialEq(bound = "GetPathError<C, T>: PartialEq")
)]
pub enum ForkGetPathError<C, T>
where
    C: Configuration + ?Sized,
    T: GetPath<C>,
{
    /// Trunk Path Query Error
    TrunkError(GetPathError<C, T>),

    /// Unknown Index on Branch Error
    UnknownIndexOnBranch,
}
*/

/// Merkle Tree Fork Branch
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct Branch<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digests
    pub leaf_digests: Vec<LeafDigest<C>>,

    /// Inner Digests
    pub inner_digests: InnerTree<C>,
}

impl<C> Branch<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`Branch`] from `leaf_digests` and `inner_digests`.
    #[inline]
    pub fn new(leaf_digests: Vec<LeafDigest<C>>, inner_digests: InnerTree<C>) -> Self {
        Self {
            leaf_digests,
            inner_digests,
        }
    }

    /// Computes the length of this branch.
    #[inline]
    pub fn len(&self) -> usize {
        self.leaf_digests.len()
    }

    /// Returns `true` if this branch is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Computes the root of the fork which has `self` as its branch and `tree` as its base tree.
    #[inline]
    fn root<T>(&self, parameters: &Parameters<C>, tree: &T) -> Root<C>
    where
        T: Tree<C>,
    {
        todo!()
    }

    /// Appends a new `leaf` to this branch, recomputing the relevant inner digests relative to
    /// the base `tree`.
    #[inline]
    fn push<T>(&mut self, parameters: &Parameters<C>, tree: &T, leaf: &Leaf<C>) -> bool
    where
        T: Tree<C>,
    {
        if tree.len() + self.len() >= capacity::<C>() {
            return false;
        }

        todo!()
    }
}
