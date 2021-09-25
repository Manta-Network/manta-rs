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

//! Merkle Tree Abstractions

extern crate alloc;

use crate::merkle_tree::{
    fork::{Delta, Fork},
    Node,
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};

/// Merkle Tree Leaf Hash
pub trait LeafHash {
    /// Leaf Type
    type Leaf: ?Sized;

    /// Leaf Hash Parameters Type
    type Parameters;

    /// Leaf Hash Output Type
    type Output: Default;

    /// Computes the digest of the `leaf` using `parameters`.
    fn digest(parameters: &Self::Parameters, leaf: &Self::Leaf) -> Self::Output;
}

/// Merkle Tree Inner Hash
pub trait InnerHash {
    /// Leaf Hash Type
    type LeafHash: LeafHash;

    /// Inner Hash Parameters Type
    type Parameters;

    /// Inner Hash Output Type
    type Output: Default + PartialEq;

    /// Combines two inner digests into a new inner digest using `parameters`.
    fn join(parameters: &Self::Parameters, lhs: &Self::Output, rhs: &Self::Output) -> Self::Output;

    /// Combines two [`LeafHash`](Self::LeafHash) digests into an inner digest.
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &<Self::LeafHash as LeafHash>::Output,
        rhs: &<Self::LeafHash as LeafHash>::Output,
    ) -> Self::Output;
}

/// Merkle Tree Configuration
pub trait Configuration {
    /// Leaf Hash Type
    type LeafHash: LeafHash;

    /// Inner Hash Type
    type InnerHash: InnerHash<LeafHash = Self::LeafHash>;

    /// Height Type
    type Height: Copy + Into<usize>;

    /// Fixed Height of the Merkle Tree
    ///
    /// # Contract
    ///
    /// Trees must always have height at least `2`.
    const HEIGHT: Self::Height;
}

/// Leaf Type
pub type Leaf<C> = <<C as Configuration>::LeafHash as LeafHash>::Leaf;

/// Leaf Hash Parameters Type
pub type LeafHashParamters<C> = <<C as Configuration>::LeafHash as LeafHash>::Parameters;

/// Leaf Hash Digest Type
pub type LeafDigest<C> = <<C as Configuration>::LeafHash as LeafHash>::Output;

/// Inner Hash Parameters Type
pub type InnerHashParameters<C> = <<C as Configuration>::InnerHash as InnerHash>::Parameters;

/// Inner Hash Digest Type
pub type InnerDigest<C> = <<C as Configuration>::InnerHash as InnerHash>::Output;

/// Returns the capacity of the merkle tree with the given [`C::HEIGHT`](Configuration::HEIGHT)
/// parameter.
#[inline]
pub fn capacity<C>() -> usize
where
    C: Configuration + ?Sized,
{
    1usize << (C::HEIGHT.into() - 1)
}

/// Returns the path length of the merkle tree with the given [`C::HEIGHT`](Configuration::HEIGHT)
/// parameter.
#[inline]
pub fn path_length<C>() -> usize
where
    C: Configuration + ?Sized,
{
    C::HEIGHT.into() - 2
}

/// Merkle Tree Structure
pub trait Tree<C>: Sized
where
    C: Configuration + ?Sized,
{
    /// Path Query Type
    type Query;

    /// Path Error Type
    type Error;

    /// Builds a new merkle tree.
    fn new(parameters: &Parameters<C>) -> Self;

    /// Builds a new merkle tree with the given `leaves` returning `None` if the iterator
    /// would overflow the capacity of the tree.
    #[inline]
    fn from_iter<'l, L>(parameters: &Parameters<C>, leaves: L) -> Option<Self>
    where
        Leaf<C>: 'l,
        L: IntoIterator<Item = &'l Leaf<C>>,
    {
        let mut tree = Self::new(parameters);
        tree.extend(parameters, leaves).then(|| tree)
    }

    /// Builds a new merkle tree with the given `leaves` returning `None` if the slice
    /// would overflow the capacity of the tree.
    #[inline]
    fn from_slice(parameters: &Parameters<C>, slice: &[Leaf<C>]) -> Option<Self>
    where
        Leaf<C>: Sized,
    {
        Self::from_iter(parameters, slice)
    }

    /// Returns the length of `self`.
    fn len(&self) -> usize;

    /// Returns `true` if the length of `self` is zero.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the [`Root`] of the merkle tree.
    fn root(&self, parameters: &Parameters<C>) -> Root<C>;

    /// Returns the [`Path`] to some element of the merkle tree given by the `query`.
    fn path(&self, parameters: &Parameters<C>, query: Self::Query) -> Result<Path<C>, Self::Error>;

    /// Checks if a leaf can be inserted into the tree and if it can, it runs `leaf_digest` to
    /// extract a leaf digest to insert, returning `None` if there was no leaf digest.
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>;

    /// Inserts the `leaf_digest` at the next available leaf node of the tree, returning `false`
    /// if the leaf could not be inserted because the tree has exhausted its capacity.
    #[inline]
    fn push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> bool
    where
        F: FnOnce() -> LeafDigest<C>,
    {
        match self.maybe_push_digest(parameters, || Some(leaf_digest())) {
            Some(result) => result,
            _ => unreachable!(),
        }
    }

    /// Inserts the digest of `leaf` at the next available leaf node of the tree, returning
    /// `false` if the leaf could not be inserted because the tree has exhausted its capacity.
    #[inline]
    fn push(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>) -> bool {
        self.push_digest(parameters, || parameters.digest(leaf))
    }

    /// Appends an iterator of leaf digests at the end of the tree, returning the iterator back
    /// if it could not be inserted because the tree has exhausted its capacity.
    ///
    /// # Implementation Note
    ///
    /// This operation is meant to be atomic, so if appending the iterator should fail, the
    /// implementation must ensure that the tree returns to the same state before the insertion
    /// occured.
    #[inline]
    fn extend_digests<L>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digests: L,
    ) -> Result<(), L::IntoIter>
    where
        L: IntoIterator<Item = LeafDigest<C>>,
    {
        let mut leaf_digests = leaf_digests.into_iter();
        if matches!(leaf_digests.size_hint().1, Some(max) if max <= capacity::<C>() - self.len()) {
            loop {
                match self.maybe_push_digest(parameters, || leaf_digests.next()) {
                    Some(result) => debug_assert!(result),
                    _ => return Ok(()),
                }
            }
        }
        Err(leaf_digests)
    }

    /// Appends an iterator of leaves at the end of the tree, returning `false` if the `leaves`
    /// could not be inserted because the tree has exhausted its capacity.
    ///
    /// # Implementation Note
    ///
    /// This operation is meant to be atomic, so if appending the iterator should fail, the
    /// implementation must ensure that the tree returns to the same state before the insertion
    /// occured.
    #[inline]
    fn extend<'l, L>(&mut self, parameters: &Parameters<C>, leaves: L) -> bool
    where
        Leaf<C>: 'l,
        L: IntoIterator<Item = &'l Leaf<C>>,
    {
        self.extend_digests(parameters, leaves.into_iter().map(|l| parameters.digest(l)))
            .is_ok()
    }

    /// Appends a slice of leaves at the end of the tree, returning `false` if the
    /// `leaves` could not be inserted because the tree has exhausted its capacity.
    ///
    /// # Implementation Note
    ///
    /// This operation is meant to be atomic, so if appending the slice should fail, the
    /// implementation must ensure that the tree returns to the same state before the insertion
    /// occured.
    #[inline]
    fn extend_slice(&mut self, parameters: &Parameters<C>, leaves: &[Leaf<C>]) -> bool
    where
        Leaf<C>: Sized,
    {
        self.extend(parameters, leaves)
    }

    /// Tries to merge the `delta` into the tree, returning it back if it would exceed the capacity
    /// of the tree.
    #[inline]
    fn merge_delta(&mut self, parameters: &Parameters<C>, delta: Delta<C>) -> Result<(), Delta<C>> {
        let Delta {
            leaf_digests,
            inner_digests,
        } = delta;
        match self.extend_digests(parameters, leaf_digests) {
            Err(leaf_digests) => Err(Delta::new(leaf_digests.collect(), inner_digests)),
            _ => Ok(()),
        }
    }
}

/// Merkle Tree Parameters
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafHashParamters<C>: Clone, InnerHashParameters<C>: Clone"),
    Copy(bound = "LeafHashParamters<C>: Copy, InnerHashParameters<C>: Copy"),
    Debug(bound = "LeafHashParamters<C>: Debug, InnerHashParameters<C>: Debug"),
    Default(bound = "LeafHashParamters<C>: Default, InnerHashParameters<C>: Default"),
    Eq(bound = "LeafHashParamters<C>: Eq, InnerHashParameters<C>: Eq"),
    Hash(bound = "LeafHashParamters<C>: Hash, InnerHashParameters<C>: Hash"),
    PartialEq(bound = "LeafHashParamters<C>: PartialEq, InnerHashParameters<C>: PartialEq")
)]
pub struct Parameters<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Hash Parameters
    pub leaf: LeafHashParamters<C>,

    /// Inner Hash Parameters
    pub inner: InnerHashParameters<C>,
}

impl<C> Parameters<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`Parameters`] from `leaf` and `inner` parameters.
    #[inline]
    pub fn new(leaf: LeafHashParamters<C>, inner: InnerHashParameters<C>) -> Self {
        Self { leaf, inner }
    }

    /// Computes the leaf digest of `leaf` using `self`.
    #[inline]
    pub fn digest(&self, leaf: &Leaf<C>) -> LeafDigest<C> {
        C::LeafHash::digest(&self.leaf, leaf)
    }

    /// Combines two inner digests into a new inner digest using `self`.
    #[inline]
    pub fn join(&self, lhs: &InnerDigest<C>, rhs: &InnerDigest<C>) -> InnerDigest<C> {
        C::InnerHash::join(&self.inner, lhs, rhs)
    }

    /// Combines two leaf digests into a new inner digest using `self`.
    #[inline]
    pub fn join_leaves(&self, lhs: &LeafDigest<C>, rhs: &LeafDigest<C>) -> InnerDigest<C> {
        C::InnerHash::join_leaves(&self.inner, lhs, rhs)
    }

    /// Verify that `path` witnesses the fact that `leaf` is a member of a merkle tree with the
    /// given `root`.
    #[inline]
    pub fn verify_path(&self, path: &Path<C>, root: &Root<C>, leaf: &Leaf<C>) -> bool {
        path.verify(self, root, leaf)
    }
}

/// Merkle Tree Root Wrapper Type
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "InnerDigest<C>: Clone"),
    Copy(bound = "InnerDigest<C>: Copy"),
    Debug(bound = "InnerDigest<C>: Debug"),
    Default(bound = "InnerDigest<C>: Default"),
    Eq(bound = "InnerDigest<C>: Eq"),
    Hash(bound = "InnerDigest<C>: Hash"),
    PartialEq(bound = "InnerDigest<C>: PartialEq")
)]
pub struct Root<C>(
    /// Root Inner Digest
    pub InnerDigest<C>,
)
where
    C: Configuration + ?Sized;

impl<C> AsRef<InnerDigest<C>> for Root<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn as_ref(&self) -> &InnerDigest<C> {
        &self.0
    }
}

/// Merkle Tree Path
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct Path<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Index
    pub leaf_index: Node,

    /// Sibling Digest
    pub sibling_digest: LeafDigest<C>,

    /// Inner Path
    ///
    /// Inner digests are stored from leaf to root, not including the root.
    pub inner_path: Vec<InnerDigest<C>>,
}

impl<C> Path<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`Path`] from `leaf_index`, `sibling_digest`, and `inner_path`.
    #[inline]
    pub fn new(
        leaf_index: Node,
        sibling_digest: LeafDigest<C>,
        inner_path: Vec<InnerDigest<C>>,
    ) -> Self {
        Self {
            leaf_index,
            sibling_digest,
            inner_path,
        }
    }

    /// Computes the root of the merkle tree relative to `leaf_digest` using `parameters`.
    #[inline]
    pub fn root_relative_to(
        &self,
        parameters: &Parameters<C>,
        leaf_digest: &LeafDigest<C>,
    ) -> Root<C> {
        let mut index = self.leaf_index;
        Root(self.inner_path.iter().fold(
            index.join_leaves(parameters, leaf_digest, &self.sibling_digest),
            move |acc, d| index.into_parent().join(parameters, &acc, d),
        ))
    }

    /// Returns `true` if `self` is a witness to the fact that `leaf_digest` is stored in a
    /// merkle tree with the given `root`.
    #[inline]
    pub fn verify_digest(
        &self,
        parameters: &Parameters<C>,
        root: &Root<C>,
        leaf_digest: &LeafDigest<C>,
    ) -> bool {
        root == &self.root_relative_to(parameters, leaf_digest)
    }

    /// Returns `true` if `self` is a witness to the fact that `leaf` is stored in a merkle tree
    /// with the given `root`.
    #[inline]
    pub fn verify(&self, parameters: &Parameters<C>, root: &Root<C>, leaf: &Leaf<C>) -> bool {
        self.verify_digest(parameters, root, &parameters.digest(leaf))
    }
}

impl<C> Default for Path<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn default() -> Self {
        let path_length = path_length::<C>();
        let mut inner_path = Vec::with_capacity(path_length);
        inner_path.resize_with(path_length, InnerDigest::<C>::default);
        Self::new(Default::default(), Default::default(), inner_path)
    }
}

/// Merkle Tree
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Parameters<C>: Clone, T: Clone"),
    Copy(bound = "Parameters<C>: Copy, T: Copy"),
    Debug(bound = "Parameters<C>: Debug, T: Debug"),
    Default(bound = "Parameters<C>: Default, T: Default"),
    Eq(bound = "Parameters<C>: Eq, T: Eq"),
    Hash(bound = "Parameters<C>: Hash, T: Hash"),
    PartialEq(bound = "Parameters<C>: PartialEq, T: PartialEq")
)]
pub struct MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Underlying Tree Structure
    pub(super) tree: T,

    /// Merkle Tree Parameters
    pub(super) parameters: Parameters<C>,
}

impl<C, T> MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Builds a new [`MerkleTree`].
    #[inline]
    pub fn new(parameters: Parameters<C>) -> Self {
        Self::from_tree(T::new(&parameters), parameters)
    }

    /// Builds a new [`MerkleTree`] with the given `leaves`.
    #[inline]
    pub fn from_iter<'l, L>(parameters: Parameters<C>, leaves: L) -> Option<Self>
    where
        Leaf<C>: 'l,
        L: IntoIterator<Item = &'l Leaf<C>>,
    {
        Some(Self::from_tree(
            T::from_iter(&parameters, leaves)?,
            parameters,
        ))
    }

    /// Builds a new [`MerkleTree`] with the given `leaves`.
    #[inline]
    pub fn from_slice(parameters: Parameters<C>, leaves: &[Leaf<C>]) -> Option<Self>
    where
        Leaf<C>: Sized,
    {
        Some(Self::from_tree(
            T::from_slice(&parameters, leaves)?,
            parameters,
        ))
    }

    /// Builds a new [`MerkleTree`] from a pre-constructed `tree` and `parameters`.
    #[inline]
    pub fn from_tree(tree: T, parameters: Parameters<C>) -> Self {
        Self { tree, parameters }
    }

    /// Returns a reference to the parameters used by this merkle tree.
    #[inline]
    pub fn parameters(&self) -> &Parameters<C> {
        &self.parameters
    }

    /// Returns the [`Root`] of the merkle tree.
    #[inline]
    pub fn root(&self) -> Root<C> {
        self.tree.root(&self.parameters)
    }

    /// Returns the [`Path`] to some element of the merkle tree given by the `query`.
    #[inline]
    pub fn path(&self, query: T::Query) -> Result<Path<C>, T::Error> {
        self.tree.path(&self.parameters, query)
    }

    /// Inserts `leaf` at the next avaiable leaf node of the tree, returning `false` if the
    /// leaf could not be inserted because the tree has exhausted its capacity.
    #[inline]
    pub fn push(&mut self, leaf: &Leaf<C>) -> bool {
        self.tree.push(&self.parameters, leaf)
    }

    /// Appends an iterator of leaves at the end of the tree, returning `false` if the `leaves`
    /// could not be inserted because the tree has exhausted its capacity.
    #[inline]
    pub fn extend<'l, L>(&mut self, leaves: L) -> bool
    where
        Leaf<C>: 'l,
        L: IntoIterator<Item = &'l Leaf<C>>,
    {
        self.tree.extend(&self.parameters, leaves)
    }

    /// Appends a slice of leaves at the end of the tree, returning `false` if the `leaves` could
    /// not be inserted because the tree has exhausted its capacity.
    #[inline]
    pub fn extend_slice(&mut self, leaves: &[Leaf<C>]) -> bool
    where
        Leaf<C>: Sized,
    {
        self.tree.extend_slice(&self.parameters, leaves)
    }

    /// Forks the merkle tree.
    #[inline]
    pub fn fork(&self) -> Fork<C, T> {
        Fork::new(self)
    }

    /// Merges the `fork` into `self`.
    #[inline]
    pub fn merge(&mut self, fork: Fork<C, T>) {
        debug_assert!(self.tree.merge_delta(&self.parameters, fork.delta).is_ok())
    }

    /// Extracts the parameters of the merkle tree, dropping the internal tree.
    #[inline]
    pub fn into_parameters(self) -> Parameters<C> {
        self.parameters
    }
}

impl<C, T> AsRef<T> for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        &self.tree
    }
}

impl<C, T> AsMut<T> for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        &mut self.tree
    }
}
