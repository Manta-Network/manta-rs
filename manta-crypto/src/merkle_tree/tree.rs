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

// TODO: Should we get rid of the `H > 2` requirement, and find a way to give correct
//       implementations for the trivial tree sizes?
// TODO: Add "copy-on-write" adapters for `Root` and `Path`, and see if we can incorporate them
//       into `Tree`.
// TODO: Should we add optimization paths for when `cloning` the default value is cheaper than
//       creating a new one from scratch (for inner digests)?

use crate::{
    merkle_tree::{
        fork::{self, Trunk},
        path::{CurrentPath, Path},
    },
    set::{MembershipProof, VerifiedSet, Verifier},
};
use core::{fmt::Debug, hash::Hash, marker::PhantomData};

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

    /// Returns `true` if `digest` is the default inner hash output value.
    #[inline]
    fn is_default(digest: &Self::Output) -> bool {
        digest == &Default::default()
    }

    /// Combines two inner digests into a new inner digest using `parameters`.
    fn join(parameters: &Self::Parameters, lhs: &Self::Output, rhs: &Self::Output) -> Self::Output;

    /// Combines two [`LeafHash`](Self::LeafHash) digests into an inner digest.
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &<Self::LeafHash as LeafHash>::Output,
        rhs: &<Self::LeafHash as LeafHash>::Output,
    ) -> Self::Output;
}

/// Merkle Tree Hash Configuration
pub trait HashConfiguration {
    /// Leaf Hash Type
    type LeafHash: LeafHash;

    /// Inner Hash Type
    type InnerHash: InnerHash<LeafHash = Self::LeafHash>;
}

/// Merkle Tree Configuration
pub trait Configuration: HashConfiguration {
    /// Height Type
    type Height: Copy + Into<usize>;

    /// Fixed Height of the Merkle Tree
    ///
    /// # Contract
    ///
    /// Trees must always have height at least `2`.
    const HEIGHT: Self::Height;
}

/// Configuration Structure
///
/// Use this `struct` to extend any [`C: HashConfiguration`](HashConfiguration) and a given
/// `const HEIGHT: usize` to a full implementation of [`Configuration`].
///
/// # Note
///
/// Since this `struct` is meant to be used as a type parameter, any values of this type have no
/// meaning, just like values of type [`HashConfiguration`] or [`Configuration`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Config<C, const HEIGHT: usize>(PhantomData<C>)
where
    C: HashConfiguration + ?Sized;

impl<C, const HEIGHT: usize> HashConfiguration for Config<C, HEIGHT>
where
    C: HashConfiguration + ?Sized,
{
    type LeafHash = C::LeafHash;
    type InnerHash = C::InnerHash;
}

impl<C, const HEIGHT: usize> Configuration for Config<C, HEIGHT>
where
    C: HashConfiguration + ?Sized,
{
    type Height = usize;

    const HEIGHT: Self::Height = HEIGHT;
}

/// Leaf Type
pub type Leaf<C> = <<C as HashConfiguration>::LeafHash as LeafHash>::Leaf;

/// Leaf Hash Parameters Type
pub type LeafHashParamters<C> = <<C as HashConfiguration>::LeafHash as LeafHash>::Parameters;

/// Leaf Hash Digest Type
pub type LeafDigest<C> = <<C as HashConfiguration>::LeafHash as LeafHash>::Output;

/// Inner Hash Parameters Type
pub type InnerHashParameters<C> = <<C as HashConfiguration>::InnerHash as InnerHash>::Parameters;

/// Inner Hash Digest Type
pub type InnerDigest<C> = <<C as HashConfiguration>::InnerHash as InnerHash>::Output;

/// Returns the capacity of the merkle tree with the given [`C::HEIGHT`](Configuration::HEIGHT)
/// parameter.
///
/// The capacity of a merkle tree with height `H` is `2^(H-1)`.
#[inline]
pub fn capacity<C>() -> usize
where
    C: Configuration + ?Sized,
{
    1usize << (C::HEIGHT.into() - 1)
}

/// Returns the path length of the merkle tree with the given [`C::HEIGHT`](Configuration::HEIGHT)
/// parameter.
///
/// The path length of a merkle tree with height `H` is `H - 2`.
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
        tree.extend(parameters, leaves).then(move || tree)
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

    /// Returns the current (i.e. right-most) leaf.
    fn current_leaf(&self) -> LeafDigest<C>;

    /// Returns the [`Root`] of the merkle tree.
    fn root(&self, parameters: &Parameters<C>) -> Root<C>;

    /// Returns the [`CurrentPath`] of the current (i.e. right-most) leaf.
    fn current_path(&self, parameters: &Parameters<C>) -> CurrentPath<C>;

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
        self.maybe_push_digest(parameters, move || Some(leaf_digest()))
            .unwrap()
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
                    Some(result) => assert!(result),
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
}

/// Merkle Tree Leaf Query Mixin
pub trait GetLeaf<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the [`LeafDigest`] at the given `index`.
    fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>>;

    /// Returns the index of the `leaf_digest` if it is contained in `self`.
    fn index_of(&self, leaf_digest: &LeafDigest<C>) -> Option<usize>;

    /// Returns `true` if `leaf_digest` is contained in the tree.
    #[inline]
    fn contains(&self, leaf_digest: &LeafDigest<C>) -> bool {
        self.index_of(leaf_digest).is_some()
    }
}

/// Merkle Tree Path Query Mixin
pub trait GetPath<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the [`Path`] of the leaf at the given `index`.
    fn path(&self, parameters: &Parameters<C>, index: usize) -> Option<Path<C>>;
}

/// Digest Type
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Copy(bound = "LeafDigest<C>: Copy, InnerDigest<C>: Copy"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub enum Digest<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digest
    Leaf(LeafDigest<C>),

    /// Inner Digest
    Inner(InnerDigest<C>),
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
    C: HashConfiguration + ?Sized,
{
    /// Leaf Hash Parameters
    pub leaf: LeafHashParamters<C>,

    /// Inner Hash Parameters
    pub inner: InnerHashParameters<C>,
}

impl<C> Parameters<C>
where
    C: HashConfiguration + ?Sized,
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
    pub fn verify_path(&self, path: &Path<C>, root: &Root<C>, leaf: &Leaf<C>) -> bool
    where
        C: Configuration,
    {
        path.verify(self, root, leaf)
    }
}

impl<C> Verifier for Parameters<C>
where
    C: Configuration + ?Sized,
{
    type Item = Leaf<C>;

    type Public = Root<C>;

    type Secret = Path<C>;

    #[inline]
    fn verify(&self, public: &Self::Public, secret: &Self::Secret, item: &Self::Item) -> bool {
        self.verify_path(secret, public, item)
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
    C: HashConfiguration + ?Sized;

impl<C> AsRef<InnerDigest<C>> for Root<C>
where
    C: HashConfiguration + ?Sized,
{
    #[inline]
    fn as_ref(&self) -> &InnerDigest<C> {
        &self.0
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

    /// Returns the length of this merkle tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Returns `true` if this merkle tree is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Returns the number of leaves that can fit in this merkle tree.
    #[inline]
    pub fn capacity(&self) -> usize {
        capacity::<C>()
    }

    /// Returns the current (i.e right-most) leaf.
    #[inline]
    pub fn current_leaf(&self) -> LeafDigest<C> {
        self.tree.current_leaf()
    }

    /// Returns the [`Root`] of the merkle tree.
    #[inline]
    pub fn root(&self) -> Root<C> {
        self.tree.root(&self.parameters)
    }

    /// Returns the [`CurrentPath`] of the current (i.e right-most) leaf.
    #[inline]
    pub fn current_path(&self) -> CurrentPath<C> {
        self.tree.current_path(&self.parameters)
    }

    /// Returns the [`LeafDigest`] at the given `index`.
    #[inline]
    pub fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>>
    where
        T: GetLeaf<C>,
    {
        self.tree.leaf_digest(index)
    }

    /// Returns the index of the `leaf_digest` if it is contained in `self`.
    #[inline]
    pub fn index_of(&self, leaf_digest: &LeafDigest<C>) -> Option<usize>
    where
        T: GetLeaf<C>,
    {
        self.tree.index_of(leaf_digest)
    }

    /// Returns `true` if `leaf_digest` is contained in the tree.
    #[inline]
    pub fn contains(&self, leaf_digest: &LeafDigest<C>) -> bool
    where
        T: GetLeaf<C>,
    {
        self.tree.contains(leaf_digest)
    }

    /// Returns the [`Path`] of the leaf at the given `index`.
    #[inline]
    pub fn path(&self, index: usize) -> Option<Path<C>>
    where
        T: GetPath<C>,
    {
        self.tree.path(&self.parameters, index)
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

    /// Converts `self` into a fork-able merkle tree.
    ///
    /// Use [`Trunk::into_tree`] to convert back.
    #[inline]
    pub fn into_trunk<P>(self) -> Trunk<C, T, P>
    where
        P: fork::raw::MerkleTreePointerFamily<C, T>,
    {
        Trunk::new(self)
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

impl<C, T> VerifiedSet for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: GetLeaf<C> + GetPath<C> + Tree<C>,
{
    type Item = Leaf<C>;

    type Public = Root<C>;

    type Secret = Path<C>;

    type Verifier = Parameters<C>;

    #[inline]
    fn verifier(&self) -> &Self::Verifier {
        &self.parameters
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.capacity()
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    #[inline]
    fn insert(&mut self, item: &Self::Item) -> bool {
        self.push(item)
    }

    #[inline]
    fn insert_non_proving(&mut self, item: &Self::Item) -> bool {
        // FIXME: What to do here?
        todo!()
    }

    #[inline]
    fn check_public(&self, public: &Self::Public) -> bool {
        &self.root() == public
    }

    #[inline]
    fn get_membership_proof(&self, item: &Self::Item) -> Option<MembershipProof<Self::Verifier>> {
        Some(MembershipProof::new(
            self.root(),
            self.path(self.index_of(&self.parameters.digest(item))?)?,
        ))
    }

    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.contains(&self.parameters.digest(item))
    }
}
