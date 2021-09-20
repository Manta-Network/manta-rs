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

//! Merkle Trees

// TODO: The following optimizations/configurations must be possible:
//
//    1. Subtree Computation/Memoization
//    2. Root computation from only the past
//    3. Path computation from only the past
//    4. Incremental Update
//    5. Only store relevant history subset
//

extern crate alloc;

use alloc::vec::Vec;

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

    /// Merkle Tree Structure Type
    type Tree: Tree<Self>;
}

/// Merkle Tree Structure
pub trait Tree<C>: Sized
where
    C: Configuration + ?Sized,
{
    /// Height Type
    type Height: Copy;

    /// Path Query Type
    type PathQuery;

    /// Builds a new merkle tree with the given `height`.
    fn new(height: Self::Height) -> Self;

    /// Builds a new merkle tree with the given `height` and pre-existing `leaves`.
    fn with_leaves(height: Self::Height, leaves: &[Leaf<C>]) -> Option<Self>
    where
        Leaf<C>: Sized;

    /// Returns the [`Root`] of the merkle tree.
    fn root(&self) -> Root<C>;

    /// Returns the [`Path`] to some element of the merkle tree given by the `path_query`.
    fn path(&self, path_query: Self::PathQuery) -> Path<C>;
}

/// Merkle Tree Append Mixin
pub trait Append<C>
where
    C: Configuration + ?Sized,
{
    /// Inserts `leaf_digest` at the next avaiable leaf node of the tree.
    fn append(&mut self, parameters: &Parameters<C>, leaf_digest: LeafDigest<C>);
}

/// Merkle Tree Update Mixin
pub trait Update<C>
where
    C: Configuration + ?Sized,
{
    /// Modifies the leaf node at the given `index` to `leaf_digest`.
    fn update(&mut self, parameters: &Parameters<C>, index: usize, leaf_digest: LeafDigest<C>);
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

/// Merkle Tree Root Type
pub type Root<C> = InnerDigest<C>;

/// Left or Right Side of a Subtree
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Parity {
    /// Left Side of the Subtree
    Left,

    /// Right Side of the Subtree
    Right,
}

impl Default for Parity {
    #[inline]
    fn default() -> Self {
        Self::Left
    }
}

impl Parity {
    /// Computes the [`Parity`] of the given `index`.
    #[inline]
    pub const fn from_index(index: usize) -> Self {
        if index % 2 == 0 {
            Self::Left
        } else {
            Self::Right
        }
    }

    /// Returns `true` if `self` represents the left side of a subtree.
    #[inline]
    pub const fn is_left(&self) -> bool {
        matches!(self, Self::Left)
    }

    /// Returns `true` if `self` represents the right side of a subtree.
    #[inline]
    pub const fn is_right(&self) -> bool {
        matches!(self, Self::Right)
    }
}

/// Node Location
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Node(usize);

impl Node {
    /// Builds a [`Node`] for this `index`.
    #[inline]
    pub const fn from_index(index: usize) -> Self {
        Self(index)
    }

    /// Returns the [`Parity`] of this node.
    #[inline]
    pub const fn parity(&self) -> Parity {
        Parity::from_index(self.0)
    }

    /// Returns the parent [`Node`] of this node.
    #[inline]
    pub const fn parent(&self) -> Self {
        Self(self.0 >> 1)
    }

    /// Converts `self` into its parent, returning the parent [`Node`].
    #[inline]
    pub fn into_parent(&mut self) -> Self {
        *self = self.parent();
        *self
    }

    /// Combines two inner digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the location of `self` in its subtree.
    #[inline]
    pub fn join<C>(
        &self,
        parameters: &InnerHashParameters<C>,
        lhs: &InnerDigest<C>,
        rhs: &InnerDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        match self.parity() {
            Parity::Left => C::InnerHash::join(parameters, lhs, rhs),
            Parity::Right => C::InnerHash::join(parameters, rhs, lhs),
        }
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the location of `self` in its subtree.
    #[inline]
    pub fn join_leaves<C>(
        &self,
        parameters: &InnerHashParameters<C>,
        lhs: &LeafDigest<C>,
        rhs: &LeafDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        match self.parity() {
            Parity::Left => C::InnerHash::join_leaves(parameters, lhs, rhs),
            Parity::Right => C::InnerHash::join_leaves(parameters, rhs, lhs),
        }
    }
}

/// Merkle Tree Parameters
pub struct Parameters<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Hash Parameters
    pub leaf: LeafHashParamters<C>,

    /// Inner Hash Parameters
    pub inner: InnerHashParameters<C>,
}

/// Merkle Tree Path
pub struct Path<C>
where
    C: Configuration + ?Sized,
{
    /// Inner Path
    inner_path: Vec<InnerDigest<C>>,

    /// Sibling Digest
    sibling_digest: LeafDigest<C>,

    /// Leaf Node
    leaf_node: Node,
}

impl<C> Path<C>
where
    C: Configuration + ?Sized,
{
    /// Returns `true` if `self` is a witness to the fact that `leaf` is stored in a merkle tree
    /// with the given `root`.
    #[inline]
    pub fn is_valid(&self, parameters: &Parameters<C>, root: &Root<C>, leaf: &Leaf<C>) -> bool {
        let mut node = self.leaf_node;
        let first_inner_digest = node.join_leaves::<C>(
            &parameters.inner,
            &C::LeafHash::digest(&parameters.leaf, leaf),
            &self.sibling_digest,
        );
        root == &self
            .inner_path
            .iter()
            .fold(first_inner_digest, move |acc, d| {
                node.into_parent().join::<C>(&parameters.inner, &acc, d)
            })
    }
}

/// Merkle Tree
pub struct MerkleTree<C>
where
    C: Configuration + ?Sized,
{
    /// Underlying Tree Structure
    tree: C::Tree,
}

impl<C> MerkleTree<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`MerkleTree`] with the given `height`.
    #[inline]
    pub fn new(height: <C::Tree as Tree<C>>::Height) -> Self {
        Self {
            tree: C::Tree::new(height),
        }
    }

    /// Returns the [`Root`] of the merkle tree.
    #[inline]
    pub fn root(&self) -> Root<C> {
        self.tree.root()
    }

    /// Returns the [`Path`] to some element of the merkle tree given by the `path_query`.
    #[inline]
    pub fn path(&self, path_query: <C::Tree as Tree<C>>::PathQuery) -> Path<C> {
        self.tree.path(path_query)
    }

    /// Inserts `leaf` at the next avaiable leaf node of the tree.
    #[inline]
    pub fn append(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>)
    where
        C::Tree: Append<C>,
    {
        self.tree
            .append(parameters, C::LeafHash::digest(&parameters.leaf, leaf))
    }

    /// Modifies the leaf node at the given `index` to `leaf`.
    #[inline]
    pub fn update(&mut self, parameters: &Parameters<C>, index: usize, leaf: &Leaf<C>)
    where
        C::Tree: Update<C>,
    {
        self.tree.update(
            parameters,
            index,
            C::LeafHash::digest(&parameters.leaf, leaf),
        )
    }
}
