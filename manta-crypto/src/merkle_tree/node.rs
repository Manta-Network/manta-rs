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

//! Merkle Tree Node Abstractions

use crate::merkle_tree::{Configuration, InnerDigest, InnerHash, LeafDigest, Parameters};
use core::{
    iter::FusedIterator,
    ops::{Add, Sub},
};

/// Parity of a Subtree
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Parity {
    /// Left Side of the Subtree
    Left,

    /// Right Side of the Subtree
    Right,
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

    /// Maps `self` to the output of `lhs` and `rhs` depending on its parity.
    #[inline]
    pub fn map<T, L, R>(self, lhs: L, rhs: R) -> T
    where
        L: FnOnce() -> T,
        R: FnOnce() -> T,
    {
        match self {
            Self::Left => lhs(),
            Self::Right => rhs(),
        }
    }

    /// Returns the arguments in the order according to the parity of `self`.
    #[inline]
    pub const fn order<T>(&self, lhs: T, rhs: T) -> (T, T) {
        match self {
            Self::Left => (lhs, rhs),
            Self::Right => (rhs, lhs),
        }
    }

    /// Returns the `center` placed in the pair at the location given by `self`, placing `lhs` and
    /// `rhs` in the left or right empty slot of the pair respectively.
    #[inline]
    pub fn triple_order<T, L, R>(&self, center: T, lhs: L, rhs: R) -> (T, T)
    where
        L: FnOnce() -> T,
        R: FnOnce() -> T,
    {
        match self {
            Self::Left => (center, rhs()),
            Self::Right => (lhs(), center),
        }
    }

    /// Combines two inner digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the parity of `self` in its subtree.
    #[inline]
    pub fn join<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &InnerDigest<C>,
        rhs: &InnerDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        let (lhs, rhs) = self.order(lhs, rhs);
        C::InnerHash::join(&parameters.inner, lhs, rhs)
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, choosing the right
    /// pair `(center, rhs)` if `self` has left parity or choosing the left pair `(lhs, center)`
    /// if `self` has right parity.
    #[inline]
    pub fn join_opposite_pair<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &InnerDigest<C>,
        center: &InnerDigest<C>,
        rhs: &InnerDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        let (lhs, rhs) = self.triple_order(center, move || lhs, move || rhs);
        C::InnerHash::join(&parameters.inner, lhs, rhs)
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the parity of `self` in its subtree.
    #[inline]
    pub fn join_leaves<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &LeafDigest<C>,
        rhs: &LeafDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        let (lhs, rhs) = self.order(lhs, rhs);
        C::InnerHash::join_leaves(&parameters.inner, lhs, rhs)
    }
}

impl Default for Parity {
    #[inline]
    fn default() -> Self {
        Self::Left
    }
}

/// Node Index
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Node<Idx = usize>(
    /// Level-wise Index to a node in a Binary Tree
    pub Idx,
);

impl Node {
    /// Returns the [`Parity`] of this node.
    #[inline]
    pub const fn parity(&self) -> Parity {
        Parity::from_index(self.0)
    }

    /// Returns `true` if this node has left parity.
    #[inline]
    pub const fn is_left(&self) -> bool {
        self.parity().is_left()
    }

    /// Returns `true` if this node has right parity.
    #[inline]
    pub const fn is_right(&self) -> bool {
        self.parity().is_right()
    }

    /// Returns the [`Node`] which is the sibling to `self`.
    #[inline]
    pub const fn sibling(&self) -> Self {
        match self.parity() {
            Parity::Left => Self(self.0 + 1),
            Parity::Right => Self(self.0 - 1),
        }
    }

    /// Returns `self` with its sibling in parity order.
    #[inline]
    pub fn with_sibling(self) -> (Self, Self) {
        self.parity()
            .triple_order(self, move || self - 1, move || self + 1)
    }

    /// Returns the left child [`Node`] of this node.
    #[inline]
    pub const fn left_child(&self) -> Self {
        Self(self.0 << 1)
    }

    /// Returns the right child [`Node`] fo this node.
    #[inline]
    pub const fn right_child(&self) -> Self {
        Self(self.left_child().0 + 1)
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

    /// Returns an iterator over the parents of `self`.
    #[inline]
    pub const fn parents(&self) -> NodeParents {
        NodeParents { index: *self }
    }

    /// Combines two inner digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the location of `self` in its subtree.
    #[inline]
    pub fn join<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &InnerDigest<C>,
        rhs: &InnerDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        self.parity().join(parameters, lhs, rhs)
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, choosing the right
    /// pair `(center, rhs)` if `self` has left parity or choosing the left pair `(lhs, center)`
    /// if `self` has right parity.
    #[inline]
    pub fn join_opposite_pair<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &InnerDigest<C>,
        center: &InnerDigest<C>,
        rhs: &InnerDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        self.parity()
            .join_opposite_pair(parameters, lhs, center, rhs)
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the location of `self` in its subtree.
    #[inline]
    pub fn join_leaves<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &LeafDigest<C>,
        rhs: &LeafDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        self.parity().join_leaves(parameters, lhs, rhs)
    }
}

impl<Idx> Add<Idx> for Node<Idx>
where
    Idx: Add<Output = Idx>,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: Idx) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl<'i, Idx> Add<&'i Idx> for &'i Node<Idx>
where
    &'i Idx: Add<Output = Idx>,
{
    type Output = Node<Idx>;

    #[inline]
    fn add(self, rhs: &'i Idx) -> Self::Output {
        Node(&self.0 + rhs)
    }
}

impl<Idx> Sub<Idx> for Node<Idx>
where
    Idx: Sub<Output = Idx>,
{
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Idx) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl<'i, Idx> Sub<&'i Idx> for &'i Node<Idx>
where
    &'i Idx: Sub<Output = Idx>,
{
    type Output = Node<Idx>;

    #[inline]
    fn sub(self, rhs: &'i Idx) -> Self::Output {
        Node(&self.0 - rhs)
    }
}

impl<Idx> From<Idx> for Node<Idx> {
    #[inline]
    fn from(index: Idx) -> Self {
        Self(index)
    }
}

impl<Idx> PartialEq<Idx> for Node<Idx>
where
    Idx: PartialEq,
{
    #[inline]
    fn eq(&self, rhs: &Idx) -> bool {
        self.0 == *rhs
    }
}

/// Node Parent Iterator
///
/// An iterator over the parents of a [`Node`].
///
/// This `struct` is created by the [`parents`](Node::parents) method on [`Node`].
/// See its documentation for more.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NodeParents {
    /// Current Index
    index: Node,
}

impl NodeParents {
    /// Stops the iterator and returns the current node index.
    #[inline]
    pub const fn stop(self) -> Node {
        self.index
    }

    /// Returns the sibling of the current parent node.
    #[inline]
    pub const fn sibling(&self) -> Node {
        self.index.sibling()
    }
}

impl AsRef<Node> for NodeParents {
    #[inline]
    fn as_ref(&self) -> &Node {
        &self.index
    }
}

// TODO: Add all methods which can be optimized.
impl Iterator for NodeParents {
    type Item = Node;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.index.into_parent())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        // NOTE: Although this iterator can never be completed, it has a well-defined
        //       final element "at infinity".
        Some(Default::default())
    }
}

impl FusedIterator for NodeParents {}
