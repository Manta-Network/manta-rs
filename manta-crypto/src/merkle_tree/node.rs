// Copyright 2019-2022 Manta Network.
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

use crate::merkle_tree::{HashConfiguration, InnerDigest, InnerHash, LeafDigest, Parameters};
use alloc::vec::Vec;
use core::{
    iter::{FusedIterator, Map},
    ops::{Add, Range, Sub},
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Parity of a Subtree
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
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

    /// Returns the output of `f` if `self` is [`Left`](Self::Left), or returns a default value
    /// otherwise.
    #[inline]
    pub fn left_or_default<T, F>(&self, f: F) -> T
    where
        T: Default,
        F: FnOnce() -> T,
    {
        match self {
            Self::Left => f(),
            Self::Right => Default::default(),
        }
    }

    /// Returns the output of `f` if `self` is [`Right`](Self::Right), or returns a default value
    /// otherwise.
    #[inline]
    pub fn right_or_default<T, F>(&self, f: F) -> T
    where
        T: Default,
        F: FnOnce() -> T,
    {
        match self {
            Self::Left => Default::default(),
            Self::Right => f(),
        }
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
        C: HashConfiguration + ?Sized,
    {
        let (lhs, rhs) = self.order(lhs, rhs);
        C::InnerHash::join(&parameters.inner, lhs, rhs, &mut ())
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the parity of `self`.
    #[inline]
    pub fn join_leaves<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &LeafDigest<C>,
        rhs: &LeafDigest<C>,
    ) -> InnerDigest<C>
    where
        C: HashConfiguration + ?Sized,
    {
        let (lhs, rhs) = self.order(lhs, rhs);
        C::InnerHash::join_leaves(&parameters.inner, lhs, rhs, &mut ())
    }
}

impl Default for Parity {
    #[inline]
    fn default() -> Self {
        Self::Left
    }
}

/// Descendants iterator type
pub type DescendantsIterator<Idx = usize> = Map<Range<Idx>, fn(Idx) -> Node<Idx>>;

/// Node Index
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
    #[must_use]
    pub const fn sibling(&self) -> Self {
        match self.parity() {
            Parity::Left => Self(self.0 + 1),
            Parity::Right => Self(self.0 - 1),
        }
    }

    /// Maps `self` and its sibling over `f`.
    #[inline]
    pub fn with_sibling<T, F>(self, mut f: F) -> (T, T)
    where
        F: FnMut(Self) -> T,
    {
        match self.parity() {
            Parity::Left => (f(self), f(self + 1)),
            Parity::Right => (f(self - 1), f(self)),
        }
    }

    /// Returns `true` if `lhs` and `rhs` are siblings.
    #[inline]
    pub const fn are_siblings(lhs: &Self, rhs: &Self) -> bool {
        lhs.sibling().0 == rhs.0
    }

    /// Returns `self` if `self` has left parity or returns the sibling of `self` if `self` has
    /// right parity.
    #[inline]
    #[must_use]
    pub const fn as_left(&self) -> Self {
        match self.parity() {
            Parity::Left => *self,
            Parity::Right => Self(self.0 - 1),
        }
    }

    /// Returns `self` if `self` has right parity or returns the sibling of `self` if `self` has
    /// left parity.
    #[inline]
    #[must_use]
    pub const fn as_right(&self) -> Self {
        match self.parity() {
            Parity::Left => Self(self.0 + 1),
            Parity::Right => *self,
        }
    }

    /// Returns the left child [`Node`] of this node.
    #[inline]
    #[must_use]
    pub const fn left_child(&self) -> Self {
        Self(self.0 << 1)
    }

    /// Returns the right child [`Node`] of this node.
    #[inline]
    #[must_use]
    pub const fn right_child(&self) -> Self {
        Self(self.left_child().0 + 1)
    }

    /// Returns the [`Node`] children of this node.
    #[inline]
    pub const fn children(&self) -> (Self, Self) {
        let left_child = self.left_child();
        (left_child, Self(left_child.0 + 1))
    }

    /// Returns the parent [`Node`] of this node.
    #[inline]
    #[must_use]
    pub const fn parent(&self) -> Self {
        Self(self.0 >> 1)
    }

    /// Returns the `k`-th ancestor [`Node`] of `self`.
    #[inline]
    pub const fn ancestor(&self, k: usize) -> Self {
        Self(self.0 >> k)
    }

    /// Returns an iterator over the [`Node`] k-th descendants of this node.
    #[inline]
    pub fn descendants(&self, k: usize) -> DescendantsIterator {
        ((self.0 << k)..((self.0 + 1) << k)).map(Self)
    }

    /// Converts `self` into its parent, returning the parent [`Node`].
    #[inline]
    #[must_use]
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
    /// of `lhs` and `rhs` depending on the location of `self`.
    #[inline]
    pub fn join<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &InnerDigest<C>,
        rhs: &InnerDigest<C>,
    ) -> InnerDigest<C>
    where
        C: HashConfiguration + ?Sized,
    {
        self.parity().join(parameters, lhs, rhs)
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the location of `self`.
    #[inline]
    pub fn join_leaves<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &LeafDigest<C>,
        rhs: &LeafDigest<C>,
    ) -> InnerDigest<C>
    where
        C: HashConfiguration + ?Sized,
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
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
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

/// Dual Parity
///
/// # Note
///
/// Given a [`NodeRange`], this struct describes the parity of its left-most
/// and right-most [`Node`]s.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DualParity(pub (Parity, Parity));

impl DualParity {
    /// Returns the starting [`Parity`] of `self`.
    #[inline]
    pub const fn starting_parity(&self) -> Parity {
        (self.0).0
    }

    /// Returns the final [`Parity`] of `self`.
    #[inline]
    pub const fn final_parity(&self) -> Parity {
        (self.0).1
    }
}

/// Node Range
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NodeRange {
    /// Starting Node
    pub node: Node,

    /// Extra Nodes
    pub extra_nodes: usize,
}

impl NodeRange {
    /// Returns the [`DualParity`] of `self`.
    #[inline]
    pub const fn dual_parity(&self) -> DualParity {
        let starting_node_parity = self.node.parity();
        let final_node_parity = match starting_node_parity {
            Parity::Left => Parity::from_index(self.extra_nodes),
            Parity::Right => Parity::from_index(self.extra_nodes + 1),
        };
        DualParity((starting_node_parity, final_node_parity))
    }

    /// Returns the [`NodeRange`] consisting of the parents of the
    /// [`Node`]s in `self`.
    #[inline]
    pub const fn parents(&self) -> Self {
        let extra_nodes = match self.dual_parity().0 {
            (Parity::Left, Parity::Right) => (self.extra_nodes - 1) >> 1,
            (Parity::Right, Parity::Left) => (self.extra_nodes + 1) >> 1,
            _ => self.extra_nodes >> 1,
        };
        Self {
            node: self.node.parent(),
            extra_nodes,
        }
    }

    /// Returns the last [`Node`] in `self`.
    #[inline]
    pub const fn last_node(&self) -> Node {
        Node(self.node.0 + self.extra_nodes)
    }

    /// Computes the inner hashes of `leaves` pairwise and in order. If the first (last) element has a
    /// right (left) [`Parity`], it will be hashed with the output of `get_leaves` or with the default
    /// value if `get_leaves` returns `None`.
    #[inline]
    pub fn join_leaves<'a, C, F>(
        &self,
        parameters: &Parameters<C>,
        leaves: &Vec<LeafDigest<C>>,
        mut get_leaves: F,
    ) -> Vec<InnerDigest<C>>
    where
        C: HashConfiguration + ?Sized,
        LeafDigest<C>: 'a + Default,
        F: FnMut(Node) -> Option<&'a LeafDigest<C>>,
    {
        let dual_parity = self.dual_parity();
        let mut result = Vec::new();
        let length = leaves.len();
        let range = match dual_parity.starting_parity() {
            Parity::Left => (0..length - 1).step_by(2),
            _ => {
                result.push(Node(0).join_leaves(
                    parameters,
                    get_leaves(self.node).unwrap_or(&Default::default()),
                    &leaves[0],
                ));
                (1..length - 1).step_by(2)
            }
        };
        for i in range {
            result.push(Node(i).join_leaves(parameters, &leaves[i], &leaves[i + 1]))
        }
        if dual_parity.final_parity().is_left() {
            result.push(self.last_node().join_leaves(
                parameters,
                &leaves[length - 1],
                get_leaves(self.last_node()).unwrap_or(&Default::default()),
            ))
        }
        result
    }
}
