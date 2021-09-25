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

//! Inner Digest Tree

extern crate alloc;

use crate::merkle_tree::{path_length, Configuration, InnerDigest, Node, Parameters, Parity};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{fmt::Debug, hash::Hash, iter::FusedIterator};

/// Inner Tree Node
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct InnerNode {
    /// Depth
    depth: usize,

    /// Index
    index: Node,
}

impl InnerNode {
    /// Builds a new [`InnerNode`] from `depth` and `index`.
    #[inline]
    const fn new(depth: usize, index: Node) -> Self {
        Self { depth, index }
    }

    /// Builds an [`InnerNode`] as the parent of a `leaf_index`, returning `None` if the
    /// parent of `leaf_index` is the root and not an inner node.
    #[inline]
    pub fn from_leaf<C>(leaf_index: Node) -> Option<Self>
    where
        C: Configuration + ?Sized,
    {
        Self::new(path_length::<C>(), leaf_index).parent()
    }

    /// Returns the [`Parity`] of this inner node.
    #[inline]
    pub const fn parity(&self) -> Parity {
        self.index.parity()
    }

    /// Returns `true` if this inner node has left parity.
    #[inline]
    pub const fn is_left(&self) -> bool {
        self.parity().is_left()
    }

    /// Returns `true` if this inner node has right parity.
    #[inline]
    pub const fn is_right(&self) -> bool {
        self.parity().is_right()
    }

    /// Returns the [`InnerNode`] which is the sibling of `self`.
    #[inline]
    pub const fn sibling(&self) -> Self {
        Self::new(self.depth, self.index.sibling())
    }

    /// Returns the parent [`InnerNode`] of this inner node.
    #[inline]
    pub const fn parent(&self) -> Option<Self> {
        match self.depth.checked_sub(1) {
            Some(depth) => Some(Self::new(depth, self.index.parent())),
            _ => None,
        }
    }

    /// Converts `self` into its parent, if the parent exists, returning the parent [`InnerNode`].
    #[inline]
    pub fn into_parent(&mut self) -> Option<Self> {
        match self.parent() {
            Some(parent) => {
                *self = parent;
                Some(*self)
            }
            _ => None,
        }
    }

    /// Returns an iterator over `self` and its parents.
    #[inline]
    pub const fn iter(&self) -> InnerNodeIter {
        InnerNodeIter::new(Some(*self))
    }

    /// Computes the starting index for the given `self.depth` in the tree.
    #[inline]
    const fn depth_starting_index(&self) -> usize {
        (1 << (self.depth + 1)) - 1
    }

    /// Computes the index into the tree map of `self`.
    #[inline]
    const fn map_index(&self) -> usize {
        self.depth_starting_index() + self.index.0
    }
}

impl From<InnerNode> for Node {
    #[inline]
    fn from(inner_node: InnerNode) -> Node {
        inner_node.index
    }
}

/// Inner Node Iterator
///
/// An iterator over the parents of an [`InnerNode`], including the node itself.
///
/// This `struct` is created by the [`iter`](InnerNode::iter) method on [`InnerNode`].
/// See its documentation for more.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct InnerNodeIter {
    /// Current Node
    node: Option<InnerNode>,
}

impl InnerNodeIter {
    /// Builds a new [`InnerNodeIter`] from `node`.
    #[inline]
    const fn new(node: Option<InnerNode>) -> Self {
        Self { node }
    }

    /// Builds a new [`InnerNodeIter`] iterator over the parents of `leaf_index`.
    #[inline]
    pub fn from_leaf<C>(leaf_index: Node) -> Self
    where
        C: Configuration + ?Sized,
    {
        Self::new(InnerNode::from_leaf::<C>(leaf_index))
    }
}

// TODO: Add all methods which can be optimized.
impl Iterator for InnerNodeIter {
    type Item = InnerNode;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let node = self.node.take()?;
        self.node = node.parent();
        Some(node)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.node.map(move |n| n.depth + 1).unwrap_or(0);
        (len, Some(len))
    }
}

impl ExactSizeIterator for InnerNodeIter {}

impl FusedIterator for InnerNodeIter {}

/// Inner Tree
///
/// Tree data-structure for storing the inner digests of a merkle tree.
///
/// # Coordinates
///
/// Locations in the tree are indexed by two coordinates `depth` and `index`. The `depth` of a
/// node is given by its layer in the tree starting from `depth := -1` at the root increasing
/// downwards towards the leaves. The `index` of a node is its position from left to right along a
/// layer in the tree.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "InnerDigest<C>: Clone"),
    Debug(bound = "InnerDigest<C>: Debug"),
    Default(bound = "InnerDigest<C>: Default"),
    Eq(bound = "InnerDigest<C>: Eq"),
    Hash(bound = "InnerDigest<C>: Hash"),
    PartialEq(bound = "InnerDigest<C>: PartialEq")
)]
pub struct InnerTree<C>
where
    C: Configuration + ?Sized,
{
    /// Inner Digest Map
    ///
    /// See [`inner_digest_index`](Self::inner_digest_index) for the definition of the tree
    /// coordinate system.
    map: BTreeMap<usize, InnerDigest<C>>,

    /// Inner Digest Default Value
    default: InnerDigest<C>,
}

impl<C> InnerTree<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`InnerTree`].
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns a reference to the root inner digest.
    #[inline]
    pub fn previous_root(&self) -> &InnerDigest<C> {
        self.map.get(&0).unwrap_or(&self.default)
    }

    /// Returns the inner digest at `node` or the default value if the inner digest is missing.
    #[inline]
    pub fn get(&self, node: InnerNode) -> &InnerDigest<C> {
        self.map.get(&node.map_index()).unwrap_or(&self.default)
    }

    /// Sets the new `inner_digest` at `(depth, index)` in the tree, and returns back a
    /// reference to `inner_digest` and its sibling in the tree in parity order.
    #[inline]
    fn set_and_get_inner_pair(
        &mut self,
        node: InnerNode,
        inner_digest: InnerDigest<C>,
    ) -> (&InnerDigest<C>, &InnerDigest<C>) {
        // TODO: Optimize this so we can remove the extra add and `unwrap_or`.
        let depth_starting_index = node.depth_starting_index();
        self.map
            .insert(depth_starting_index + node.index.0, inner_digest);
        let (lhs_index, rhs_index) = node.index.with_sibling();
        (
            self.map
                .get(&(depth_starting_index + lhs_index.0))
                .unwrap_or(&self.default),
            self.map
                .get(&(depth_starting_index + rhs_index.0))
                .unwrap_or(&self.default),
        )
    }

    /// Inserts `inner_digest` into the tree at `node` and computes the join of `inner_digest`
    /// and its sibling in the tree, using the `default` value if it's sibling is not stored in
    /// the tree.
    #[inline]
    fn insert_and_join(
        &mut self,
        parameters: &Parameters<C>,
        node: InnerNode,
        inner_digest: InnerDigest<C>,
    ) -> InnerDigest<C> {
        let (lhs, rhs) = self.set_and_get_inner_pair(node, inner_digest);
        parameters.join(lhs, rhs)
    }

    /// Computes the new root of the tree after inserting `base` which corresponds to the leaf at
    /// `leaf_index`.
    #[inline]
    fn compute_root(
        &mut self,
        parameters: &Parameters<C>,
        leaf_index: Node,
        base: InnerDigest<C>,
    ) -> InnerDigest<C> {
        InnerNodeIter::from_leaf::<C>(leaf_index).fold(base, move |acc, node| {
            self.insert_and_join(parameters, node, acc)
        })
    }

    /// Inserts the `base` inner digest corresponding to the leaf at `leaf_index` into the tree.
    #[inline]
    pub fn insert(&mut self, parameters: &Parameters<C>, leaf_index: Node, base: InnerDigest<C>) {
        // TODO: Implement random insertion, not just for leaves.
        let root = self.compute_root(parameters, leaf_index, base);
        self.map.insert(0, root);
    }

    /// Computes the inner path starting from `node`.
    #[inline]
    pub fn inner_path(&self, node: InnerNode) -> Vec<InnerDigest<C>>
    where
        InnerDigest<C>: Clone,
    {
        node.iter()
            .map(move |node| self.get(node.sibling()).clone())
            .collect()
    }

    /// Computes the inner path of the leaf given by `leaf_index`.
    #[inline]
    pub fn inner_path_for_leaf(&self, leaf_index: Node) -> Vec<InnerDigest<C>>
    where
        InnerDigest<C>: Clone,
    {
        InnerNodeIter::from_leaf::<C>(leaf_index)
            .map(move |node| self.get(node.sibling()).clone())
            .collect()
    }
}

/// Inner Path Iterator
#[derive(derivative::Derivative)]
#[derivative(
    Copy,
    Clone,
    Debug(bound = "InnerDigest<C>: Debug"),
    Eq(bound = "InnerDigest<C>: Eq"),
    Hash(bound = "InnerDigest<C>: Hash"),
    PartialEq(bound = "InnerDigest<C>: PartialEq")
)]
pub struct InnerPathIter<'t, C>
where
    C: Configuration + ?Sized,
{
    /// Inner Node Iterator
    iter: InnerNodeIter,

    /// Inner Tree
    inner_tree: &'t InnerTree<C>,
}

impl<'t, C> Iterator for InnerPathIter<'t, C>
where
    C: Configuration + ?Sized,
{
    type Item = &'t InnerDigest<C>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(move |n| self.inner_tree.get(n.sibling()))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}
