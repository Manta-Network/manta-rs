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
use alloc::collections::btree_map;
use core::{fmt::Debug, hash::Hash, iter::FusedIterator, ops::Index};

#[cfg(feature = "std")]
use std::{collections::hash_map, hash::BuildHasher};

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

    /// Returns `true` if the iterator has completed.
    #[inline]
    pub const fn is_done(&self) -> bool {
        self.node.is_none()
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

/// [`InnerTree`] Map Backend
pub trait InnerMap<C>: Default
where
    C: Configuration + ?Sized,
{
    /// Returns the inner digest stored at `index`.
    fn get(&self, index: usize) -> Option<&InnerDigest<C>>;

    /// Sets the inner digest at `index` to `inner_digest`.
    fn set(&mut self, index: usize, inner_digest: InnerDigest<C>);
}

/// B-Tree Map [`InnerTree`] Backend
pub type BTreeMap<C> = btree_map::BTreeMap<usize, InnerDigest<C>>;

impl<C> InnerMap<C> for BTreeMap<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn get(&self, index: usize) -> Option<&InnerDigest<C>> {
        self.get(&index)
    }

    #[inline]
    fn set(&mut self, index: usize, inner_digest: InnerDigest<C>) {
        self.insert(index, inner_digest);
    }
}

/// Hash Map [`InnerTree`] Backend
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub type HashMap<C, S = hash_map::RandomState> = hash_map::HashMap<usize, InnerDigest<C>, S>;

#[cfg(feature = "std")]
impl<C, S> InnerMap<C> for HashMap<C, S>
where
    C: Configuration + ?Sized,
    S: Default + BuildHasher,
{
    #[inline]
    fn get(&self, index: usize) -> Option<&InnerDigest<C>> {
        self.get(&index)
    }

    #[inline]
    fn set(&mut self, index: usize, inner_digest: InnerDigest<C>) {
        self.insert(index, inner_digest);
    }
}

/// Inner Tree
///
/// Tree data-structure for storing the inner digests of a merkle tree.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "InnerDigest<C>: Clone, M: Clone"),
    Debug(bound = "InnerDigest<C>: Debug, M: Debug"),
    Default(bound = ""),
    Eq(bound = "InnerDigest<C>: Eq, M: Eq"),
    Hash(bound = "InnerDigest<C>: Hash, M: Hash"),
    PartialEq(bound = "InnerDigest<C>: PartialEq, M: PartialEq")
)]
pub struct InnerTree<C, M = BTreeMap<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    /// Inner Digest Map
    ///
    /// # Coordinates
    ///
    /// Locations in the tree are indexed by two coordinates `depth` and `index`. The `depth` of a
    /// node is given by its layer in the tree starting from `depth := -1` at the root increasing
    /// downwards towards the leaves. The `index` of a node is its position from left to right
    /// along a layer in the tree. See [`InnerNode`] for more details.
    map: M,

    /// Inner Digest Default Value
    default: InnerDigest<C>,
}

impl<C, M> InnerTree<C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    /// Builds a new [`InnerTree`].
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the inner digest at `node` or the default value if the inner digest is missing.
    #[inline]
    fn map_get(&self, index: usize) -> &InnerDigest<C> {
        self.map.get(index).unwrap_or(&self.default)
    }

    /// Returns a reference to the root inner digest.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.map_get(0)
    }

    /// Returns the inner digest at `node` or the default value if the inner digest is missing.
    #[inline]
    pub fn get(&self, node: InnerNode) -> &InnerDigest<C> {
        self.map_get(node.map_index())
    }

    /// Inserts the new `inner_digest` at `node` in the tree, and returns a reference to
    /// `inner_digest` and its sibling in the tree in parity order.
    #[inline]
    fn insert_and_get_pair(
        &mut self,
        node: InnerNode,
        inner_digest: InnerDigest<C>,
    ) -> (&InnerDigest<C>, &InnerDigest<C>) {
        let index = node.map_index();
        self.map.set(index, inner_digest);
        match node.parity() {
            Parity::Left => (self.map_get(index), self.map_get(index + 1)),
            Parity::Right => (self.map_get(index - 1), self.map_get(index)),
        }
    }

    /// Inserts `inner_digest` into the tree at `node` and computes the join of `inner_digest`
    /// and its sibling in the tree, using the default value if its sibling is not stored in
    /// the tree.
    #[inline]
    fn insert_and_join(
        &mut self,
        parameters: &Parameters<C>,
        node: InnerNode,
        inner_digest: InnerDigest<C>,
    ) -> InnerDigest<C> {
        let (lhs, rhs) = self.insert_and_get_pair(node, inner_digest);
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
        let root = self.compute_root(parameters, leaf_index, base);
        self.map.set(0, root);
    }

    /// Computes the inner path starting from `node`.
    #[inline]
    pub fn inner_path(&self, node: InnerNode) -> InnerPathIter<C, M> {
        InnerPathIter::new(self, node.iter())
    }

    /// Computes the inner path of the leaf given by `leaf_index`.
    #[inline]
    pub fn inner_path_for_leaf(&self, leaf_index: Node) -> InnerPathIter<C, M> {
        InnerPathIter::new(self, InnerNodeIter::from_leaf::<C>(leaf_index))
    }
}

impl<C, M> Index<InnerNode> for InnerTree<C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    type Output = InnerDigest<C>;

    #[inline]
    fn index(&self, index: InnerNode) -> &Self::Output {
        self.get(index)
    }
}

/// Inner Path Iterator
#[derive(derivative::Derivative)]
#[derivative(
    Copy,
    Clone,
    Debug(bound = "InnerDigest<C>: Debug, M: Debug"),
    Eq(bound = "InnerDigest<C>: Eq, M: Eq"),
    Hash(bound = "InnerDigest<C>: Hash, M: Hash"),
    PartialEq(bound = "InnerDigest<C>: PartialEq, M: PartialEq")
)]
pub struct InnerPathIter<'t, C, M = BTreeMap<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    /// Inner Tree
    inner_tree: &'t InnerTree<C, M>,

    /// Inner Node Iterator
    iter: InnerNodeIter,
}

impl<'t, C, M> InnerPathIter<'t, C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    /// Builds a new [`InnerPathIter`] for `inner_tree` using `iter`.
    #[inline]
    fn new(inner_tree: &'t InnerTree<C, M>, iter: InnerNodeIter) -> Self {
        Self { inner_tree, iter }
    }
}

// TODO: Add all methods which can be optimized.
impl<'t, C, M> Iterator for InnerPathIter<'t, C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    type Item = &'t InnerDigest<C>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(move |n| &self.inner_tree[n.sibling()])
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'t, C, M> ExactSizeIterator for InnerPathIter<'t, C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
}

impl<'t, C, M> FusedIterator for InnerPathIter<'t, C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
}
