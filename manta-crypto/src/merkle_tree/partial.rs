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

//! Partial Merkle Tree Storage

// TODO: Do we allow custom sentinel sources for this tree?

use crate::merkle_tree::{
    capacity,
    inner_tree::{BTreeMap, InnerMap, InnerNodeIter, PartialInnerTree},
    leaf_map::{LeafBTreeMap, LeafMap},
    node::{NodeRange, Parity},
    Configuration, CurrentPath, InnerDigest, Leaf, LeafDigest, MerkleTree, Node, Parameters, Path,
    PathError, Root, Tree, WithProofs,
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Partial Merkle Tree Type
pub type PartialMerkleTree<C, M = BTreeMap<C>> = MerkleTree<C, Partial<C, M>>;

/// Partial Merkle Tree Backing Structure
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "L: Deserialize<'de>, InnerDigest<C>: Deserialize<'de>, M: Deserialize<'de>",
            serialize = "L: Serialize, InnerDigest<C>: Serialize, M: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "L: Clone, InnerDigest<C>: Clone, M: Clone"),
    Debug(bound = "L: Debug, InnerDigest<C>: Debug, M: Debug"),
    Default(bound = "L: Default, InnerDigest<C>: Default, M: Default"),
    Eq(bound = "L: Eq, InnerDigest<C>: Eq, M: Eq"),
    Hash(bound = "L: Hash, InnerDigest<C>: Hash, M: Hash"),
    PartialEq(bound = "L: PartialEq, InnerDigest<C>: PartialEq, M: PartialEq")
)]
pub struct Partial<C, M = BTreeMap<C>, L = LeafBTreeMap<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    L: LeafMap<C>,
{
    /// Leaf Map
    leaf_map: L,

    /// Inner Digests
    inner_digests: PartialInnerTree<C, M>,
}

impl<C, M, L> Partial<C, M, L>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    L: LeafMap<C>,
{
    /// Builds a new [`Partial`] without checking that `leaf_map` and `inner_digests` form a
    /// consistent merkle tree.
    #[inline]
    pub fn new_unchecked(leaf_map: L, inner_digests: PartialInnerTree<C, M>) -> Self {
        Self {
            leaf_map,
            inner_digests,
        }
    }

    /// Builds a new [`Partial`] without checking that `leaf_digests` and `inner_digests` form a
    /// consistent merkle tree.
    #[inline]
    pub fn new_unchecked_from_leaves(
        leaf_digests: Vec<LeafDigest<C>>,
        inner_digests: PartialInnerTree<C, M>,
    ) -> Self {
        Self::new_unchecked(LeafMap::from_vec(leaf_digests), inner_digests)
    }

    /// Builds a new [`Partial`] from `leaf_digests` and `path` without checking that
    /// `path` is consistent with the leaves and that it is a [`CurrentPath`].
    #[inline]
    pub fn from_leaves_and_path_unchecked(
        parameters: &Parameters<C>,
        leaf_digests: Vec<LeafDigest<C>>,
        path: Path<C>,
    ) -> Self
    where
        M: Default,
        InnerDigest<C>: Default + PartialEq,
    {
        let n = leaf_digests.len();
        if n == 0 {
            Self::new_unchecked(LeafMap::from_vec(leaf_digests), Default::default())
        } else {
            let base = match Parity::from_index(n - 1) {
                Parity::Left => parameters.join_leaves(&leaf_digests[n - 1], &path.sibling_digest),
                Parity::Right => parameters.join_leaves(&path.sibling_digest, &leaf_digests[n - 1]),
            };
            let mut partial_tree = Self::new_unchecked(
                LeafMap::from_vec(leaf_digests),
                PartialInnerTree::from_current(
                    parameters,
                    base,
                    CurrentPath::from_path_unchecked(path).inner_path,
                ),
            );
            partial_tree
                .inner_digests
                .reset_starting_leaf_index(Default::default());
            partial_tree
        }
    }

    /// Returns the leaf digests currently stored in the merkle tree.
    ///
    /// # Note
    ///
    /// Since this tree does not start its leaf nodes from the first possible index, indexing into
    /// this slice will not be the same as indexing into a slice from a full tree. For all other
    /// indexing, use the full indexing scheme.
    #[inline]
    pub fn leaf_digests(&self) -> Vec<&LeafDigest<C>> {
        self.leaf_map.leaf_digests()
    }

    /// Returns the marked leaves of the Merkle tree.
    #[inline]
    pub fn marked_leaves(&self) -> Vec<&LeafDigest<C>> {
        self.leaf_map.marked_leaf_digests()
    }

    /// Returns the leaf digests stored in the tree, dropping the rest of the tree data.
    ///
    /// # Note
    ///
    /// See the note at [`leaf_digests`](Self::leaf_digests) for more information on indexing this
    /// vector.
    #[inline]
    pub fn into_leaves(self) -> Vec<LeafDigest<C>> {
        self.leaf_map.into_leaf_digests()
    }

    /// Returns the leaf digests stored in the tree with their markings,
    /// dropping the rest of the tree data.
    ///
    /// # Note
    ///
    /// See the note at [`leaf_digests`](Self::leaf_digests) for more information on indexing this
    /// vector.
    #[inline]
    pub fn into_leaves_with_markings(self) -> Vec<(bool, LeafDigest<C>)> {
        self.leaf_map.into_leaf_digests_with_markings()
    }

    /// Returns the starting leaf [`Node`] for this tree.
    #[inline]
    pub fn starting_leaf_node(&self) -> Node {
        self.inner_digests.starting_leaf_index()
    }

    /// Returns the starting leaf index for this tree.
    #[inline]
    pub fn starting_leaf_index(&self) -> usize {
        self.starting_leaf_node().0
    }

    /// Returns the number of leaves in this tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.starting_leaf_index()
            + self
                .leaf_map
                .current_index()
                .map(|index| index + 1)
                .unwrap_or(0)
    }

    /// Returns `true` if this tree is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a reference to the root inner digest.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.inner_digests.root()
    }

    /// Returns the leaf digest at the given `index` in the tree.
    #[inline]
    pub fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>> {
        self.leaf_map.get(index - self.starting_leaf_index())
    }

    /// Returns the position of `leaf_digest` in the tree.
    #[inline]
    pub fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.leaf_map
            .position(leaf_digest)
            .map(move |i| i + self.starting_leaf_index())
    }

    /// Returns the sibling leaf node to `index`.
    #[inline]
    pub fn get_leaf_sibling(&self, index: Node) -> Option<&LeafDigest<C>> {
        self.leaf_map
            .get((index - self.starting_leaf_index()).sibling().0)
    }

    /// Returns an owned sibling leaf node to `index`.
    #[inline]
    pub fn get_owned_leaf_sibling(&self, index: Node) -> LeafDigest<C>
    where
        LeafDigest<C>: Clone + Default,
    {
        self.get_leaf_sibling(index).cloned().unwrap_or_default()
    }

    /// Returns the current (right-most) leaf of the tree.
    #[inline]
    pub fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.leaf_map.current_leaf()
    }

    /// Returns the current (right-most) path of the tree.
    #[inline]
    pub fn current_path(&self) -> CurrentPath<C>
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone + PartialEq,
    {
        let length = self.len();
        if length == 0 {
            return Default::default();
        }
        let leaf_index = Node(length - 1);
        CurrentPath::from_inner(
            self.get_owned_leaf_sibling(leaf_index),
            self.inner_digests.current_path_unchecked(leaf_index),
        )
    }

    /// Returns the path at `index` without bounds-checking on the index.
    #[inline]
    pub fn path_unchecked(&self, index: usize) -> Path<C>
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone,
    {
        let leaf_index = Node(index);
        Path::from_inner(
            self.get_owned_leaf_sibling(leaf_index),
            self.inner_digests.path_unchecked(leaf_index),
        )
    }

    /// Appends a `leaf_digest` with index given by `leaf_index` into the tree.
    #[inline]
    pub fn push_leaf_digest(
        &mut self,
        parameters: &Parameters<C>,
        leaf_index: Node,
        leaf_digest: LeafDigest<C>,
    ) where
        LeafDigest<C>: Default,
    {
        self.inner_digests.insert(
            parameters,
            leaf_index,
            leaf_index.join_leaves(
                parameters,
                &leaf_digest,
                self.get_leaf_sibling(leaf_index)
                    .unwrap_or(&Default::default()),
            ),
        );
        self.leaf_map.push(leaf_digest);
    }

    /// Appends `leaf_digests` with indices given by `leaf_indices` into the tree.
    #[inline]
    fn batch_push_leaf_digests(
        &mut self,
        parameters: &Parameters<C>,
        leaf_indices: NodeRange,
        leaf_digests: Vec<LeafDigest<C>>,
    ) where
        LeafDigest<C>: Default,
    {
        let base_inner_digests = leaf_indices.join_leaves(parameters, &leaf_digests, |node| {
            self.get_leaf_sibling(node)
        });
        self.inner_digests
            .batch_insert(parameters, leaf_indices, base_inner_digests);
        self.leaf_map.extend(leaf_digests);
    }

    /// Appends `leaf_digests` to the tree using `parameters`.
    #[inline]
    pub fn batch_maybe_push_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digests: F,
    ) -> Option<(bool, usize)>
    where
        F: FnOnce() -> Vec<LeafDigest<C>>,
        LeafDigest<C>: Default,
    {
        let mut leaf_digests = leaf_digests();
        if leaf_digests.is_empty() {
            return None;
        }
        let len = self.len();
        let number_of_leaf_digests = leaf_digests.len();
        let capacity = capacity::<C, _>();
        if len + number_of_leaf_digests > capacity {
            let max_number_of_insertions = capacity - len;
            if max_number_of_insertions != 0 {
                leaf_digests.truncate(max_number_of_insertions);
                self.batch_push_leaf_digests(
                    parameters,
                    NodeRange {
                        node: Node(len),
                        extra_nodes: max_number_of_insertions - 1,
                    },
                    leaf_digests,
                );
            }
            Some((false, max_number_of_insertions))
        } else {
            self.batch_push_leaf_digests(
                parameters,
                NodeRange {
                    node: Node(len),
                    extra_nodes: number_of_leaf_digests - 1,
                },
                leaf_digests,
            );
            Some((true, number_of_leaf_digests))
        }
    }

    /// Appends an iterator of marked leaf digests at the end of the tree, returning the iterator back
    /// if it could not be inserted because the tree has exhausted its capacity.
    ///
    /// # Implementation Note
    ///
    /// This operation is meant to be atomic, so if appending the iterator should fail, the
    /// implementation must ensure that the tree returns to the same state before the insertion
    /// occured.
    #[inline]
    pub fn extend_with_marked_digests<I>(
        &mut self,
        parameters: &Parameters<C>,
        marked_leaf_digests: I,
    ) -> Result<(), I::IntoIter>
    where
        I: IntoIterator<Item = (bool, LeafDigest<C>)>,
        L: Default,
        M: Default,
        InnerDigest<C>: Clone + Default + PartialEq,
        LeafDigest<C>: Clone + Default,
    {
        let marked_leaf_digests = marked_leaf_digests.into_iter();
        if matches!(marked_leaf_digests.size_hint().1, Some(max) if max <= capacity::<C, _>() - self.len())
        {
            let mut marked_inserts = Vec::new();
            for (marking, leaf_digest) in marked_leaf_digests {
                if marking {
                    marked_inserts.push(leaf_digest);
                } else {
                    if !marked_inserts.is_empty() {
                        assert!(self.batch_push_digest(parameters, || marked_inserts.drain(..).collect::<Vec<_>>()),
                            "Pushing a leaf digest into the tree should always succeed because of the check above.");
                    }
                    assert!(self.push_provable_digest(parameters, move || leaf_digest),
                 "Pushing a leaf digest into the tree should always succeed because of the check above.");
                }
            }
            if !marked_inserts.is_empty() {
                assert!(self.batch_push_digest(parameters, || marked_inserts.drain(..).collect::<Vec<_>>()),
                    "Pushing a leaf digest into the tree should always succeed because of the check above.");
            }
            return Ok(());
        }
        Err(marked_leaf_digests)
    }

    /// Appends a `leaf` to the tree using `parameters`.
    #[inline]
    pub fn push(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>) -> bool
    where
        LeafDigest<C>: Default,
    {
        let len = self.len();
        if len >= capacity::<C, _>() {
            return false;
        }
        self.push_leaf_digest(parameters, Node(len), parameters.digest(leaf));
        true
    }

    /// Appends `leaf_digest` to the tree using `parameters`.
    #[inline]
    pub fn maybe_push_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digest: F,
    ) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
        LeafDigest<C>: Default,
    {
        // TODO: Push without keeping unnecessary proof.
        let len = self.len();
        if len >= capacity::<C, _>() {
            return Some(false);
        }
        self.push_leaf_digest(parameters, Node(len), leaf_digest()?);
        Some(true)
    }

    /// Removes the paths corresponding to the nonprovable leaves in `self`.
    #[inline]
    pub fn prune(&mut self) {
        // We need to collect before looping because we are taking a mutable
        // reference of `self` in the loop and an immutable one in the `filter`
        // method.
        if let Some(current_index) = self.leaf_map.current_index() {
            let marked_indices = (0..current_index)
                .filter(|index| self.leaf_map.is_marked(*index).unwrap_or(false))
                .collect::<Vec<_>>();
            for index in marked_indices {
                self.remove_path_at_index(index);
            }
        }
    }

    /// Removes the [`Path`] above the leaf at `index`. Returns `false` if the leaf
    /// or its sibling are not marked for removal, or if either of them is the current leaf.
    #[inline]
    fn remove_path_at_index(&mut self, index: usize) -> bool {
        let sibling_index = Node(index).sibling().0;
        if self.leaf_map.is_marked_or_removed(sibling_index)
            && self.leaf_map.is_marked_or_removed(index)
        {
            self.leaf_map.remove(index);
            self.leaf_map.remove(sibling_index);
            for inner_node in InnerNodeIter::from_leaf::<C>(Node(index)) {
                let sibling_node = inner_node.sibling();
                self.inner_digests.remove(sibling_node.map_index());
                if sibling_node
                    .leaf_nodes(C::HEIGHT)
                    .any(|x| !self.leaf_map.is_marked_or_removed(x.0))
                {
                    break;
                }
            }
            true
        } else {
            false
        }
    }

    /// Marks the leaf at `index` for removal and then tries to remove the [`Path`]
    /// above it.
    #[inline]
    pub fn remove_path(&mut self, index: usize) -> bool {
        let leaf_index = index - self.starting_leaf_index();
        match self.leaf_map.current_index() {
            Some(current_index) if leaf_index <= current_index => (),
            _ => return false,
        };
        self.leaf_map.mark(leaf_index);
        true
        //self.remove_path_at_index(leaf_index)
    }
}

impl<C, M, L> Tree<C> for Partial<C, M, L>
where
    C: Configuration + ?Sized,
    M: InnerMap<C> + Default,
    L: LeafMap<C> + Default,
    LeafDigest<C>: Clone + Default,
    InnerDigest<C>: Clone + Default + PartialEq,
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
    fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.current_leaf()
    }

    #[inline]
    fn root(&self) -> &Root<C> {
        self.root()
    }

    #[inline]
    fn current_path(&self, parameters: &Parameters<C>) -> CurrentPath<C> {
        let _ = parameters;
        self.current_path()
    }

    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        let len = self.len();
        let result = self.maybe_push_digest(parameters, leaf_digest);
        self.leaf_map.mark(len - self.starting_leaf_index());
        result
    }

    #[inline]
    fn batch_maybe_push_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digests: F,
    ) -> Option<bool>
    where
        F: FnOnce() -> Vec<LeafDigest<C>>,
    {
        let leaf_index = self.len() - self.starting_leaf_index();
        let (result, number_of_insertions) =
            self.batch_maybe_push_digest(parameters, leaf_digests)?;
        for index in leaf_index..leaf_index + number_of_insertions {
            self.leaf_map.mark(index)
        }
        Some(result)
    }

    #[inline]
    fn prune(&mut self) {
        self.prune()
    }
}

impl<C, M, L> WithProofs<C> for Partial<C, M, L>
where
    C: Configuration + ?Sized,
    M: Default + InnerMap<C>,
    L: LeafMap<C>,
    LeafDigest<C>: Clone + Default,
    InnerDigest<C>: Clone + Default + PartialEq,
{
    #[inline]
    fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>> {
        self.leaf_digest(index)
    }

    #[inline]
    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.position(leaf_digest)
    }

    #[inline]
    fn maybe_push_provable_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digest: F,
    ) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        self.maybe_push_digest(parameters, leaf_digest)
    }

    #[inline]
    fn path(&self, parameters: &Parameters<C>, index: usize) -> Result<Path<C>, PathError> {
        let _ = parameters;
        let length = self.len();
        if index > 0 && index >= length {
            return Err(PathError::IndexTooLarge { length });
        }
        if index < self.starting_leaf_index() {
            return Err(PathError::MissingPath);
        }
        Ok(self.path_unchecked(index))
    }

    #[inline]
    fn remove_path(&mut self, index: usize) -> bool {
        self.remove_path(index)
    }

    #[inline]
    fn batch_maybe_push_provable_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digests: F,
    ) -> Option<bool>
    where
        F: FnOnce() -> Vec<LeafDigest<C>>,
    {
        Some(self.batch_maybe_push_digest(parameters, leaf_digests)?.0)
    }
}
