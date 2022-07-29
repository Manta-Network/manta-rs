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
    inner_tree::{BTreeMap, InnerMap, PartialInnerTree},
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
            deserialize = "LeafDigest<C>: Deserialize<'de>, InnerDigest<C>: Deserialize<'de>, M: Deserialize<'de>",
            serialize = "LeafDigest<C>: Serialize, InnerDigest<C>: Serialize, M: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone, M: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug, M: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default, M: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq, M: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash, M: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq, M: PartialEq")
)]
pub struct Partial<C, M = BTreeMap<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    /// Leaf Digests
    leaf_digests: Vec<LeafDigest<C>>,

    /// Inner Digests
    inner_digests: PartialInnerTree<C, M>,
}

impl<C, M> Partial<C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    /// Builds a new [`Partial`] without checking that `leaf_digests` and `inner_digests` form a
    /// consistent merkle tree.
    #[inline]
    pub fn new_unchecked(
        leaf_digests: Vec<LeafDigest<C>>,
        inner_digests: PartialInnerTree<C, M>,
    ) -> Self {
        Self {
            leaf_digests,
            inner_digests,
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
    pub fn leaf_digests(&self) -> &[LeafDigest<C>] {
        &self.leaf_digests
    }

    /// Returns the leaf digests stored in the tree, dropping the rest of the tree data.
    ///
    /// # Note
    ///
    /// See the note at [`leaf_digests`](Self::leaf_digests) for more information on indexing this
    /// vector.
    #[inline]
    pub fn into_leaves(self) -> Vec<LeafDigest<C>> {
        self.leaf_digests
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

    /// Returns the number of nodes in this tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.starting_leaf_index() + self.leaf_digests.len()
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
        self.leaf_digests.get(index - self.starting_leaf_index())
    }

    /// Returns the position of `leaf_digest` in the tree.
    #[inline]
    pub fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize>
    where
        LeafDigest<C>: PartialEq,
    {
        self.leaf_digests
            .iter()
            .position(move |d| d == leaf_digest)
            .map(move |i| i + self.starting_leaf_index())
    }

    /// Returns the sibling leaf node to `index`.
    #[inline]
    pub fn get_leaf_sibling(&self, index: Node) -> Option<&LeafDigest<C>> {
        self.leaf_digests
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
        self.leaf_digests.last()
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
        self.leaf_digests.push(leaf_digest);
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
}

impl<C, M> Tree<C> for Partial<C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C> + Default,
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
        self.maybe_push_digest(parameters, leaf_digest)
    }
}

impl<C, M> WithProofs<C> for Partial<C, M>
where
    C: Configuration + ?Sized,
    M: Default + InnerMap<C>,
    LeafDigest<C>: Clone + Default + PartialEq,
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
        // TODO: Implement this optimization.
        let mut node = Node(self.starting_leaf_index() + index);
        let height = C::HEIGHT;
        let mut nodes_to_be_removed: Vec<Node> = Vec::new();
        for level in 0..height - 1 {
            nodes_to_be_removed.push(node.sibling());
            if node
                .sibling()
                .descendants(level)
                .iter()
                .map(|x| x.0 - self.starting_leaf_index())
                .map(|y| self.leaf_digest(y))
                .any(|z| match z {
                    None => false,
                    Some(q) => self.contains(q),
                })
            {
                break;
            } else {
                node = node.parent();
            }
        }
        // So far: the nodes that can be pruned are computed
        // TODO: delete the corresponding digests
        let _ = index;
        false
    }
}
