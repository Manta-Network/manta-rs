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
    inner_tree::{BTreeMap, InnerMap, InnerNode, PartialInnerTree},
    Configuration, CurrentPath, InnerDigest, Leaf, LeafDigest, MerkleTree, Node, Parameters, Path,
    PathError, Root, Tree, WithProofs,
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::collections::hash_map::HashMap;

/// LeafMap
pub trait LeafMap<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the number of stored leaves
    fn len(&self) -> usize;

    /// Checks whether the LeafMap is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the leaf digest stored at 'index'
    fn get(&self, index: usize) -> Option<&LeafDigest<C>>;

    /// Returns the current (i.e. rightmost) leaf
    #[inline]
    fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.get(self.current_index())
    }

    /// Returns the current index
    fn current_index(&self) -> usize;

    /// Returns the index at which 'leaf_digest' is stored. Default implementation always returns 'None',
    /// non-trivial implementations require [`LeafDigest<C>`] to implement the [`PartialEq`] trait.
    fn position(&self, _leaf_digest: &LeafDigest<C>) -> Option<usize> {
        None
    }

    /// Pushes a leaf digest to the right-most position
    fn push(&mut self, leaf_digest: LeafDigest<C>);

    /// Marks the leaf digest at 'index' for removal
    fn mark(&mut self, index: usize);

    /// Checks whether the leaf digest at 'index' is marked for removal. Returns 'None' if there
    /// is no leaf digest stored at 'index'
    fn is_marked(&self, index: usize) -> Option<bool>;

    /// Checks whether a leaf digest is either already deleted or marked for removal
    #[inline]
    fn is_marked_or_removed(&self, index: usize) -> bool {
        self.is_marked(index).unwrap_or(true)
    }

    /// Removes the leaf digest stored at 'index'. Fails when trying to remove the current leaf.
    fn remove(&mut self, index: usize) -> bool;

    /// Generates a LeafMap from a 'Vec<LeafDigest>'
    fn from_vec(leaf_digests: Vec<LeafDigest<C>>) -> Self;

    /// Returns a vector with all leaf digests
    #[inline]
    fn leaf_digests(&self) -> Vec<LeafDigest<C>>
    where
        LeafDigest<C>: Clone,
    {
        (0..self.len())
            .map(|x| self.get(x))
            .filter(|x| match x {
                None => false,
                Some(_) => true,
            })
            .map(|x| x.unwrap().clone())
            .collect()
    }
    /// Returns a vector with all marked leaf digests
    #[inline]
    fn marked_leaf_digests(&self) -> Vec<LeafDigest<C>>
    where
        LeafDigest<C>: Clone,
    {
        (0..self.len())
            .filter(|&index| self.is_marked(index).unwrap_or(false))
            .map(|x| self.get(x).unwrap().clone())
            .collect()
    }
}

/// Vector of leaf digests with markings
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq")
)]
pub struct LeafVec<C>
where
    C: Configuration + ?Sized,
{
    vec: Vec<(bool, LeafDigest<C>)>,
}

impl<C> LeafMap<C> for LeafVec<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: Clone + PartialEq,
{
    fn len(&self) -> usize {
        self.vec.len()
    }

    fn get(&self, index: usize) -> Option<&LeafDigest<C>> {
        let leaf_digest = &self.vec.get(index)?.1;
        Some(leaf_digest)
    }

    fn current_index(&self) -> usize {
        self.len() - 1
    }

    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.vec.iter().position(|(_, l)| l == leaf_digest)
    }

    fn push(&mut self, leaf_digest: LeafDigest<C>) {
        self.vec.push((false, leaf_digest));
    }

    fn from_vec(leaf_digests: Vec<LeafDigest<C>>) -> Self {
        Self {
            vec: leaf_digests
                .iter()
                .map(|x| (false, x.clone()))
                .collect::<Vec<(bool, LeafDigest<C>)>>(),
        }
    }

    fn mark(&mut self, index: usize) {
        if let Some((b, _)) = self.vec.get_mut(index) {
            *b = true
        };
    }

    fn is_marked(&self, index: usize) -> Option<bool> {
        let mark = self.vec.get(index)?.0;
        Some(mark)
    }

    /// LeafVec does not implement leaf removal
    fn remove(&mut self, _index: usize) -> bool {
        false
    }
}

/// Hash map of leaf digests.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq"),
    PartialEq(bound = "LeafDigest<C>: PartialEq")
)]
#[cfg(feature = "std")]
pub struct LeafHashMap<C>
where
    C: Configuration + ?Sized,
{
    map: HashMap<usize, (bool, LeafDigest<C>)>,
    last_index: usize,
}

#[cfg(feature = "std")]
impl<C> LeafMap<C> for LeafHashMap<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: Clone + PartialEq,
{
    fn len(&self) -> usize {
        self.map.len()
    }

    fn get(&self, index: usize) -> Option<&LeafDigest<C>> {
        let leaf_digest = &self.map.get(&index)?.1;
        Some(leaf_digest)
    }

    fn current_index(&self) -> usize {
        self.last_index
    }

    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.map.iter().position(|(_, (_, l))| l == leaf_digest)
    }

    fn push(&mut self, leaf_digest: LeafDigest<C>) {
        self.map.insert(self.last_index, (false, leaf_digest));
        if self.len() > 0 {
            self.last_index += 1;
        }
    }

    fn from_vec(leaf_digests: Vec<LeafDigest<C>>) -> Self {
        Self {
            map: leaf_digests
                .iter()
                .map(|x| (false, x.clone()))
                .enumerate()
                .collect::<HashMap<usize, (bool, LeafDigest<C>)>>(),
            last_index: leaf_digests.len() - 1,
        }
    }

    fn mark(&mut self, index: usize) {
        if let Some((b, _)) = self.map.get_mut(&index) {
            *b = true
        };
    }

    fn is_marked(&self, index: usize) -> Option<bool> {
        let mark = self.map.get(&index)?.0;
        Some(mark)
    }

    fn remove(&mut self, index: usize) -> bool {
        if index >= self.last_index {
            false
        } else {
            self.map.remove(&index);
            true
        }
    }
}

/// Partial Merkle Tree Type
pub type PartialMerkleTree<C, M = BTreeMap<C>> = MerkleTree<C, Partial<C, M>>;

/// Partial Merkle Tree Backing Structure
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "LeafDigest<C>: Deserialize<'de>, InnerDigest<C>: Deserialize<'de>, M: Deserialize<'de>, L: Deserialize<'de>",
            serialize = "LeafDigest<C>: Serialize, InnerDigest<C>: Serialize, M: Serialize, L: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone, M: Clone, L: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug, M: Debug, L: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default, M: Default, L: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq, M: Eq, L: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash, M: Hash, L: Hash"),
    PartialEq(bound = "InnerDigest<C>: PartialEq, M: PartialEq, L: PartialEq")
)]
pub struct Partial<C, M = BTreeMap<C>, L = LeafVec<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    L: LeafMap<C>,
{
    /// Leaf Digests
    leaf_digests: L,

    /// Inner Digests
    inner_digests: PartialInnerTree<C, M>,
}

impl<C, M, L> Partial<C, M, L>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    L: LeafMap<C>,
{
    /// Builds a new [`Partial`] without checking that `leaf_digests` and `inner_digests` form a
    /// consistent merkle tree.
    #[inline]
    pub fn new_unchecked(leaf_digests: L, inner_digests: PartialInnerTree<C, M>) -> Self {
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
    pub fn leaf_digests(&self) -> Vec<LeafDigest<C>>
    where
        LeafDigest<C>: Clone,
    {
        self.leaf_digests.leaf_digests()
    }

    /// Returns the marked leaves of the Merkle tree.
    #[inline]
    pub fn marked_leaves(&self) -> Vec<LeafDigest<C>>
    where
        LeafDigest<C>: Clone,
    {
        self.leaf_digests.marked_leaf_digests()
    }

    /// Returns the leaf digests stored in the tree, dropping the rest of the tree data.
    ///
    /// # Note
    ///
    /// See the note at [`leaf_digests`](Self::leaf_digests) for more information on indexing this
    /// vector.
    #[inline]
    pub fn into_leaves(self) -> Vec<LeafDigest<C>>
    where
        LeafDigest<C>: Clone,
    {
        self.leaf_digests.leaf_digests()
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
    pub fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.leaf_digests.position(leaf_digest)
    }

    /// Returns the sibling leaf node to `index`.
    #[inline]
    pub fn get_leaf_sibling(&self, index: Node) -> Option<&LeafDigest<C>> {
        self.leaf_digests
            .get((index - self.starting_leaf_index()).sibling().0)
    }

    /// Returns an owned sibling leaf node to `index`.
    #[inline]
    pub fn get_owned_leaf_sibling(&self, index: Node) -> Option<LeafDigest<C>>
    where
        LeafDigest<C>: Clone + Default,
    {
        self.get_leaf_sibling(index).cloned()
    }

    /// Returns the current (right-most) leaf of the tree.
    #[inline]
    pub fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.leaf_digests.current_leaf()
    }

    /// Returns the current index of the tree.
    #[inline]
    pub fn current_index(&self) -> usize {
        self.leaf_digests.current_index()
    }

    /// Returns the current (right-most) path of the tree.
    #[inline]
    pub fn current_path(&self) -> Result<CurrentPath<C>, PathError>
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone + PartialEq,
    {
        let length = self.len();
        if length == 0 {
            return Ok(Default::default());
        }
        let leaf_index = Node(length - 1);
        let leaf_sibling = match (
            self.leaf_digest(length - 1),
            self.get_owned_leaf_sibling(leaf_index),
        ) {
            (None, _) => return Err(PathError::MissingPath),
            (_, None) => return Err(PathError::MissingPath),
            (Some(_), Some(leaf_sibling)) => leaf_sibling,
        };
        if let Ok(inner_path) = self.inner_digests.current_path_unchecked(leaf_index) {
            Ok(CurrentPath::from_inner(leaf_sibling, inner_path))
        } else {
            Err(PathError::MissingPath)
        }
    }

    /// Returns the path at `index` without bounds-checking on the index.
    #[inline]
    pub fn path_unchecked(&self, index: usize) -> Result<Path<C>, PathError>
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone,
    {
        let leaf_index = Node(index);
        let leaf_sibling = match (
            self.leaf_digest(index),
            self.get_owned_leaf_sibling(leaf_index),
        ) {
            (None, _) => return Err(PathError::MissingPath),
            (_, None) => return Err(PathError::MissingPath),
            (Some(_), Some(leaf_sibling)) => leaf_sibling,
        };
        if let Ok(inner_path) = self.inner_digests.path_unchecked(leaf_index) {
            Ok(Path::from_inner(leaf_sibling, inner_path))
        } else {
            Err(PathError::MissingPath)
        }
    }

    /// Appends a `leaf_digest` with index given by `leaf_index` into the tree.
    #[inline]
    pub fn push_provable_leaf_digest(
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

    /// Appends a `leaf_digest` with index given by `leaf_index` into the tree and then removes
    /// its proof.
    #[inline]
    pub fn push_leaf_digest(
        &mut self,
        parameters: &Parameters<C>,
        leaf_index: Node,
        leaf_digest: LeafDigest<C>,
    ) where
        LeafDigest<C>: Default,
    {
        self.push_provable_leaf_digest(parameters, leaf_index, leaf_digest);
        self.leaf_digests.remove(leaf_index.0);
    }

    /// Appends a `leaf` to the tree using `parameters`.
    #[inline]
    pub fn push_provable(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>) -> bool
    where
        LeafDigest<C>: Default,
    {
        let len = self.len();
        if len >= capacity::<C, _>() {
            return false;
        }
        self.push_provable_leaf_digest(parameters, Node(len), parameters.digest(leaf));
        true
    }

    /// Appends a `leaf` to the tree using `parameters` and then it removes its proof.
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
    pub fn maybe_push_provable_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digest: F,
    ) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
        LeafDigest<C>: Default,
    {
        let len = self.len();
        if len >= capacity::<C, _>() {
            return Some(false);
        }
        self.push_provable_leaf_digest(parameters, Node(len), leaf_digest()?);
        Some(true)
    }

    /// Appends `leaf_digest` to the tree using `parameters` and then it removes its proof.
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
        let len = self.len();
        if len >= capacity::<C, _>() {
            return Some(false);
        }
        self.push_leaf_digest(parameters, Node(len), leaf_digest()?);
        Some(true)
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
        match self.current_path() {
            Ok(current_path) => current_path,
            Err(_) => Default::default(),
        }
    }

    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        self.maybe_push_digest(parameters, leaf_digest)
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
        self.maybe_push_provable_digest(parameters, leaf_digest)
    }

    #[inline]
    fn path(&self, parameters: &Parameters<C>, index: usize) -> Result<Path<C>, PathError> {
        let _ = parameters;
        let last_index = self.current_index();
        if index > 0 && index > last_index {
            return Err(PathError::IndexTooLarge { length: last_index });
        }
        if index < self.starting_leaf_index() {
            return Err(PathError::IndexTooSmall {
                starting_index: self.starting_leaf_index(),
            });
        }
        self.path_unchecked(index)
    }

    #[inline]
    fn remove_path(&mut self, index: usize) -> bool {
        self.leaf_digests.mark(index);
        if self
            .leaf_digests
            .is_marked_or_removed(Node(index).sibling().0)
        {
            if index != self.current_index() {
                // The current leaf cannot be removed!
                self.leaf_digests.remove(index);
            }
            self.leaf_digests.remove(Node(index).sibling().0);
            let height = C::HEIGHT;
            let mut inner_node = match InnerNode::from_leaf::<C>(Node::parent(&Node(index))) {
                Some(q) => q,
                None => {
                    return true;
                }
            };
            for level in 1..height - 1 {
                self.inner_digests.remove(inner_node.sibling().map_index());
                if Node::from(inner_node)
                    .sibling()
                    .descendants(level)
                    .iter()
                    .all(|x| self.leaf_digests.is_marked_or_removed(x.0))
                {
                    if let Some(parent) = inner_node.parent() {
                        inner_node = parent;
                    } else {
                        return true;
                    }
                } else {
                    return true;
                }
            }
            true
        } else {
            false
        }
    }
}
