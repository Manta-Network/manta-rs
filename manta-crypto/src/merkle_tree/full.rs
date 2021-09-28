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

//! Full Merkle Tree Storage

// TODO: Do we allow custom sentinel sources for this tree?

extern crate alloc;

use crate::merkle_tree::{
    capacity,
    inner_tree::{BTreeMap, InnerMap, InnerTree},
    Configuration, GetPath, InnerDigest, LeafDigest, MerkleTree, Node, Parameters, Path, Root,
    Tree,
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};

/// Full Merkle Tree Type
pub type FullMerkleTree<C, M = BTreeMap<C>> = MerkleTree<C, Full<C, M>>;

/// Full Merkle Tree Backing Structure
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone, M: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug, M: Debug"),
    Default(bound = "M: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq, M: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash, M: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq, M: PartialEq")
)]
pub struct Full<C, M = BTreeMap<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    /// Leaf Digests
    leaf_digests: Vec<LeafDigest<C>>,

    /// Inner Digests
    inner_digests: InnerTree<C, M>,
}

impl<C, M> Full<C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    /// Returns the leaf digests currently stored in the merkle tree.
    #[inline]
    pub fn leaf_digests(&self) -> &[LeafDigest<C>] {
        &self.leaf_digests
    }

    /// Returns a reference to the root inner digest.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.inner_digests.root()
    }

    /// Returns the sibling leaf node to `index`.
    #[inline]
    fn get_leaf_sibling(&self, index: Node) -> Option<&LeafDigest<C>> {
        // TODO: Add `Index` methods to accept `Node` as indices.
        self.leaf_digests.get(index.sibling().0)
    }

    /// Appends a `leaf_digest` with index given by `leaf_index` into the tree.
    #[inline]
    fn push_leaf_digest(
        &mut self,
        parameters: &Parameters<C>,
        leaf_index: Node,
        leaf_digest: LeafDigest<C>,
    ) {
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
}

impl<C, M> Tree<C> for Full<C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C> + Default,
    LeafDigest<C>: Clone,
    InnerDigest<C>: Clone,
{
    #[inline]
    fn new(parameters: &Parameters<C>) -> Self {
        let _ = parameters;
        Default::default()
    }

    #[inline]
    fn len(&self) -> usize {
        self.leaf_digests.len()
    }

    #[inline]
    fn root(&self, parameters: &Parameters<C>) -> Root<C> {
        let _ = parameters;
        Root(self.root().clone())
    }

    #[inline]
    fn current_path(&self, parameters: &Parameters<C>) -> Path<C> {
        self.path(parameters, 0).unwrap()
    }

    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        let len = self.len();
        if len >= capacity::<C>() {
            return Some(false);
        }
        self.push_leaf_digest(parameters, Node(len), leaf_digest()?);
        Some(true)
    }
}

impl<C, M> GetPath<C> for Full<C, M>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    LeafDigest<C>: Clone,
    InnerDigest<C>: Clone,
{
    type Error = ();

    #[inline]
    fn path(&self, parameters: &Parameters<C>, index: usize) -> Result<Path<C>, Self::Error> {
        let _ = parameters;
        if index > 0 && index >= self.leaf_digests.len() {
            return Err(());
        }
        let leaf_index = Node(index);
        Ok(Path::new(
            leaf_index,
            self.get_leaf_sibling(leaf_index)
                .map(Clone::clone)
                .unwrap_or_default(),
            self.inner_digests
                .inner_path_for_leaf(leaf_index)
                .cloned()
                .collect(),
        ))
    }
}
