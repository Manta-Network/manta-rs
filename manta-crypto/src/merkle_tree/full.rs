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

extern crate alloc;

use crate::merkle_tree::{
    capacity, inner_tree::InnerTree, Configuration, InnerDigest, LeafDigest, MerkleTree, Node,
    Parameters, Path, Root, Tree,
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};

/// Full Merkle Tree Type
pub type FullMerkleTree<C> = MerkleTree<C, Full<C>>;

/// Path Query Error Type
///
/// Querying for paths beyond the current length of a [`Full`] tree is an error.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Unknown;

/// Full Merkle Tree Backing Structure
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct Full<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digests
    leaf_digests: Vec<LeafDigest<C>>,

    /// Inner Digests
    inner_digests: InnerTree<C>,
}

impl<C> Full<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the leaf digests currently stored in the merkle tree.
    #[inline]
    pub fn leaf_digests(&self) -> &[LeafDigest<C>] {
        &self.leaf_digests
    }

    /// Returns a reference to the root inner digest.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.inner_digests.previous_root()
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

impl<C> Tree<C> for Full<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: Clone,
    InnerDigest<C>: Clone,
{
    type Query = usize;

    type Error = Unknown;

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
    fn path(&self, parameters: &Parameters<C>, query: Self::Query) -> Result<Path<C>, Self::Error> {
        let _ = parameters;
        if query > capacity::<C>() {
            return Err(Unknown);
        }
        let leaf_index = Node(query);
        Ok(Path::new(
            leaf_index,
            self.get_leaf_sibling(leaf_index)
                .map(Clone::clone)
                .unwrap_or_default(),
            self.inner_digests.inner_path_for_leaf(leaf_index),
        ))
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
