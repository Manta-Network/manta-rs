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

//! Sharded Merkle Tree Abstractions

use crate::merkle_tree::tree::{Configuration, Leaf, Parameters, Tree};

/// Sharding Configuration
pub trait Sharding<C>
where
    C: Configuration + ?Sized,
{
    /// Sharded Tree Type
    type Tree: ShardedTree<C>;

    /// Tree over Shard Roots Type
    type RootTree: Tree<C>;

    /// Returns the shard index for the given `leaf`.
    fn shard(leaf: &Leaf<C>) -> <Self::Tree as ShardedTree<C>>::Index;
}

/// Sharded Merkle Tree
pub trait ShardedTree<C>
where
    C: Configuration + ?Sized,
{
    /// Shard Index
    type Index: Copy + Into<usize>;

    /// Builds a new sharded merkle tree from `parameters`.
    fn new(parameters: &Parameters<C>) -> Self;
}

/// Sharded Merkle Tree
pub struct ShardedMerkleTree<C, S>
where
    C: Configuration + ?Sized,
    S: Sharding<C>,
{
    /// Sharded Tree
    tree: S::Tree,

    /// Tree over the Shard Roots
    root_tree: S::RootTree,

    /// Merkle Tree Parameters
    parameters: Parameters<C>,
}

impl<C, S> ShardedMerkleTree<C, S>
where
    C: Configuration + ?Sized,
    S: Sharding<C>,
{
    /// Builds a new [`ShardedMerkleTree`] from `parameters`.
    #[inline]
    pub fn new(parameters: Parameters<C>) -> Self {
        Self {
            tree: S::Tree::new(&parameters),
            root_tree: S::RootTree::new(&parameters),
            parameters,
        }
    }
}
