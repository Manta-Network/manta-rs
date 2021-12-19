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

//! Merkle Forest Abstractions

use crate::{
    accumulator::{
        self, Accumulator, ConstantCapacityAccumulator, ExactSizeAccumulator, MembershipProof,
        OptimizedAccumulator,
    },
    merkle_tree::{
        tree::{self, Configuration, Leaf, Parameters, Tree, Verifier},
        WithProofs,
    },
};

/// Forest Configuration
pub trait Forest<C>
where
    C: Configuration + ?Sized,
{
    /// Tree Type
    type Tree: Tree<C>;

    /// Tree Index
    type Index;

    /// Fixed Width of the Merkle Forest
    const WIDTH: usize;

    /// Builds a new empty merkle forest.
    fn new(parameters: &Parameters<C>) -> Self;

    /// Returns the number of items in `self`.
    fn len(&self) -> usize;

    /// Returns `true` if the length of `self` is zero.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the index of the merkle tree where `leaf` should be inserted.
    ///
    /// # Contract
    ///
    /// This method should be deterministic and should distribute the space of leaves uniformly over
    /// the space of indices.
    fn tree_index(&self, leaf: &Leaf<C>) -> Self::Index;

    /// Returns a shared reference to the tree at the given `index`.
    fn get(&self, index: Self::Index) -> &Self::Tree;

    /// Returns a shared reference to the tree which `leaf` corresponds with.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for computing [`tree_index`](Self::tree_index) followed
    /// by [`get`](Self::get).
    #[inline]
    fn get_tree(&self, leaf: &Leaf<C>) -> &Self::Tree {
        self.get(self.tree_index(leaf))
    }

    /// Returns a mutable reference to the tree at the given `index`.
    fn get_mut(&mut self, index: Self::Index) -> &mut Self::Tree;

    /// Returns a mutable reference to the tree which `leaf` corresponds with.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for computing [`tree_index`](Self::tree_index) followed
    /// by [`get_mut`](Self::get_mut).
    #[inline]
    fn get_tree_mut(&mut self, leaf: &Leaf<C>) -> &mut Self::Tree {
        self.get_mut(self.tree_index(leaf))
    }
}

/// Returns the capacity of the merkle forest with the given [`C::HEIGHT`](Configuration::HEIGHT)
/// and [`F::WIDTH`](Forest::WIDTH) parameters.
///
/// The capacity of a merkle forest with height `H` and width `W` is `W * 2^(H - 1)`.
#[inline]
pub fn capacity<C, F>() -> usize
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    F::WIDTH * tree::capacity::<C>()
}

/// Merkle Forest
pub struct MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    /// Underlying Forest Structure
    forest: F,

    /// Merkle Forest Parameters
    parameters: Parameters<C>,
}

impl<C, F> MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    /// Builds a new [`MerkleForest`] from `parameters`.
    ///
    /// See [`Forest::new`] for more.
    #[inline]
    pub fn new(parameters: Parameters<C>) -> Self {
        Self::from_forest(F::new(&parameters), parameters)
    }

    /// Builds a new [`MerkleForest`] from a pre-constructed `forest` and `parameters`.
    #[inline]
    pub fn from_forest(forest: F, parameters: Parameters<C>) -> Self {
        Self { forest, parameters }
    }

    /// Returns a shared reference to the parameters used by this merkle forest.
    #[inline]
    pub fn parameters(&self) -> &Parameters<C> {
        &self.parameters
    }

    /// Returns the number of leaves that can fit in this merkle tree.
    ///
    /// See [`capacity`] for more.
    #[inline]
    pub fn capacity(&self) -> usize {
        capacity::<C, F>()
    }

    /// Returns the number of items in this merkle forest.
    ///
    /// See [`Forest::len`] for more.
    #[inline]
    pub fn len(&self) -> usize {
        self.forest.len()
    }

    /// Returns `true` if this merkle forest is empty.
    ///
    /// See [`Forest::is_empty`] for more.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.forest.is_empty()
    }
}

impl<C, F> AsMut<F> for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut F {
        &mut self.forest
    }
}

impl<C, F> AsRef<F> for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    #[inline]
    fn as_ref(&self) -> &F {
        &self.forest
    }
}

impl<C, F> Accumulator for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
    F::Tree: WithProofs<C>,
{
    type Item = Leaf<C>;

    type Verifier = Verifier<C>;

    #[inline]
    fn parameters(&self) -> &accumulator::Parameters<Self> {
        self.parameters()
    }

    #[inline]
    fn matching_output(&self, output: &accumulator::Output<Self>) -> bool {
        // FIXME: Implement this
        let _ = output;
        todo!()
    }

    #[inline]
    fn insert(&mut self, item: &Self::Item) -> bool {
        self.forest
            .get_tree_mut(item)
            .push_provable(&self.parameters, item)
    }

    #[inline]
    fn prove(&self, item: &Self::Item) -> Option<MembershipProof<Self::Verifier>> {
        let tree = self.forest.get_tree(item);
        Some(MembershipProof::new(
            tree.path(
                &self.parameters,
                tree.index_of(&self.parameters.digest(item))?,
            )
            .ok()?,
            tree.root(&self.parameters),
        ))
    }

    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.forest
            .get_tree(item)
            .contains(&self.parameters.digest(item))
    }
}

impl<C, F> ConstantCapacityAccumulator for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
    F::Tree: WithProofs<C>,
{
    #[inline]
    fn capacity() -> usize {
        capacity::<C, F>()
    }
}

impl<C, F> ExactSizeAccumulator for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
    F::Tree: WithProofs<C>,
{
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<C, F> OptimizedAccumulator for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
    F::Tree: WithProofs<C>,
{
    #[inline]
    fn insert_nonprovable(&mut self, item: &Self::Item) -> bool {
        self.forest.get_tree_mut(item).push(&self.parameters, item)
    }
}
