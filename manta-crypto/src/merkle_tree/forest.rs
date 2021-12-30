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

//! Merkle Forests

// FIXME: Replace `N` parameter on `FixedIndex` with an associated value in the trait when
//        `generic_const_exprs` is stabilized and get rid of `ConstantWidthForest`.
// FIXME: Reduce code duplication between this and `tree.rs` code.

use crate::{
    accumulator::{
        Accumulator, ConstantCapacityAccumulator, ExactSizeAccumulator, MembershipProof,
        OptimizedAccumulator,
    },
    merkle_tree::{
        tree::{self, Leaf, Parameters, Tree},
        WithProofs,
    },
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use manta_util::into_array_unchecked;

/// Merkle Forest Configuration
pub trait Configuration: tree::Configuration {
    /// Tree Index Type
    type Index: PartialEq;

    /// Returns the index of the merkle tree where `leaf` should be inserted.
    ///
    /// # Contract
    ///
    /// This method should be deterministic and should distribute the space of leaves uniformly over
    /// the space of indices.
    fn tree_index(leaf: &Leaf<Self>) -> Self::Index;
}

/// Merkle Forest Fixed Index Type
///
/// # Contract
///
/// For a type to be a fixed index, the number of possible values must be known at compile time. In
/// this case, `N` must be the the number of values. If this type is used as an
/// [`Index`](Configuration::Index) for a merkle forest configuration, the
/// [`tree_index`](Configuration::tree_index) method must return values from a distribution over
/// exactly `N` values.
pub trait FixedIndex<const N: usize>: Into<usize> {}

/// Merkle Forest Structure
pub trait Forest<C>
where
    C: Configuration + ?Sized,
{
    /// Tree Type
    type Tree: Tree<C>;

    /// Builds a new empty merkle forest.
    fn new(parameters: &Parameters<C>) -> Self;

    /// Returns the number of items in `self`.
    fn len(&self) -> usize;

    /// Returns `true` if the length of `self` is zero.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of items that can be stored in `self`.
    fn capacity(&self) -> usize;

    /// Returns a shared reference to the tree at the given `index`.
    ///
    /// # Panics
    ///
    /// This method is allowed to panic if `index` is out-of-bounds.
    fn get(&self, index: C::Index) -> &Self::Tree;

    /// Returns a shared reference to the tree which `leaf` corresponds with.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for computing [`tree_index`](Configuration::tree_index)
    /// followed by [`get`](Self::get).
    #[inline]
    fn get_tree(&self, leaf: &Leaf<C>) -> &Self::Tree {
        self.get(C::tree_index(leaf))
    }

    /// Returns a mutable reference to the tree at the given `index`.
    ///
    /// # Panics
    ///
    /// This method is allowed to panic if `index` is out-of-bounds.
    fn get_mut(&mut self, index: C::Index) -> &mut Self::Tree;

    /// Returns a mutable reference to the tree which `leaf` corresponds with.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for computing [`tree_index`](Configuration::tree_index)
    /// followed by [`get_mut`](Self::get_mut).
    #[inline]
    fn get_tree_mut(&mut self, leaf: &Leaf<C>) -> &mut Self::Tree {
        self.get_mut(C::tree_index(leaf))
    }
}

/// Constant Width Forest
pub trait ConstantWidthForest<C>: Forest<C>
where
    C: Configuration + ?Sized,
{
    /// Fixed Number of Trees in the Forest
    const WIDTH: usize;
}

/// Returns the capacity of the merkle forest with the given [`C::HEIGHT`] and [`F::WIDTH`]
/// parameters.
///
/// The capacity of a merkle forest with height `H` and width `W` is `W * 2^(H - 1)`.
///
/// [`C::HEIGHT`]: tree::Configuration::HEIGHT
/// [`F::WIDTH`]: ConstantWidthForest::WIDTH
#[inline]
pub fn capacity<C, F>() -> usize
where
    C: Configuration + ?Sized,
    F: ConstantWidthForest<C>,
{
    F::WIDTH * tree::capacity::<C>()
}

/// Merkle Forest
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Parameters<C>: Clone, F: Clone"),
    Copy(bound = "Parameters<C>: Copy, F: Copy"),
    Debug(bound = "Parameters<C>: Debug, F: Debug"),
    Default(bound = "Parameters<C>: Default, F: Default"),
    Eq(bound = "Parameters<C>: Eq, F: Eq"),
    Hash(bound = "Parameters<C>: Hash, F: Hash"),
    PartialEq(bound = "Parameters<C>: PartialEq, F: PartialEq")
)]
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
        self.forest.capacity()
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

    type Model = Parameters<C>;

    #[inline]
    fn model(&self) -> &Self::Model {
        self.parameters()
    }

    #[inline]
    fn insert(&mut self, item: &Self::Item) -> bool {
        self.forest
            .get_tree_mut(item)
            .push_provable(&self.parameters, item)
    }

    #[inline]
    fn are_independent(&self, fst: &Self::Item, snd: &Self::Item) -> bool {
        C::tree_index(fst) != C::tree_index(snd)
    }

    #[inline]
    fn prove(&self, item: &Self::Item) -> Option<MembershipProof<Self::Model>> {
        let tree = self.forest.get_tree(item);
        Some(MembershipProof::new(
            tree.path(
                &self.parameters,
                tree.position(&self.parameters.digest(item))?,
            )
            .ok()?,
            tree.root().clone(),
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
    F: ConstantWidthForest<C>,
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

    #[inline]
    fn remove_proof(&mut self, item: &Self::Item) -> bool {
        let tree = self.forest.get_tree_mut(item);
        tree.position(&self.parameters.digest(item))
            .map(move |i| tree.remove_path(i))
            .unwrap_or(false)
    }
}

/// Tree Array Merkle Forest Alias
pub type TreeArrayMerkleForest<C, T, const N: usize> = MerkleForest<C, TreeArray<C, T, N>>;

/// Tree Array
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    Copy(bound = "T: Copy"),
    Debug(bound = "T: Debug"),
    Eq(bound = "T: Eq"),
    Hash(bound = "T: Hash"),
    PartialEq(bound = "T: PartialEq")
)]
pub struct TreeArray<C, T, const N: usize>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    /// Array of Trees
    array: [T; N],

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, T, const N: usize> Default for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Default + Tree<C>,
{
    #[inline]
    fn default() -> Self {
        Self::from(into_array_unchecked(
            (0..N)
                .into_iter()
                .map(move |_| Default::default())
                .collect::<Vec<_>>(),
        ))
    }
}

impl<C, T, const N: usize> Forest<C> for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    type Tree = T;

    #[inline]
    fn new(parameters: &Parameters<C>) -> Self {
        Self::from(into_array_unchecked(
            (0..N)
                .into_iter()
                .map(move |_| T::new(parameters))
                .collect::<Vec<_>>(),
        ))
    }

    #[inline]
    fn len(&self) -> usize {
        self.array.iter().map(T::len).sum()
    }

    #[inline]
    fn capacity(&self) -> usize {
        capacity::<C, Self>()
    }

    #[inline]
    fn get(&self, index: C::Index) -> &Self::Tree {
        &self.array[index.into()]
    }

    #[inline]
    fn get_mut(&mut self, index: C::Index) -> &mut Self::Tree {
        &mut self.array[index.into()]
    }
}

impl<C, T, const N: usize> ConstantWidthForest<C> for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    const WIDTH: usize = N;
}

impl<C, T, const N: usize> From<[T; N]> for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    #[inline]
    fn from(array: [T; N]) -> Self {
        Self {
            array,
            __: PhantomData,
        }
    }
}
