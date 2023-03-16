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

//! Testing Framework

use crate::{
    accumulator::{Accumulator, FromItemsAndWitnesses},
    merkle_tree::{
        forest::{self, Forest, MerkleForest, TreeArrayMerkleForest},
        fork::ForkedTree,
        full::{Full, FullMerkleTree},
        partial::{Partial, PartialMerkleTree},
        Configuration, HashConfiguration, IdentityLeafHash, InnerDigest, InnerHash,
        InnerHashParameters, Leaf, LeafHashParameters, MerkleTree, Parameters, Path, Tree,
        WithProofs,
    },
    rand::{OsRng, Rand, RngCore, Sample},
};
use alloc::string::String;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};

use super::forest::FixedIndex;

/// Hash Parameter Sampling
pub trait HashParameterSampling: HashConfiguration {
    /// Leaf Hash Parameter Distribution
    type LeafHashParameterDistribution;

    /// Inner Hash Parameter Distribution
    type InnerHashParameterDistribution;

    /// Sample leaf hash parameters from `distribution` using the given `rng`.
    fn sample_leaf_hash_parameters<R>(
        distribution: Self::LeafHashParameterDistribution,
        rng: &mut R,
    ) -> LeafHashParameters<Self>
    where
        R: RngCore + ?Sized;

    /// Sample inner hash parameters from `distribution` using the given `rng`.
    fn sample_inner_hash_parameters<R>(
        distribution: Self::InnerHashParameterDistribution,
        rng: &mut R,
    ) -> InnerHashParameters<Self>
    where
        R: RngCore + ?Sized;
}

/// Hash Parameter Distribution
#[derive(derivative::Derivative)]
#[derivative(
    Clone(
        bound = "C::LeafHashParameterDistribution: Clone, C::InnerHashParameterDistribution: Clone"
    ),
    Copy(
        bound = "C::LeafHashParameterDistribution: Copy, C::InnerHashParameterDistribution: Copy"
    ),
    Debug(
        bound = "C::LeafHashParameterDistribution: Debug, C::InnerHashParameterDistribution: Debug"
    ),
    Default(
        bound = "C::LeafHashParameterDistribution: Default, C::InnerHashParameterDistribution: Default"
    ),
    Eq(bound = "C::LeafHashParameterDistribution: Eq, C::InnerHashParameterDistribution: Eq"),
    Hash(
        bound = "C::LeafHashParameterDistribution: Hash, C::InnerHashParameterDistribution: Hash"
    ),
    PartialEq(bound = "C::LeafHashParameterDistribution: PartialEq,
        C::InnerHashParameterDistribution: PartialEq")
)]
pub struct HashParameterDistribution<C>
where
    C: HashParameterSampling + ?Sized,
{
    /// Leaf Hash Parameter Distribution
    pub leaf: C::LeafHashParameterDistribution,

    /// Inner Hash Parameter Distribution
    pub inner: C::InnerHashParameterDistribution,
}

impl<C> Sample<HashParameterDistribution<C>> for Parameters<C>
where
    C: HashParameterSampling + ?Sized,
{
    #[inline]
    fn sample<R>(distribution: HashParameterDistribution<C>, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(
            C::sample_leaf_hash_parameters(distribution.leaf, rng),
            C::sample_inner_hash_parameters(distribution.inner, rng),
        )
    }
}

/// Tests that a tree constructed with `parameters` can accept at least two leaves without
/// failing.
#[inline]
pub fn push_twice_to_empty_tree_succeeds<C, T>(
    parameters: Parameters<C>,
    lhs: &Leaf<C>,
    rhs: &Leaf<C>,
) -> Parameters<C>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    let mut tree = MerkleTree::<C, T>::new(parameters);
    assert!(
        tree.push(lhs),
        "Trees always have a capacity of at least two."
    );
    assert!(
        tree.push(rhs),
        "Trees always have a capacity of at least two."
    );
    tree.into_parameters()
}

/// Tests path construction by checking that the path at the given `index` on `tree` is a valid
/// [`Path`](super::Path) for `leaf`.
#[inline]
pub fn assert_valid_path<C, T>(tree: &MerkleTree<C, T>, index: usize, leaf: &Leaf<C>)
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
    InnerDigest<C>: Debug + PartialEq,
    Path<C>: Debug,
{
    let path = tree.path(index).expect("Only valid queries are accepted.");
    let root = tree.root();
    assert!(
        path.verify(tree.parameters(), root, leaf),
        "Path returned from tree was not valid: {:?}. Expected {:?} but got {:?}.",
        path,
        root,
        path.root(&tree.parameters, &tree.parameters.digest(leaf)),
    );
}

/// Tests path construction for multiple insertions. This is an extension of the
/// [`assert_valid_path`] test.
#[inline]
pub fn assert_valid_paths<C, T>(tree: &mut MerkleTree<C, T>, leaves: &[Leaf<C>])
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
    InnerDigest<C>: Debug + PartialEq,
    Path<C>: Debug,
    Leaf<C>: Sized,
{
    let starting_index = tree.len();
    for (i, leaf) in leaves.iter().enumerate() {
        tree.push(leaf);
        for (j, previous_leaf) in leaves.iter().enumerate().take(i + 1) {
            assert_valid_path(tree, starting_index + j, previous_leaf);
        }
    }
}

/// Test Inner Hash
///
/// # Warning
///
/// This is only meant for testing purposes, and should not be used in any production or
/// cryptographically secure environments.
pub trait TestHash {
    /// Joins `lhs` and `rhs` into an output hash value.
    fn join(lhs: &Self, rhs: &Self) -> Self;
}

impl TestHash for u64 {
    #[inline]
    fn join(lhs: &Self, rhs: &Self) -> Self {
        *lhs ^ *rhs
    }
}

impl TestHash for String {
    #[inline]
    fn join(lhs: &Self, rhs: &Self) -> Self {
        let mut lhs = lhs.clone();
        lhs.push_str(rhs);
        lhs
    }
}

/// Test Merkle Tree Configuration
///
/// # Warning
///
/// This is only meant for testing purposes, and should not be used in production or
/// cryptographically secure environments.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Test<T, const HEIGHT: usize>(PhantomData<T>)
where
    T: Clone + Default + PartialEq + TestHash;

impl<T, const HEIGHT: usize> InnerHash for Test<T, HEIGHT>
where
    T: Clone + Default + PartialEq + TestHash,
{
    type LeafDigest = T;
    type Parameters = ();
    type Output = T;

    #[inline]
    fn join(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        _: &mut (),
    ) -> Self::Output {
        let _ = parameters;
        TestHash::join(lhs, rhs)
    }

    #[inline]
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        _: &mut (),
    ) -> Self::Output {
        let _ = parameters;
        TestHash::join(lhs, rhs)
    }
}

impl<T, const HEIGHT: usize> HashConfiguration for Test<T, HEIGHT>
where
    T: Clone + Default + PartialEq + TestHash,
{
    type LeafHash = IdentityLeafHash<T>;
    type InnerHash = Test<T, HEIGHT>;
}

impl<T, const HEIGHT: usize> Configuration for Test<T, HEIGHT>
where
    T: Clone + Default + PartialEq + TestHash,
{
    const HEIGHT: usize = HEIGHT;
}

impl<T, const HEIGHT: usize> HashParameterSampling for Test<T, HEIGHT>
where
    T: Clone + Default + PartialEq + TestHash,
{
    type LeafHashParameterDistribution = ();
    type InnerHashParameterDistribution = ();

    #[inline]
    fn sample_leaf_hash_parameters<R>(
        distribution: Self::LeafHashParameterDistribution,
        rng: &mut R,
    ) -> LeafHashParameters<Self>
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
    }

    #[inline]
    fn sample_inner_hash_parameters<R>(
        distribution: Self::InnerHashParameterDistribution,
        rng: &mut R,
    ) -> InnerHashParameters<Self>
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
    }
}

///
#[test]
fn test_from_leaves_and_path() {
    let mut rng = OsRng;
    const HEIGHT: usize = 7;
    type Config = Test<u64, HEIGHT>;
    let parameters = Parameters::<Config>::sample(Default::default(), &mut rng);
    let number_of_insertions = rng.gen_range(5..(1 << (HEIGHT - 1)));
    let inner_element_index = rng.gen_range(0..number_of_insertions - 3); // make sure this one isn't the last nor its sibling
    println!("{number_of_insertions}, {inner_element_index}");
    let mut tree = FullMerkleTree::<Config>::new(parameters);
    let mut insertions = Vec::<u64>::with_capacity(number_of_insertions);
    for _ in 0..number_of_insertions {
        insertions.push(rng.gen());
    }
    for leaf in &insertions {
        tree.insert(leaf);
    }
    let forked_tree = ForkedTree::<Config, Full<Config>>::new(tree.tree.clone(), &parameters);
    let path = tree.current_path();
    let partial_tree = PartialMerkleTree::<Test<u64, HEIGHT>> {
        parameters,
        tree: Partial::from_leaves_and_path_unchecked(
            &parameters,
            insertions.clone(),
            path.clone().into(),
        ),
    };
    let forked_partial_tree = ForkedTree::<Config, Partial<Config>>::from_leaves_and_path_unchecked(
        &parameters,
        insertions.clone(),
        path.clone().into(),
    );
    let root = tree.root().clone();
    let partial_root = partial_tree.root().clone();
    let forked_root = forked_tree.root().clone();
    let forked_partial_root = forked_partial_tree.root().clone();
    assert_eq!(root, partial_root, "Roots must be equal");
    assert_eq!(root, forked_root, "Roots must be equal");
    assert_eq!(root, forked_partial_root, "Roots must be equal");
    let proof_full_inner = tree
        .prove(&insertions[inner_element_index])
        .expect("Failed to generate proof");
    let proof_partial_inner = partial_tree
        .prove(&insertions[inner_element_index])
        .expect("Failed to generate proof");
    assert!(
        proof_full_inner.verify(&parameters, &insertions[inner_element_index], &mut ()),
        "Inner proof in the full tree must be valid"
    );
    assert!(
        !proof_partial_inner.verify(&parameters, &insertions[inner_element_index], &mut ()),
        "Inner proof in the partial tree must be invalid"
    );
    let proof_full = tree
        .prove(&insertions[number_of_insertions - 1])
        .expect("Failed to generate proof");
    let proof_partial = partial_tree
        .prove(&insertions[number_of_insertions - 1])
        .expect("Failed to generate proof");
    assert!(
        proof_full.verify(&parameters, &insertions[number_of_insertions - 1], &mut ()),
        "Final proof in the full tree must be valid"
    );
    assert!(
        proof_partial.verify(&parameters, &insertions[number_of_insertions - 1], &mut ()),
        "Final proof in the partial tree must be valid"
    );
}

///
#[derive(PartialEq)]
pub enum Index {
    ///
    Zero,

    ///
    One,
}

impl From<Index> for usize {
    fn from(value: Index) -> Self {
        match value {
            Index::Zero => 0,
            Index::One => 1,
        }
    }
}

impl FixedIndex<2> for Index {
    fn from_index(index: usize) -> Self {
        if index % 2 == 0 {
            Index::Zero
        } else {
            Index::One
        }
    }
}

impl<const HEIGHT: usize> forest::Configuration for Test<u64, HEIGHT> {
    type Index = Index;
    fn tree_index(leaf: &Leaf<Self>) -> Self::Index {
        let parity = leaf % 2;
        if parity == 0 {
            Index::Zero
        } else {
            Index::One
        }
    }
}
///
#[test]
fn test_from_leaves_and_path_forest() {
    let mut rng = OsRng;
    const HEIGHT: usize = 7;
    type Config = Test<u64, HEIGHT>;
    let parameters = Parameters::<Config>::sample(Default::default(), &mut rng);
    let mut forest =
        TreeArrayMerkleForest::<Config, ForkedTree<Config, Full<Config>>, 2>::new(parameters);
    let number_of_insertions = rng.gen_range(5..(1 << (HEIGHT - 1)));
    let mut insertions = Vec::<u64>::with_capacity(number_of_insertions);
    for _ in 0..number_of_insertions {
        insertions.push(rng.gen());
    }
    for leaf in &insertions {
        forest.insert(leaf);
    }
    let path_1 = Path::from(forest.forest.get(Index::Zero).current_path());
    let path_2 = Path::from(forest.forest.get(Index::One).current_path());
    let paths = vec![path_1, path_2];
    let partial_forest =
        TreeArrayMerkleForest::<_, ForkedTree<_, Partial<Config>>, 2>::from_items_and_witnesses(
            &parameters,
            insertions.clone(),
            paths,
        );
    for leaf in &insertions {
        assert_eq!(forest.output_from(leaf), partial_forest.output_from(leaf));
    }
}

///
#[test]
fn visual_test_with_strings() {
    const HEIGHT: usize = 5;
    let mut rng = OsRng;
    let parameters = Parameters::<Test<String, HEIGHT>>::sample(Default::default(), &mut rng);
    let mut tree = FullMerkleTree::<Test<String, HEIGHT>>::new(parameters);
    let insertions = vec![
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<String>>();
    for leaf in &insertions {
        tree.insert(leaf);
    }
    let root = tree.root().clone();
    let path = tree.current_path();
    println!("{path:?}");
    let partial_tree = PartialMerkleTree::<Test<String, HEIGHT>> {
        parameters,
        tree: Partial::from_leaves_and_path_unchecked(&parameters, insertions.clone(), path.into()),
    };
    let second_root = partial_tree.root().clone();
    assert_eq!(root, second_root);
    const INNER_ELEMENT_INDEX: usize = 10; // k
    let proof = tree.prove(&insertions[INNER_ELEMENT_INDEX]).unwrap();
    println!("{proof:?}");
    let proof_2 = partial_tree
        .prove(&insertions[INNER_ELEMENT_INDEX])
        .unwrap();
    println!("{proof_2:?}");
    let proof_3 = tree.prove(&insertions[insertions.len() - 1]).unwrap();
    let proof_4 = partial_tree
        .prove(&insertions[insertions.len() - 1])
        .unwrap();
    println!("{proof_3:?}");
    println!("{proof_4:?}");
}
