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

//! Batch Insertion

use crate::{
    accumulator::{Accumulator, BatchInsertion},
    merkle_tree::{
        forest, fork, full, partial,
        test::Test,
        tree::{Parameters, Tree},
        Leaf, MerkleTree, WithProofs,
    },
    rand::{ChaCha20Rng, OsRng, Rand, Sample, SeedableRng},
};
use core::fmt::Debug;

/// Merkle Tree Height
const HEIGHT: usize = 4;

/// Merkle Tree Configuration
type Config = Test<u64, HEIGHT>;

/// Full Merkle Tree
type Full = full::Full<Config>;

/// Partial Merkle Tree
type Partial = partial::Partial<Config>;

/// Forked Merkle Tree
type ForkedTree = fork::ForkedTree<Config, partial::Partial<Config>>;

/// Merkle Forest Type
type Forest = forest::TreeArrayMerkleForest<Config, ForkedTree, 2>;

/// Tests that batch inserting new leaves into a Merkle tree yields the same result
/// as inserting them one by one.
#[inline]
fn test_batch_insertion<T, F, G, H>(f: F, mut insert: G, mut batch_insert: H)
where
    T: Clone + Debug + PartialEq,
    Leaf<Config>: Sample,
    F: FnOnce(&Parameters<Config>) -> T,
    G: FnMut(&mut T, &Parameters<Config>, &Leaf<Config>) -> bool,
    H: FnMut(&mut T, &Parameters<Config>, &[Leaf<Config>]) -> bool,
{
    let mut rng = OsRng;
    let parameters = Parameters::<Config>::sample(Default::default(), &mut rng);
    let mut tree = f(&parameters);
    let mut cloned_tree = tree.clone();
    let number_of_insertions = rng.gen_range(1..(1 << (HEIGHT - 1)));
    let insertions = (0..number_of_insertions)
        .map(|_| rng.gen())
        .collect::<Vec<_>>();
    for leaf in &insertions {
        insert(&mut tree, &parameters, leaf);
    }
    batch_insert(&mut cloned_tree, &parameters, &insertions);
    assert_eq!(
        tree, cloned_tree,
        "Individual insertions and batch insertions should yield the same results."
    );
}

/// Runs [`test_batch_insertion`] on a [`Full`] Merkle tree.
#[test]
fn test_batch_insertion_full() {
    test_batch_insertion(
        |parameters| Full::new(parameters),
        |tree, parameters, leaf| tree.push_provable(parameters, leaf),
        |tree, parameters, leaves| tree.batch_push_provable(parameters, leaves),
    )
}

/// Runs [`test_batch_insertion`] on a [`Partial`] Merkle tree.
#[test]
fn test_batch_insertion_partial() {
    test_batch_insertion(
        |parameters| Partial::new(parameters),
        |tree, parameters, leaf| tree.push_provable(parameters, leaf),
        |tree, parameters, leaves| tree.batch_push_provable(parameters, leaves),
    )
}

/// Runs [`test_batch_insertion`] on a [`ForkedTree`].
#[test]
fn test_batch_insertion_fork() {
    test_batch_insertion(
        |parameters| ForkedTree::new(Partial::new(parameters), parameters),
        |tree, parameters, leaf| tree.push_provable(parameters, leaf),
        |tree, parameters, leaves| tree.batch_push_provable(parameters, leaves),
    )
}

/// Tests batch insertion on a Merkle forest.
#[test]
fn test_batch_insertion_forest() {
    test_batch_insertion(
        |parameters| Forest::new(*parameters),
        |forest, _, leaf| forest.insert(leaf),
        |forest, _, leaves| forest.batch_insert(leaves),
    )
}

///
#[test]
fn branch_and_merge_test() {
    type StringConfig = Test<String, HEIGHT>;
    type PartialString = partial::Partial<StringConfig>;
    type ForkedString = fork::ForkedTree<StringConfig, PartialString>;
    let mut rng = ChaCha20Rng::from_seed(Default::default());
    let parameters = Parameters::<StringConfig>::sample(Default::default(), &mut rng);
    let mut tree = ForkedString::new(PartialString::new(&parameters), &parameters);
    let number_of_insertions = rng.gen_range(1..(1 << (HEIGHT - 1)) / 2);
    let insertions = (0..number_of_insertions)
        .map(|e| (e as u8).to_string())
        .collect::<Vec<_>>();
    for leaf in insertions {
        Tree::push(&mut tree, &parameters, &leaf);
    }
    tree.merge_fork(&parameters);
    println!("Tree before: {tree:#?}");
    let second_number_of_insertions = rng.gen_range(number_of_insertions..(1 << (HEIGHT - 1)));
    let insertions = (number_of_insertions..second_number_of_insertions)
        .map(|e| (e as u8).to_string())
        .collect::<Vec<_>>();
    for leaf in insertions {
        Tree::push(&mut tree, &parameters, &leaf);
    }
    let mut cloned_tree = tree.clone();
    tree.merge_fork_partial(&parameters);
    cloned_tree.merge_fork(&parameters);
    println!("Tree after (batch): {tree:#?}");
    println!("Tree after (no batch): {cloned_tree:#?}");
    assert_eq!(tree.root(), cloned_tree.root(), "Second round wrong");
}

// cargo test --package manta-crypto --lib --all-features -- merkle_tree::test::batch_insertion::branch_and_merge_test --exact --nocapture > test_result
