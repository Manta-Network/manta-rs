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

//! Manta Pay Merkle Tree Testing

use crate::config::MerkleTreeConfiguration;
use core::iter::repeat;
use manta_crypto::{
    accumulator,
    accumulator::Accumulator,
    merkle_tree::{self, forest, fork, test, MerkleTree},
    rand::{Rand, Standard},
};
use rand::thread_rng;

/// Base Tree
pub type Base = merkle_tree::full::Full<MerkleTreeConfiguration>;

/// Forked Base Tree
pub type ForkedBase = fork::ForkedTree<MerkleTreeConfiguration, Base>;

/// Tree Wrapper for Base
pub type Tree = MerkleTree<MerkleTreeConfiguration, Base>;

/// Tree Wrapper for Forked Base
pub type ForkedTree = MerkleTree<MerkleTreeConfiguration, ForkedBase>;

/// Forest Wrapper for Base
pub type Forest = forest::TreeArrayMerkleForest<MerkleTreeConfiguration, Base, 256>;

/// Forest Wrapper for Forked Base
pub type ForkedForest = forest::TreeArrayMerkleForest<MerkleTreeConfiguration, ForkedBase, 256>;

#[test]
fn test_suite() {
    let mut rng = thread_rng();
    let parameters = rng.gen();
    let parameters = test::push_twice_to_empty_tree_succeeds::<MerkleTreeConfiguration, Base>(
        parameters,
        &rng.gen(),
        &rng.gen(),
    );

    let mut tree = Tree::new(parameters);

    accumulator::test::assert_unique_outputs(
        &mut tree,
        &rng.sample_iter(repeat(Standard).take(300))
            .collect::<Vec<_>>(),
    );
    for _ in 0..30000 {
        tree.insert(&rng.gen());
    }
    accumulator::test::assert_unique_outputs(
        &mut tree,
        &rng.sample_iter(repeat(Standard).take(300))
            .collect::<Vec<_>>(),
    );

    let parameters = tree.into_parameters();

    let mut forest = Forest::new(parameters);

    accumulator::test::assert_unique_outputs(
        &mut forest,
        &rng.sample_iter(repeat(Standard).take(300))
            .collect::<Vec<_>>(),
    );
    for _ in 0..30000 {
        forest.insert(&rng.gen());
    }
    accumulator::test::assert_unique_outputs(
        &mut forest,
        &rng.sample_iter(repeat(Standard).take(300))
            .collect::<Vec<_>>(),
    );
}
