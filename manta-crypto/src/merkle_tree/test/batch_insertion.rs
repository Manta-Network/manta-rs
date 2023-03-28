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
        inner_tree::{InnerNode, InnerNodeRangeIter}, node::Node, partial::PartialMerkleTree, test::Test, tree::Parameters, full::FullMerkleTree
    },
    rand::{OsRng, Rand, Sample},
};

/// Merkle Tree Height
const HEIGHT: usize = 4;

/// Merkle Tree Configuration
type Config = Test<String, HEIGHT>;

///
#[test]
fn test_batch_insertion() {
    let mut rng = OsRng;
    let parameters = Parameters::<Config>::sample(Default::default(), &mut rng);
    let mut tree = PartialMerkleTree::<Config>::new(parameters);
    let mut cloned_tree = tree.clone();
    let insertions = vec!["a", "b", "c", "d", "e", "f", "g", "h"].into_iter().map(String::from).collect::<Vec<_>>();
    for leaf in &insertions {
        tree.insert(leaf);
    }
    println!("{insertions:?}");
    cloned_tree.batch_insert(&insertions);
    let mut node = InnerNodeRangeIter::from_leaves::<Config>(0.into(), 7);
    println!("{:?}", node.next());
    println!("{:?}", node.next());
    println!("{:?}", node.next());
    assert_eq!(tree.tree, cloned_tree.tree);
}