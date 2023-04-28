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

//! Partial Merkle Tree Tests

use crate::{
    accumulator::{Accumulator, FromItemsAndWitnesses},
    merkle_tree::{
        forest::{Forest, TreeArrayMerkleForest},
        fork::ForkedTree,
        full::{Full, FullMerkleTree},
        partial::{Partial, PartialMerkleTree},
        path::Path,
        test::{BinaryIndex, Test},
        tree::Parameters,
    },
    rand::{OsRng, Rand, Sample},
};

/// Merkle Tree Height
const HEIGHT: usize = 7;

/// Merkle Tree Configuration
type Config = Test<u64, HEIGHT>;

/// Tests the [`Partial`] tree generated from a set of leaves and a [`Path`] behaves
/// as expected.
#[test]
fn test_from_leaves_and_path() {
    let mut rng = OsRng;
    let parameters = Parameters::<Config>::sample(Default::default(), &mut rng);
    let number_of_insertions = rng.gen_range(5..(1 << (HEIGHT - 1)));
    let inner_element_index = rng.gen_range(0..number_of_insertions - 3);
    let mut tree = FullMerkleTree::<Config>::new(parameters);
    let insertions = (0..number_of_insertions)
        .map(|_| rng.gen())
        .collect::<Vec<_>>();
    for leaf in &insertions {
        tree.insert(leaf);
    }
    let forked_tree = ForkedTree::<Config, Full<Config>>::new(tree.tree.clone(), &parameters);
    let path = tree.current_path();
    let partial_tree = PartialMerkleTree::<Config> {
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
        path.into(),
    );
    let root = tree.root();
    let partial_root = partial_tree.root();
    let forked_root = forked_tree.root();
    let forked_partial_root = forked_partial_tree.root();
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

/// Tests the forest consisting of [`Partial`] trees generated from a set of leaves
/// and a [`Path`]s behaves as expected.
#[test]
fn test_from_leaves_and_path_forest() {
    let mut rng = OsRng;
    let parameters = Parameters::<Config>::sample(Default::default(), &mut rng);
    let mut forest =
        TreeArrayMerkleForest::<Config, ForkedTree<Config, Full<Config>>, 2>::new(parameters);
    let number_of_insertions = rng.gen_range(5..(1 << (HEIGHT - 1)));
    let insertions = (0..number_of_insertions)
        .map(|_| rng.gen())
        .collect::<Vec<_>>();
    for leaf in &insertions {
        forest.insert(leaf);
    }
    let path_1 = Path::from(forest.forest.get(BinaryIndex::Zero).current_path());
    let path_2 = Path::from(forest.forest.get(BinaryIndex::One).current_path());
    let paths = vec![path_1, path_2];
    let items = TreeArrayMerkleForest::<_, ForkedTree<_, Partial<Config>>, 2>::sort_items(
        insertions.clone(),
    );
    let partial_forest =
        TreeArrayMerkleForest::<_, ForkedTree<_, Partial<Config>>, 2>::from_items_and_witnesses(
            &parameters,
            items,
            paths,
        );
    for leaf in &insertions {
        assert_eq!(forest.output_from(leaf), partial_forest.output_from(leaf));
    }
}
