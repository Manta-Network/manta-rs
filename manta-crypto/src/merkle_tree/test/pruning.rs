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

//! Pruning

use crate::{
    accumulator::{Accumulator, MembershipProof, OptimizedAccumulator},
    merkle_tree::{
        fork::ForkedTree,
        partial::{Partial, PartialMerkleTree},
        test::Test,
        tree::Parameters,
        Leaf, Tree, WithProofs,
    },
    rand::{OsRng, Rand, Sample},
};

/// Merkle Tree Height
const HEIGHT: usize = 10;

/// Proportion of provable insertions.
///
/// # Note
///
/// 1/`PROVABLE_PROPORTION` of the insertions in the test will be provable.
const PROVABLE_PROPORTION: u32 = 10;

/// Merkle Tree Configuration
type Config = Test<String, HEIGHT>;

/// Provability
enum Provability {
    /// Provable
    Provable,

    /// Non Provable
    NonProvable,
}

impl Sample for Provability {
    #[inline]
    fn sample<R>(_distribution: (), rng: &mut R) -> Self
    where
        R: rand::RngCore + ?Sized,
    {
        let number = u32::gen(rng);
        match number % PROVABLE_PROPORTION {
            0 => Provability::Provable,
            _ => Provability::NonProvable,
        }
    }
}

/// Tests that pruning doesn't remove necessary proofs.
#[inline]
fn test_pruning_safety<T, F, G, H, P, PT>(
    f: F,
    mut push: G,
    mut push_provable: H,
    prove: P,
    mut prune_tree: PT,
) where
    F: FnOnce(&Parameters<Config>) -> T,
    G: FnMut(&mut T, &Parameters<Config>, &Leaf<Config>) -> bool,
    H: FnMut(&mut T, &Parameters<Config>, &Leaf<Config>) -> bool,
    P: Fn(&T, &Parameters<Config>, &Leaf<Config>) -> Option<MembershipProof<Parameters<Config>>>,
    PT: FnMut(&mut T),
{
    let mut rng = OsRng;
    let parameters = Parameters::<Config>::sample(Default::default(), &mut rng);
    let number_of_insertions = rng.gen_range((1 << (HEIGHT - 2))..(1 << (HEIGHT - 1)));
    let mut tree = f(&parameters);
    let insertions = (0..number_of_insertions)
        .map(|i| (i.to_string(), Provability::gen(&mut rng)))
        .collect::<Vec<_>>();
    for (insertion, provability) in insertions.iter() {
        match provability {
            Provability::NonProvable => {
                push(&mut tree, &parameters, insertion);
            }
            _ => {
                push_provable(&mut tree, &parameters, insertion);
            }
        }
    }
    prune_tree(&mut tree);
    for insertion in insertions
        .iter()
        .filter(|(_, provability)| matches!(provability, Provability::Provable))
        .map(|(insertion, _)| insertion)
    {
        let proof = prove(&tree, &parameters, insertion).expect("Failed to generate proof");
        assert!(
            proof.verify(&parameters, insertion, &mut ()),
            "Proof must be valid"
        );
    }
}

/// Runs [`test_pruning_safety`] on a [`PartialMerkleTree`].
#[test]
fn test_pruning_safety_partial() {
    test_pruning_safety(
        |parameters| PartialMerkleTree::<Config>::new(*parameters),
        |tree, _, leaf| tree.insert_nonprovable(leaf),
        |tree, _, leaf| tree.insert(leaf),
        |tree, _, leaf| tree.prove(leaf),
        |tree| tree.prune(),
    )
}

/// Runs [`test_pruning_safety`] on a [`ForkedTree`].
#[test]
fn test_pruning_safety_forked() {
    test_pruning_safety(
        |parameters| {
            ForkedTree::<Config, Partial<Config>>::new(Partial::new(parameters), parameters)
        },
        |tree, parameters, leaf| Tree::push(tree, parameters, leaf),
        |tree, parameters, leaf| tree.push_provable(parameters, leaf),
        |tree, parameters, leaf| {
            Some(MembershipProof::new(
                tree.path(parameters, tree.position(&parameters.digest(leaf))?)
                    .ok()?,
                tree.root().clone(),
            ))
        },
        |tree| tree.prune(),
    )
}
