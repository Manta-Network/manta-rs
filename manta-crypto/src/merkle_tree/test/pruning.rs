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
    accumulator::{Accumulator, OptimizedAccumulator},
    merkle_tree::{partial::PartialMerkleTree, test::Test, tree::Parameters},
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
#[test]
fn test_batch_pruning() {
    let mut rng = OsRng;
    let parameters = Parameters::<Config>::sample(Default::default(), &mut rng);
    let number_of_insertions = rng.gen_range((1 << (HEIGHT - 2))..(1 << (HEIGHT - 1)));
    let mut tree = PartialMerkleTree::<Config>::new(parameters);
    let insertions = (0..number_of_insertions)
        .map(|i| (i.to_string(), Provability::gen(&mut rng)))
        .collect::<Vec<_>>();
    for (insertion, provability) in insertions.iter() {
        match provability {
            Provability::NonProvable => {
                tree.insert_nonprovable(insertion);
            }
            _ => {
                tree.insert(insertion);
            }
        }
    }
    tree.prune();
    for insertion in insertions
        .iter()
        .filter(|(_, provability)| matches!(provability, Provability::Provable))
        .map(|(insertion, _)| insertion)
    {
        let proof = tree.prove(insertion).expect("Failed to generate proof");
        assert!(
            proof.verify(&parameters, insertion, &mut ()),
            "Proof must be valid"
        );
    }
}
