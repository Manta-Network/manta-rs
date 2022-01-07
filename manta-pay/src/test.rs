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

//! Manta Pay Testing

use crate::config::{self, FullParameters, Mint, PrivateTransfer, Reclaim};
use manta_crypto::{
    constraint::{measure::Measure, ProofSystem},
    merkle_tree,
    rand::Rand,
};
use rand::thread_rng;

type UtxoSet = merkle_tree::full::FullMerkleTree<config::MerkleTreeConfiguration>;

/// Tests the generation of proving/verifying contexts for [`Mint`].
#[test]
fn sample_mint_context() {
    let mut rng = thread_rng();
    let cs = Mint::unknown_constraints(FullParameters::new(&rng.gen(), &rng.gen()));
    println!("Mint: {:?}", cs.measure());
    config::ProofSystem::generate_context(cs, &mut rng).unwrap();
}

/// Tests the generation of proving/verifying contexts for [`PrivateTransfer`].
#[test]
fn sample_private_transfer_context() {
    let mut rng = thread_rng();
    let cs = PrivateTransfer::unknown_constraints(FullParameters::new(&rng.gen(), &rng.gen()));
    println!("PrivateTransfer: {:?}", cs.measure());
    config::ProofSystem::generate_context(cs, &mut rng).unwrap();
}

/// Tests the generation of proving/verifying contexts for [`Reclaim`].
#[test]
fn sample_reclaim_context() {
    let mut rng = thread_rng();
    let cs = Reclaim::unknown_constraints(FullParameters::new(&rng.gen(), &rng.gen()));
    println!("Reclaim: {:?}", cs.measure());
    config::ProofSystem::generate_context(cs, &mut rng).unwrap();
}

/// Tests the generation of a [`Mint`].
#[test]
fn mint() {
    let mut rng = thread_rng();
    let result = Mint::sample_and_check_proof(&rng.gen(), &mut UtxoSet::new(rng.gen()), &mut rng);
    println!("Mint: {:?}", result);
    assert!(matches!(result, Ok(true)));
}

/// Tests the generation of a [`PrivateTransfer`].
#[test]
fn private_transfer() {
    let mut rng = thread_rng();
    let result =
        PrivateTransfer::sample_and_check_proof(&rng.gen(), &mut UtxoSet::new(rng.gen()), &mut rng);
    println!("PrivateTransfer: {:?}", result);
    assert!(matches!(result, Ok(true)));
}

/// Tests the generation of a [`Reclaim`].
#[test]
fn reclaim() {
    let mut rng = thread_rng();
    let result =
        Reclaim::sample_and_check_proof(&rng.gen(), &mut UtxoSet::new(rng.gen()), &mut rng);
    println!("Reclaim: {:?}", result);
    assert!(matches!(result, Ok(true)));
}
