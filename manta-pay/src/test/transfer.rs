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

//! Manta Pay Transfer Testing

use crate::{
    config::{FullParameters, Mint, PrivateTransfer, Proof, ProofSystem, Reclaim},
    test::payment::UtxoAccumulator,
    util::scale::{assert_valid_codec, assert_valid_io_codec},
};
use manta_crypto::{
    accumulator::Accumulator,
    constraint::{measure::Measure, ProofSystem as _},
    rand::{OsRng, Rand},
};
use std::io::Cursor;

/// Tests the generation of proving/verifying contexts for [`Mint`].
#[test]
fn sample_mint_context() {
    let mut rng = OsRng;
    let cs = Mint::unknown_constraints(FullParameters::new(&rng.gen(), &rng.gen()));
    println!("Mint: {:?}", cs.measure());
    ProofSystem::compile(&(), cs, &mut rng).expect("Unable to generate Mint context.");
}

/// Tests the generation of proving/verifying contexts for [`PrivateTransfer`].
#[test]
fn sample_private_transfer_context() {
    let mut rng = OsRng;
    let cs = PrivateTransfer::unknown_constraints(FullParameters::new(&rng.gen(), &rng.gen()));
    println!("PrivateTransfer: {:?}", cs.measure());
    ProofSystem::compile(&(), cs, &mut rng).expect("Unable to generate PrivateTransfer context.");
}

/// Tests the generation of proving/verifying contexts for [`Reclaim`].
#[test]
fn sample_reclaim_context() {
    let mut rng = OsRng;
    let cs = Reclaim::unknown_constraints(FullParameters::new(&rng.gen(), &rng.gen()));
    println!("Reclaim: {:?}", cs.measure());
    ProofSystem::compile(&(), cs, &mut rng).expect("Unable to generate Reclaim context.");
}

/// Tests the generation of a [`Mint`].
#[test]
fn mint() {
    let mut rng = OsRng;
    assert!(
        Mint::sample_and_check_proof(
            &(),
            &rng.gen(),
            &mut UtxoAccumulator::new(rng.gen()),
            &mut rng
        )
        .expect("Random Mint should have successfully produced a proof."),
        "The Mint proof should have been valid."
    );
}

/// Tests the generation of a [`PrivateTransfer`].
#[test]
fn private_transfer() {
    let mut rng = OsRng;
    assert!(
        PrivateTransfer::sample_and_check_proof(
            &(),
            &rng.gen(),
            &mut UtxoAccumulator::new(rng.gen()),
            &mut rng
        )
        .expect("Random PrivateTransfer should have successfully produced a proof."),
        "The PrivateTransfer proof should have been valid."
    );
}

/// Tests the generation of a [`Reclaim`].
#[test]
fn reclaim() {
    let mut rng = OsRng;
    assert!(
        Reclaim::sample_and_check_proof(
            &(),
            &rng.gen(),
            &mut UtxoAccumulator::new(rng.gen()),
            &mut rng
        )
        .expect("Random Reclaim should have successfully produced a proof."),
        "The Reclaim proof should have been valid."
    );
}

/// Tests that `generate_proof_input` from [`Transfer`] and [`TransferPost`] gives the same [`ProofInput`].
#[test]
fn generate_proof_input_is_compatibile() {
    let mut rng = OsRng;
    assert!(
        Mint::sample_and_check_generate_proof_input_compatibility(
            &(),
            &rng.gen(),
            &mut UtxoAccumulator::new(rng.gen()),
            &mut rng
        )
        .expect("For a random Mint, `generate_proof_input` from `Transfer` and `ProofInput` should give the same `ProofInput`."),
        "For a random Mint, `generate_proof_input` from `Transfer` and `TransferPost` should have given the same `ProofInput`."
    );
    assert!(
        PrivateTransfer::sample_and_check_generate_proof_input_compatibility(
            &(),
            &rng.gen(),
            &mut UtxoAccumulator::new(rng.gen()),
            &mut rng
        )
        .expect("For a random PrivateTransfer, `generate_proof_input` from `Transfer` and `ProofInput` should give the same `ProofInput`."),
        "For a random PrivateTransfer, `generate_proof_input` from `Transfer` and `TransferPost` should have given the same `ProofInput`."
    );
    assert!(
        Reclaim::sample_and_check_generate_proof_input_compatibility(
            &(),
            &rng.gen(),
            &mut UtxoAccumulator::new(rng.gen()),
            &mut rng
        )
        .expect("For a random Reclaim, `generate_proof_input` from `Transfer` and `ProofInput` should give the same `ProofInput`."),
        "For a random Reclaim, `generate_proof_input` from `Transfer` and `TransferPost` should have given the same `ProofInput`."
    );
}

/// Asserts that `proof` can be SCALE encoded and decoded with at least [`Vec`], [`Cursor`], and
/// [`File`](std::fs::File).
#[inline]
fn assert_valid_proof_codec(proof: &Proof) {
    assert_valid_codec(proof, &mut Vec::new(), move |v| v.as_slice());
    assert_valid_io_codec(proof, &mut Cursor::new(vec![0; 8192]));
    assert_valid_io_codec(
        proof,
        &mut tempfile::tempfile().expect("Unable to construct temporary file."),
    );
}

/// Tests the SCALE encoding and decoding of a [`Mint`] proof.
#[test]
fn mint_proof_scale_codec() {
    let mut rng = OsRng;
    let parameters = rng.gen();
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let (proving_context, verifying_context) = Mint::generate_context(
        &(),
        FullParameters::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let post = Mint::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        &mut rng,
    )
    .expect("Random Mint should have produced a proof.");
    assert_valid_proof_codec(post.assert_valid_proof(&verifying_context));
}

/// Tests the SCALE encoding and decoding of a [`PrivateTransfer`] proof.
#[test]
fn private_transfer_proof_scale_codec() {
    let mut rng = OsRng;
    let parameters = rng.gen();
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let (proving_context, verifying_context) = PrivateTransfer::generate_context(
        &(),
        FullParameters::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let post = PrivateTransfer::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        &mut rng,
    )
    .expect("Random PrivateTransfer should have produced a proof.");
    assert_valid_proof_codec(post.assert_valid_proof(&verifying_context));
}

/// Tests the SCALE encoding and decoding of a [`Mint`] proof.
#[test]
fn reclaim_proof_scale_codec() {
    let mut rng = OsRng;
    let parameters = rng.gen();
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let (proving_context, verifying_context) = Reclaim::generate_context(
        &(),
        FullParameters::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let post = Reclaim::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        &mut rng,
    )
    .expect("Random Reclaim should have produced a proof.");
    assert_valid_proof_codec(post.assert_valid_proof(&verifying_context));
}
