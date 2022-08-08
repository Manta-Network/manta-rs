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
    config::{FullParametersRef, PrivateTransfer, Proof, ProofSystem, ToPrivate, ToPublic},
    test::payment::UtxoAccumulator,
    util::scale::{assert_valid_codec, assert_valid_io_codec},
};
use manta_crypto::{
    accumulator::Accumulator,
    constraint::{measure::Measure, ProofSystem as _},
    rand::{OsRng, Rand},
};
use std::io::Cursor;

/// Tests the generation of proving/verifying contexts for [`ToPrivate`].
#[test]
fn sample_to_private_context() {
    let mut rng = OsRng;
    let cs = ToPrivate::unknown_constraints(FullParametersRef::new(&rng.gen(), &rng.gen()));
    println!("ToPrivate: {:?}", cs.measure());
    ProofSystem::compile(&(), cs, &mut rng).expect("Unable to generate ToPrivate context.");
}

/// Tests the generation of proving/verifying contexts for [`PrivateTransfer`].
#[test]
fn sample_private_transfer_context() {
    let mut rng = OsRng;
    let cs = PrivateTransfer::unknown_constraints(FullParametersRef::new(&rng.gen(), &rng.gen()));
    println!("PrivateTransfer: {:?}", cs.measure());
    ProofSystem::compile(&(), cs, &mut rng).expect("Unable to generate PrivateTransfer context.");
}

/// Tests the generation of proving/verifying contexts for [`ToPublic`].
#[test]
fn sample_to_public_context() {
    let mut rng = OsRng;
    let cs = ToPublic::unknown_constraints(FullParametersRef::new(&rng.gen(), &rng.gen()));
    println!("ToPublic: {:?}", cs.measure());
    ProofSystem::compile(&(), cs, &mut rng).expect("Unable to generate ToPublic context.");
}

/// Tests the generation of a [`ToPrivate`].
#[test]
fn to_private() {
    let mut rng = OsRng;
    assert!(
        ToPrivate::sample_and_check_proof(
            &(),
            &rng.gen(),
            &mut UtxoAccumulator::new(rng.gen()),
            None,
            &mut rng
        )
        .expect("Random ToPrivate should have successfully produced a proof."),
        "The ToPrivate proof should have been valid."
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
            Some(&rng.gen()),
            &mut rng
        )
        .expect("Random PrivateTransfer should have successfully produced a proof."),
        "The PrivateTransfer proof should have been valid."
    );
}

/// Tests the generation of a [`ToPublic`].
#[test]
fn to_public() {
    let mut rng = OsRng;
    assert!(
        ToPublic::sample_and_check_proof(
            &(),
            &rng.gen(),
            &mut UtxoAccumulator::new(rng.gen()),
            Some(&rng.gen()),
            &mut rng
        )
        .expect("Random ToPublic should have successfully produced a proof."),
        "The ToPublic proof should have been valid."
    );
}

/* IGNORE:

/// Tests that `generate_proof_input` from [`Transfer`] and [`TransferPost`] gives the same
/// [`ProofInput`] for [`ToPrivate`].
#[test]
fn to_private_generate_proof_input_is_compatibile() {
    let mut rng = OsRng;
    assert!(
        matches!(
            ToPrivate::sample_and_check_generate_proof_input_compatibility(
                &(),
                &rng.gen(),
                &mut UtxoAccumulator::new(rng.gen()),
                None,
                &mut rng
            ),
            Ok(true),
        ),
        "For a random ToPrivate, `generate_proof_input` from `Transfer` and `TransferPost` should have given the same `ProofInput`."
    );
}

/// Tests that `generate_proof_input` from [`Transfer`] and [`TransferPost`] gives the same
/// [`ProofInput`] for [`PrivateTransfer`].
#[test]
fn private_transfer_generate_proof_input_is_compatibile() {
    let mut rng = OsRng;
    assert!(
        matches!(
            PrivateTransfer::sample_and_check_generate_proof_input_compatibility(
                &(),
                &rng.gen(),
                &mut UtxoAccumulator::new(rng.gen()),
                Some(&rng.gen()),
                &mut rng
            ),
            Ok(true),
        ),
        "For a random PrivateTransfer, `generate_proof_input` from `Transfer` and `TransferPost` should have given the same `ProofInput`."
    );
}

/// Tests that `generate_proof_input` from [`Transfer`] and [`TransferPost`] gives the same
/// [`ProofInput`] for [`ToPublic`].
#[test]
fn to_public_generate_proof_input_is_compatibile() {
    let mut rng = OsRng;
    assert!(
        matches!(
            ToPublic::sample_and_check_generate_proof_input_compatibility(
                &(),
                &rng.gen(),
                &mut UtxoAccumulator::new(rng.gen()),
                Some(&rng.gen()),
                &mut rng
            ),
            Ok(true),
        ),
        "For a random ToPublic, `generate_proof_input` from `Transfer` and `TransferPost` should have given the same `ProofInput`."
    );
}

*/

/* TODO:

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

/// Tests the SCALE encoding and decoding of a [`ToPrivate`] proof.
#[test]
fn to_private_proof_scale_codec() {
    let mut rng = OsRng;
    let parameters = rng.gen();
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let (proving_context, verifying_context) = ToPrivate::generate_context(
        &(),
        FullParametersRef::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let post = ToPrivate::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        None,
        &mut rng,
    )
    .expect("Random ToPrivate should have produced a proof.")
    .expect("Correct shape should have been used.");
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
        FullParametersRef::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let post = PrivateTransfer::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        Some(&rng.gen()),
        &mut rng,
    )
    .expect("Random PrivateTransfer should have produced a proof.")
    .expect("Correct shape should have been used.");
    assert_valid_proof_codec(post.assert_valid_proof(&verifying_context));
}

/// Tests the SCALE encoding and decoding of a [`ToPublic`] proof.
#[test]
fn to_public_proof_scale_codec() {
    let mut rng = OsRng;
    let parameters = rng.gen();
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let (proving_context, verifying_context) = ToPublic::generate_context(
        &(),
        FullParametersRef::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let post = ToPublic::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        Some(&rng.gen()),
        &mut rng,
    )
    .expect("Random ToPublic should have produced a proof.")
    .expect("Correct shape should have been used.");
    assert_valid_proof_codec(post.assert_valid_proof(&verifying_context));
}

*/
