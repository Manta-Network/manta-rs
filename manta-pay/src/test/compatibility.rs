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

//! Manta Pay UTXO Binary Compatibility
//!
//! Checks if the current circuit implementation is compatible with precomputed parameters.

use crate::{
    parameters::load_parameters,
    signer::base::UtxoAccumulator,
    test::payment::{
        private_transfer::prove as prove_private_transfer, to_private::prove as prove_to_private,
        to_public::prove as prove_to_public,
    },
};
use manta_crypto::rand::{OsRng, Rand};

/// Tests that the circuit is compatible with the current known parameters in `manta-parameters`.
#[test]
fn compatibility() {
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    let mut rng = OsRng;
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("Failed to load parameters");
    let _ = &prove_to_private(
        &proving_context.to_private,
        &parameters,
        &utxo_accumulator_model,
        &mut rng,
    )
    .assert_valid_proof(&verifying_context.to_private);
    let mut utxo_accumulator = UtxoAccumulator::new(utxo_accumulator_model);
    let _ = &prove_private_transfer(
        &proving_context.private_transfer,
        &parameters,
        &mut utxo_accumulator,
        &mut rng,
    )
    .assert_valid_proof(&verifying_context.private_transfer);
    let _ = &prove_to_public(
        &proving_context.to_public,
        &parameters,
        &mut utxo_accumulator,
        rng.gen(),
        &mut rng,
    )
    .assert_valid_proof(&verifying_context.to_public);
}
