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

//! Signer Testing Suite

use crate::{
    config::Config, parameters::load_parameters, simulation::sample_signer,
    test::payment::UtxoAccumulator,
};
use manta_accounting::transfer::{identity_verification, IdentifiedAsset, Identifier};
use manta_crypto::rand::{OsRng, Rand, fuzz::Fuzz};
use manta_crypto::arkworks::constraint::fp::Fp;

/// Checks the generation and verification of [`IdentityProof`](manta_accounting::transfer::IdentityProof)s.
#[test]
fn identity_proof_test() {
    let mut rng = OsRng;
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("Failed to load parameters");
    let mut signer = sample_signer(
        &proving_context,
        &parameters,
        &utxo_accumulator_model,
        &mut rng,
    );
    let identifier = Identifier::<Config>::new(false, rng.gen());
    let virtual_asset = IdentifiedAsset::<Config>::new(identifier, rng.gen());
    let identity_proof = signer
        .identity_proof(virtual_asset)
        .expect("Error producing identity proof");
    let address = signer.address();
    let verification = identity_verification(
        &parameters,
        &verifying_context.to_public,
        &mut UtxoAccumulator::new(utxo_accumulator_model.clone()),
        identity_proof.clone(),
        virtual_asset,
        address,
    );
    assert!(verification.is_ok(), "Verification failed");
    let new_identifier = Identifier::<Config>::new(true, identifier.utxo_commitment_randomness);
    let new_virtual_asset = IdentifiedAsset::<Config>::new(new_identifier, virtual_asset.asset);
    let verification_2 = identity_verification(
        &parameters,
        &verifying_context.to_public,
        &mut UtxoAccumulator::new(utxo_accumulator_model.clone()),
        identity_proof.clone(),
        new_virtual_asset,
        address,
    );
    assert!(verification_2.is_err(), "Verification should have failed");
    let fuzzed_salt = Fp(identifier.utxo_commitment_randomness.0.fuzz(&mut rng));
    let new_virtual_asset = IdentifiedAsset::<Config>::new(Identifier::<Config>::new(false, fuzzed_salt), virtual_asset.asset);
    let verification_3 = identity_verification(
        &parameters,
        &verifying_context.to_public,
        &mut UtxoAccumulator::new(utxo_accumulator_model),
        identity_proof,
        new_virtual_asset,
        address,
    );
    assert!(verification_3.is_err(), "Verification should have failed");
}
