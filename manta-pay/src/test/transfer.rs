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
    config::{FullParametersRef, Parameters, PrivateTransfer, ProofSystem, ToPrivate, ToPublic},
    test::payment::UtxoAccumulator,
};
use manta_crypto::{
    accumulator::Accumulator,
    constraint::{measure::Measure, ProofSystem as _},
    rand::{OsRng, Rand},
};

/// Tests the generation of proving/verifying contexts for [`ToPrivate`].
#[test]
fn sample_to_private_context() {
    let mut rng = OsRng;
    let cs = ToPrivate::unknown_constraints(FullParametersRef::new(
        &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>(),
        &rng.gen(),
    ));
    println!("ToPrivate: {:?}", cs.measure());
    ProofSystem::compile(&(), cs, &mut rng).expect("Unable to generate ToPrivate context.");
}

/// Tests the generation of proving/verifying contexts for [`PrivateTransfer`].
#[test]
fn sample_private_transfer_context() {
    let mut rng = OsRng;
    let cs = PrivateTransfer::unknown_constraints(FullParametersRef::new(
        &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>(),
        &rng.gen(),
    ));
    println!("PrivateTransfer: {:?}", cs.measure());
    ProofSystem::compile(&(), cs, &mut rng).expect("Unable to generate PrivateTransfer context.");
}

/// Tests the generation of proving/verifying contexts for [`ToPublic`].
#[test]
fn sample_to_public_context() {
    let mut rng = OsRng;
    let cs = ToPublic::unknown_constraints(FullParametersRef::new(
        &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>(),
        &rng.gen(),
    ));
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
            &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>(),
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
            &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>(),
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
            &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>(),
            &mut UtxoAccumulator::new(rng.gen()),
            Some(&rng.gen()),
            &mut rng
        )
        .expect("Random ToPublic should have successfully produced a proof."),
        "The ToPublic proof should have been valid."
    );
}

/// Checks that an empty message will produce a valid signature.
#[test]
fn check_empty_message_signature() {
    let mut rng = OsRng;
    assert!(
        manta_crypto::signature::test::correctness(
            &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), Parameters>()
                .signature_scheme(),
            &rng.gen(),
            &rng.gen(),
            &vec![],
            &mut (),
        ),
        "Unable to verify signature correctly."
    );
}

/// Checks that a random [`PrivateTransfer`] produces a valid transaction signature.
#[test]
fn private_transfer_check_signature() {
    let mut rng = OsRng;
    let parameters = rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>();
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let (proving_context, verifying_context) = PrivateTransfer::generate_context(
        &(),
        FullParametersRef::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let spending_key = rng.gen();
    let post = PrivateTransfer::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        Some(&spending_key),
        &mut rng,
    )
    .expect("Random Private Transfer should have produced a proof.")
    .expect("");
    post.assert_valid_proof(&verifying_context);
    manta_accounting::transfer::utxo::auth::test::signature_correctness(
        &parameters,
        &spending_key,
        &post.body,
        &mut rng,
    );
}

/// Checks that a random [`ToPublic`] produces a valid transaction signature.
#[test]
fn to_public_check_signature() {
    let mut rng = OsRng;
    let parameters = rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>();
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let (proving_context, verifying_context) = ToPublic::generate_context(
        &(),
        FullParametersRef::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let spending_key = rng.gen();
    let post = ToPublic::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        Some(&spending_key),
        &mut rng,
    )
    .expect("Random To-Public should have produced a proof.")
    .expect("");
    post.assert_valid_proof(&verifying_context);
    manta_accounting::transfer::utxo::auth::test::signature_correctness(
        &parameters,
        &spending_key,
        &post.body,
        &mut rng,
    );
}

/// Tests that `generate_proof_input` from [`Transfer`] and [`TransferPost`] gives the same
/// [`ProofInput`] for [`ToPrivate`].
#[test]
fn to_private_generate_proof_input_is_compatibile() {
    let mut rng = OsRng;
    assert!(
        matches!(
            ToPrivate::sample_and_check_generate_proof_input_compatibility(
                &(),
                &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>(),
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
                &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>(),
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
                &rng.gen::<(((), (), ((), ()), (), (), (), (), ()), (), ()), _>(),
                &mut UtxoAccumulator::new(rng.gen()),
                Some(&rng.gen()),
                &mut rng
            ),
            Ok(true),
        ),
        "For a random ToPublic, `generate_proof_input` from `Transfer` and `TransferPost` should have given the same `ProofInput`."
    );
}

/* TODO: fix the fuzzing test bug, then uncomment.
/// Checks that a [`TransferPost`] is valid, and that its proof cannot be verified when tested against a fuzzed
/// or randomized `public_input`.
#[inline]
fn validity_check_with_fuzzing<C, R, A, M>(
    verifying_context: &VerifyingContext<C>,
    post: &TransferPost<C>,
    rng: &mut R,
) where
    A: Clone + Sample + Fuzz<M>,
    C: Configuration,
    C::ProofSystem: constraint::ProofSystem<Input = Vec<A>>,
    ProofSystemError<C>: Debug,
    R: RngCore + ?Sized,
    TransferPost<C>: Debug,
{
    let public_input = post.generate_proof_input();
    let proof = &post.validity_proof;
    assert_valid_proof(verifying_context, post);
    verify_fuzz_public_input::<C::ProofSystem, _>(
        verifying_context,
        &public_input,
        proof,
        |input| input.fuzz(rng),
    );
    verify_fuzz_public_input::<C::ProofSystem, _>(
        verifying_context,
        &public_input,
        proof,
        |input| (0..input.len()).map(|_| rng.gen()).collect(),
    );
}
/// Tests a [`ToPrivate`] proof is valid verified against the right public input and invalid
/// when the public input has been fuzzed or randomly generated.
#[test]
fn to_private_proof_validity() {
    let mut rng = OsRng;
    let parameters = rng.gen();
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let (proving_context, verifying_context) = ToPrivate::generate_context(
        &(),
        FullParameters::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let post = ToPrivate::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        &mut rng,
    )
    .expect("Random ToPrivate should have produced a proof.");
    validity_check_with_fuzzing(&verifying_context, &post, &mut rng);
}
/// Tests a [`PrivateTransfer`] proof is valid verified against the right public input and invalid
/// when the public input has been fuzzed or randomly generated.
#[test]
fn private_transfer_proof_validity() {
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
    .expect("Random Private Transfer should have produced a proof.");
    validity_check_with_fuzzing(&verifying_context, &post, &mut rng);
}
/// Tests a [`ToPublic`] proof is valid verified against the right public input and invalid
/// when the public input has been fuzzed or randomly generated.
#[test]
fn to_public_proof_validity() {
    let mut rng = OsRng;
    let parameters = rng.gen();
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let (proving_context, verifying_context) = ToPublic::generate_context(
        &(),
        FullParameters::new(&parameters, utxo_accumulator.model()),
        &mut rng,
    )
    .expect("Unable to create proving and verifying contexts.");
    let post = ToPublic::sample_post(
        &proving_context,
        &parameters,
        &mut utxo_accumulator,
        &mut rng,
    )
    .expect("Random ToPublic should have produced a proof.");
    validity_check_with_fuzzing(&verifying_context, &post, &mut rng);
}
*/
