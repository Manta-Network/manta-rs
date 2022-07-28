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

//! Groth16 Trusted Setup Testing

use crate::{
    groth16::{
        kzg::{self, Accumulator, Configuration, Contribution, Size},
        mpc::{self, contribute, initialize, verify_transform, verify_transform_all, Proof, State},
    },
    mpc::{Transcript, Types},
    pairing::Pairing,
    ratio::RatioProof,
    util::{
        into_array_unchecked, AffineCurve, BlakeHasher, HasDistribution, KZGBlakeHasher,
        PairingEngine, Sample,
    },
};
use alloc::vec::Vec;
use ark_bls12_381::{Fr, FrParameters};
use ark_ff::{field_new, Fp256, UniformRand};
use ark_groth16::{Groth16, ProvingKey};
use ark_r1cs_std::eq::EqGadget;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use blake2::Digest;
use manta_crypto::{
    constraint::Allocate,
    eclair::alloc::mode::{Public, Secret},
    rand::{CryptoRng, OsRng, RngCore},
};
use manta_pay::crypto::constraint::arkworks::{Fp, FpVar, R1CS};

/// Test MPC
#[derive(Clone, Default)]
pub struct Test;

impl Size for Test {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
    const G2_POWERS: usize = 1 << 3;
}

impl HasDistribution for Test {
    type Distribution = ();
}

impl Pairing for Test {
    type Scalar = ark_bls12_381::Fr;
    type G1 = ark_bls12_381::G1Affine;
    type G1Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Prepared;
    type G2 = ark_bls12_381::G2Affine;
    type G2Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Prepared;
    type Pairing = ark_bls12_381::Bls12_381;

    fn g1_prime_subgroup_generator() -> Self::G1 {
        ark_bls12_381::G1Affine::prime_subgroup_generator()
    }

    fn g2_prime_subgroup_generator() -> Self::G2 {
        ark_bls12_381::G2Affine::prime_subgroup_generator()
    }
}

impl kzg::Configuration for Test {
    type DomainTag = u8;
    type Challenge = [u8; 64];
    type Response = [u8; 64];
    type HashToGroup = KZGBlakeHasher<Self>;

    const TAU_DOMAIN_TAG: Self::DomainTag = 0;
    const ALPHA_DOMAIN_TAG: Self::DomainTag = 1;
    const BETA_DOMAIN_TAG: Self::DomainTag = 2;

    fn response(
        state: &Accumulator<Self>,
        challenge: &Self::Challenge,
        proof: &crate::groth16::kzg::Proof<Self>,
    ) -> Self::Response {
        let mut hasher = BlakeHasher::default();
        for item in &state.tau_powers_g1 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        for item in &state.tau_powers_g2 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        for item in &state.alpha_tau_powers_g1 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        for item in &state.beta_tau_powers_g1 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        state.beta_g2.serialize_uncompressed(&mut hasher).unwrap();
        hasher.0.update(&challenge);
        proof
            .tau
            .ratio
            .0
            .serialize_uncompressed(&mut hasher)
            .unwrap();
        proof
            .tau
            .ratio
            .1
            .serialize_uncompressed(&mut hasher)
            .unwrap();
        proof
            .tau
            .matching_point
            .serialize_uncompressed(&mut hasher)
            .unwrap();

        proof
            .alpha
            .ratio
            .0
            .serialize_uncompressed(&mut hasher)
            .unwrap();
        proof
            .alpha
            .ratio
            .1
            .serialize_uncompressed(&mut hasher)
            .unwrap();
        proof
            .alpha
            .matching_point
            .serialize_uncompressed(&mut hasher)
            .unwrap();
        proof
            .beta
            .ratio
            .0
            .serialize_uncompressed(&mut hasher)
            .unwrap();
        proof
            .beta
            .ratio
            .1
            .serialize_uncompressed(&mut hasher)
            .unwrap();
        proof
            .beta
            .matching_point
            .serialize_uncompressed(&mut hasher)
            .unwrap();
        into_array_unchecked(hasher.0.finalize())
    }

    fn hasher(domain_tag: Self::DomainTag) -> Self::HashToGroup {
        Self::HashToGroup { domain_tag }
    }
}

impl mpc::Configuration for Test {
    type Challenge = [u8; 64];
    type Hasher = BlakeHasher;

    fn challenge(
        challenge: &Self::Challenge,
        prev: &State<Self>,
        next: &State<Self>,
        proof: &Proof<Self>,
    ) -> Self::Challenge {
        let mut hasher = Self::Hasher::new();
        hasher.0.update(challenge);
        prev.serialize(&mut hasher)
            .expect("Consuming the previous state failed.");
        next.serialize(&mut hasher)
            .expect("Consuming the current state failed.");
        proof
            .ratio
            .0
            .serialize(&mut hasher)
            .expect("Consuming proof failed");
        proof
            .ratio
            .1
            .serialize(&mut hasher)
            .expect("Consuming proof failed");
        proof
            .matching_point
            .serialize(&mut hasher)
            .expect("Consuming proof failed");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl<P> mpc::ProvingKeyHasher<P> for Test
where
    P: Pairing,
{
    type Output = [u8; 64];

    #[inline]
    fn hash(proving_key: &ProvingKey<P::Pairing>) -> Self::Output {
        let mut hasher = BlakeHasher::new();
        proving_key
            .serialize(&mut hasher)
            .expect("Hasher is not allowed to fail");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl Types for Test {
    type State = State<Test>;
    type Challenge = [u8; 64];
    type Proof = Proof<Test>;
}

/// Conducts a dummy phase one trusted setup.
pub fn dummy_phase_one_trusted_setup() -> Accumulator<Test> {
    let mut rng = OsRng;
    let accumulator = Accumulator::default();
    let challenge = [0; 64];
    let contribution = Contribution::gen(&mut rng);
    let proof = contribution.proof(&challenge, &mut rng).unwrap();
    let mut next_accumulator = accumulator.clone();
    next_accumulator.update(&contribution);
    Accumulator::verify_transform(accumulator, next_accumulator, challenge, proof).unwrap()
}

/// Generates a dummy R1CS circuit.
pub fn dummy_circuit(cs: &mut R1CS<Fp256<FrParameters>>) {
    let a = Fp(field_new!(Fr, "2")).as_known::<Secret, FpVar<_>>(cs);
    let b = Fp(field_new!(Fr, "3")).as_known::<Secret, FpVar<_>>(cs);
    let c = &a * &b;
    let d = Fp(field_new!(Fr, "6")).as_known::<Public, FpVar<_>>(cs);
    c.enforce_equal(&d)
        .expect("enforce_equal is not allowed to fail");
}

/// Proves and verifies a dummy circuit with proving key `pk` and a random number generator `rng`.
pub fn dummy_prove_and_verify_circuit<P, R>(pk: ProvingKey<P>, mut rng: &mut R)
where
    P: PairingEngine<Fr = Fp256<ark_bls12_381::FrParameters>>,
    R: CryptoRng + RngCore + ?Sized,
{
    let mut cs = R1CS::for_proofs();
    dummy_circuit(&mut cs);
    let proof = Groth16::prove(&pk, cs, &mut rng).unwrap();
    assert!(
        Groth16::verify(&pk.vk, &[field_new!(Fr, "6")], &proof).unwrap(),
        "Verify proof should succeed."
    );
}

/// Tests if proving and verifying ratio proof is correct.
#[test]
pub fn proving_and_verifying_ratio_proof_is_correct() {
    let mut rng = OsRng;
    let delta = <Test as Pairing>::Scalar::rand(&mut rng);
    let proof = RatioProof::prove(
        &<Test as kzg::Configuration>::hasher(Test::TAU_DOMAIN_TAG),
        &[0; 64],
        &delta,
        &mut rng,
    )
    .expect("Proving a ratio proof should be correct.");
    proof
        .verify(
            &<Test as kzg::Configuration>::hasher(Test::TAU_DOMAIN_TAG),
            &[0; 64],
        )
        .expect("Verifying a ratio proof should be correct.");
}

/// Tests if trusted setup phase 2 is valid with trusted setup phase 1 and proves and verifies a
/// dummy circuit.
#[test]
pub fn trusted_setup_phase_two_is_valid() {
    let mut rng = OsRng;
    let mut cs = R1CS::for_contexts();
    dummy_circuit(&mut cs);
    let accumulator = dummy_phase_one_trusted_setup();
    let mut state =
        initialize::<Test, R1CS<Fp256<ark_bls12_381::FrParameters>>>(accumulator, cs).unwrap();
    let mut transcript = Transcript::<Test> {
        initial_challenge: <Test as mpc::ProvingKeyHasher<Test>>::hash(&state),
        initial_state: state.clone(),
        rounds: Vec::new(),
    };
    let hasher = <Test as mpc::Configuration>::Hasher::new();
    let (mut prev_state, mut proof);
    let mut challenge = transcript.initial_challenge;
    for _ in 0..5 {
        prev_state = state.clone();
        proof = contribute::<Test, _>(&hasher, &challenge, &mut state, &mut rng).unwrap();
        (challenge, state) = verify_transform::<Test>(&challenge, prev_state, state, proof.clone())
            .expect("Verify transform failed");
        transcript.rounds.push((state.clone(), proof));
    }
    verify_transform_all(
        transcript.initial_challenge,
        transcript.initial_state,
        transcript.rounds,
    )
    .expect("Verifying all transformations failed.");
    let mut cs = R1CS::for_contexts();
    dummy_circuit(&mut cs);
    dummy_prove_and_verify_circuit(state, &mut rng);
}
