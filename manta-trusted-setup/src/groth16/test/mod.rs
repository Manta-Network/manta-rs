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
    mpc::{ChallengeType, ContributionType, ProofType, StateType, Transcript},
    util::{BlakeHasher, HasDistribution, KZGBlakeHasher},
};
use alloc::vec::Vec;
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use blake2::Digest;
use manta_crypto::{
    arkworks::{
        bn254::{Bn254, Fr, G1Affine, G2Affine},
        ec::{AffineCurve, PairingEngine},
        ff::{field_new, UniformRand},
        pairing::Pairing,
        r1cs_std::eq::EqGadget,
        ratio::test::assert_valid_ratio_proof,
        serialize::CanonicalSerialize,
    },
    eclair::alloc::{
        mode::{Public, Secret},
        Allocate,
    },
    rand::{CryptoRng, OsRng, RngCore, Sample},
};
use manta_pay::crypto::constraint::arkworks::{Fp, FpVar, R1CS};
use manta_util::into_array_unchecked;

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
    type Scalar = Fr;
    type G1 = G1Affine;
    type G1Prepared = <Self::Pairing as PairingEngine>::G1Prepared;
    type G2 = G2Affine;
    type G2Prepared = <Self::Pairing as PairingEngine>::G2Prepared;
    type Pairing = Bn254;

    #[inline]
    fn g1_prime_subgroup_generator() -> Self::G1 {
        G1Affine::prime_subgroup_generator()
    }

    #[inline]
    fn g2_prime_subgroup_generator() -> Self::G2 {
        G2Affine::prime_subgroup_generator()
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

    #[inline]
    fn hasher(domain_tag: Self::DomainTag) -> Self::HashToGroup {
        Self::HashToGroup { domain_tag }
    }

    #[inline]
    fn response(
        state: &Accumulator<Self>,
        challenge: &Self::Challenge,
        proof: &kzg::Proof<Self>,
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
        hasher.0.update(challenge);
        proof
            .tau
            .serialize(&mut hasher)
            .expect("Consuming ratio proof of tau failed.");
        proof
            .alpha
            .serialize(&mut hasher)
            .expect("Consuming ratio proof of alpha failed.");
        proof
            .beta
            .serialize(&mut hasher)
            .expect("Consuming ratio proof of beta failed.");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl mpc::Configuration for Test {
    type Hasher = BlakeHasher;

    #[inline]
    fn challenge(
        challenge: &Self::Challenge,
        prev: &State<Self>,
        next: &State<Self>,
        proof: &Proof<Self>,
    ) -> Self::Challenge {
        let mut hasher = Self::Hasher::default();
        hasher.0.update(challenge);
        prev.0
            .serialize(&mut hasher)
            .expect("Consuming the previous state failed.");
        next.0
            .serialize(&mut hasher)
            .expect("Consuming the current state failed.");
        proof
            .0
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
        let mut hasher = BlakeHasher::default();
        proving_key
            .serialize(&mut hasher)
            .expect("Hasher is not allowed to fail");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl ChallengeType for Test {
    type Challenge = [u8; 64];
}

impl ContributionType for Test {
    type Contribution = Contribution<Self>;
}

impl ProofType for Test {
    type Proof = Proof<Self>;
}

impl StateType for Test {
    type State = State<Self>;
}

/// Conducts a dummy phase one trusted setup.
#[inline]
pub fn dummy_phase_one_trusted_setup() -> Accumulator<Test> {
    let mut rng = OsRng;
    let accumulator = Accumulator::default();
    let challenge = [0; 64];
    let contribution = Contribution::gen(&mut rng);
    let proof = contribution
        .proof(&challenge, &mut rng)
        .expect("The contribution proof should have been generated correctly.");
    let mut next_accumulator = accumulator.clone();
    next_accumulator.update(&contribution);
    Accumulator::verify_transform(accumulator, next_accumulator, challenge, proof)
        .expect("Accumulator should have been generated correctly.")
}

/// Generates a dummy R1CS circuit.
#[inline]
pub fn dummy_circuit(cs: &mut R1CS<Fr>) {
    let a = Fp(field_new!(Fr, "2")).as_known::<Secret, FpVar<_>>(cs);
    let b = Fp(field_new!(Fr, "3")).as_known::<Secret, FpVar<_>>(cs);
    let c = &a * &b;
    let d = Fp(field_new!(Fr, "6")).as_known::<Public, FpVar<_>>(cs);
    c.enforce_equal(&d)
        .expect("enforce_equal is not allowed to fail");
}

/// Generates a dummy ProverKey
#[inline]
pub fn dummy_prover_key() -> ProvingKey<Bn254> {
    let mut cs = R1CS::for_contexts();
    dummy_circuit(&mut cs);
    initialize(dummy_phase_one_trusted_setup(), cs).unwrap().0
}

/// Proves and verifies a R1CS circuit with proving key `pk` and a random number generator `rng`.
#[inline]
pub fn prove_and_verify_circuit<P, R>(pk: ProvingKey<P>, cs: R1CS<Fr>, mut rng: &mut R)
where
    P: PairingEngine<Fr = Fr>,
    R: CryptoRng + RngCore + ?Sized,
{
    assert!(
        Groth16::verify(
            &pk.vk,
            &[field_new!(Fr, "6")],
            &Groth16::prove(&pk, cs, &mut rng).unwrap()
        )
        .unwrap(),
        "Verify proof should succeed."
    );
}

/// Tests if proving and verifying ratio proof is correct.
#[test]
fn proving_and_verifying_ratio_proof_is_correct() {
    assert_valid_ratio_proof(
        &Test::hasher(Test::TAU_DOMAIN_TAG),
        &[0; 64],
        &<Test as Pairing>::Scalar::rand(&mut OsRng),
        &mut OsRng,
    );
}

/// Tests if trusted setup phase 2 is valid with trusted setup phase 1 and proves and verifies a
/// dummy circuit.
#[test]
fn trusted_setup_phase_two_is_valid() {
    let mut rng = OsRng;
    let mut state = State(dummy_prover_key());
    let mut transcript = Transcript::<Test> {
        initial_challenge: <Test as mpc::ProvingKeyHasher<Test>>::hash(&state.0),
        initial_state: state.clone(),
        rounds: Vec::new(),
    };
    let hasher = <Test as mpc::Configuration>::Hasher::default();
    let (mut prev_state, mut proof);
    let mut challenge = transcript.initial_challenge;
    for _ in 0..5 {
        prev_state = state.clone();
        proof = contribute(&hasher, &challenge, &mut state, &mut rng).unwrap();
        (challenge, state) = verify_transform(&challenge, &prev_state, state, proof.clone())
            .expect("Verify transform failed");
        transcript.rounds.push((state.clone(), proof));
    }
    verify_transform_all(
        transcript.initial_challenge,
        transcript.initial_state,
        transcript.rounds,
    )
    .expect("Verifying all transformations failed.");
    let mut cs = R1CS::for_proofs();
    dummy_circuit(&mut cs);
    prove_and_verify_circuit(state.0, cs, &mut rng);
}
