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

//! Trusted Setup Configuration

use crate::{
    config::{FullParameters, Reclaim, Mint, PrivateTransfer},
    crypto::constraint::arkworks::{Fp, FpVar, R1CS},
    test::payment::UtxoAccumulator,
};
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{field_new, Field, PrimeField};
use ark_groth16::{Groth16, ProvingKey};
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use blake2::Digest;
use manta_crypto::{
    accumulator::Accumulator,
    constraint::Allocate,
    eclair::alloc::mode::{Public, Secret},
    rand::{CryptoRng, OsRng, RngCore},
};
use manta_trusted_setup::{
    groth16::{
        kzg::{self, Accumulator as PhaseOneAccumulator, Contribution, Size},
        mpc::{self, contribute, initialize, verify_transform, verify_transform_all, Proof, State},
    },
    mpc::{Transcript, Types},
    pairing::Pairing,
    util::{BlakeHasher, HasDistribution, KZGBlakeHasher, Sample},
};
use manta_util::into_array_unchecked;

/// Trusted Setup MPC
#[derive(Clone, Default)]
pub struct TrustedSetupMPC;

impl Size for TrustedSetupMPC {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
    const G2_POWERS: usize = 1 << 15;
}

impl HasDistribution for TrustedSetupMPC {
    type Distribution = ();
}

impl Pairing for TrustedSetupMPC {
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

impl kzg::Configuration for TrustedSetupMPC {
    type DomainTag = u8;
    type Challenge = [u8; 64];
    type Response = [u8; 64];
    type HashToGroup = KZGBlakeHasher<Self>;

    const TAU_DOMAIN_TAG: Self::DomainTag = 0;
    const ALPHA_DOMAIN_TAG: Self::DomainTag = 1;
    const BETA_DOMAIN_TAG: Self::DomainTag = 2;

    fn response(
        state: &PhaseOneAccumulator<Self>,
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
        hasher.0.update(&challenge);
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

    fn hasher(domain_tag: Self::DomainTag) -> Self::HashToGroup {
        Self::HashToGroup { domain_tag }
    }
}

impl mpc::Configuration for TrustedSetupMPC {
    type Challenge = [u8; 64];
    type Hasher = BlakeHasher;

    fn challenge(
        challenge: &Self::Challenge,
        prev: &State<Self>,
        next: &State<Self>,
        proof: &Proof<Self>,
    ) -> Self::Challenge {
        let mut hasher = Self::Hasher::default();
        hasher.0.update(challenge);
        prev.serialize(&mut hasher)
            .expect("Consuming the previous state failed.");
        next.serialize(&mut hasher)
            .expect("Consuming the current state failed.");
        proof
            .serialize(&mut hasher)
            .expect("Consuming proof failed");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl<P> mpc::ProvingKeyHasher<P> for TrustedSetupMPC
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

impl Types for TrustedSetupMPC {
    type State = State<TrustedSetupMPC>;
    type Challenge = [u8; 64];
    type Proof = Proof<TrustedSetupMPC>;
}

/// Testing Suite
#[cfg(test)]
mod test {
    use ark_bls12_381::Fr;

    use super::*;

    /// Conducts a dummy phase one trusted setup.
    pub fn dummy_phase_one_trusted_setup() -> PhaseOneAccumulator<TrustedSetupMPC> {
        let mut rng = OsRng;
        let accumulator = PhaseOneAccumulator::default();
        let challenge = [0; 64];
        let contribution = Contribution::gen(&mut rng);
        let proof = contribution.proof(&challenge, &mut rng).unwrap();
        let mut next_accumulator = accumulator.clone();
        next_accumulator.update(&contribution);
        PhaseOneAccumulator::verify_transform(accumulator, next_accumulator, challenge, proof)
            .unwrap()
    }

    /// TODO
    pub fn dummy_trusted_setup<S>(constraint_system: S)
    where
        S: ConstraintSynthesizer<Fr>,
    {
        let mut rng = OsRng;
        // let now = Instant::now();
        let mut state = initialize(dummy_phase_one_trusted_setup(), constraint_system).unwrap(); // 558 seconds
        // println!("Initialize Phase 2 parameters takes {:?}\n", now.elapsed());
        let mut transcript = Transcript::<TrustedSetupMPC> {
            initial_challenge: <TrustedSetupMPC as mpc::ProvingKeyHasher<TrustedSetupMPC>>::hash(
                &state,
            ),
            initial_state: state.clone(),
            rounds: Vec::new(),
        };
        let hasher = <TrustedSetupMPC as mpc::Configuration>::Hasher::default();
        let (mut prev_state, mut proof);
        let mut challenge = transcript.initial_challenge;
        let NUM = 5;
        for _ in 0..NUM {
            prev_state = state.clone();
            // let now = Instant::now();
            proof = contribute(&hasher, &challenge, &mut state, &mut rng).unwrap();
            // println!(
            //     "On client side, contribute Phase 2 parameters takes {:?}",
            //     now.elapsed()
            // );
            // let now = Instant::now();
            (challenge, state) = verify_transform(&challenge, prev_state, state, proof.clone())
                .expect("Verify transform failed");
            // println!(
            //     "On server side, verify transform for Phase 2 parameters takes {:?}",
            //     now.elapsed()
            // );
            transcript.rounds.push((state.clone(), proof));
        }
        // let now = Instant::now();
        verify_transform_all(
            transcript.initial_challenge,
            transcript.initial_state,
            transcript.rounds,
        )
        .expect("Verifying all transformations failed.");
        // println!(
        //     "Given {} contributions, verify transform all for Phase 2 parameters takes {:?}",
        //     NUM,
        //     now.elapsed()
        // );
    }

    #[test]
    fn reclaim_trusted_setup() {
        let mut rng = OsRng;
        let utxo_accumulator = UtxoAccumulator::new(manta_crypto::rand::Rand::gen(&mut rng));
        let parameters = manta_crypto::rand::Rand::gen(&mut rng);
        let cs =
            Reclaim::unknown_constraints(FullParameters::new(&parameters, utxo_accumulator.model()));
        dummy_trusted_setup(cs);
    }

    #[test]
    fn mint_trusted_setup() {
        let mut rng = OsRng;
        let utxo_accumulator = UtxoAccumulator::new(manta_crypto::rand::Rand::gen(&mut rng));
        let parameters = manta_crypto::rand::Rand::gen(&mut rng);
        let cs =
            Mint::unknown_constraints(FullParameters::new(&parameters, utxo_accumulator.model()));
        dummy_trusted_setup(cs);
    }

    #[test]
    fn private_transfer_trusted_setup() {
        let mut rng = OsRng;
        let utxo_accumulator = UtxoAccumulator::new(manta_crypto::rand::Rand::gen(&mut rng));
        let parameters = manta_crypto::rand::Rand::gen(&mut rng);
        let cs =
            PrivateTransfer::unknown_constraints(FullParameters::new(&parameters, utxo_accumulator.model()));
        dummy_trusted_setup(cs);
    }

    // #[test]
    // fn benchmark() {
    //     let mut rng = OsRng;
    //     let utxo_accumulator = UtxoAccumulator::new(manta_crypto::rand::Rand::gen(&mut rng));
    //     let parameters = manta_crypto::rand::Rand::gen(&mut rng);
    //     let cs =
    //         Reclaim::unknown_constraints(FullParameters::new(&parameters, utxo_accumulator.model()));
    //     // let now = Instant::now();
    //     let mut state = initialize(dummy_phase_one_trusted_setup(), cs).unwrap(); // 558 seconds
    //                                                                               // println!("Initialize Phase 2 parameters takes {:?}\n", now.elapsed());
    //     let mut transcript = Transcript::<TrustedSetupMPC> {
    //         initial_challenge: <TrustedSetupMPC as mpc::ProvingKeyHasher<TrustedSetupMPC>>::hash(
    //             &state,
    //         ),
    //         initial_state: state.clone(),
    //         rounds: Vec::new(),
    //     };
    //     let hasher = <TrustedSetupMPC as mpc::Configuration>::Hasher::default();
    //     let (mut prev_state, mut proof);
    //     let mut challenge = transcript.initial_challenge;
    //     let NUM = 5;
    //     for _ in 0..NUM {
    //         prev_state = state.clone();
    //         // let now = Instant::now();
    //         proof = contribute(&hasher, &challenge, &mut state, &mut rng).unwrap();
    //         // println!(
    //         //     "On client side, contribute Phase 2 parameters takes {:?}",
    //         //     now.elapsed()
    //         // );
    //         // let now = Instant::now();
    //         (challenge, state) = verify_transform(&challenge, prev_state, state, proof.clone())
    //             .expect("Verify transform failed");
    //         // println!(
    //         //     "On server side, verify transform for Phase 2 parameters takes {:?}",
    //         //     now.elapsed()
    //         // );
    //         transcript.rounds.push((state.clone(), proof));
    //     }
    //     // let now = Instant::now();
    //     verify_transform_all(
    //         transcript.initial_challenge,
    //         transcript.initial_state,
    //         transcript.rounds,
    //     )
    //     .expect("Verifying all transformations failed.");
    //     // println!(
    //     //     "Given {} contributions, verify transform all for Phase 2 parameters takes {:?}",
    //     //     NUM,
    //     //     now.elapsed()
    //     // );
    // }

    // // Trusted setup phase2 for Reclaim circuit
    // // Initialize Phase 2 parameters takes 565.827243979s
    // // On client side, contribute Phase 2 parameters takes 6.17264351s
    // // On server side, verify transform for Phase 2 parameters takes 13.872369574s
    // // Given 5 contributions, verify transform all for Phase 2 parameters takes 13.997831401s
}
