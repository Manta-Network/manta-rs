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

//! Trusted Setup Utilities

use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use manta_crypto::rand::OsRng;
use manta_trusted_setup::{
    groth16::{
        kzg::{self, Accumulator as PhaseOneAccumulator, Contribution, Size},
        mpc::{self, contribute, initialize, verify_transform, verify_transform_all, Proof, State},
    },
    mpc::{Transcript, Types},
    pairing::Pairing,
    util::{BlakeHasher, HasDistribution, KZGBlakeHasher, Sample},
};

use crate::crypto::constraint::arkworks::R1CS;

use super::config::TrustedSetupMPC;

/// Conducts a dummy phase one trusted setup.
pub fn dummy_phase_one_trusted_setup() -> PhaseOneAccumulator<TrustedSetupMPC> {
    let mut rng = OsRng;
    let accumulator = PhaseOneAccumulator::default();
    let challenge = [0; 64];
    let contribution = Contribution::gen(&mut rng);
    let proof = contribution.proof(&challenge, &mut rng).unwrap();
    let mut next_accumulator = accumulator.clone();
    next_accumulator.update(&contribution);
    PhaseOneAccumulator::verify_transform(accumulator, next_accumulator, challenge, proof).unwrap()
}

// /// Proves and verifies a R1CS circuit with proving key `pk` and a random number generator `rng`.
// pub fn prove_and_verify_circuit<F, P, R>(pk: ProvingKey<P>, cs: R1CS<F>, mut rng: &mut R)
// where
//     F: PrimeField,
//     P: PairingEngine<Fr = F>,
//     R: CryptoRng + RngCore + ?Sized,
// {
//     assert!(
//         Groth16::verify(
//             &pk.vk,
//             &[F::from(6u8)],
//             &Groth16::prove(&pk, cs, &mut rng).unwrap()
//         )
//         .unwrap(),
//         "Verify proof should succeed."
//     );
// }
