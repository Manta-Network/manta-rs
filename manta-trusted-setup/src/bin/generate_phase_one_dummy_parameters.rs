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

//! Generate Dummy Phase One Parameters

use std::time::Instant;

use ark_bls12_381::Fr;
use manta_crypto::{
    accumulator::Accumulator,
    arkworks::{
        ec::{
            short_weierstrass_jacobian::GroupAffine, wnaf::WnafContext, AffineCurve, PairingEngine,
            ProjectiveCurve, SWModelParameters,
        },
        ff::field_new,
        pairing::{Pair, Pairing},
        r1cs_std::eq::EqGadget,
        serialize::{CanonicalDeserialize, CanonicalSerialize},
    },
    eclair::alloc::Allocate, constraint::measure::Measure,
};
use manta_util::{cfg_into_iter, cfg_iter, cfg_iter_mut, cfg_reduce, into_array_unchecked};

use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use blake2::Digest;
use manta_crypto::{
    // constraint::Allocate,
    eclair::alloc::mode::{Public, Secret},
    rand::{CryptoRng, OsRng, RngCore, Sample, SeedableRng},
};

use manta_pay::{
    config::{FullParameters, Reclaim},
    crypto::constraint::arkworks::{Fp, FpVar, R1CS},
    test::payment::UtxoAccumulator,
};
use manta_trusted_setup::{
    groth16::{
        kzg::{self, Accumulator as PhaseOneAccumulator, Contribution, Size},
        mpc::{self, contribute, initialize, verify_transform, verify_transform_all, Proof, State},
    },
    mpc::{Transcript, Types},
    util::{BlakeHasher, HasDistribution, KZGBlakeHasher, Serializer},
};

/// Test MPC
#[derive(Clone, Default)]
pub struct Test;

impl Size for Test {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
    const G2_POWERS: usize = 1 << 16;
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

impl mpc::Configuration for Test {
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

impl Types for Test {
    type State = State<Test>;
    type Challenge = [u8; 64];
    type Proof = Proof<Test>;
}

use manta_trusted_setup::util::{G1Type, G2Type};

impl Serializer<<Test as Pairing>::G1, G1Type> for Test {
    fn serialize_unchecked<W>(
        item: &<Test as Pairing>::G1,
        writer: &mut W,
    ) -> Result<(), ark_std::io::Error>
    where
        W: ark_std::io::Write,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        item.serialize_unchecked(writer).map_err(|_| error.into())
    }

    fn serialize_uncompressed<W>(
        item: &<Test as Pairing>::G1,
        writer: &mut W,
    ) -> Result<(), ark_std::io::Error>
    where
        W: ark_std::io::Write,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        item.serialize_uncompressed(writer)
            .map_err(|_| error.into())
    }

    fn uncompressed_size(item: &<Test as Pairing>::G1) -> usize {
        item.uncompressed_size()
    }

    fn serialize_compressed<W>(
        item: &<Test as Pairing>::G1,
        writer: &mut W,
    ) -> Result<(), ark_std::io::Error>
    where
        W: ark_std::io::Write,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        item.serialize_uncompressed(writer)
            .map_err(|_| error.into())
    }

    fn compressed_size(item: &<Test as Pairing>::G1) -> usize {
        item.uncompressed_size()
    }
}

impl Serializer<<Test as Pairing>::G2, G2Type> for Test {
    fn serialize_unchecked<W>(
        item: &<Test as Pairing>::G2,
        writer: &mut W,
    ) -> Result<(), ark_std::io::Error>
    where
        W: ark_std::io::Write,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        item.serialize_unchecked(writer).map_err(|_| error.into())
    }

    fn serialize_uncompressed<W>(
        item: &<Test as Pairing>::G2,
        writer: &mut W,
    ) -> Result<(), ark_std::io::Error>
    where
        W: ark_std::io::Write,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        item.serialize_uncompressed(writer)
            .map_err(|_| error.into())
    }

    fn uncompressed_size(item: &<Test as Pairing>::G2) -> usize {
        item.uncompressed_size()
    }

    fn serialize_compressed<W>(
        item: &<Test as Pairing>::G2,
        writer: &mut W,
    ) -> Result<(), ark_std::io::Error>
    where
        W: ark_std::io::Write,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        item.serialize_uncompressed(writer)
            .map_err(|_| error.into())
    }

    fn compressed_size(item: &<Test as Pairing>::G2) -> usize {
        item.uncompressed_size()
    }
}

use manta_trusted_setup::util::Deserializer;

impl Deserializer<<Test as Pairing>::G1, G1Type> for Test {
    type Error = ark_std::io::Error; // TODO

    fn deserialize_unchecked<R>(reader: &mut R) -> Result<<Test as Pairing>::G1, Self::Error>
    where
        R: ark_std::io::Read,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        <Test as Pairing>::G1::deserialize_unchecked(reader).map_err(|_| error.into())
    }

    fn deserialize_compressed<R>(reader: &mut R) -> Result<<Test as Pairing>::G1, Self::Error>
    where
        R: ark_std::io::Read,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        <Test as Pairing>::G1::deserialize_uncompressed(reader).map_err(|_| error.into())
    }
}

impl Deserializer<<Test as Pairing>::G2, G2Type> for Test {
    type Error = ark_std::io::Error; // TODO

    fn deserialize_unchecked<R>(reader: &mut R) -> Result<<Test as Pairing>::G2, Self::Error>
    where
        R: ark_std::io::Read,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        <Test as Pairing>::G2::deserialize_unchecked(reader).map_err(|_| error.into())
    }

    fn deserialize_compressed<R>(reader: &mut R) -> Result<<Test as Pairing>::G2, Self::Error>
    where
        R: ark_std::io::Read,
    {
        let error = ark_std::io::ErrorKind::Other; // TODO
        <Test as Pairing>::G2::deserialize_uncompressed(reader).map_err(|_| error.into())
    }
}

/// Conducts a dummy phase one trusted setup.
pub fn dummy_phase_one_trusted_setup() -> PhaseOneAccumulator<Test> {
    let mut rng = OsRng;
    let accumulator = PhaseOneAccumulator::default();
    let challenge = [0; 64];
    let contribution = Contribution::gen(&mut rng);
    let proof = contribution.proof(&challenge, &mut rng).unwrap();
    let mut next_accumulator = accumulator.clone();
    next_accumulator.update(&contribution);
    PhaseOneAccumulator::verify_transform(accumulator, next_accumulator, challenge, proof).unwrap()
}

/// Proves and verifies a R1CS circuit with proving key `pk` and a random number generator `rng`.
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

use async_std::fs;
use async_std::{fs::File, prelude::*};


// cargo run --release --package manta-trusted-setup --bin generate_phase_one_dummy_parameters --nocapture

// /// TODO
// #[async_std::main]
// pub async fn main() {
//     let mut rng = OsRng;
//     let utxo_accumulator = UtxoAccumulator::new(manta_crypto::rand::Rand::gen(&mut rng));
//     let parameters = manta_crypto::rand::Rand::gen(&mut rng);
//     let now = Instant::now();
//     let cs =
//         Reclaim::unknown_constraints(FullParameters::new(&parameters, utxo_accumulator.model()));
//     let dummy_phase_one_parameter = fs::read("/home/boyuan/manta/code/manta-rs/manta-trusted-setup/dummy_phase_one_parameter.data").await.unwrap();
//     let dummy_phase_one_parameter =
//         CanonicalDeserialize::deserialize(dummy_phase_one_parameter.as_slice()).unwrap();
//     println!("Successfully read & deserialize data");
//     let mut state = initialize::<Test, R1CS<Fr>>(dummy_phase_one_parameter, cs).unwrap();
//     let mut transcript = Transcript::<Test> {
//         initial_challenge: <Test as mpc::ProvingKeyHasher<Test>>::hash(&state),
//         initial_state: state.clone(),
//         rounds: Vec::new(),
//     };
//     let hasher = <Test as mpc::Configuration>::Hasher::default();
//     let (mut prev_state, mut proof);
//     let mut challenge = transcript.initial_challenge;
//     let NUM = 5;
//     for _ in 0..NUM {
//         prev_state = state.clone();
//         proof = contribute(&hasher, &challenge, &mut state, &mut rng).unwrap();
//         (challenge, state) = verify_transform(&challenge, prev_state, state, proof.clone())
//             .expect("Verify transform failed");
//         transcript.rounds.push((state.clone(), proof));
//     }
//     verify_transform_all(
//         transcript.initial_challenge,
//         transcript.initial_state,
//         transcript.rounds,
//     )
//     .expect("Verifying all transformations failed.");
// }


#[async_std::main]
async fn main() {
    let mut rng = OsRng;
    let utxo_accumulator = UtxoAccumulator::new(manta_crypto::rand::Rand::gen(&mut rng));
    let parameters = manta_crypto::rand::Rand::gen(&mut rng);
    let now = Instant::now();
    let cs =
        Reclaim::unknown_constraints(FullParameters::new(&parameters, utxo_accumulator.model()));
    println!("cs.constraint_count(): {:?}", cs.constraint_count());
    let dummy_phase_one_parameter = dummy_phase_one_trusted_setup();
    println!(
        "Finished trusted setup phase one takes {:?}\n",
        now.elapsed()
    );
    let mut raw_data: Vec<u8> = Vec::new();
    let now = Instant::now();
    dummy_phase_one_parameter.serialize(&mut raw_data).unwrap();
    File::create("dummy_phase_one_parameter.data")
        .await
        .unwrap()
        .write_all(&raw_data)
        .await
        .unwrap();
    println!(
        "Wrote phase one parameters to disk. Took {:?}\n",
        now.elapsed()
    );
    let now = Instant::now();
    let mut state = initialize(dummy_phase_one_parameter, cs).unwrap(); // 558 seconds
    println!("Initialize Phase 2 parameters takes {:?}\n", now.elapsed());
    let mut transcript = Transcript::<Test> {
        initial_challenge: <Test as mpc::ProvingKeyHasher<Test>>::hash(&state),
        initial_state: state.clone(),
        rounds: Vec::new(),
    };
    let hasher = <Test as mpc::Configuration>::Hasher::default();
    let (mut prev_state, mut proof);
    let mut challenge = transcript.initial_challenge;
    let NUM = 5;
    for _ in 0..NUM {
        prev_state = state.clone();
        let now = Instant::now();
        proof = contribute(&hasher, &challenge, &mut state, &mut rng).unwrap();
        println!(
            "On client side, contribute Phase 2 parameters takes {:?}",
            now.elapsed()
        );
        let now = Instant::now();
        (challenge, state) = verify_transform(&challenge, prev_state, state, proof.clone())
            .expect("Verify transform failed");
        println!(
            "On server side, verify transform for Phase 2 parameters takes {:?}",
            now.elapsed()
        );
        transcript.rounds.push((state.clone(), proof));
    }
    let now = Instant::now();
    verify_transform_all(
        transcript.initial_challenge,
        transcript.initial_state,
        transcript.rounds,
    )
    .expect("Verifying all transformations failed.");
    println!(
        "Given {} contributions, verify transform all for Phase 2 parameters takes {:?}",
        NUM,
        now.elapsed()
    );
}

// cargo run --release --package manta-trusted-setup --bin generate_phase_one_dummy_parameters -- --nocapture
