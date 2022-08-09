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

//! Bn254 Backend for MantaPay Groth16 Trusted Setup

use crate::{
    groth16::{
        bn254::ppot,
        kzg::{Accumulator, Configuration as KzgConfiguration, Proof as KzgProof, Size},
        mpc::{
            initialize, Configuration as MpcConfiguration, Proof as MpcProof, ProvingKeyHasher,
            State as MpcState,
        },
    },
    mpc::Types,
    util::{BlakeHasher, Deserializer, KZGBlakeHasher, Serializer},
};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::io;
use blake2::Digest;
use manta_crypto::{
    arkworks::{
        ec::{short_weierstrass_jacobian, AffineCurve, PairingEngine, SWModelParameters},
        pairing::Pairing,
    },
    merkle_tree::forest::MerkleForest,
    rand::{OsRng, Rand, SeedableRng},
};
use manta_pay::crypto::constraint::arkworks::R1CS;
use manta_util::{into_array_unchecked, vec::Vec};
use memmap::MmapOptions;
use std::{
    fs::{File, OpenOptions},
    time::Instant,
};

/// Configuration for a Phase1 Ceremony large enough to support MantaPay circuits
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct MantaPaySetupCeremony;

impl Size for MantaPaySetupCeremony {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;

    const G2_POWERS: usize = 1 << 19;
}

impl Pairing for MantaPaySetupCeremony {
    type Scalar = Fr;

    type G1 = G1Affine;

    type G1Prepared = <Bn254 as PairingEngine>::G1Prepared;

    type G2 = G2Affine;

    type G2Prepared = <Bn254 as PairingEngine>::G2Prepared;

    type Pairing = Bn254;

    fn g1_prime_subgroup_generator() -> Self::G1 {
        G1Affine::prime_subgroup_generator()
    }

    fn g2_prime_subgroup_generator() -> Self::G2 {
        G2Affine::prime_subgroup_generator()
    }
}

impl KzgConfiguration for MantaPaySetupCeremony {
    type DomainTag = u8;
    type Challenge = [u8; 64];
    type Response = [u8; 64];
    type HashToGroup = KZGBlakeHasher<Self>;

    const TAU_DOMAIN_TAG: Self::DomainTag = 0;
    const ALPHA_DOMAIN_TAG: Self::DomainTag = 1;
    const BETA_DOMAIN_TAG: Self::DomainTag = 2;

    fn hasher(domain_tag: Self::DomainTag) -> Self::HashToGroup {
        Self::HashToGroup { domain_tag }
    }

    fn response(
        state: &Accumulator<Self>,
        challenge: &Self::Challenge,
        proof: &KzgProof<Self>,
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
}

/// An accumulator for phase 1 parameters whose size is sufficient
/// for all MantaPay circuits.
pub type MantaPayAccumulator = Accumulator<MantaPaySetupCeremony>;

impl MpcConfiguration for MantaPaySetupCeremony {
    type Challenge = [u8; 64];
    type Hasher = BlakeHasher;

    #[inline]
    fn challenge(
        challenge: &Self::Challenge,
        prev: &MpcState<Self>,
        next: &MpcState<Self>,
        proof: &MpcProof<Self>,
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

impl Types for MantaPaySetupCeremony {
    type State = MpcState<Self>;
    type Challenge = [u8; 64];
    type Proof = MpcProof<Self>;
}

impl ProvingKeyHasher<Self> for MantaPaySetupCeremony {
    type Output = [u8; 64];

    #[inline]
    fn hash(proving_key: &ProvingKey<<Self as Pairing>::Pairing>) -> Self::Output {
        let mut hasher = BlakeHasher::default();
        proving_key
            .serialize(&mut hasher)
            .expect("Hasher is not allowed to fail");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl<P> Serializer<short_weierstrass_jacobian::GroupAffine<P>> for MantaPaySetupCeremony
where
    P: SWModelParameters,
{
    fn serialize_unchecked<W>(
        item: &short_weierstrass_jacobian::GroupAffine<P>,
        writer: &mut W,
    ) -> Result<(), io::Error>
    where
        W: Write,
    {
        CanonicalSerialize::serialize_unchecked(item, writer)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn serialize_uncompressed<W>(
        item: &short_weierstrass_jacobian::GroupAffine<P>,
        writer: &mut W,
    ) -> Result<(), io::Error>
    where
        W: Write,
    {
        CanonicalSerialize::serialize_uncompressed(item, writer)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn uncompressed_size(item: &short_weierstrass_jacobian::GroupAffine<P>) -> usize {
        CanonicalSerialize::uncompressed_size(item)
    }

    fn serialize_compressed<W>(
        item: &short_weierstrass_jacobian::GroupAffine<P>,
        writer: &mut W,
    ) -> Result<(), io::Error>
    where
        W: Write,
    {
        CanonicalSerialize::serialize(item, writer)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn compressed_size(item: &short_weierstrass_jacobian::GroupAffine<P>) -> usize {
        CanonicalSerialize::serialized_size(item)
    }
}

impl<P> Deserializer<short_weierstrass_jacobian::GroupAffine<P>> for MantaPaySetupCeremony
where
    P: SWModelParameters,
{
    type Error = SerializationError;

    fn deserialize_unchecked<R>(
        reader: &mut R,
    ) -> Result<short_weierstrass_jacobian::GroupAffine<P>, Self::Error>
    where
        R: Read,
    {
        CanonicalDeserialize::deserialize_unchecked(reader)
    }

    fn deserialize_compressed<R>(
        reader: &mut R,
    ) -> Result<short_weierstrass_jacobian::GroupAffine<P>, Self::Error>
    where
        R: Read,
    {
        CanonicalDeserialize::deserialize_uncompressed(reader)
    }
}

/// Generates our `Reclaim` circuit with unknown variables
pub fn reclaim_circuit() -> R1CS<Fr> {
    use manta_crypto::accumulator::Accumulator;
    use manta_pay::{
        config::{FullParameters, Reclaim},
        test::payment::UtxoAccumulator,
    };
    use rand_chacha::ChaCha20Rng;

    // 2. Specialize the final Accumulator to phase 2 parameters, write these to transcript (?)
    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let parameters = rng.gen();

    Reclaim::unknown_constraints(FullParameters::new(
        &parameters,
        <MerkleForest<_, _> as Accumulator>::model(&utxo_accumulator),
    ))
}

/// Produces a ProvingKey for the MantaPay `Reclaim` circuit
pub fn generate_reclaim_pk() -> ProvingKey<Bn254> {
    let reader = OpenOptions::new()
        .read(true)
        .open("/Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072")
        .expect("unable open `./challenge` in this directory");
    // Make a memory map
    let readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    let accumulator = ppot::read_subaccumulator::<MantaPaySetupCeremony>(&readable_map).unwrap();
    let (cs_unknown, _, _) = generate_reclaim_constraints_and_public_inputs();
    initialize(accumulator, cs_unknown).unwrap()
}

/// Produces constraint synthesizers for the `Reclaim` circuit with unknown and
/// known witness and returns public input vector for this sample.
pub fn generate_reclaim_constraints_and_public_inputs() -> (R1CS<Fr>, R1CS<Fr>, Vec<Fr>) {
    use manta_accounting::transfer::test::TransferDistribution;
    use manta_crypto::{accumulator::Accumulator, rand::Sample};
    use manta_pay::{
        config::{FullParameters, Reclaim},
        test::payment::UtxoAccumulator,
    };
    use rand_chacha::ChaCha20Rng;

    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let parameters = rng.gen();
    let sample = Reclaim::sample(
        TransferDistribution {
            parameters: &parameters,
            utxo_accumulator: &mut utxo_accumulator,
        },
        &mut rng,
    );
    let cs_known =
        sample.known_constraints(FullParameters::new(&parameters, utxo_accumulator.model()));
    let cs_unknown = Reclaim::unknown_constraints(FullParameters::new(
        &parameters,
        <MerkleForest<_, _> as Accumulator>::model(&utxo_accumulator),
    ));
    (cs_unknown, cs_known, sample.generate_proof_input())
}

/// This takes about 1 hour to complete (with 1 << 16 powers)
#[test]
pub fn generate_reclaim_pk_test() {
    let pk = generate_reclaim_pk();
    // Write to file for quick access later
    let _f = File::create("phase2_reclaim_pk").unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .open("phase2_reclaim_pk")
        .expect("unable to create parameter file in this directory");
    CanonicalSerialize::serialize_uncompressed(&pk, &mut file).unwrap();

    // Check that this was written correctly:
    let mut reader = OpenOptions::new()
        .read(true)
        .open("phase2_reclaim_pk")
        .expect("file not found");
    let pk_read: ProvingKey<Bn254> =
        CanonicalDeserialize::deserialize_unchecked(&mut reader).unwrap();
    assert_eq!(pk, pk_read)
}

/// Takes about 5 minutes to run
#[test]
pub fn phase2_contribution_test() {
    use crate::{
        groth16::mpc::{self, contribute, verify_transform, verify_transform_all},
        mpc::Transcript,
    };

    println!("Reading ProverKey from file");
    let now = Instant::now();
    let mut reader = OpenOptions::new()
        .read(true)
        .open("phase2_reclaim_pk")
        .expect("file not found");
    let mut state: ProvingKey<Bn254> =
        // CanonicalDeserialize::deserialize_uncompressed(&mut reader).unwrap();
        CanonicalDeserialize::deserialize_unchecked(&mut reader).unwrap();
    println!("Finished reading ProverKey in {:?}", now.elapsed());

    println!("Contributing to phase 2 params");
    // Contribute and verify
    let mut rng = OsRng;
    let mut transcript = Transcript::<MantaPaySetupCeremony> {
        initial_challenge: <MantaPaySetupCeremony as ProvingKeyHasher<MantaPaySetupCeremony>>::hash(
            &state,
        ),
        initial_state: state.clone(),
        rounds: Vec::new(),
    };
    let hasher = <MantaPaySetupCeremony as mpc::Configuration>::Hasher::default();
    let (mut prev_state, mut proof): (
        MpcState<MantaPaySetupCeremony>,
        MpcProof<MantaPaySetupCeremony>,
    );
    let mut challenge = transcript.initial_challenge;
    for _ in 0..5 {
        let now = Instant::now();
        prev_state = state.clone();
        proof = contribute::<MantaPaySetupCeremony, _>(&hasher, &challenge, &mut state, &mut rng)
            .unwrap();
        (challenge, state) = verify_transform(&challenge, prev_state, state, proof.clone())
            .expect("Verify transform failed");
        transcript.rounds.push((state.clone(), proof));
        println!("Performed a contribution in {:?}", now.elapsed());
    }
    println!("Verifying 5 contributions");
    let now = Instant::now();
    verify_transform_all(
        transcript.initial_challenge,
        transcript.initial_state,
        transcript.rounds,
    )
    .expect("Verifying all transformations failed.");
    println!("Verified phase 2 contributions in {:?}", now.elapsed());

    // Generate and verify a proof
    println!("Generating a proof");
    let now = Instant::now();
    let (_, cs, public_inputs) = generate_reclaim_constraints_and_public_inputs();
    let proof = ark_groth16::prover::create_random_proof(cs, &state, &mut rng).unwrap();
    println!("Took {:?} to generate a proof", now.elapsed());

    let now = Instant::now();
    let vk = &state.vk;
    let prepared_vk = ark_groth16::verifier::prepare_verifying_key(vk);
    let result = ark_groth16::verifier::verify_proof(&prepared_vk, &proof, &public_inputs).unwrap();
    println!("Took {:?} to verify the proof", now.elapsed());
    assert!(result);
}
