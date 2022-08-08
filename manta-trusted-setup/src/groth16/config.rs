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

//! Trusted Setup Phase2 Configuration

use crate::{
    groth16::{
        kzg,
        kzg::{Accumulator, Size},
        mpc::{Configuration, Proof, ProvingKeyHasher, State},
    },
    mpc::Types,
    ratio::HashToGroup,
    util::{BlakeHasher, Deserializer, HasDistribution, KZGBlakeHasher},
};
use ark_bls12_381::{G1Affine, G2Affine};
use ark_groth16::ProvingKey;
use ark_std::io::{Read, Write};
use bincode::Options;
use blake2::Digest;
use manta_crypto::{
    arkworks::{
        ec::{AffineCurve, PairingEngine},
        pairing::Pairing,
        serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError},
    },
    rand::Sample,
};
use manta_util::into_array_unchecked;

/// Configuration for the Groth16 Phase2 Server.
#[derive(Clone, Default)]
pub struct Config;

impl HasDistribution for Config {
    type Distribution = ();
}

impl Pairing for Config {
    type Scalar = ark_bls12_381::Fr;
    type G1 = ark_bls12_381::G1Affine;
    type G1Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Prepared;
    type G2 = ark_bls12_381::G2Affine;
    type G2Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Prepared;
    type Pairing = ark_bls12_381::Bls12_381;

    #[inline]
    fn g1_prime_subgroup_generator() -> Self::G1 {
        ark_bls12_381::G1Affine::prime_subgroup_generator()
    }

    #[inline]
    fn g2_prime_subgroup_generator() -> Self::G2 {
        ark_bls12_381::G2Affine::prime_subgroup_generator()
    }
}

impl Size for Config {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
    const G2_POWERS: usize = 1 << 3;
}

impl<T> Deserializer<T> for Config
where
    T: CanonicalDeserialize,
{
    type Error = SerializationError;

    fn deserialize_unchecked<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        <T as CanonicalDeserialize>::deserialize_unchecked(reader)
    }

    fn deserialize_compressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        <T as CanonicalDeserialize>::deserialize(reader)
    }
}

impl kzg::Configuration for Config {
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

#[derive(Clone, Copy, Debug)]
/// Challenge
// we wrap this challenge to make it serializable
pub struct Challenge([u8; 64]);

impl CanonicalSerialize for Challenge {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        64
    }
}

impl CanonicalDeserialize for Challenge {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 64];
        reader.read_exact(&mut buf)?;
        Ok(Challenge(buf))
    }
}

impl From<[u8; 64]> for Challenge {
    #[inline]
    fn from(challenge: [u8; 64]) -> Self {
        Challenge(challenge)
    }
}

impl From<Challenge> for [u8; 64] {
    #[inline]
    fn from(challenge: Challenge) -> Self {
        challenge.0
    }
}

impl<P> HashToGroup<P, Challenge> for BlakeHasher
where
    P: Pairing,
    P::G2: Sample,
{
    #[inline]
    fn hash(&self, challenge: &Challenge, ratio: (&P::G1, &P::G1)) -> P::G2 {
        <Self as HashToGroup<P, [u8; 64]>>::hash(self, &challenge.0, ratio)
    }
}

impl Configuration for Config {
    type Challenge = Challenge;
    type Hasher = BlakeHasher;

    #[inline]
    fn challenge(
        challenge: &Self::Challenge,
        prev: &State<Self>,
        next: &State<Self>,
        proof: &Proof<Self>,
    ) -> Self::Challenge {
        let mut hasher = Self::Hasher::default();
        hasher.0.update(challenge.0);
        prev.serialize_uncompressed(&mut hasher)
            .expect("Consuming the previous state failed.");
        next.serialize_uncompressed(&mut hasher)
            .expect("Consuming the current state failed.");
        proof
            .serialize_uncompressed(&mut hasher)
            .expect("Consuming proof failed");
        into_array_unchecked(hasher.0.finalize()).into()
    }
}

impl<P> ProvingKeyHasher<P> for Config
where
    P: Pairing,
{
    type Output = [u8; 64];

    #[inline]
    fn hash(proving_key: &ProvingKey<P::Pairing>) -> Self::Output {
        let mut hasher = BlakeHasher::default();
        proving_key
            .serialize_uncompressed(&mut hasher)
            .expect("Hasher is not allowed to fail");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl Types for Config {
    type State = State<Config>;
    type Challenge = [u8; 64];
    type Proof = Proof<Config>;
}
