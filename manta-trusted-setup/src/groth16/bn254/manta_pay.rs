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
        kzg::{Accumulator, Configuration as KzgConfiguration, Proof as KzgProof, Size},
        mpc::{
            Configuration as MpcConfiguration, Proof as MpcProof, ProvingKeyHasher,
            State as MpcState,
        },
    },
    mpc::Types,
    util::{from_serialization_error, BlakeHasher, Deserializer, KZGBlakeHasher, Serializer},
};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::io;
use blake2::Digest;
use manta_crypto::arkworks::{
    ec::{short_weierstrass_jacobian, AffineCurve, PairingEngine, SWModelParameters},
    pairing::Pairing,
};
use manta_util::into_array_unchecked;

/// Configuration for a Phase1 Ceremony large enough to support MantaPay circuits
#[derive(CanonicalDeserialize, CanonicalSerialize, Debug, PartialEq, Eq)]
pub struct MantaPaySetupCeremony;

impl Size for MantaPaySetupCeremony {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
    const G2_POWERS: usize = 1 << 19;
}

impl Pairing for MantaPaySetupCeremony {
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
    #[inline]
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

    #[inline]
    fn serialize_uncompressed<W>(
        item: &short_weierstrass_jacobian::GroupAffine<P>,
        writer: &mut W,
    ) -> Result<(), io::Error>
    where
        W: Write,
    {
        CanonicalSerialize::serialize_uncompressed(item, writer).map_err(from_serialization_error)
    }

    #[inline]
    fn uncompressed_size(item: &short_weierstrass_jacobian::GroupAffine<P>) -> usize {
        CanonicalSerialize::uncompressed_size(item)
    }

    #[inline]
    fn serialize_compressed<W>(
        item: &short_weierstrass_jacobian::GroupAffine<P>,
        writer: &mut W,
    ) -> Result<(), io::Error>
    where
        W: Write,
    {
        CanonicalSerialize::serialize(item, writer).map_err(from_serialization_error)
    }

    #[inline]
    fn compressed_size(item: &short_weierstrass_jacobian::GroupAffine<P>) -> usize {
        CanonicalSerialize::serialized_size(item)
    }
}

impl<P> Deserializer<short_weierstrass_jacobian::GroupAffine<P>> for MantaPaySetupCeremony
where
    P: SWModelParameters,
{
    type Error = SerializationError;

    #[inline]
    fn deserialize_unchecked<R>(
        reader: &mut R,
    ) -> Result<short_weierstrass_jacobian::GroupAffine<P>, Self::Error>
    where
        R: Read,
    {
        CanonicalDeserialize::deserialize_unchecked(reader)
    }

    #[inline]
    fn deserialize_compressed<R>(
        reader: &mut R,
    ) -> Result<short_weierstrass_jacobian::GroupAffine<P>, Self::Error>
    where
        R: Read,
    {
        CanonicalDeserialize::deserialize_uncompressed(reader)
    }
}
