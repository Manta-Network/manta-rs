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
        bn254::ppot::PerpetualPowersOfTauCeremony,
        kzg::Accumulator,
        mpc::{
            Configuration as MpcConfiguration, Proof as MpcProof, ProvingKeyHasher,
            State as MpcState,
        },
    },
    mpc::Types,
    util::{from_serialization_error, BlakeHasher, Deserializer, Serializer},
};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::io;
use blake2::Digest;
use manta_crypto::arkworks::{
    ec::{short_weierstrass_jacobian, SWModelParameters},
    pairing::Pairing,
};
use manta_util::into_array_unchecked;

const MANTA_PAY_POWERS: usize = 1 << 19;
/// Configuration for a Phase1 Ceremony large enough to support MantaPay circuits
pub type MantaPaySetupCeremony =
    PerpetualPowersOfTauCeremony<ArkworksSerialization, MANTA_PAY_POWERS>;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Arkworks Canonical(De)Serialize
pub struct ArkworksSerialization {}

impl<P> Serializer<short_weierstrass_jacobian::GroupAffine<P>> for ArkworksSerialization
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

impl<P> Deserializer<short_weierstrass_jacobian::GroupAffine<P>> for ArkworksSerialization
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
