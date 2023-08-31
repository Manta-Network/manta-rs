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

//! Groth16 Proof System

use crate::{
    arkworks::{
        constraint::R1CS,
        ec::PairingEngine,
        relations::r1cs::SynthesisError,
        serialize::{
            ArkReader, ArkWriter, CanonicalDeserialize, CanonicalSerialize, HasDeserialization,
            HasSerialization, Read, SerializationError, Write,
        },
    },
    constraint::{Input, ProofSystem},
    rand::{CryptoRng, RngCore, SizedRng},
};
use alloc::vec::Vec;
use ark_groth16::{Groth16 as ArkGroth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use core::{
    hash::{Hash, Hasher},
    marker::PhantomData,
};
use manta_util::codec::{self, DecodeError};

#[cfg(feature = "scale")]
use crate::crypto::ecc::arkworks::Group;

#[cfg(feature = "serde")]
use {
    crate::arkworks::serialize::{canonical_deserialize, canonical_serialize},
    manta_util::serde::{Deserialize, Serialize, Serializer},
};

/// Proof System Error
///
/// This is the error state of the [`Groth16`] proof system methods. This type is intentionally
/// opaque so that error details are not revealed.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Error;

/// Groth16 Proof
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "", serialize = ""),
        crate = "manta_util::serde",
        deny_unknown_fields,
        try_from = "Vec<u8>"
    )
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug, Default(bound = ""), Eq, PartialEq)]
pub struct Proof<E>(
    /// Groth16 Proof
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_proof::<E, _>"))]
    pub ark_groth16::Proof<E>,
)
where
    E: PairingEngine;

impl<E> Hash for Proof<E>
where
    E: PairingEngine,
{
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.a.hash(state);
        self.0.b.hash(state);
        self.0.c.hash(state);
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<E> scale_codec::Decode for Proof<E>
where
    E: PairingEngine,
{
    #[inline]
    fn decode<I>(input: &mut I) -> Result<Self, scale_codec::Error>
    where
        I: scale_codec::Input,
    {
        Ok(Self(
            CanonicalDeserialize::deserialize(arkworks::codec::ScaleCodecReader(input))
                .map_err(|_| "Deserialization Error")?,
        ))
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<E> scale_codec::Encode for Proof<E>
where
    E: PairingEngine,
{
    #[inline]
    fn using_encoded<R, Encoder>(&self, f: Encoder) -> R
    where
        Encoder: FnOnce(&[u8]) -> R,
    {
        f(&proof_as_bytes::<E>(&self.0))
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<E> scale_codec::EncodeLike for Proof<E> where E: PairingEngine {}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<E> scale_codec::MaxEncodedLen for Proof<E>
where
    E: PairingEngine,
{
    #[inline]
    fn max_encoded_len() -> usize {
        2 * Group::<E::G1Projective>::max_encoded_len()
            + Group::<E::G2Projective>::max_encoded_len()
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<E> scale_info::TypeInfo for Proof<E>
where
    E: PairingEngine,
{
    type Identity = [u8];

    #[inline]
    fn type_info() -> scale_info::Type {
        Self::Identity::type_info()
    }
}

impl<E> codec::Encode for Proof<E>
where
    E: PairingEngine,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        proof_as_bytes(&self.0).encode(writer)
    }
}

impl<E> TryFrom<Vec<u8>> for Proof<E>
where
    E: PairingEngine,
{
    type Error = SerializationError;

    #[inline]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        CanonicalDeserialize::deserialize(&mut bytes.as_slice()).map(Self)
    }
}

/// Converts `proof` into its canonical byte-representation.
#[inline]
pub fn proof_as_bytes<E>(proof: &ark_groth16::Proof<E>) -> Vec<u8>
where
    E: PairingEngine,
{
    let mut buffer = Vec::new();
    proof
        .serialize(&mut buffer)
        .expect("Serialization is not allowed to fail.");
    buffer
}

/// Uses `serializer` to serialize `proof`.
#[cfg(feature = "serde")]
#[inline]
fn serialize_proof<E, S>(proof: &ark_groth16::Proof<E>, serializer: S) -> Result<S::Ok, S::Error>
where
    E: PairingEngine,
    S: Serializer,
{
    serializer.serialize_bytes(&proof_as_bytes::<E>(proof))
}

/// Proving Context
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone, Debug, Eq, PartialEq)]
pub struct ProvingContext<E>
where
    E: PairingEngine,
{
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "canonical_serialize::<ProvingKey<E>, _>",
            deserialize_with = "canonical_deserialize::<'de, _, ProvingKey<E>>"
        )
    )]
    proving_key: ProvingKey<E>,
}

impl<E> ProvingContext<E>
where
    E: PairingEngine,
{
    /// Builds a new [`ProvingContext`] from `proving_key`.
    #[inline]
    pub fn new(proving_key: ProvingKey<E>) -> Self {
        Self { proving_key }
    }

    /// Returns the [`VerifyingContext`] for `self`.
    #[inline]
    pub fn get_verifying_context(&self) -> Result<VerifyingContext<E>, SynthesisError> {
        VerifyingContext::from_proving_context(self)
    }
}

impl<E> Hash for ProvingContext<E>
where
    E: PairingEngine,
{
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.proving_key.vk.alpha_g1.hash(state);
        self.proving_key.vk.beta_g2.hash(state);
        self.proving_key.vk.gamma_g2.hash(state);
        self.proving_key.vk.delta_g2.hash(state);
        self.proving_key.vk.gamma_abc_g1.hash(state);
        self.proving_key.beta_g1.hash(state);
        self.proving_key.delta_g1.hash(state);
        self.proving_key.a_query.hash(state);
        self.proving_key.b_g1_query.hash(state);
        self.proving_key.b_g2_query.hash(state);
        self.proving_key.h_query.hash(state);
        self.proving_key.l_query.hash(state);
    }
}

impl<E> codec::Decode for ProvingContext<E>
where
    E: PairingEngine,
{
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: codec::Read,
    {
        let mut reader = ArkReader::new(reader);
        match CanonicalDeserialize::deserialize_unchecked(&mut reader) {
            Ok(value) => reader
                .finish()
                .map(move |_| Self::new(value))
                .map_err(DecodeError::Read),
            Err(err) => Err(DecodeError::Decode(err)),
        }
    }
}

impl<E> codec::Encode for ProvingContext<E>
where
    E: PairingEngine,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        let mut writer = ArkWriter::new(writer);
        let _ = self.proving_key.serialize_unchecked(&mut writer);
        writer.finish().map(move |_| ())
    }
}

/// Verifying Context
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug, Default)]
pub struct VerifyingContext<E>(pub PreparedVerifyingKey<E>)
where
    E: PairingEngine;

impl<E> VerifyingContext<E>
where
    E: PairingEngine,
{
    /// Builds a new [`VerifyingContext`] from `prepared_verifying_key`.
    #[inline]
    pub fn new_prepared(prepared_verifying_key: PreparedVerifyingKey<E>) -> Self {
        Self(prepared_verifying_key)
    }

    /// Builds a new [`VerifyingContext`] from `verifying_key`.
    #[inline]
    pub fn new(verifying_key: &VerifyingKey<E>) -> Result<Self, SynthesisError> {
        Ok(Self(ArkGroth16::process_vk(verifying_key)?))
    }

    /// Returns the [`VerifyingContext`] for `proving_context`.
    #[inline]
    pub fn from_proving_context(
        proving_context: &ProvingContext<E>,
    ) -> Result<Self, SynthesisError> {
        Self::new(&proving_context.proving_key.vk)
    }
}

impl<E> CanonicalSerialize for VerifyingContext<E>
where
    E: PairingEngine,
    for<'s> E::G2Prepared: HasSerialization<'s>,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        let PreparedVerifyingKey {
            vk,
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
        } = &self.0;
        vk.serialize(&mut writer)?;
        alpha_g1_beta_g2.serialize(&mut writer)?;
        <E::G2Prepared as HasSerialization<'_>>::Serialize::from(gamma_g2_neg_pc)
            .serialize(&mut writer)?;
        <E::G2Prepared as HasSerialization<'_>>::Serialize::from(delta_g2_neg_pc)
            .serialize(&mut writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        let PreparedVerifyingKey {
            vk,
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
        } = &self.0;
        vk.serialized_size()
            + alpha_g1_beta_g2.serialized_size()
            + <E::G2Prepared as HasSerialization<'_>>::Serialize::from(gamma_g2_neg_pc)
                .serialized_size()
            + <E::G2Prepared as HasSerialization<'_>>::Serialize::from(delta_g2_neg_pc)
                .serialized_size()
    }

    #[inline]
    fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        let PreparedVerifyingKey {
            vk,
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
        } = &self.0;
        vk.serialize_uncompressed(&mut writer)?;
        alpha_g1_beta_g2.serialize_uncompressed(&mut writer)?;
        <E::G2Prepared as HasSerialization<'_>>::Serialize::from(gamma_g2_neg_pc)
            .serialize_uncompressed(&mut writer)?;
        <E::G2Prepared as HasSerialization<'_>>::Serialize::from(delta_g2_neg_pc)
            .serialize_uncompressed(&mut writer)?;
        Ok(())
    }

    #[inline]
    fn serialize_unchecked<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        let PreparedVerifyingKey {
            vk,
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
        } = &self.0;
        vk.serialize_unchecked(&mut writer)?;
        alpha_g1_beta_g2.serialize_unchecked(&mut writer)?;
        <E::G2Prepared as HasSerialization<'_>>::Serialize::from(gamma_g2_neg_pc)
            .serialize_unchecked(&mut writer)?;
        <E::G2Prepared as HasSerialization<'_>>::Serialize::from(delta_g2_neg_pc)
            .serialize_unchecked(&mut writer)?;
        Ok(())
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        let PreparedVerifyingKey {
            vk,
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
        } = &self.0;
        vk.uncompressed_size()
            + alpha_g1_beta_g2.uncompressed_size()
            + <E::G2Prepared as HasSerialization<'_>>::Serialize::from(gamma_g2_neg_pc)
                .uncompressed_size()
            + <E::G2Prepared as HasSerialization<'_>>::Serialize::from(delta_g2_neg_pc)
                .uncompressed_size()
    }
}

impl<E> CanonicalDeserialize for VerifyingContext<E>
where
    E: PairingEngine,
    E::G2Prepared: HasDeserialization,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        Ok(Self(PreparedVerifyingKey {
            vk: CanonicalDeserialize::deserialize(&mut reader)?,
            alpha_g1_beta_g2: CanonicalDeserialize::deserialize(&mut reader)?,
            gamma_g2_neg_pc: <E::G2Prepared as HasDeserialization>::Deserialize::deserialize(
                &mut reader,
            )?
            .into(),
            delta_g2_neg_pc: <E::G2Prepared as HasDeserialization>::Deserialize::deserialize(
                &mut reader,
            )?
            .into(),
        }))
    }

    #[inline]
    fn deserialize_uncompressed<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        Ok(Self(PreparedVerifyingKey {
            vk: CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
            alpha_g1_beta_g2: CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
            gamma_g2_neg_pc:
                <E::G2Prepared as HasDeserialization>::Deserialize::deserialize_uncompressed(
                    &mut reader,
                )?
                .into(),
            delta_g2_neg_pc:
                <E::G2Prepared as HasDeserialization>::Deserialize::deserialize_uncompressed(
                    &mut reader,
                )?
                .into(),
        }))
    }

    #[inline]
    fn deserialize_unchecked<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        Ok(Self(PreparedVerifyingKey {
            vk: CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
            alpha_g1_beta_g2: CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
            gamma_g2_neg_pc:
                <E::G2Prepared as HasDeserialization>::Deserialize::deserialize_unchecked(
                    &mut reader,
                )?
                .into(),
            delta_g2_neg_pc:
                <E::G2Prepared as HasDeserialization>::Deserialize::deserialize_unchecked(
                    &mut reader,
                )?
                .into(),
        }))
    }
}

impl<E> codec::Decode for VerifyingContext<E>
where
    E: PairingEngine,
    E::G2Prepared: HasDeserialization,
{
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: codec::Read,
    {
        let mut reader = ArkReader::new(reader);
        match CanonicalDeserialize::deserialize(&mut reader) {
            Ok(value) => reader
                .finish()
                .map(move |_| value)
                .map_err(DecodeError::Read),
            Err(err) => Err(DecodeError::Decode(err)),
        }
    }
}

impl<E> codec::Encode for VerifyingContext<E>
where
    E: PairingEngine,
    for<'s> E::G2Prepared: HasSerialization<'s>,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        let mut writer = ArkWriter::new(writer);
        let _ = self.serialize(&mut writer);
        writer.finish().map(move |_| ())
    }
}

/// Arkworks Groth16 Proof System
#[derivative(Clone(clone_trait = "::std::clone::Clone"))]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Groth16<E>(PhantomData<E>)
where
    E: PairingEngine;

impl<E> ProofSystem for Groth16<E>
where
    E: PairingEngine,
{
    type Compiler = R1CS<E::Fr>;
    type PublicParameters = ();
    type ProvingContext = ProvingContext<E>;
    type VerifyingContext = VerifyingContext<E>;
    type Input = Vec<E::Fr>;
    type Proof = Proof<E>;
    type Error = Error;

    #[inline]
    fn context_compiler() -> Self::Compiler {
        Self::Compiler::for_contexts()
    }

    #[inline]
    fn proof_compiler() -> Self::Compiler {
        Self::Compiler::for_proofs()
    }

    #[inline]
    fn compile<R>(
        public_parameters: &Self::PublicParameters,
        compiler: Self::Compiler,
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = public_parameters;
        let (proving_key, verifying_key) =
            ArkGroth16::circuit_specific_setup(compiler, &mut SizedRng(rng)).map_err(|_| Error)?;
        Ok((
            ProvingContext::new(proving_key),
            VerifyingContext(ArkGroth16::process_vk(&verifying_key).map_err(|_| Error)?),
        ))
    }

    #[inline]
    fn prove<R>(
        context: &Self::ProvingContext,
        compiler: Self::Compiler,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        ArkGroth16::prove(&context.proving_key, compiler, &mut SizedRng(rng))
            .map(Proof)
            .map_err(|_| Error)
    }

    #[inline]
    fn verify(
        context: &Self::VerifyingContext,
        input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        ArkGroth16::verify_with_processed_vk(&context.0, input, &proof.0).map_err(|_| Error)
    }
}

/// Implements [`Input`] over [`Groth16`] for `$type` that can convert to a field element.
macro_rules! public_input_impl {
    ($($type:tt),* $(,)?) => {
        $(
            impl<E> Input<Groth16<E>> for $type
            where
                E: PairingEngine,
            {
                #[inline]
                fn extend(&self, input: &mut Vec<E::Fr>) {
                    input.push((*self).into());
                }
            }
        )*
    };
}

public_input_impl!(bool, u8, u16, u32, u64, u128);
