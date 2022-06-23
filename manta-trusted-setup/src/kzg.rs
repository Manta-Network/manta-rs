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

//! KZG Trusted Setup

use crate::util::{
    CanonicalDeserialize, CanonicalSerialize, Deserializer, HasDistribution, NonZero, Read, Sample,
    SerializationError, Serializer, Write, Zero,
};
use ark_ec::{AffineCurve, PairingEngine};
use manta_util::{iter, sum, try_for_each, vec::VecExt};

/// KZG Trusted Setup Size
pub trait Size {
    /// Number of G1 Powers to Produce
    const G1_POWERS: usize;

    /// Number of G2 Powers to Produce
    const G2_POWERS: usize;
}

///
pub trait Pairing: HasDistribution {
    ///
    type Scalar;

    /// First Group of the Pairing
    type G1: AffineCurve<ScalarField = Self::Scalar> + Sample<Self::Distribution> + Zero;

    /// Second Group of the Pairing
    type G2: AffineCurve<ScalarField = Self::Scalar> + Sample<Self::Distribution> + Zero;

    /// Pairing Engine Type
    type Engine: PairingEngine<G1Affine = Self::G1, G2Affine = Self::G2>;

    ///
    fn g1_prime_subgroup_generator() -> Self::G1;

    ///
    fn g2_prime_subgroup_generator() -> Self::G2;
}

/// Verification Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationError {
    /// Invalid Proof of Knowledge for τ
    TauKnowledgeProof,

    /// Invalid Proof of Knowledge for α
    AlphaKnowledgeProof,

    /// Invalid Proof of Knowledge for β
    BetaKnowledgeProof,

    /// Element Differs from Prime Subgroup Generator in G1
    PrimeSubgroupGeneratorG1,

    /// Element Differs from Prime Subgroup Generator in G2
    PrimeSubgroupGeneratorG2,

    /// Invalid Multiplication of τ
    TauMultiplication,

    /// Invalid Multiplication of α
    AlphaMultiplication,

    /// Invalid Multiplication of β
    BetaMultiplication,

    /// Invalid Computation of Powers of τ
    PowersOfTau,
}

/// Contribution Public Key
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct PublicKey<C>
where
    C: Pairing,
{
    /// Tau G1 Ratio
    pub tau_g1_ratio: (C::G1, C::G1),

    /// Alpha G1 Ratio
    pub alpha_g1_ratio: (C::G1, C::G1),

    /// Beta G1 Ratio
    pub beta_g1_ratio: (C::G1, C::G1),

    /// Tau in G2
    pub tau_g2: C::G2,

    /// Alpha in G2
    pub alpha_g2: C::G2,

    /// Beta in G2
    pub beta_g2: C::G2,
}

impl<C> CanonicalSerialize for PublicKey<C>
where
    C: Pairing + Serializer<C::G1> + Serializer<C::G2>,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        C::serialize_compressed(&self.tau_g1_ratio.0, &mut writer)?;
        C::serialize_compressed(&self.tau_g1_ratio.1, &mut writer)?;
        C::serialize_compressed(&self.alpha_g1_ratio.0, &mut writer)?;
        C::serialize_compressed(&self.alpha_g1_ratio.1, &mut writer)?;
        C::serialize_compressed(&self.beta_g1_ratio.0, &mut writer)?;
        C::serialize_compressed(&self.beta_g1_ratio.1, &mut writer)?;
        C::serialize_compressed(&self.tau_g2, &mut writer)?;
        C::serialize_compressed(&self.alpha_g2, &mut writer)?;
        C::serialize_compressed(&self.beta_g2, &mut writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        C::compressed_size(&self.tau_g1_ratio.0)
            + C::compressed_size(&self.tau_g1_ratio.1)
            + C::compressed_size(&self.alpha_g1_ratio.0)
            + C::compressed_size(&self.alpha_g1_ratio.1)
            + C::compressed_size(&self.beta_g1_ratio.0)
            + C::compressed_size(&self.beta_g1_ratio.1)
            + C::compressed_size(&self.tau_g2)
            + C::compressed_size(&self.alpha_g2)
            + C::compressed_size(&self.beta_g2)
    }

    #[inline]
    fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        C::serialize_uncompressed(&self.tau_g1_ratio.0, &mut writer)?;
        C::serialize_uncompressed(&self.tau_g1_ratio.1, &mut writer)?;
        C::serialize_uncompressed(&self.alpha_g1_ratio.0, &mut writer)?;
        C::serialize_uncompressed(&self.alpha_g1_ratio.1, &mut writer)?;
        C::serialize_uncompressed(&self.beta_g1_ratio.0, &mut writer)?;
        C::serialize_uncompressed(&self.beta_g1_ratio.1, &mut writer)?;
        C::serialize_uncompressed(&self.tau_g2, &mut writer)?;
        C::serialize_uncompressed(&self.alpha_g2, &mut writer)?;
        C::serialize_uncompressed(&self.beta_g2, &mut writer)?;
        Ok(())
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        C::uncompressed_size(&self.tau_g1_ratio.0)
            + C::uncompressed_size(&self.tau_g1_ratio.1)
            + C::uncompressed_size(&self.alpha_g1_ratio.0)
            + C::uncompressed_size(&self.alpha_g1_ratio.1)
            + C::uncompressed_size(&self.beta_g1_ratio.0)
            + C::uncompressed_size(&self.beta_g1_ratio.1)
            + C::uncompressed_size(&self.tau_g2)
            + C::uncompressed_size(&self.alpha_g2)
            + C::uncompressed_size(&self.beta_g2)
    }
}

impl<C> CanonicalDeserialize for PublicKey<C>
where
    C: Deserializer<C::G1> + Deserializer<C::G2> + Pairing,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        Ok(Self {
            tau_g1_ratio: (
                NonZero::<C>::deserialize_compressed(&mut reader)?,
                NonZero::<C>::deserialize_compressed(&mut reader)?,
            ),
            alpha_g1_ratio: (
                NonZero::<C>::deserialize_compressed(&mut reader)?,
                NonZero::<C>::deserialize_compressed(&mut reader)?,
            ),
            beta_g1_ratio: (
                NonZero::<C>::deserialize_compressed(&mut reader)?,
                NonZero::<C>::deserialize_compressed(&mut reader)?,
            ),
            tau_g2: NonZero::<C>::deserialize_compressed(&mut reader)?,
            alpha_g2: NonZero::<C>::deserialize_compressed(&mut reader)?,
            beta_g2: NonZero::<C>::deserialize_compressed(&mut reader)?,
        })
    }

    #[inline]
    fn deserialize_uncompressed<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        Ok(Self {
            tau_g1_ratio: (
                NonZero::<C>::deserialize_uncompressed(&mut reader)?,
                NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            ),
            alpha_g1_ratio: (
                NonZero::<C>::deserialize_uncompressed(&mut reader)?,
                NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            ),
            beta_g1_ratio: (
                NonZero::<C>::deserialize_uncompressed(&mut reader)?,
                NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            ),
            tau_g2: NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            alpha_g2: NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            beta_g2: NonZero::<C>::deserialize_uncompressed(&mut reader)?,
        })
    }
}

/// Contribution Accumulator
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Accumulator<C>
where
    C: Pairing + Size,
{
    /// Vector of Tau Powers in G1 of size [`G1_POWERS`]
    tau_powers_g1: Vec<C::G1>,

    /// Vector of Tau Powers in G2 of size [`G2_POWERS`]
    tau_powers_g2: Vec<C::G2>,

    /// Vector of Alpha Multiplied by Tau Powers in G1 of size [`G2_POWERS`]
    alpha_tau_powers_g1: Vec<C::G1>,

    /// Vector of Beta Multiplied by Tau Powers in G1 of size [`G2_POWERS`]
    beta_tau_powers_g1: Vec<C::G1>,

    /// Beta in G2
    beta_g2: C::G2,
}

impl<C> CanonicalSerialize for Accumulator<C>
where
    C: Pairing + Size + Serializer<C::G1> + Serializer<C::G2>,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        for elem in &self.tau_powers_g1 {
            C::serialize_compressed(elem, &mut writer)?;
        }
        for elem in &self.tau_powers_g2 {
            C::serialize_compressed(elem, &mut writer)?;
        }
        for elem in &self.alpha_tau_powers_g1 {
            C::serialize_compressed(elem, &mut writer)?;
        }
        for elem in &self.beta_tau_powers_g1 {
            C::serialize_compressed(elem, &mut writer)?;
        }
        C::serialize_compressed(&self.beta_g2, &mut writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        sum!(iter!(self.tau_powers_g1).map(C::compressed_size), usize)
            + sum!(iter!(self.tau_powers_g2).map(C::compressed_size), usize)
            + sum!(
                iter!(self.alpha_tau_powers_g1).map(C::compressed_size),
                usize
            )
            + sum!(
                iter!(self.beta_tau_powers_g1).map(C::compressed_size),
                usize
            )
            + C::compressed_size(&self.beta_g2)
    }

    #[inline]
    fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        for elem in &self.tau_powers_g1 {
            C::serialize_uncompressed(elem, &mut writer)?;
        }
        for elem in &self.tau_powers_g2 {
            C::serialize_uncompressed(elem, &mut writer)?;
        }
        for elem in &self.alpha_tau_powers_g1 {
            C::serialize_uncompressed(elem, &mut writer)?;
        }
        for elem in &self.beta_tau_powers_g1 {
            C::serialize_uncompressed(elem, &mut writer)?;
        }
        C::serialize_uncompressed(&self.beta_g2, &mut writer)?;
        Ok(())
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        sum!(iter!(self.tau_powers_g1).map(C::uncompressed_size), usize)
            + sum!(iter!(self.tau_powers_g2).map(C::uncompressed_size), usize)
            + sum!(
                iter!(self.alpha_tau_powers_g1).map(C::uncompressed_size),
                usize
            )
            + sum!(
                iter!(self.beta_tau_powers_g1).map(C::uncompressed_size),
                usize
            )
            + C::uncompressed_size(&self.beta_g2)
    }
}

impl<C> CanonicalDeserialize for Accumulator<C>
where
    C: Deserializer<C::G1> + Deserializer<C::G2> + Pairing + Size,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        let mut tau_powers_g1 = Vec::with_capacity(C::G1_POWERS);
        for _ in 0..C::G1_POWERS {
            tau_powers_g1.push(C::deserialize_compressed(&mut reader).map_err(Into::into)?);
        }
        let mut tau_powers_g2 = Vec::with_capacity(C::G2_POWERS);
        for _ in 0..C::G2_POWERS {
            tau_powers_g2.push(C::deserialize_compressed(&mut reader).map_err(Into::into)?);
        }
        let mut alpha_tau_powers_g1 = Vec::with_capacity(C::G2_POWERS);
        for _ in 0..C::G2_POWERS {
            alpha_tau_powers_g1.push(C::deserialize_compressed(&mut reader).map_err(Into::into)?);
        }
        let mut beta_tau_powers_g1 = Vec::with_capacity(C::G2_POWERS);
        for _ in 0..C::G2_POWERS {
            beta_tau_powers_g1.push(C::deserialize_compressed(&mut reader).map_err(Into::into)?);
        }
        Ok(Self {
            tau_powers_g1,
            tau_powers_g2,
            alpha_tau_powers_g1,
            beta_tau_powers_g1,
            beta_g2: C::deserialize_compressed(&mut reader).map_err(Into::into)?,
        })
    }

    #[inline]
    fn deserialize_uncompressed<R>(reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        let accumulator = Self::deserialize_unchecked(reader)?;
        try_for_each!(iter!(&accumulator.tau_powers_g1), C::check).map_err(Into::into)?;
        try_for_each!(iter!(&accumulator.tau_powers_g2), C::check).map_err(Into::into)?;
        try_for_each!(iter!(&accumulator.alpha_tau_powers_g1), C::check).map_err(Into::into)?;
        try_for_each!(iter!(&accumulator.beta_tau_powers_g1), C::check).map_err(Into::into)?;
        C::check(&accumulator.beta_g2).map_err(Into::into)?;
        Ok(accumulator)
    }

    #[inline]
    fn deserialize_unchecked<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        Ok(Self {
            tau_powers_g1: Vec::try_allocate_with(C::G1_POWERS, |_| {
                C::deserialize_unchecked(&mut reader)
            })
            .map_err(Into::into)?,
            tau_powers_g2: Vec::try_allocate_with(C::G2_POWERS, |_| {
                C::deserialize_unchecked(&mut reader)
            })
            .map_err(Into::into)?,
            alpha_tau_powers_g1: Vec::try_allocate_with(C::G2_POWERS, |_| {
                C::deserialize_unchecked(&mut reader)
            })
            .map_err(Into::into)?,
            beta_tau_powers_g1: Vec::try_allocate_with(C::G2_POWERS, |_| {
                C::deserialize_unchecked(&mut reader)
            })
            .map_err(Into::into)?,
            beta_g2: C::deserialize_unchecked(&mut reader).map_err(Into::into)?,
        })
    }
}

impl<C> Default for Accumulator<C>
where
    C: Pairing + Size,
{
    #[inline]
    fn default() -> Self {
        Self {
            tau_powers_g1: vec![C::g1_prime_subgroup_generator(); C::G1_POWERS],
            tau_powers_g2: vec![C::g2_prime_subgroup_generator(); C::G2_POWERS],
            alpha_tau_powers_g1: vec![C::g1_prime_subgroup_generator(); C::G2_POWERS],
            beta_tau_powers_g1: vec![C::g1_prime_subgroup_generator(); C::G2_POWERS],
            beta_g2: C::g2_prime_subgroup_generator(),
        }
    }
}
