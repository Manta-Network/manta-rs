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
    ///
    pub tau_g1_ratio: (C::G1, C::G1),

    ///
    pub alpha_g1_ratio: (C::G1, C::G1),

    ///
    pub beta_g1_ratio: (C::G1, C::G1),

    ///
    pub tau_g2: C::G2,

    ///
    pub alpha_g2: C::G2,

    ///
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
        /* TODO:
        // Compressed G1 is 48 bytes
        // Compressed G2 is 96 bytes
        48 * 2 * 3 + 96 * 3
        */
        todo!()
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
        /* TODO:
        // Compressed G1 is 96 bytes
        // Compressed G2 is 192 bytes
        96 * 2 * 3 + 192 * 3
        */
        todo!()
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
    ///
    tau_powers_g1: Vec<C::G1>,

    ///
    tau_powers_g2: Vec<C::G2>,

    ///
    alpha_tau_powers_g1: Vec<C::G1>,

    ///
    beta_tau_powers_g1: Vec<C::G1>,

    ///
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
        /* TODO:
        // A compressed G1 element is 48 bytes
        // A compressed G2 element is 96 bytes
        C::G1_POWERS * 48 + C::G2_POWERS * 96 + C::G1_POWERS * 48 * 2 + 96
        */
        todo!()
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
        /* TODO:
        // An uncompressed G1 element is 96 bytes
        // An uncompressed G2 element is 192 bytes
        C::G1_POWERS * 96 + C::G2_POWERS * 192 + C::G1_POWERS * 96 * 2 + 192
        */
        todo!()
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
        /*
        let mut tau_powers_g1 = Vec::with_capacity(C::G1_POWERS);
        for _ in 0..C::G1_POWERS {
            tau_powers_g1.push(
                C::deserialize_g1_compressed(&mut reader)
                    .map_err(C::convert_serialization_error)?,
            );
        }
        let mut tau_powers_g2 = Vec::with_capacity(C::G2_POWERS);
        for _ in 0..C::G2_POWERS {
            tau_powers_g2.push(
                C::deserialize_g2_compressed(&mut reader)
                    .map_err(C::convert_serialization_error)?,
            );
        }
        let mut alpha_tau_powers_g1 = Vec::with_capacity(C::G2_POWERS);
        for _ in 0..C::G2_POWERS {
            alpha_tau_powers_g1.push(
                C::deserialize_g1_compressed(&mut reader)
                    .map_err(C::convert_serialization_error)?,
            );
        }
        let mut beta_tau_powers_g1 = Vec::with_capacity(C::G2_POWERS);
        for _ in 0..C::G2_POWERS {
            beta_tau_powers_g1.push(
                C::deserialize_g1_compressed(&mut reader)
                    .map_err(C::convert_serialization_error)?,
            );
        }
        Ok(Self {
            tau_powers_g1,
            tau_powers_g2,
            alpha_tau_powers_g1,
            beta_tau_powers_g1,
            beta_g2: C::deserialize_g2_compressed(&mut reader)
                .map_err(C::convert_serialization_error)?,
        })
        */
        todo!()
    }

    #[inline]
    fn deserialize_uncompressed<R>(reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        /* TODO:
        let unchecked = Self::deserialize_unchecked(reader)?;
        let counter = std::sync::atomic::AtomicU64::new(0);
        cfg_try_for_each!(cfg_iter!(&unchecked.tau_powers_g1), |point| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if counter.load(std::sync::atomic::Ordering::SeqCst) % 1000000 == 0 {
                println!("Checked this many elements: {:?}", counter);
            }
            C::curve_point_checks_g1(point)
        })
        .map_err(C::convert_serialization_error)?;
        cfg_try_for_each!(
            cfg_iter!(&unchecked.tau_powers_g2),
            C::curve_point_checks_g2
        )
        .map_err(C::convert_serialization_error)?;
        cfg_try_for_each!(
            cfg_iter!(&unchecked.alpha_tau_powers_g1),
            C::curve_point_checks_g1
        )
        .map_err(C::convert_serialization_error)?;
        cfg_try_for_each!(
            cfg_iter!(&unchecked.beta_tau_powers_g1),
            C::curve_point_checks_g1
        )
        .map_err(C::convert_serialization_error)?;
        C::curve_point_checks_g2(&unchecked.beta_g2).map_err(C::convert_serialization_error)?;
        Ok(unchecked)
        */
        todo!()
    }

    #[inline]
    fn deserialize_unchecked<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        /* TODO:
        let mut tau_powers_g1 = Vec::with_capacity(C::G1_POWERS);
        for i in 0..C::G1_POWERS {
            tau_powers_g1.push(
                C::deserialize_g1_unchecked(&mut reader).map_err(C::convert_serialization_error)?,
            );
        }
        let mut tau_powers_g2 = Vec::with_capacity(C::G2_POWERS);
        for i in 0..C::G2_POWERS {
            tau_powers_g2.push(
                C::deserialize_g2_unchecked(&mut reader).map_err(C::convert_serialization_error)?,
            );
        }
        let mut alpha_tau_powers_g1 = Vec::with_capacity(C::G2_POWERS);
        for i in 0..C::G2_POWERS {
            alpha_tau_powers_g1.push(
                C::deserialize_g1_unchecked(&mut reader).map_err(C::convert_serialization_error)?,
            );
        }
        let mut beta_tau_powers_g1 = Vec::with_capacity(C::G2_POWERS);
        for i in 0..C::G2_POWERS {
            beta_tau_powers_g1.push(
                C::deserialize_g1_unchecked(&mut reader).map_err(C::convert_serialization_error)?,
            );
        }
        Ok(Self {
            tau_powers_g1,
            tau_powers_g2,
            alpha_tau_powers_g1,
            beta_tau_powers_g1,
            beta_g2: C::deserialize_g2_unchecked(&mut reader)
                .map_err(C::convert_serialization_error)?,
        })
        */
        todo!()
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
