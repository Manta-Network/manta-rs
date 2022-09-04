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

//! KZG Trusted Setup for Groth16

use crate::util::{power_pairs, scalar_mul, Deserializer, NonZero, Serializer};
use alloc::{vec, vec::Vec};
use core::{iter, ops::Mul};
use manta_crypto::{
    arkworks::{
        ff::{One, UniformRand},
        pairing::{Pairing, PairingEngineExt},
        ratio::{HashToGroup, RatioProof},
        serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write},
    },
    rand::{CryptoRng, RngCore, Sample},
};
use manta_util::{cfg_iter, cfg_iter_mut, from_variant, vec::VecExt};

#[cfg(feature = "rayon")]
use manta_util::rayon::iter::{IndexedParallelIterator, ParallelIterator};

/// G1 Marker Type
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct G1;

/// G2 Marker Type
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct G2;

/// KZG Trusted Setup Size
pub trait Size {
    /// Number of G1 Powers to Produce
    ///
    /// The number of G1 powers must be greater than or equal to the number of G2 powers.
    const G1_POWERS: usize;

    /// Number of G2 Powers to Produce
    ///
    /// The number of G2 powers must be smaller than or equal to the number of G1 powers.
    const G2_POWERS: usize;
}

/// Trusted Setup Configuration
pub trait Configuration: Pairing + Size {
    /// Domain Tag
    type DomainTag;

    /// Challenge Type
    type Challenge;

    /// Response Type
    type Response;

    /// Hash To Group Type
    type HashToGroup: HashToGroup<Self, Self::Challenge>;

    /// Tau Domain Tag Type
    const TAU_DOMAIN_TAG: Self::DomainTag;

    /// Alpha Domain Tag Type
    const ALPHA_DOMAIN_TAG: Self::DomainTag;

    /// Beta Domain Tag Type
    const BETA_DOMAIN_TAG: Self::DomainTag;

    /// Generates a [`HashToGroup`](Self::HashToGroup) instance paramterized by `domain_tag`.
    fn hasher(domain_tag: Self::DomainTag) -> Self::HashToGroup;

    /// Computes the challenge response from `state`, `challenge`, and `proof`.
    fn response(
        state: &Accumulator<Self>,
        challenge: &Self::Challenge,
        proof: &Proof<Self>,
    ) -> Self::Response;
}

/// Knowledge Proof Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KnowledgeError {
    /// Invalid Proof of Knowledge for τ
    TauKnowledgeProof,

    /// Invalid Proof of Knowledge for α
    AlphaKnowledgeProof,

    /// Invalid Proof of Knowledge for β
    BetaKnowledgeProof,
}

/// Verification Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationError {
    /// Element Differs from Prime Subgroup Generator in G1
    PrimeSubgroupGeneratorG1,

    /// Element Differs from Prime Subgroup Generator in G2
    PrimeSubgroupGeneratorG2,

    /// Knowledge Proof Error
    Knowledge(KnowledgeError),

    /// Invalid Multiplication of τ
    TauMultiplication,

    /// Invalid Multiplication of α
    AlphaMultiplication,

    /// Invalid Multiplication of β
    BetaMultiplication,

    /// Invalid Computation of Powers of τ in G1
    TauG1Powers,

    /// Invalid Computation of Powers of τ in G2
    TauG2Powers,

    /// Invalid Computation of Powers of α in G1
    AlphaG1Powers,

    /// Invalid Computation of Powers of β in G1
    BetaG1Powers,
}

from_variant!(VerificationError, Knowledge, KnowledgeError);

/// Contribution
pub struct Contribution<C>
where
    C: Pairing,
{
    /// Tau Scalar
    tau: C::Scalar,

    /// Alpha Scalar
    alpha: C::Scalar,

    /// Beta Scalar
    beta: C::Scalar,
}

impl<C> Contribution<C>
where
    C: Configuration,
{
    /// Generates a proof of knowledge for `self`.
    #[inline]
    pub fn proof<R>(&self, challenge: &C::Challenge, rng: &mut R) -> Option<Proof<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Some(Proof {
            tau: RatioProof::prove(&C::hasher(C::TAU_DOMAIN_TAG), challenge, &self.tau, rng)?,
            alpha: RatioProof::prove(&C::hasher(C::ALPHA_DOMAIN_TAG), challenge, &self.alpha, rng)?,
            beta: RatioProof::prove(&C::hasher(C::BETA_DOMAIN_TAG), challenge, &self.beta, rng)?,
        })
    }
}

impl<C> Sample for Contribution<C>
where
    C: Pairing,
{
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self {
            tau: C::Scalar::rand(rng),
            alpha: C::Scalar::rand(rng),
            beta: C::Scalar::rand(rng),
        }
    }
}

/// Knowledge Proof Certificate
pub struct KnowledgeProofCertificate<C>
where
    C: Pairing,
{
    /// Tau Ratio in G2
    pub tau: (C::G2Prepared, C::G2Prepared),

    /// Alpha Ratio in G2
    pub alpha: (C::G2Prepared, C::G2Prepared),

    /// Beta Ratio in G2
    pub beta: (C::G2Prepared, C::G2Prepared),
}

/// Contribution Proof
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Proof<C>
where
    C: Pairing + ?Sized,
{
    /// Tau Ratio Proof
    pub tau: RatioProof<C>,

    /// Alpha Ratio Proof
    pub alpha: RatioProof<C>,

    /// Beta Ratio Proof
    pub beta: RatioProof<C>,
}

impl<C> Proof<C>
where
    C: Pairing,
{
    /// Verifies that all [`RatioProof`]s in `self` are valid, returning all of their G2 ratios. See
    /// [`RatioProof::verify`] for more.
    #[inline]
    pub fn verify(
        self,
        challenge: &C::Challenge,
    ) -> Result<KnowledgeProofCertificate<C>, KnowledgeError>
    where
        C: Configuration,
    {
        Ok(KnowledgeProofCertificate {
            tau: self
                .tau
                .verify(&C::hasher(C::TAU_DOMAIN_TAG), challenge)
                .ok_or(KnowledgeError::TauKnowledgeProof)?
                .1,
            alpha: self
                .alpha
                .verify(&C::hasher(C::ALPHA_DOMAIN_TAG), challenge)
                .ok_or(KnowledgeError::AlphaKnowledgeProof)?
                .1,
            beta: self
                .beta
                .verify(&C::hasher(C::BETA_DOMAIN_TAG), challenge)
                .ok_or(KnowledgeError::BetaKnowledgeProof)?
                .1,
        })
    }

    /// Reinterpret a proof from a KZG ceremony as a proof
    /// for a sub-ceremony.
    #[inline]
    pub fn cast_to_subceremony<D>(self) -> Proof<D>
    where
        D: Pairing<G1 = C::G1, G2 = C::G2>,
    {
        Proof {
            tau: RatioProof {
                ratio: self.tau.ratio,
                matching_point: self.tau.matching_point,
            },
            alpha: RatioProof {
                ratio: self.alpha.ratio,
                matching_point: self.alpha.matching_point,
            },
            beta: RatioProof {
                ratio: self.beta.ratio,
                matching_point: self.beta.matching_point,
            },
        }
    }
}

impl<C> CanonicalSerialize for Proof<C>
where
    C: Pairing + Serializer<C::G1, G1> + Serializer<C::G2, G2>,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        C::serialize_compressed(&self.tau.ratio.0, &mut writer)?;
        C::serialize_compressed(&self.tau.ratio.1, &mut writer)?;
        C::serialize_compressed(&self.alpha.ratio.0, &mut writer)?;
        C::serialize_compressed(&self.alpha.ratio.1, &mut writer)?;
        C::serialize_compressed(&self.beta.ratio.0, &mut writer)?;
        C::serialize_compressed(&self.beta.ratio.1, &mut writer)?;
        C::serialize_compressed(&self.tau.matching_point, &mut writer)?;
        C::serialize_compressed(&self.alpha.matching_point, &mut writer)?;
        C::serialize_compressed(&self.beta.matching_point, &mut writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        C::compressed_size(&self.tau.ratio.0)
            + C::compressed_size(&self.tau.ratio.1)
            + C::compressed_size(&self.alpha.ratio.0)
            + C::compressed_size(&self.alpha.ratio.1)
            + C::compressed_size(&self.beta.ratio.0)
            + C::compressed_size(&self.beta.ratio.1)
            + C::compressed_size(&self.tau.matching_point)
            + C::compressed_size(&self.alpha.matching_point)
            + C::compressed_size(&self.beta.matching_point)
    }

    #[inline]
    fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        C::serialize_uncompressed(&self.tau.ratio.0, &mut writer)?;
        C::serialize_uncompressed(&self.tau.ratio.1, &mut writer)?;
        C::serialize_uncompressed(&self.alpha.ratio.0, &mut writer)?;
        C::serialize_uncompressed(&self.alpha.ratio.1, &mut writer)?;
        C::serialize_uncompressed(&self.beta.ratio.0, &mut writer)?;
        C::serialize_uncompressed(&self.beta.ratio.1, &mut writer)?;
        C::serialize_uncompressed(&self.tau.matching_point, &mut writer)?;
        C::serialize_uncompressed(&self.alpha.matching_point, &mut writer)?;
        C::serialize_uncompressed(&self.beta.matching_point, &mut writer)?;
        Ok(())
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        C::uncompressed_size(&self.tau.ratio.0)
            + C::uncompressed_size(&self.tau.ratio.1)
            + C::uncompressed_size(&self.alpha.ratio.0)
            + C::uncompressed_size(&self.alpha.ratio.1)
            + C::uncompressed_size(&self.beta.ratio.0)
            + C::uncompressed_size(&self.beta.ratio.1)
            + C::uncompressed_size(&self.tau.matching_point)
            + C::uncompressed_size(&self.alpha.matching_point)
            + C::uncompressed_size(&self.beta.matching_point)
    }
}

impl<C> CanonicalDeserialize for Proof<C>
where
    C: Deserializer<C::G1, G1> + Deserializer<C::G2, G2> + Pairing,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        let tau_ratio = (
            NonZero::<C>::deserialize_compressed(&mut reader)?,
            NonZero::<C>::deserialize_compressed(&mut reader)?,
        );
        let alpha_ratio = (
            NonZero::<C>::deserialize_compressed(&mut reader)?,
            NonZero::<C>::deserialize_compressed(&mut reader)?,
        );
        let beta_ratio = (
            NonZero::<C>::deserialize_compressed(&mut reader)?,
            NonZero::<C>::deserialize_compressed(&mut reader)?,
        );
        Ok(Self {
            tau: RatioProof {
                ratio: tau_ratio,
                matching_point: NonZero::<C>::deserialize_compressed(&mut reader)?,
            },
            alpha: RatioProof {
                ratio: alpha_ratio,
                matching_point: NonZero::<C>::deserialize_compressed(&mut reader)?,
            },
            beta: RatioProof {
                ratio: beta_ratio,
                matching_point: NonZero::<C>::deserialize_compressed(&mut reader)?,
            },
        })
    }

    #[inline]
    fn deserialize_uncompressed<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        let tau_ratio = (
            NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            NonZero::<C>::deserialize_uncompressed(&mut reader)?,
        );
        let alpha_ratio = (
            NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            NonZero::<C>::deserialize_uncompressed(&mut reader)?,
        );
        let beta_ratio = (
            NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            NonZero::<C>::deserialize_uncompressed(&mut reader)?,
        );
        Ok(Self {
            tau: RatioProof {
                ratio: tau_ratio,
                matching_point: NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            },
            alpha: RatioProof {
                ratio: alpha_ratio,
                matching_point: NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            },
            beta: RatioProof {
                ratio: beta_ratio,
                matching_point: NonZero::<C>::deserialize_uncompressed(&mut reader)?,
            },
        })
    }
}

/// Contribution Accumulator
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Accumulator<C>
where
    C: Pairing + Size + ?Sized,
{
    /// Vector of Tau Powers in G1 of size [`G1_POWERS`](Size::G1_POWERS)
    pub tau_powers_g1: Vec<C::G1>,

    /// Vector of Tau Powers in G2 of size [`G2_POWERS`](Size::G2_POWERS)
    pub tau_powers_g2: Vec<C::G2>,

    /// Vector of Alpha Multiplied by Tau Powers in G1 of size [`G2_POWERS`](Size::G2_POWERS)
    pub alpha_tau_powers_g1: Vec<C::G1>,

    /// Vector of Beta Multiplied by Tau Powers in G1 of size [`G2_POWERS`](Size::G2_POWERS)
    pub beta_tau_powers_g1: Vec<C::G1>,

    /// Beta in G2
    pub beta_g2: C::G2,
}

impl<C> Accumulator<C>
where
    C: Pairing + Size,
{
    /// Updates `self` by multiplying each element of the accumulator by the powers of its
    /// respective element in the `contribution`.
    #[inline]
    pub fn update(&mut self, contribution: &Contribution<C>) {
        let mut tau_powers =
            iter::successors(Some(C::Scalar::one()), |x| Some(x.mul(contribution.tau)))
                .take(C::G1_POWERS)
                .collect::<Vec<_>>();
        let remaining_tau_powers = tau_powers.split_off(C::G2_POWERS);
        cfg_iter_mut!(self.tau_powers_g1)
            .zip(cfg_iter_mut!(self.tau_powers_g2))
            .zip(cfg_iter_mut!(self.alpha_tau_powers_g1))
            .zip(cfg_iter_mut!(self.beta_tau_powers_g1))
            .zip(tau_powers)
            .for_each(
                |((((tau_g1, tau_g2), alpha_tau_g1), beta_tau_g1), tau_power)| {
                    scalar_mul(tau_g1, tau_power);
                    scalar_mul(tau_g2, tau_power);
                    scalar_mul(alpha_tau_g1, tau_power.mul(contribution.alpha));
                    scalar_mul(beta_tau_g1, tau_power.mul(contribution.beta));
                },
            );
        cfg_iter_mut!(self.tau_powers_g1)
            .skip(C::G2_POWERS)
            .zip(remaining_tau_powers)
            .for_each(|(tau_g1, tau_power)| scalar_mul(tau_g1, tau_power));
        scalar_mul(&mut self.beta_g2, contribution.beta);
    }

    /// Verifies that `next` was computed properly from `last` with `proof` of the contribution.
    #[inline]
    pub fn verify_transform(
        last: Self,
        next: Self,
        next_challenge: C::Challenge,
        proof: Proof<C>,
    ) -> Result<Self, VerificationError>
    where
        C: Configuration,
    {
        if next.tau_powers_g1[0] != C::g1_prime_subgroup_generator() {
            return Err(VerificationError::PrimeSubgroupGeneratorG1);
        }
        if next.tau_powers_g2[0] != C::g2_prime_subgroup_generator() {
            return Err(VerificationError::PrimeSubgroupGeneratorG2);
        }
        let KnowledgeProofCertificate { tau, alpha, beta } = proof.verify(&next_challenge)?;
        C::Pairing::same(
            (last.tau_powers_g1[1], tau.0),
            (next.tau_powers_g1[1], tau.1),
        )
        .ok_or(VerificationError::TauMultiplication)?;
        C::Pairing::same(
            (last.alpha_tau_powers_g1[0], alpha.0),
            (next.alpha_tau_powers_g1[0], alpha.1),
        )
        .ok_or(VerificationError::AlphaMultiplication)?;
        let ((last_beta_tau_powers_g1_0, _), (next_beta_tau_powers_g1_0, _)) = C::Pairing::same(
            (last.beta_tau_powers_g1[0], beta.0),
            (next.beta_tau_powers_g1[0], beta.1),
        )
        .ok_or(VerificationError::BetaMultiplication)?;
        C::Pairing::same(
            (last_beta_tau_powers_g1_0, next.beta_g2),
            (next_beta_tau_powers_g1_0, last.beta_g2),
        )
        .ok_or(VerificationError::BetaMultiplication)?;
        let (lhs, rhs) = power_pairs(&next.tau_powers_g2);
        C::Pairing::same((next.tau_powers_g1[0], rhs), (next.tau_powers_g1[1], lhs))
            .ok_or(VerificationError::TauG1Powers)?;
        let (lhs, rhs) = power_pairs(&next.tau_powers_g1);
        let ((_, next_tau_powers_g2_1), (_, next_tau_powers_g2_0)) =
            C::Pairing::same((lhs, next.tau_powers_g2[1]), (rhs, next.tau_powers_g2[0]))
                .ok_or(VerificationError::TauG2Powers)?;
        let (lhs, rhs) = power_pairs(&next.alpha_tau_powers_g1);
        let ((_, next_tau_powers_g2_1), (_, next_tau_powers_g2_0)) =
            C::Pairing::same((lhs, next_tau_powers_g2_1), (rhs, next_tau_powers_g2_0))
                .ok_or(VerificationError::AlphaG1Powers)?;
        let (lhs, rhs) = power_pairs(&next.beta_tau_powers_g1);
        C::Pairing::same((lhs, next_tau_powers_g2_1), (rhs, next_tau_powers_g2_0))
            .ok_or(VerificationError::BetaG1Powers)?;
        Ok(next)
    }
}

impl<C> CanonicalSerialize for Accumulator<C>
where
    C: Pairing + Size + Serializer<C::G1, G1> + Serializer<C::G2, G2>,
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
        cfg_iter!(self.tau_powers_g1)
            .map(C::compressed_size)
            .sum::<usize>()
            + cfg_iter!(self.tau_powers_g2)
                .map(C::compressed_size)
                .sum::<usize>()
            + cfg_iter!(&self.alpha_tau_powers_g1)
                .map(C::compressed_size)
                .sum::<usize>()
            + cfg_iter!(&self.beta_tau_powers_g1)
                .map(C::compressed_size)
                .sum::<usize>()
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
        cfg_iter!(self.tau_powers_g1)
            .map(C::uncompressed_size)
            .sum::<usize>()
            + cfg_iter!(self.tau_powers_g2)
                .map(C::uncompressed_size)
                .sum::<usize>()
            + cfg_iter!(&self.alpha_tau_powers_g1)
                .map(C::uncompressed_size)
                .sum::<usize>()
            + cfg_iter!(&self.beta_tau_powers_g1)
                .map(C::uncompressed_size)
                .sum::<usize>()
            + C::uncompressed_size(&self.beta_g2)
    }
}

impl<C> CanonicalDeserialize for Accumulator<C>
where
    C: Deserializer<C::G1, G1> + Deserializer<C::G2, G2> + Pairing + Size,
    <C as Deserializer<C::G1, G1>>::Error: Send,
    <C as Deserializer<C::G2, G2>>::Error: Send,
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
        cfg_iter!(accumulator.tau_powers_g1)
            .try_for_each(C::check)
            .map_err(Into::into)?;
        cfg_iter!(accumulator.tau_powers_g2)
            .try_for_each(C::check)
            .map_err(Into::into)?;
        cfg_iter!(accumulator.alpha_tau_powers_g1)
            .try_for_each(C::check)
            .map_err(Into::into)?;
        cfg_iter!(accumulator.beta_tau_powers_g1)
            .try_for_each(C::check)
            .map_err(Into::into)?;
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
