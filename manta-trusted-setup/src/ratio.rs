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

//! Ratio Proofs

use crate::pairing::{Pairing, PairingEngineExt};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use manta_crypto::rand::{CryptoRng, RngCore};

/// Hash to Group Trait for Ratio Proof
pub trait HashToGroup<P, C>
where
    P: Pairing + ?Sized,
{
    /// Hashes `challenge` and `ratio` into a group point.
    fn hash(&self, challenge: &C, ratio: (&P::G1, &P::G1)) -> P::G2;
}

/// Pairing Ratio Proof of Knowledge
#[derive(derivative::Derivative, CanonicalDeserialize, CanonicalSerialize)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct RatioProof<P>
where
    P: Pairing + ?Sized,
{
    /// Ratio in G1
    pub ratio: (P::G1, P::G1),

    /// Matching Point in G2
    pub matching_point: P::G2,
}

impl<P> RatioProof<P>
where
    P: Pairing + ?Sized,
{
    /// Builds a [`RatioProof`] for `scalar` against `challenge`.
    #[inline]
    pub fn prove<H, C, R>(
        hasher: &H,
        challenge: &C,
        scalar: &P::Scalar,
        rng: &mut R,
    ) -> Option<Self>
    where
        H: HashToGroup<P, C>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let g1_point = <P::G1 as AffineCurve>::Projective::rand(rng);
        if g1_point.is_zero() {
            return None;
        }
        let scaled_g1_point = g1_point.mul(scalar.into_repr());
        if scaled_g1_point.is_zero() {
            return None;
        }
        let g1_point = g1_point.into_affine();
        let scaled_g1_point = scaled_g1_point.into_affine();
        let g2_point = Self::challenge_point(hasher, challenge, (&g1_point, &scaled_g1_point));
        if g2_point.is_zero() {
            return None;
        }
        let scaled_g2_point = g2_point.mul(*scalar);
        if scaled_g2_point.is_zero() {
            return None;
        }
        Some(Self {
            ratio: (g1_point, scaled_g1_point),
            matching_point: scaled_g2_point.into_affine(),
        })
    }

    /// Computes the challenge point that corresponds with the given `challenge`.
    #[inline]
    pub fn challenge_point<H, C>(hasher: &H, challenge: &C, ratio: (&P::G1, &P::G1)) -> P::G2
    where
        H: HashToGroup<P, C>,
    {
        hasher.hash(challenge, (ratio.0, ratio.1))
    }

    /// Verifies that `self` is a valid ratio proof-of-knowledge, returning the ratio of the
    /// underlying scalar.
    #[allow(clippy::type_complexity)]
    #[inline]
    pub fn verify<H, C>(
        self,
        hasher: &H,
        challenge: &C,
    ) -> Option<(
        (P::G1Prepared, P::G1Prepared),
        (P::G2Prepared, P::G2Prepared),
    )>
    where
        H: HashToGroup<P, C>,
    {
        let challenge_point =
            Self::challenge_point(hasher, challenge, (&self.ratio.0, &self.ratio.1));
        let ((ratio_0, matching_point), (ratio_1, challenge_point)) = P::Pairing::same(
            (self.ratio.0, self.matching_point),
            (self.ratio.1, challenge_point),
        )?;
        Some(((ratio_0, ratio_1), (matching_point, challenge_point)))
    }
}
