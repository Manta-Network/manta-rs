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

//! Sapling MPC

use crate::{
    groth16::kzg::{Pairing, Size},
    util::HasDistribution,
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_std::UniformRand;
use core::fmt;

/// TODO
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum PointDeserializeError {
    /// TODO
    CompressionFlag,
    /// TODO
    ExpectedCompressed,
    /// TODO
    ExpectedUncompressed,
    /// TODO
    PointAtInfinity,
    /// TODO
    ExtraYCoordinate,
    /// TODO
    NotOnCurve,
    /// TODO
    NotInSubgroup,
}

impl fmt::Display for PointDeserializeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Point Deserializer Error: {}", self)
    }
}

/// Sapling MPC
#[derive(Clone)]
pub struct Sapling;

impl Size for Sapling {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
    const G2_POWERS: usize = 1 << 21;
}

impl HasDistribution for Sapling {
    // TODO
    type Distribution = ();
}

impl Pairing for Sapling {
    type Scalar = ark_bls12_381::Fr;

    type G1 = ark_bls12_381::G1Affine;

    type G1Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Prepared;

    type G2 = ark_bls12_381::G2Affine;

    type G2Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Prepared;

    type Pairing = ark_bls12_381::Bls12_381;

    fn sample_g1_affine<R>(rng: &mut R) -> Self::G1
    where
        R: ark_std::rand::CryptoRng + ark_std::rand::RngCore + ?Sized,
    {
        <ark_bls12_381::Bls12_381 as PairingEngine>::G1Projective::rand(rng).into_affine()
    }

    fn sample_g2_affine<R>(rng: &mut R) -> Self::G2
    where
        R: ark_std::rand::CryptoRng + ark_std::rand::RngCore + ?Sized,
    {
        <ark_bls12_381::Bls12_381 as PairingEngine>::G2Projective::rand(rng).into_affine()
    }

    fn g1_prime_subgroup_generator() -> Self::G1 {
        ark_bls12_381::G1Affine::prime_subgroup_generator()
    }

    fn g2_prime_subgroup_generator() -> Self::G2 {
        ark_bls12_381::G2Affine::prime_subgroup_generator()
    }
}

impl Sapling {
    /// TODO
    #[inline]
    pub fn is_valid_g1_curve_point(g: &<Self as Pairing>::G1) -> Result<(), PointDeserializeError> {
        if !g.is_on_curve() {
            return Err(PointDeserializeError::NotOnCurve);
        } else if !g.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PointDeserializeError::NotInSubgroup);
        }
        Ok(())
    }

    /// TODO
    #[inline]
    pub fn is_valid_g2_curve_point(g: &<Self as Pairing>::G2) -> Result<(), PointDeserializeError> {
        if !g.is_on_curve() {
            return Err(PointDeserializeError::NotOnCurve);
        } else if !g.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PointDeserializeError::NotInSubgroup);
        }
        Ok(())
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    /// Tests if we can generate a valid transcript and verify it.
    #[test]
    fn transcript_generation_and_verify_is_correct() {
        // let mut accumulator = Accumulator::<Sapling>::default();
    }
}
