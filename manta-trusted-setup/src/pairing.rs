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

//! Pairing

use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::PrimeField;
use core::iter;

/// Pairing Configuration
pub trait Pairing {
    /// Underlying Scalar Field
    type Scalar: PrimeField;

    /// First Group of the Pairing
    type G1: AffineCurve<ScalarField = Self::Scalar> + Into<Self::G1Prepared>;

    /// First Group Pairing-Prepared Point
    type G1Prepared;

    /// Second Group of the Pairing
    type G2: AffineCurve<ScalarField = Self::Scalar> + Into<Self::G2Prepared>;

    /// Second Group Pairing-Prepared Point
    type G2Prepared;

    /// Pairing Engine Type
    type Pairing: PairingEngine<
        G1Affine = Self::G1,
        G2Affine = Self::G2,
        G1Prepared = Self::G1Prepared,
        G2Prepared = Self::G2Prepared,
    >;

    /// Returns the base G1 generator for this configuration.
    fn g1_prime_subgroup_generator() -> Self::G1;

    /// Returns the base G2 generator for this configuration.
    fn g2_prime_subgroup_generator() -> Self::G2;
}

/// Pair from a [`PairingEngine`]
type Pair<P> = (
    <P as PairingEngine>::G1Prepared,
    <P as PairingEngine>::G2Prepared,
);

/// Pairing Engine Extension
pub trait PairingEngineExt: PairingEngine {
    /// Evaluates the pairing function on `pair`.
    #[inline]
    fn eval(pair: &Pair<Self>) -> Self::Fqk {
        Self::product_of_pairings(iter::once(pair))
    }

    /// Checks if `lhs` and `rhs` evaluate to the same point under the pairing function.
    #[inline]
    fn has_same(lhs: &Pair<Self>, rhs: &Pair<Self>) -> bool {
        Self::eval(lhs) == Self::eval(rhs)
    }

    /// Checks if `lhs` and `rhs` evaluate to the same point under the pairing function, returning
    /// `Some` with prepared points if the pairing outcome is the same. This function checks if
    /// there exists an `r` such that `(r * lhs.0 == rhs.0) && (lhs.1 == r * rhs.1)`.
    #[inline]
    fn same<L1, L2, R1, R2>(lhs: (L1, L2), rhs: (R1, R2)) -> Option<(Pair<Self>, Pair<Self>)>
    where
        L1: Into<Self::G1Prepared>,
        L2: Into<Self::G2Prepared>,
        R1: Into<Self::G1Prepared>,
        R2: Into<Self::G2Prepared>,
    {
        let lhs = (lhs.0.into(), lhs.1.into());
        let rhs = (rhs.0.into(), rhs.1.into());
        Self::has_same(&lhs, &rhs).then_some((lhs, rhs))
    }

    /// Checks if the ratio of `(lhs.0, lhs.1)` from `G1` is the same as the ratio of
    /// `(lhs.0, lhs.1)` from `G2`.
    #[inline]
    fn same_ratio<L1, L2, R1, R2>(lhs: (L1, R1), rhs: (L2, R2)) -> bool
    where
        L1: Into<Self::G1Prepared>,
        L2: Into<Self::G2Prepared>,
        R1: Into<Self::G1Prepared>,
        R2: Into<Self::G2Prepared>,
    {
        Self::has_same(&(lhs.0.into(), rhs.1.into()), &(lhs.1.into(), rhs.0.into()))
    }
}

impl<E> PairingEngineExt for E where E: PairingEngine {}

#[cfg(test)]
mod test {
    use crate::{pairing::PairingEngineExt, util::Sample};
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use manta_crypto::rand::OsRng;

    /// Tests if the ratio check is correct.
    #[test]
    fn ratio_check_is_correct() {
        let mut rng = OsRng;
        let g1 = G1Affine::gen(&mut rng);
        let g2 = G2Affine::gen(&mut rng);
        let scalar = Fr::gen(&mut rng);
        assert!(Bls12_381::same(
            (g1, g2.mul(scalar).into_affine()),
            (g1.mul(scalar).into_affine(), g2)
        )
        .is_some());
        assert!(!Bls12_381::same(
            (g1, g2.mul(scalar).into_affine()),
            (g1.mul(Fr::gen(&mut rng)).into_affine(), g2)
        )
        .is_some())
    }
}
