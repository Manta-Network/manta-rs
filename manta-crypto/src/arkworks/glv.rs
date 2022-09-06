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

//! Arkwprks Elliptic Curve Implementation

use crate::arkworks::{
    ec::{
        models::{short_weierstrass_jacobian, SWModelParameters},
        AffineCurve, ProjectiveCurve,
    },
    ff::PrimeField,
};
use ark_ff::BigInteger;
use num_bigint::{BigInt, Sign};

/// Affine Curve Extension
pub trait AffineCurveExt: AffineCurve {
    /// Gets `x` coordinate.
    fn x(&self) -> &Self::BaseField;

    /// Gets `y` coordinate.
    fn y(&self) -> &Self::BaseField;

    /// Builds [`Self`] from `x` and `y`.
    fn from_xy_unchecked(x: Self::BaseField, y: Self::BaseField) -> Self;
}

impl<P> AffineCurveExt for short_weierstrass_jacobian::GroupAffine<P>
where
    P: SWModelParameters,
{
    #[inline]
    fn x(&self) -> &Self::BaseField {
        &self.x
    }

    #[inline]
    fn y(&self) -> &Self::BaseField {
        &self.y
    }

    #[inline]
    fn from_xy_unchecked(x: Self::BaseField, y: Self::BaseField) -> Self {
        Self::new(x, y, false)
    }
}

/// Basis Vectors
pub struct Basis(pub ((BigInt, BigInt), (BigInt, BigInt)));

/// Given a scalar `k` and basis vectors `v` and `u` finds integer scalars `k1` and `k2`,
/// so that `(k, 0)` is close to `k1v + k2u`
/// TODO: Check the bit length of BitInt v.s. BaseField or ScalarField. See if there is any overflow issue.
#[inline]
pub fn decompose_scalar<F>(k: &F, v: (BigInt, BigInt), u: (BigInt, BigInt)) -> (BigInt, BigInt)
where
    F: PrimeField,
{
    // NOTE: We first find rational solutions to `(k,0) = q1v + q2u`
    //       We can re-write this problem as a matrix `A(q1,q2) = (k,0)`
    //       so that `(q1,q2) = A^-1(k,0)`.
    let k: BigInt = BigInt::from_bytes_be(Sign::Plus, &k.into_repr().to_bytes_be());
    let det = (v.0.clone() * u.1.clone()) - (v.1.clone() * u.0.clone());
    let q1 = (u.1.clone() * k.clone()) / det.clone();
    let q2 = (-v.1.clone() * k.clone()) / det;
    let k1 = k - q1.clone() * v.0 - q2.clone() * u.0;
    let k2 = 0 - q1 * v.1 - q2 * u.1;
    (k1, k2)
}

/// GLV Parameters
pub struct GLVParameters<C>
where
    C: AffineCurve,
{
    ///
    pub lambda: C::ScalarField,

    ///
    pub beta: C::BaseField,

    ///
    pub base_v1: (BigInt, BigInt),

    ///
    pub base_v2: (BigInt, BigInt),
}

impl<C> GLVParameters<C>
where
    C: AffineCurve,
{
    ///
    #[inline]
    pub fn generate() -> Self {
        todo!()
    }

    ///
    #[inline]
    pub fn scalar_mul(&self, point: &C, scalar: &C::ScalarField) -> C
    where
        C: AffineCurveExt,
    {
        let (k1, k2) = decompose_scalar(scalar, self.base_v1.clone(), self.base_v2.clone());
        let (k1_sign, k1) = k1.into_parts();
        let k1_scalar = C::ScalarField::from_le_bytes_mod_order(&k1.to_bytes_le());
        let p1 = match k1_sign {
            Sign::Minus => -point.mul(k1_scalar.into_repr()),
            _ => point.mul(k1_scalar.into_repr()),
        };
        let (k2_sign, k2) = k2.into_parts();
        let k2_scalar = C::ScalarField::from_le_bytes_mod_order(&k2.to_bytes_le());
        let p2 = match k2_sign {
            Sign::Minus => -glv_endomorphism(point, &self.beta).mul(k2_scalar.into_repr()),
            _ => glv_endomorphism(point, &self.beta).mul(k2_scalar.into_repr()),
        };
        (p1 + p2).into_affine()
    }
}

///
#[inline]
fn glv_endomorphism<C>(point: &C, beta: &C::BaseField) -> C
where
    C: AffineCurveExt,
{
    C::from_xy_unchecked(*point.x() * beta, *point.y())
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        arkworks::ff::{Field, PrimeField, UniformRand},
        rand::OsRng,
    };
    use core::str::FromStr;
    use num_bigint::BigUint;

    pub fn glv_is_correct<C>()
    where
        C: AffineCurveExt,
    {
        let mut rng = OsRng;
        let scalar = C::ScalarField::rand(&mut rng);
        let point = C::Projective::rand(&mut rng);
        assert_eq!(
            point.mul(scalar.into_repr()).into_affine(),
            GLVParameters::<C>{
            lambda: C::ScalarField::from_le_bytes_mod_order(&"228988810152649578064853576960394133503".parse::<BigUint>().unwrap().to_bytes_le()),
            beta: C::BaseField::from_random_bytes(&"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436".parse::<BigUint>().unwrap().to_bytes_le()).unwrap(),
            base_v1: (BigInt::from_str("1").unwrap(), BigInt::from_str("228988810152649578064853576960394133504").unwrap()),
            base_v2: ("228988810152649578064853576960394133503".parse().unwrap(),"-1".parse().unwrap())
            }.scalar_mul(&point.into_affine(), &scalar),
            "GLV should produce the same results as Arkworks scalar multiplication."
        );
    }

    #[test]
    fn glv_matches_arkworks_scalar_mul() {
        glv_is_correct::<ark_bls12_381::G1Affine>();
    }
}