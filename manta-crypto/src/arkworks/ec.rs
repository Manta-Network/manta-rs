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

use crate::arkworks::ff::PrimeField;
use models::short_weierstrass_jacobian;
use models::twisted_edwards_extended;
use models::SWModelParameters;
use models::TEModelParameters;
use num_bigint::Sign;
use num_bigint::{BigInt, BigUint};

#[doc(inline)]
pub use ark_ec::*;

///
pub trait AffineCurveExt: AffineCurve {
    ///
    fn x(&self) -> &Self::BaseField;

    ///
    fn y(&self) -> &Self::BaseField;

    ///
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

impl<P> AffineCurveExt for twisted_edwards_extended::GroupAffine<P>
where
    P: TEModelParameters,
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
        Self::new(x, y)
    }
}

///
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
    pub fn scalar_mul(&self, point: &C, scalar: &C::ScalarField) -> C {
        let (k1, k2) = glv_decompose_scalar::<&C>(&scalar, self.base_v1, self.base_v2);

    let mut P1 = C::zero();
    let mut P2 = C::zero();

    let P1 = match k1.sign() {
        Sign::Minus => {
            let k1_unsigned: BigUint = BigInt::to_biguint(&-k1).unwrap();
            let k1_scalar = C::ScalarField::from_le_bytes_mod_order(&k1_unsigned.to_bytes_le());
            -point.mul(*&k1_scalar.into_repr())
        },
        _ => {
            let k1_unsigned: BigUint = BigInt::to_biguint(&k1).unwrap();
            let k1_scalar = C::ScalarField::from_le_bytes_mod_order(&k1_unsigned.to_bytes_le());
            point.mul(*&k1_scalar.into_repr())
        }
    };
    let P2 = match k2.sign() {
        Sign::Minus => {
            let k2_unsigned: BigUint = BigInt::to_biguint(&-k2).unwrap();
            let k2_scalar = C::ScalarField::from_le_bytes_mod_order(&k2_unsigned.to_bytes_le());
            -glv_endomorphism::<C>(point, &self.beta).mul(*&k2_scalar.into_repr())
        },
        _ => {
            let k1_unsigned: BigUint = BigInt::to_biguint(&k1).unwrap();
            let k1_scalar = C::ScalarField::from_le_bytes_mod_order(&k1_unsigned.to_bytes_le());
            point.mul(*&k1_scalar.into_repr())
        }
    };

    // if Sign::Minus == k1.sign() {
    //     let k1_unsigned: BigUint = BigInt::to_biguint(&-(&decomposition[0])).unwrap();
    //     let k1_scalar = C::ScalarField::from_le_bytes_mod_order(&k1_unsigned.to_bytes_le());
    //     P1 = -point.mul(&k1_scalar.into_repr());
    // } else {
    //     let k1_unsigned: BigUint = BigInt::to_biguint(&decomposition[0]).unwrap();
    //     let k1_scalar = C::ScalarField::from_le_bytes_mod_order(&k1_unsigned.to_bytes_le());
    //     P1 = point.mul(&k1_scalar.into_repr());
    // }

    // if Sign::Minus == decomposition[1].sign() {
    //     let k2_unsigned: BigUint = BigInt::to_biguint(&-(&decomposition[1])).unwrap();
    //     let k2_scalar = C::ScalarField::from_le_bytes_mod_order(&k2_unsigned.to_bytes_le());
    //     let p_affine= point.into_affine();
    //     let p_affine_x = AffineCurveExt::x(&p_affine);
    //     //P2 = -endomorphism::<C,F>(point, beta_raw).mul(&k2_scalar.into_repr());
    // } else {
    //     let k2_unsigned: BigUint = BigInt::to_biguint(&decomposition[1]).unwrap();
    //     let k2_scalar = C::ScalarField::from_le_bytes_mod_order(&k2_unsigned.to_bytes_le());
    //     //P2 = endomorphism::<C>(point, beta_raw).mul(&k2_scalar.into_repr());
    // }
    let answer = P1 + P2;
    answer
        todo!()
    }
}

/// Given a scalar `k` and basis vectors `v` and `u` finds integer scalars `z1` and `z2`,
/// so that `(k, 0)` is close to `z1v + z2u`
#[inline]
pub fn glv_decompose_scalar<F>(k: &F, v: (BigInt, BigInt), u: (BigInt, BigInt)) -> (BigInt, BigInt)
where
    F: PrimeField,
{
    // NOTE: We first find rational solutions to `(k,0) = q1v + q2u`
    //       We can re-write this problem as a matrix `A(q1,q2) = (k,0)`
    //       so that `(q1,q2) = A^-1(k,0)`.
    let k = BigInt::from_biguint(Sign::Plus, k.into());
    let det = (v.0 * u.1) - (v.1 * u.0);
    let q1 = (u.1 * k) / det;
    let q2 = (-v.1 * k) / det;
    let k1 = k - q1 * v.0 - q2 * u.0;
    let k2 = 0 - q1 * v.1 - q2 * u.1;
    (k1, k2)
}

///
#[inline]
fn glv_endomorphism<C>(point: &C, beta: &C::BaseField) -> C
where
    C: AffineCurveExt,
{
    C::from_xy_unchecked(*point.x() * beta, *point.y())
}

///
#[inline]
pub fn mul_glv<C>(scalar: &C::ScalarField, point: &C) -> C
//, parameters: &GLVParameters) -> C
where
    C: ProjectiveCurve,
{
    let beta_raw: BigUint = "2203960485148121921418603742825762020974279258880205651966".parse().unwrap();
    // NOTE: First generate basis vectors u and v
    let v1: BigInt = "9931322734385697763".parse().unwrap();
    let v2: BigInt = "-147946756881789319000765030803803410728".parse().unwrap();
    let mut v: Vec<BigInt> = Vec::new();
    v.push(v1);
    v.push(v2);

    // NOTE: Components for second basis vector u:
    let u1: BigInt = "147946756881789319010696353538189108491".parse().unwrap();
    let u2: BigInt = "9931322734385697763".parse().unwrap();
    let mut u: Vec<BigInt> = Vec::new();
    u.push(u1);
    u.push(u2);

    let decomposition = decompose_scalar::<C>(&scalar, v, u);

    // NOTE: Check sign for k1
    let mut P1 = C::zero();
    let mut P2 = C::zero().into_affine();
    if Sign::Minus == decomposition[0].sign() {
        let k1_unsigned: BigUint = BigInt::to_biguint(&-(&decomposition[0])).unwrap();
        let k1_scalar = C::ScalarField::from_le_bytes_mod_order(&k1_unsigned.to_bytes_le());
        P1 = -point.mul(&k1_scalar.into_repr());
    } else {
        let k1_unsigned: BigUint = BigInt::to_biguint(&decomposition[0]).unwrap();
        let k1_scalar = C::ScalarField::from_le_bytes_mod_order(&k1_unsigned.to_bytes_le());
        P1 = point.mul(&k1_scalar.into_repr());
    }
    //Check sign for k2
    if Sign::Minus == decomposition[1].sign() {
        let k2_unsigned: BigUint = BigInt::to_biguint(&-(&decomposition[1])).unwrap();
        let k2_scalar = C::ScalarField::from_le_bytes_mod_order(&k2_unsigned.to_bytes_le());
        let p_affine= point.into_affine();
        let p_affine_x = AffineCurveExt::x(&p_affine);
        //P2 = -endomorphism::<C,F>(point, beta_raw).mul(&k2_scalar.into_repr());
    } else {
        let k2_unsigned: BigUint = BigInt::to_biguint(&decomposition[1]).unwrap();
        let k2_scalar = C::ScalarField::from_le_bytes_mod_order(&k2_unsigned.to_bytes_le());
        //P2 = endomorphism::<C>(point, beta_raw).mul(&k2_scalar.into_repr());
    }
    let answer = P1 + P2;
    answer
}
