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

//! Arkworks Elliptic Curve Implementation

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

/// Given a scalar `k` and basis vectors `v` and `u` finds integer scalars `k1` and `k2`,
/// so that `(k, 0)` is close to `k1v + k2u`
/// TODO: Check the bit length of BitInt v.s. BaseField or ScalarField. See if there is any overflow issue.
#[inline]
pub fn decompose_scalar<F>(k: &F, v: (&BigInt, &BigInt), u: (&BigInt, &BigInt)) -> (BigInt, BigInt)
where
    F: PrimeField,
{
    // NOTE: We first find rational solutions to `(k,0) = q1v + q2u`
    //       We can re-write this problem as a matrix `A(q1,q2) = (k,0)`
    //       so that `(q1,q2) = A^-1(k,0)`.
    let k = BigInt::from_bytes_be(Sign::Plus, &k.into_repr().to_bytes_be());
    let q1 = (u.1 * &k) / ((v.0 * u.1) - (v.1 * u.0));
    let q2 = (-v.1 * &k) / ((v.0 * u.1) - (v.1 * u.0));
    let k1 = k - &q1 * v.0 - &q2 * u.0;
    let k2 = 0 - q1 * v.1 - q2 * u.1;
    (k1, k2)
}

/// GLV Parameters
pub struct GLVParameters<C>
where
    C: AffineCurve,
{
    /// Endomorphism-defining Element
    pub beta: C::BaseField,

    /// Basis Element
    pub base_v1: (BigInt, BigInt),

    /// Basis Element
    pub base_v2: (BigInt, BigInt),
}

impl<C> GLVParameters<C>
where
    C: AffineCurve,
{
    /// Creates a new instance of [`GLVParameters`] without checking that `base_v1` and `base_v2` form a
    /// basis of the kernel of the function defined by the root of the characteristic polynomial
    /// of the endomorphism associated with `beta`.
    #[inline]
    pub fn new_unchecked(
        beta: C::BaseField,
        base_v1: (BigInt, BigInt),
        base_v2: (BigInt, BigInt),
    ) -> Self {
        Self {
            beta,
            base_v1,
            base_v2,
        }
    }

    /// Returns a reference to `beta`.
    pub fn beta(&self) -> &C::BaseField {
        &self.beta
    }

    /// Returns `beta`, dropping `self`.
    pub fn into_beta(self) -> C::BaseField {
        self.beta
    }

    /// Returns a reference to the basis elements.
    pub fn basis(&self) -> ((&BigInt, &BigInt), (&BigInt, &BigInt)) {
        (
            (&self.base_v1.0, &self.base_v1.1),
            (&self.base_v2.0, &self.base_v2.1),
        )
    }

    /// Multiplies `point` by `scalar` using the GLV method.
    #[inline]
    pub fn scalar_mul(&self, point: &C, scalar: &C::ScalarField) -> C
    where
        C: AffineCurveExt,
    {
        let (k1, k2) = decompose_scalar(scalar, self.basis().0, self.basis().1);
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

/// Multiplies the `x` coordinate of `point` by `beta`.
#[inline]
fn glv_endomorphism<C>(point: &C, beta: &C::BaseField) -> C
where
    C: AffineCurveExt,
{
    C::from_xy_unchecked(*point.x() * beta, *point.y())
}
