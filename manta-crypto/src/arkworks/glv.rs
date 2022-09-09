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
use alloc::vec::Vec;
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

    /// Applies the GLV endomorphism to `self`
    fn glv_endomorphism(&self, beta: &Self::BaseField) -> Self {
        Self::from_xy_unchecked(*self.x() * beta, *self.y())
    }
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

    /// Generate scalars and points for the simultaneous multiple
    /// point multiplication
    #[inline]
    fn scalars_and_points(&self, point: &C, scalar: &C::ScalarField) -> (Vec<bool>, Vec<bool>, C::Projective, C::Projective)
    where
        C: AffineCurveExt,
    {
        // TODO: make sure both output vectors have the same length. I guess into_repr and
        // to_bits_be() do that already?
        let (k1, k2) = decompose_scalar(scalar, self.basis().0, self.basis().1);
        let (k1_sign, k1) = k1.into_parts();
        let p1 = match k1_sign {
            Sign::Minus => -*point,
            _ => *point,
        };
        let (k2_sign, k2) = k2.into_parts();
        let p2 = match k2_sign {
            Sign::Minus => -point.glv_endomorphism(&self.beta),
            _ => point.glv_endomorphism(&self.beta),
        };
        (
            C::ScalarField::from_le_bytes_mod_order(&k1.to_bytes_le())
                .into_repr()
                .to_bits_be(),
            C::ScalarField::from_le_bytes_mod_order(&k2.to_bytes_le())
                .into_repr()
                .to_bits_be(),
            p1.into_projective(),
            p2.into_projective(),
        )
    }

    /// Executes a simulatenous multiple point multiplication without windowing.
    #[inline]
    fn simultaneous_multiple_point_multiplication(u: Vec<bool>, v: Vec<bool>, p: C::Projective, q: C::Projective) -> C {
        // TODO: implement windowing.
        let mut table = Vec::with_capacity(4);
        table.push(C::zero().into_projective());
        table.push(p);
        table.push(q);
        table.push(p + q);
        let mut r = C::zero().into_projective();
        for i in 0..u.len() {
            ProjectiveCurve::double_in_place(& mut r);
            r = r + table[u[i] as usize + 2 * (v[i] as usize)]
        }
        r.into_affine()
    }

    /// Multiplies `point` by `scalar` using the GLV method.
    #[inline]
    pub fn scalar_mul(&self, point: &C, scalar: &C::ScalarField) -> C
    where
        C: AffineCurveExt,
    {
        let (k1, k2, p1, p2) = self.scalars_and_points(point, scalar);
        Self::simultaneous_multiple_point_multiplication(k1, k2, p1, p2)
    }
}
