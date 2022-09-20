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
use alloc::{vec, vec::Vec};
use ark_ff::{BigInteger, Field};
use core::str::FromStr;
use num_bigint::{BigInt, BigUint, Sign};

#[cfg(feature = "ark-bls12-381")]
use crate::arkworks::bls12_381;

#[cfg(feature = "ark-bn254")]
use crate::arkworks::bn254;

/// Affine Curve Extension
pub trait AffineCurveExt: AffineCurve {
    /// Returns the `x` coordinate of `self`.
    fn x(&self) -> &Self::BaseField;

    /// Returns the `y` coordinate of `self`.
    fn y(&self) -> &Self::BaseField;

    /// Builds [`Self`] from `x` and `y`.
    fn from_xy_unchecked(x: Self::BaseField, y: Self::BaseField) -> Self;

    /// Applies the GLV endomorphism to `self`.
    #[inline]
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
/// so that `(k, 0)` is close to `k1v + k2u`, meaning the norm of the difference `||(k,0) - (k1v + k2u)||`
/// is at most `max(||v||, ||u||)`.
#[inline]
pub fn decompose_scalar<F>(k: &F, v: (&BigInt, &BigInt), u: (&BigInt, &BigInt)) -> (BigInt, BigInt)
where
    F: PrimeField,
{
    let k = BigInt::from_bytes_be(Sign::Plus, &k.into_repr().to_bytes_be());
    let q1 = (u.1 * &k) / ((v.0 * u.1) - (v.1 * u.0));
    let q2 = (-v.1 * &k) / ((v.0 * u.1) - (v.1 * u.0));
    let k1 = k - &q1 * v.0 - &q2 * u.0;
    let k2 = 0 - q1 * v.1 - q2 * u.1;
    (k1, k2)
}

/// GLV Parameters
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
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

    /// Creates a new instance of [`GLVParameters`] from the curve parameters.
    #[inline]
    pub fn new<M>() -> Self
    where
        C: HasGLV<M>,
    {
        C::glv_parameters()
    }

    /// Returns a reference to `beta`.
    #[inline]
    pub fn beta(&self) -> &C::BaseField {
        &self.beta
    }

    /// Returns `beta`, dropping `self`.
    #[inline]
    pub fn into_beta(self) -> C::BaseField {
        self.beta
    }

    /// Returns a reference to the basis elements.
    #[inline]
    pub fn basis(&self) -> ((&BigInt, &BigInt), (&BigInt, &BigInt)) {
        (
            (&self.base_v1.0, &self.base_v1.1),
            (&self.base_v2.0, &self.base_v2.1),
        )
    }

    /// Generates scalars and points for the simultaneous multiple
    /// point multiplication.
    #[inline]
    fn scalars_and_points(
        &self,
        point: &C,
        scalar: &C::ScalarField,
    ) -> (Vec<bool>, Vec<bool>, C::Projective, C::Projective)
    where
        C: AffineCurveExt,
    {
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
    fn simultaneous_multiple_point_multiplication(
        u: Vec<bool>,
        v: Vec<bool>,
        p: C::Projective,
        q: C::Projective,
    ) -> C {
        let table = vec![C::zero().into_projective(), p, q, p + q];
        let mut r = C::zero().into_projective();
        for i in 0..u.len() {
            r.double_in_place();
            r += table[u[i] as usize + 2 * (v[i] as usize)]
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

/// HasGLV Trait
pub trait HasGLV<M>: AffineCurve {
    /// Generates [`GLVParameters`] from some precomputed parameters encoded
    /// in the marker type `M`.
    fn glv_parameters() -> GLVParameters<Self>;
}

#[cfg(feature = "ark-bls12-381")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "ark-bls12-381")))]
impl HasGLV<bls12_381::Parameters> for bls12_381::G1Affine {
    #[inline]
    fn glv_parameters() -> GLVParameters<Self> {
        let beta = <bls12_381::G1Affine as AffineCurve>::BaseField::from_random_bytes(
            &"793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350"
            .parse::<BigUint>()
            .unwrap()
            .to_bytes_le()
        )
        .unwrap();
        let base_v1 = (
            BigInt::from_str("1").unwrap(),
            BigInt::from_str("-228988810152649578064853576960394133503").unwrap(),
        );
        let base_v2 = (
            BigInt::from_str("228988810152649578064853576960394133504").unwrap(),
            BigInt::from_str("1").unwrap(),
        );
        GLVParameters::new_unchecked(beta, base_v1, base_v2)
    }
}

#[cfg(feature = "ark-bn254")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "ark-bn254")))]
impl HasGLV<bn254::Parameters> for bn254::G1Affine {
    #[inline]
    fn glv_parameters() -> GLVParameters<Self> {
        let beta = <bn254::G1Affine as AffineCurve>::BaseField::from_random_bytes(
            &"21888242871839275220042445260109153167277707414472061641714758635765020556616"
                .parse::<BigUint>()
                .unwrap()
                .to_bytes_le(),
        )
        .unwrap();
        let base_v1 = (
            BigInt::from_str("147946756881789319000765030803803410728").unwrap(),
            BigInt::from_str("-9931322734385697763").unwrap(),
        );
        let base_v2 = (
            BigInt::from_str("9931322734385697763").unwrap(),
            BigInt::from_str("147946756881789319010696353538189108491").unwrap(),
        );
        GLVParameters::<Self>::new_unchecked(beta, base_v1, base_v2)
    }
}

/// Testing Suite
#[cfg(test)]
pub mod test {
    use super::*;
    use crate::rand::RngCore;
    use ark_ff::UniformRand;
    use rand_core::OsRng;

    /// Parses the GLV parameters from strings.
    #[inline]
    pub fn parse_glv_parameters<C>(glv_parameters: [&str; 5]) -> GLVParameters<C>
    where
        C: AffineCurveExt,
    {
        let beta = C::BaseField::from_random_bytes(
            &glv_parameters[0].parse::<BigUint>().unwrap().to_bytes_le(),
        )
        .unwrap();
        let base_v1 = (
            BigInt::from_str(glv_parameters[1]).unwrap(),
            BigInt::from_str(glv_parameters[2]).unwrap(),
        );
        let base_v2 = (
            BigInt::from_str(glv_parameters[3]).unwrap(),
            BigInt::from_str(glv_parameters[4]).unwrap(),
        );
        GLVParameters::<C>::new_unchecked(beta, base_v1, base_v2)
    }

    /// Checks the GLV parameters of BLS12 and BN254 match the hardcoded sage outputs.
    #[test]
    fn bls_glv_parameters_match() {
        let bls_hardcoded_parameters = parse_glv_parameters::<bls12_381::G1Affine>(include!(
            "precomputed_glv_values/bls_values"
        ));
        let bls_parameters = bls12_381::G1Affine::glv_parameters();
        assert_eq!(bls_hardcoded_parameters, bls_parameters);
    }

    /// Checks the GLV parameters of BN254 match the hardcoded sage outputs.
    #[test]
    fn bn_glv_parameters_match() {
        let bn_hardcoded_parameters =
            parse_glv_parameters::<bn254::G1Affine>(include!("precomputed_glv_values/bn_values"));
        let bn_parameters = bn254::G1Affine::glv_parameters();
        assert_eq!(bn_hardcoded_parameters, bn_parameters);
    }

    /// Checks the GLV scalar multiplication gives the expected result for the curve `C`.
    #[inline]
    pub fn glv_is_correct<C, R, M>(rng: &mut R)
    where
        C: AffineCurveExt + HasGLV<M>,
        R: RngCore + ?Sized,
    {
        let scalar = C::ScalarField::rand(rng);
        let point = C::Projective::rand(rng).into_affine();
        let glv = C::glv_parameters();
        assert_eq!(
            glv.scalar_mul(&point, &scalar),
            point.mul(scalar).into_affine()
        );
    }

    /// Checks the implementation of GLV for BLS is correct.
    #[test]
    fn glv_bls_is_correct() {
        glv_is_correct::<bls12_381::G1Affine, _, _>(&mut OsRng)
    }

    /// Checks the implementation of GLV for BN is correct.
    #[test]
    fn glv_bn_is_correct() {
        glv_is_correct::<bn254::G1Affine, _, _>(&mut OsRng);
    }
}
