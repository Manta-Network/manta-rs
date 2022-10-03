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

//! Elliptic Curve Cryptography Utilities

use core::ops::AddAssign;
use manta_crypto::{
    arkworks::{
        ec::{AffineCurve, ProjectiveCurve},
        ff::UniformRand,
    },
    rand::RngCore,
};

/// Samples an affine point.
#[inline]
pub fn sample_affine_point<A, R>(rng: &mut R) -> A
where
    A: AffineCurve,
    R: RngCore + ?Sized,
{
    A::Projective::rand(rng).into_affine()
}

/// Samples a projective point.
#[inline]
pub fn sample_projective_point<P, R>(rng: &mut R) -> P
where
    P: ProjectiveCurve,
    R: RngCore + ?Sized,
{
    P::rand(rng)
}

/// Samples a scalar field element.
#[inline]
pub fn sample_scalar<A, R>(rng: &mut R) -> A::ScalarField
where
    A: AffineCurve,
    R: RngCore + ?Sized,
{
    A::ScalarField::rand(rng)
}

/// Adds two affine points.
#[inline]
pub fn affine_affine_add_assign<'a, A>(lhs: &mut A, rhs: &'a A)
where
    A: AffineCurve + AddAssign<&'a A>,
{
    lhs.add_assign(rhs);
}

/// Adds a projective point with an affine point.
#[inline]
pub fn projective_affine_add_assign<P>(lhs: &mut P, rhs: &P::Affine)
where
    P: ProjectiveCurve,
{
    lhs.add_assign_mixed(rhs);
}

/// Adds two projective points.
#[inline]
pub fn projective_projective_add_assign<P>(lhs: &mut P, rhs: P)
where
    P: ProjectiveCurve,
{
    lhs.add_assign(rhs);
}

/// Multiplies an affine point `point` with a scalar field element `scalar`.
#[inline]
pub fn affine_scalar_mul<A>(point: &A, scalar: A::ScalarField) -> A::Projective
where
    A: AffineCurve,
{
    point.mul(scalar)
}

/// Multiplies a projective point `point` with a scalar field element `scalar`.
#[inline]
pub fn projective_scalar_mul_assign<P>(point: &mut P, scalar: P::ScalarField)
where
    P: ProjectiveCurve,
{
    point.mul_assign(scalar);
}

/// Normalizes a projective point into an affine point.
#[inline]
pub fn projective_to_affine_normalization<P>(point: &P) -> P::Affine
where
    P: ProjectiveCurve,
{
    point.into_affine()
}

/// Normalizes each projective point of `point_vec` into an affine point with the batching optimization.
#[inline]
pub fn batch_vector_projective_to_affine_normalization<P>(point_vec: &[P]) -> Vec<P::Affine>
where
    P: ProjectiveCurve,
{
    P::batch_normalization_into_affine(point_vec)
}

/// Naively normalizes each projective point of `point_vec` into an affine point without the batching optimization.
#[inline]
pub fn naive_vector_projective_to_affine_normalization<P>(point_vec: &[P]) -> Vec<P::Affine>
where
    P: ProjectiveCurve,
{
    point_vec.iter().map(P::into_affine).collect()
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use manta_crypto::{arkworks::bls12_381::G1Affine, rand::OsRng};

    /// Tests if affine-affine addition, affine-projective addition, and projective-projective
    /// addition give same results.
    #[test]
    fn addition_is_consistent_for_projective_and_affine_curve() {
        let mut rng = OsRng;
        let mut lhs_affine = sample_affine_point::<G1Affine, _>(&mut rng);
        let mut lhs_projective = lhs_affine.into_projective();
        let mut lhs_projective_clone = lhs_projective;
        let rhs_affine = sample_affine_point::<G1Affine, _>(&mut rng);
        affine_affine_add_assign(&mut lhs_affine, &rhs_affine);
        projective_affine_add_assign(&mut lhs_projective, &rhs_affine);
        projective_projective_add_assign(&mut lhs_projective_clone, rhs_affine.into_projective());
        assert_eq!(
            lhs_affine, lhs_projective,
            "Addition is not consistent for affine curve and projective curve."
        );
        assert_eq!(
            lhs_affine, lhs_projective_clone,
            "Addition is not consistent for affine curve and projective curve."
        );
    }

    /// Tests if affine-scalar multiplication and projective-scalar multiplication give
    /// same results.
    #[test]
    fn multiplication_is_consistent_for_projective_and_affine_curve() {
        let mut rng = OsRng;
        let lhs_affine = sample_affine_point::<G1Affine, _>(&mut rng);
        let mut lhs_projective = lhs_affine.into_projective();
        let scalar = sample_scalar::<G1Affine, _>(&mut rng);
        let out_projective = affine_scalar_mul(&lhs_affine, scalar);
        projective_scalar_mul_assign(&mut lhs_projective, scalar);
        assert_eq!(
            out_projective, lhs_projective,
            "Multiplication is not consistent between projective curve and affine curve."
        );
    }
}
