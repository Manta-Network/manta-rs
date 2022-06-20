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

//! Poseidon Arkworks Backend

use crate::crypto::{
    constraint::arkworks::{Fp, FpVar, R1CS},
    poseidon::FieldGeneration,
};
use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
use ark_r1cs_std::fields::FieldVar;
use manta_crypto::constraint::Constant;

/// Compiler Type.
type Compiler<S> = R1CS<<S as Specification>::Field>;

/// Poseidon Permutation Specification.
pub trait Specification {
    /// Field Type
    type Field: PrimeField;

    /// Width of the Permutation
    ///
    /// This number is the total number `t` of field elements in the state which is `F^t`.
    const WIDTH: usize;

    /// Number of Partial Rounds
    const PARTIAL_ROUNDS: usize;

    /// Number of Full Rounds
    ///
    /// The total number of full rounds in the Poseidon permutation, including the first set of
    /// full rounds and then the second set after the partial rounds.
    const FULL_ROUNDS: usize;

    /// S-BOX Exponenet
    const SBOX_EXPONENT: u64;
}

impl<F> super::Field for Fp<F>
where
    F: PrimeField,
{
    #[inline]
    fn zero() -> Self {
        Self(F::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0 == F::zero()
    }

    #[inline]
    fn one() -> Self {
        Self(F::one())
    }

    #[inline]
    fn add(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }

    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }

    #[inline]
    fn sub(&self, rhs: &Self) -> Self {
        Self(self.0 - rhs.0)
    }

    #[inline]
    fn mul(&self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }

    #[inline]
    fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Self)
    }
}

impl<F> FieldGeneration for Fp<F>
where
    F: PrimeField,
{
    const MODULUS_BITS: usize = F::Params::MODULUS_BITS as usize;

    #[inline]
    fn try_from_bits_be(bits: &[bool]) -> Option<Self> {
        F::from_repr(F::BigInt::from_bits_be(bits)).map(Self)
    }

    #[inline]
    fn from_u64(elem: u64) -> Self {
        Self(F::from(elem))
    }
}

impl<S> super::Specification for S
where
    S: Specification,
{
    type Field = Fp<S::Field>;
    type ParameterField = Fp<S::Field>;

    const WIDTH: usize = S::WIDTH;
    const FULL_ROUNDS: usize = S::FULL_ROUNDS;
    const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

    #[inline]
    fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
        Fp(lhs.0 + rhs.0)
    }

    #[inline]
    fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
        Fp(lhs.0 + rhs.0)
    }

    #[inline]
    fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
        Fp(lhs.0 * rhs.0)
    }

    #[inline]
    fn mul_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
        Fp(lhs.0 * rhs.0)
    }

    #[inline]
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut ()) {
        lhs.0 += rhs.0;
    }

    #[inline]
    fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, _: &mut ()) {
        lhs.0 += rhs.0;
    }

    #[inline]
    fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
        point.0 = point.0.pow(&[Self::SBOX_EXPONENT, 0, 0, 0]);
    }
}

impl<S> super::Specification<Compiler<S>> for S
where
    S: Specification,
{
    type Field = FpVar<S::Field>;
    type ParameterField = Fp<S::Field>;

    const WIDTH: usize = S::WIDTH;
    const FULL_ROUNDS: usize = S::FULL_ROUNDS;
    const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

    #[inline]
    fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) -> Self::Field {
        lhs + rhs
    }

    #[inline]
    fn add_const(
        lhs: &Self::Field,
        rhs: &Self::ParameterField,
        _: &mut Compiler<S>,
    ) -> Self::Field {
        lhs + FpVar::Constant(rhs.0)
    }

    #[inline]
    fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) -> Self::Field {
        lhs * rhs
    }

    #[inline]
    fn mul_const(
        lhs: &Self::Field,
        rhs: &Self::ParameterField,
        _: &mut Compiler<S>,
    ) -> Self::Field {
        lhs * FpVar::Constant(rhs.0)
    }

    #[inline]
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) {
        *lhs += rhs;
    }

    #[inline]
    fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, _: &mut Compiler<S>) {
        *lhs += FpVar::Constant(rhs.0)
    }

    #[inline]
    fn apply_sbox(point: &mut Self::Field, _: &mut Compiler<S>) {
        *point = point
            .pow_by_constant(&[Self::SBOX_EXPONENT])
            .expect("Exponentiation is not allowed to fail.");
    }
}

impl<S> Constant<Compiler<S>> for super::Permutation<S, Compiler<S>>
where
    S: Specification,
{
    type Type = super::Permutation<S>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler<S>) -> Self {
        let _ = compiler;
        Self {
            additive_round_keys: this.additive_round_keys.clone(),
            mds_matrix: this.mds_matrix.clone(),
        }
    }
}
