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

//! Arkworks Constraint-System Backends

use crate::{
    arkworks::{
        algebra::modulus_is_smaller,
        constraint::fp::Fp,
        ff::{BigInteger, FpParameters, PrimeField},
        r1cs_std::{
            alloc::AllocVar, eq::EqGadget, fields::FieldVar, select::CondSelectGadget, R1CSVar,
            ToBitsGadget,
        },
        relations::{
            ns,
            r1cs::{
                ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
                SynthesisMode,
            },
        },
    },
    constraint::measure::{Count, Measure},
    eclair::{
        self,
        alloc::{
            mode::{self, Public, Secret},
            Constant, Variable,
        },
        bool::{Assert, ConditionalSelect, ConditionalSwap},
        num::{AssertWithinBitRange, Zero},
        ops::{Add, BitAnd, BitOr, Rem},
        Has, NonNative,
    },
};
use core::marker::PhantomData;
use num_integer::Integer;

pub use crate::arkworks::{
    r1cs_std::{bits::boolean::Boolean, fields::fp::FpVar},
    relations::r1cs::SynthesisError,
};

pub mod fp;

/// Synthesis Result
pub type SynthesisResult<T = ()> = Result<T, SynthesisError>;

/// Returns an empty variable assignment for setup mode.
///
/// # Warning
///
/// This does not work for all variable assignments! For some assignments, the variable inherits
/// some structure from its input, like its length or number of bits, which are only known at
/// run-time. For those cases, some mocking is required and this function can not be used directly.
#[inline]
pub fn empty<T>() -> SynthesisResult<T> {
    Err(SynthesisError::AssignmentMissing)
}

/// Returns a filled variable assignment with the given `value`.
#[inline]
pub fn full<T>(value: T) -> impl FnOnce() -> SynthesisResult<T> {
    move || Ok(value)
}

/// Conditionally select from `lhs` and `rhs` depending on the value of `bit`.
#[inline]
pub fn conditionally_select<F, T>(bit: &Boolean<F>, lhs: &T, rhs: &T) -> T
where
    F: PrimeField,
    T: CondSelectGadget<F>,
{
    CondSelectGadget::conditionally_select(bit, lhs, rhs)
        .expect("Conditionally selecting from two values is not allowed to fail.")
}

/// Arkworks Rank-1 Constraint System
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct R1CS<F>(ConstraintSystemRef<F>)
where
    F: PrimeField;

impl<F> R1CS<F>
where
    F: PrimeField,
{
    /// Builds a new [`R1CS`] constraint system from `constraint_system` without checking its
    /// optimization goal or synthesis mode.
    #[inline]
    pub fn new_unchecked(constraint_system: ConstraintSystemRef<F>) -> Self {
        Self(constraint_system)
    }

    /// Constructs a new constraint system which is ready for unknown variables.
    #[inline]
    pub fn for_contexts() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let constraint_system = ConstraintSystem::new_ref();
        constraint_system.set_optimization_goal(OptimizationGoal::Constraints);
        constraint_system.set_mode(SynthesisMode::Setup);
        Self::new_unchecked(constraint_system)
    }

    /// Constructs a new constraint system which is ready for known variables.
    #[inline]
    pub fn for_proofs() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let constraint_system = ConstraintSystem::new_ref();
        constraint_system.set_optimization_goal(OptimizationGoal::Constraints);
        Self::new_unchecked(constraint_system)
    }

    /// Check if all constraints are satisfied.
    #[inline]
    pub fn is_satisfied(&self) -> bool {
        self.0
            .is_satisfied()
            .expect("Checking circuit satisfaction is not allowed to fail.")
    }
}

impl<F> AsRef<ConstraintSystemRef<F>> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn as_ref(&self) -> &ConstraintSystemRef<F> {
        &self.0
    }
}

impl<F> NonNative for R1CS<F> where F: PrimeField {}

impl<F> Has<bool> for R1CS<F>
where
    F: PrimeField,
{
    type Type = Boolean<F>;
}

impl<F> Assert for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn assert(&mut self, b: &Boolean<F>) {
        b.enforce_equal(&Boolean::TRUE)
            .expect("Enforcing equality is not allowed to fail.");
    }
}

impl<F> Count<mode::Constant> for R1CS<F> where F: PrimeField {}

impl<F> Count<Public> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn count(&self) -> Option<usize> {
        Some(self.0.num_instance_variables())
    }
}

impl<F> Count<Secret> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn count(&self) -> Option<usize> {
        Some(self.0.num_witness_variables())
    }
}

impl<F> Measure for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn constraint_count(&self) -> usize {
        self.0.num_constraints()
    }
}

impl<F> ConstraintSynthesizer<F> for R1CS<F>
where
    F: PrimeField,
{
    /// Generates constraints for `self` by copying them into `cs`. This method is necessary to hook
    /// into the proof system traits defined in `arkworks`.
    #[inline]
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> SynthesisResult {
        let precomputed_cs = self
            .0
            .into_inner()
            .expect("We own this constraint system so we can consume it.");
        let mut target_cs = cs
            .borrow_mut()
            .expect("This is given to us to mutate so it can't be borrowed by anyone else.");
        *target_cs = precomputed_cs;
        Ok(())
    }
}

impl<F> Constant<R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        AllocVar::new_constant(ns!(compiler.0, "boolean constant"), this)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Public, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.0, "boolean public input"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.0, "boolean public input"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.0, "boolean secret witness"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.0, "boolean secret witness"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> BitAnd<Self, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self, compiler: &mut R1CS<F>) -> Self::Output {
        let _ = compiler;
        self.and(&rhs).expect("Bitwise AND is not allowed to fail.")
    }
}

impl<F> BitOr<Self, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self, compiler: &mut R1CS<F>) -> Self::Output {
        let _ = compiler;
        self.or(&rhs).expect("Bitwise OR is not allowed to fail.")
    }
}

impl<F> eclair::cmp::PartialEq<Self, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        self.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F, const BITS: usize> AssertWithinBitRange<FpVar<F>, BITS> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn assert_within_range(&mut self, value: &FpVar<F>) {
        assert!(
            BITS < F::Params::MODULUS_BITS as usize,
            "BITS must be strictly less than modulus bits of `F`."
        );
        let value_bits = value
            .to_bits_le()
            .expect("Bit decomposition is not allowed to fail.");
        for bit in &value_bits[BITS..] {
            bit.enforce_equal(&Boolean::FALSE)
                .expect("Enforcing equality is not allowed to fail.");
        }
    }
}

impl<F> Constant<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        AllocVar::new_constant(ns!(compiler.0, "field constant"), this.0)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Constant<R1CS<F>> for Fp<F>
where
    F: PrimeField,
{
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        *this
    }
}

impl<F> Variable<Public, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.0, "field public input"), full(this.0))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.0, "field public input"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.0, "field secret witness"), full(this.0))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.0, "field secret witness"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> eclair::cmp::PartialEq<Self, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        self.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> ConditionalSelect<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn select(
        bit: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
        compiler: &mut R1CS<F>,
    ) -> Self {
        let _ = compiler;
        conditionally_select(bit, true_value, false_value)
    }
}

impl<F> ConditionalSwap<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn swap(bit: &Boolean<F>, lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> (Self, Self) {
        let _ = compiler;
        (
            conditionally_select(bit, rhs, lhs),
            conditionally_select(bit, lhs, rhs),
        )
    }
}

impl<F> Add<Self, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self, compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        self + rhs
    }
}

impl<F> Zero<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Verification = Boolean<F>;

    #[inline]
    fn zero(compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        FieldVar::zero()
    }

    #[inline]
    fn is_zero(&self, compiler: &mut R1CS<F>) -> Self::Verification {
        let _ = compiler;
        FieldVar::is_zero(self).expect("Comparison with zero is not allowed to fail.")
    }
}

/// Prime Modulus
#[derive(derivative::Derivative)]
#[derivative(Clone(clone_trait = "::std::clone::Clone"))]
#[derivative(Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct PrimeModulus<F>(PhantomData<F>)
where
    F: PrimeField;

impl<F, R> Rem<PrimeModulus<R>, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
    R: PrimeField,
{
    type Output = FpVar<F>;

    #[inline]
    fn rem(self, rhs: PrimeModulus<R>, compiler: &mut R1CS<F>) -> Self::Output {
        let _ = (rhs, compiler);
        assert!(
            modulus_is_smaller::<R, F>(),
            "The modulus of the embedded scalar field is larger than that of the constraint field."
        );
        let (quotient, remainder) = match self.value() {
            Ok(value) => {
                let (quotient, remainder) = div_rem_mod_prime::<F, R>(value);
                (
                    FpVar::new_witness(self.cs(), full(quotient))
                        .expect("Allocating a witness is not allowed to fail."),
                    FpVar::new_witness(
                        self.cs(),
                        full(F::from_le_bytes_mod_order(&remainder.to_bytes_le())),
                    )
                    .expect("Allocating a witness is not allowed to fail."),
                )
            }
            _ => (
                FpVar::new_witness(self.cs(), empty::<F>)
                    .expect("Allocating a witness is not allowed to fail."),
                FpVar::new_witness(self.cs(), empty::<F>)
                    .expect("Allocating a witness is not allowed to fail."),
            ),
        };
        let modulus = FpVar::Constant(F::from_le_bytes_mod_order(
            &<R::Params as FpParameters>::MODULUS.to_bytes_le(),
        ));
        self.enforce_equal(&(quotient * &modulus + &remainder))
            .expect("This equality holds because of the Euclidean algorithm.");
        remainder
            .enforce_cmp(&modulus, core::cmp::Ordering::Less, false)
            .expect("This inequality holds because of the Euclidean algorithm.");
        remainder
    }
}

/// Divides `value` by the modulus of the [`PrimeField`] `R` and returns the quotient and
/// the remainder.
#[inline]
pub fn div_rem_mod_prime<F, R>(value: F) -> (F, R::BigInt)
where
    F: PrimeField,
    R: PrimeField,
{
    let modulus = <R::Params as FpParameters>::MODULUS;
    let (quotient, remainder) = value.into_repr().into().div_rem(&modulus.into());
    (
        F::from_le_bytes_mod_order(
            &F::BigInt::try_from(quotient)
                .ok()
                .expect("Unable to compute modular reduction.")
                .to_bytes_le(),
        ),
        R::BigInt::try_from(remainder)
            .ok()
            .expect("Unable to compute modular reduction."),
    )
}

/// Returns the remainder of `value` divided by the modulus of the [`PrimeField`] `R`.
#[inline]
pub fn rem_mod_prime<F, R>(value: F) -> R
where
    F: PrimeField,
    R: PrimeField,
{
    R::from_repr(div_rem_mod_prime::<F, R>(value).1)
        .expect("This element is guaranteed to be within the modulus.")
}

/// Testing Suite
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arkworks::{bn254::Fr, ff::BigInteger},
        eclair::alloc::Allocate,
        rand::{OsRng, Rand, RngCore},
    };
    use alloc::vec::Vec;
    use core::iter::repeat_with;

    /// Checks if `assert_within_range` passes when `should_pass` is `true` and fails when
    /// `should_pass` is `false`.
    #[inline]
    fn check_assert_within_range<F, const BITS: usize>(value: Fp<F>, should_pass: bool)
    where
        F: PrimeField,
    {
        let mut cs = R1CS::<F>::for_proofs();
        let variable = value.as_known::<Secret, FpVar<_>>(&mut cs);
        AssertWithinBitRange::<_, BITS>::assert_within_range(&mut cs, &variable);
        let satisfied = cs.is_satisfied();
        assert_eq!(
            should_pass, satisfied,
            "on value {value:?}, expect satisfied = {should_pass}, but got {satisfied}",
        );
    }

    /// Samples a field element with fewer than `BITS`-many bits using `rng`.
    #[inline]
    fn sample_smaller_than<R, F, const BITS: usize>(rng: &mut R) -> Fp<F>
    where
        R: RngCore + ?Sized,
        F: PrimeField,
    {
        Fp(F::from_repr(F::BigInt::from_bits_le(
            &repeat_with(|| rng.gen()).take(BITS).collect::<Vec<_>>(),
        ))
        .expect("BITS should be less than modulus bits of field."))
    }

    /// Samples a field element larger than `bound` using `rng`.
    #[inline]
    fn sample_larger_than<R, F>(bound: &Fp<F>, rng: &mut R) -> Fp<F>
    where
        R: RngCore + ?Sized,
        F: PrimeField,
    {
        let mut value = rng.gen();
        while &value <= bound {
            value = rng.gen();
        }
        value
    }

    /// Checks if [`assert_within_range`] works correctly for `BITS`-many bits with `ROUNDS`-many
    /// tests for less than the range and more than the range.
    #[inline]
    fn test_assert_within_range<R, F, const BITS: usize, const ROUNDS: usize>(rng: &mut R)
    where
        R: RngCore + ?Sized,
        F: PrimeField,
    {
        let bound = Fp(F::from(2u64).pow([BITS as u64]));
        check_assert_within_range::<_, BITS>(Fp(F::zero()), true);
        check_assert_within_range::<_, BITS>(Fp(bound.0 - F::one()), true);
        check_assert_within_range::<_, BITS>(bound, false);
        for _ in 0..ROUNDS {
            check_assert_within_range::<_, BITS>(sample_smaller_than::<_, F, BITS>(rng), true);
            check_assert_within_range::<_, BITS>(sample_larger_than(&bound, rng), false);
        }
    }

    /// Tests if `assert_within_range` works correctly for U8, U16, U32, U64, and U128.
    #[test]
    fn assert_within_range_is_correct() {
        let mut rng = OsRng;
        test_assert_within_range::<_, Fr, 8, 32>(&mut rng);
        test_assert_within_range::<_, Fr, 16, 32>(&mut rng);
        test_assert_within_range::<_, Fr, 32, 32>(&mut rng);
        test_assert_within_range::<_, Fr, 64, 32>(&mut rng);
        test_assert_within_range::<_, Fr, 128, 32>(&mut rng);
    }
}
