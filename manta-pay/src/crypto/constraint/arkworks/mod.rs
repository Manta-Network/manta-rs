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

//! Arkworks Constraint System and Proof System Implementations

use manta_crypto::{
    arkworks::{
        constraint::FpVar,
        ff::{Fp, FpParameters, PrimeField},
        r1cs_std::{
            alloc::AllocVar, eq::EqGadget, fields::FieldVar, select::CondSelectGadget, ToBitsGadget,
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
        ops::{Add, BitAnd, BitOr},
        Has, NonNative,
    },
};

pub use manta_crypto::arkworks::{
    r1cs_std::bits::boolean::Boolean, relations::r1cs::SynthesisError,
};

pub mod codec;

/// Synthesis Result
pub type SynthesisResult<T = ()> = Result<T, SynthesisError>;

/// Returns an empty variable assignment for setup mode.
///
/// # Warning
///
/// This does not work for all variable assignments! For some assignemnts, the variable inherits
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

/// Testing Suite
#[cfg(test)]
mod tests {
    // TODO: move to constraint with R1CS
    use super::*;
    use core::iter::repeat_with;
    use manta_crypto::{
        arkworks::{bls12_381::Fr, ff::BigInteger},
        eclair::alloc::Allocate,
        rand::{OsRng, Rand, RngCore},
    };

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
            "on value {:?}, expect satisfied = {}, but got {}",
            value, should_pass, satisfied
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
