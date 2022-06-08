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

//! Constraint Systems and Proof Systems

// FIXME: Leverage the type system to constrain allocation to only unknown modes for verifier
//        generation and only known modes for proof generation, instead of relying on the `for_*`
//        methods to "do the right thing".
// TODO:  Find ways to enforce public input structure, since it's very easy to extend the input
//        vector by the wrong amount or in the wrong order.

use crate::rand::{CryptoRng, RngCore};

pub use crate::eclair::{
    alloc::{
        mode::{self, Derived, Public, Secret},
        Allocate, Allocator, Const, Constant, Var, Variable,
    },
    cmp::{Eq, HasBool, PartialEq},
    ops::{Add, Assert, AssertEq, Not, Sub},
    Native,
};

/// Constraint System
pub trait ConstraintSystem {
    /* TODO:
    /// Boolean Variable Type
    type Bool;

    /// Asserts that `b == 1`.
    fn assert(&mut self, b: Self::Bool);

    /// Asserts that all the booleans in `iter` are equal to `1`.
    #[inline]
    fn assert_all<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Self::Bool>,
    {
        iter.into_iter().for_each(move |b| self.assert(b));
    }

    /// Generates a boolean that represents the fact that `lhs` and `rhs` may be equal.
    #[inline]
    fn eq<V>(&mut self, lhs: &V, rhs: &V) -> Self::Bool
    where
        V: Equal<Self>,
    {
        V::eq(lhs, rhs, self)
    }

    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq<V>(&mut self, lhs: &V, rhs: &V)
    where
        V: Equal<Self>,
    {
        V::assert_eq(lhs, rhs, self);
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, V, I>(&mut self, base: &'t V, iter: I)
    where
        V: 't + Equal<Self>,
        I: IntoIterator<Item = &'t V>,
    {
        V::assert_all_eq_to_base(base, iter, self);
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, V, I>(&mut self, iter: I)
    where
        V: 't + Equal<Self>,
        I: IntoIterator<Item = &'t V>,
    {
        V::assert_all_eq(iter, self);
    }

    /// Selects `true_value` when `bit == 1` and `false_value` when `bit == 0`.
    #[inline]
    fn conditional_select<V>(&mut self, bit: &Self::Bool, true_value: &V, false_value: &V) -> V
    where
        V: ConditionalSelect<Self>,
    {
        V::select(bit, true_value, false_value, self)
    }

    /// Swaps `lhs` and `rhs` if `bit == 1`.
    #[inline]
    fn conditional_swap<V>(&mut self, bit: &Self::Bool, lhs: &V, rhs: &V) -> (V, V)
    where
        V: ConditionalSelect<Self>,
    {
        V::swap(bit, lhs, rhs, self)
    }

    /// Swaps `lhs` and `rhs` in-place if `bit == 1`.
    #[inline]
    fn conditional_swap_in_place<V>(&mut self, bit: &Self::Bool, lhs: &mut V, rhs: &mut V)
    where
        V: ConditionalSelect<Self>,
    {
        V::swap_in_place(bit, lhs, rhs, self)
    }
    */
}

/* TODO:
/// Conditional Selection
pub trait ConditionalSelect<COM>
where
    COM: ConstraintSystem + ?Sized,
{
    /// Selects `true_value` when `bit == 1` and `false_value` when `bit == 0`.
    fn select(bit: &COM::Bool, true_value: &Self, false_value: &Self, compiler: &mut COM) -> Self;

    /// Swaps `lhs` and `rhs` if `bit == 1`.
    #[inline]
    fn swap(bit: &COM::Bool, lhs: &Self, rhs: &Self, compiler: &mut COM) -> (Self, Self)
    where
        Self: Sized,
    {
        (
            Self::select(bit, rhs, lhs, compiler),
            Self::select(bit, lhs, rhs, compiler),
        )
    }

    /// Swaps `lhs` and `rhs` in-place if `bit == 1`.
    #[inline]
    fn swap_in_place(bit: &COM::Bool, lhs: &mut Self, rhs: &mut Self, compiler: &mut COM)
    where
        Self: Sized,
    {
        let (swapped_lhs, swapped_rhs) = Self::swap(bit, lhs, rhs, compiler);
        *lhs = swapped_lhs;
        *rhs = swapped_rhs;
    }
}
*/

/// Proof System
pub trait ProofSystem {
    /// Context Compiler
    type ContextCompiler;

    /// Proof Compiler
    type ProofCompiler;

    /// Public Parameters Type
    type PublicParameters;

    /// Proving Context Type
    type ProvingContext;

    /// Verifying Context Type
    type VerifyingContext;

    /// Verification Input Type
    type Input: Default;

    /// Proof Type
    type Proof;

    /// Error Type
    type Error;

    /// Returns a compiler which is setup to build proving and verifying contexts.
    #[must_use]
    fn context_compiler() -> Self::ContextCompiler;

    /// Returns a compiler which is setup to build a proof.
    #[must_use]
    fn proof_compiler() -> Self::ProofCompiler;

    /// Returns proving and verifying contexts for the constraints contained in `compiler` using
    /// `pubpublic_parameters`.
    fn generate_context<R>(
        public_parameters: &Self::PublicParameters,
        compiler: &Self::ContextCompiler,
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Returns a proof that the constraint system encoded in `compiler` is consistent with the
    /// proving `context`.
    fn prove<R>(
        context: &Self::ProvingContext,
        compiler: &Self::ProofCompiler,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Verifies that a proof generated from this proof system is valid.
    fn verify(
        context: &Self::VerifyingContext,
        input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error>;
}

/// Proof System Input
pub trait ProofSystemInput<T>: ProofSystem
where
    T: ?Sized,
{
    /// Extend the `input` with the `next` element.
    fn extend(input: &mut Self::Input, next: &T);
}

/// Constraint System Measurement
pub mod measure {
    use super::mode::{Constant, Public, Secret};
    use core::{
        fmt::{Debug, Display},
        hash::Hash,
        ops::{Add, AddAssign, Deref, DerefMut},
    };

    #[cfg(feature = "alloc")]
    use alloc::{format, string::String, vec::Vec};

    #[cfg(feature = "serde")]
    use manta_util::serde::{Deserialize, Serialize};

    /// Variable Counting
    pub trait Count<M> {
        /// Returns the number of variables of the given mode `M` are stored in `self`.
        fn count(&self) -> Option<usize> {
            None
        }
    }

    /// Constraint System Measurement
    pub trait Measure: Count<Constant> + Count<Public> + Count<Secret> {
        /// Returns the number of constraints stored in `self`.
        fn constraint_count(&self) -> usize;

        /// Returns a [`Size`] with the number of constraints and variables of each kind.
        #[inline]
        fn measure(&self) -> Size {
            Size {
                constraint_count: self.constraint_count(),
                constant_count: Count::<Constant>::count(self),
                public_variable_count: Count::<Public>::count(self),
                secret_variable_count: Count::<Secret>::count(self),
            }
        }

        /// Performs a measurement after running `f` on `self`, adding the result to `measurement`.
        #[inline]
        fn after<T, F>(&mut self, measurement: &mut Size, f: F) -> T
        where
            F: FnOnce(&mut Self) -> T,
        {
            let value = f(self);
            *measurement += self.measure();
            value
        }

        /// Performs a measurement after running `f` on `self`, ignoring the resulting value,
        /// returning the measurement only.
        #[inline]
        fn after_ignore<T, F>(&mut self, f: F) -> Size
        where
            F: FnOnce(&mut Self) -> T,
        {
            let mut measurement = Default::default();
            self.after(&mut measurement, f);
            measurement
        }
    }

    /// Constraint System Size Measurement
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde", deny_unknown_fields)
    )]
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    #[must_use]
    pub struct Size {
        /// Number of Constraints
        pub constraint_count: usize,

        /// Number of Constants
        pub constant_count: Option<usize>,

        /// Number of Public Variables
        pub public_variable_count: Option<usize>,

        /// Number of Secret Variables
        pub secret_variable_count: Option<usize>,
    }

    impl Size {
        /// Computes the difference between `self` and `rhs`. If any of the measurements in `rhs`
        /// are greater than those in `self`, this method returns `None`.
        #[inline]
        pub fn checked_sub(&self, rhs: Self) -> Option<Self> {
            Some(Self {
                constraint_count: self.constraint_count.checked_sub(rhs.constraint_count)?,
                constant_count: match (self.constant_count, rhs.constant_count) {
                    (Some(lhs), Some(rhs)) => Some(lhs.checked_sub(rhs)?),
                    (Some(lhs), None) => Some(lhs),
                    _ => None,
                },
                public_variable_count: match (self.public_variable_count, rhs.public_variable_count)
                {
                    (Some(lhs), Some(rhs)) => Some(lhs.checked_sub(rhs)?),
                    (Some(lhs), None) => Some(lhs),
                    _ => None,
                },
                secret_variable_count: match (self.secret_variable_count, rhs.secret_variable_count)
                {
                    (Some(lhs), Some(rhs)) => Some(lhs.checked_sub(rhs)?),
                    (Some(lhs), None) => Some(lhs),
                    _ => None,
                },
            })
        }
    }

    impl Add for Size {
        type Output = Self;

        #[inline]
        fn add(mut self, rhs: Self) -> Self::Output {
            self += rhs;
            self
        }
    }

    impl AddAssign for Size {
        #[inline]
        fn add_assign(&mut self, rhs: Self) {
            self.constraint_count += rhs.constraint_count;
            match (self.constant_count.as_mut(), rhs.constant_count) {
                (Some(lhs), Some(rhs)) => *lhs += rhs,
                (Some(_), None) => {}
                (None, rhs) => self.constant_count = rhs,
            }
            match (
                self.public_variable_count.as_mut(),
                rhs.public_variable_count,
            ) {
                (Some(lhs), Some(rhs)) => *lhs += rhs,
                (Some(_), None) => {}
                (None, rhs) => self.public_variable_count = rhs,
            }
            match (
                self.secret_variable_count.as_mut(),
                rhs.secret_variable_count,
            ) {
                (Some(lhs), Some(rhs)) => *lhs += rhs,
                (Some(_), None) => {}
                (None, rhs) => self.secret_variable_count = rhs,
            }
        }
    }

    /// Measurement Instrument
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    pub struct Instrument<'c, COM>
    where
        COM: Measure,
    {
        /// Base Compiler
        pub base: &'c mut COM,

        /// Measurements
        pub measurements: Vec<(String, Size)>,
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    impl<'c, COM> Instrument<'c, COM>
    where
        COM: Measure,
    {
        /// Builds a new [`Instrument`] for `base`.
        #[inline]
        pub fn new(base: &'c mut COM) -> Self {
            Self {
                base,
                measurements: Default::default(),
            }
        }

        /// Measures the size of `f` in the base compiler, attaching `label` to the measurement.
        #[inline]
        pub fn measure<D, T, F>(&mut self, label: D, f: F) -> T
        where
            D: Display,
            F: FnOnce(&mut COM) -> T,
        {
            let before = self.base.measure();
            let value = f(self.base);
            self.measurements.push((
                format!("{}", label),
                self.base
                    .measure()
                    .checked_sub(before)
                    .expect("Measurements should increase when adding more constraints."),
            ));
            value
        }
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    impl<'c, COM> Deref for Instrument<'c, COM>
    where
        COM: Measure,
    {
        type Target = COM;

        #[inline]
        fn deref(&self) -> &Self::Target {
            self.base
        }
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    impl<'c, COM> DerefMut for Instrument<'c, COM>
    where
        COM: Measure,
    {
        #[inline]
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.base
        }
    }
}
