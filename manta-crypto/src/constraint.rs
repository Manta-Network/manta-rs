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

/// Proof System
pub trait ProofSystem {
    /// Context Compiler
    type Compiler;

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
    fn context_compiler() -> Self::Compiler;

    /// Returns a compiler which is setup to build a proof.
    #[must_use]
    fn proof_compiler() -> Self::Compiler;

    /// Returns proving and verifying contexts for the constraints contained in `compiler` using
    /// `public_parameters`.
    fn compile<R>(
        public_parameters: &Self::PublicParameters,
        compiler: Self::Compiler,
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Returns a proof that the constraint system encoded in `compiler` is consistent with the
    /// proving `context`.
    fn prove<R>(
        context: &Self::ProvingContext,
        compiler: Self::Compiler,
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
pub trait Input<P>
where
    P: ProofSystem + ?Sized,
{
    /// Extends the `input` buffer with data from `self`.
    fn extend(&self, input: &mut P::Input);
}

/// Proof System Input Introspection
///
/// This `trait` is automatically implemented for all [`T: Input<Self>`](Input) and cannot be
/// implemented manually.
pub trait HasInput<T>: ProofSystem
where
    T: ?Sized,
{
    /// Extends the `input` buffer with data from `value`.
    fn extend(input: &mut Self::Input, value: &T);
}

impl<P, T> HasInput<T> for P
where
    P: ProofSystem + ?Sized,
    T: Input<P> + ?Sized,
{
    #[inline]
    fn extend(input: &mut Self::Input, value: &T) {
        value.extend(input)
    }
}

/// Constraint System Measurement
pub mod measure {
    use crate::eclair::alloc::mode::{Constant, Public, Secret};
    use alloc::{fmt::Display, format, string::String, vec::Vec};
    use core::{
        fmt::Debug,
        hash::Hash,
        ops::{Add, AddAssign, Deref, DerefMut},
    };

    #[cfg(feature = "serde")]
    use manta_util::serde::{Deserialize, Serialize};

    /// Variable Counting
    pub trait Count<M> {
        /// Returns the number of variables of the given mode `M` stored in `self`.
        #[inline]
        fn count(&self) -> Option<usize> {
            None
        }
    }

    impl<M> Count<M> for () {}

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

    impl Measure for () {
        #[inline]
        fn constraint_count(&self) -> usize {
            0
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

    /// Prints the measurement of the call to `f` with the given `label`.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    #[inline]
    pub fn print_measurement<D, F, T, COM>(label: D, f: F, compiler: &mut COM) -> T
    where
        D: Display,
        F: FnOnce(&mut COM) -> T,
        COM: Measure,
    {
        let before = compiler.measure();
        let value = f(compiler);
        println!(
            "{}: {:?}",
            label,
            compiler
                .measure()
                .checked_sub(before)
                .expect("Measurements should increase when adding more constraints.")
        );
        value
    }

    /// Measurement Instrument
    pub struct Instrument<'c, COM>
    where
        COM: Measure,
    {
        /// Base Compiler
        pub base: &'c mut COM,

        /// Measurements
        pub measurements: Vec<(String, Size)>,
    }

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

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use core::fmt::Debug;

    /// Checks that attempting to verify `proof` against fuzzed inputs fails.
    #[inline]
    pub fn verify_fuzz_public_input<P, F>(
        context: &P::VerifyingContext,
        input: &P::Input,
        proof: &P::Proof,
        mut fuzzer: F,
    ) where
        P: ProofSystem,
        P::Error: Debug,
        F: FnMut(&P::Input) -> P::Input,
    {
        assert!(
            !P::verify(context, &fuzzer(input), proof).expect("Unable to verify proof."),
            "Proof remained valid after fuzzing."
        );
    }
}
