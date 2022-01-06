// Copyright 2019-2021 Manta Network.
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

use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use manta_util::{create_seal, seal};
use rand_core::{CryptoRng, RngCore};

create_seal! {}

/// Generic Derived Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Derived;

/// Public Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Public;

impl From<Derived> for Public {
    #[inline]
    fn from(d: Derived) -> Self {
        let _ = d;
        Self
    }
}

/// Secret Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Secret;

impl From<Derived> for Secret {
    #[inline]
    fn from(d: Derived) -> Self {
        let _ = d;
        Self
    }
}

/// Constant Type Alias
pub type Const<C, COM> = <C as Constant<COM>>::Type;

/// Compiler Constant
pub trait Constant<COM>
where
    COM: ?Sized,
{
    /// Underlying Type
    type Type;

    /// Allocates a new constant from `this` into the `compiler`.
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self;
}

impl<T, COM> Constant<COM> for PhantomData<T>
where
    COM: ?Sized,
{
    type Type = PhantomData<T>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        PhantomData
    }
}

/// Variable Type Alias
pub type Var<V, M, COM> = <V as Variable<M, COM>>::Type;

/// Compiler Variable
pub trait Variable<M, COM>
where
    COM: ?Sized,
{
    /// Underlying Type
    type Type;

    /// Allocates a new known value from `this` into the `compiler`.
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self;

    /// Allocates a new unknown value into the `compiler`.
    fn new_unknown(compiler: &mut COM) -> Self;
}

impl<T, M, COM> Variable<M, COM> for PhantomData<T>
where
    COM: ?Sized,
{
    type Type = PhantomData<T>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        PhantomData
    }

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        let _ = compiler;
        PhantomData
    }
}

/// Value Source Auto-Trait
pub trait ValueSource<COM>
where
    COM: ?Sized,
{
    /// Allocates `self` as a constant in `compiler`.
    #[inline]
    fn as_constant<C>(&self, compiler: &mut COM) -> C
    where
        C: Constant<COM, Type = Self>,
    {
        C::new_constant(self, compiler)
    }

    /// Allocates `self` as a known value in `compiler`.
    #[inline]
    fn as_known<M, V>(&self, compiler: &mut COM) -> V
    where
        V: Variable<M, COM, Type = Self>,
    {
        V::new_known(self, compiler)
    }

    /// Allocates an unknown value of type `Self` into `compiler`.
    #[inline]
    fn as_unknown<M, V>(compiler: &mut COM) -> V
    where
        V: Variable<M, COM, Type = Self>,
    {
        V::new_unknown(compiler)
    }
}

impl<COM, T> ValueSource<COM> for T where T: ?Sized {}

/// Allocator Auto-Trait
pub trait Allocator {
    /// Allocates a constant with the given `value` into `self`.
    #[inline]
    fn allocate_constant<C>(&mut self, value: &C::Type) -> C
    where
        C: Constant<Self>,
    {
        C::new_constant(value, self)
    }

    /// Allocates a known variable with the given `value` into `self`.
    #[inline]
    fn allocate_known<M, V>(&mut self, value: &V::Type) -> V
    where
        V: Variable<M, Self>,
    {
        V::new_known(value, self)
    }

    /// Allocates an unknown variable into `self`.
    #[inline]
    fn allocate_unknown<M, V>(&mut self) -> V
    where
        V: Variable<M, Self>,
    {
        V::new_unknown(self)
    }
}

impl<COM> Allocator for COM where COM: ?Sized {}

/// Native Compiler Marker Trait
///
/// This trait is only implemented for `()`, the only native compiler.
pub trait Native: sealed::Sealed {
    /// Returns the native compiler.
    fn compiler() -> Self;
}

seal! { () }

impl Native for () {
    #[inline]
    fn compiler() -> Self {}
}

/// Constraint System
pub trait ConstraintSystem {
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

    /// Selects `lhs` if `bit == 0` and `rhs` if `bit == 1`.
    #[inline]
    fn conditional_select<V>(&mut self, bit: &Self::Bool, lhs: &V, rhs: &V) -> V
    where
        V: ConditionalSelect<Self>,
    {
        V::select(bit, lhs, rhs, self)
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
}

/* TODO: Can we safely implement this?
impl ConstraintSystem for () {
    type Bool = bool;

    #[inline]
    fn assert(&mut self, b: Self::Bool) {
        assert!(b, "Native Constraint System assertion.");
    }
}
*/

/// Equality Trait
pub trait Equal<COM>
where
    COM: ConstraintSystem + ?Sized,
{
    /// Generates a boolean that represents the fact that `lhs` and `rhs` may be equal.
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut COM) -> COM::Bool;

    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq(lhs: &Self, rhs: &Self, compiler: &mut COM) {
        let boolean = Self::eq(lhs, rhs, compiler);
        compiler.assert(boolean);
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, I>(base: &'t Self, iter: I, compiler: &mut COM)
    where
        I: IntoIterator<Item = &'t Self>,
    {
        for item in iter {
            Self::assert_eq(base, item, compiler);
        }
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, I>(iter: I, compiler: &mut COM)
    where
        Self: 't,
        I: IntoIterator<Item = &'t Self>,
    {
        let mut iter = iter.into_iter();
        if let Some(base) = iter.next() {
            Self::assert_all_eq_to_base(base, iter, compiler);
        }
    }
}

/// Conditional Selection
pub trait ConditionalSelect<COM>
where
    COM: ConstraintSystem + ?Sized,
{
    /// Selects `lhs` if `bit == 0` and `rhs` if `bit == 1`.
    fn select(bit: &COM::Bool, lhs: &Self, rhs: &Self, compiler: &mut COM) -> Self;

    /// Swaps `lhs` and `rhs` if `bit == 1`.
    #[inline]
    fn swap(bit: &COM::Bool, lhs: &Self, rhs: &Self, compiler: &mut COM) -> (Self, Self)
    where
        Self: Sized,
    {
        (
            Self::select(bit, lhs, rhs, compiler),
            Self::select(bit, rhs, lhs, compiler),
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

/// Addition
pub trait Add<COM>
where
    COM: ?Sized,
{
    /// Adds `lhs` and `rhs` inside of `compiler`.
    fn add(lhs: Self, rhs: Self, compiler: &mut COM) -> Self;
}

/// Subtraction
pub trait Sub<COM>
where
    COM: ?Sized,
{
    /// Subtracts `rhs` from `lhs` inside of `compiler`.
    fn sub(lhs: Self, rhs: Self, compiler: &mut COM) -> Self;
}

/// Proof System
pub trait ProofSystem {
    /// Constraint System
    type ConstraintSystem: ConstraintSystem;

    /// Proving Context Type
    type ProvingContext;

    /// Verifying Context Type
    type VerifyingContext;

    /// Verification Input Type
    type Input: Default;

    /// Proof Type
    type Proof;

    /// Verification Type
    ///
    /// For non-recursive proof systems this is just `bool`.
    type Verification;

    /// Error Type
    type Error;

    /// Returns a constraint system which is setup to build proving and verifying contexts.
    #[must_use]
    fn for_unknown() -> Self::ConstraintSystem;

    /// Returns a constraint system which is setup to build a proof.
    #[must_use]
    fn for_known() -> Self::ConstraintSystem;

    /// Returns proving and verifying contexts for the constraints contained in `compiler`.
    fn generate_context<R>(
        compiler: Self::ConstraintSystem,
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Returns a proof that the constraint system `compiler` is consistent.
    fn prove<R>(
        compiler: Self::ConstraintSystem,
        context: &Self::ProvingContext,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Verifies that a proof generated from this proof system is valid.
    fn verify(
        input: &Self::Input,
        proof: &Self::Proof,
        context: &Self::VerifyingContext,
    ) -> Result<Self::Verification, Self::Error>;
}

/// Proof System Input
pub trait Input<T>: ProofSystem
where
    T: ?Sized,
{
    /// Extend the `input` with the `next` element.
    fn extend(input: &mut Self::Input, next: &T);
}

/// Constraint System Measurement
pub mod measure {
    use super::*;

    /// Constraint System Measurement
    pub trait Measure {
        /// Returns the number of constraints stored in `self`.
        fn constraint_count(&self) -> usize;

        /// Returns the number of allocated constants.
        #[inline]
        fn constant_count(&self) -> Option<usize> {
            None
        }

        /// Returns the number of allocated public variables.
        #[inline]
        fn public_variable_count(&self) -> Option<usize> {
            None
        }

        /// Returns the number of allocated secret variables.
        #[inline]
        fn secret_variable_count(&self) -> Option<usize> {
            None
        }

        /// Returns a [`SizeReport`] with the number of constraints and variables of each kind.
        #[inline]
        fn measure(&self) -> SizeReport {
            SizeReport {
                constraint_count: self.constraint_count(),
                constant_count: self.constant_count(),
                public_variable_count: self.public_variable_count(),
                secret_variable_count: self.secret_variable_count(),
            }
        }
    }

    /// Constraint System Size Measurement Report
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct SizeReport {
        /// Number of Constraints
        pub constraint_count: usize,

        /// Number of Constants
        pub constant_count: Option<usize>,

        /// Number of Public Variables
        pub public_variable_count: Option<usize>,

        /// Number of Secret Variables
        pub secret_variable_count: Option<usize>,
    }
}
