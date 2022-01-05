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

// TODO:  Add derive macros to all the enums/structs here.
// TODO:  Add derive trait to implement `HasAllocation` for structs (and enums?).
// TODO:  Add more convenience functions for allocating unknown variables.
// FIXME: Leverage the type system to constrain allocation to only unknown modes for verifier
//        generation and only known modes for proof generation, instead of relying on the `for_*`
//        methods to "do the right thing".

use core::{
    convert::{Infallible, TryFrom},
    fmt::Debug,
    hash::Hash,
    marker::PhantomData,
};
use rand_core::{CryptoRng, RngCore};

/// Allocation Mode
pub trait AllocationMode {
    /// Known Allocation Mode
    type Known;

    /// Unknown Allocation Mode
    type Unknown;
}

impl AllocationMode for Infallible {
    type Known = Self;
    type Unknown = Self;
}

impl AllocationMode for () {
    type Known = Self;
    type Unknown = Self;
}

/// Allocation Entry
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Mode::Known: Clone, Mode::Unknown: Clone"),
    Copy(bound = "Mode::Known: Copy, Mode::Unknown: Copy"),
    Debug(bound = "T: Debug, Mode::Known: Debug, Mode::Unknown: Debug"),
    Eq(bound = "T: Eq, Mode::Known: Eq, Mode::Unknown: Eq"),
    Hash(bound = "T: Hash, Mode::Known: Hash, Mode::Unknown: Hash"),
    PartialEq(bound = "T: PartialEq, Mode::Known: PartialEq, Mode::Unknown: PartialEq")
)]
pub enum Allocation<'t, T, Mode>
where
    T: ?Sized,
    Mode: AllocationMode,
{
    /// Known Value
    Known(
        /// Allocation Value
        &'t T,
        /// Allocation Mode
        Mode::Known,
    ),
    /// Unknown Value
    Unknown(
        /// Allocation Mode
        Mode::Unknown,
    ),
}

impl<'t, T, Mode> From<(&'t T, Mode::Known)> for Allocation<'t, T, Mode>
where
    T: ?Sized,
    Mode: AllocationMode,
{
    #[inline]
    fn from((value, mode): (&'t T, Mode::Known)) -> Self {
        Self::Known(value, mode)
    }
}

impl<'t, T, Mode> Allocation<'t, T, Mode>
where
    T: ?Sized,
    Mode: AllocationMode,
{
    /// Returns `true` if `self` represents a known value and mode.
    #[inline]
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(..))
    }

    /// Returns `true` if `self` represents an unknown value mode.
    #[inline]
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(..))
    }

    /// Converts `self` into a possibly known value and mode.
    #[inline]
    pub fn known(self) -> Option<(&'t T, Mode::Known)> {
        match self {
            Self::Known(value, mode) => Some((value, mode)),
            _ => None,
        }
    }

    /// Converts `self` into a possibly unknown mode.
    #[inline]
    pub fn unknown(self) -> Option<Mode::Unknown> {
        match self {
            Self::Unknown(mode) => Some(mode),
            _ => None,
        }
    }

    /// Converts `self` into a known value and mode whenever its unknown mode is [`Infallible`].
    #[inline]
    pub fn into_known(self) -> (&'t T, Mode::Known)
    where
        Mode: AllocationMode<Unknown = Infallible>,
    {
        match self {
            Self::Known(value, mode) => (value, mode),
            _ => unreachable!("Values of infallible types cannot be constructed."),
        }
    }

    /// Converts `self` into an unknown mode whenever its known mode is [`Infallible`].
    #[inline]
    pub fn into_unknown(self) -> Mode::Unknown
    where
        Mode: AllocationMode<Known = Infallible>,
    {
        match self {
            Self::Unknown(mode) => mode,
            _ => unreachable!("Values of infallible types cannot be constructed."),
        }
    }

    /// Maps over the possible value stored in `self`.
    #[inline]
    pub fn map<'u, U, N, F>(self, f: F) -> Allocation<'u, U, N>
    where
        Mode::Known: Into<N::Known>,
        Mode::Unknown: Into<N::Unknown>,
        N: AllocationMode,
        F: FnOnce(&'t T) -> &'u U,
    {
        match self {
            Self::Known(value, mode) => Allocation::Known(f(value), mode.into()),
            Self::Unknown(mode) => Allocation::Unknown(mode.into()),
        }
    }

    /// Allocates a variable with `self` as the allocation entry into `cs`.
    #[inline]
    pub fn allocate<C, V>(self, cs: &mut C) -> V
    where
        C: ?Sized,
        V: Variable<C, Type = T, Mode = Mode>,
    {
        V::new(cs, self)
    }

    /// Allocates a variable into `cs` after mapping over `self`.
    #[inline]
    pub fn map_allocate<C, V, F>(self, cs: &mut C, f: F) -> V
    where
        Mode::Known: Into<<V::Mode as AllocationMode>::Known>,
        Mode::Unknown: Into<<V::Mode as AllocationMode>::Unknown>,
        C: ?Sized,
        V: Variable<C>,
        F: FnOnce(&'t T) -> V::Type,
    {
        match self {
            Self::Known(value, mode) => V::new_known(cs, &f(value), mode),
            Self::Unknown(mode) => V::new_unknown(cs, mode),
        }
    }
}

/// Native Compiler Marker Trait
///
/// This trait is only implemented for `()`, the only native compiler.
pub trait Native {
    /// Returns the native compiler.
    fn compiler() -> Self;
}

impl Native for () {
    #[inline]
    fn compiler() -> Self {}
}

/// Variable Allocation Trait
pub trait Variable<C>: Sized
where
    C: ?Sized,
{
    /// Origin Type of the Variable
    type Type;

    /// Allocation Mode
    type Mode: AllocationMode;

    /// Allocates a new variable into `cs` with the given `allocation`.
    fn new(cs: &mut C, allocation: Allocation<Self::Type, Self::Mode>) -> Self;

    /// Allocates a new known variable into `cs` with the given `mode`.
    #[inline]
    fn new_known(
        cs: &mut C,
        value: &Self::Type,
        mode: impl Into<<Self::Mode as AllocationMode>::Known>,
    ) -> Self {
        Self::new(cs, Allocation::Known(value, mode.into()))
    }

    /// Allocates a new unknown variable into `cs` with the given `mode`.
    #[inline]
    fn new_unknown(cs: &mut C, mode: impl Into<<Self::Mode as AllocationMode>::Unknown>) -> Self {
        Self::new(cs, Allocation::Unknown(mode.into()))
    }

    /// Allocates a new known variable into `cs` with the given `mode` which holds the default
    /// value of [`Self::Type`].
    #[inline]
    fn from_default(cs: &mut C, mode: impl Into<<Self::Mode as AllocationMode>::Known>) -> Self
    where
        Self::Type: Default,
    {
        Self::new_known(cs, &Default::default(), mode)
    }

    /// Allocates a new known variable into `cs` with the given `mode` which holds the default
    /// value of [`&Self::Type`](Self::Type).
    #[inline]
    fn from_default_ref<'t>(
        cs: &mut C,
        mode: impl Into<<Self::Mode as AllocationMode>::Known>,
    ) -> Self
    where
        Self::Type: 't,
        &'t Self::Type: Default,
    {
        Self::new_known(cs, Default::default(), mode)
    }
}

/// Variable Source
pub trait VariableSource {
    /// Allocates a new variable into `cs` with the given `allocation`.
    #[inline]
    fn as_variable<C, V>(cs: &mut C, allocation: Allocation<Self, V::Mode>) -> V
    where
        C: ?Sized,
        V: Variable<C, Type = Self>,
    {
        V::new(cs, allocation)
    }

    /// Allocates a new known variable into `cs` with the given `mode`.
    #[inline]
    fn as_known<C, V>(&self, cs: &mut C, mode: impl Into<<V::Mode as AllocationMode>::Known>) -> V
    where
        C: ?Sized,
        V: Variable<C, Type = Self>,
    {
        V::new_known(cs, self, mode)
    }

    /// Allocates a new unknown variable into `cs` with the given `mode`.
    #[inline]
    fn as_unknown<C, V>(cs: &mut C, mode: impl Into<<V::Mode as AllocationMode>::Unknown>) -> V
    where
        C: ?Sized,
        V: Variable<C, Type = Self>,
    {
        V::new_unknown(cs, mode)
    }
}

impl<T> VariableSource for T where T: ?Sized {}

impl<T, C> Variable<C> for PhantomData<T>
where
    T: ?Sized,
    C: ?Sized,
{
    type Type = PhantomData<T>;

    type Mode = ();

    #[inline]
    fn new(cs: &mut C, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        let _ = (cs, allocation);
        PhantomData
    }
}

/* TODO[remove]:
impl<T, C> reflection::HasAllocation<C> for PhantomData<T>
where
    T: ?Sized,
    C: ?Sized,
{
    type Variable = PhantomData<T>;
    type Mode = ();
}
*/

/// Allocates a new known variable into `cs` with the given `mode`.
#[inline]
pub fn known<C, V>(
    cs: &mut C,
    value: &V::Type,
    mode: impl Into<<V::Mode as AllocationMode>::Known>,
) -> V
where
    C: ?Sized,
    V: Variable<C>,
{
    V::new_known(cs, value, mode)
}

/// Allocates a new unknown variable into `cs` with the given `mode`.
#[inline]
pub fn unknown<C, V>(cs: &mut C, mode: impl Into<<V::Mode as AllocationMode>::Unknown>) -> V
where
    C: ?Sized,
    V: Variable<C>,
{
    V::new_unknown(cs, mode)
}

/// Allocation System
pub trait AllocationSystem {
    /// Allocates a new variable into `self` with the given `allocation`.
    #[inline]
    fn allocate<V>(&mut self, allocation: Allocation<V::Type, V::Mode>) -> V
    where
        V: Variable<Self>,
    {
        V::new(self, allocation)
    }

    /// Allocates a new known variable into `self` with the given `mode`.
    #[inline]
    fn allocate_known<V>(
        &mut self,
        value: &V::Type,
        mode: impl Into<<V::Mode as AllocationMode>::Known>,
    ) -> V
    where
        V: Variable<Self>,
    {
        known(self, value, mode)
    }

    /// Allocates a new unknown variable into `self` with the given `mode`.
    #[inline]
    fn allocate_unknown<V>(&mut self, mode: impl Into<<V::Mode as AllocationMode>::Unknown>) -> V
    where
        V: Variable<Self>,
    {
        unknown(self, mode)
    }
}

impl<C> AllocationSystem for C where C: ?Sized {}

/// Constraint System
pub trait ConstraintSystem {
    /// Boolean Variable Type
    type Bool: Variable<Self, Type = bool>;

    /// Asserts that `b` is `true`.
    fn assert(&mut self, b: Self::Bool);

    /// Asserts that all the booleans in `iter` are `true`.
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
        V::eq(self, lhs, rhs)
    }

    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq<V>(&mut self, lhs: &V, rhs: &V)
    where
        V: Equal<Self>,
    {
        V::assert_eq(self, lhs, rhs);
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, V, I>(&mut self, base: &'t V, iter: I)
    where
        V: 't + Equal<Self>,
        I: IntoIterator<Item = &'t V>,
    {
        V::assert_all_eq_to_base(self, base, iter);
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, V, I>(&mut self, iter: I)
    where
        V: 't + Equal<Self>,
        I: IntoIterator<Item = &'t V>,
    {
        V::assert_all_eq(self, iter);
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

    /// Returns proving and verifying contexts for the constraints contained in `self`.
    #[inline]
    fn generate_context<P, R>(
        self,
        rng: &mut R,
    ) -> Result<(P::ProvingContext, P::VerifyingContext), P::Error>
    where
        Self: Sized,
        P: ProofSystem<ConstraintSystem = Self>,
        R: CryptoRng + RngCore + ?Sized,
    {
        P::generate_context(self, rng)
    }

    /// Returns a proof that the constraint system `self` is consistent.
    #[inline]
    fn prove<P, R>(self, context: &P::ProvingContext, rng: &mut R) -> Result<P::Proof, P::Error>
    where
        Self: Sized,
        P: ProofSystem<ConstraintSystem = Self>,
        R: CryptoRng + RngCore + ?Sized,
    {
        P::prove(self, context, rng)
    }
}

/// Equality Trait
pub trait Equal<C>
where
    C: ConstraintSystem + ?Sized,
{
    /// Generates a boolean that represents the fact that `lhs` and `rhs` may be equal.
    fn eq(cs: &mut C, lhs: &Self, rhs: &Self) -> C::Bool;

    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq(cs: &mut C, lhs: &Self, rhs: &Self) {
        let boolean = Self::eq(cs, lhs, rhs);
        cs.assert(boolean);
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, I>(cs: &mut C, base: &'t Self, iter: I)
    where
        I: IntoIterator<Item = &'t Self>,
    {
        for item in iter {
            Self::assert_eq(cs, base, item);
        }
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, I>(cs: &mut C, iter: I)
    where
        Self: 't,
        I: IntoIterator<Item = &'t Self>,
    {
        let mut iter = iter.into_iter();
        if let Some(base) = iter.next() {
            Self::assert_all_eq_to_base(cs, base, iter);
        }
    }
}

/// Conditional Selection
pub trait ConditionalSelect<C>
where
    C: ConstraintSystem + ?Sized,
{
    /// Selects `lhs` if `bit == 0` and `rhs` if `bit == 1`.
    fn select(bit: &C::Bool, lhs: &Self, rhs: &Self, cs: &mut C) -> Self;

    /// Swaps `lhs` and `rhs` if `bit == 1`.
    #[inline]
    fn swap(bit: &C::Bool, lhs: &Self, rhs: &Self, cs: &mut C) -> (Self, Self)
    where
        Self: Sized,
    {
        (
            Self::select(bit, lhs, rhs, cs),
            Self::select(bit, lhs, rhs, cs),
        )
    }
}

/// Addition Trait
pub trait Add<C>
where
    C: ConstraintSystem + ?Sized,
{
    /// Adds `lhs` to `rhs` inside of `cs`, returning the sum.
    fn add(cs: &mut C, lhs: Self, rhs: Self) -> Self;
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

    /// Returns proving and verifying contexts for the constraints contained in `cs`.
    fn generate_context<R>(
        cs: Self::ConstraintSystem,
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Returns a proof that the constraint system `cs` is consistent.
    fn prove<R>(
        cs: Self::ConstraintSystem,
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

/// Derived Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Derived;

impl AllocationMode for Derived {
    type Known = Self;
    type Unknown = Self;
}

impl From<Derived> for () {
    #[inline]
    fn from(d: Derived) -> Self {
        let _ = d;
    }
}

/// Always Public Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Public;

impl AllocationMode for Public {
    type Known = Self;
    type Unknown = Self;
}

impl From<Derived> for Public {
    #[inline]
    fn from(d: Derived) -> Self {
        let _ = d;
        Self
    }
}

/// Always Secret Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Secret;

impl AllocationMode for Secret {
    type Known = Self;
    type Unknown = Self;
}

impl From<Derived> for Secret {
    #[inline]
    fn from(d: Derived) -> Self {
        let _ = d;
        Self
    }
}

/// Constant Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Constant<T = Public>(
    /// Underyling Allocation Mode
    pub T,
)
where
    T: AllocationMode;

impl<T> AllocationMode for Constant<T>
where
    T: AllocationMode,
{
    type Known = T::Known;
    type Unknown = Infallible;
}

impl<T> From<Derived> for Constant<T>
where
    T: AllocationMode + From<Derived>,
{
    #[inline]
    fn from(d: Derived) -> Self {
        Self(d.into())
    }
}

/// Public/Secret Allocation Mode
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PublicOrSecret {
    /// Public Variable Mode
    Public,

    /// Secret Variable Mode
    Secret,
}

impl PublicOrSecret {
    /// Returns `true` if this mode is for public variables.
    #[inline]
    pub const fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    /// Converts [`PublicOrSecret`] into `Option<Public>`.
    #[inline]
    pub const fn public(self) -> Option<Public> {
        match self {
            Self::Public => Some(Public),
            Self::Secret => None,
        }
    }

    /// Returns `true` if this mode is for secret variables.
    #[inline]
    pub const fn is_secret(&self) -> bool {
        matches!(self, Self::Secret)
    }

    /// Converts [`PublicOrSecret`] into `Option<Secret>`.
    #[inline]
    pub const fn secret(self) -> Option<Secret> {
        match self {
            Self::Secret => Some(Secret),
            Self::Public => None,
        }
    }
}

impl AllocationMode for PublicOrSecret {
    type Known = Self;
    type Unknown = Self;
}

impl Default for PublicOrSecret {
    #[inline]
    fn default() -> Self {
        Self::Secret
    }
}

impl From<Public> for PublicOrSecret {
    #[inline]
    fn from(p: Public) -> Self {
        let _ = p;
        Self::Public
    }
}

impl TryFrom<PublicOrSecret> for Public {
    type Error = Secret;

    #[inline]
    fn try_from(pos: PublicOrSecret) -> Result<Self, Self::Error> {
        pos.public().ok_or(Secret)
    }
}

impl From<Secret> for PublicOrSecret {
    #[inline]
    fn from(s: Secret) -> Self {
        let _ = s;
        Self::Secret
    }
}

impl TryFrom<PublicOrSecret> for Secret {
    type Error = Public;

    #[inline]
    fn try_from(pos: PublicOrSecret) -> Result<Self, Self::Error> {
        pos.secret().ok_or(Public)
    }
}

impl<T> From<Constant<T>> for PublicOrSecret
where
    T: AllocationMode + Into<PublicOrSecret>,
{
    #[inline]
    fn from(c: Constant<T>) -> Self {
        c.0.into()
    }
}

impl<T> TryFrom<PublicOrSecret> for Constant<T>
where
    T: AllocationMode + TryFrom<PublicOrSecret>,
{
    type Error = T::Error;

    #[inline]
    fn try_from(pos: PublicOrSecret) -> Result<Self, Self::Error> {
        T::try_from(pos).map(Self)
    }
}

/// Constraint System Measurement
pub mod measure {
    use super::*;

    /// Constraint System Measurement
    pub trait Measure<M>
    where
        M: ?Sized,
    {
        /// Returns the number of constraints stored in `self`.
        fn constraint_count(&self) -> usize;

        /// Returns the number of variables allocated with the given `mode`.
        fn variable_count(&self, mode: M) -> usize;

        /// Returns the number of constraints and number and kind of variables stored in `self`.
        #[inline]
        fn measure(&self) -> SizeReport<M>
        where
            M: MeasureVariables,
        {
            M::measure(self)
        }
    }

    /// Constraint System Variable Allocation Measurement
    pub trait MeasureVariables {
        /// Measurement Type
        type Measurement;

        /// Counts the number of constraints and the number of variables allocated with all of the
        /// possible modes in `Self`, returning a [`SizeReport`].
        fn measure<C>(cs: &C) -> SizeReport<Self>
        where
            C: Measure<Self> + ?Sized;
    }

    /// Constraint System Size Measurement Report
    #[derive(derivative::Derivative)]
    #[derivative(
        Clone(bound = "M::Measurement: Clone"),
        Copy(bound = "M::Measurement: Copy"),
        Debug(bound = "M::Measurement: Debug"),
        Default(bound = "M::Measurement: Default"),
        Eq(bound = "M::Measurement: Eq"),
        Hash(bound = "M::Measurement: Hash"),
        PartialEq(bound = "M::Measurement: PartialEq")
    )]
    pub struct SizeReport<M>
    where
        M: MeasureVariables + ?Sized,
    {
        /// Number of constraints
        pub constraint_count: usize,

        /// Number of variables
        pub variable_count: M::Measurement,
    }

    impl<M> SizeReport<M>
    where
        M: MeasureVariables + ?Sized,
    {
        /// Builds a new [`SizeReport`] from `constraint_count` and `variable_count`.
        #[inline]
        pub fn new(constraint_count: usize, variable_count: M::Measurement) -> Self {
            Self {
                constraint_count,
                variable_count,
            }
        }

        /// Builds a new [`SizeReport`] with the given `cs` to measure its constraint count and
        /// `variable_count` as the number of variables in the resulting report.
        #[inline]
        pub fn with<C>(cs: &C, variable_count: M::Measurement) -> Self
        where
            C: Measure<M> + ?Sized,
        {
            Self::new(cs.constraint_count(), variable_count)
        }
    }

    impl MeasureVariables for Public {
        type Measurement = usize;

        #[inline]
        fn measure<C>(cs: &C) -> SizeReport<Self>
        where
            C: Measure<Self> + ?Sized,
        {
            SizeReport::with(cs, cs.variable_count(Public))
        }
    }

    impl MeasureVariables for Secret {
        type Measurement = usize;

        #[inline]
        fn measure<C>(cs: &C) -> SizeReport<Self>
        where
            C: Measure<Self> + ?Sized,
        {
            SizeReport::with(cs, cs.variable_count(Secret))
        }
    }

    impl MeasureVariables for PublicOrSecret {
        type Measurement = PublicOrSecretMeasurement;

        #[inline]
        fn measure<C>(cs: &C) -> SizeReport<Self>
        where
            C: Measure<Self> + ?Sized,
        {
            SizeReport::with(
                cs,
                PublicOrSecretMeasurement {
                    public: cs.variable_count(PublicOrSecret::Public),
                    secret: cs.variable_count(PublicOrSecret::Secret),
                },
            )
        }
    }

    /// [`PublicOrSecret`] Measurement
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct PublicOrSecretMeasurement {
        /// Public Variable Count
        pub public: usize,

        /// Secret Variable Count
        pub secret: usize,
    }
}

/* TODO[remove]:
/// Opt-In Compile-Time Reflection Capabilities
///
/// See [`HasAllocation`] and [`HasVariable`] for more information.
///
/// [`HasAllocation`]: reflection::HasAllocation
/// [`HasVariable`]: reflection::HasVariable
pub mod reflection {
    use super::*;

    /// Variable Type
    ///
    /// Requires a [`HasAllocation`] implementation for `T`.
    pub type Var<T, C> = <C as HasVariable<T>>::Variable;

    /// Allocation Mode Type
    ///
    /// Requires a [`HasAllocation`] implementation for `T`.
    pub type Mode<T, C> = <Var<T, C> as Variable<C>>::Mode;

    /// Known Allocation Mode Type
    ///
    /// Requires a [`HasAllocation`] implementation for `T`.
    pub type KnownMode<T, C> = <Mode<T, C> as AllocationMode>::Known;

    /// Known Allocation Mode Type
    ///
    /// Requires a [`HasAllocation`] implementation for `T`.
    pub type UnknownMode<T, C> = <Mode<T, C> as AllocationMode>::Unknown;

    /// Allocation Entry Type
    ///
    /// Requires a [`HasAllocation`] implementation for `T`.
    pub type Alloc<'t, T, C> = Allocation<'t, T, Mode<T, C>>;

    /// Variable Existence Reflection Trait
    ///
    /// This trait can be optionally implemented by any type `T` which has an existing variable
    /// type that implements [`Variable<C, Type = T>`](Variable). Implementing this trait unlocks
    /// all of the reflection capabilities in this module.
    ///
    /// Whenever possible, library authors should implement [`HasAllocation`] on their types which
    /// have associated variables but should minimize their use of [`HasVariable`] so that users
    /// can take advantage of as much of a library as possible while implementing as little as
    /// possible.
    pub trait HasAllocation<C>
    where
        C: ?Sized,
    {
        /// Variable Object Type
        type Variable: Variable<C, Mode = Self::Mode, Type = Self>;

        /// Allocation Mode
        type Mode: AllocationMode;

        /// Allocates a new variable into `cs` with the given `allocation`.
        #[inline]
        fn variable(cs: &mut C, allocation: Allocation<Self, Self::Mode>) -> Self::Variable {
            Self::Variable::new(cs, allocation)
        }

        /// Allocates a new known variable into `cs` with the given `mode`.
        #[inline]
        fn known(
            &self,
            cs: &mut C,
            mode: impl Into<<Self::Mode as AllocationMode>::Known>,
        ) -> Self::Variable {
            Self::Variable::new_known(cs, self, mode)
        }

        /// Allocates a new unknown variable into `cs` with the given `mode`.
        #[inline]
        fn unknown(
            cs: &mut C,
            mode: impl Into<<Self::Mode as AllocationMode>::Unknown>,
        ) -> Self::Variable {
            Self::Variable::new_unknown(cs, mode)
        }
    }

    /// Variable Existence Reflection Trait
    ///
    /// This trait is automatically implemented for all types [`T: HasAllocation`](HasAllocation)
    /// and it activates all the reflection features in this module. See that trait for more
    /// information on activating reflection.
    pub trait HasVariable<T>
    where
        T: ?Sized,
    {
        /// Variable Object Type
        type Variable: Variable<Self, Mode = Self::Mode, Type = T>;

        /// Allocation Mode
        type Mode: AllocationMode;

        /// Allocates a new variable into `self` with the given `allocation`.
        #[inline]
        fn new_allocation(&mut self, allocation: Allocation<T, Self::Mode>) -> Self::Variable {
            Self::Variable::new(self, allocation)
        }

        /// Allocates a new known variable into `self` with the given `mode`.
        #[inline]
        fn new_known_allocation(
            &mut self,
            value: &T,
            mode: impl Into<<Self::Mode as AllocationMode>::Known>,
        ) -> Self::Variable {
            Self::Variable::new_known(self, value, mode)
        }

        /// Allocates a new unknown variable into `self` with the given `mode`.
        #[inline]
        fn new_unknown_allocation(
            &mut self,
            mode: impl Into<<Self::Mode as AllocationMode>::Unknown>,
        ) -> Self::Variable {
            Self::Variable::new_unknown(self, mode)
        }
    }

    impl<C, T> HasVariable<T> for C
    where
        C: ?Sized,
        T: HasAllocation<C> + ?Sized,
    {
        type Variable = T::Variable;
        type Mode = T::Mode;
    }

    ///
    pub trait HasEqual<V>: ConstraintSystem {
        ///
        fn eq(&mut self, lhs: &V, rhs: &V) -> Self::Bool;
    }

    impl<C, V> Equal<C> for V
    where
        C: HasEqual<V>,
    {
        #[inline]
        fn eq(cs: &mut C, lhs: &Self, rhs: &Self) -> C::Bool {
            HasEqual::eq(cs, lhs, rhs)
        }
    }

    /// Allocates a new unknown variable into `cs` with the given `mode`.
    #[inline]
    pub fn known<T, C>(cs: &mut C, value: &T, mode: KnownMode<T, C>) -> Var<T, C>
    where
        T: ?Sized,
        C: HasVariable<T> + ?Sized,
    {
        cs.new_known_allocation(value, mode)
    }

    /// Allocates a new unknown variable into `cs` with the given `mode`.
    #[inline]
    pub fn unknown<T, C>(cs: &mut C, mode: UnknownMode<T, C>) -> Var<T, C>
    where
        T: ?Sized,
        C: HasVariable<T> + ?Sized,
    {
        cs.new_unknown_allocation(mode)
    }
}

/// Type Aliases
///
/// All of these types depend on reflection capabilities. See [`reflection`] for more information.
pub mod types {
    use super::reflection::Var;

    /// Boolean Variable Type
    pub type Bool<C> = Var<bool, C>;

    /// Character Variable Type
    pub type Char<C> = Var<char, C>;

    /// 32-bit Floating Point Variable Type
    pub type F32<C> = Var<f32, C>;

    /// 64-bit Floating Point Variable Type
    pub type F64<C> = Var<f64, C>;

    /// Signed 8-bit Integer Variable Type
    pub type I8<C> = Var<i8, C>;

    /// Signed 16-bit Integer Variable Type
    pub type I16<C> = Var<i16, C>;

    /// Signed 32-bit Integer Variable Type
    pub type I32<C> = Var<i32, C>;

    /// Signed 64-bit Integer Variable Type
    pub type I64<C> = Var<i64, C>;

    /// Signed 128-bit Integer Variable Type
    pub type I128<C> = Var<i128, C>;

    /// Pointer-Sized Integer Variable Type
    pub type Isize<C> = Var<isize, C>;

    /// Unsigned 8-bit Integer Variable Type
    pub type U8<C> = Var<u8, C>;

    /// Unsigned 16-bit Integer Variable Type
    pub type U16<C> = Var<u16, C>;

    /// Unsigned 32-bit Integer Variable Type
    pub type U32<C> = Var<u32, C>;

    /// Unsigned 64-bit Integer Variable Type
    pub type U64<C> = Var<u64, C>;

    /// Unsigned 128-bit Integer Variable Type
    pub type U128<C> = Var<u128, C>;

    /// Pointer-Sized Unsigned Integer Variable Type
    pub type Usize<C> = Var<usize, C>;
}
*/
