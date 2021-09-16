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

//! Constraint Proof Systems

// TODO: Add derive macros to all the enums/structs here.
// TODO: Add derive trait to implement `HasAllocation` for structs (and enums?).
// TODO: Add more convenience functions for allocating unknown variables.
// TODO: How to do verification systems? Should it be a separate trait or part of `ProofSystem`?

use core::{
    convert::{Infallible, TryFrom},
    fmt::Debug,
    hash::Hash,
    marker::PhantomData,
};

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

    /// Allocates a variable with `self` as the allocation entry into `ps`.
    #[inline]
    pub fn allocate<P, V>(self, ps: &mut P) -> V
    where
        P: ?Sized,
        V: Variable<P, Type = T, Mode = Mode>,
    {
        V::new(ps, self)
    }

    /// Allocates a variable into `ps` after mapping over `self`.
    #[inline]
    pub fn map_allocate<P, V, F>(self, ps: &mut P, f: F) -> V
    where
        Mode::Known: Into<<V::Mode as AllocationMode>::Known>,
        Mode::Unknown: Into<<V::Mode as AllocationMode>::Unknown>,
        P: ?Sized,
        V: Variable<P>,
        F: FnOnce(&'t T) -> V::Type,
    {
        match self {
            Self::Known(value, mode) => V::new_known(ps, &f(value), mode),
            Self::Unknown(mode) => V::new_unknown(ps, mode),
        }
    }
}

/// Variable Allocation Trait
pub trait Variable<P>: Sized
where
    P: ?Sized,
{
    /// Origin Type of the Variable
    type Type;

    /// Allocation Mode
    type Mode: AllocationMode;

    /// Allocates a new variable into `ps` with the given `allocation`.
    fn new(ps: &mut P, allocation: Allocation<Self::Type, Self::Mode>) -> Self;

    /// Allocates a new known variable into `ps` with the given `mode`.
    #[inline]
    fn new_known(
        ps: &mut P,
        value: &Self::Type,
        mode: impl Into<<Self::Mode as AllocationMode>::Known>,
    ) -> Self {
        Self::new(ps, Allocation::Known(value, mode.into()))
    }

    /// Allocates a new unknown variable into `ps` with the given `mode`.
    #[inline]
    fn new_unknown(ps: &mut P, mode: impl Into<<Self::Mode as AllocationMode>::Unknown>) -> Self {
        Self::new(ps, Allocation::Unknown(mode.into()))
    }

    /// Allocates a new known variable into `ps` with the given `mode` which holds the default
    /// value of [`Self::Type`].
    #[inline]
    fn from_default(ps: &mut P, mode: impl Into<<Self::Mode as AllocationMode>::Known>) -> Self
    where
        Self::Type: Default,
    {
        Self::new_known(ps, &Default::default(), mode)
    }

    /// Allocates a new known variable into `ps` with the given `mode` which holds the default
    /// value of [`&Self::Type`](Self::Type).
    #[inline]
    fn from_default_ref<'t>(
        ps: &mut P,
        mode: impl Into<<Self::Mode as AllocationMode>::Known>,
    ) -> Self
    where
        Self::Type: 't,
        &'t Self::Type: Default,
    {
        Self::new_known(ps, Default::default(), mode)
    }
}

/// Variable Source
pub trait VariableSource {
    /// Allocates a new variable into `ps` with the given `allocation`.
    #[inline]
    fn as_variable<P, V>(ps: &mut P, allocation: Allocation<Self, V::Mode>) -> V
    where
        P: ?Sized,
        V: Variable<P, Type = Self>,
    {
        V::new(ps, allocation)
    }

    /// Allocates a new known variable into `ps` with the given `mode`.
    #[inline]
    fn as_known<P, V>(&self, ps: &mut P, mode: impl Into<<V::Mode as AllocationMode>::Known>) -> V
    where
        P: ?Sized,
        V: Variable<P, Type = Self>,
    {
        V::new_known(ps, self, mode)
    }

    /// Allocates a new unknown variable into `ps` with the given `mode`.
    #[inline]
    fn as_unknown<P, V>(ps: &mut P, mode: impl Into<<V::Mode as AllocationMode>::Unknown>) -> V
    where
        P: ?Sized,
        V: Variable<P, Type = Self>,
    {
        V::new_unknown(ps, mode)
    }
}

impl<T> VariableSource for T where T: ?Sized {}

impl<T, P> Variable<P> for PhantomData<T>
where
    T: ?Sized,
    P: ?Sized,
{
    type Type = PhantomData<T>;

    type Mode = ();

    #[inline]
    fn new(ps: &mut P, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        let _ = (ps, allocation);
        PhantomData
    }
}

impl<T, P> reflection::HasAllocation<P> for PhantomData<T>
where
    T: ?Sized,
    P: ?Sized,
{
    type Variable = PhantomData<T>;
    type Mode = ();
}

/// Allocates a new known variable into `ps` with the given `mode`.
#[inline]
pub fn known<P, V>(
    ps: &mut P,
    value: &V::Type,
    mode: impl Into<<V::Mode as AllocationMode>::Known>,
) -> V
where
    P: ?Sized,
    V: Variable<P>,
{
    V::new_known(ps, value, mode)
}

/// Allocates a new unknown variable into `ps` with the given `mode`.
#[inline]
pub fn unknown<P, V>(ps: &mut P, mode: impl Into<<V::Mode as AllocationMode>::Unknown>) -> V
where
    P: ?Sized,
    V: Variable<P>,
{
    V::new_unknown(ps, mode)
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

impl<P> AllocationSystem for P where P: ?Sized {}

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
        iter.into_iter().for_each(move |b| self.assert(b))
    }

    /// Generates a boolean that represents the fact that `lhs` and `rhs` may be equal.
    #[inline]
    fn eq<V>(&mut self, lhs: &V, rhs: &V) -> Self::Bool
    where
        V: Variable<Self> + Equal<Self>,
    {
        V::eq(self, lhs, rhs)
    }

    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq<V>(&mut self, lhs: &V, rhs: &V)
    where
        V: Variable<Self> + Equal<Self>,
    {
        V::assert_eq(self, lhs, rhs)
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, V, I>(&mut self, base: &'t V, iter: I)
    where
        V: 't + Variable<Self> + Equal<Self>,
        I: IntoIterator<Item = &'t V>,
    {
        V::assert_all_eq_to_base(self, base, iter)
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, V, I>(&mut self, iter: I)
    where
        V: 't + Variable<Self> + Equal<Self>,
        I: IntoIterator<Item = &'t V>,
    {
        V::assert_all_eq(self, iter)
    }
}

/// Equality Trait
pub trait Equal<P>: Variable<P>
where
    P: ConstraintSystem + ?Sized,
{
    /// Generates a boolean that represents the fact that `lhs` and `rhs` may be equal.
    fn eq(ps: &mut P, lhs: &Self, rhs: &Self) -> P::Bool;

    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq(ps: &mut P, lhs: &Self, rhs: &Self) {
        let boolean = Self::eq(ps, lhs, rhs);
        ps.assert(boolean)
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, I>(ps: &mut P, base: &'t Self, iter: I)
    where
        I: IntoIterator<Item = &'t Self>,
    {
        for item in iter {
            Self::assert_eq(ps, base, item)
        }
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, I>(ps: &mut P, iter: I)
    where
        Self: 't,
        I: IntoIterator<Item = &'t Self>,
    {
        let mut iter = iter.into_iter();
        if let Some(base) = iter.next() {
            Self::assert_all_eq_to_base(ps, base, iter)
        }
    }
}

/// Proof System
pub trait ProofSystem: ConstraintSystem + Default {
    /// Proof Type
    type Proof;

    /// Error Type
    type Error;

    /// Returns a proof that the boolean system is consistent.
    fn finish(self) -> Result<Self::Proof, Self::Error>;
}

/// Proof System Verifier
pub trait Verifier<P>
where
    P: ProofSystem + ?Sized,
{
    /// Verifies that a proof generated from a proof system is valid.
    fn verify(proof: &P::Proof) -> bool;
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
            _ => None,
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
            _ => None,
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
    pub type Var<T, P> = <P as HasVariable<T>>::Variable;

    /// Allocation Mode Type
    ///
    /// Requires a [`HasAllocation`] implementation for `T`.
    pub type Mode<T, P> = <Var<T, P> as Variable<P>>::Mode;

    /// Known Allocation Mode Type
    ///
    /// Requires a [`HasAllocation`] implementation for `T`.
    pub type KnownMode<T, P> = <Mode<T, P> as AllocationMode>::Known;

    /// Known Allocation Mode Type
    ///
    /// Requires a [`HasAllocation`] implementation for `T`.
    pub type UnknownMode<T, P> = <Mode<T, P> as AllocationMode>::Unknown;

    /// Allocation Entry Type
    ///
    /// Requires a [`HasAllocation`] implementation for `T`.
    pub type Alloc<'t, T, P> = Allocation<'t, T, Mode<T, P>>;

    /// Variable Existence Reflection Trait
    ///
    /// This trait can be optionally implemented by any type `T` which has an existing variable
    /// type that implements [`Variable<P, Type = T>`](Variable). Implementing this trait unlocks
    /// all of the reflection capabilities in this module.
    ///
    /// Whenever possible, library authors should implement [`HasAllocation`] on their types which
    /// have associated variables but should minimize their use of [`HasVariable`] so that users
    /// can take advantage of as much of a library as possible while implementing as little as
    /// possible.
    pub trait HasAllocation<P>
    where
        P: ?Sized,
    {
        /// Variable Object Type
        type Variable: Variable<P, Mode = Self::Mode, Type = Self>;

        /// Allocation Mode
        type Mode: AllocationMode;

        /// Allocates a new variable into `ps` with the given `allocation`.
        #[inline]
        fn variable(ps: &mut P, allocation: Allocation<Self, Self::Mode>) -> Self::Variable {
            Self::Variable::new(ps, allocation)
        }

        /// Allocates a new known variable into `ps` with the given `mode`.
        #[inline]
        fn known(
            &self,
            ps: &mut P,
            mode: impl Into<<Self::Mode as AllocationMode>::Known>,
        ) -> Self::Variable {
            Self::Variable::new_known(ps, self, mode)
        }

        /// Allocates a new unknown variable into `ps` with the given `mode`.
        #[inline]
        fn unknown(
            ps: &mut P,
            mode: impl Into<<Self::Mode as AllocationMode>::Unknown>,
        ) -> Self::Variable {
            Self::Variable::new_unknown(ps, mode)
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

    impl<P, T> HasVariable<T> for P
    where
        P: ?Sized,
        T: HasAllocation<P> + ?Sized,
    {
        type Variable = T::Variable;
        type Mode = T::Mode;
    }

    /// Allocates a new unknown variable into `ps` with the given `mode`.
    #[inline]
    pub fn known<T, P>(ps: &mut P, value: &T, mode: KnownMode<T, P>) -> Var<T, P>
    where
        T: ?Sized,
        P: HasVariable<T> + ?Sized,
    {
        ps.new_known_allocation(value, mode)
    }

    /// Allocates a new unknown variable into `ps` with the given `mode`.
    #[inline]
    pub fn unknown<T, P>(ps: &mut P, mode: UnknownMode<T, P>) -> Var<T, P>
    where
        T: ?Sized,
        P: HasVariable<T> + ?Sized,
    {
        ps.new_unknown_allocation(mode)
    }
}

/// Type Aliases
///
/// All of these types depend on reflection capabilities. See [`reflection`] for more information.
pub mod types {
    use super::reflection::Var;

    /// Boolean Variable Type
    pub type Bool<P> = Var<bool, P>;

    /// Character Variable Type
    pub type Char<P> = Var<char, P>;

    /// 32-bit Floating Point Variable Type
    pub type F32<P> = Var<f32, P>;

    /// 64-bit Floating Point Variable Type
    pub type F64<P> = Var<f64, P>;

    /// Signed 8-bit Integer Variable Type
    pub type I8<P> = Var<i8, P>;

    /// Signed 16-bit Integer Variable Type
    pub type I16<P> = Var<i16, P>;

    /// Signed 32-bit Integer Variable Type
    pub type I32<P> = Var<i32, P>;

    /// Signed 64-bit Integer Variable Type
    pub type I64<P> = Var<i64, P>;

    /// Signed 128-bit Integer Variable Type
    pub type I128<P> = Var<i128, P>;

    /// Pointer-Sized Integer Variable Type
    pub type Isize<P> = Var<isize, P>;

    /// Unsigned 8-bit Integer Variable Type
    pub type U8<P> = Var<u8, P>;

    /// Unsigned 16-bit Integer Variable Type
    pub type U16<P> = Var<u16, P>;

    /// Unsigned 32-bit Integer Variable Type
    pub type U32<P> = Var<u32, P>;

    /// Unsigned 64-bit Integer Variable Type
    pub type U64<P> = Var<u64, P>;

    /// Unsigned 128-bit Integer Variable Type
    pub type U128<P> = Var<u128, P>;

    /// Pointer-Sized Unsigned Integer Variable Type
    pub type Usize<P> = Var<usize, P>;
}
