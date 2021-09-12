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
// TODO: Add derive trait to implement `Alloc` for structs (and enums?).
// TODO: Add more convenience functions for allocating unknown variables.
// TODO: How to do verification systems? Should it be a separate trait or part of `ProofSystem`?
// TODO: Should we (can we?) seal the `HasVariable` trait so no one implements it by accident?

use core::{
    convert::{Infallible, TryFrom},
    marker::PhantomData,
};

#[doc(inline)]
pub use types::Bool;

/// Variable Type
pub type Var<T, P> = <P as HasVariable<T>>::Variable;

/// Allocation Mode Type
pub type Mode<T, P> = <Var<T, P> as Variable<P>>::Mode;

/// Known Allocation Mode Type
pub type KnownMode<T, P> = <Mode<T, P> as AllocationMode>::Known;

/// Known Allocation Mode Type
pub type UnknownMode<T, P> = <Mode<T, P> as AllocationMode>::Unknown;

/// Allocation Mode
pub trait AllocationMode {
    /// Known Allocation Mode
    type Known;

    /// Unknown Allocation Mode
    type Unknown;

    /* TODO: Do we want this?
    /// Upgrades the unknown allocation mode to the known allocation mode.
    #[inline]
    fn upgrade_mode(mode: Self::Unknown) -> Self::Known;

    /// Upgrades the value from an unknown to known allocation.
    #[inline]
    fn upgrade<P, T>(value: &T, mode: Self::Unknown) -> Allocation<T, P>
    where
        T: Alloc<P, Mode = Self>,
    {
        Allocation::Known(value, Self::upgrade_mode(mode))
    }
    */
}

impl AllocationMode for Infallible {
    type Known = Infallible;
    type Unknown = Infallible;
}

impl AllocationMode for () {
    type Known = ();
    type Unknown = ();
}

/// Allocation Entry
pub enum Allocation<'t, T, P>
where
    T: ?Sized,
    P: HasVariable<T> + ?Sized,
{
    /// Known Value
    Known(
        /// Allocation Value
        &'t T,
        /// Allocation Mode
        KnownMode<T, P>,
    ),
    /// Unknown Value
    Unknown(
        /// Allocation Mode
        UnknownMode<T, P>,
    ),
}

impl<'t, T, P> Allocation<'t, T, P>
where
    T: ?Sized,
    P: HasVariable<T> + ?Sized,
{
    /// Returns `true` if `self` represents a known variable.
    #[inline]
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(..))
    }

    /// Returns `true` if `self` represents an unknown value.
    #[inline]
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(..))
    }

    /// Converts `self` into a possible known value.
    #[inline]
    pub fn known(self) -> Option<(&'t T, KnownMode<T, P>)> {
        match self {
            Self::Known(value, mode) => Some((value, mode)),
            _ => None,
        }
    }

    /// Converts `self` into a possibly unknown value.
    #[inline]
    pub fn unknown(self) -> Option<UnknownMode<T, P>> {
        match self {
            Self::Unknown(mode) => Some(mode),
            _ => None,
        }
    }

    /// Maps the underlying allocation value if it is known.
    #[inline]
    pub fn map<'u, U, Q, F>(self, f: F) -> Allocation<'u, U, Q>
    where
        U: ?Sized,
        Q: HasVariable<U, Mode = Mode<T, P>> + ?Sized,
        F: FnOnce(&'t T) -> &'u U,
    {
        match self {
            Self::Known(value, mode) => Allocation::Known(f(value), mode),
            Self::Unknown(mode) => Allocation::Unknown(mode),
        }
    }

    /// Allocates a variable into `ps` using `self` as the allocation.
    #[inline]
    pub fn into_variable(self, ps: &mut P) -> Var<T, P> {
        ps.allocate(self)
    }
}

impl<'t, T, P> From<(&'t T, KnownMode<T, P>)> for Allocation<'t, T, P>
where
    T: ?Sized,
    P: HasVariable<T> + ?Sized,
{
    #[inline]
    fn from((value, mode): (&'t T, KnownMode<T, P>)) -> Self {
        Self::Known(value, mode)
    }
}

/// Variable Allocation Trait
pub trait Alloc<P>
where
    P: ?Sized,
{
    /// Allocation Mode
    type Mode: AllocationMode;

    /// Variable Object Type
    type Variable: Variable<P, Mode = Self::Mode, Type = Self>;

    /// Allocates a new variable into `ps` with the given `allocation`.
    fn variable<'t>(ps: &mut P, allocation: impl Into<Allocation<'t, Self, P>>) -> Self::Variable
    where
        Self: 't;

    /// Allocates a new known variable into `ps` with the given `mode`.
    #[inline]
    fn as_known(
        &self,
        ps: &mut P,
        mode: impl Into<<Self::Mode as AllocationMode>::Known>,
    ) -> Self::Variable {
        Self::variable(ps, (self, mode.into()))
    }

    /// Allocates a new unknown variable into `ps` with the given `mode`.
    #[inline]
    fn unknown(
        ps: &mut P,
        mode: impl Into<<Self::Mode as AllocationMode>::Unknown>,
    ) -> Self::Variable {
        Self::variable(ps, Allocation::Unknown(mode.into()))
    }
}

/// Variable Reflection Trait
pub trait Variable<P>: Sized
where
    P: ?Sized,
{
    /// Allocation Mode
    type Mode: AllocationMode;

    /// Origin Type of the Variable
    type Type: Alloc<P, Mode = Self::Mode, Variable = Self>;

    /// Allocates a new variable into `ps` with the given `allocation`.
    #[inline]
    fn new<'t>(ps: &mut P, allocation: impl Into<Allocation<'t, Self::Type, P>>) -> Self
    where
        Self::Type: 't,
    {
        Self::Type::variable(ps, allocation)
    }

    /// Allocates a new known variable into `ps` with the given `mode`.
    #[inline]
    fn new_known(
        ps: &mut P,
        value: &Self::Type,
        mode: impl Into<<Self::Mode as AllocationMode>::Known>,
    ) -> Self {
        Self::new(ps, (value, mode.into()))
    }

    /// Allocates a new unknown variable into `ps` with the given `mode`.
    #[inline]
    fn new_unknown(ps: &mut P, mode: impl Into<<Self::Mode as AllocationMode>::Unknown>) -> Self {
        Self::new(ps, Allocation::Unknown(mode.into()))
    }
}

/// Variable Reflection Trait
pub trait HasVariable<T>
where
    T: ?Sized,
{
    /// Allocation Mode
    type Mode: AllocationMode;

    /// Variable Object Type
    type Variable: Variable<Self, Mode = Self::Mode, Type = T>;

    /// Allocates a new variable into `self` with the given `allocation`.
    #[inline]
    fn allocate<'t>(&mut self, allocation: impl Into<Allocation<'t, T, Self>>) -> Self::Variable
    where
        T: 't,
    {
        Self::Variable::new(self, allocation)
    }

    /// Allocates a new known variable into `self` with the given `mode`.
    #[inline]
    fn allocate_known(
        &mut self,
        value: &T,
        mode: impl Into<<Self::Mode as AllocationMode>::Known>,
    ) -> Self::Variable {
        self.allocate((value, mode.into()))
    }

    /// Allocates a new unknown variable into `self` with the given `mode`.
    #[inline]
    fn allocate_unknown(
        &mut self,
        mode: impl Into<<Self::Mode as AllocationMode>::Unknown>,
    ) -> Self::Variable {
        self.allocate(Allocation::Unknown(mode.into()))
    }
}

impl<P, T> HasVariable<T> for P
where
    P: ?Sized,
    T: Alloc<P> + ?Sized,
{
    type Mode = T::Mode;
    type Variable = T::Variable;
}

/// Allocates a new unknown variable into `ps` with the given `mode`.
#[inline]
pub fn known<T, P>(ps: &mut P, value: &T, mode: KnownMode<T, P>) -> Var<T, P>
where
    T: ?Sized,
    P: HasVariable<T> + ?Sized,
{
    ps.allocate_known(value, mode)
}

/// Allocates a new unknown variable into `ps` with the given `mode`.
#[inline]
pub fn unknown<T, P>(ps: &mut P, mode: UnknownMode<T, P>) -> Var<T, P>
where
    T: ?Sized,
    P: HasVariable<T> + ?Sized,
{
    ps.allocate_unknown(mode)
}

impl<T, P> Alloc<P> for PhantomData<T>
where
    T: ?Sized,
    P: ?Sized,
{
    type Mode = ();

    type Variable = PhantomData<T>;

    #[inline]
    fn variable<'t>(ps: &mut P, allocation: impl Into<Allocation<'t, Self, P>>) -> Self::Variable
    where
        Self: 't,
    {
        let _ = (ps, allocation);
        PhantomData
    }
}

impl<T, P> Variable<P> for PhantomData<T>
where
    T: ?Sized,
    P: ?Sized,
{
    type Mode = ();
    type Type = PhantomData<T>;
}

/// Boolean Constraint System
pub trait BooleanSystem: HasVariable<bool> {
    /// Asserts that `b` is `true`.
    fn assert(&mut self, b: Bool<Self>);

    /// Asserts that all the booleans in `iter` are `true`.
    #[inline]
    fn assert_all<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Bool<Self>>,
    {
        iter.into_iter().for_each(move |b| self.assert(b))
    }

    /// Generates a boolean that represents the fact that `lhs` and `rhs` may be equal.
    #[inline]
    fn eq<V>(&mut self, lhs: &V, rhs: &V) -> Bool<Self>
    where
        V: Variable<Self>,
        V::Type: Equal<Self>,
    {
        V::Type::eq(self, lhs, rhs)
    }

    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq<V>(&mut self, lhs: &V, rhs: &V)
    where
        V: Variable<Self>,
        V::Type: Equal<Self>,
    {
        V::Type::assert_eq(self, lhs, rhs)
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, V, I>(&mut self, base: &'t V, iter: I)
    where
        V: 't + Variable<Self>,
        V::Type: Equal<Self>,
        I: IntoIterator<Item = &'t V>,
    {
        V::Type::assert_all_eq_to_base(self, base, iter)
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, V, I>(&mut self, iter: I)
    where
        V: 't + Variable<Self>,
        V::Type: Equal<Self>,
        I: IntoIterator<Item = &'t V>,
    {
        V::Type::assert_all_eq(self, iter)
    }
}

/// Equality Trait
pub trait Equal<P>: Alloc<P>
where
    P: BooleanSystem + ?Sized,
{
    /// Generates a boolean that represents the fact that `lhs` and `rhs` may be equal.
    fn eq(ps: &mut P, lhs: &Self::Variable, rhs: &Self::Variable) -> Bool<P>;

    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq(ps: &mut P, lhs: &Self::Variable, rhs: &Self::Variable) {
        let boolean = Self::eq(ps, lhs, rhs);
        ps.assert(boolean)
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, I>(ps: &mut P, base: &'t Self::Variable, iter: I)
    where
        I: IntoIterator<Item = &'t Self::Variable>,
    {
        for item in iter {
            Self::assert_eq(ps, base, item)
        }
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, I>(ps: &mut P, iter: I)
    where
        Self::Variable: 't,
        I: IntoIterator<Item = &'t Self::Variable>,
    {
        let mut iter = iter.into_iter();
        if let Some(base) = iter.next() {
            Self::assert_all_eq_to_base(ps, base, iter)
        }
    }
}

/// Proof System
pub trait ProofSystem: BooleanSystem + Default {
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

/* TODO: Should we have this mode?
/// Compound Allocation Mode
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompoundMode<Known, Unknown> {
    /// Known Allocation Mode
    Known(Known),

    /// Unknown Allocation Mode
    Unknown(Unknown),
}

impl<Known, Unknown> AllocationMode for CompoundMode<Known, Unknown> {
    type Known = Known;
    type Unknown = Unknown;
}
*/

/// Derived Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Derived;

impl AllocationMode for Derived {
    type Known = Derived;
    type Unknown = Derived;
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
    type Known = Public;
    type Unknown = Public;
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
    type Known = Secret;
    type Unknown = Secret;
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
    type Known = PublicOrSecret;
    type Unknown = PublicOrSecret;
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

/// Type Aliases
pub mod types {
    use super::*;

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
