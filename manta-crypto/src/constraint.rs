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

// TODO: Add derive trait to implement `Alloc` for structs (and enums?).
// TODO: How to do verification systems? Should it be a separate trait or part of `ProofSystem`?

use core::convert::{Infallible, TryFrom};

/// Boolean Variable Type
pub type Bool<P> = <P as BooleanSystem>::Bool;

/// Variable Type
pub type Variable<T, P, K = (), U = K> = <T as Var<P, K, U>>::Variable;

/// Constant Type
pub type Constant<T, P> = <T as Var<P, Public, Infallible>>::Variable;

/// Character Variable Type
pub type Char<P, K = (), U = K> = Variable<char, P, K, U>;

/// Signed 8-bit Integer Variable Type
pub type I8<P, K = (), U = K> = Variable<i8, P, K, U>;

/// Signed 16-bit Integer Variable Type
pub type I16<P, K = (), U = K> = Variable<i16, P, K, U>;

/// Signed 32-bit Integer Variable Type
pub type I32<P, K = (), U = K> = Variable<i32, P, K, U>;

/// Signed 64-bit Integer Variable Type
pub type I64<P, K = (), U = K> = Variable<i64, P, K, U>;

/// Signed 128-bit Integer Variable Type
pub type I128<P, K = (), U = K> = Variable<i128, P, K, U>;

/// Unsigned 8-bit Integer Variable Type
pub type U8<P, K = (), U = K> = Variable<u8, P, K, U>;

/// Unsigned 16-bit Integer Variable Type
pub type U16<P, K = (), U = K> = Variable<u16, P, K, U>;

/// Unsigned 32-bit Integer Variable Type
pub type U32<P, K = (), U = K> = Variable<u32, P, K, U>;

/// Unsigned 64-bit Integer Variable Type
pub type U64<P, K = (), U = K> = Variable<u64, P, K, U>;

/// Unsigned 128-bit Integer Variable Type
pub type U128<P, K = (), U = K> = Variable<u128, P, K, U>;

/// Allocation Entry
pub enum Allocation<T, Known = (), Unknown = Known> {
    /// Known Value
    Value(T, Known),

    /// Unknown Value
    Unknown(Unknown),
}

/// Variable Reflection Trait
pub trait IsVariable<P, Known = (), Unknown = Known>: Sized
where
    P: ?Sized,
{
    /// Origin Type of the Variable
    type Type: Var<P, Known, Unknown, Variable = Self>;

    /// Returns a new variable with `value`.
    #[inline]
    fn new_variable(value: &Self::Type, ps: &mut P, mode: Known) -> Self {
        value.as_variable(ps, mode)
    }

    /// Returns a new variable with an unknown value.
    #[inline]
    fn new_unknown(ps: &mut P, mode: Unknown) -> Self {
        Self::Type::unknown(ps, mode)
    }
}

/// Variable Trait
pub trait Var<P, Known = (), Unknown = Known>
where
    P: ?Sized,
{
    /// Variable Object
    type Variable: IsVariable<P, Known, Unknown, Type = Self>;

    /// Returns a new variable with value `self`.
    fn as_variable(&self, ps: &mut P, mode: Known) -> Self::Variable;

    /// Returns a new variable with an unknown value.
    fn unknown(ps: &mut P, mode: Unknown) -> Self::Variable;
}

/// Constant Trait
pub trait Const<P>: Var<P, Public, Infallible>
where
    P: ?Sized,
{
    /// Returns a new constant with value `self`.
    #[inline]
    fn as_constant(&self, ps: &mut P) -> Self::Variable {
        self.as_variable(ps, Public)
    }
}

impl<T, P> Const<P> for T
where
    T: Var<P, Public, Infallible>,
    P: ?Sized,
{
}

/// Boolean Constraint System
pub trait BooleanSystem {
    /// Boolean Variable Type
    type Bool: IsVariable<Self, Self::KnownBool, Self::UnknownBool, Type = bool>;

    /// Known Boolean Allocation Mode Type
    type KnownBool;

    /// Unknown Boolean Allocation Mode Type
    type UnknownBool;

    /// Allocates a known boolean with value `b` with the given `mode`.
    fn known_bool(&mut self, b: bool, mode: Self::KnownBool) -> Self::Bool;

    /// Allocates an unknown boolean with the given `mode`.
    fn unknown_bool(&mut self, mode: Self::UnknownBool) -> Self::Bool;

    /// Allocates a new variable with the given `value`.
    #[inline]
    fn allocate_variable<T, K, U>(&mut self, value: T, mode: K) -> T::Variable
    where
        T: Var<Self, K, U>,
    {
        value.as_variable(self, mode)
    }

    /// Allocates a new variable with an unknown value.
    #[inline]
    fn allocate_unknown<T, K, U>(&mut self, mode: U) -> T::Variable
    where
        T: Var<Self, K, U>,
    {
        T::unknown(self, mode)
    }

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

    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq<V, K, U>(&mut self, lhs: &V, rhs: &V)
    where
        V: IsVariable<Self, K, U>,
        V::Type: Equal<Self, K, U>,
    {
        V::Type::assert_eq(self, lhs, rhs)
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, V, K, U, I>(&mut self, base: &'t V, iter: I)
    where
        V: 't + IsVariable<Self, K, U>,
        V::Type: Equal<Self, K, U>,
        I: IntoIterator<Item = &'t V>,
    {
        V::Type::assert_all_eq_to_base(self, base, iter)
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, V, K, U, I>(&mut self, iter: I)
    where
        V: 't + IsVariable<Self, K, U>,
        V::Type: Equal<Self, K, U>,
        I: IntoIterator<Item = &'t V>,
    {
        V::Type::assert_all_eq(self, iter)
    }
}

impl<P> Var<P, P::KnownBool, P::UnknownBool> for bool
where
    P: BooleanSystem + ?Sized,
{
    type Variable = P::Bool;

    #[inline]
    fn as_variable(&self, ps: &mut P, mode: P::KnownBool) -> Self::Variable {
        ps.known_bool(*self, mode)
    }

    #[inline]
    fn unknown(ps: &mut P, mode: P::UnknownBool) -> Self::Variable {
        ps.unknown_bool(mode)
    }
}

/// Equality Trait
pub trait Equal<P, Known = (), Unknown = Known>: Var<P, Known, Unknown>
where
    P: BooleanSystem + ?Sized,
{
    /// Generates a boolean that represents the fact that `lhs` and `rhs` may be equal.
    fn eq(ps: &mut P, lhs: &Self::Variable, rhs: &Self::Variable) -> P::Bool;

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

/// Derived Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Derived;

/// Always Public Allocation Mode
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Public;

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

impl From<Derived> for Secret {
    #[inline]
    fn from(d: Derived) -> Self {
        let _ = d;
        Self
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
        match pos {
            PublicOrSecret::Public => Ok(Self),
            PublicOrSecret::Secret => Err(Secret),
        }
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
        match pos {
            PublicOrSecret::Secret => Ok(Self),
            PublicOrSecret::Public => Err(Public),
        }
    }
}
