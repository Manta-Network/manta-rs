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

//! Conversion Utilities

use core::convert::Infallible;

/// The Never Type
///
/// This `type` will eventually be replaced by `!`, the primitive never type. See the ongoing
/// discussion for the [never_type #35121](https://github.com/rust-lang/rust/issues/35121) feature.
pub type Never = Infallible;

/// Promotes a [`Never`] value to another type.
#[inline]
pub fn never<T>(_: Never) -> T {
    unreachable!("This type never has any values, so this promotion is safe.")
}

/// Contextual Conversion Equivalent of [`From`](core::convert::From)
pub trait From<T, CONTEXT = ()>: Sized {
    /// Performs the conversion from `t` to an element of type `Self`.
    fn from(t: T) -> Self;
}

impl<T, CONTEXT> From<T, CONTEXT> for T {
    #[inline]
    fn from(t: T) -> Self {
        t
    }
}

/// Contextual Conversion Equivalent of [`Into`](core::convert::Into)
pub trait Into<T, CONTEXT = ()>: Sized {
    /// Performs the conversion from `self` to an element of type `T`.
    fn into(self) -> T;
}

impl<A, B, CONTEXT> Into<B, CONTEXT> for A
where
    B: From<A, CONTEXT>,
{
    #[inline]
    fn into(self) -> B {
        B::from(self)
    }
}

/// Contextual Conversion Equivalent of [`TryFrom`](core::convert::TryFrom)
pub trait TryFrom<T, CONTEXT = ()>: Sized {
    /// Conversion Error Type
    type Error;

    /// Tries to perform the conversion from `t` to an element of type `Self` but may fail
    /// with [`Self::Error`].
    fn try_from(t: T) -> Result<Self, Self::Error>;
}

impl<A, B, CONTEXT> TryFrom<A, CONTEXT> for B
where
    A: Into<B, CONTEXT>,
{
    type Error = Infallible;

    #[inline]
    fn try_from(a: A) -> Result<Self, Self::Error> {
        Ok(a.into())
    }
}

/// Contextual Conversion Equivalent of [`TryInto`](core::convert::TryInto)
pub trait TryInto<T, CONTEXT = ()>: Sized {
    /// Conversion Error Type
    type Error;

    /// Tries to perform the conversion from `self` to an element of type `T` but may fail with
    /// [`Self::Error`].
    fn try_into(self) -> Result<T, Self::Error>;
}

impl<A, B, CONTEXT> TryInto<B, CONTEXT> for A
where
    B: TryFrom<A, CONTEXT>,
{
    type Error = B::Error;

    #[inline]
    fn try_into(self) -> Result<B, Self::Error> {
        TryFrom::try_from(self)
    }
}
