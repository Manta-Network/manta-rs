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

//! Operations

use crate::eclair::cmp::{HasBool, PartialEq};
use core::{cmp, fmt::Debug, ops};

/// Assertion
pub trait Assert: HasBool {
    /// Asserts that `b` reduces to `true`.
    fn assert(&mut self, b: &Self::Bool);
}

impl Assert for () {
    #[inline]
    fn assert(&mut self, b: &Self::Bool) {
        // TODO: USe `dbg!` macro here to get more info, but add a feature-flag for this.
        assert!(b)
    }
}

/// Equality Assertion
pub trait AssertEq<T, Rhs = T>: Assert
where
    T: PartialEq<Rhs, Self>,
{
    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq(&mut self, lhs: &T, rhs: &Rhs) {
        let are_equal = lhs.eq(rhs, self);
        self.assert(&are_equal)
    }
}

impl<T, Rhs> AssertEq<T, Rhs> for ()
where
    T: cmp::PartialEq<Rhs> + Debug,
    Rhs: Debug,
{
    #[inline]
    fn assert_eq(&mut self, lhs: &T, rhs: &Rhs) {
        assert_eq!(lhs, rhs)
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

impl<T> Add<()> for T
where
    T: ops::Add<Output = T>,
{
    #[inline]
    fn add(lhs: Self, rhs: Self, _: &mut ()) -> Self {
        lhs.add(rhs)
    }
}

/// Negation
pub trait Not<COM = ()>
where
    COM: ?Sized,
{
    /// Output Type
    type Output;

    ///
    fn not(self, compiler: &mut COM) -> Self::Output;
}

impl<T> Not for T
where
    T: ops::Not,
{
    type Output = T::Output;

    #[inline]
    fn not(self, _: &mut ()) -> Self::Output {
        self.not()
    }
}

/// Subtraction
pub trait Sub<COM>
where
    COM: ?Sized,
{
    /// Subtracts `rhs` from `lhs` inside of `compiler`.
    fn sub(lhs: Self, rhs: Self, compiler: &mut COM) -> Self;
}

impl<T> Sub<()> for T
where
    T: ops::Sub<Output = T>,
{
    #[inline]
    fn sub(lhs: Self, rhs: Self, _: &mut ()) -> Self {
        lhs.sub(rhs)
    }
}
