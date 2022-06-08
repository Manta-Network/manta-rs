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

//! Structures over Booleans
//!
//! For many of the standard Rust operations we need access to some simulation of the primitive
//! types. In this module, we define the access interfaces needed to simulate the [`bool`] type with
//! [`Bool`].

use crate::eclair::{cmp::PartialEq, Has};
use core::{cmp, fmt::Debug};

/// Boolean Type Inside of the Compiler
pub type Bool<COM = ()> = <COM as Has<bool>>::Type;

/// Assertion
pub trait Assert: Has<bool> {
    /// Asserts that `bit` reduces to `true`.
    fn assert(&mut self, bit: &Bool<Self>);

    /// Asserts that all the items in the `iter` reduce to `true`.
    #[inline]
    fn assert_all<'b, I>(&mut self, iter: I)
    where
        Self: Assert,
        Bool<Self>: 'b,
        I: IntoIterator<Item = &'b Bool<Self>>,
    {
        iter.into_iter().for_each(move |b| self.assert(b));
    }
}

impl Assert for () {
    #[inline]
    fn assert(&mut self, bit: &Bool<Self>) {
        // TODO: USe `dbg!` macro here to get more info, but add a feature-flag for this.
        assert!(bit);
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
        self.assert(&are_equal);
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, I>(&mut self, base: &'t T, iter: I)
    where
        Rhs: 't,
        I: IntoIterator<Item = &'t Rhs>,
    {
        for item in iter {
            self.assert_eq(base, item);
        }
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, I>(&mut self, iter: I)
    where
        Self: AssertEq<T>,
        T: 't + PartialEq<T, Self>,
        I: IntoIterator<Item = &'t T>,
    {
        let mut iter = iter.into_iter();
        if let Some(base) = iter.next() {
            self.assert_all_eq_to_base(base, iter);
        }
    }
}

impl<T, Rhs> AssertEq<T, Rhs> for ()
where
    T: cmp::PartialEq<Rhs> + Debug,
    Rhs: Debug,
{
    #[inline]
    fn assert_eq(&mut self, lhs: &T, rhs: &Rhs) {
        assert_eq!(lhs, rhs);
    }
}

/// Conditional Selection
pub trait ConditionalSelect<COM = ()>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Selects the result of `true_value` when `bit == true` and the result of `false_value` when
    /// `bit == false`.
    fn select_from<T, F>(
        bit: &Bool<COM>,
        true_value: T,
        false_value: F,
        compiler: &mut COM,
    ) -> Self
    where
        T: FnOnce() -> Self,
        F: FnOnce() -> Self;

    /// Selects `true_value` when `bit == true` and `false_value` when `bit == false`.
    #[inline]
    fn select(bit: &Bool<COM>, true_value: Self, false_value: Self, compiler: &mut COM) -> Self {
        Self::select_from(bit, || true_value, || false_value, compiler)
    }
}

impl<V> ConditionalSelect for V {
    #[inline]
    fn select_from<T, F>(bit: &bool, true_value: T, false_value: F, _: &mut ()) -> Self
    where
        T: FnOnce() -> Self,
        F: FnOnce() -> Self,
    {
        if *bit {
            true_value()
        } else {
            false_value()
        }
    }
}

/// Conditional Swap
pub trait ConditionalSwap<COM = ()>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Swaps `lhs` and `rhs` whenever `bit == true` and keeps them in the same order when `bit ==
    /// false`.
    fn swap(bit: &Bool<COM>, lhs: Self, rhs: Self, compiler: &mut COM) -> (Self, Self);
}

impl<V> ConditionalSwap for V {
    #[inline]
    fn swap(bit: &bool, lhs: Self, rhs: Self, _: &mut ()) -> (Self, Self) {
        if *bit {
            (rhs, lhs)
        } else {
            (lhs, rhs)
        }
    }
}
