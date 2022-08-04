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

use crate::eclair::{cmp::PartialEq, Has, Type};

/// Boolean Type Inside of the Compiler
pub type Bool<COM = ()> = Type<COM, bool>;

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
    fn assert(&mut self, bit: &bool) {
        assert!(bit)
    }
}

/// Equality Assertion
pub trait AssertEq: Assert {
    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq<T, Rhs>(&mut self, lhs: &T, rhs: &Rhs)
    where
        T: PartialEq<Rhs, Self>,
    {
        T::assert_equal(lhs, rhs, self);
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, T, Rhs, I>(&mut self, base: &'t T, iter: I)
    where
        T: PartialEq<Rhs, Self>,
        Rhs: 't,
        I: IntoIterator<Item = &'t Rhs>,
    {
        for item in iter {
            self.assert_eq(base, item);
        }
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, T, I>(&mut self, iter: I)
    where
        T: 't + PartialEq<T, Self>,
        I: IntoIterator<Item = &'t T>,
    {
        let mut iter = iter.into_iter();
        if let Some(base) = iter.next() {
            self.assert_all_eq_to_base(base, iter);
        }
    }
}

impl<COM> AssertEq for COM where COM: Assert {}

/// Conditional Selection
pub trait ConditionalSelect<COM = ()>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Selects `true_value` when `bit == true` and `false_value` when `bit == false`.
    fn select(bit: &Bool<COM>, true_value: &Self, false_value: &Self, compiler: &mut COM) -> Self;
}

///
macro_rules! impl_conditional_select {
    ($($type:tt),* $(,)?) => {
        $(
            impl ConditionalSelect for $type {
                #[inline]
                fn select(bit: &Bool, true_value: &Self, false_value: &Self, _: &mut ()) -> Self {
                    if *bit {
                        true_value.clone()
                    } else {
                        false_value.clone()
                    }
                }
            }
        )*
    }
}

impl_conditional_select!(bool, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// Conditional Swap
pub trait ConditionalSwap<COM = ()>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Swaps `lhs` and `rhs` whenever `bit == true` and keeps them in the same order when `bit ==
    /// false`.
    fn swap(bit: &Bool<COM>, lhs: &Self, rhs: &Self, compiler: &mut COM) -> (Self, Self);
}
