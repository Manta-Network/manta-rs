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

//! Assertions

use crate::eclair::{bool::Bool, cmp::PartialEq, Has};

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

/* FIXME: We cannot implement this yet.
impl Assert for () {
    #[inline]
    fn assert(&mut self, bit: &Bool<Self>) {
        // TODO: Use `dbg!` macro here to get more info, but add a feature-flag for this.
        assert!(bit);
    }
}
*/

/// Equality Assertion
pub trait AssertEq: Assert {
    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq<T, Rhs>(&mut self, lhs: &T, rhs: &Rhs)
    where
        T: PartialEq<Rhs, Self>,
    {
        let are_equal = lhs.eq(rhs, self);
        self.assert(&are_equal);
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

/// Within-Range Assertion
pub trait AssertWithinRange<T, const BITS: usize> {
    /// Asserts that `value` is smaller than `2^BITS`
    fn assert_within_range(&mut self, value: &T);
}
