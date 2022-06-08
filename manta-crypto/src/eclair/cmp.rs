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

//! Comparison

use crate::eclair::ops::Not;
use core::cmp;

/// Boolean Type
///
/// This `trait` should be implemented for compilers that offer a boolean type equivalent to `bool`.
pub trait HasBool {
    /// Boolean Type
    ///
    /// This type should have a notion of `true` and `false` and negation.
    type Bool: Not<Self, Output = Self::Bool>;
}

impl HasBool for () {
    type Bool = bool;
}

///
pub trait Eq<COM = ()>: PartialEq<Self, COM>
where
    COM: HasBool,
{
}

impl<T> Eq for T where T: cmp::Eq {}

///
pub trait PartialEq<Rhs = Self, COM = ()>
where
    Rhs: ?Sized,
    COM: HasBool + ?Sized,
{
    ///
    fn eq(&self, rhs: &Rhs, compiler: &mut COM) -> COM::Bool;

    ///
    #[inline]
    fn ne(&self, other: &Rhs, compiler: &mut COM) -> COM::Bool {
        self.eq(other, compiler).not(compiler)
    }

    /* TODO:
       /// Asserts that `lhs` and `rhs` are equal.
       #[inline]
       fn assert_eq(lhs: &Self, rhs: &Self, compiler: &mut COM) {
           let boolean = lhs.eq(rhs, compiler);
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
    */
}

impl<T, Rhs> PartialEq<Rhs> for T
where
    T: cmp::PartialEq<Rhs>,
{
    #[inline]
    fn eq(&self, rhs: &Rhs, _: &mut ()) -> bool {
        self.eq(rhs)
    }

    #[inline]
    fn ne(&self, rhs: &Rhs, _: &mut ()) -> bool {
        self.ne(rhs)
    }
}
