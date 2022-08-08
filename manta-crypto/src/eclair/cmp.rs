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

use crate::eclair::{
    alloc::{Allocate, Constant},
    bool::{Assert, AssertEq, Bool},
    ops::{BitAnd, Not},
    Has, Type,
};
use core::cmp::{self, Ordering};
use manta_util::{Array, BoxArray};

/// Partial Equivalence Relations
pub trait PartialEq<Rhs, COM = ()>
where
    Rhs: ?Sized,
    COM: Has<bool> + ?Sized,
{
    /// Returns `true` if `self` and `rhs` are equal.
    fn eq(&self, rhs: &Rhs, compiler: &mut COM) -> Bool<COM>;

    /// Returns `true` if `self` and `rhs` are not equal.
    #[inline]
    fn ne(&self, other: &Rhs, compiler: &mut COM) -> Bool<COM>
    where
        Bool<COM>: Not<COM, Output = Bool<COM>>,
    {
        self.eq(other, compiler).not(compiler)
    }

    /// Asserts that `self` and `rhs` are equal.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for the case when comparing for equality and then
    /// asserting is more expensive than a custom assertion.
    #[inline]
    fn assert_equal(&self, rhs: &Rhs, compiler: &mut COM)
    where
        COM: Assert,
    {
        let are_equal = self.eq(rhs, compiler);
        compiler.assert(&are_equal);
    }
}

///
macro_rules! impl_partial_eq {
    ($($type:tt),* $(,)?) => {
        $(
            impl<Rhs> PartialEq<Rhs> for $type
            where
                $type: cmp::PartialEq<Rhs>,
            {
                #[inline]
                fn eq(&self, rhs: &Rhs, _: &mut ()) -> bool {
                    cmp::PartialEq::eq(self, rhs)
                }

                #[inline]
                fn ne(&self, rhs: &Rhs, _: &mut ()) -> bool {
                    cmp::PartialEq::ne(self, rhs)
                }
            }
        )*
    };
}

impl_partial_eq!(bool, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl<T, Rhs, COM> PartialEq<Vec<Rhs>, COM> for Vec<T>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    T: PartialEq<Rhs, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Vec<Rhs>, compiler: &mut COM) -> Bool<COM> {
        if self.len() != rhs.len() {
            false.as_constant(compiler)
        } else {
            let mut are_equal = true.as_constant::<Bool<COM>>(compiler);
            for (lhs, rhs) in self.iter().zip(rhs) {
                are_equal = are_equal.bitand(lhs.eq(rhs, compiler), compiler);
            }
            are_equal
        }
    }

    #[inline]
    fn assert_equal(&self, rhs: &Vec<Rhs>, compiler: &mut COM)
    where
        COM: Assert,
    {
        if self.len() != rhs.len() {
            let not_equal = false.as_constant(compiler);
            compiler.assert(&not_equal);
        } else {
            for (lhs, rhs) in self.iter().zip(rhs) {
                compiler.assert_eq(lhs, rhs);
            }
        }
    }
}

impl<T, Rhs, const N: usize, COM> PartialEq<Array<Rhs, N>, COM> for Array<T, N>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    T: PartialEq<Rhs, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Array<Rhs, N>, compiler: &mut COM) -> Bool<COM> {
        let mut are_equal = true.as_constant::<Bool<COM>>(compiler);
        for (lhs, rhs) in self.iter().zip(rhs) {
            are_equal = are_equal.bitand(lhs.eq(rhs, compiler), compiler);
        }
        are_equal
    }

    #[inline]
    fn assert_equal(&self, rhs: &Array<Rhs, N>, compiler: &mut COM)
    where
        COM: Assert,
    {
        for (lhs, rhs) in self.iter().zip(rhs) {
            compiler.assert_eq(lhs, rhs);
        }
    }
}

impl<T, Rhs, const N: usize, COM> PartialEq<BoxArray<Rhs, N>, COM> for BoxArray<T, N>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    T: PartialEq<Rhs, COM>,
{
    #[inline]
    fn eq(&self, rhs: &BoxArray<Rhs, N>, compiler: &mut COM) -> Bool<COM> {
        let mut are_equal = true.as_constant::<Bool<COM>>(compiler);
        for (lhs, rhs) in self.iter().zip(rhs) {
            are_equal = are_equal.bitand(lhs.eq(rhs, compiler), compiler);
        }
        are_equal
    }

    #[inline]
    fn assert_equal(&self, rhs: &BoxArray<Rhs, N>, compiler: &mut COM)
    where
        COM: Assert,
    {
        for (lhs, rhs) in self.iter().zip(rhs) {
            compiler.assert_eq(lhs, rhs);
        }
    }
}

/* TODO:
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
*/

/// Equality
pub trait Eq<COM = ()>: PartialEq<Self, COM>
where
    COM: Has<bool>,
{
}

/* TODO:
impl<T> Eq for T where T: cmp::Eq {}
*/

///
pub trait PartialOrd<Rhs, COM = ()>: PartialEq<Rhs, COM>
where
    Rhs: ?Sized,
    COM: Has<bool> + Has<Option<Ordering>>,
{
    ///
    fn partial_cmp(&self, other: &Rhs, compiler: &mut COM) -> Type<COM, Option<Ordering>>;

    /* TODO:
    ///
    fn lt(&self, other: &Rhs, compiler: &mut COM) -> Bool<COM> { ... }

    ///
    fn le(&self, other: &Rhs) -> bool { ... }

    ///
    fn gt(&self, other: &Rhs) -> bool { ... }

    ///
    fn ge(&self, other: &Rhs) -> bool { ... }
    */
}

/* TODO:
impl<T, Rhs> PartialOrd<Rhs> for T
where
    T: cmp::PartialOrd<Rhs>,
{
    #[inline]
    fn partial_cmp(&self, rhs: &Rhs, _: &mut ()) -> Option<Ordering> {
        self.partial_cmp(rhs)
    }

    /*
    #[inline]
    fn lt(&self, rhs: &Rhs, _: &mut ()) -> bool {
        self.lt(rhs)
    }
    */
}
*/

///
pub trait Ord<COM = ()>: Eq<COM> + PartialOrd<Self, COM>
where
    COM: Has<bool> + Has<Option<Ordering>> + Has<Ordering>,
{
    ///
    fn cmp(&self, other: &Self, compiler: &mut COM) -> Type<COM, Ordering>;

    /* TODO:
    ///
    fn max(self, other: Self) -> Self
    where
        Self: Sized,
    { ... }

    ///
    fn min(self, other: Self) -> Self
    where
        Self: Sized,
    { ... }

    ///
    fn clamp(self, min: Self, max: Self) -> Self
    where
        Self: Sized,
        Self: PartialOrd,
    { ... }
    */
}

/* TODO:
impl<T> Ord for T
where
    T: cmp::Ord,
{
    #[inline]
    fn cmp(&self, other: &Self, _: &mut ()) -> Ordering {
        self.cmp(other)
    }
}
*/
