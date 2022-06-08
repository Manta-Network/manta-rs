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

use crate::eclair::{bool::Bool, ops::Not, Has};
use core::cmp;

/// Equality
pub trait Eq<COM = ()>: PartialEq<Self, COM>
where
    COM: Has<bool>,
{
}

impl<T> Eq for T where T: cmp::Eq {}

/// Partial Equivalence Relations
pub trait PartialEq<Rhs = Self, COM = ()>
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
