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

//! Unsigned Integers Implementation

use crate::{
    constraint::Add,
    eclair::{assert::AssertWithinRange, ops::AddAssign},
};

/// Unsigned 128-bit Integer
pub struct U128<T>(T);

impl<T> U128<T> {
    /// Builds a new [`U128`] over `value`, asserting that it does not exceed 128 bits.
    #[inline]
    pub fn new<COM>(value: T, compiler: &mut COM) -> Self
    where
        COM: AssertWithinRange<T, 128>,
    {
        compiler.assert_within_range(&value);
        Self(value)
    }
}

impl<O, T, COM> Add<Self, COM> for U128<T>
where
    COM: AssertWithinRange<O, 128>,
    T: Add<T, COM, Output = O>,
{
    type Output = U128<O>;

    #[inline]
    fn add(self, rhs: Self, compiler: &mut COM) -> Self::Output {
        Self::Output::new(self.0.add(rhs.0, compiler), compiler)
    }
}

impl<T, COM> AddAssign<Self, COM> for U128<T>
where
    COM: AssertWithinRange<T, 128>,
    T: AddAssign<T, COM>,
{
    #[inline]
    fn add_assign(&mut self, rhs: Self, compiler: &mut COM) {
        self.0.add_assign(rhs.0, compiler);
        compiler.assert_within_range(&self.0);
    }
}
