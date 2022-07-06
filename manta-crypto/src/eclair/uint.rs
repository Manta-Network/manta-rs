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

/// Unsigned Integer
pub struct UnsignedInteger<T, const BITS: usize>(T);

impl<T, const BITS: usize> UnsignedInteger<T, BITS> {
    /// Builds a new [`UnsignedInteger`] over `value`, asserting that it does not exceed BITS bits.
    #[inline]
    pub fn new<COM>(value: T, compiler: &mut COM) -> Self
    where
        COM: AssertWithinRange<T, BITS>,
    {
        compiler.assert_within_range(&value);
        Self(value)
    }

    /// Mutates an [`UnsignedInteger`] with a function `f`.
    #[inline]
    fn mutate<F, U, COM>(&mut self, f: F, compiler: &mut COM) -> U
    where
        COM: AssertWithinRange<T, BITS>,
        F: FnOnce(&mut T, &mut COM) -> U,
    {
        let output = f(&mut self.0, compiler);
        compiler.assert_within_range(&self.0);
        output
    }
}

impl<T, COM, const BITS: usize> Add<Self, COM> for UnsignedInteger<T, BITS>
where
    COM: AssertWithinRange<T::Output, BITS>,
    T: Add<T, COM>,
{
    type Output = UnsignedInteger<T::Output, BITS>;

    #[inline]
    fn add(self, rhs: Self, compiler: &mut COM) -> Self::Output {
        Self::Output::new(self.0.add(rhs.0, compiler), compiler)
    }
}

impl<T, COM, const BITS: usize> AddAssign<Self, COM> for UnsignedInteger<T, BITS>
where
    COM: AssertWithinRange<T, BITS>,
    T: AddAssign<T, COM>,
{
    #[inline]
    fn add_assign(&mut self, rhs: Self, compiler: &mut COM) {
        self.mutate(|lhs, compiler| lhs.add_assign(rhs.0, compiler), compiler);
    }
}

macro_rules! define_uint {
    ($($doc:expr, $name:ident, $bits:expr),* $(,)?) => {
        $(
            #[doc = $doc]
            pub type $name<T> = UnsignedInteger<T, $bits>;
        )*
    }
}

define_uint! {
    "64-Bit Unsigned Integer", U64, 64,
    "128-Bit Unsigned Integer", U128, 128,
}
