// Copyright 2019-2021 Manta Network.
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

//! Numeric Utilities

use core::num::Wrapping;

/// Parity Trait
pub trait HasParity {
    /// Returns `true` if `self` represents an even integer.
    fn is_even(&self) -> bool;

    /// Returns `true` if `self` does not represent an even integer.
    #[inline]
    fn is_odd(&self) -> bool {
        !self.is_even()
    }
}

macro_rules! impl_has_parity {
    ($($type:tt),+) => {
        $(
            impl HasParity for $type {
                #[inline]
                fn is_even(&self) -> bool {
                    self % 2 == 0
                }
            }

            impl HasParity for Wrapping<$type> {
                #[inline]
                fn is_even(&self) -> bool {
                    self.0 % 2 == 0
                }
            }
        )*
    };
}

impl_has_parity!(i8, i16, i32, i64, i128, isize, u8, u16, u64, u128, usize);
