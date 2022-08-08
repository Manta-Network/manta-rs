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

//! Arkworks Finite Field Backend

use manta_util::into_array_unchecked;

#[doc(inline)]
pub use ark_ff::*;

/// Tries to convert a field element `x` into a `u128` integer.
#[inline]
pub fn try_into_u128<F>(x: F) -> Option<u128>
where
    F: PrimeField,
{
    if x < F::from(2u8).pow([128, 0, 0, 0]) {
        let mut bytes = x.into_repr().to_bytes_le();
        bytes.truncate(16);
        Some(u128::from_le_bytes(into_array_unchecked(bytes)))
    } else {
        None
    }
}
