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

//! Array Utilities

use alloc::vec::Vec;
use core::convert::TryInto;

/// Performs the [`TryInto`] conversion into an array without checking if the conversion succeeded.
#[inline]
pub fn into_array_unchecked<T, V, const N: usize>(v: V) -> [T; N]
where
    V: TryInto<[T; N]>,
{
    match v.try_into() {
        Ok(array) => array,
        _ => unreachable!(
            "Input did not have the correct length to match the output slice of length {:?}.",
            N,
        ),
    }
}

/// Maps `f` over the `array`.
#[inline]
pub fn array_map<T, U, F, const N: usize>(array: [T; N], f: F) -> [U; N]
where
    F: FnMut(T) -> U,
{
    into_array_unchecked(IntoIterator::into_iter(array).map(f).collect::<Vec<_>>())
}

/// Maps `f` over the `array` by reference.
#[inline]
pub fn array_map_ref<T, U, F, const N: usize>(array: &[T; N], f: F) -> [U; N]
where
    F: FnMut(&T) -> U,
{
    into_array_unchecked(array.iter().map(f).collect::<Vec<_>>())
}

/// Maps `f` over the `array` returning the target array if all of the mappings succeeded, or
/// returning the first error that occurs.
#[inline]
pub fn fallible_array_map<T, U, E, F, const N: usize>(array: [T; N], f: F) -> Result<[U; N], E>
where
    F: FnMut(T) -> Result<U, E>,
{
    Ok(into_array_unchecked(
        IntoIterator::into_iter(array)
            .map(f)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

/// Maps `f` over the `array` by reference returning the target array if all of the mappings
/// succeeded, or returning the first error that occurs.
#[inline]
pub fn fallible_array_map_ref<T, U, E, F, const N: usize>(array: &[T; N], f: F) -> Result<[U; N], E>
where
    F: FnMut(&T) -> Result<U, E>,
{
    Ok(into_array_unchecked(
        array.iter().map(f).collect::<Result<Vec<_>, _>>()?,
    ))
}
