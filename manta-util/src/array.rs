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

//! Array Utilities

use core::{
    borrow::{Borrow, BorrowMut},
    convert::TryInto,
    ops::{Deref, DerefMut},
};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "serde-array")]
use crate::serde::{Deserialize, Serialize};

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

/// Performs the [`TryInto`] conversion into a boxed array without checking if the conversion
/// succeeded.
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
#[inline]
pub fn into_boxed_array_unchecked<T, V, const N: usize>(v: V) -> Box<[T; N]>
where
    V: TryInto<Box<[T; N]>>,
{
    match v.try_into() {
        Ok(array) => array,
        _ => unreachable!(
            "Input did not have the correct length to match the output slice of length {:?}.",
            N,
        ),
    }
}

/// Maps `f` over the `array` using allocation.
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
#[inline]
pub fn array_map<T, U, F, const N: usize>(array: [T; N], f: F) -> [U; N]
where
    F: FnMut(T) -> U,
{
    into_array_unchecked(array.into_iter().map(f).collect::<Vec<_>>())
}

/// Maps `f` over the `array` by reference using allocation.
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
#[inline]
pub fn array_map_ref<T, U, F, const N: usize>(array: &[T; N], f: F) -> [U; N]
where
    F: FnMut(&T) -> U,
{
    into_array_unchecked(array.iter().map(f).collect::<Vec<_>>())
}

/// Maps `f` over the `array` returning the target array if all of the mappings succeeded, or
/// returning the first error that occurs.
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
#[inline]
pub fn fallible_array_map<T, U, E, F, const N: usize>(array: [T; N], f: F) -> Result<[U; N], E>
where
    F: FnMut(T) -> Result<U, E>,
{
    Ok(into_array_unchecked(
        array.into_iter().map(f).collect::<Result<Vec<_>, _>>()?,
    ))
}

/// Maps `f` over the `array` by reference returning the target array if all of the mappings
/// succeeded, or returning the first error that occurs.
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
#[inline]
pub fn fallible_array_map_ref<T, U, E, F, const N: usize>(array: &[T; N], f: F) -> Result<[U; N], E>
where
    F: FnMut(&T) -> Result<U, E>,
{
    Ok(into_array_unchecked(
        array.iter().map(f).collect::<Result<Vec<_>, _>>()?,
    ))
}

/// Implements some traits for array wrapper types.
macro_rules! impl_array_traits {
    ($type:tt) => {
        impl<T, const N: usize> AsMut<[T; N]> for $type<T, N> {
            #[inline]
            fn as_mut(&mut self) -> &mut [T; N] {
                &mut self.0
            }
        }

        impl<T, const N: usize> AsMut<[T]> for $type<T, N> {
            #[inline]
            fn as_mut(&mut self) -> &mut [T] {
                self.0.as_mut()
            }
        }

        impl<T, const N: usize> AsRef<[T; N]> for $type<T, N> {
            #[inline]
            fn as_ref(&self) -> &[T; N] {
                &self.0
            }
        }

        impl<T, const N: usize> AsRef<[T]> for $type<T, N> {
            #[inline]
            fn as_ref(&self) -> &[T] {
                self.0.as_ref()
            }
        }

        impl<T, const N: usize> Borrow<[T; N]> for $type<T, N> {
            #[inline]
            fn borrow(&self) -> &[T; N] {
                &self.0
            }
        }

        impl<T, const N: usize> BorrowMut<[T; N]> for $type<T, N> {
            #[inline]
            fn borrow_mut(&mut self) -> &mut [T; N] {
                &mut self.0
            }
        }

        impl<T, const N: usize> Borrow<[T]> for $type<T, N> {
            #[inline]
            fn borrow(&self) -> &[T] {
                self.0.as_ref()
            }
        }

        impl<T, const N: usize> BorrowMut<[T]> for $type<T, N> {
            #[inline]
            fn borrow_mut(&mut self) -> &mut [T] {
                self.0.as_mut()
            }
        }

        impl<T, const N: usize> Deref for $type<T, N> {
            type Target = [T; N];

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<T, const N: usize> DerefMut for $type<T, N> {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<T, const N: usize> From<[T; N]> for $type<T, N> {
            #[inline]
            fn from(array: [T; N]) -> Self {
                Self(array.into())
            }
        }
    };
}

/// Array
///
/// This type wraps a standard Rust array but provides some additional methods and optional
/// compatibility with [`serde`](crate::serde). The type `Array<T, N>` is mostly a drop-in
/// replacement for `[T; N]`.
#[cfg_attr(
    feature = "serde-array",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "T: Deserialize<'de>", serialize = "T: Serialize"),
        crate = "crate::serde",
        deny_unknown_fields
    )
)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Array<T, const N: usize>(
    /// Array Data
    #[cfg_attr(
        feature = "serde-array",
        serde(with = "serde_with::As::<[serde_with::Same; N]>")
    )]
    pub [T; N],
);

impl<T, const N: usize> Array<T, N> {
    /// Performs the [`TryInto`] conversion into an array without checking if the conversion
    /// succeeded. See [`into_array_unchecked`] for more.
    #[inline]
    pub fn from_unchecked<V>(v: V) -> Self
    where
        V: TryInto<[T; N]>,
    {
        Self(into_array_unchecked(v))
    }

    /// Maps `f` over `self` using allocation.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    pub fn map<U, F>(self, f: F) -> Array<U, N>
    where
        F: FnMut(T) -> U,
    {
        Array(array_map(self.0, f))
    }

    /// Maps `f` over `self` by reference using allocation.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    pub fn map_ref<U, F>(&self, f: F) -> Array<U, N>
    where
        F: FnMut(&T) -> U,
    {
        Array(array_map_ref(&self.0, f))
    }

    /// Maps `f` over `self` returning the target array if all of the mappings succeeded, or
    /// returning the first error that occurs.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    pub fn fallible_array_map<U, E, F>(self, f: F) -> Result<Array<U, N>, E>
    where
        F: FnMut(T) -> Result<U, E>,
    {
        fallible_array_map(self.0, f).map(Array)
    }

    /// Maps `f` over `self` by reference returning the target array if all of the mappings
    /// succeeded, or returning the first error that occurs.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    pub fn fallible_array_map_ref<U, E, F>(&self, f: F) -> Result<Array<U, N>, E>
    where
        F: FnMut(&T) -> Result<U, E>,
    {
        fallible_array_map_ref(&self.0, f).map(Array)
    }
}

impl_array_traits!(Array);

impl<T, const N: usize> Default for Array<T, N>
where
    T: Copy + Default,
{
    #[inline]
    fn default() -> Self {
        Self([T::default(); N])
    }
}

impl<T, const N: usize> From<Array<T, N>> for [T; N] {
    #[inline]
    fn from(array: Array<T, N>) -> Self {
        array.0
    }
}

/// Boxed Array
///
/// This type wraps a boxed standard Rust array but provides some additional methods and optional
/// compatibility with [`serde`](crate::serde). The type `BoxArray<T, N>` is mostly a drop-in
/// replacement for `Box<[T; N]>`.
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
#[cfg_attr(
    all(feature = "serde-alloc", feature = "serde-array"),
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "T: Deserialize<'de>", serialize = "T: Serialize"),
        crate = "crate::serde",
        deny_unknown_fields
    )
)]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct BoxArray<T, const N: usize>(
    /// Array Data
    #[cfg_attr(
        all(feature = "serde-alloc", feature = "serde-array"),
        serde(with = "serde_with::As::<Box<[serde_with::Same; N]>>")
    )]
    pub Box<[T; N]>,
);

#[cfg(feature = "alloc")]
impl<T, const N: usize> BoxArray<T, N> {
    /// Performs the [`TryInto`] conversion into a boxed array without checking if the conversion
    /// succeeded. See [`into_boxed_array_unchecked`] for more.
    #[inline]
    pub fn from_unchecked<V>(v: V) -> Self
    where
        V: TryInto<Box<[T; N]>>,
    {
        Self(into_boxed_array_unchecked(v))
    }
}

#[cfg(feature = "alloc")]
impl_array_traits!(BoxArray);
