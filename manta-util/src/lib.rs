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

//! Utilities

#![no_std]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use core::{borrow::Borrow, convert::TryInto};

/// Implements [`From`]`<$from>` for an enum `$to`, choosing the `$kind` variant.
// TODO: add `where` clauses
#[macro_export]
macro_rules! from_variant_impl {
    ($to:tt, $kind:ident, $from:tt) => {
        impl From<$from> for $to {
            #[inline]
            fn from(t: $from) -> Self {
                Self::$kind(t)
            }
        }
    };
}

/// Performs the [`TryInto`] conversion into an array without checking if the conversion succeeded.
#[inline]
pub fn into_array_unchecked<T, V, const N: usize>(v: V) -> [T; N]
where
    V: TryInto<[T; N]>,
{
    match v.try_into() {
        Ok(array) => array,
        _ => unreachable!("User was supposed to ensure that this branch is never reached."),
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

/// Byte Accumulation Trait
pub trait ByteAccumulator {
    /// Extends the current accumulator by a `buffer` of elements.
    fn extend(&mut self, buffer: &[u8]);

    /// Reserves space in the accumulator for `additional` more elements.
    #[inline]
    fn reserve(&mut self, additional: usize) {
        let _ = additional;
    }

    /// Drops extra capacity in the accumulator.
    #[inline]
    fn shrink_to_fit(&mut self) {}

    /// Captures the accumulator and drops extra capacity before returning an owned copy.
    #[inline]
    fn finish(mut self) -> Self
    where
        Self: Sized,
    {
        self.shrink_to_fit();
        self
    }

    /// Creates a "by mutable reference" adaptor for this instance of [`ByteAccumulator`].
    #[inline]
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }
}

impl<A> ByteAccumulator for &mut A
where
    A: ByteAccumulator + ?Sized,
{
    #[inline]
    fn extend(&mut self, buffer: &[u8]) {
        (**self).extend(buffer)
    }

    #[inline]
    fn reserve(&mut self, additional: usize) {
        (**self).reserve(additional)
    }

    #[inline]
    fn shrink_to_fit(&mut self) {
        (**self).shrink_to_fit()
    }
}

impl ByteAccumulator for Vec<u8> {
    #[inline]
    fn extend(&mut self, buffer: &[u8]) {
        self.extend_from_slice(buffer)
    }

    #[inline]
    fn reserve(&mut self, additional: usize) {
        self.reserve(additional)
    }

    #[inline]
    fn shrink_to_fit(&mut self) {
        self.shrink_to_fit()
    }
}

/// Byte Concatenation Trait
pub trait ConcatBytes {
    /// Concatenates `self` on the end of the accumulator.
    ///
    /// # Note
    ///
    /// Implementations should not ask to reserve additional space for elements in this method.
    /// Instead, reimplement [`reserve_concat`](Self::reserve_concat) if the default implementation
    /// is not efficient.
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ByteAccumulator + ?Sized;

    /// Returns a hint to the possible number of bytes that will be accumulated when concatenating
    /// `self`.
    #[inline]
    fn size_hint(&self) -> Option<usize> {
        None
    }

    /// Concatenates `self` on the end of the accumulator after trying to reserve space for it.
    #[inline]
    fn reserve_concat<A>(&self, accumulator: &mut A)
    where
        A: ByteAccumulator + ?Sized,
    {
        if let Some(capacity) = self.size_hint() {
            accumulator.reserve(capacity);
        }
        self.concat(accumulator)
    }

    /// Constructs a default accumulator and accumulates over `self`, reserving the appropriate
    /// capacity.
    #[inline]
    fn as_bytes<A>(&self) -> A
    where
        A: Default + ByteAccumulator,
    {
        let mut accumulator = A::default();
        self.reserve_concat(&mut accumulator);
        accumulator.finish()
    }
}

impl<T> ConcatBytes for T
where
    T: Borrow<[u8]> + ?Sized,
{
    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ByteAccumulator + ?Sized,
    {
        accumulator.extend(self.borrow())
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(self.borrow().len())
    }
}

/// Concatenates `$item`s together by building a [`ByteAccumulator`] and running
/// [`ConcatBytes::concat`] over each `$item`.
#[macro_export]
macro_rules! concatenate {
	($($item:expr),*) => {
		{
            extern crate alloc;
            let mut accumulator = ::alloc::vec::Vec::new();
            $($crate::ConcatBytes::reserve_concat($item, &mut accumulator);)*
            $crate::ByteAccumulator::finish(accumulator)
		}
	}
}

/// Returns byte vector representation of `$item`.
#[macro_export]
macro_rules! as_bytes {
    ($item:expr) => {
        $crate::concatenate!($item)
    };
}
