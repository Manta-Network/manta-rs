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

//! Byte Concatenation Utilities

use alloc::vec::Vec;

/// Concatenation Accumulator Trait
pub trait ConcatAccumulator<T> {
    /// Extends the current accumulator by a `buffer` of elements.
    fn extend(&mut self, buffer: &[T]);

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

    /// Creates a "by mutable reference" adaptor for this instance of [`ConcatAccumulator`].
    #[inline]
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }
}

impl<T, A> ConcatAccumulator<T> for &mut A
where
    A: ConcatAccumulator<T> + ?Sized,
{
    #[inline]
    fn extend(&mut self, buffer: &[T]) {
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

impl<T> ConcatAccumulator<T> for Vec<T>
where
    T: Clone,
{
    #[inline]
    fn extend(&mut self, buffer: &[T]) {
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

/// Concatenation Trait
pub trait Concat {
    /// Item Type
    type Item;

    /// Concatenates `self` on the end of the accumulator.
    ///
    /// # Note
    ///
    /// Implementations should not ask to reserve additional space for elements in this method.
    /// Instead, reimplement [`reserve_concat`](Self::reserve_concat) if the default implementation
    /// is not efficient.
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized;

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
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        if let Some(capacity) = self.size_hint() {
            accumulator.reserve(capacity);
        }
        self.concat(accumulator)
    }

    /// Constructs a default accumulator and accumulates over `self`, reserving the appropriate
    /// capacity.
    #[inline]
    fn accumulated<A>(&self) -> A
    where
        A: Default + ConcatAccumulator<Self::Item>,
    {
        let mut accumulator = A::default();
        self.reserve_concat(&mut accumulator);
        accumulator.finish()
    }
}

impl<T> Concat for [T] {
    type Item = T;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<T> + ?Sized,
    {
        accumulator.extend(self)
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(self.len())
    }
}

impl<T, const N: usize> Concat for [T; N] {
    type Item = T;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<T> + ?Sized,
    {
        accumulator.extend(self)
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(self.len())
    }
}

impl<T> Concat for Vec<T> {
    type Item = T;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<T> + ?Sized,
    {
        accumulator.extend(self)
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(self.len())
    }
}

/// Concatenates `$item`s together by building a [`ConcatAccumulator`] and running
/// [`Concat::concat`] over each `$item`.
#[macro_export]
macro_rules! concatenate {
    ($($item:expr),*) => {
        {
            extern crate alloc;
            let mut accumulator = ::alloc::vec::Vec::new();
            $($crate::Concat::reserve_concat($item, &mut accumulator);)*
            $crate::ConcatAccumulator::finish(accumulator)
        }
    }
}

/// Returns byte vector representation of `$item` if it implements [`Concat<Item = u8>`](Concat).
#[macro_export]
macro_rules! as_bytes {
    ($item:expr) => {{
        let bytes: Vec<u8> = $crate::concatenate!($item);
        bytes
    }};
}
