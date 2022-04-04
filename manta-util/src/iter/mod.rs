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

//! Iteration Utilities

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub mod chunk_by;

#[cfg(all(feature = "alloc", feature = "crossbeam-channel"))]
#[cfg_attr(
    doc_cfg,
    doc(cfg(all(feature = "alloc", feature = "crossbeam-channel")))
)]
pub mod select_all;

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub use chunk_by::ChunkBy;

#[cfg(all(feature = "alloc", feature = "crossbeam-channel"))]
#[cfg_attr(
    doc_cfg,
    doc(cfg(all(feature = "alloc", feature = "crossbeam-channel")))
)]
pub use select_all::SelectAll;

/// Iterator Extensions
pub trait IteratorExt: Iterator {
    /// Returns an iterator over chunks of size `N` from `iter`.
    ///
    /// # Note
    ///
    /// This is an alternative to [`ChunksExact`] but it works for any iterator and the
    /// chunk size must be known at compile time.
    ///
    /// [`ChunksExact`]: core::slice::ChunksExact
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn chunk_by<const N: usize>(self) -> ChunkBy<Self, N>
    where
        Self: Sized,
    {
        ChunkBy::new(self)
    }

    /// Selects items from each iterator in `self` in parallel.
    #[cfg(all(feature = "alloc", feature = "crossbeam-channel", feature = "rayon"))]
    #[cfg_attr(
        doc_cfg,
        doc(cfg(all(feature = "alloc", feature = "crossbeam-channel", feature = "rayon")))
    )]
    #[inline]
    fn select_all<'s, I>(self, scope: &rayon::Scope<'s>) -> SelectAll<I::Item>
    where
        Self: ExactSizeIterator<Item = I> + Sized,
        I: IntoIterator,
        I::IntoIter: 's + Send,
        I::Item: Send,
    {
        SelectAll::spawn(self, scope)
    }

    /// Folds every element into an accumulator by applying an operation, returning the final result.
    ///
    /// This function differs from [`Iterator::fold`] because its initial state is borrowed instead
    /// of owned. This means that we have to return `Option<B>` in case the iterator is empty.
    #[inline]
    fn fold_ref<B, F>(mut self, init: &B, mut f: F) -> Option<B>
    where
        Self: Sized,
        F: FnMut(&B, Self::Item) -> B,
    {
        self.next()
            .map(move |first| self.fold(f(init, first), move |acc, n| f(&acc, n)))
    }
}

impl<I> IteratorExt for I where I: Iterator {}
