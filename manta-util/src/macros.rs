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

//! Utility Macros

/// Implements [`From`]`<$from>` for an enum `$to`, choosing the `$kind` variant.
#[macro_export]
macro_rules! from_variant_impl {
    ($to:ty, $kind:ident, $from:ty) => {
        impl From<$from> for $to {
            #[inline]
            fn from(t: $from) -> Self {
                Self::$kind(t)
            }
        }
    };
}

/// Calls the `into_iter` method on `$e` or the `into_par_iter` Rayon method if the `rayon` feature
/// is enabled.
#[macro_export]
macro_rules! into_iter {
    ($e:expr) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::iter::IntoParallelIterator::into_par_iter($e);
        #[cfg(not(feature = "rayon"))]
        let result = $e.into_iter();
        result
    }};
}

/// Calls the `iter` method on `$e` or the `par_iter` Rayon method if the `rayon` feature is
/// enabled.
#[macro_export]
macro_rules! iter {
    ($e:expr) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::iter::IntoParallelRefIterator::par_iter($e);
        #[cfg(not(feature = "rayon"))]
        let result = $e.iter();
        result
    }};
}

/// Calls the `iter_mut` method on `$e` or the `par_iter_mut` Rayon method if the `rayon` feature is
/// enabled.
#[macro_export]
macro_rules! iter_mut {
    ($e:expr) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::iter::IntoParallelRefMutIterator::par_iter_mut($e);
        #[cfg(not(feature = "rayon"))]
        let result = $e.iter_mut();
        result
    }};
}

/// Calls the `chunks` method on `$e` or the `par_chunks` Rayon method if the `rayon` feature is
/// enabled.
#[macro_export]
macro_rules! chunks {
    ($e:expr, $size:expr) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::slice::ParallelSlice::par_chunks($e, $size);
        #[cfg(not(feature = "rayon"))]
        let result = $e.chunks($size);
        result
    }};
}

/// Calls the `chunks_mut` method on `$e` or the `par_chunks_mut` Rayon method if the `rayon`
/// feature is enabled.
#[macro_export]
macro_rules! chunks_mut {
    ($e:expr, $size:expr) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::slice::ParallelSliceMut::par_chunks_mut($e, $size);
        #[cfg(not(feature = "rayon"))]
        let result = $e.chunks_mut($size);
        result
    }};
}

/// Calls the `fold` method on `$e` or the `reduce` Rayon method if the `rayon` feature is enabled.
#[macro_export]
macro_rules! reduce {
    ($e:expr, $default:expr, $op:expr) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::iter::ParallelIterator::reduce($e, $default, $op);
        #[cfg(not(feature = "rayon"))]
        let result = $e.fold($default(), $op);
        result
    }};
}

/// Calls the `sum` method on `$e` or the `sum` Rayon method if the `rayon` feature is enabled.
#[macro_export]
macro_rules! sum {
    ($e:expr) => {{
        $crate::sum!($e, _)
    }};
    ($e:expr, $T:ty) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::iter::ParallelIterator::sum::<$T>($e);
        #[cfg(not(feature = "rayon"))]
        let result = $e.sum::<$T>();
        result
    }};
}

/// Calls the `product` method on `$e` or the `product` Rayon method if the `rayon` feature is
/// enabled.
#[macro_export]
macro_rules! product {
    ($e:expr) => {{
        $crate::product!($e, _)
    }};
    ($e:expr, $T:ty) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::iter::ParallelIterator::product::<$T>($e);
        #[cfg(not(feature = "rayon"))]
        let result = $e.product::<$T>();
        result
    }};
}

/// Calls the `min` method on `$e` or the `min` Rayon method if the `rayon` feature is enabled.
#[macro_export]
macro_rules! min {
    ($e:expr) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::iter::ParallelIterator::min($e);
        #[cfg(not(feature = "rayon"))]
        let result = $e.min();
        result
    }};
}

/// Calls the `max` method on `$e` or the `max` Rayon method if the `rayon` feature is enabled.
#[macro_export]
macro_rules! max {
    ($e:expr) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::iter::ParallelIterator::max($e);
        #[cfg(not(feature = "rayon"))]
        let result = $e.max();
        result
    }};
}

/// Calls the `try_for_each` method on `$e` or the `try_for_each` Rayon method if the `rayon`
/// feature is enabled.
#[macro_export]
macro_rules! try_for_each {
    ($e:expr, $op:expr) => {{
        #[cfg(feature = "rayon")]
        let result = ::rayon::iter::ParallelIterator::try_for_each($e, $op);
        #[cfg(not(feature = "rayon"))]
        let result = $e.try_for_each($op);
        result
    }};
}
