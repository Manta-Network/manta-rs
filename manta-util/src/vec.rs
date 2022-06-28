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

//! Vectors

use crate::create_seal;

#[doc(inline)]
pub use alloc::vec::*;

create_seal! {}

impl<T> sealed::Sealed for Vec<T> {}

/// Vector Extension Trait
pub trait VecExt<T>: From<Vec<T>> + Into<Vec<T>> + sealed::Sealed + Sized {
    /// Returns the `n`th element of `self`, dropping the rest of the vector.
    #[inline]
    fn take(self, n: usize) -> T {
        let mut vec = self.into();
        vec.truncate(n + 1);
        vec.remove(n)
    }

    /// Returns the first element of `self`, dropping the rest of the vector.
    #[inline]
    fn take_first(self) -> T {
        self.take(0)
    }

    /// Allocates a vector of length `n` and initializes with `f`.
    #[inline]
    fn allocate_with<F>(n: usize, f: F) -> Self
    where
        F: FnMut() -> T,
    {
        let mut vec = Vec::with_capacity(n);
        vec.resize_with(n, f);
        vec.into()
    }
}

impl<T> VecExt<T> for Vec<T> {}
