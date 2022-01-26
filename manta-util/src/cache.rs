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

//! Caching Utilities

use core::{convert::Infallible, ops::Deref};

/// Cached Resource
pub trait CachedResource<T> {
    /// Reading Key Type
    type ReadingKey;

    /// Aquisition Error Type
    type Error;

    /// Tries to aquire the resource with `self`, returning a reading key if successful, storing
    /// the aquired resource in the cache.
    ///
    /// # Contract
    ///
    /// This method should be idempotent unless calls to [`aquire`](Self::aquire) are interleaved
    /// with calls to [`release`](Self::release).
    fn aquire(&mut self) -> Result<Self::ReadingKey, Self::Error>;

    /// Reads the resource, spending the `reading_key`. The reference can be held on to until
    /// [`release`](Self::release) is called or the reference falls out of scope.
    fn read(&self, reading_key: Self::ReadingKey) -> &T;

    /// Releases the resource with `self`, clearing the cache.
    ///
    /// # Contract
    ///
    /// This method should be idempotent unless calls to [`release`](Self::release) are interleaved
    /// with calls to [`aquire`](Self::aquire). This method can be a no-op if the resource was not
    /// aquired.
    fn release(&mut self);
}

/// Cached Resource Error Type
pub type CachedResourceError<T, R> = <R as CachedResource<T>>::Error;

impl<T, D> CachedResource<T> for D
where
    D: Deref<Target = T>,
{
    type ReadingKey = ();
    type Error = Infallible;

    #[inline]
    fn aquire(&mut self) -> Result<Self::ReadingKey, Self::Error> {
        Ok(())
    }

    #[inline]
    fn read(&self, reading_key: Self::ReadingKey) -> &T {
        let _ = reading_key;
        self
    }

    #[inline]
    fn release(&mut self) {}
}
