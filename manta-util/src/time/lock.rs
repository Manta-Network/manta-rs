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

//! Time-synchronized and Time-locked Data

use crate::time::{Duration, Instant};
use core::{mem, ops::Deref};

/// Timed Data
#[derive(Copy, Debug, Eq, Hash, PartialEq)]
pub struct Timed<T> {
    /// Value
    value: T,

    /// Instant
    instant: Instant,
}

impl<T> Timed<T> {
    /// Builds a new [`Timed`] object over `value`.
    #[inline]
    pub fn new(value: T) -> Self {
        Self::new_unchecked(value, Instant::now())
    }

    /// Builds a new [`Timed`] object over `value` created at the given `instant` without checking
    /// that `instant` is [`Instant::now`].
    #[inline]
    pub const fn new_unchecked(value: T, instant: Instant) -> Self {
        Self { instant, value }
    }

    /// Returns a shared reference to the underlying data.
    #[inline]
    pub const fn get(&self) -> &T {
        &self.value
    }

    /// Returns the last [`Instant`] that `self` was modified. See [`elapsed`](Self::elapsed) to get
    /// the amount of time since the last modification.
    #[inline]
    pub const fn modified_at(&self) -> Instant {
        self.instant
    }

    /// Returns the amount of time that has elapsed since the last modification of the underlying
    /// value. See [`modified_at`](Self::modified_at) to get the [`Instant`] of the last
    /// modification.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.instant.elapsed()
    }

    /// Returns `true` if the amount of time elapsed since the last modification is larger than the
    /// `timeout`.
    #[inline]
    pub fn has_expired(&self, timeout: Duration) -> bool {
        self.elapsed() >= timeout
    }

    /// Resets the modification time to the value returned by [`Instant::now`].
    #[inline]
    pub fn tap(&mut self) {
        self.instant = Instant::now();
    }

    ///
    #[inline]
    pub fn set(&mut self, value: T) -> T {
        self.mutate(move |t| mem::replace(t, value))
    }

    /// Mutates the internal value using `f`, resetting the modification time to [`Instant::now`].
    #[inline]
    pub fn mutate<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        self.mutate_timed(move |value, _| f(value))
    }

    /// Mutates the internal value with the [`Instant`] of the last modification to `self`,
    /// resetting the modification time to [`Instant::now`].
    #[inline]
    pub fn mutate_timed<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T, Instant) -> R,
    {
        let result = f(&mut self.value, self.instant);
        self.tap();
        result
    }

    ///
    #[inline]
    pub fn mutate_if_expired<F, R>(&mut self, timeout: Duration, f: F) -> Option<R>
    where
        F: FnOnce(&mut T) -> R,
    {
        if self.has_expired(timeout) {
            Some(self.mutate(f))
        } else {
            None
        }
    }

    ///
    #[inline]
    pub fn set_if_expired(&mut self, timeout: Duration, value: T) -> Option<T> {
        self.set_with_if_expired(timeout, move || value)
    }

    ///
    #[inline]
    pub fn set_with_if_expired<F>(&mut self, timeout: Duration, value: F) -> Option<T>
    where
        F: FnOnce() -> T,
    {
        self.mutate_if_expired(timeout, move |t| mem::replace(t, value()))
    }

    /// Returns the underlying timed value, dropping `self`.
    #[inline]
    pub fn into_inner(self) -> T {
        self.value
    }

    /// Returns the underlying timed value and its last modification time, dropping `self`.
    #[inline]
    pub fn into_pair(self) -> (T, Instant) {
        (self.value, self.instant)
    }
}

impl<T> Timed<Option<T>> {
    ///
    #[inline]
    pub fn replace_if_expired<F, R>(&mut self, timeout: Duration, value: T) -> Option<T> {
        self.mutate_if_expired(timeout, move |t| t.replace(value))
            .flatten()
    }

    ///
    #[inline]
    pub fn take_if_expired<F, R>(&mut self, timeout: Duration) -> Option<T> {
        self.mutate_if_expired(timeout, Option::take).flatten()
    }
}

impl<T> AsRef<T> for Timed<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        self.get()
    }
}

impl<T> Clone for Timed<T>
where
    T: Clone,
{
    /// Clones the underlying data, creating a new [`Timed`] object with a new creation time set to
    /// the return value of [`Instant::now`].
    #[inline]
    fn clone(&self) -> Self {
        Self::new(self.value.clone())
    }
}

impl<T> Default for Timed<T>
where
    T: Default,
{
    /// Builds a new [`Timed`] object from the default value of `T` and the current time returned by
    /// [`Instant::now`].
    #[inline]
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T> Deref for Timed<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T> From<Timed<T>> for (T, Instant) {
    #[inline]
    fn from(timed: Timed<T>) -> Self {
        timed.into_pair()
    }
}

/*

/// Time Lock
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct TimeLock<T>(Option<Timed<T>>);

impl<T> TimeLock<T> {
    ///
    #[inline]
    pub fn new(value: T) -> Self {
        Self::from_timed(Timed::new(value))
    }

    /// Converts a `timed` object into a time-locked object.
    #[inline]
    pub const fn from_timed(timed: Timed<T>) -> Self {
        Self(Some(timed))
    }

    ///
    #[inline]
    pub const fn new_unchecked(value: T, instant: Instant) -> Self {
        Self::from_timed(Timed::new_unchecked(value, instant))
    }

    /// Returns `true` if the time-lock is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0.is_some()
    }

    /// Returns a shared reference to the underlying value inside `self`.
    #[inline]
    pub const fn get(&self) -> Option<&T> {
        match &self.0 {
            Some(timed) => Some(timed.get()),
            _ => None,
        }
    }

    /// Returns a shared reference to the underlying [`Timed`] value.
    #[inline]
    pub const fn as_timed(&self) -> Option<&Timed<T>> {
        self.0.as_ref()
    }

    /// Returns the last [`Instant`] that `self` was modified when it was time-locked.
    #[inline]
    pub const fn maybe_modified_at(&self) -> Option<Instant> {
        match &self.0 {
            Some(timed) => Some(timed.modified_at()),
            _ => None,
        }
    }

    ///
    #[inline]
    pub fn read_timed<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T, Instant) -> R,
    {
        self.0.as_ref().map(|timed| f(&timed.value, timed.instant))
    }

    ///
    #[inline]
    pub fn set(&mut self, value: T) -> Option<T> {
        self.0.replace(Timed::new(value)).map(Timed::into_inner)
    }

    ///
    #[inline]
    pub fn set_if_empty(&mut self, value: T) -> Option<T> {
        if self.is_empty() {
            self.set(value)
        } else {
            None
        }
    }

    ///
    #[inline]
    pub fn take_if_expired(&mut self, timeout: Duration) -> Option<T> {
        match &self.0 {
            Some(lock) if lock.has_expired(timeout) => self.0.take().map(Timed::into_inner),
            _ => None,
        }
    }

    ///
    #[inline]
    pub fn mutate_if_expired<F, R>(&mut self, timeout: Duration, f: F) -> Option<R>
    where
        F: FnOnce(&mut T) -> R,
    {
        match &mut self.0 {
            Some(lock) if lock.has_expired(timeout) => Some(lock.mutate(f)),
            _ => None,
        }
    }
}

impl<T> From<Timed<T>> for TimeLock<T> {
    #[inline]
    fn from(timed: Timed<T>) -> Self {
        Self::from_timed(timed)
    }
}

*/
