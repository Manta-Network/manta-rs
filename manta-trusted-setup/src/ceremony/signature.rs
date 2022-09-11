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

//! Trusted Setup Ceremony Signatures

use alloc::vec::Vec;
use manta_util::AsBytes;

/// Nonce
pub trait Nonce: Default + PartialEq {
    /// Increments the current nonce by one.
    fn increment(&mut self);

    /// Checks if the current nonce is valid.
    fn is_valid(&self) -> bool;

    ///
    #[inline]
    fn matches(&self, rhs: &Self) -> bool {
        self.is_valid() && rhs.is_valid() && self == rhs
    }
}

impl Nonce for u64 {
    #[inline]
    fn increment(&mut self) {
        *self = self.saturating_add(1);
    }

    #[inline]
    fn is_valid(&self) -> bool {
        *self != Self::MAX
    }
}

/// Message with Nonce
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Message<N> {
    /// Nonce
    pub nonce: N,

    /// Encoded Message
    pub encoded_message: Vec<u8>,
}

impl<N> AsBytes for Message<N>
where
    N: AsBytes,
{
    #[inline]
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = self.nonce.as_bytes();
        bytes.extend_from_slice(&self.encoded_message);
        bytes
    }
}
