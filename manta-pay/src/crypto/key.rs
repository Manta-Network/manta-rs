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

//! Cryptographic Key Primitive Implementations

use alloc::vec::Vec;
use blake2::{Blake2s, Digest};
use manta_crypto::{
    key::agreement::{Derive, PublicKeyType, SecretKeyType},
    rand::{RngCore, Sample},
};
use manta_util::{impl_empty_codec, into_array_unchecked};

/// Blake2s KDF
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2sKdf;

impl SecretKeyType for Blake2sKdf {
    type SecretKey = Vec<u8>;
}

impl PublicKeyType for Blake2sKdf {
    type PublicKey = [u8; 32];
}

impl Derive for Blake2sKdf {
    #[inline]
    fn derive(&self, key: &Self::SecretKey, _: &mut ()) -> Self::PublicKey {
        let mut hasher = Blake2s::new();
        hasher.update(key);
        hasher.update(b"manta kdf instantiated with blake2s hash function");
        into_array_unchecked(hasher.finalize())
    }
}

impl_empty_codec! { Blake2sKdf }

impl Sample for Blake2sKdf {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
        Self
    }
}
