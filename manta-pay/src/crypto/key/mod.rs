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

//! Cryptographic Key Primitive Implementations

use blake2::{Blake2s, Digest};
use core::marker::PhantomData;
use manta_crypto::key::KeyDerivationFunction;
use manta_util::into_array_unchecked;

pub mod elliptic_curve_diffie_hellman;

/// Blake2s KDF
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2sKdf<T>(PhantomData<T>)
where
    T: AsRef<[u8]>;

impl<T> KeyDerivationFunction for Blake2sKdf<T>
where
    T: AsRef<[u8]>,
{
    type Key = T;

    type Output = [u8; 32];

    #[inline]
    fn derive(&self, secret: Self::Key, compiler: &mut ()) -> Self::Output {
        let _ = compiler;
        let mut hasher = Blake2s::new();
        hasher.update(secret.as_ref());
        hasher.update(b"manta kdf instantiated with blake2s hash function");
        into_array_unchecked(hasher.finalize())
    }
}
