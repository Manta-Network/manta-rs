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

//! Encryption Implementations

// FIXME: Don't use raw bytes as secret and public key.
// FIXME: Make sure secret keys are protected.

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Nonce,
};
use core::marker::PhantomData;
use generic_array::GenericArray;
use manta_crypto::encryption::SymmetricKeyEncryptionScheme;

/// AES Galois Counter Mode
pub struct AesGcm<T>(PhantomData<T>)
where
    T: AsRef<[u8]> + From<Vec<u8>>;

impl<T> AesGcm<T>
where
    T: AsRef<[u8]> + From<Vec<u8>>,
{
    /// Encryption/Decryption Nonce
    const NONCE: &'static [u8] = b"manta rocks!";
}

impl<T> SymmetricKeyEncryptionScheme for AesGcm<T>
where
    T: AsRef<[u8]> + From<Vec<u8>>,
{
    type Key = [u8; 32];

    type Plaintext = T;

    type Ciphertext = Vec<u8>;

    #[inline]
    fn encrypt(key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext {
        // SAFETY: Using a deterministic nonce is ok since we never reuse keys.
        Aes256Gcm::new(GenericArray::from_slice(&key))
            .encrypt(Nonce::from_slice(Self::NONCE), plaintext.as_ref())
            .expect("Symmetric encryption is not allowed to fail.")
    }

    #[inline]
    fn decrypt(key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext> {
        // SAFETY: Using a deterministic nonce is ok since we never reuse keys.
        Aes256Gcm::new(GenericArray::from_slice(&key))
            .decrypt(Nonce::from_slice(Self::NONCE), ciphertext.as_ref())
            .ok()
            .map(Into::into)
    }
}
