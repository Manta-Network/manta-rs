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

// FIXME: Don't use raw bytes as encryption/decryption key.

/// AES Encryption Implementation
pub mod aes {
    use aes_gcm::{
        aead::{Aead, NewAead},
        Aes256Gcm, Nonce,
    };
    use generic_array::GenericArray;
    use manta_crypto::encryption::SymmetricKeyEncryptionScheme;
    use manta_util::into_array_unchecked;

    /// AES-GCM Authentication Tag Size
    #[allow(clippy::cast_possible_truncation)] // NOTE: GCM Tag Size should be smaller than `2^32`.
    const TAG_SIZE: usize = (aes_gcm::C_MAX - aes_gcm::P_MAX) as usize;

    /// Computes the size of the ciphertext corresponding to a plaintext of the given
    /// `plaintext_size`.
    #[inline]
    pub const fn ciphertext_size(plaintext_size: usize) -> usize {
        plaintext_size + TAG_SIZE
    }

    /// AES Galois Counter Mode
    pub struct AesGcm<const P: usize, const C: usize>;

    impl<const P: usize, const C: usize> AesGcm<P, C> {
        /// Encryption/Decryption Nonce
        const NONCE: &'static [u8] = b"manta rocks!";
    }

    impl<const P: usize, const C: usize> SymmetricKeyEncryptionScheme for AesGcm<P, C> {
        type Key = [u8; 32];
        type Plaintext = [u8; P];
        type Ciphertext = [u8; C];

        #[inline]
        fn encrypt(key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext {
            // SAFETY: Using a deterministic nonce is ok since we never reuse keys.
            into_array_unchecked(
                Aes256Gcm::new(GenericArray::from_slice(&key))
                    .encrypt(Nonce::from_slice(Self::NONCE), plaintext.as_ref())
                    .expect("Symmetric encryption is not allowed to fail."),
            )
        }

        #[inline]
        fn decrypt(key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext> {
            // SAFETY: Using a deterministic nonce is ok since we never reuse keys.
            Aes256Gcm::new(GenericArray::from_slice(&key))
                .decrypt(Nonce::from_slice(Self::NONCE), ciphertext.as_ref())
                .ok()
                .map(into_array_unchecked)
        }
    }

    /// Test Suite
    #[cfg(test)]
    mod test {
        use super::*;
        use manta_accounting::asset::Asset;
        use manta_crypto::{encryption, rand::RngCore};
        use rand::thread_rng;

        /// Tests if symmetric encryption of [`Asset`] decrypts properly.
        #[test]
        fn asset_encryption() {
            let mut rng = thread_rng();
            let mut key = [0; 32];
            rng.fill_bytes(&mut key);
            let mut plaintext = [0; Asset::SIZE];
            rng.fill_bytes(&mut plaintext);
            encryption::test::symmetric_encryption::<
                AesGcm<{ Asset::SIZE }, { ciphertext_size(Asset::SIZE) }>,
            >(key, plaintext);
        }
    }
}
