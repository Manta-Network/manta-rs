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

//! Encryption Implementations

// FIXME: Don't use raw bytes as encryption/decryption key.

/// AES Encryption Implementation
pub mod aes {
    use aes_gcm_siv::{
        aead::{Aead, NewAead},
        Aes256GcmSiv, Nonce,
    };
    use manta_crypto::encryption::symmetric::SymmetricKeyEncryptionScheme;
    use manta_util::Array;

    /// AES-GCM Authentication Tag Size
    #[allow(clippy::cast_possible_truncation)] // NOTE: GCM Tag Size should be smaller than `2^32`.
    const TAG_SIZE: usize = (aes_gcm_siv::C_MAX - aes_gcm_siv::P_MAX) as usize;

    /// Computes the size of the ciphertext corresponding to a plaintext of the given
    /// `plaintext_size`.
    #[inline]
    pub const fn ciphertext_size(plaintext_size: usize) -> usize {
        plaintext_size + TAG_SIZE
    }

    /// AES Galois Counter Mode with Synthetic Initialization Vectors
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct AesGcmSiv<const P: usize, const C: usize>;

    impl<const P: usize, const C: usize> AesGcmSiv<P, C> {
        /// Fixed Random Nonce
        ///
        /// # Safety
        ///
        /// Using a fixed nonce is safe under the assumption that the encryption keys are only used
        /// once. We add SIV for some extra safety which makes the effective nonce dependent on the
        /// plaintext.
        const NONCE: &'static [u8] = b"random nonce";
    }

    impl<const P: usize, const C: usize> SymmetricKeyEncryptionScheme for AesGcmSiv<P, C> {
        type Key = [u8; 32];
        type Plaintext = Array<u8, P>;
        type Ciphertext = Array<u8, C>;

        #[inline]
        fn encrypt(key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext {
            Array::from_unchecked(
                Aes256GcmSiv::new_from_slice(&key)
                    .expect("The key has the correct size.")
                    .encrypt(Nonce::from_slice(Self::NONCE), plaintext.as_ref())
                    .expect("Symmetric encryption is not allowed to fail."),
            )
        }

        #[inline]
        fn decrypt(key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext> {
            Aes256GcmSiv::new_from_slice(&key)
                .expect("The key has the correct size.")
                .decrypt(Nonce::from_slice(Self::NONCE), ciphertext.as_ref())
                .ok()
                .map(Array::from_unchecked)
        }
    }

    /// Test Suite
    #[cfg(test)]
    mod test {
        use super::*;
        use manta_accounting::asset::Asset;
        use manta_crypto::{
            encryption,
            rand::{FromEntropy, RngCore},
        };
        use rand_chacha::ChaCha20Rng;

        /// Tests if symmetric encryption of [`Asset`] decrypts properly.
        #[test]
        fn asset_encryption() {
            let mut rng = ChaCha20Rng::from_entropy();
            let mut key = [0; 32];
            rng.fill_bytes(&mut key);
            let mut plaintext = [0; Asset::SIZE];
            rng.fill_bytes(&mut plaintext);
            encryption::symmetric::test::encryption::<
                AesGcmSiv<{ Asset::SIZE }, { ciphertext_size(Asset::SIZE) }>,
            >(key, Array(plaintext));
        }
    }
}
