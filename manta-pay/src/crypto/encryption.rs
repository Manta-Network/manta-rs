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
    use aes_gcm::{
        aead::{Aead, NewAead},
        Aes256Gcm, Nonce,
    };
    use core::convert::Infallible;
    use manta_crypto::{
        encryption::symmetric::SymmetricKeyEncryptionScheme,
        rand::{CryptoRng, RngCore, Sample},
    };
    use manta_util::{
        codec::{Decode, DecodeError, Encode, Read, Write},
        Array,
    };

    /// AES-GCM Authentication Tag Size
    #[allow(clippy::cast_possible_truncation)] // NOTE: GCM Tag Size should be smaller than `2^32`.
    const TAG_SIZE: usize = (aes_gcm::C_MAX - aes_gcm::P_MAX) as usize;

    /// Computes the size of the ciphertext corresponding to a plaintext of the given
    /// `plaintext_size`.
    #[inline]
    pub const fn ciphertext_size(plaintext_size: usize) -> usize {
        plaintext_size + TAG_SIZE
    }

    /// Fixed-Nonce AES Galois Counter Mode
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct FixedNonceAesGcm<const P: usize, const C: usize>;

    impl<const P: usize, const C: usize> FixedNonceAesGcm<P, C> {
        /// Fixed Random Nonce
        ///
        /// # Safety
        ///
        /// Using a fixed nonce is safe under the assumption that the encryption keys are only used
        /// once.
        const NONCE: &'static [u8] = b"random nonce";
    }

    impl<const P: usize, const C: usize> SymmetricKeyEncryptionScheme for FixedNonceAesGcm<P, C> {
        type Key = [u8; 32];
        type Plaintext = Array<u8, P>;
        type Ciphertext = Array<u8, C>;

        #[inline]
        fn encrypt(&self, key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext {
            Array::from_unchecked(
                Aes256Gcm::new_from_slice(&key)
                    .expect("The key has the correct size.")
                    .encrypt(Nonce::from_slice(Self::NONCE), plaintext.as_ref())
                    .expect("Symmetric encryption is not allowed to fail."),
            )
        }

        #[inline]
        fn decrypt(
            &self,
            key: Self::Key,
            ciphertext: &Self::Ciphertext,
        ) -> Option<Self::Plaintext> {
            Aes256Gcm::new_from_slice(&key)
                .expect("The key has the correct size.")
                .decrypt(Nonce::from_slice(Self::NONCE), ciphertext.as_ref())
                .ok()
                .map(Array::from_unchecked)
        }
    }

    impl<const P: usize, const C: usize> Decode for FixedNonceAesGcm<P, C> {
        type Error = Infallible;

        #[inline]
        fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
        where
            R: Read,
        {
            let _ = reader;
            Ok(Self)
        }
    }

    impl<const P: usize, const C: usize> Encode for FixedNonceAesGcm<P, C> {
        #[inline]
        fn encode<W>(&self, writer: W) -> Result<(), W::Error>
        where
            W: Write,
        {
            let _ = writer;
            Ok(())
        }
    }

    impl<const P: usize, const C: usize> Sample for FixedNonceAesGcm<P, C> {
        #[inline]
        fn sample<R>(distribution: (), rng: &mut R) -> Self
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            let _ = (distribution, rng);
            Self
        }
    }
}

/// Test Suite
#[cfg(test)]
mod test {
    use crate::config::NoteSymmetricEncryptionScheme;
    use manta_crypto::{
        encryption,
        rand::{OsRng, Rand},
    };

    /// Tests if symmetric encryption of [`Note`] decrypts properly.
    #[test]
    fn note_encryption() {
        let mut rng = OsRng;
        encryption::symmetric::test::encryption::<NoteSymmetricEncryptionScheme>(
            &rng.gen(),
            rng.gen_bytes(),
            rng.gen(),
        );
    }
}
