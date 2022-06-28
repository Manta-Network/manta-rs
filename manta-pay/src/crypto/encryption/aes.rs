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

//! AES Encryption Implementation

// FIXME: Don't use raw bytes as encryption/decryption key.

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Nonce,
};
use core::convert::Infallible;
use manta_crypto::{
    encryption::{
        CiphertextType, Decrypt, DecryptedPlaintextType, DecryptionKeyType, Derive, Encrypt,
        EncryptionKeyType, HeaderType, PlaintextType, RandomnessType,
    },
    rand::{RngCore, Sample},
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
///
/// # Safety
///
/// The encryption key can be used only once.
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

impl<const P: usize, const C: usize> HeaderType for FixedNonceAesGcm<P, C> {
    type Header = ();
}

impl<const P: usize, const C: usize> CiphertextType for FixedNonceAesGcm<P, C> {
    type Ciphertext = Array<u8, C>;
}

impl<const P: usize, const C: usize> EncryptionKeyType for FixedNonceAesGcm<P, C> {
    type EncryptionKey = [u8; 32];
}

impl<const P: usize, const C: usize> DecryptionKeyType for FixedNonceAesGcm<P, C> {
    type DecryptionKey = [u8; 32];
}

impl<const P: usize, const C: usize> Derive for FixedNonceAesGcm<P, C> {
    #[inline]
    fn derive(&self, decryption_key: &Self::DecryptionKey, _: &mut ()) -> Self::EncryptionKey {
        *decryption_key
    }
}

impl<const P: usize, const C: usize> PlaintextType for FixedNonceAesGcm<P, C> {
    type Plaintext = Array<u8, P>;
}

impl<const P: usize, const C: usize> RandomnessType for FixedNonceAesGcm<P, C> {
    type Randomness = ();
}

impl<const P: usize, const C: usize> DecryptedPlaintextType for FixedNonceAesGcm<P, C> {
    type DecryptedPlaintext = Option<Array<u8, P>>;
}

impl<const P: usize, const C: usize> Encrypt for FixedNonceAesGcm<P, C> {
    #[inline]
    fn encrypt(
        &self,
        encryption_key: &Self::EncryptionKey,
        _: &Self::Randomness,
        _: &Self::Header,
        plaintext: &Self::Plaintext,
        _: &mut (),
    ) -> Self::Ciphertext {
        Array::from_unchecked(
            Aes256Gcm::new_from_slice(encryption_key)
                .expect("The key has the correct size.")
                .encrypt(Nonce::from_slice(Self::NONCE), plaintext.as_ref())
                .expect("Symmetric encryption is not allowed to fail."),
        )
    }
}

impl<const P: usize, const C: usize> Decrypt for FixedNonceAesGcm<P, C> {
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        _: &Self::Header,
        ciphertext: &Self::Ciphertext,
        _: &mut (),
    ) -> Self::DecryptedPlaintext {
        Aes256Gcm::new_from_slice(decryption_key)
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
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
        Self
    }
}
