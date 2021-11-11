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

//! Encryption Primitives

pub mod ies;

pub use ies::prelude::*;

use crate::key::KeyAgreementScheme;

/// Symmetric-Key Encryption Scheme
///
/// # Specification
///
/// All implementations of this trait must adhere to the following properties:
///
/// 1. **Invertibility**: For all possible inputs, the following function returns `true`:
///
///     ```text
///     fn invertibility(key: Key, plaintext: Plaintext) -> bool {
///         matches!(decrypt(key, &encrypt(key, plaintext.clone())), Some(p) if p == plaintext)
///     }
///     ```
pub trait SymmetricKeyEncryptionScheme {
    /// Encryption/Decryption Key Type
    type Key;

    /// Plaintext Type
    type Plaintext;

    /// Ciphertext Type
    type Ciphertext;

    /// Encrypts `plaintext` using `key`.
    fn encrypt(key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext;

    /// Tries to decrypt `ciphertext` using `key`.
    fn decrypt(key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext>;
}

/// Key-Derivation Function
pub trait KeyDerivationFunction {
    /// Shared Secret Type
    type SharedSecret;

    /// Encryption/Decryption Key Type
    type Key;

    /// Key-Agreement Scheme Type
    type KeyAgreementScheme: KeyAgreementScheme<SharedSecret = Self::SharedSecret>;

    /// Symmetric-Key Encryption Scheme Type
    type SymmetricKeyEncryptionScheme: SymmetricKeyEncryptionScheme<Key = Self::Key>;

    /// Derives an encryption/decryption key from a given `shared_secret`.
    fn derive(shared_secret: Self::SharedSecret) -> Self::Key;
}

/// Hybrid Public Key Encryption Scheme
pub trait HybridPublicKeyEncryptionScheme {
    /// Secret Key Type
    type SecretKey;

    /// Public Key Type
    type PublicKey;

    /// Plaintext Type
    type Plaintext;

    /// Ciphertext Type
    type Ciphertext;

    /// Key-Agreement Scheme Type
    type KeyAgreementScheme: KeyAgreementScheme<
        SecretKey = Self::SecretKey,
        PublicKey = Self::PublicKey,
    >;

    /// Symmetric-Key Encryption Scheme Type
    type SymmetricKeyEncryptionScheme: SymmetricKeyEncryptionScheme<
        Plaintext = Self::Plaintext,
        Ciphertext = Self::Ciphertext,
    >;

    /// Key-Derivation Function Type
    type KeyDerivationFunction: KeyDerivationFunction<
        SharedSecret = <Self::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret,
        Key = <Self::SymmetricKeyEncryptionScheme as SymmetricKeyEncryptionScheme>::Key,
        KeyAgreementScheme = Self::KeyAgreementScheme,
        SymmetricKeyEncryptionScheme = Self::SymmetricKeyEncryptionScheme,
    >;
}

/// Encrypted Message
pub struct EncryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme + ?Sized,
{
    /// Ciphertext
    ciphertext: H::Ciphertext,

    /// Ephemeral Public Key
    ephemeral_public_key: H::PublicKey,
}

impl<H> EncryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme + ?Sized,
{
    /// Builds a new [`EncryptedMessage`] containing an encrypted `plaintext` using `public_key`
    /// and an `ephemeral_secret_key`.
    #[inline]
    pub fn new(
        public_key: &H::PublicKey,
        ephemeral_secret_key: H::SecretKey,
        plaintext: H::Plaintext,
    ) -> Self {
        Self {
            ciphertext: H::SymmetricKeyEncryptionScheme::encrypt(
                H::KeyDerivationFunction::derive(H::KeyAgreementScheme::agree(
                    &ephemeral_secret_key,
                    public_key,
                )),
                plaintext,
            ),
            ephemeral_public_key: H::KeyAgreementScheme::derive(ephemeral_secret_key),
        }
    }

    /// Tries to decrypt `self` using `secret_key`, returning back `Err(self)` if the `secret_key`
    /// was unable to decrypt the message.
    #[inline]
    pub fn decrypt(self, secret_key: &H::SecretKey) -> Result<DecryptedMessage<H>, Self> {
        match H::SymmetricKeyEncryptionScheme::decrypt(
            H::KeyDerivationFunction::derive(H::KeyAgreementScheme::agree(
                secret_key,
                &self.ephemeral_public_key,
            )),
            &self.ciphertext,
        ) {
            Some(plaintext) => Ok(DecryptedMessage::new(plaintext, self.ephemeral_public_key)),
            _ => Err(self),
        }
    }
}

/// Decrypted Message
pub struct DecryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme + ?Sized,
{
    /// Plaintext
    pub plaintext: H::Plaintext,

    /// Ephemeral Public Key
    pub ephemeral_public_key: H::PublicKey,
}

impl<H> DecryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme + ?Sized,
{
    /// Builds a new [`DecryptedMessage`] from `plaintext` and `ephemeral_public_key`.
    #[inline]
    pub fn new(plaintext: H::Plaintext, ephemeral_public_key: H::PublicKey) -> Self {
        Self {
            plaintext,
            ephemeral_public_key,
        }
    }
}
