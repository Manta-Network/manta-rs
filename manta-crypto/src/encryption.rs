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

use crate::key::{KeyAgreementScheme, KeyDerivationFunction};
use core::marker::PhantomData;

/// Symmetric Key Encryption Scheme
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

/// Hybrid Public Key Encryption Scheme
pub trait HybridPublicKeyEncryptionScheme: SymmetricKeyEncryptionScheme {
    /// Key Agreement Scheme Type
    type KeyAgreementScheme: KeyAgreementScheme;

    /// Key Derivation Function Type
    type KeyDerivationFunction: KeyDerivationFunction<
        <Self::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret,
        Output = Self::Key,
    >;

    /// Computes the shared secret given the known `secret_key` and the given `public_key` and then
    /// uses the key derivation function to derive a final shared secret.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for calling [`KeyAgreementScheme::agree`] and then
    /// [`KeyDerivationFunction::derive`].
    #[inline]
    fn agree_derive(secret_key: &SecretKey<Self>, public_key: &PublicKey<Self>) -> Self::Key {
        Self::KeyDerivationFunction::derive(Self::KeyAgreementScheme::agree(secret_key, public_key))
    }
}

/// Secret Key Type
pub type SecretKey<H> =
    <<H as HybridPublicKeyEncryptionScheme>::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;

/// Public Key Type
pub type PublicKey<H> =
    <<H as HybridPublicKeyEncryptionScheme>::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;

/// Hybrid Public Key Encryption Scheme
///
/// # Optimization Note
///
/// Since [`Hybrid`] takes the three parts of the [`HybridPublicKeyEncryptionScheme`] implementation
/// as type parameters, the [`agree_derive`] optimization cannot be implemented. To implement a
/// custom optimization, the entire [`HybridPublicKeyEncryptionScheme`] trait will need to be
/// implemented.
///
/// [`agree_derive`]: HybridPublicKeyEncryptionScheme::agree_derive
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hybrid<K, S, F>
where
    K: KeyAgreementScheme,
    S: SymmetricKeyEncryptionScheme,
    F: KeyDerivationFunction<K::SharedSecret, Output = S::Key>,
{
    /// Type Parameter Marker
    __: PhantomData<(K, S, F)>,
}

impl<K, S, F> SymmetricKeyEncryptionScheme for Hybrid<K, S, F>
where
    K: KeyAgreementScheme,
    S: SymmetricKeyEncryptionScheme,
    F: KeyDerivationFunction<K::SharedSecret, Output = S::Key>,
{
    type Key = S::Key;

    type Plaintext = S::Plaintext;

    type Ciphertext = S::Ciphertext;

    #[inline]
    fn encrypt(key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext {
        S::encrypt(key, plaintext)
    }

    #[inline]
    fn decrypt(key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext> {
        S::decrypt(key, ciphertext)
    }
}

impl<K, S, F> HybridPublicKeyEncryptionScheme for Hybrid<K, S, F>
where
    K: KeyAgreementScheme,
    S: SymmetricKeyEncryptionScheme,
    F: KeyDerivationFunction<K::SharedSecret, Output = S::Key>,
{
    type KeyAgreementScheme = K;
    type KeyDerivationFunction = F;
}

/// Encrypted Message
pub struct EncryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Ciphertext
    ciphertext: H::Ciphertext,

    /// Ephemeral Public Key
    ephemeral_public_key: PublicKey<H>,
}

impl<H> EncryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Builds a new [`EncryptedMessage`] containing an encrypted `plaintext` using `public_key`
    /// and an `ephemeral_secret_key`.
    #[inline]
    pub fn new(
        public_key: &PublicKey<H>,
        ephemeral_secret_key: SecretKey<H>,
        plaintext: H::Plaintext,
    ) -> Self {
        Self {
            ciphertext: H::encrypt(
                H::agree_derive(&ephemeral_secret_key, public_key),
                plaintext,
            ),
            ephemeral_public_key: H::KeyAgreementScheme::derive_owned(ephemeral_secret_key),
        }
    }

    /// Returns the ephemeral public key associated to `self`.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &PublicKey<H> {
        &self.ephemeral_public_key
    }

    /// Tries to decrypt `self` using `secret_key`, returning back `Err(self)` if the `secret_key`
    /// was unable to decrypt the message.
    #[inline]
    pub fn decrypt(self, secret_key: &SecretKey<H>) -> Result<DecryptedMessage<H>, Self> {
        match H::decrypt(
            H::agree_derive(secret_key, &self.ephemeral_public_key),
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
    H: HybridPublicKeyEncryptionScheme,
{
    /// Plaintext
    pub plaintext: H::Plaintext,

    /// Ephemeral Public Key
    pub ephemeral_public_key: PublicKey<H>,
}

impl<H> DecryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Builds a new [`DecryptedMessage`] from `plaintext` and `ephemeral_public_key`.
    #[inline]
    pub fn new(plaintext: H::Plaintext, ephemeral_public_key: PublicKey<H>) -> Self {
        Self {
            plaintext,
            ephemeral_public_key,
        }
    }

    /// Tries to decrypt `encrypted_message` with `secret_key`, if the `Option` contains a message.
    #[inline]
    pub fn try_new(
        encrypted_message: &mut Option<EncryptedMessage<H>>,
        secret_key: &SecretKey<H>,
    ) -> Option<Self> {
        if let Some(message) = encrypted_message.take() {
            match message.decrypt(secret_key) {
                Ok(decrypted_message) => return Some(decrypted_message),
                Err(message) => *encrypted_message = Some(message),
            }
        }
        None
    }
}
