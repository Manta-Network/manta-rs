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

//! Hybrid Encryption

use crate::{
    encryption::symmetric::SymmetricKeyEncryptionScheme,
    key::{KeyAgreementScheme, KeyDerivationFunction},
};
use core::{fmt::Debug, hash::Hash, marker::PhantomData};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Hybrid Public Key Encryption Scheme
pub trait HybridPublicKeyEncryptionScheme: SymmetricKeyEncryptionScheme {
    /// Key Agreement Scheme Type
    type KeyAgreementScheme: KeyAgreementScheme;

    /// Key Derivation Function Type
    type KeyDerivationFunction: KeyDerivationFunction<
        Key = <Self::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret,
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
    fn agree_derive(
        parameters: &Self::KeyAgreementScheme,
        secret_key: &SecretKey<Self>,
        public_key: &PublicKey<Self>,
    ) -> Self::Key {
        Self::KeyDerivationFunction::derive(&parameters.agree(secret_key, public_key))
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
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde")
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hybrid<K, S, F>(PhantomData<(K, S, F)>)
where
    K: KeyAgreementScheme,
    S: SymmetricKeyEncryptionScheme,
    F: KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key>;

impl<K, S, F> SymmetricKeyEncryptionScheme for Hybrid<K, S, F>
where
    K: KeyAgreementScheme,
    S: SymmetricKeyEncryptionScheme,
    F: KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key>,
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
    F: KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key>,
{
    type KeyAgreementScheme = K;
    type KeyDerivationFunction = F;
}

/// Encrypted Message
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "H::Ciphertext: Deserialize<'de>, PublicKey<H>: Deserialize<'de>",
            serialize = "H::Ciphertext: Serialize, PublicKey<H>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "H::Ciphertext: Clone, PublicKey<H>: Clone"),
    Copy(bound = "H::Ciphertext: Copy, PublicKey<H>: Copy"),
    Debug(bound = "H::Ciphertext: Debug, PublicKey<H>: Debug"),
    Eq(bound = "H::Ciphertext: Eq, PublicKey<H>: Eq"),
    Hash(bound = "H::Ciphertext: Hash, PublicKey<H>: Hash"),
    PartialEq(bound = "H::Ciphertext: PartialEq, PublicKey<H>: PartialEq")
)]
pub struct EncryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Ciphertext
    pub ciphertext: H::Ciphertext,

    /// Ephemeral Public Key
    pub ephemeral_public_key: PublicKey<H>,
}

impl<H> EncryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Builds a new [`EncryptedMessage`] containing an encrypted `plaintext` using `public_key`
    /// and an `ephemeral_secret_key`.
    #[inline]
    pub fn new(
        parameters: &H::KeyAgreementScheme,
        public_key: &PublicKey<H>,
        ephemeral_secret_key: &SecretKey<H>,
        plaintext: H::Plaintext,
    ) -> Self {
        Self {
            ciphertext: H::encrypt(
                H::agree_derive(parameters, ephemeral_secret_key, public_key),
                plaintext,
            ),
            ephemeral_public_key: parameters.derive(ephemeral_secret_key),
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
    pub fn decrypt(
        self,
        parameters: &H::KeyAgreementScheme,
        secret_key: &SecretKey<H>,
    ) -> Result<DecryptedMessage<H>, Self> {
        match H::decrypt(
            H::agree_derive(parameters, secret_key, &self.ephemeral_public_key),
            &self.ciphertext,
        ) {
            Some(plaintext) => Ok(DecryptedMessage::new(plaintext, self.ephemeral_public_key)),
            _ => Err(self),
        }
    }
}

/// Decrypted Message
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "H::Plaintext: Deserialize<'de>, PublicKey<H>: Deserialize<'de>",
            serialize = "H::Plaintext: Serialize, PublicKey<H>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "H::Plaintext: Clone, PublicKey<H>: Clone"),
    Copy(bound = "H::Plaintext: Copy, PublicKey<H>: Copy"),
    Debug(bound = "H::Plaintext: Debug, PublicKey<H>: Debug"),
    Eq(bound = "H::Plaintext: Eq, PublicKey<H>: Eq"),
    Hash(bound = "H::Plaintext: Hash, PublicKey<H>: Hash"),
    PartialEq(bound = "H::Plaintext: PartialEq, PublicKey<H>: PartialEq")
)]
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

    /// Builds a new [`DecryptionFinder`] for `encrypted_message`. Use [`DecryptionFinder::decrypt`]
    /// to try and decrypt the message.
    #[inline]
    pub fn find(encrypted_message: EncryptedMessage<H>) -> DecryptionFinder<H> {
        DecryptionFinder::new(encrypted_message)
    }
}

/// Decryption Finder
pub struct DecryptionFinder<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Encrypted Message
    encrypted_message: Option<EncryptedMessage<H>>,
}

impl<H> DecryptionFinder<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Builds a new [`DecryptionFinder`] for `encrypted_message`.
    #[inline]
    pub fn new(encrypted_message: EncryptedMessage<H>) -> Self {
        Self {
            encrypted_message: Some(encrypted_message),
        }
    }

    /// Returns `true` if the decryption was found.
    #[inline]
    pub fn found(&self) -> bool {
        self.encrypted_message.is_none()
    }

    /// Tries to decrypt with `secret_key`, if `self` still contains a message.
    #[inline]
    pub fn decrypt(
        &mut self,
        parameters: &H::KeyAgreementScheme,
        secret_key: &SecretKey<H>,
    ) -> Option<DecryptedMessage<H>> {
        if let Some(message) = self.encrypted_message.take() {
            match message.decrypt(parameters, secret_key) {
                Ok(decrypted_message) => return Some(decrypted_message),
                Err(message) => self.encrypted_message = Some(message),
            }
        }
        None
    }

    /// Extracts the possible encrypted message which has not yet been decrypted.
    #[inline]
    pub fn into_inner(self) -> Option<EncryptedMessage<H>> {
        self.encrypted_message
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;

    /// Tests if hybrid encryption of `plaintext` using `public_key` returns the same plaintext on
    /// decryption.
    #[inline]
    pub fn encryption<H>(
        parameters: &H::KeyAgreementScheme,
        secret_key: &SecretKey<H>,
        ephemeral_secret_key: &SecretKey<H>,
        plaintext: H::Plaintext,
    ) where
        H: HybridPublicKeyEncryptionScheme,
        H::Plaintext: Clone + Debug + PartialEq,
        H::Ciphertext: Debug,
        PublicKey<H>: Debug + PartialEq,
    {
        let decrypted_message = EncryptedMessage::<H>::new(
            parameters,
            &parameters.derive(secret_key),
            ephemeral_secret_key,
            plaintext.clone(),
        )
        .decrypt(parameters, secret_key)
        .expect("Decryption of encrypted message should have succeeded.");
        assert_eq!(
            decrypted_message.plaintext, plaintext,
            "Plaintext should have matched decrypted-encrypted plaintext."
        );
        assert_eq!(
            decrypted_message.ephemeral_public_key,
            parameters.derive(ephemeral_secret_key),
            "Decrypted message should have included the correct ephemeral public key.",
        );
    }
}
