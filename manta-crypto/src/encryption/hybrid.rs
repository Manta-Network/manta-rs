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
    rand::{CryptoRng, Rand, RngCore, Sample},
};
use core::{fmt::Debug, hash::Hash};
use manta_util::codec::{Decode, DecodeError, Encode, Read, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Hybrid Public Key Encryption Scheme
pub trait HybridPublicKeyEncryptionScheme: SymmetricKeyEncryptionScheme {
    /// Key Agreement Scheme Type
    type KeyAgreementScheme: KeyAgreementScheme;

    /// Key Derivation Function Type
    type KeyDerivationFunction: KeyDerivationFunction<
        Key = SharedSecret<Self>,
        Output = SymmetricKey<Self>,
    >;

    /// Returns the [`KeyAgreementScheme`](Self::KeyAgreementScheme) used by this hybrid encryption
    /// scheme.
    fn key_agreement_scheme(&self) -> &Self::KeyAgreementScheme;

    /// Returns the [`KeyDerivationFunction`](Self::KeyDerivationFunction) used by this hybrid
    /// encryption scheme.
    fn key_derivation_function(&self) -> &Self::KeyDerivationFunction;

    /// Computes the shared secret given the known `secret_key` and the given `public_key` and then
    /// uses the key derivation function to derive a final shared secret.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for calling [`KeyAgreementScheme::agree`] and then
    /// [`KeyDerivationFunction::derive`].
    #[inline]
    fn agree_derive(
        &self,
        secret_key: &SecretKey<Self>,
        public_key: &PublicKey<Self>,
    ) -> SymmetricKey<Self> {
        self.key_derivation_function().derive(
            &self
                .key_agreement_scheme()
                .agree(secret_key, public_key, &mut ()),
            &mut (),
        )
    }
}

/// Secret Key Type
pub type SecretKey<H> =
    <<H as HybridPublicKeyEncryptionScheme>::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;

/// Public Key Type
pub type PublicKey<H> =
    <<H as HybridPublicKeyEncryptionScheme>::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;

/// Shared Secret Type
pub type SharedSecret<H> = <<H as HybridPublicKeyEncryptionScheme>::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret;

/// Symmetric Key Type
pub type SymmetricKey<H> = <H as SymmetricKeyEncryptionScheme>::Key;

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
pub struct Hybrid<K, F, S>
where
    K: KeyAgreementScheme,
    F: KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key>,
    S: SymmetricKeyEncryptionScheme,
{
    /// Key Agreement Scheme
    pub key_agreement_scheme: K,

    /// Key Derivation Function
    pub key_derivation_function: F,

    /// Symmetric Key Encryption Scheme
    pub symmetric_key_encryption_scheme: S,
}

impl<K, F, S> Hybrid<K, F, S>
where
    K: KeyAgreementScheme,
    F: KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key>,
    S: SymmetricKeyEncryptionScheme,
{
    /// Builds a new [`Hybrid`] Public Key Encryption Scheme from a `key_agreement_scheme`, a
    /// `key_derivation_function`, and a `symmetric_key_encryption_scheme`.
    #[inline]
    pub fn new(
        key_agreement_scheme: K,
        key_derivation_function: F,
        symmetric_key_encryption_scheme: S,
    ) -> Self {
        Self {
            key_agreement_scheme,
            key_derivation_function,
            symmetric_key_encryption_scheme,
        }
    }
}

impl<K, F, S> HybridPublicKeyEncryptionScheme for Hybrid<K, F, S>
where
    K: KeyAgreementScheme,
    F: KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key>,
    S: SymmetricKeyEncryptionScheme,
{
    type KeyAgreementScheme = K;
    type KeyDerivationFunction = F;

    #[inline]
    fn key_agreement_scheme(&self) -> &Self::KeyAgreementScheme {
        &self.key_agreement_scheme
    }

    #[inline]
    fn key_derivation_function(&self) -> &Self::KeyDerivationFunction {
        &self.key_derivation_function
    }
}

impl<K, F, S> Decode for Hybrid<K, F, S>
where
    K: Decode + KeyAgreementScheme,
    F: Decode + KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key>,
    S: Decode + SymmetricKeyEncryptionScheme,
{
    // NOTE: We use a blank error here for simplicity. This trait will be removed in the future
    //       anyways. See https://github.com/Manta-Network/manta-rs/issues/27.
    type Error = ();

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(
            K::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
            F::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
            S::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
        ))
    }
}

impl<K, F, S> Encode for Hybrid<K, F, S>
where
    K: Encode + KeyAgreementScheme,
    F: Encode + KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key>,
    S: Encode + SymmetricKeyEncryptionScheme,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.key_agreement_scheme.encode(&mut writer)?;
        self.key_derivation_function.encode(&mut writer)?;
        self.symmetric_key_encryption_scheme.encode(&mut writer)?;
        Ok(())
    }
}

impl<K, F, S, KD, FD, SD> Sample<(KD, FD, SD)> for Hybrid<K, F, S>
where
    K: KeyAgreementScheme + Sample<KD>,
    F: KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key> + Sample<FD>,
    S: SymmetricKeyEncryptionScheme + Sample<SD>,
{
    #[inline]
    fn sample<R>(distribution: (KD, FD, SD), rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::new(
            rng.sample(distribution.0),
            rng.sample(distribution.1),
            rng.sample(distribution.2),
        )
    }
}

impl<K, F, S> SymmetricKeyEncryptionScheme for Hybrid<K, F, S>
where
    K: KeyAgreementScheme,
    F: KeyDerivationFunction<Key = K::SharedSecret, Output = S::Key>,
    S: SymmetricKeyEncryptionScheme,
{
    type Key = S::Key;
    type Plaintext = S::Plaintext;
    type Ciphertext = S::Ciphertext;

    #[inline]
    fn encrypt(&self, key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext {
        self.symmetric_key_encryption_scheme.encrypt(key, plaintext)
    }

    #[inline]
    fn decrypt(&self, key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext> {
        self.symmetric_key_encryption_scheme
            .decrypt(key, ciphertext)
    }
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
    /// Ephemeral Public Key
    pub ephemeral_public_key: PublicKey<H>,

    /// Ciphertext
    pub ciphertext: H::Ciphertext,
}

impl<H> EncryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Builds a new [`EncryptedMessage`] containing an encrypted `plaintext` using `public_key`
    /// and an `ephemeral_secret_key`.
    #[inline]
    pub fn new(
        cipher: &H,
        ephemeral_secret_key: &SecretKey<H>,
        public_key: &PublicKey<H>,
        plaintext: H::Plaintext,
    ) -> Self {
        Self {
            ciphertext: cipher.encrypt(
                cipher.agree_derive(ephemeral_secret_key, public_key),
                plaintext,
            ),
            ephemeral_public_key: cipher
                .key_agreement_scheme()
                .derive(ephemeral_secret_key, &mut ()),
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
        cipher: &H,
        secret_key: &SecretKey<H>,
    ) -> Result<DecryptedMessage<H>, Self> {
        match cipher.decrypt(
            cipher.agree_derive(secret_key, &self.ephemeral_public_key),
            &self.ciphertext,
        ) {
            Some(plaintext) => Ok(DecryptedMessage::new(self.ephemeral_public_key, plaintext)),
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
    /// Ephemeral Public Key
    pub ephemeral_public_key: PublicKey<H>,

    /// Plaintext
    pub plaintext: H::Plaintext,
}

impl<H> DecryptedMessage<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Builds a new [`DecryptedMessage`] from `ephemeral_public_key` and `plaintext`.
    #[inline]
    pub fn new(ephemeral_public_key: PublicKey<H>, plaintext: H::Plaintext) -> Self {
        Self {
            ephemeral_public_key,
            plaintext,
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
        cipher: &H,
        secret_key: &SecretKey<H>,
    ) -> Option<DecryptedMessage<H>> {
        if let Some(message) = self.encrypted_message.take() {
            match message.decrypt(cipher, secret_key) {
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
        cipher: &H,
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
            cipher,
            ephemeral_secret_key,
            &cipher.key_agreement_scheme().derive(secret_key, &mut ()),
            plaintext.clone(),
        )
        .decrypt(cipher, secret_key)
        .expect("Decryption of encrypted message should have succeeded.");
        assert_eq!(
            decrypted_message.plaintext, plaintext,
            "Plaintext should have matched decrypted-encrypted plaintext."
        );
        assert_eq!(
            decrypted_message.ephemeral_public_key,
            cipher
                .key_agreement_scheme()
                .derive(ephemeral_secret_key, &mut ()),
            "Decrypted message should have included the correct ephemeral public key.",
        );
    }
}
