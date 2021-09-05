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

//! Integrated Encryption Schemes and Encrypted Messages

// FIXME: add zeroize for secret keys

use core::{fmt::Debug, hash::Hash};
use manta_codec::{ScaleDecode, ScaleEncode};
use rand::{CryptoRng, RngCore};

pub(crate) mod prelude {
    #[doc(inline)]
    pub use crate::ies::IntegratedEncryptionScheme;
}

/// [`IntegratedEncryptionScheme`] Public Key
pub struct PublicKey<I>
where
    I: IntegratedEncryptionScheme + ?Sized,
{
    /// Public Key
    public_key: I::PublicKey,
}

impl<I> PublicKey<I>
where
    I: IntegratedEncryptionScheme + ?Sized,
{
    /// Generates a new [`PublicKey`] from a
    /// [`I::PublicKey`](IntegratedEncryptionScheme::PublicKey).
    #[inline]
    pub fn new(public_key: I::PublicKey) -> Self {
        Self { public_key }
    }

    /// Encrypts the `plaintext` with `self`, generating an [`EncryptedMessage`].
    #[inline]
    pub fn encrypt<R>(
        self,
        plaintext: I::Plaintext,
        rng: &mut R,
    ) -> Result<EncryptedMessage<I>, I::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        I::encrypt(plaintext, self.public_key, rng)
    }
}

/// [`IntegratedEncryptionScheme`] Secret Key
pub struct SecretKey<I>
where
    I: IntegratedEncryptionScheme + ?Sized,
{
    /// Secret Key
    secret_key: I::SecretKey,
}

impl<I> SecretKey<I>
where
    I: IntegratedEncryptionScheme + ?Sized,
{
    /// Generates a new `SecretKey` from an `I::SecretKey`.
    ///
    /// # API Note
    ///
    /// This function is intentionally private so that secret keys are not part of the
    /// public interface.
    #[inline]
    fn new(secret_key: I::SecretKey) -> Self {
        Self { secret_key }
    }

    /// Decrypts the `message` with `self`.
    #[inline]
    pub fn decrypt(self, message: EncryptedMessage<I>) -> Result<I::Plaintext, I::Error> {
        message.decrypt(self)
    }
}

/// [`IntegratedEncryptionScheme`] Key Pair
pub struct KeyPair<I>
where
    I: IntegratedEncryptionScheme + ?Sized,
{
    /// Public Key
    public_key: I::PublicKey,

    /// Secret Key
    secret_key: I::SecretKey,
}

impl<I> KeyPair<I>
where
    I: IntegratedEncryptionScheme + ?Sized,
{
    /// Builds a new [`KeyPair`] from a `public_key` and a `secret_key`.
    #[inline]
    pub fn new(public_key: I::PublicKey, secret_key: I::SecretKey) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }

    /// Generates a public/secret keypair.
    #[inline]
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        I::keygen(rng)
    }

    /// Returns the public side of the key pair.
    #[inline]
    pub fn into_public(self) -> PublicKey<I> {
        PublicKey::new(self.public_key)
    }

    /// Returns the secret side of the key pair.
    #[inline]
    pub fn into_secret(self) -> SecretKey<I> {
        SecretKey::new(self.secret_key)
    }

    /// Encrypts the `plaintext` with `self, generating an [`EncryptedMessage`].
    #[inline]
    pub fn encrypt<R>(
        self,
        plaintext: I::Plaintext,
        rng: &mut R,
    ) -> Result<(EncryptedMessage<I>, SecretKey<I>), I::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let (public_key, secret_key) = self.into();
        Ok((public_key.encrypt(plaintext, rng)?, secret_key))
    }
}

impl<I> From<KeyPair<I>> for (PublicKey<I>, SecretKey<I>)
where
    I: IntegratedEncryptionScheme + ?Sized,
{
    #[inline]
    fn from(keypair: KeyPair<I>) -> Self {
        (
            PublicKey::new(keypair.public_key),
            SecretKey::new(keypair.secret_key),
        )
    }
}

/// Integrated Encryption Scheme Trait
pub trait IntegratedEncryptionScheme {
    /// Public Key Type
    type PublicKey;

    /// Secret Key Type
    type SecretKey;

    /// Plaintext Type
    type Plaintext;

    /// Ciphertext Type
    type Ciphertext;

    /// Encryption/Decryption Error Type
    type Error;

    /// Generates a public/secret keypair.
    fn keygen<R>(rng: &mut R) -> KeyPair<Self>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Encrypts the `plaintext` with the `public_key`, generating an [`EncryptedMessage`].
    fn encrypt<R>(
        plaintext: Self::Plaintext,
        public_key: Self::PublicKey,
        rng: &mut R,
    ) -> Result<EncryptedMessage<Self>, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Generates a public/secret keypair and then encrypts the `plaintext` with the generated
    /// public key, generating an [`EncryptedMessage`] and a [`SecretKey`].
    #[inline]
    fn keygen_encrypt<R>(
        plaintext: Self::Plaintext,
        rng: &mut R,
    ) -> Result<(EncryptedMessage<Self>, SecretKey<Self>), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::keygen(rng).encrypt(plaintext, rng)
    }

    /// Decrypts the `ciphertext` with the `secret_key`.
    fn decrypt(
        ciphertext: Self::Ciphertext,
        secret_key: Self::SecretKey,
    ) -> Result<Self::Plaintext, Self::Error>;
}

/// Encrypted Message
#[derive(derivative::Derivative, ScaleDecode, ScaleEncode)]
#[derivative(
    Clone(bound = "I::Ciphertext: Clone"),
    Copy(bound = "I::Ciphertext: Copy"),
    Debug(bound = "I::Ciphertext: Debug"),
    Default(bound = "I::Ciphertext: Default"),
    Eq(bound = "I::Ciphertext: Eq"),
    Hash(bound = "I::Ciphertext: Hash"),
    PartialEq(bound = "I::Ciphertext: PartialEq")
)]
pub struct EncryptedMessage<I>
where
    I: IntegratedEncryptionScheme + ?Sized,
{
    /// Message Ciphertext
    ciphertext: I::Ciphertext,
}

impl<I> EncryptedMessage<I>
where
    I: IntegratedEncryptionScheme + ?Sized,
{
    /// Builds a new [`EncryptedMessage`] from
    /// [`I::Ciphertext`](IntegratedEncryptionScheme::Ciphertext).
    #[inline]
    pub fn new(ciphertext: I::Ciphertext) -> Self {
        Self { ciphertext }
    }

    /// Encrypts the `plaintext` with the `public_key`, generating an [`EncryptedMessage`].
    #[inline]
    pub fn encrypt<R>(
        plaintext: I::Plaintext,
        public_key: I::PublicKey,
        rng: &mut R,
    ) -> Result<Self, I::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        I::encrypt(plaintext, public_key, rng)
    }

    /// Generates a public/secret keypair and then encrypts the `plaintext` with the generated
    /// public key, generating an [`EncryptedMessage`] and a [`SecretKey`].
    #[inline]
    pub fn keygen_encrypt<R>(
        plaintext: I::Plaintext,
        rng: &mut R,
    ) -> Result<(Self, SecretKey<I>), I::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        I::keygen_encrypt(plaintext, rng)
    }

    /// Decrypts `self` with the `secret_key`.
    #[inline]
    pub fn decrypt(self, secret_key: SecretKey<I>) -> Result<I::Plaintext, I::Error> {
        I::decrypt(self.ciphertext, secret_key.secret_key)
    }
}
