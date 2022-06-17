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

//! Hybrid Public-Key Encryption
//!
//! For encrypting against the same [`EncryptionKey`] and [`DecryptionKey`] we may want to use a
//! key-exchange protocol in order to generate these keys as unique shared secrets. The [`Hybrid`]
//! encryption scheme inlines this complexity into the encryption interfaces.

use crate::{
    encryption::{
        CiphertextType, Decrypt, DecryptedPlaintextType, DecryptionKeyType, Derive, Encrypt,
        EncryptedMessage, EncryptionKeyType, HeaderType, PlaintextType, RandomnessType,
    },
    key,
    rand::{Rand, RngCore, Sample},
};
use core::{fmt::Debug, hash::Hash};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Encryption Key
pub type EncryptionKey<K> = <K as key::agreement::Types>::PublicKey;

/// Decryption Key
pub type DecryptionKey<K> = <K as key::agreement::Types>::SecretKey;

/// Encryption Randomness
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "K::SecretKey: Clone, E::Randomness: Clone"),
    Copy(bound = "K::SecretKey: Copy, E::Randomness: Copy"),
    Debug(bound = "K::SecretKey: Debug, E::Randomness: Debug"),
    Default(bound = "K::SecretKey: Default, E::Randomness: Default"),
    Eq(bound = "K::SecretKey: Eq, E::Randomness: Eq"),
    Hash(bound = "K::SecretKey: Hash, E::Randomness: Hash"),
    PartialEq(bound = "K::SecretKey: PartialEq, E::Randomness: PartialEq")
)]
pub struct Randomness<K, E>
where
    K: key::agreement::Types,
    E: RandomnessType,
{
    /// Ephemeral Secret Key
    pub ephemeral_secret_key: K::SecretKey,

    /// Base Encryption Randomness
    pub randomness: E::Randomness,
}

impl<K, E> Randomness<K, E>
where
    K: key::agreement::Types,
    E: RandomnessType,
{
    /// Builds a new [`Randomness`] from `ephemeral_secret_key` and `randomness`.
    #[inline]
    pub fn new(ephemeral_secret_key: K::SecretKey, randomness: E::Randomness) -> Self {
        Self {
            ephemeral_secret_key,
            randomness,
        }
    }

    /// Builds a new [`Randomness`] from `ephemeral_secret_key` whenever the base encryption scheme
    /// has no [`Randomness`] type (i.e. uses `()` as its [`Randomness`] type).
    ///
    /// [`Randomness`]: RandomnessType::Randomness
    #[inline]
    pub fn from_key(ephemeral_secret_key: K::SecretKey) -> Self
    where
        E: RandomnessType<Randomness = ()>,
    {
        Self::new(ephemeral_secret_key, ())
    }
}

impl<K, E, DS, DR> Sample<(DS, DR)> for Randomness<K, E>
where
    K: key::agreement::Types,
    E: RandomnessType,
    K::SecretKey: Sample<DS>,
    E::Randomness: Sample<DR>,
{
    #[inline]
    fn sample<R>(distribution: (DS, DR), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

/// Full Ciphertext
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "K::PublicKey: Clone, E::Ciphertext: Clone"),
    Copy(bound = "K::PublicKey: Copy, E::Ciphertext: Copy"),
    Debug(bound = "K::PublicKey: Debug, E::Ciphertext: Debug"),
    Default(bound = "K::PublicKey: Default, E::Ciphertext: Default"),
    Eq(bound = "K::PublicKey: Eq, E::Ciphertext: Eq"),
    Hash(bound = "K::PublicKey: Hash, E::Ciphertext: Hash"),
    PartialEq(bound = "K::PublicKey: PartialEq, E::Ciphertext: PartialEq")
)]
pub struct Ciphertext<K, E>
where
    K: key::agreement::Types,
    E: CiphertextType,
{
    /// Ephemeral Public Key
    pub ephemeral_public_key: K::PublicKey,

    /// Base Encryption Ciphertext
    pub ciphertext: E::Ciphertext,
}

impl<K, E> Ciphertext<K, E>
where
    K: key::agreement::Types,
    E: CiphertextType,
{
    /// Builds a new [`Ciphertext`] from `ephemeral_public_key` and `ciphertext`.
    #[inline]
    pub fn new(ephemeral_public_key: K::PublicKey, ciphertext: E::Ciphertext) -> Self {
        Self {
            ephemeral_public_key,
            ciphertext,
        }
    }
}

impl<K, E, DP, DC> Sample<(DP, DC)> for Ciphertext<K, E>
where
    K: key::agreement::Types,
    E: CiphertextType,
    K::PublicKey: Sample<DP>,
    E::Ciphertext: Sample<DC>,
{
    #[inline]
    fn sample<R>(distribution: (DP, DC), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

/// Hybrid Encryption Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Hybrid<K, E> {
    /// Key Agreement Scheme
    pub key_agreement_scheme: K,

    /// Base Encryption Scheme
    pub encryption_scheme: E,
}

impl<K, E> Hybrid<K, E> {
    /// Builds a new [`Hybrid`] encryption scheme from `key_agreement_scheme` and a base
    /// `encryption_scheme`.
    #[inline]
    pub fn new(key_agreement_scheme: K, encryption_scheme: E) -> Self {
        Self {
            key_agreement_scheme,
            encryption_scheme,
        }
    }
}

impl<K, E> EncryptedMessage<Hybrid<K, E>>
where
    K: key::agreement::Types,
    E: CiphertextType + HeaderType,
{
    /// Returns the ephemeral public key associated to `self`, stored in its ciphertext.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &K::PublicKey {
        &self.ciphertext.ephemeral_public_key
    }
}

impl<K, E> HeaderType for Hybrid<K, E>
where
    E: HeaderType,
{
    type Header = E::Header;
}

impl<K, E> CiphertextType for Hybrid<K, E>
where
    K: key::agreement::Types,
    E: CiphertextType,
{
    type Ciphertext = Ciphertext<K, E>;
}

impl<K, E> EncryptionKeyType for Hybrid<K, E>
where
    K: key::agreement::Types,
{
    type EncryptionKey = EncryptionKey<K>;
}

impl<K, E> DecryptionKeyType for Hybrid<K, E>
where
    K: key::agreement::Types,
{
    type DecryptionKey = DecryptionKey<K>;
}

impl<K, E> PlaintextType for Hybrid<K, E>
where
    E: PlaintextType,
{
    type Plaintext = E::Plaintext;
}

impl<K, E> RandomnessType for Hybrid<K, E>
where
    K: key::agreement::Types,
    E: RandomnessType,
{
    type Randomness = Randomness<K, E>;
}

impl<K, E> DecryptedPlaintextType for Hybrid<K, E>
where
    E: DecryptedPlaintextType,
{
    type DecryptedPlaintext = E::DecryptedPlaintext;
}

impl<K, E, COM> Derive<COM> for Hybrid<K, E>
where
    K: key::agreement::Derive<COM>,
{
    #[inline]
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut COM,
    ) -> Self::EncryptionKey {
        self.key_agreement_scheme.derive(decryption_key, compiler)
    }
}

impl<K, E, COM> Encrypt<COM> for Hybrid<K, E>
where
    K: key::agreement::Derive<COM> + key::agreement::Agree<COM>,
    E: Encrypt<COM, EncryptionKey = K::SharedSecret>,
{
    #[inline]
    fn encrypt(
        &self,
        encryption_key: &Self::EncryptionKey,
        randomness: &Self::Randomness,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext {
        Ciphertext {
            ephemeral_public_key: self
                .key_agreement_scheme
                .derive(&randomness.ephemeral_secret_key, compiler),
            ciphertext: self.encryption_scheme.encrypt(
                &self.key_agreement_scheme.agree(
                    encryption_key,
                    &randomness.ephemeral_secret_key,
                    compiler,
                ),
                &randomness.randomness,
                header,
                plaintext,
                compiler,
            ),
        }
    }
}

impl<K, E, COM> Decrypt<COM> for Hybrid<K, E>
where
    K: key::agreement::Agree<COM>,
    E: Decrypt<COM, DecryptionKey = K::SharedSecret>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        self.encryption_scheme.decrypt(
            &self.key_agreement_scheme.agree(
                &ciphertext.ephemeral_public_key,
                decryption_key,
                compiler,
            ),
            header,
            &ciphertext.ciphertext,
            compiler,
        )
    }
}

impl<K, E, DK, DE> Sample<(DK, DE)> for Hybrid<K, E>
where
    K: Sample<DK>,
    E: Sample<DE>,
{
    #[inline]
    fn sample<R>(distribution: (DK, DE), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}
