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

//! Address Scheme

// TODO: Implement a more general "view key" system, for arbitrarily-many view keys.

use core::marker::PhantomData;
use manta_crypto::{
    encryption::{DecryptedMessage, EncryptedMessage, HybridPublicKeyEncryptionScheme},
    key::KeyAgreementScheme,
};
use manta_util::{create_seal, seal};

create_seal! {}

/// Key Type Marker Trait
///
/// This trait identifies a key type for [`SecretKey`] and [`PublicKey`]. This trait is sealed and
/// can only be used with the existing implementations.
pub trait KeyType: sealed::Sealed {
    /// Spending capability for this key type.
    const IS_SPEND: bool;
}

/// Implements the [`KeyType`] trait on the type with the given `$name`.
macro_rules! impl_key_type {
    ($name:ty, $is_spend:expr) => {
        seal!($name);
        impl KeyType for $name {
            const IS_SPEND: bool = $is_spend;
        }
    };
}

/// Spend Key Type
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd)]
pub struct Spend;

impl_key_type!(Spend, true);

/// View Key Type
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd)]
pub struct View;

impl_key_type!(View, false);

/// Secret Spend Key Type
pub type SecretSpendKey<K> = SecretKey<K, Spend>;

/// Public Spend Key Type
pub type PublicSpendKey<K> = PublicKey<K, Spend>;

/// Secret View Key Type
pub type SecretViewKey<K> = SecretKey<K, View>;

/// Public View Key Type
pub type PublicViewKey<K> = PublicKey<K, View>;

/// Secret Key
pub struct SecretKey<K, T>
where
    K: KeyAgreementScheme,
    T: KeyType,
{
    /// Secret Key
    secret_key: K::SecretKey,

    /// Type Parameter Marker
    __: PhantomData<T>,
}

impl<K, T> SecretKey<K, T>
where
    K: KeyAgreementScheme,
    T: KeyType,
{
    /// Builds a new [`SecretKey`] from `secret_key`.
    #[inline]
    pub fn new(secret_key: K::SecretKey) -> Self {
        Self {
            secret_key,
            __: PhantomData,
        }
    }

    /// Derives the corresponding [`PublicKey`] of the same [`KeyType`] as `self`, from a borrowed
    /// value.
    #[inline]
    pub fn derive(&self) -> PublicKey<K, T> {
        PublicKey::new(K::derive(&self.secret_key))
    }

    /// Derives the corresponding [`PublicKey`] of the same [`KeyType`] as `self`, from an owned
    /// value.
    #[inline]
    pub fn derive_owned(self) -> PublicKey<K, T> {
        PublicKey::new(K::derive_owned(self.secret_key))
    }
}

impl<K> SecretSpendKey<K>
where
    K: KeyAgreementScheme,
{
    /// Generates the spending secret associated to `self` and the `ephemeral_public_key`.
    #[inline]
    pub fn spending_secret(&self, ephemeral_public_key: &K::PublicKey) -> K::SharedSecret {
        K::agree(&self.secret_key, ephemeral_public_key)
    }
}

impl<H> SecretViewKey<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Decrypts `message` using `self`.
    ///
    /// This method uses the [`decrypt`](EncryptedMessage::decrypt) method of [`EncryptedMessage`].
    /// See its documentation for more.
    #[inline]
    pub fn decrypt(
        &self,
        message: EncryptedMessage<H>,
    ) -> Result<DecryptedMessage<H>, EncryptedMessage<H>> {
        message.decrypt(&self.secret_key)
    }
}

/// Public Key
pub struct PublicKey<K, T>
where
    K: KeyAgreementScheme,
    T: KeyType,
{
    /// Public Key
    public_key: K::PublicKey,

    /// Type Parameter Marker
    __: PhantomData<T>,
}

impl<K, T> PublicKey<K, T>
where
    K: KeyAgreementScheme,
    T: KeyType,
{
    /// Builds a new [`PublicKey`] from `public_key`.
    ///
    /// # Implementation Note
    ///
    /// This method is intentionally private, since these keys should only be constructed by some
    /// call to the appropriate `derive` method.
    #[inline]
    fn new(public_key: K::PublicKey) -> Self {
        Self {
            public_key,
            __: PhantomData,
        }
    }
}

impl<K> PublicSpendKey<K>
where
    K: KeyAgreementScheme,
{
    /// Generates the spending secret associated to `self` and the `ephemeral_secret_key`.
    #[inline]
    pub fn spending_secret(&self, ephemeral_secret_key: &K::SecretKey) -> K::SharedSecret {
        K::agree(ephemeral_secret_key, &self.public_key)
    }
}

impl<H> PublicViewKey<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Encrypts `plaintext` using `self` and `ephemeral_secret_key`.
    ///
    /// This method uses the [`new`](EncryptedMessage::new) method of [`EncryptedMessage`].
    /// See its documentation for more.
    #[inline]
    pub fn encrypt(
        &self,
        ephemeral_secret_key: H::SecretKey,
        plaintext: H::Plaintext,
    ) -> EncryptedMessage<H> {
        EncryptedMessage::new(&self.public_key, ephemeral_secret_key, plaintext)
    }
}

/// Spending Key
pub struct SpendingKey<K>
where
    K: KeyAgreementScheme,
{
    /// Spend Part of the Spending Key
    spend: SecretSpendKey<K>,

    /// View Part of the Spending Key
    view: SecretViewKey<K>,
}

impl<K> SpendingKey<K>
where
    K: KeyAgreementScheme,
{
    /// Builds a new [`SpendingKey`] from `spend` and `view`.
    #[inline]
    pub fn new(spend: SecretSpendKey<K>, view: SecretViewKey<K>) -> Self {
        Self { spend, view }
    }

    /// Returns the [`SecretViewKey`] component of `self`.
    #[inline]
    pub fn viewing_key(&self) -> &SecretViewKey<K> {
        &self.view
    }

    /// Returns the [`ReceivingKey`] corresponding to `self`.
    #[inline]
    pub fn receiving_key(&self) -> ReceivingKey<K> {
        ReceivingKey::new(self.spend.derive(), self.view.derive())
    }

    /// Converts `self` into its corresponding [`ReceivingKey`].
    #[inline]
    pub fn into_receiving_key(self) -> ReceivingKey<K> {
        ReceivingKey::new(self.spend.derive_owned(), self.view.derive_owned())
    }

    /// Generates the spending secret associated to `self` and the `ephemeral_public_key`.
    #[inline]
    pub fn spending_secret(&self, ephemeral_public_key: &K::PublicKey) -> K::SharedSecret {
        self.spend.spending_secret(ephemeral_public_key)
    }
}

impl<H> SpendingKey<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Decrypts `message` using `self`.
    ///
    /// This method uses the [`decrypt`](EncryptedMessage::decrypt) method of [`EncryptedMessage`].
    /// See its documentation for more.
    #[inline]
    pub fn decrypt(
        &self,
        message: EncryptedMessage<H>,
    ) -> Result<DecryptedMessage<H>, EncryptedMessage<H>> {
        self.view.decrypt(message)
    }
}

/// Receiving Key
pub struct ReceivingKey<K>
where
    K: KeyAgreementScheme,
{
    /// Spend Part of the Receiving Key
    spend: PublicSpendKey<K>,

    /// View Part of the Receiving Key
    view: PublicViewKey<K>,
}

impl<K> ReceivingKey<K>
where
    K: KeyAgreementScheme,
{
    /// Builds a new [`ReceivingKey`] from `spend` and `view`.
    ///
    /// # Implementation Note
    ///
    /// This method is intentionally private, since these keys should only be constructed by some
    /// call to the appropriate `derive` method.
    #[inline]
    fn new(spend: PublicSpendKey<K>, view: PublicViewKey<K>) -> Self {
        Self { spend, view }
    }

    /// Returns the [`PublicViewKey`] component of `self`.
    #[inline]
    pub fn viewing_key(&self) -> &PublicViewKey<K> {
        &self.view
    }

    /// Generates the spending secret associated to `self` and the `ephemeral_secret_key`.
    #[inline]
    pub fn spending_secret(&self, ephemeral_secret_key: &K::SecretKey) -> K::SharedSecret {
        self.spend.spending_secret(ephemeral_secret_key)
    }
}

impl<H> ReceivingKey<H>
where
    H: HybridPublicKeyEncryptionScheme,
{
    /// Encrypts `plaintext` using `self` and `ephemeral_secret_key`.
    ///
    /// This method uses the [`new`](EncryptedMessage::new) method of [`EncryptedMessage`].
    /// See its documentation for more.
    #[inline]
    pub fn encrypt(
        &self,
        ephemeral_secret_key: H::SecretKey,
        plaintext: H::Plaintext,
    ) -> EncryptedMessage<H> {
        self.view.encrypt(ephemeral_secret_key, plaintext)
    }
}
