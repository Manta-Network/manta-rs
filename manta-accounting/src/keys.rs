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

//! Secret Key Generation Primitives

// NOTE: These interfaces are based on BIP-0044. See the specification here:
//         https://raw.githubusercontent.com/bitcoin/bips/master/bip-0044.mediawiki

// TODO: Check to make sure we conform to the specification and then make a note about it in the
//       module documentation, and add a link to the specification.

/// Secret Key Generator Trait
pub trait SecretKeyGenerator {
    /// Secret Key Type
    type SecretKey;

    /// Key Generation Error
    type Error;

    /// Generates a new secret key.
    fn generate_key(&mut self) -> Result<Self::SecretKey, Self::Error>;
}

/// Derived Secret Key Parameter
pub trait DerivedSecretKeyParameter: Default {
    /// Increments the key parameter by one unit.
    fn increment(&mut self);
}

/// Derived Secret Key Generator
pub trait DerivedSecretKeyGenerator {
    /// Secret Key Type
    type SecretKey;

    /// Account Type
    type Account: DerivedSecretKeyParameter;

    /// Index Type
    type Index: DerivedSecretKeyParameter;

    /// Key Generation Error
    type Error;

    /// Generates a new secret key determined by `is_external` for the `account` with
    /// the given `index`.
    fn generate_key(
        &self,
        is_external: bool,
        account: &Self::Account,
        index: &Self::Index,
    ) -> Result<Self::SecretKey, Self::Error>;

    /// Builds a [`SecretKeyGenerator`] for external keys associated to `account`.
    #[inline]
    fn external_keys<'s>(&'s self, account: &'s Self::Account) -> ExternalKeys<'s, Self> {
        ExternalKeys::new(self, account)
    }

    /// Builds a [`SecretKeyGenerator`] for internal keys associated to `account`.
    #[inline]
    fn internal_keys<'s>(&'s self, account: &'s Self::Account) -> InternalKeys<'s, Self> {
        InternalKeys::new(self, account)
    }
}

/// Keys
struct Keys<'d, D>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    /// Derived Key Generator
    derived_key_generator: &'d D,

    /// Key Account
    account: &'d D::Account,

    /// Current Index
    index: D::Index,
}

impl<'d, D> Keys<'d, D>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    /// Builds a new [`Keys`] generator from a [`DerivedSecretKeyGenerator`] and an `account`.
    #[inline]
    fn new(derived_key_generator: &'d D, account: &'d D::Account) -> Self {
        Self {
            derived_key_generator,
            account,
            index: Default::default(),
        }
    }

    /// Generates a secret key according to the [`DerivedSecretKeyGenerator`] protocol and
    /// increments the running `self.index`.
    #[inline]
    fn generate_key(&mut self, is_external: bool) -> Result<D::SecretKey, D::Error> {
        let secret_key =
            self.derived_key_generator
                .generate_key(is_external, self.account, &self.index)?;
        self.index.increment();
        Ok(secret_key)
    }

    /// Generates an external secret key according to the [`DerivedSecretKeyGenerator`] protocol
    /// and increments the running `self.index`.
    #[inline]
    fn generate_external_key(&mut self) -> Result<D::SecretKey, D::Error> {
        self.generate_key(true)
    }

    /// Generates an internal secret key according to the [`DerivedSecretKeyGenerator`] protocol
    /// and increments the running `self.index`.
    #[inline]
    fn generate_internal_key(&mut self) -> Result<D::SecretKey, D::Error> {
        self.generate_key(false)
    }
}

/// External Keys
pub struct ExternalKeys<'d, D>(Keys<'d, D>)
where
    D: DerivedSecretKeyGenerator + ?Sized;

impl<'d, D> ExternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    /// Builds a new [`ExternalKeys`] generator for `account` from a `source`.
    #[inline]
    pub fn new(source: &'d D, account: &'d D::Account) -> Self {
        Self(Keys::new(source, account))
    }
}

impl<'d, D> SecretKeyGenerator for ExternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    type SecretKey = D::SecretKey;

    type Error = D::Error;

    #[inline]
    fn generate_key(&mut self) -> Result<Self::SecretKey, Self::Error> {
        self.0.generate_external_key()
    }
}

impl<'d, D> Iterator for ExternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    type Item = D::SecretKey;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.generate_key().ok()
    }
}

/// Internal Keys
pub struct InternalKeys<'d, D>(Keys<'d, D>)
where
    D: DerivedSecretKeyGenerator + ?Sized;

impl<'d, D> InternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    /// Builds a new [`InternalKeys`] generator for `account` from a `source`.
    #[inline]
    pub fn new(source: &'d D, account: &'d D::Account) -> Self {
        Self(Keys::new(source, account))
    }
}

impl<'d, D> SecretKeyGenerator for InternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    type SecretKey = D::SecretKey;

    type Error = D::Error;

    #[inline]
    fn generate_key(&mut self) -> Result<Self::SecretKey, Self::Error> {
        self.0.generate_internal_key()
    }
}

impl<'d, D> Iterator for InternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    type Item = D::SecretKey;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.generate_key().ok()
    }
}
