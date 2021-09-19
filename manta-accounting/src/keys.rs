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
pub trait DerivedSecretKeyParameter: Clone + Default {
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
        kind: KeyKind,
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

    /// Builds a [`SecretKeyGenerator`] for external keys associated to `account`, starting
    /// from `index`.
    #[inline]
    fn external_keys_from_index<'s>(
        &'s self,
        account: &'s Self::Account,
        index: Self::Index,
    ) -> ExternalKeys<'s, Self> {
        ExternalKeys::from_index(self, account, index)
    }

    /// Builds a [`SecretKeyGenerator`] for internal keys associated to `account`, starting
    /// from `index`.
    #[inline]
    fn internal_keys_from_index<'s>(
        &'s self,
        account: &'s Self::Account,
        index: Self::Index,
    ) -> InternalKeys<'s, Self> {
        InternalKeys::from_index(self, account, index)
    }
}

/// Key Kind
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyKind {
    /// External Key
    External,

    /// Internal Key
    Internal,
}

impl KeyKind {
    /// Returns `true` if `self` matches [`External`](Self::External).
    #[inline]
    pub const fn is_external(&self) -> bool {
        matches!(self, Self::External)
    }

    /// Returns `true` if `self` matches [`Internal`](Self::Internal).
    #[inline]
    pub const fn is_internal(&self) -> bool {
        matches!(self, Self::Internal)
    }
}

/// Generates an internal or external secret key according to the [`DerivedSecretKeyGenerator`]
/// protocol and increments the running `index`.
#[inline]
fn next_key<D>(
    source: &D,
    kind: KeyKind,
    account: &D::Account,
    index: &mut D::Index,
) -> Result<D::SecretKey, D::Error>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    let secret_key = source.generate_key(kind, account, index)?;
    index.increment();
    Ok(secret_key)
}

/// Generates an external secret key according to the [`DerivedSecretKeyGenerator`] protocol
/// and increments the running `index`.
#[inline]
pub fn next_external<D>(
    source: &D,
    account: &D::Account,
    index: &mut D::Index,
) -> Result<D::SecretKey, D::Error>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    next_key(source, KeyKind::External, account, index)
}

/// Generates an internal secret key according to the [`DerivedSecretKeyGenerator`] protocol
/// and increments the running `index`.
#[inline]
pub fn next_internal<D>(
    source: &D,
    account: &D::Account,
    index: &mut D::Index,
) -> Result<D::SecretKey, D::Error>
where
    D: DerivedSecretKeyGenerator + ?Sized,
{
    next_key(source, KeyKind::Internal, account, index)
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
        Self::from_index(derived_key_generator, account, Default::default())
    }

    /// Builds a new [`Keys`] generator from a [`DerivedSecretKeyGenerator`] and an `account`,
    /// starting at `index`.
    #[inline]
    fn from_index(derived_key_generator: &'d D, account: &'d D::Account, index: D::Index) -> Self {
        Self {
            derived_key_generator,
            account,
            index,
        }
    }

    /// Generates an external secret key according to the [`DerivedSecretKeyGenerator`] protocol
    /// and increments the running `self.index`.
    #[inline]
    fn generate_external_key(&mut self) -> Result<D::SecretKey, D::Error> {
        next_external(self.derived_key_generator, self.account, &mut self.index)
    }

    /// Generates an internal secret key according to the [`DerivedSecretKeyGenerator`] protocol
    /// and increments the running `self.index`.
    #[inline]
    fn generate_internal_key(&mut self) -> Result<D::SecretKey, D::Error> {
        next_internal(self.derived_key_generator, self.account, &mut self.index)
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

    /// Builds a new [`ExternalKeys`] generator for `account` from a `source`, starting at `index`.
    #[inline]
    pub fn from_index(source: &'d D, account: &'d D::Account, index: D::Index) -> Self {
        Self(Keys::from_index(source, account, index))
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

    /// Builds a new [`InternalKeys`] generator for `account` from a `source`, starting at `index`.
    #[inline]
    pub fn from_index(source: &'d D, account: &'d D::Account, index: D::Index) -> Self {
        Self(Keys::from_index(source, account, index))
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
