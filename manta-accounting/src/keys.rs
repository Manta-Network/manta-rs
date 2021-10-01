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
// TODO: How many of these interfaces should actually return `SecretKey<D>` instead of
//       `D::SecretKey`?

use core::{fmt::Debug, hash::Hash};

/// Secret Key Generator Trait
pub trait SecretKeyGenerator {
    /// Secret Key Type
    type SecretKey;

    /// Key Generation Error
    type Error;

    /// Generates a new secret key.
    fn generate_key(&mut self) -> Result<Self::SecretKey, Self::Error>;
}

impl<S> SecretKeyGenerator for &mut S
where
    S: SecretKeyGenerator,
{
    type SecretKey = S::SecretKey;

    type Error = S::Error;

    #[inline]
    fn generate_key(&mut self) -> Result<Self::SecretKey, Self::Error> {
        (*self).generate_key()
    }
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

    /// Generates a new secret key determined by `kind` for the `account` with
    /// the given `index`.
    fn generate_key(
        &self,
        kind: KeyKind,
        account: &Self::Account,
        index: &Self::Index,
    ) -> Result<Self::SecretKey, Self::Error>;

    /// Generates a new external secret key for the `account` with the given `index`.
    #[inline]
    fn generate_external_key(
        &self,
        account: &Self::Account,
        index: &Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        self.generate_key(KeyKind::External, account, index)
    }

    /// Generates a new internal secret key for the `account` with the given `index`.
    #[inline]
    fn generate_internal_key(
        &self,
        account: &Self::Account,
        index: &Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        self.generate_key(KeyKind::Internal, account, index)
    }

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

impl<D> DerivedSecretKeyGenerator for &D
where
    D: DerivedSecretKeyGenerator,
{
    type SecretKey = D::SecretKey;

    type Account = D::Account;

    type Index = D::Index;

    type Error = D::Error;

    #[inline]
    fn generate_key(
        &self,
        kind: KeyKind,
        account: &Self::Account,
        index: &Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).generate_key(kind, account, index)
    }

    #[inline]
    fn generate_external_key(
        &self,
        account: &Self::Account,
        index: &Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).generate_external_key(account, index)
    }

    #[inline]
    fn generate_internal_key(
        &self,
        account: &Self::Account,
        index: &Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).generate_internal_key(account, index)
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

/// Key Index
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = "D::Index: Copy"),
    Debug(bound = "D::Index: Debug"),
    Eq(bound = "D::Index: Eq"),
    Hash(bound = "D::Index: Hash"),
    PartialEq(bound = "D::Index: PartialEq")
)]
pub struct Index<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Key Kind
    pub kind: KeyKind,

    /// Key Index
    pub index: D::Index,
}

impl<D> Index<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Returns `true` if `self` represents an external key.
    #[inline]
    pub fn is_external(&self) -> bool {
        self.kind.is_external()
    }

    /// Returns `true` if `self` represents an internal key.
    #[inline]
    pub fn is_internal(&self) -> bool {
        self.kind.is_internal()
    }
}

/// Labelled Secret Key Type
pub type SecretKey<D> = KeyOwned<D, <D as DerivedSecretKeyGenerator>::SecretKey>;

/// Key-Owned Value
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    Copy(bound = "D::Index: Copy, T: Copy"),
    Debug(bound = "D::Index: Debug, T: Debug"),
    Eq(bound = "D::Index: Eq, T: Eq"),
    Hash(bound = "D::Index: Hash, T: Hash"),
    PartialEq(bound = "D::Index: PartialEq, T: PartialEq")
)]
pub struct KeyOwned<D, T>
where
    D: DerivedSecretKeyGenerator,
{
    /// Key Index
    pub index: Index<D>,

    /// Value Owned by the Key
    pub value: T,
}

impl<D, T> KeyOwned<D, T>
where
    D: DerivedSecretKeyGenerator,
{
    /// Returns `true` if `self` represents a value owned by an external key.
    #[inline]
    pub fn is_external(&self) -> bool {
        self.index.is_external()
    }

    /// Returns `true` if `self` represents a value owned by an internal key.
    #[inline]
    pub fn is_internal(&self) -> bool {
        self.index.is_internal()
    }
}

/// Generates an external or internal secret key according to the [`DerivedSecretKeyGenerator`]
/// protocol and increments the running `index`.
#[inline]
pub fn next_key<D>(
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
    let secret_key = source.generate_external_key(account, index)?;
    index.increment();
    Ok(secret_key)
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
    let secret_key = source.generate_internal_key(account, index)?;
    index.increment();
    Ok(secret_key)
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

/// Account Index Manager
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = "D::Account: Copy, D::Index: Copy"),
    Debug(bound = "D::Account: Debug, D::Index: Debug"),
    Default(bound = ""),
    Eq(bound = "D::Account: Eq, D::Index: Eq"),
    Hash(bound = "D::Account: Hash, D::Index: Hash"),
    PartialEq(bound = "D::Account: PartialEq, D::Index: PartialEq")
)]
pub struct Account<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Account Identifier
    pub account: D::Account,

    /// External Transaction Running Index
    pub external_index: D::Index,

    /// Internal Transaction Running Index
    pub internal_index: D::Index,
}

impl<D> Account<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a new [`Account`] for the given `account` identifier.
    #[inline]
    pub fn new(account: D::Account) -> Self {
        Self::with_indices(account, Default::default(), Default::default())
    }

    /// Builds a new [`Account`] for the given `account` identifier with starting indices
    /// `external_index` and `internal_index`.
    #[inline]
    pub fn with_indices(
        account: D::Account,
        external_index: D::Index,
        internal_index: D::Index,
    ) -> Self {
        Self {
            account,
            external_index,
            internal_index,
        }
    }

    /// Returns the next [`Account`] after `this`.
    #[inline]
    pub fn next(this: &Self) -> Self {
        let mut next_account = this.account.clone();
        next_account.increment();
        Self::new(next_account)
    }

    /// Resets the external and internal running indices to their default values.
    #[inline]
    pub fn reset(&mut self) -> &mut Self {
        self.external_index = Default::default();
        self.internal_index = Default::default();
        self
    }

    /// Generates a new key of the given `kind` for this account.
    #[inline]
    pub fn key(&self, source: &D, kind: KeyKind) -> Result<D::SecretKey, D::Error> {
        match kind {
            KeyKind::External => self.external_key(source),
            KeyKind::Internal => self.internal_key(source),
        }
    }

    /// Generates a new external key for this account.
    #[inline]
    pub fn external_key(&self, source: &D) -> Result<D::SecretKey, D::Error> {
        source.generate_external_key(&self.account, &self.external_index)
    }

    /// Generates a new internal key for this account.
    #[inline]
    pub fn internal_key(&self, source: &D) -> Result<D::SecretKey, D::Error> {
        source.generate_internal_key(&self.account, &self.internal_index)
    }

    /// Generates the next key of the given `kind` for this account, incrementing the
    /// appropriate index.
    #[inline]
    pub fn next_key(&mut self, source: &D, kind: KeyKind) -> Result<D::SecretKey, D::Error> {
        match kind {
            KeyKind::External => self.next_external_key(source),
            KeyKind::Internal => self.next_internal_key(source),
        }
    }

    /// Generates the next external key for this account, incrementing the `external_index`.
    #[inline]
    pub fn next_external_key(&mut self, source: &D) -> Result<D::SecretKey, D::Error> {
        next_external(source, &self.account, &mut self.external_index)
    }

    /// Generates the next internal key for this account, incrementing the `internal_index`.
    #[inline]
    pub fn next_internal_key(&mut self, source: &D) -> Result<D::SecretKey, D::Error> {
        next_internal(source, &self.account, &mut self.internal_index)
    }

    /// Returns an [`ExternalKeys`] generator starting from the current external index.
    #[inline]
    pub fn external_keys<'s>(&'s self, source: &'s D) -> ExternalKeys<'s, D> {
        self.external_keys_from_index(source, self.external_index.clone())
    }

    /// Returns an [`InternalKeys`] generator starting from the current internal index.
    #[inline]
    pub fn internal_keys<'s>(&'s self, source: &'s D) -> InternalKeys<'s, D> {
        self.internal_keys_from_index(source, self.internal_index.clone())
    }

    /// Returns an [`ExternalKeys`] generator starting from the given `index`.
    #[inline]
    pub fn external_keys_from_index<'s>(
        &'s self,
        source: &'s D,
        index: D::Index,
    ) -> ExternalKeys<'s, D> {
        source.external_keys_from_index(&self.account, index)
    }

    /// Returns an [`InternalKeys`] generator starting from the given `index`.
    #[inline]
    pub fn internal_keys_from_index<'s>(
        &'s self,
        source: &'s D,
        index: D::Index,
    ) -> InternalKeys<'s, D> {
        source.internal_keys_from_index(&self.account, index)
    }
}

impl<D> AsRef<D::Account> for Account<D>
where
    D: DerivedSecretKeyGenerator,
{
    #[inline]
    fn as_ref(&self) -> &D::Account {
        &self.account
    }
}
