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

use core::{convert::TryFrom, fmt::Debug, hash::Hash};

/// Secret Key Generator Trait
pub trait SecretKeyGenerator {
    /// Secret Key Type
    type SecretKey;

    /// Key Generation Error
    type Error;

    /// Generates a new secret key.
    fn next_key(&mut self) -> Result<Self::SecretKey, Self::Error>;
}

impl<S> SecretKeyGenerator for &mut S
where
    S: SecretKeyGenerator,
{
    type SecretKey = S::SecretKey;

    type Error = S::Error;

    #[inline]
    fn next_key(&mut self) -> Result<Self::SecretKey, Self::Error> {
        (*self).next_key()
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
    /// Builds a new [`Index`] for `kind` and `index`.
    #[inline]
    pub fn new(kind: KeyKind, index: D::Index) -> Self {
        Self { kind, index }
    }

    /// Builds a new [`Index`] for an external key with the given `index`.
    #[inline]
    pub fn new_external(index: D::Index) -> Self {
        Self::new(KeyKind::External, index)
    }

    /// Builds a new [`Index`] for an internal key with the given `index`.
    #[inline]
    pub fn new_internal(index: D::Index) -> Self {
        Self::new(KeyKind::Internal, index)
    }

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

    /// Increments the internal `index`.
    #[inline]
    pub fn increment(&mut self) {
        self.index.increment()
    }

    /// Gets the underlying key for this `index` at the `account`.
    #[inline]
    pub fn key(&self, source: &D, account: &D::Account) -> Result<D::SecretKey, D::Error> {
        source.generate_key(self.kind, account, &self.index)
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
    /// Value Owned by the Key
    pub value: T,

    /// Key Index
    pub index: Index<D>,
}

impl<D, T> KeyOwned<D, T>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a new [`KeyOwned`] for `value` with `index` as the [`Index`].
    #[inline]
    pub fn new(value: T, index: Index<D>) -> Self {
        Self { value, index }
    }

    /// Builds a new [`KeyOwned`] for `value` with `kind` and `index` as the [`Index`].
    #[inline]
    pub fn with_kind(value: T, kind: KeyKind, index: D::Index) -> Self {
        Self::new(value, Index::new(kind, index))
    }

    /// Builds a new [`KeyOwned`] for `value` for an external key with `index`.
    #[inline]
    pub fn new_external(value: T, index: D::Index) -> Self {
        Self::new(value, Index::new_external(index))
    }

    /// Builds a new [`KeyOwned`] for `value` for an internal key with `index`.
    #[inline]
    pub fn new_internal(value: T, index: D::Index) -> Self {
        Self::new(value, Index::new_internal(index))
    }

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

    /// Returns the inner [`self.value`] dropping the [`self.index`].
    #[inline]
    pub fn unwrap(self) -> T {
        self.value
    }

    /// Maps the underlying value using `f`.
    #[inline]
    pub fn map<U, F>(self, f: F) -> KeyOwned<D, U>
    where
        F: FnOnce(T) -> U,
    {
        KeyOwned::new(f(self.value), self.index)
    }

    /// Maps the underlying value using `f` and then factors over the `Some` branch.
    #[inline]
    pub fn map_some<U, F>(self, f: F) -> Option<KeyOwned<D, U>>
    where
        F: FnOnce(T) -> Option<U>,
    {
        self.map(f).collect()
    }

    /// Maps the underlying value using `f` and then factors over the `Ok` branch.
    #[inline]
    pub fn map_ok<U, E, F>(self, f: F) -> Result<KeyOwned<D, U>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        self.map(f).collect()
    }
}

impl<D, T> AsRef<T> for KeyOwned<D, T>
where
    D: DerivedSecretKeyGenerator,
{
    #[inline]
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<D, T> AsMut<T> for KeyOwned<D, T>
where
    D: DerivedSecretKeyGenerator,
{
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<D, T> From<KeyOwned<D, T>> for (T, Index<D>)
where
    D: DerivedSecretKeyGenerator,
{
    #[inline]
    fn from(key_owned: KeyOwned<D, T>) -> Self {
        (key_owned.value, key_owned.index)
    }
}

impl<D, L, R> KeyOwned<D, (L, R)>
where
    D: DerivedSecretKeyGenerator,
{
    /// Factors the key index over the left value in the pair.
    #[inline]
    pub fn left(self) -> (KeyOwned<D, L>, R) {
        (KeyOwned::new(self.value.0, self.index), self.value.1)
    }

    /// Factors the key index over the right value in the pair.
    #[inline]
    pub fn right(self) -> (L, KeyOwned<D, R>) {
        (self.value.0, KeyOwned::new(self.value.1, self.index))
    }
}

impl<D, T> KeyOwned<D, Option<T>>
where
    D: DerivedSecretKeyGenerator,
{
    /// Converts a `KeyOwned<D, Option<T>>` into an `Option<KeyOwned<D, T>>`.
    #[inline]
    pub fn collect(self) -> Option<KeyOwned<D, T>> {
        Some(KeyOwned::new(self.value?, self.index))
    }
}

impl<D, T> From<KeyOwned<D, Option<T>>> for Option<KeyOwned<D, T>>
where
    D: DerivedSecretKeyGenerator,
{
    #[inline]
    fn from(key_owned: KeyOwned<D, Option<T>>) -> Self {
        key_owned.collect()
    }
}

impl<D, T, E> KeyOwned<D, Result<T, E>>
where
    D: DerivedSecretKeyGenerator,
{
    /// Converts a `KeyOwned<D, Result<T, E>>` into an `Result<KeyOwned<D, T>, E>`.
    #[inline]
    pub fn collect(self) -> Result<KeyOwned<D, T>, E> {
        Ok(KeyOwned::new(self.value?, self.index))
    }

    /// Converts a `KeyOwned<D, Result<T, E>>` into an `Option<KeyOwned<D, T>>`.
    #[inline]
    pub fn ok(self) -> Option<KeyOwned<D, T>> {
        self.collect().ok()
    }
}

impl<D, T, E> From<KeyOwned<D, Result<T, E>>> for Result<KeyOwned<D, T>, E>
where
    D: DerivedSecretKeyGenerator,
{
    #[inline]
    fn from(key_owned: KeyOwned<D, Result<T, E>>) -> Self {
        key_owned.collect()
    }
}

impl<D, T, E> TryFrom<KeyOwned<D, Result<T, E>>> for KeyOwned<D, T>
where
    D: DerivedSecretKeyGenerator,
{
    type Error = E;

    #[inline]
    fn try_from(key_owned: KeyOwned<D, Result<T, E>>) -> Result<Self, Self::Error> {
        key_owned.collect()
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
) -> Result<SecretKey<D>, D::Error>
where
    D: DerivedSecretKeyGenerator,
{
    let secret_key = SecretKey::with_kind(
        source.generate_key(kind, account, index)?,
        kind,
        index.clone(),
    );
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
) -> Result<SecretKey<D>, D::Error>
where
    D: DerivedSecretKeyGenerator,
{
    let secret_key =
        SecretKey::new_external(source.generate_external_key(account, index)?, index.clone());
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
) -> Result<SecretKey<D>, D::Error>
where
    D: DerivedSecretKeyGenerator,
{
    let secret_key =
        SecretKey::new_internal(source.generate_internal_key(account, index)?, index.clone());
    index.increment();
    Ok(secret_key)
}

/// Keys
struct Keys<'d, D>
where
    D: DerivedSecretKeyGenerator,
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
    D: DerivedSecretKeyGenerator,
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
    fn generate_external_key(&mut self) -> Result<SecretKey<D>, D::Error> {
        next_external(self.derived_key_generator, self.account, &mut self.index)
    }

    /// Generates an internal secret key according to the [`DerivedSecretKeyGenerator`] protocol
    /// and increments the running `self.index`.
    #[inline]
    fn generate_internal_key(&mut self) -> Result<SecretKey<D>, D::Error> {
        next_internal(self.derived_key_generator, self.account, &mut self.index)
    }
}

/// External Keys
pub struct ExternalKeys<'d, D>(Keys<'d, D>)
where
    D: DerivedSecretKeyGenerator;

impl<'d, D> ExternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator,
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
    D: DerivedSecretKeyGenerator,
{
    type SecretKey = SecretKey<D>;

    type Error = D::Error;

    #[inline]
    fn next_key(&mut self) -> Result<Self::SecretKey, Self::Error> {
        self.0.generate_external_key()
    }
}

impl<'d, D> Iterator for ExternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator,
{
    type Item = Result<SecretKey<D>, D::Error>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_key())
    }
}

/// Internal Keys
pub struct InternalKeys<'d, D>(Keys<'d, D>)
where
    D: DerivedSecretKeyGenerator;

impl<'d, D> InternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator,
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
    D: DerivedSecretKeyGenerator,
{
    type SecretKey = SecretKey<D>;

    type Error = D::Error;

    #[inline]
    fn next_key(&mut self) -> Result<Self::SecretKey, Self::Error> {
        self.0.generate_internal_key()
    }
}

impl<'d, D> Iterator for InternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator,
{
    type Item = Result<SecretKey<D>, D::Error>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_key())
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

    /// Returns the next [`Account`] after `self`.
    #[inline]
    pub fn next(mut self) -> Self {
        self.account.increment();
        Self::new(self.account)
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
    pub fn key(&self, source: &D, kind: KeyKind) -> Result<SecretKey<D>, D::Error> {
        match kind {
            KeyKind::External => self.external_key(source),
            KeyKind::Internal => self.internal_key(source),
        }
    }

    /// Generates a new external key for this account.
    #[inline]
    pub fn external_key(&self, source: &D) -> Result<SecretKey<D>, D::Error> {
        Ok(SecretKey::new_external(
            source.generate_external_key(&self.account, &self.external_index)?,
            self.external_index.clone(),
        ))
    }

    /// Generates a new internal key for this account.
    #[inline]
    pub fn internal_key(&self, source: &D) -> Result<SecretKey<D>, D::Error> {
        Ok(SecretKey::new_internal(
            source.generate_internal_key(&self.account, &self.internal_index)?,
            self.internal_index.clone(),
        ))
    }

    /// Generates the next key of the given `kind` for this account, incrementing the
    /// appropriate index.
    #[inline]
    pub fn next_key(&mut self, source: &D, kind: KeyKind) -> Result<SecretKey<D>, D::Error> {
        match kind {
            KeyKind::External => self.next_external_key(source),
            KeyKind::Internal => self.next_internal_key(source),
        }
    }

    /// Generates the next external key for this account, incrementing the `external_index`.
    #[inline]
    pub fn next_external_key(&mut self, source: &D) -> Result<SecretKey<D>, D::Error> {
        next_external(source, &self.account, &mut self.external_index)
    }

    /// Generates the next internal key for this account, incrementing the `internal_index`.
    #[inline]
    pub fn next_internal_key(&mut self, source: &D) -> Result<SecretKey<D>, D::Error> {
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
        ExternalKeys::from_index(source, &self.account, index)
    }

    /// Returns an [`InternalKeys`] generator starting from the given `index`.
    #[inline]
    pub fn internal_keys_from_index<'s>(
        &'s self,
        source: &'s D,
        index: D::Index,
    ) -> InternalKeys<'s, D> {
        InternalKeys::from_index(source, &self.account, index)
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
