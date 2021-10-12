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
// TODO: Try to get rid of `KeyOwned` if possible, or at least minimize its use.

use core::{convert::TryFrom, fmt::Debug, hash::Hash, ops::Range};

/// Derived Secret Key Parameter
pub trait DerivedSecretKeyParameter: Clone + Default + PartialOrd {
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

/// External Key Kind
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct External;

impl From<External> for KeyKind {
    #[inline]
    fn from(kind: External) -> Self {
        let _ = kind;
        Self::External
    }
}

/// Internal Key Kind
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Internal;

impl From<Internal> for KeyKind {
    #[inline]
    fn from(kind: Internal) -> Self {
        let _ = kind;
        Self::Internal
    }
}

/// External Secret Key Index Type
pub type ExternalIndex<D> = Index<D, External>;

/// Internal Secret Key Index Type
pub type InternalIndex<D> = Index<D, Internal>;

/// Secret Key Index
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "K: Clone"),
    Copy(bound = "K: Copy, D::Index: Copy"),
    Debug(bound = "K: Debug, D::Index: Debug"),
    Eq(bound = "K: Eq, D::Index: Eq"),
    Hash(bound = "K: Hash, D::Index: Hash"),
    PartialEq(bound = "K: PartialEq")
)]
pub struct Index<D, K = KeyKind>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    /// Key Kind
    pub kind: K,

    /// Key Index
    pub index: D::Index,
}

impl<D, K> Index<D, K>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    /// Builds a new [`Index`] for `kind` and `index`.
    #[inline]
    pub fn new(kind: K, index: D::Index) -> Self {
        Self { kind, index }
    }

    /// Increments the internal `index`.
    #[inline]
    pub fn increment(&mut self) {
        self.index.increment()
    }

    /// Reduces `self` into an [`Index`] with [`KeyKind`] as the key kind.
    #[inline]
    pub fn reduce(self) -> Index<D> {
        Index::new(self.kind.into(), self.index)
    }

    /// Wraps an `inner` value into a [`KeyOwned`] with `self` as the index.
    #[inline]
    pub fn wrap<T>(self, inner: T) -> KeyOwned<D, T, K> {
        KeyOwned::new(inner, self)
    }
}

impl<D> Index<D>
where
    D: DerivedSecretKeyGenerator,
{
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

    /// Gets the underlying key for this `index` at the `account`.
    #[inline]
    pub fn key(&self, source: &D, account: &D::Account) -> Result<D::SecretKey, D::Error> {
        source.generate_key(self.kind, account, &self.index)
    }
}

impl<D> ExternalIndex<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a new [`Index`] for an external key with the given `index`.
    #[inline]
    pub fn from(index: D::Index) -> Self {
        Self::new(External, index)
    }

    /// Gets the underlying key for this `index` at the `account`.
    #[inline]
    pub fn key(&self, source: &D, account: &D::Account) -> Result<D::SecretKey, D::Error> {
        source.generate_external_key(account, &self.index)
    }
}

impl<D> InternalIndex<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a new [`Index`] for an internal key with the given `index`.
    #[inline]
    pub fn from(index: D::Index) -> Self {
        Self::new(Internal, index)
    }

    /// Gets the underlying key for this `index` at the `account`.
    #[inline]
    pub fn key(&self, source: &D, account: &D::Account) -> Result<D::SecretKey, D::Error> {
        source.generate_internal_key(account, &self.index)
    }
}

/// Labelled Secret Key Type
pub type SecretKey<D, K = KeyKind> = KeyOwned<D, <D as DerivedSecretKeyGenerator>::SecretKey, K>;

/// Labelled External Secret Key Type
pub type ExternalSecretKey<D> = SecretKey<D, External>;

/// Labelled Internal Secret Key Type
pub type InternalSecretKey<D> = SecretKey<D, Internal>;

/// External Key-Owned Value Type
pub type ExternalKeyOwned<D, T> = KeyOwned<D, T, External>;

/// Internal Key-Owned Value Type
pub type InternalKeyOwned<D, T> = KeyOwned<D, T, Internal>;

/// Key-Owned Value
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T: Clone, K: Clone"),
    Copy(bound = "D::Index: Copy, T: Copy, K: Copy"),
    Debug(bound = "D::Index: Debug, T: Debug, K: Debug"),
    Eq(bound = "D::Index: Eq, T: Eq, K: Eq"),
    Hash(bound = "D::Index: Hash, T: Hash, K: Hash"),
    PartialEq(bound = "T: PartialEq, K: PartialEq")
)]
pub struct KeyOwned<D, T, K = KeyKind>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    /// Value Owned by the Key
    pub inner: T,

    /// Key Index
    pub index: Index<D, K>,
}

impl<D, T, K> KeyOwned<D, T, K>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    /// Builds a new [`KeyOwned`] for `inner` with `index` as the [`Index`].
    #[inline]
    pub fn new(inner: T, index: Index<D, K>) -> Self {
        Self { inner, index }
    }

    /// Builds a new [`KeyOwned`] for `inner` with `kind` and `index` as the [`Index`].
    #[inline]
    pub fn with_kind(inner: T, kind: K, index: D::Index) -> Self {
        Self::new(inner, Index::new(kind, index))
    }

    /// Returns the inner [`self.inner`](Self::inner) dropping the [`self.index`](Self::index).
    #[inline]
    pub fn unwrap(self) -> T {
        self.inner
    }

    /// Reduces `self` into a [`KeyOwned`] with [`KeyKind`] as the key kind.
    #[inline]
    pub fn reduce(self) -> KeyOwned<D, T> {
        KeyOwned::new(self.inner, self.index.reduce())
    }

    /// Maps the underlying value using `f`.
    #[inline]
    pub fn map<U, F>(self, f: F) -> KeyOwned<D, U, K>
    where
        F: FnOnce(T) -> U,
    {
        KeyOwned::new(f(self.inner), self.index)
    }

    /// Maps the underlying value using `f` and then factors over the `Some` branch.
    #[inline]
    pub fn map_some<U, F>(self, f: F) -> Option<KeyOwned<D, U, K>>
    where
        F: FnOnce(T) -> Option<U>,
    {
        self.map(f).collect()
    }

    /// Maps the underlying value using `f` and then factors over the `Ok` branch.
    #[inline]
    pub fn map_ok<U, E, F>(self, f: F) -> Result<KeyOwned<D, U, K>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        self.map(f).collect()
    }
}

impl<D, T> KeyOwned<D, T>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a new [`KeyOwned`] for `inner` for an external key with `index`.
    #[inline]
    pub fn new_external(inner: T, index: D::Index) -> Self {
        Self::new(inner, Index::new_external(index))
    }

    /// Builds a new [`KeyOwned`] for `inner` for an internal key with `index`.
    #[inline]
    pub fn new_internal(inner: T, index: D::Index) -> Self {
        Self::new(inner, Index::new_internal(index))
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
}

impl<D, T, K> AsRef<T> for KeyOwned<D, T, K>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<D, T, K> AsMut<T> for KeyOwned<D, T, K>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<D, T, K> From<KeyOwned<D, T, K>> for (T, Index<D, K>)
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    #[inline]
    fn from(key_owned: KeyOwned<D, T, K>) -> Self {
        (key_owned.inner, key_owned.index)
    }
}

impl<D, L, R, K> KeyOwned<D, (L, R), K>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    /// Factors the key index over the left value in the pair.
    #[inline]
    pub fn left(self) -> (KeyOwned<D, L, K>, R) {
        (KeyOwned::new(self.inner.0, self.index), self.inner.1)
    }

    /// Factors the key index over the right value in the pair.
    #[inline]
    pub fn right(self) -> (L, KeyOwned<D, R, K>) {
        (self.inner.0, KeyOwned::new(self.inner.1, self.index))
    }
}

impl<D, T, K> KeyOwned<D, Option<T>, K>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    /// Converts a `KeyOwned<D, Option<T>, K>` into an `Option<KeyOwned<D, T, K>>`.
    #[inline]
    pub fn collect(self) -> Option<KeyOwned<D, T, K>> {
        Some(KeyOwned::new(self.inner?, self.index))
    }
}

impl<D, T, K> From<KeyOwned<D, Option<T>, K>> for Option<KeyOwned<D, T, K>>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    #[inline]
    fn from(key_owned: KeyOwned<D, Option<T>, K>) -> Self {
        key_owned.collect()
    }
}

impl<D, T, E, K> KeyOwned<D, Result<T, E>, K>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    /// Converts a `KeyOwned<D, Result<T, E>, K>` into an `Result<KeyOwned<D, T, K>, E>`.
    #[inline]
    pub fn collect(self) -> Result<KeyOwned<D, T, K>, E> {
        Ok(KeyOwned::new(self.inner?, self.index))
    }

    /// Converts a `KeyOwned<D, Result<T, E>, K>` into an `Option<KeyOwned<D, T, K>>`.
    #[inline]
    pub fn ok(self) -> Option<KeyOwned<D, T, K>> {
        self.collect().ok()
    }
}

impl<D, T, E, K> From<KeyOwned<D, Result<T, E>, K>> for Result<KeyOwned<D, T, K>, E>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    #[inline]
    fn from(key_owned: KeyOwned<D, Result<T, E>, K>) -> Self {
        key_owned.collect()
    }
}

impl<D, T, E, K> TryFrom<KeyOwned<D, Result<T, E>, K>> for KeyOwned<D, T, K>
where
    D: DerivedSecretKeyGenerator,
    K: Into<KeyKind>,
{
    type Error = E;

    #[inline]
    fn try_from(key_owned: KeyOwned<D, Result<T, E>, K>) -> Result<Self, Self::Error> {
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
) -> Result<ExternalSecretKey<D>, D::Error>
where
    D: DerivedSecretKeyGenerator,
{
    let secret_key = ExternalSecretKey::new(
        source.generate_external_key(account, index)?,
        Index::new(External, index.clone()),
    );
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
) -> Result<InternalSecretKey<D>, D::Error>
where
    D: DerivedSecretKeyGenerator,
{
    let secret_key = InternalSecretKey::new(
        source.generate_internal_key(account, index)?,
        Index::new(Internal, index.clone()),
    );
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
    fn generate_external_key(&mut self) -> Result<ExternalSecretKey<D>, D::Error> {
        next_external(self.derived_key_generator, self.account, &mut self.index)
    }

    /// Generates an internal secret key according to the [`DerivedSecretKeyGenerator`] protocol
    /// and increments the running `self.index`.
    #[inline]
    fn generate_internal_key(&mut self) -> Result<InternalSecretKey<D>, D::Error> {
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

impl<'d, D> Iterator for ExternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator,
{
    type Item = Result<ExternalSecretKey<D>, D::Error>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.0.generate_external_key())
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

impl<'d, D> Iterator for InternalKeys<'d, D>
where
    D: DerivedSecretKeyGenerator,
{
    type Item = Result<InternalSecretKey<D>, D::Error>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.0.generate_internal_key())
    }
}

/// Account Index Manager
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = "D::Account: Debug, D::Index: Debug"),
    Default(bound = ""),
    Eq(bound = "D::Account: Eq, D::Index: Eq"),
    Hash(bound = "D::Account: Hash, D::Index: Hash"),
    PartialEq(bound = "")
)]
pub struct Account<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Account Identifier
    pub account: D::Account,

    /// External Transaction Index Range
    pub external_indices: Range<D::Index>,

    /// Internal Transaction Index Range
    pub internal_indices: Range<D::Index>,
}

impl<D> Account<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a new [`Account`] for the given `account` identifier.
    #[inline]
    pub fn new(account: D::Account) -> Self {
        Self::with_ranges(account, Default::default(), Default::default())
    }

    /// Builds a new [`Account`] for the given `account` identifier with starting ranges
    /// `external_indices` and `internal_indices`.
    #[inline]
    pub fn with_ranges(
        account: D::Account,
        external_indices: Range<D::Index>,
        internal_indices: Range<D::Index>,
    ) -> Self {
        Self {
            account,
            external_indices,
            internal_indices,
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
        self.external_indices = Default::default();
        self.internal_indices = Default::default();
        self
    }

    /// Generates a new key of the given `kind` for this account.
    #[inline]
    pub fn key(&self, source: &D, kind: KeyKind) -> Result<SecretKey<D>, D::Error> {
        match kind {
            KeyKind::External => Ok(self.external_key(source)?.reduce()),
            KeyKind::Internal => Ok(self.internal_key(source)?.reduce()),
        }
    }

    /// Generates a new external key for this account.
    #[inline]
    pub fn external_key(&self, source: &D) -> Result<ExternalSecretKey<D>, D::Error> {
        Ok(SecretKey::new(
            source.generate_external_key(&self.account, &self.external_indices.end)?,
            Index::new(External, self.external_indices.end.clone()),
        ))
    }

    /// Generates a new internal key for this account.
    #[inline]
    pub fn internal_key(&self, source: &D) -> Result<InternalSecretKey<D>, D::Error> {
        Ok(SecretKey::new(
            source.generate_internal_key(&self.account, &self.internal_indices.end)?,
            Index::new(Internal, self.internal_indices.end.clone()),
        ))
    }

    /// Generates the next key of the given `kind` for this account, incrementing the
    /// appropriate index.
    #[inline]
    pub fn next_key(&mut self, source: &D, kind: KeyKind) -> Result<SecretKey<D>, D::Error> {
        match kind {
            KeyKind::External => Ok(self.next_external_key(source)?.reduce()),
            KeyKind::Internal => Ok(self.next_internal_key(source)?.reduce()),
        }
    }

    /// Generates the next external key for this account, incrementing the `external_index`.
    #[inline]
    pub fn next_external_key(&mut self, source: &D) -> Result<ExternalSecretKey<D>, D::Error> {
        next_external(source, &self.account, &mut self.external_indices.end)
    }

    /// Generates the next internal key for this account, incrementing the `internal_index`.
    #[inline]
    pub fn next_internal_key(&mut self, source: &D) -> Result<InternalSecretKey<D>, D::Error> {
        next_internal(source, &self.account, &mut self.internal_indices.end)
    }

    /// Returns an iterator over the external keys generated by the indices in
    /// [`self.external_indices`](Self::external_indices).
    #[inline]
    pub fn external_keys<'s>(&'s self, source: &'s D) -> ExternalKeysRange<'s, D> {
        ExternalKeysRange {
            source,
            account: &self.account,
            range: self.external_indices.clone(),
        }
    }

    /// Increments the start of the external index range if `index` is equal to the start of the
    /// range.
    #[inline]
    pub fn conditional_increment_external_range(&mut self, index: &D::Index) {
        if &self.external_indices.start == index {
            self.external_indices.start.increment()
        }
    }

    /// Shifts the end of the internal key range to the start.
    #[inline]
    pub fn internal_range_shift_to_start(&mut self) {
        self.internal_indices.end = self.internal_indices.start.clone();
    }

    /// Shifts the start of the internal key range to the end.
    #[inline]
    pub fn internal_range_shift_to_end(&mut self) {
        self.internal_indices.start = self.internal_indices.end.clone();
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

/// External Keys Range Iterator
///
/// This `struct` is created by the [`external_keys`](Account::external_keys) method on [`Account`].
/// See its documentation for more.
pub struct ExternalKeysRange<'d, D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Derived Secret Key Generator
    source: &'d D,

    /// Key Account
    account: &'d D::Account,

    /// Index Range
    range: Range<D::Index>,
}

impl<'d, D> Iterator for ExternalKeysRange<'d, D>
where
    D: DerivedSecretKeyGenerator,
{
    type Item = Result<ExternalSecretKey<D>, D::Error>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.range.is_empty() {
            return None;
        }
        Some(next_external(
            self.source,
            self.account,
            &mut self.range.end,
        ))
    }
}
