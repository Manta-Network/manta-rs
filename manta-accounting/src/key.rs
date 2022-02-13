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

//! Hierarchical Key Derivation Schemes

// TODO: Build custom iterator types for [`keypairs`] and [`generate_keys`].

use alloc::vec::Vec;
use core::{
    cmp,
    fmt::{self, Debug},
    hash::Hash,
    iter,
    marker::PhantomData,
};
use manta_crypto::{
    key::KeyDerivationFunction,
    rand::{CryptoRng, RngCore, Sample},
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Hierarchical Key Derivation Parameter Type
pub type IndexType = u32;

/// Hierarchical Key Derivation Parameter
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields, transparent)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HierarchicalKeyDerivationParameter<M> {
    /// Index
    index: IndexType,

    /// Type Parameter Marker
    __: PhantomData<M>,
}

impl<M> HierarchicalKeyDerivationParameter<M> {
    /// Builds a new [`HierarchicalKeyDerivationParameter`] from `index`.
    #[inline]
    pub const fn new(index: IndexType) -> Self {
        Self {
            index,
            __: PhantomData,
        }
    }

    /// Increments the index of `self` by one unit.
    #[inline]
    fn increment(&mut self) {
        self.index += 1;
    }

    /// Returns the index of `self`.
    #[inline]
    pub const fn index(&self) -> IndexType {
        self.index
    }
}

/// Implements the [`HierarchicalKeyDerivationParameter`] subtype for `$type` and `$index`.
macro_rules! impl_index_type {
    ($doc:expr, $fmt:expr, $type:ident, $index:ident) => {
        #[doc = $doc]
        #[doc = "Type"]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $type;

        #[doc = $doc]
        pub type $index = HierarchicalKeyDerivationParameter<$type>;

        impl Debug for $index {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_tuple($fmt).field(&self.index).finish()
            }
        }
    };
}

impl_index_type!(
    "Account Index",
    "AccountIndex",
    AccountIndexType,
    AccountIndex
);

impl_index_type!("Key Index", "KeyIndex", KeyIndexType, KeyIndex);

/// Key Kind
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Spend Key
    Spend,

    /// View Key
    View,
}

/// Hierarchical Key Derivation Scheme
pub trait HierarchicalKeyDerivationScheme {
    /// Secret Key Type
    type SecretKey;

    /// Derives a secret key for `account` with `kind` and `index`.
    fn derive(&self, account: AccountIndex, kind: Kind, index: KeyIndex) -> Self::SecretKey;

    /// Derives a spend secret key for `account` using the spend `index`.
    #[inline]
    fn derive_spend(&self, account: AccountIndex, index: KeyIndex) -> Self::SecretKey {
        self.derive(account, Kind::Spend, index)
    }

    /// Derives a view secret key for `account` using the view `index`.
    #[inline]
    fn derive_view(&self, account: AccountIndex, index: KeyIndex) -> Self::SecretKey {
        self.derive(account, Kind::View, index)
    }

    /// Derives a spend-view pair of secret keys for `account` and `index`.
    #[inline]
    fn derive_pair(&self, account: AccountIndex, index: KeyIndex) -> SecretKeyPair<Self> {
        SecretKeyPair::new(
            self.derive_spend(account, index),
            self.derive_view(account, index),
        )
    }

    /// Maps `self` along a key derivation function.
    #[inline]
    fn map<K>(self) -> Map<Self, K>
    where
        Self: Sized,
        K: KeyDerivationFunction<Key = Self::SecretKey>,
    {
        Map::new(self)
    }
}

impl<H> HierarchicalKeyDerivationScheme for &H
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    type SecretKey = H::SecretKey;

    #[inline]
    fn derive(&self, account: AccountIndex, kind: Kind, index: KeyIndex) -> Self::SecretKey {
        (*self).derive(account, kind, index)
    }

    #[inline]
    fn derive_spend(&self, account: AccountIndex, index: KeyIndex) -> Self::SecretKey {
        (*self).derive_spend(account, index)
    }

    #[inline]
    fn derive_view(&self, account: AccountIndex, index: KeyIndex) -> Self::SecretKey {
        (*self).derive_view(account, index)
    }
}

/// Mapping Hierarchical Key Derivation Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Map<H, K>
where
    H: HierarchicalKeyDerivationScheme,
    K: KeyDerivationFunction<Key = H::SecretKey>,
{
    /// Base Derivation Scheme
    base: H,

    /// Type Parameter Marker
    __: PhantomData<K>,
}

impl<H, K> Map<H, K>
where
    H: HierarchicalKeyDerivationScheme,
    K: KeyDerivationFunction<Key = H::SecretKey>,
{
    /// Builds a new [`Map`] from `base`.
    #[inline]
    pub fn new(base: H) -> Self {
        Self {
            base,
            __: PhantomData,
        }
    }
}

impl<H, K> HierarchicalKeyDerivationScheme for Map<H, K>
where
    H: HierarchicalKeyDerivationScheme,
    K: KeyDerivationFunction<Key = H::SecretKey>,
{
    type SecretKey = K::Output;

    #[inline]
    fn derive(&self, account: AccountIndex, kind: Kind, index: KeyIndex) -> Self::SecretKey {
        K::derive(&self.base.derive(account, kind, index))
    }

    #[inline]
    fn derive_spend(&self, account: AccountIndex, index: KeyIndex) -> Self::SecretKey {
        K::derive(&self.base.derive_spend(account, index))
    }

    #[inline]
    fn derive_view(&self, account: AccountIndex, index: KeyIndex) -> Self::SecretKey {
        K::derive(&self.base.derive_view(account, index))
    }
}

impl<H, K, D> Sample<D> for Map<H, K>
where
    H: HierarchicalKeyDerivationScheme + Sample<D>,
    K: KeyDerivationFunction<Key = H::SecretKey>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::new(H::sample(distribution, rng))
    }
}

/// Hierarchical Key Derivation Secret Key Pair
pub struct SecretKeyPair<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Spend Part of the Key Pair
    pub spend: H::SecretKey,

    /// View Part of the Key Pair
    pub view: H::SecretKey,
}

impl<H> SecretKeyPair<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`SecretKeyPair`] from `spend` and `view`.
    #[inline]
    pub fn new(spend: H::SecretKey, view: H::SecretKey) -> Self {
        Self { spend, view }
    }
}

/// Account Keys
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = "H: Debug"),
    Eq(bound = "H: Eq"),
    Hash(bound = "H: Hash"),
    PartialEq(bound = "H: PartialEq")
)]
pub struct AccountKeys<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Hierarchical Key Derivation Scheme
    keys: &'h H,

    /// Account Index
    account: AccountIndex,

    /// Maximum Index
    max_index: KeyIndex,
}

impl<'h, H> AccountKeys<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`AccountKeys`] from `keys`, `account`, and `max_index`.
    #[inline]
    fn new(keys: &'h H, account: AccountIndex, max_index: KeyIndex) -> Self {
        Self {
            keys,
            account,
            max_index,
        }
    }

    /// Performs the bounds check on `index` and then runs `f`.
    #[inline]
    fn with_bounds_check<T, F>(&self, index: KeyIndex, f: F) -> Option<T>
    where
        F: FnOnce(&Self, KeyIndex) -> T,
    {
        (index <= self.max_index).then(|| f(self, index))
    }

    /// Derives the spend key for this account at `index` without performing bounds checks.
    #[inline]
    fn derive_spend(&self, index: KeyIndex) -> H::SecretKey {
        self.keys.derive_spend(self.account, index)
    }

    /// Returns the default spend key for this account.
    #[inline]
    pub fn default_spend_key(&self) -> H::SecretKey {
        self.derive_spend(Default::default())
    }

    /// Returns the spend key for this account at `index`, if it does not exceed the maximum index.
    #[inline]
    pub fn spend_key(&self, index: KeyIndex) -> Option<H::SecretKey> {
        self.with_bounds_check(index, Self::derive_spend)
    }

    /// Derives the view key for this account at `index` without performing bounds checks.
    #[inline]
    fn derive_view(&self, index: KeyIndex) -> H::SecretKey {
        self.keys.derive_view(self.account, index)
    }

    /// Returns the default view key for this account.
    #[inline]
    pub fn default_view_key(&self) -> H::SecretKey {
        self.derive_view(Default::default())
    }

    /// Returns the view key for this account at `index`, if it does not exceed the maximum index.
    #[inline]
    pub fn view_key(&self, index: KeyIndex) -> Option<H::SecretKey> {
        self.with_bounds_check(index, Self::derive_view)
    }

    /// Derives the secret key pair for this account at `index` without performing bounds checks.
    #[inline]
    fn derive_pair(&self, index: KeyIndex) -> SecretKeyPair<H> {
        self.keys.derive_pair(self.account, index)
    }

    /// Returns the default secret key pair for this account.
    #[inline]
    pub fn default_keypair(&self) -> SecretKeyPair<H> {
        self.derive_pair(Default::default())
    }

    /// Returns the key pair for this account at the `spend` and `view` indices, if those indices
    /// do not exceed the maximum indices.
    #[inline]
    pub fn keypair(&self, index: KeyIndex) -> Option<SecretKeyPair<H>> {
        self.with_bounds_check(index, Self::derive_pair)
    }

    /// Returns an iterator over all the key pairs associated to `self`.
    #[inline]
    pub fn keypairs(&self) -> impl '_ + Iterator<Item = SecretKeyPair<H>> {
        let mut index = KeyIndex::default();
        iter::from_fn(move || {
            let next = self.keypair(index);
            index.increment();
            next
        })
    }

    /// Applies `f` to the view keys generated by `self` returning the first non-`None` result with
    /// it's key index and key attached, or returns `None` if every application of `f` returned
    /// `None`.
    #[inline]
    pub fn find_index<T, F>(&self, mut f: F) -> Option<ViewKeySelection<H, T>>
    where
        F: FnMut(&H::SecretKey) -> Option<T>,
    {
        let mut index = KeyIndex::default();
        loop {
            let view_key = self.view_key(index)?;
            if let Some(item) = f(&view_key) {
                return Some(ViewKeySelection {
                    index,
                    keypair: SecretKeyPair::new(self.derive_spend(index), view_key),
                    item,
                });
            }
            index.increment();
        }
    }

    /// Applies `f` to the view keys generated by `self` returning the first non-`None` result with
    /// it's key index and key attached, or returns `None` if every application pf `f` returned
    /// `None`.
    ///
    /// # Gap Limit
    ///
    /// This method, extends the current maximum index by `gap`-many indices while searching
    /// and then sets the new maximum to the previous maximum or the located index, whichever is
    /// larger.
    #[inline]
    pub fn find_index_with_gap<T, F>(
        &mut self,
        gap: KeyIndex,
        f: F,
    ) -> Option<ViewKeySelection<H, T>>
    where
        F: FnMut(&H::SecretKey) -> Option<T>,
    {
        let previous_maximum = self.max_index;
        self.max_index.index += gap.index;
        match self.find_index(f) {
            Some(result) => {
                self.max_index = cmp::max(previous_maximum, result.index);
                Some(result)
            }
            _ => {
                self.max_index = previous_maximum;
                None
            }
        }
    }
}

/// View Key Selection
pub struct ViewKeySelection<H, T>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Selection Index
    pub index: KeyIndex,

    /// Selection Key Pair
    pub keypair: SecretKeyPair<H>,

    /// Selection Item
    pub item: T,
}

/// Account Map Trait
pub trait AccountMap {
    /// Builds a new [`AccountMap`] with a starting account with the default maximum index.
    fn new() -> Self;

    /// Returns the last account index stored in the map.
    fn last_account(&self) -> AccountIndex;

    /// Returns the maximum key index for `account`, if it exists.
    fn max_index(&self, account: AccountIndex) -> Option<KeyIndex>;

    /// Adds a new account to the map, returning the new account index.
    fn create_account(&mut self) -> AccountIndex;

    /// Increments the maximum key index for `account`, if it exists, returning the new maximum
    /// index.
    fn increment_index(&mut self, account: AccountIndex) -> Option<KeyIndex>;
}

/// [`Vec`] Account Map Type
pub type VecAccountMap = Vec<KeyIndex>;

impl AccountMap for VecAccountMap {
    #[inline]
    fn new() -> Self {
        let mut this = Self::new();
        this.create_account();
        this
    }

    #[inline]
    fn last_account(&self) -> AccountIndex {
        AccountIndex::new(
            (self.len() - 1)
                .try_into()
                .expect("AccountIndex is not allowed to exceed IndexType::MAX."),
        )
    }

    #[inline]
    fn max_index(&self, account: AccountIndex) -> Option<KeyIndex> {
        self.get(account.index() as usize).copied()
    }

    #[inline]
    fn create_account(&mut self) -> AccountIndex {
        let index = AccountIndex::new(
            self.len()
                .try_into()
                .expect("AccountIndex is not allowed to exceed IndexType::MAX."),
        );
        self.push(Default::default());
        index
    }

    #[inline]
    fn increment_index(&mut self, account: AccountIndex) -> Option<KeyIndex> {
        self.get_mut(account.index() as usize).map(|m| {
            m.increment();
            *m
        })
    }
}

/// Account Table
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "H: Clone, M: Clone"),
    Copy(bound = "H: Copy, M: Copy"),
    Debug(bound = "H: Debug, M: Debug"),
    Eq(bound = "H: Eq, M: Eq"),
    Hash(bound = "H: Hash, M: Hash"),
    PartialEq(bound = "H: PartialEq, M: PartialEq")
)]
pub struct AccountTable<H, M = VecAccountMap>
where
    H: HierarchicalKeyDerivationScheme,
    M: AccountMap,
{
    /// Hierarchical Key Derivation Scheme
    keys: H,

    /// Account Map
    accounts: M,
}

impl<H, M> AccountTable<H, M>
where
    H: HierarchicalKeyDerivationScheme,
    M: AccountMap,
{
    /// Builds a new [`AccountTable`] using `keys` and the default account map.
    #[inline]
    pub fn new(keys: H) -> Self {
        Self::with_accounts(keys, M::new())
    }

    /// Builds a new [`AccountTable`] using `keys` and `accounts`.
    #[inline]
    pub fn with_accounts(keys: H, accounts: M) -> Self {
        Self { keys, accounts }
    }

    /// Returns the secret key pair associated to `account` if it exists, using `index` if it does
    /// not exceed the maximum key index.
    #[inline]
    pub fn keypair(
        &self,
        account: AccountIndex,
        index: KeyIndex,
    ) -> Option<Option<SecretKeyPair<H>>> {
        self.get(account).map(move |k| k.keypair(index))
    }

    /// Returns the account keys for `account` if it exists.
    #[inline]
    pub fn get(&self, account: AccountIndex) -> Option<AccountKeys<H>> {
        Some(AccountKeys::new(
            &self.keys,
            account,
            self.accounts.max_index(account)?,
        ))
    }

    /// Returns the account keys for the default account.
    #[inline]
    pub fn get_default(&self) -> AccountKeys<H> {
        self.get(Default::default()).unwrap()
    }

    /// Returns the maximum key index for `account`, if it exists.
    #[inline]
    pub fn max_index(&self, account: AccountIndex) -> Option<KeyIndex> {
        self.accounts.max_index(account)
    }

    /// Adds a new account to the map, returning the new account parameter.
    #[inline]
    pub fn create_account(&mut self) -> AccountIndex {
        self.accounts.create_account()
    }

    /// Increments the maximum key index for `account`, if it exists, returning the current
    /// maximum index.
    #[inline]
    pub fn increment_index(&mut self, account: AccountIndex) -> Option<KeyIndex> {
        self.accounts.increment_index(account)
    }

    /// Increments the spend index and returns the [`KeyIndex`] for the new index.
    #[inline]
    pub fn next_index(&mut self, account: AccountIndex) -> Option<KeyIndex> {
        let max_index = self.increment_index(account)?;
        Some(max_index)
    }

    /// Increments the spend index and returns the [`SecretKeyPair`] for the new index.
    #[inline]
    pub fn next(&mut self, account: AccountIndex) -> Option<SecretKeyPair<H>> {
        let index = self.next_index(account)?;
        Some(self.keys.derive_pair(account, index))
    }

    /// Returns an iterator over keys, generated by calling [`next`](Self::next) repeatedly.
    #[inline]
    pub fn generate_keys(
        &mut self,
        account: AccountIndex,
    ) -> impl '_ + Iterator<Item = SecretKeyPair<H>> {
        iter::from_fn(move || self.next(account))
    }
}

impl<H, M> Default for AccountTable<H, M>
where
    H: Default + HierarchicalKeyDerivationScheme,
    M: AccountMap,
{
    #[inline]
    fn default() -> Self {
        Self::new(Default::default())
    }
}
