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
//!
//! This module defines a Hierarchical Key Derivation Scheme similar to the one defined in the
//! [`BIP-0044`] specification.
//!
//! [`BIP-0044`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

use alloc::vec::Vec;
use core::{
    cmp,
    fmt::{self, Debug},
    hash::Hash,
    iter,
    marker::PhantomData,
};
use manta_crypto::{
    key::kdf::KeyDerivationFunction,
    rand::{RngCore, Sample},
};
use manta_util::collections::btree_map::{self, BTreeMap};

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
    /// [`KeyIndex`] Gap Limit
    const GAP_LIMIT: IndexType;

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

    /// Borrows `self` rather than consuming it, returning an implementation of
    /// [`HierarchicalKeyDerivationScheme`].
    #[inline]
    fn by_ref(&self) -> &Self {
        self
    }

    /// Maps `self` along a key derivation function.
    #[inline]
    fn map<F>(self, key_derivation_function: F) -> Map<Self, F>
    where
        Self: Sized,
        F: KeyDerivationFunction<Key = Self::SecretKey>,
    {
        Map::new(self, key_derivation_function)
    }
}

impl<H> HierarchicalKeyDerivationScheme for &H
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    const GAP_LIMIT: IndexType = H::GAP_LIMIT;

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
pub struct Map<H, F>
where
    H: HierarchicalKeyDerivationScheme,
    F: KeyDerivationFunction<Key = H::SecretKey>,
{
    /// Base Derivation Scheme
    base: H,

    /// Key Derivation Function
    key_derivation_function: F,
}

impl<H, F> Map<H, F>
where
    H: HierarchicalKeyDerivationScheme,
    F: KeyDerivationFunction<Key = H::SecretKey>,
{
    /// Builds a new [`Map`] from `base` and `key_derivation_function`.
    #[inline]
    pub fn new(base: H, key_derivation_function: F) -> Self {
        Self {
            base,
            key_derivation_function,
        }
    }
}

impl<H, F> HierarchicalKeyDerivationScheme for Map<H, F>
where
    H: HierarchicalKeyDerivationScheme,
    F: KeyDerivationFunction<Key = H::SecretKey>,
{
    const GAP_LIMIT: IndexType = H::GAP_LIMIT;

    type SecretKey = F::Output;

    #[inline]
    fn derive(&self, account: AccountIndex, kind: Kind, index: KeyIndex) -> Self::SecretKey {
        self.key_derivation_function
            .derive(&self.base.derive(account, kind, index), &mut ())
    }

    #[inline]
    fn derive_spend(&self, account: AccountIndex, index: KeyIndex) -> Self::SecretKey {
        self.key_derivation_function
            .derive(&self.base.derive_spend(account, index), &mut ())
    }

    #[inline]
    fn derive_view(&self, account: AccountIndex, index: KeyIndex) -> Self::SecretKey {
        self.key_derivation_function
            .derive(&self.base.derive_view(account, index), &mut ())
    }
}

impl<H, F, D> Sample<(D, F)> for Map<H, F>
where
    H: HierarchicalKeyDerivationScheme + Sample<D>,
    F: KeyDerivationFunction<Key = H::SecretKey>,
{
    #[inline]
    fn sample<R>(distribution: (D, F), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(H::sample(distribution.0, rng), distribution.1)
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
    index: AccountIndex,

    /// Account Information
    account: Account,
}

impl<'h, H> AccountKeys<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`AccountKeys`] from `keys`, `index`, and `account`.
    #[inline]
    fn new(keys: &'h H, index: AccountIndex, account: Account) -> Self {
        Self {
            keys,
            index,
            account,
        }
    }

    /// Performs the bounds check on `index` and then runs `f`.
    #[inline]
    fn with_bounds_check<T, F>(&self, index: KeyIndex, f: F) -> Option<T>
    where
        F: FnOnce(&Self, KeyIndex) -> T,
    {
        (index <= self.account.maximum_index).then(|| f(self, index))
    }

    /// Derives the spend key for this account at `index` without performing bounds checks.
    #[inline]
    fn derive_spend(&self, index: KeyIndex) -> H::SecretKey {
        self.keys.derive_spend(self.index, index)
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
        self.keys.derive_view(self.index, index)
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
        self.keys.derive_pair(self.index, index)
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
}

/// Account Keys with Mutable Access to the Account Table
#[derive(derivative::Derivative)]
#[derivative(
    Debug(bound = "H: Debug"),
    Eq(bound = "H: Eq"),
    Hash(bound = "H: Hash"),
    PartialEq(bound = "H: PartialEq")
)]
pub struct AccountKeysMut<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Hierarchical Key Derivation Scheme
    keys: &'h H,

    /// Account Index
    index: AccountIndex,

    /// Account Information
    account: &'h mut Account,
}

impl<'h, H> AccountKeysMut<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`AccountKeysMut`] from `keys`, `index`, and `account`.
    #[inline]
    fn new(keys: &'h H, index: AccountIndex, account: &'h mut Account) -> Self {
        Self {
            keys,
            index,
            account,
        }
    }

    /// Performs the bounds check on `index` and then runs `f`.
    #[inline]
    fn with_bounds_check<T, F>(&self, index: KeyIndex, f: F) -> Option<T>
    where
        F: FnOnce(&Self, KeyIndex) -> T,
    {
        (index <= self.account.maximum_index).then(|| f(self, index))
    }

    /// Derives the spend key for this account at `index` without performing bounds checks.
    #[inline]
    fn derive_spend(&self, index: KeyIndex) -> H::SecretKey {
        self.keys.derive_spend(self.index, index)
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
        self.keys.derive_view(self.index, index)
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
        self.keys.derive_pair(self.index, index)
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

    /// Returns a new [`ViewKeyTable`] for `self`.
    #[inline]
    pub fn view_key_table(self) -> ViewKeyTable<'h, H> {
        ViewKeyTable::new(self)
    }
}

/// View Key Table
pub struct ViewKeyTable<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Account Keys
    keys: AccountKeysMut<'h, H>,

    /// Pre-computed View Keys
    view_keys: BTreeMap<KeyIndex, H::SecretKey>,
}

impl<'h, H> ViewKeyTable<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// View Key Buffer Maximum Size Limit
    pub const VIEW_KEY_BUFFER_LIMIT: usize = 16 * (H::GAP_LIMIT as usize);

    /// Builds a new [`ViewKeyTable`] over the account `keys`.
    #[inline]
    pub fn new(keys: AccountKeysMut<'h, H>) -> Self {
        Self {
            keys,
            view_keys: Default::default(),
        }
    }

    /// Returns the account keys associated to `self`.
    #[inline]
    pub fn into_keys(self) -> AccountKeysMut<'h, H> {
        self.keys
    }

    /// Returns the view key for this account at `index`, if it does not exceed the maximum index.
    ///
    /// # Limits
    ///
    /// This function uses a view key buffer that stores the computed keys to reduce the number of
    /// times a re-compute of the view keys is needed while searching. The buffer only grows past
    /// the current key bounds with a call to [`find_index_with_gap`](Self::find_index_with_gap)
    /// which extends the buffer by at most [`GAP_LIMIT`]-many keys per round. To prevent allocating
    /// too much memory, the internal buffer is capped at [`VIEW_KEY_BUFFER_LIMIT`]-many elements.
    ///
    /// [`GAP_LIMIT`]: HierarchicalKeyDerivationScheme::GAP_LIMIT
    /// [`VIEW_KEY_BUFFER_LIMIT`]: Self::VIEW_KEY_BUFFER_LIMIT
    #[inline]
    pub fn view_key(&mut self, index: KeyIndex) -> Option<&H::SecretKey> {
        btree_map::get_or_mutate(&mut self.view_keys, &index, |map| {
            let next_key = self.keys.view_key(index)?;
            if map.len() == Self::VIEW_KEY_BUFFER_LIMIT {
                btree_map::pop_last(map);
            }
            Some(btree_map::insert_then_get(map, index, next_key))
        })
    }

    /// Applies `f` to the view keys generated by `self` returning the first non-`None` result with
    /// it's key index and key attached, or returns `None` if every application of `f` returned
    /// `None`.
    #[inline]
    pub fn find_index<T, F>(&mut self, mut f: F) -> Option<ViewKeySelection<H, T>>
    where
        F: FnMut(&H::SecretKey) -> Option<T>,
    {
        let mut index = KeyIndex::default();
        loop {
            if let Some(item) = f(self.view_key(index)?) {
                self.keys.account.last_used_index =
                    cmp::max(self.keys.account.last_used_index, index);
                return Some(ViewKeySelection {
                    index,
                    keypair: self.keys.derive_pair(index),
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
    /// This method extends the current maximum index by [`GAP_LIMIT`]-many indices while searching
    /// and then sets the new maximum to the previous maximum or the located index, whichever is
    /// larger.
    ///
    /// [`GAP_LIMIT`]: HierarchicalKeyDerivationScheme::GAP_LIMIT
    #[inline]
    pub fn find_index_with_gap<T, F>(&mut self, f: F) -> Option<ViewKeySelection<H, T>>
    where
        F: FnMut(&H::SecretKey) -> Option<T>,
    {
        let previous_maximum = self.keys.account.maximum_index;
        self.keys.account.maximum_index.index += H::GAP_LIMIT;
        match self.find_index(f) {
            Some(result) => {
                self.keys.account.maximum_index = cmp::max(previous_maximum, result.index);
                Some(result)
            }
            _ => {
                self.keys.account.maximum_index = previous_maximum;
                None
            }
        }
    }

    /// Runs one of the index search algorithms depending on the value of `use_gap_limit`, where
    /// [`find_index_with_gap`](Self::find_index_with_gap) is used in the case that `use_gap_limit`
    /// is `true`, and [`find_index`](Self::find_index) is used otherwise.
    #[inline]
    pub fn find_index_with_maybe_gap<T, F>(
        &mut self,
        use_gap_limit: bool,
        f: F,
    ) -> Option<ViewKeySelection<H, T>>
    where
        F: FnMut(&H::SecretKey) -> Option<T>,
    {
        if use_gap_limit {
            self.find_index_with_gap(f)
        } else {
            self.find_index(f)
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

impl<H, T> ViewKeySelection<H, T>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Computes `f` on `self.item` returning a new [`ViewKeySelection`] with the same `index` and
    /// `keypair`.
    #[inline]
    pub fn map<U, F>(self, f: F) -> ViewKeySelection<H, U>
    where
        F: FnOnce(T) -> U,
    {
        ViewKeySelection {
            index: self.index,
            keypair: self.keypair,
            item: f(self.item),
        }
    }
}

/// Account
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Account {
    /// Last Used Index
    ///
    /// This index is used to enforce limits when generating new keys beyond the `maximum_index`.
    pub last_used_index: KeyIndex,

    /// Maximum Index
    pub maximum_index: KeyIndex,
}

/// Account Map Trait
pub trait AccountMap {
    /// Builds a new [`AccountMap`] with a starting account with the default maximum index.
    fn new() -> Self;

    /// Returns the last account index stored in the map.
    fn last_account(&self) -> AccountIndex;

    /// Adds a new account to the map, returning the new account index.
    fn create_account(&mut self) -> AccountIndex;

    /// Returns the [`Account`] associated to `account`.
    fn get(&self, account: AccountIndex) -> Option<Account>;

    /// Returns the [`Account`] associated to `account`.
    fn get_mut(&mut self, account: AccountIndex) -> Option<&mut Account>;
}

/// [`Vec`] Account Map Type
pub type VecAccountMap = Vec<Account>;

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
    fn get(&self, account: AccountIndex) -> Option<Account> {
        self.as_slice().get(account.index() as usize).copied()
    }

    #[inline]
    fn get_mut(&mut self, account: AccountIndex) -> Option<&mut Account> {
        self.as_mut_slice().get_mut(account.index() as usize)
    }
}

/// Account Table
///
/// The account table stores an underlying [`HierarchicalKeyDerivationScheme`] for key generation
/// and a set of accounts defined by an [`AccountMap`] which can be queried to get the set of
/// existing keys and for generating new keys.
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
            self.accounts.get(account)?,
        ))
    }

    /// Returns the account keys for `account` if it exists.
    #[inline]
    pub fn get_mut(&mut self, account: AccountIndex) -> Option<AccountKeysMut<H>> {
        Some(AccountKeysMut::new(
            &self.keys,
            account,
            self.accounts.get_mut(account)?,
        ))
    }

    /// Returns the account keys for the default account.
    #[inline]
    pub fn get_default(&self) -> AccountKeys<H> {
        self.get(Default::default()).unwrap()
    }

    /// Returns the account keys for the default account.
    #[inline]
    pub fn get_mut_default(&mut self) -> AccountKeysMut<H> {
        self.get_mut(Default::default()).unwrap()
    }

    /// Returns the maximum key index for `account`, if it exists.
    #[inline]
    pub fn maximum_index(&self, account: AccountIndex) -> Option<KeyIndex> {
        self.accounts
            .get(account)
            .map(|account| account.maximum_index)
    }

    /// Adds a new account to the map, returning the new account parameter.
    #[inline]
    pub fn create_account(&mut self) -> AccountIndex {
        self.accounts.create_account()
    }

    /// Increments the maximum key index for `account`, if it exists, returning the current
    /// maximum index. This method also returns `None` in the case that the
    /// [`GAP_LIMIT`](HierarchicalKeyDerivationScheme::GAP_LIMIT) would be exceeded.
    #[inline]
    pub fn increment_maximum_index(&mut self, account: AccountIndex) -> Option<KeyIndex> {
        self.accounts.get_mut(account).and_then(|account| {
            match H::GAP_LIMIT
                .checked_sub(account.maximum_index.index - account.last_used_index.index)
            {
                Some(diff) if diff > 0 => {
                    account.maximum_index.increment();
                    Some(account.maximum_index)
                }
                _ => None,
            }
        })
    }

    /// Increments the spend index and returns the [`KeyIndex`] for the new index.
    #[inline]
    pub fn next_index(&mut self, account: AccountIndex) -> Option<KeyIndex> {
        let max_index = self.increment_maximum_index(account)?;
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
