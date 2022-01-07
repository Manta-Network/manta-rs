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

//! Hierarchical Key Derivation Schemes

use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use manta_crypto::key::KeyDerivationFunction;

/// Hierarchical Key Derivation Parameter
pub trait HierarchicalKeyDerivationParameter: Copy + Default + PartialOrd {
    /// Increments the key parameter by one unit.
    fn increment(&mut self);
}

/// Hierarchical Key Derivation Scheme
pub trait HierarchicalKeyDerivationScheme {
    /// Account Type
    type Account: HierarchicalKeyDerivationParameter + From<usize> + Into<usize>;

    /// Index Type
    type Index: HierarchicalKeyDerivationParameter;

    /// Secret Key Type
    type SecretKey;

    /// Key Derivation Error Type
    type Error;

    /// Derives a spend secret key for `account` using the `spend` index.
    fn derive_spend(
        &self,
        account: Self::Account,
        spend: Self::Index,
    ) -> Result<Self::SecretKey, Self::Error>;

    /// Derives a view secret key for `account` using the `spend` and `view` indices.
    fn derive_view(
        &self,
        account: Self::Account,
        spend: Self::Index,
        view: Self::Index,
    ) -> Result<Self::SecretKey, Self::Error>;

    /// Derives a spend-view pair of secret keys for `account` using the `spend` and `view` indices.
    #[inline]
    fn derive(
        &self,
        account: Self::Account,
        spend: Self::Index,
        view: Self::Index,
    ) -> Result<SecretKeyPair<Self>, Self::Error> {
        Ok(SecretKeyPair::new(
            self.derive_spend(account, spend)?,
            self.derive_view(account, spend, view)?,
        ))
    }
}

impl<H> HierarchicalKeyDerivationScheme for &H
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    type Account = H::Account;

    type Index = H::Index;

    type SecretKey = H::SecretKey;

    type Error = H::Error;

    #[inline]
    fn derive_spend(
        &self,
        account: Self::Account,
        spend: Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).derive_spend(account, spend)
    }

    #[inline]
    fn derive_view(
        &self,
        account: Self::Account,
        spend: Self::Index,
        view: Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).derive_view(account, spend, view)
    }
}

/// Mapping Hierarchical Key Derivation Scheme
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

impl<H, K> HierarchicalKeyDerivationScheme for Map<H, K>
where
    H: HierarchicalKeyDerivationScheme,
    K: KeyDerivationFunction<Key = H::SecretKey>,
{
    type Account = H::Account;

    type Index = H::Index;

    type SecretKey = K::Output;

    type Error = H::Error;

    #[inline]
    fn derive_spend(
        &self,
        account: Self::Account,
        spend: Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        self.base
            .derive_spend(account, spend)
            .map(move |k| K::derive(&k))
    }

    #[inline]
    fn derive_view(
        &self,
        account: Self::Account,
        spend: Self::Index,
        view: Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        self.base
            .derive_view(account, spend, view)
            .map(move |k| K::derive(&k))
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

/// Error Type
pub enum Error<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Exceeded Current Maximum Spend Index
    ///
    /// See the [`increment_spend`](AccountMap::increment_spend) method on [`AccountMap`] for more.
    ExceedingCurrentMaximumSpendIndex,

    /// Exceeded Current Maximum View Index
    ///
    /// See the [`increment_view`](AccountMap::increment_view) method on [`AccountMap`] for more.
    ExceedingCurrentMaximumViewIndex,

    /// Key Derivation Error
    KeyDerivationError(H::Error),
}

/// Key Index Type
#[derive(derivative::Derivative)]
#[derivative(
    Clone,
    Copy,
    Debug(bound = "H::Index: Debug"),
    Default,
    Eq,
    Hash(bound = "H::Index: Hash"),
    PartialEq
)]
pub struct Index<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Spend Part of the Key Index
    pub spend: H::Index,

    /// View Part of the Key Index
    pub view: H::Index,
}

impl<H> Index<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`Index`] using `spend` and `view`.
    #[inline]
    pub fn new(spend: H::Index, view: H::Index) -> Self {
        Self { spend, view }
    }
}

/// View Key Selection
pub struct ViewKeySelection<H, T>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Selection Index
    pub index: Index<H>,

    /// Selection Key Pair
    pub keypair: SecretKeyPair<H>,

    /// Selection Item
    pub item: T,
}

/// Account Keys
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = "H: Debug, H::Account: Debug, H::Index: Debug"),
    Eq(bound = "H: Eq"),
    Hash(bound = "H: Hash, H::Account: Hash, H::Index: Hash"),
    PartialEq(bound = "H: PartialEq")
)]
pub struct AccountKeys<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Hierarchical Key Derivation Scheme
    keys: &'h H,

    /// Account Parameter
    account: H::Account,

    /// Maximum Key Index
    max_index: Index<H>,
}

impl<'h, H> AccountKeys<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`AccountKeys`] from `keys`, `account`, and `max_index`.
    #[inline]
    fn new(keys: &'h H, account: H::Account, max_index: Index<H>) -> Self {
        Self {
            keys,
            account,
            max_index,
        }
    }

    /// Performs the bounds check on `spend` and then runs `f`.
    #[inline]
    fn with_spend_bounds_check<T, F>(&self, spend: H::Index, f: F) -> Result<T, Error<H>>
    where
        F: FnOnce(&Self, H::Index) -> Result<T, H::Error>,
    {
        if spend <= self.max_index.spend {
            f(self, spend).map_err(Error::KeyDerivationError)
        } else {
            Err(Error::ExceedingCurrentMaximumSpendIndex)
        }
    }

    /// Performs the bounds check on `spend` and `view` and then runs `f`.
    #[inline]
    fn with_view_bounds_check<T, F>(
        &self,
        spend: H::Index,
        view: H::Index,
        f: F,
    ) -> Result<T, Error<H>>
    where
        F: FnOnce(&Self, H::Index, H::Index) -> Result<T, H::Error>,
    {
        if spend <= self.max_index.spend {
            if view <= self.max_index.view {
                f(self, spend, view).map_err(Error::KeyDerivationError)
            } else {
                Err(Error::ExceedingCurrentMaximumViewIndex)
            }
        } else {
            Err(Error::ExceedingCurrentMaximumSpendIndex)
        }
    }

    /// Derives the spend key for this account at `spend` without performing bounds checks.
    #[inline]
    fn derive_spend(&self, spend: H::Index) -> Result<H::SecretKey, H::Error> {
        self.keys.derive_spend(self.account, spend)
    }

    /// Returns the default spend key for this account.
    #[inline]
    pub fn default_spend_key(&self) -> Result<H::SecretKey, H::Error> {
        self.derive_spend(Default::default())
    }

    /// Returns the spend key for this account at the `spend` index, if it does not exceed the
    /// maximum index.
    #[inline]
    pub fn spend_key(&self, spend: H::Index) -> Result<H::SecretKey, Error<H>> {
        self.with_spend_bounds_check(spend, Self::derive_spend)
    }

    /// Derives the view key for this account at `spend` and `view` without performing bounds
    /// checks.
    #[inline]
    fn derive_view(&self, spend: H::Index, view: H::Index) -> Result<H::SecretKey, H::Error> {
        self.keys.derive_view(self.account, spend, view)
    }

    /// Returns the default view key for this account.
    #[inline]
    pub fn default_view_key(&self) -> Result<H::SecretKey, H::Error> {
        let default_index = Default::default();
        self.derive_view(default_index, default_index)
    }

    /// Returns the view key for this account at `index`, if it does not exceed the maximum index.
    #[inline]
    pub fn view_key(&self, index: Index<H>) -> Result<H::SecretKey, Error<H>> {
        self.view_key_with(index.spend, index.view)
    }

    /// Returns the view key for this account at the `spend` and `view` indices, if those indices
    /// do not exceed the maximum indices.
    #[inline]
    pub fn view_key_with(&self, spend: H::Index, view: H::Index) -> Result<H::SecretKey, Error<H>> {
        self.with_view_bounds_check(spend, view, Self::derive_view)
    }

    /// Derives the secret key pair for this account at `spend` and `view` without performing bounds
    /// checks.
    #[inline]
    fn derive(&self, spend: H::Index, view: H::Index) -> Result<SecretKeyPair<H>, H::Error> {
        self.keys.derive(self.account, spend, view)
    }

    /// Returns the default secret key pair for this account.
    #[inline]
    pub fn default_keypair(&self) -> Result<SecretKeyPair<H>, H::Error> {
        let default_index = Default::default();
        self.derive(default_index, default_index)
    }

    /// Returns the key pair for this account at `index`, if it does not exceed the maximum index.
    #[inline]
    pub fn keypair(&self, index: Index<H>) -> Result<SecretKeyPair<H>, Error<H>> {
        self.keypair_with(index.spend, index.view)
    }

    /// Returns the key pair for this account at the `spend` and `view` indices, if those indices
    /// do not exceed the maximum indices.
    #[inline]
    pub fn keypair_with(
        &self,
        spend: H::Index,
        view: H::Index,
    ) -> Result<SecretKeyPair<H>, Error<H>> {
        self.with_view_bounds_check(spend, view, Self::derive)
    }

    /// Applies `f` to the view keys generated by `self` returning the first non-`None` result with
    /// it's key index and key attached, or returns an error if the key derivation failed.
    #[inline]
    pub fn find_index<T, F>(&self, mut f: F) -> Result<Option<ViewKeySelection<H, T>>, H::Error>
    where
        F: FnMut(&H::SecretKey) -> Option<T>,
    {
        let mut index = Index::default();
        loop {
            loop {
                match self.view_key(index) {
                    Ok(view_key) => {
                        if let Some(item) = f(&view_key) {
                            return Ok(Some(ViewKeySelection {
                                index,
                                keypair: SecretKeyPair::new(
                                    self.derive_spend(index.spend)?,
                                    view_key,
                                ),
                                item,
                            }));
                        }
                    }
                    Err(Error::ExceedingCurrentMaximumViewIndex) => break,
                    Err(Error::ExceedingCurrentMaximumSpendIndex) => return Ok(None),
                    Err(Error::KeyDerivationError(err)) => return Err(err),
                }
                index.view.increment();
            }
            index.spend.increment();
        }
    }
}

/// Account Map Trait
pub trait AccountMap<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`AccountMap`] with a starting account with default max indices.
    fn new() -> Self;

    /// Returns the maximum spend and view indices for `account`, if it exists.
    fn max_index(&self, account: H::Account) -> Option<Index<H>>;

    /// Adds a new account to the map, returning the new account parameter.
    fn create_account(&mut self) -> H::Account;

    /// Increments the maximum spend index for `account`, if it exists, returning the current
    /// maximum indices.
    fn increment_spend(&mut self, account: H::Account) -> Option<Index<H>>;

    /// Increments the maximum view index for `account`, if it exists, returning the current
    /// maximum indices.
    fn increment_view(&mut self, account: H::Account) -> Option<Index<H>>;
}

/// [`Vec`] Account Map Type
pub type VecAccountMap<H> = Vec<Index<H>>;

impl<H> AccountMap<H> for VecAccountMap<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    #[inline]
    fn new() -> Self {
        let mut this = Self::new();
        this.create_account();
        this
    }

    #[inline]
    fn max_index(&self, account: H::Account) -> Option<Index<H>> {
        self.get(account.into()).copied()
    }

    #[inline]
    fn create_account(&mut self) -> H::Account {
        self.push(Default::default());
        (self.len() - 1).into()
    }

    #[inline]
    fn increment_spend(&mut self, account: H::Account) -> Option<Index<H>> {
        self.get_mut(account.into()).map(move |index| {
            index.spend.increment();
            *index
        })
    }

    #[inline]
    fn increment_view(&mut self, account: H::Account) -> Option<Index<H>> {
        self.get_mut(account.into()).map(move |index| {
            index.view.increment();
            *index
        })
    }
}

/// Account Table
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "H: Clone, M: Clone"),
    Copy(bound = "H: Copy, M: Copy"),
    Debug(bound = "H: Debug, M: Debug"),
    Eq(bound = "H: Eq, M: Eq"),
    Hash(bound = "H: Hash, M: Hash"),
    PartialEq(bound = "H: PartialEq, M: PartialEq")
)]
pub struct AccountTable<H, M = VecAccountMap<H>>
where
    H: HierarchicalKeyDerivationScheme,
    M: AccountMap<H>,
{
    /// Hierarchical Key Derivation Scheme
    keys: H,

    /// Account Map
    accounts: M,
}

impl<H, M> AccountTable<H, M>
where
    H: HierarchicalKeyDerivationScheme,
    M: AccountMap<H>,
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

    /// Returns the key associated to `account` if it exists, using `index` if it does not exceed
    /// the maximum index.
    #[inline]
    pub fn keypair(
        &self,
        account: H::Account,
        index: Index<H>,
    ) -> Option<Result<SecretKeyPair<H>, Error<H>>> {
        self.keypair_with(account, index.spend, index.view)
    }

    /// Returns the key associated to `account` if it exists, using the `spend` and `view` indices
    /// if they do not exceed the maximum indices.
    #[inline]
    pub fn keypair_with(
        &self,
        account: H::Account,
        spend: H::Index,
        view: H::Index,
    ) -> Option<Result<SecretKeyPair<H>, Error<H>>> {
        self.get(account).map(move |k| k.keypair_with(spend, view))
    }

    /// Returns the account keys for `account` if it exists.
    #[inline]
    pub fn get(&self, account: H::Account) -> Option<AccountKeys<H>> {
        Some(AccountKeys::new(
            &self.keys,
            account,
            self.accounts.max_index(account)?,
        ))
    }

    /// Adds a new account to the map, returning the new account parameter.
    #[inline]
    pub fn create_account(&mut self) -> H::Account {
        self.accounts.create_account()
    }

    /// Increments the maximum spend index for `account`, if it exists, returning the current
    /// maximum indices.
    #[inline]
    pub fn increment_spend(&mut self, account: H::Account) -> Option<Index<H>> {
        self.accounts.increment_spend(account)
    }

    /// Increments the maximum view index for `account`, if it exists, returning the current
    /// maximum indices.
    #[inline]
    pub fn increment_view(&mut self, account: H::Account) -> Option<Index<H>> {
        self.accounts.increment_view(account)
    }
}

impl<H, M> Default for AccountTable<H, M>
where
    H: Default + HierarchicalKeyDerivationScheme,
    M: AccountMap<H>,
{
    #[inline]
    fn default() -> Self {
        Self::new(Default::default())
    }
}
