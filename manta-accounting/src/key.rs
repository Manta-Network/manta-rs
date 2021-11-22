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
use core::{fmt::Debug, hash::Hash};

/// Hierarchical Key Derivation Parameter
pub trait HierarchicalKeyDerivationParameter:
    Clone + Copy + Default + PartialOrd + From<usize> + Into<usize>
{
    /// Increments the key parameter by one unit.
    fn increment(&mut self);
}

/// Hierarchical Key Derivation Scheme
pub trait HierarchicalKeyDerivationScheme {
    /// Account Type
    type Account: HierarchicalKeyDerivationParameter;

    /// Index Type
    type Index: HierarchicalKeyDerivationParameter;

    /// Secret Key Type
    type SecretKey;

    /// Key Derivation Error Type
    type Error;

    ///
    fn derive(
        &self,
        account: Self::Account,
        spend: Self::Index,
        view: Self::Index,
    ) -> Result<Key<Self>, Self::Error>;
}

impl<H> HierarchicalKeyDerivationScheme for &H
where
    H: HierarchicalKeyDerivationScheme,
{
    type Account = H::Account;

    type Index = H::Index;

    type SecretKey = H::SecretKey;

    type Error = H::Error;

    #[inline]
    fn derive(
        &self,
        account: Self::Account,
        spend: Self::Index,
        view: Self::Index,
    ) -> Result<Key<Self>, Self::Error> {
        let key = (*self).derive(account, spend, view)?;
        Ok(Key {
            spend: key.spend,
            view: key.view,
        })
    }
}

/// Hierarchical Key Derivation Key Type
pub struct Key<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Spend Part of the Key
    pub spend: H::SecretKey,

    /// View Part of the Key
    pub view: H::SecretKey,
}

impl<H> Key<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`Key`] from `spend` and `view`.
    #[inline]
    pub fn new(spend: H::SecretKey, view: H::SecretKey) -> Self {
        Self { spend, view }
    }
}

/// Error Type
pub enum Error<H>
where
    H: HierarchicalKeyDerivationScheme,
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
#[derivative(Clone, Copy, Default, Eq, PartialEq)]
pub struct Index<H>
where
    H: HierarchicalKeyDerivationScheme,
{
    /// Spend Part of the Key Index
    pub spend: H::Index,

    /// View Part of the Key Index
    pub view: H::Index,
}

impl<H> Index<H>
where
    H: HierarchicalKeyDerivationScheme,
{
    /// Builds a new [`Index`] using `spend` and `view`.
    #[inline]
    pub fn new(spend: H::Index, view: H::Index) -> Self {
        Self { spend, view }
    }
}

/// Account Keys
#[derive(derivative::Derivative)]
pub struct AccountKeys<'h, H>
where
    H: HierarchicalKeyDerivationScheme,
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
    H: HierarchicalKeyDerivationScheme,
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

    /// Returns the key for this account at the `spend` and `view` indices, if those indices do not
    /// exceed the maximum indices.
    #[inline]
    pub fn key(&self, spend: H::Index, view: H::Index) -> Result<Key<H>, Error<H>> {
        if spend <= self.max_index.spend {
            if view <= self.max_index.view {
                self.keys
                    .derive(self.account, spend, view)
                    .map_err(Error::KeyDerivationError)
            } else {
                Err(Error::ExceedingCurrentMaximumViewIndex)
            }
        } else {
            Err(Error::ExceedingCurrentMaximumSpendIndex)
        }
    }
}

/// Account Map Trait
pub trait AccountMap<H>
where
    H: HierarchicalKeyDerivationScheme,
{
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
    H: HierarchicalKeyDerivationScheme,
{
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
    Default(bound = "H: Default, M: Default"),
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
    /// Builds a new [`AccountTable`] using `keys` and a default account map.
    #[inline]
    pub fn new(keys: H) -> Self
    where
        M: Default,
    {
        Self::with_accounts(keys, Default::default())
    }

    /// Builds a new [`AccountTable`] using `keys` and `accounts`.
    #[inline]
    pub fn with_accounts(keys: H, accounts: M) -> Self {
        Self { keys, accounts }
    }

    /// Returns the key associated to `account` if it exists, using the `spend` and `view` indices
    /// if they do not exceed the maximum indices.
    #[inline]
    pub fn key(
        &self,
        account: H::Account,
        spend: H::Index,
        view: H::Index,
    ) -> Option<Result<Key<H>, Error<H>>> {
        self.get(account).map(move |k| k.key(spend, view))
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
