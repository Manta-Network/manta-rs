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

//! Hierarchical Key Tables

use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};

/// Hierarchical Key Table Parameter
pub trait HierarchicalKeyTableParameter:
    Clone + Copy + Default + PartialOrd + From<usize> + Into<usize>
{
    /// Increments the key parameter by one unit.
    fn increment(&mut self);
}

/// Hierarchical Key Table
pub trait HierarchicalKeyTable {
    /// Account Type
    type Account: HierarchicalKeyTableParameter;

    /// Index Type
    type Index: HierarchicalKeyTableParameter;

    /// Key Kind Type
    type Kind;

    /// Secret Key Type
    type SecretKey;

    /// Key Access Error Type
    type Error;

    /// Returns the secret key associated to `account` and `index` of the given `kind`.
    fn get(
        &self,
        account: Self::Account,
        index: Self::Index,
        kind: &Self::Kind,
    ) -> Result<Self::SecretKey, Self::Error>;
}

impl<H> HierarchicalKeyTable for &H
where
    H: HierarchicalKeyTable,
{
    type Account = H::Account;

    type Index = H::Index;

    type Kind = H::Kind;

    type SecretKey = H::SecretKey;

    type Error = H::Error;

    #[inline]
    fn get(
        &self,
        account: Self::Account,
        index: Self::Index,
        kind: &Self::Kind,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).get(account, index, kind)
    }
}

/// Account Map
pub trait AccountMap<H>
where
    H: HierarchicalKeyTable,
{
    /// Returns the maximum index associated to `account`.
    fn max_index(&self, account: H::Account) -> Option<H::Index>;

    /// Creates a new account, returning the new account parameter.
    fn create_account(&mut self) -> H::Account;

    /// Increments the index on the existing account, returning the new index parameter.
    fn increment_index(&mut self, account: H::Account) -> Option<H::Index>;
}

/// [`Vec`] Account Map Type
pub type VecAccountMap<H> = Vec<<H as HierarchicalKeyTable>::Index>;

impl<H> AccountMap<H> for VecAccountMap<H>
where
    H: HierarchicalKeyTable,
{
    #[inline]
    fn max_index(&self, account: H::Account) -> Option<H::Index> {
        self.get(account.into()).copied()
    }

    #[inline]
    fn create_account(&mut self) -> H::Account {
        self.push(0.into());
        (self.len() - 1).into()
    }

    #[inline]
    fn increment_index(&mut self, account: H::Account) -> Option<H::Index> {
        self.get_mut(account.into()).map(move |index| {
            index.increment();
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
    H: HierarchicalKeyTable,
    M: AccountMap<H>,
{
    /// Hierarchical Key Table
    table: H,

    /// Account Map
    accounts: M,
}

impl<H, M> AccountTable<H, M>
where
    H: HierarchicalKeyTable,
    M: AccountMap<H>,
{
    /// Builds a new [`AccountTable`] from a hierarchical key `table`.
    #[inline]
    pub fn new(table: H) -> Self
    where
        M: Default,
    {
        Self::with_accounts(table, Default::default())
    }

    /// Builds a new [`AccountTable`] from `table` and `accounts`.
    #[inline]
    pub fn with_accounts(table: H, accounts: M) -> Self {
        Self { table, accounts }
    }

    /// Returns the key associated to `account`, `index`, and `kind`.
    #[inline]
    pub fn key(
        &self,
        account: H::Account,
        index: H::Index,
        kind: &H::Kind,
    ) -> Option<Result<H::SecretKey, H::Error>> {
        self.subtable(account, index).map(move |st| st.key(kind))
    }

    /// Returns a subtable of `self` with fixed `account` and `index` parameters.
    #[inline]
    pub fn subtable(&self, account: H::Account, index: H::Index) -> Option<AccountSubTable<H>> {
        match self.accounts.max_index(account) {
            Some(max_index) if index <= max_index => {
                Some(AccountSubTable::new(&self.table, account, index))
            }
            _ => None,
        }
    }

    /// Creates a new account, returning the new account parameter.
    #[inline]
    pub fn create_account(&mut self) -> H::Account {
        self.accounts.create_account()
    }

    /// Increments the index on the existing account, returning the new index parameter.
    #[inline]
    pub fn increment_index(&mut self, account: H::Account) -> Option<H::Index> {
        self.accounts.increment_index(account)
    }
}

/// Account Sub-Table
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = "H: Debug, H::Account: Debug, H::Index: Debug"),
    Eq(bound = "H: Eq, H::Account: Eq, H::Index: Eq"),
    Hash(bound = "H: Hash, H::Account: Hash, H::Index: Hash"),
    PartialEq(bound = "H: PartialEq, H::Account: PartialEq, H::Index: PartialEq")
)]
pub struct AccountSubTable<'t, H>
where
    H: HierarchicalKeyTable,
{
    /// Hierarchical Key Table
    table: &'t H,

    /// Account Parameter
    account: H::Account,

    /// Index Parameter
    index: H::Index,
}

impl<'t, H> AccountSubTable<'t, H>
where
    H: HierarchicalKeyTable,
{
    /// Builds a new [`AccountSubTable`] for `table`, `account`, and `index`.
    #[inline]
    fn new(table: &'t H, account: H::Account, index: H::Index) -> Self {
        Self {
            table,
            account,
            index,
        }
    }

    /// Returns the inner account parameter of this subtable.
    #[inline]
    pub fn account(&self) -> H::Account {
        self.account
    }

    /// Returns the inner index parameter of this subtable.
    #[inline]
    pub fn index(&self) -> H::Index {
        self.index
    }

    /// Returns the key of the given `kind` from the hierarchical key table with a fixed account
    /// and index.
    #[inline]
    pub fn key(&self, kind: &H::Kind) -> Result<H::SecretKey, H::Error> {
        self.table.get(self.account, self.index, kind)
    }
}
