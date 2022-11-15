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

//! Key Accounting

use alloc::vec::Vec;
use core::{
    fmt::{self, Debug},
    hash::Hash,
    marker::PhantomData,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Base Index Type
pub type IndexType = u32;

/// Index
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields, transparent)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Index<M> {
    /// Index
    index: IndexType,

    /// Type Parameter Marker
    __: PhantomData<M>,
}

impl<M> Index<M> {
    /// Builds a new [`Index`] from `index`.
    #[inline]
    pub const fn new(index: IndexType) -> Self {
        Self {
            index,
            __: PhantomData,
        }
    }

    /// Increments the index of `self` by one unit.
    #[inline]
    pub fn increment(&mut self) {
        self.index += 1;
    }

    /// Returns the index of `self`.
    #[inline]
    pub const fn index(&self) -> IndexType {
        self.index
    }
}

/// Implements the [`Index`] subtype for `$type` and `$index`.
macro_rules! impl_index_type {
    ($doc:expr, $fmt:expr, $type:ident, $index:ident) => {
        #[doc = $doc]
        #[doc = "Type"]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $type;

        #[doc = $doc]
        pub type $index = Index<$type>;

        impl Debug for $index {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_tuple($fmt).field(&self.index).finish()
            }
        }

        impl From<IndexType> for $index {
            #[inline]
            fn from(index: IndexType) -> Self {
                Self::new(index)
            }
        }

        impl From<$index> for IndexType {
            #[inline]
            fn from(index: $index) -> Self {
                index.index()
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

/// Account Collection
pub trait AccountCollection {
    /// Spending Key Type
    type SpendingKey;

    /// Returns the [`SpendingKey`] corresponding to `index`.
    fn spending_key(&self, index: &AccountIndex) -> Self::SpendingKey;
}

impl<A> AccountCollection for &A
where
    A: AccountCollection,
{
    type SpendingKey = A::SpendingKey;

    #[inline]
    fn spending_key(&self, index: &AccountIndex) -> Self::SpendingKey {
        (**self).spending_key(index)
    }
}

/// Spending Key Type
pub type SpendingKey<A> = <A as AccountCollection>::SpendingKey;

/// Account Map
pub trait AccountMap {
    /// Account Type
    type Account;

    /// Builds a new [`AccountMap`] with a starting account.
    fn new() -> Self;

    /// Returns the last account index stored in the map.
    fn last_account(&self) -> AccountIndex;

    /// Adds a new account to the map, returning the new account index.
    fn create_account(&mut self) -> AccountIndex;

    /// Returns a shared reference to the [`Account`](Self::Account) associated to `account`.
    fn get(&self, account: AccountIndex) -> Option<&Self::Account>;

    /// Returns a shared referece to the default [`Account`](Self::Account) for this map.
    #[inline]
    fn get_default(&self) -> &Self::Account {
        self.get(Default::default())
            .expect("The default account must always exist.")
    }

    /// Returns a mutable reference to the [`Account`](Self::Account) associated to `account`.
    fn get_mut(&mut self, account: AccountIndex) -> Option<&mut Self::Account>;

    /// Returns a mutable reference to the default [`Account`](Self::Account) for this map.
    #[inline]
    fn get_mut_default(&mut self) -> &mut Self::Account {
        self.get_mut(Default::default())
            .expect("The default account must always exist.")
    }
}

/// [`Vec`] Account Map Type
pub type VecAccountMap = Vec<AccountIndex>;

impl AccountMap for VecAccountMap {
    type Account = AccountIndex;

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
    fn get(&self, account: AccountIndex) -> Option<&Self::Account> {
        self.as_slice().get(account.index() as usize)
    }

    #[inline]
    fn get_mut(&mut self, account: AccountIndex) -> Option<&mut Self::Account> {
        self.as_mut_slice().get_mut(account.index() as usize)
    }
}

/// Derive Address Trait
pub trait DeriveAddress {
    /// Address Generation Parameters
    type Parameters;

    /// Address Type
    type Address;

    /// Returns the [`Address`](Self::Address) corresponding to `self`.
    fn address(&self, parameters: &Self::Parameters) -> Self::Address;
}

/// Derive Addresses Trait
pub trait DeriveAddresses {
    /// Address Generation Parameters
    type Parameters;

    /// Address Type
    type Address;

    /// Returns the [`Address`](Self::Address) corresponding to `index`.
    fn address(&self, parameters: &Self::Parameters, index: AccountIndex) -> Self::Address;
}

/// Account
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "H: Deserialize<'de>", serialize = "H: Serialize",),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "H: Clone"),
    Copy(bound = "H: Copy"),
    Debug(bound = "H: Debug"),
    Eq(bound = "H: Eq"),
    Hash(bound = "H: Hash"),
    PartialEq(bound = "H: PartialEq")
)]
pub struct Account<H>
where
    H: AccountCollection,
{
    /// Account Collection
    key: H,

    /// Index
    index: AccountIndex,
}

impl<H> Account<H>
where
    H: AccountCollection,
{
    /// Builds a new [`Account`] from `key` and `index`.
    #[inline]
    pub fn new(key: H, index: AccountIndex) -> Self {
        Self { key, index }
    }

    /// Returns the [`SpendingKey`] corresponding to `self`.
    #[inline]
    pub fn spending_key(&self) -> SpendingKey<H> {
        self.key.spending_key(&self.index)
    }
}

impl<H> DeriveAddress for Account<H>
where
    H: AccountCollection + DeriveAddresses,
{
    type Address = H::Address;
    type Parameters = H::Parameters;

    #[inline]
    fn address(&self, parameters: &Self::Parameters) -> Self::Address {
        self.key.address(parameters, self.index)
    }
}

/// Account Table
///
/// The account table stores an underlying [`AccountCollection`] for key generation
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
    H: AccountCollection,
    M: AccountMap<Account = AccountIndex>,
{
    /// Account Collection
    keys: H,

    /// Account Map
    accounts: M,
}

impl<H, M> AccountTable<H, M>
where
    H: AccountCollection,
    M: AccountMap<Account = AccountIndex>,
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

    /// Returns the account keys for `account` if it exists.
    #[inline]
    pub fn get(&self, account: AccountIndex) -> Option<Account<H>>
    where
        H: Clone,
    {
        let index = self.accounts.get(account).copied()?;
        Some(Account::new(self.keys.clone(), index))
    }

    /// Returns the account keys for the default account.
    #[inline]
    pub fn get_default(&self) -> Account<H>
    where
        H: Clone,
    {
        self.get(Default::default()).unwrap()
    }

    /// Adds a new account to the map, returning the new account parameter.
    #[inline]
    pub fn create_account(&mut self) -> AccountIndex {
        self.accounts.create_account()
    }
}

impl<H, M> Default for AccountTable<H, M>
where
    H: Default + AccountCollection,
    M: AccountMap<Account = AccountIndex>,
{
    #[inline]
    fn default() -> Self {
        Self::new(Default::default())
    }
}
