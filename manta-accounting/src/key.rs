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

use core::{
    cmp,
    fmt::{self, Debug},
    hash::Hash,
    iter,
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
    fn increment(&mut self) {
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
impl_index_type!(
    "Address Index",
    "AddressIndex",
    AddressIndexType,
    AddressIndex
);

/// Account
pub trait Account {
    /// Spending Key Type
    type SpendingKey;

    /// Address Type
    type Address;

    /// Account Key-Generation Parameters
    type Parameters;

    /// Returns the spending key associated to this account.
    fn spending_key(&self, parameters: &Self::Parameters) -> Self::SpendingKey;

    /// Returns the address at the given `index` for this account.
    fn address(&mut self, parameters: &Self::Parameters, index: AddressIndex) -> Self::Address;

    /// Returns the default address for this account.
    #[inline]
    fn default_address(&mut self, parameters: &Self::Parameters) -> Self::Address {
        self.address(parameters, Default::default())
    }
}

impl<A> Account for &mut A
where
    A: Account,
{
    type SpendingKey = A::SpendingKey;
    type Address = A::Address;
    type Parameters = A::Parameters;

    #[inline]
    fn spending_key(&self, parameters: &Self::Parameters) -> Self::SpendingKey {
        (**self).spending_key(parameters)
    }

    #[inline]
    fn address(&mut self, parameters: &Self::Parameters, index: AddressIndex) -> Self::Address {
        (*self).address(parameters, index)
    }

    #[inline]
    fn default_address(&mut self, parameters: &Self::Parameters) -> Self::Address {
        (*self).default_address(parameters)
    }
}

/// Spending Key Type
pub type SpendingKey<A> = <A as Account>::SpendingKey;

/// Address Type
pub type Address<A> = <A as Account>::Address;

/// Parameters Type
pub type Parameters<A> = <A as Account>::Parameters;

/// Limit Account
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct LimitAccount<A>
where
    A: Account,
{
    /// Account Data
    account: A,

    /// Address Limit
    address_limit: AddressIndex,
}

impl<A> LimitAccount<A>
where
    A: Account,
{
    /// Builds a new [`LimitAccount`] over `account` without checking that the `address_limit` is
    /// positive.
    #[inline]
    fn new_unchecked(account: A, address_limit: AddressIndex) -> Self {
        Self {
            account,
            address_limit,
        }
    }

    /// Builds a new [`LimitAccount`] over `account`.
    #[inline]
    pub fn new(account: A) -> Self {
        Self::new_unchecked(account, 1.into())
    }

    /// Builds a new [`LimitAccount`] over `account` with the given `address_limit`.
    ///
    /// # Panics
    ///
    /// This constructor panics if `address_limit == 0`.
    #[inline]
    pub fn with_limit(account: A, address_limit: AddressIndex) -> Self {
        assert!(
            address_limit.index() > 0,
            "Address limit should be positive."
        );
        Self::new_unchecked(account, address_limit)
    }

    /// Returns the next new address for `self`.
    #[inline]
    pub fn next_address(&mut self, parameters: &Parameters<Self>) -> Address<Self> {
        let address = self.account.address(parameters, self.address_limit);
        self.address_limit.increment();
        address
    }

    /// Returns an iterator over all of the already observed addresses.
    #[inline]
    pub fn iter_observed<'s>(
        &'s mut self,
        parameters: &'s Parameters<Self>,
    ) -> impl 's + Iterator<Item = Address<Self>> {
        (0..self.address_limit.index()).map(|i| self.account.address(parameters, i.into()))
    }

    /// Returns an iterator over all addresses beyond what have already been observed.
    #[inline]
    pub fn iter_new<'s>(
        &'s mut self,
        parameters: &'s Parameters<Self>,
    ) -> impl 's + Iterator<Item = Address<Self>> {
        iter::repeat_with(|| self.next_address(parameters))
    }
}

impl<A> Account for LimitAccount<A>
where
    A: Account,
{
    type SpendingKey = A::SpendingKey;
    type Address = A::Address;
    type Parameters = A::Parameters;

    #[inline]
    fn spending_key(&self, parameters: &Self::Parameters) -> Self::SpendingKey {
        self.account.spending_key(parameters)
    }

    #[inline]
    fn address(&mut self, parameters: &Self::Parameters, index: AddressIndex) -> Self::Address {
        self.address_limit = cmp::max(self.address_limit, index);
        self.account.address(parameters, index)
    }

    #[inline]
    fn default_address(&mut self, parameters: &Self::Parameters) -> Self::Address {
        self.account.default_address(parameters)
    }
}

/// Account Map
pub trait AccountMap {
    /// Account Type
    type Account: Account;

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
