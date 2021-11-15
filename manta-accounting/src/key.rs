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

// TODO: Make [`Account`] more useful for managing accounts.

use core::{fmt::Debug, hash::Hash};

/// Hierarchical Key Table Parameter
pub trait HierarchicalKeyTableParameter: Clone + Default + PartialOrd {
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
        account: &Self::Account,
        index: &Self::Index,
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
        account: &Self::Account,
        index: &Self::Index,
        kind: &Self::Kind,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).get(account, index, kind)
    }
}

/// Account Index with Table
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "H: Clone,"),
    Copy(bound = "H: Copy, H::Account: Copy, H::Index: Copy"),
    Debug(bound = "H: Debug, H::Account: Debug, H::Index: Debug"),
    Default(bound = "H: Default"),
    Eq(bound = "H: Eq, H::Account: Eq, H::Index: Eq"),
    Hash(bound = "H: Hash, H::Account: Hash, H::Index: Hash"),
    PartialEq(bound = "H: PartialEq")
)]
pub struct Account<H>
where
    H: HierarchicalKeyTable,
{
    /// Hierarchical Key Table
    table: H,

    /// Account Identifier
    account: H::Account,

    /// Latest Index
    latest_index: H::Index,
}

impl<H> Account<H>
where
    H: HierarchicalKeyTable,
{
    /// Builds a new [`Account`] for `table` and the given `account` identifier.
    #[inline]
    pub fn new(table: H, account: H::Account) -> Self {
        Self::with_index(table, account, Default::default())
    }

    /// Builds a new [`Account`] for `table` and the given `account` identifier and `latest_index`.
    #[inline]
    pub fn with_index(table: H, account: H::Account, latest_index: H::Index) -> Self {
        Self {
            table,
            account,
            latest_index,
        }
    }

    /// Returns the key of the given `kind` for `self`.
    #[inline]
    pub fn key(&self, kind: &H::Kind) -> Result<H::SecretKey, H::Error> {
        self.table.get(&self.account, &self.latest_index, kind)
    }
}
