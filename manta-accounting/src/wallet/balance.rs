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

//! Wallet Balance State
//!
//! This module defines the balance states of a wallet using the current private asset transfer
//! protocol. Applications which define balances beyond fungible assets should extend these
//! abstractions.

use crate::asset::{Asset, AssetId, AssetList, AssetValue};
use alloc::collections::btree_map::{BTreeMap, Entry as BTreeMapEntry};

#[cfg(feature = "std")]
use std::{
    collections::hash_map::{Entry as HashMapEntry, HashMap, RandomState},
    hash::BuildHasher,
};

/// Balance State
pub trait BalanceState: Default {
    /// Returns the current balance associated with this `id`.
    fn balance(&self, id: AssetId) -> AssetValue;

    /// Returns true if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    fn contains(&self, asset: Asset) -> bool {
        self.balance(asset.id) >= asset.value
    }

    /// Deposits `asset` into the balance state, increasing the balance of the asset stored at
    /// `asset.id` by an amount equal to `asset.value`.
    fn deposit(&mut self, asset: Asset);

    /// Deposits every asset in `assets` into the balance state.
    #[inline]
    fn deposit_all<I>(&mut self, assets: I)
    where
        I: IntoIterator<Item = Asset>,
    {
        assets.into_iter().for_each(move |a| self.deposit(a));
    }

    /// Withdraws `asset` from the balance state returning `false` if it would overdraw the balance.
    fn withdraw(&mut self, asset: Asset) -> bool;

    /// Withdraws every asset in `assets` from the balance state, returning `false` if it would
    /// overdraw the balance.
    #[inline]
    fn withdraw_all<I>(&mut self, assets: I) -> bool
    where
        I: IntoIterator<Item = Asset>,
    {
        for asset in AssetList::from_iter(assets) {
            if !self.withdraw(asset) {
                return false;
            }
        }
        true
    }

    /// Clears the entire balance state.
    fn clear(&mut self);
}

impl BalanceState for AssetList {
    #[inline]
    fn balance(&self, id: AssetId) -> AssetValue {
        self.value(id)
    }

    #[allow(clippy::only_used_in_recursion)] // NOTE: False-positive: rust-clippy/issues/8560
    #[inline]
    fn deposit(&mut self, asset: Asset) {
        self.deposit(asset);
    }

    #[allow(clippy::only_used_in_recursion)] // NOTE: False-positive: rust-clippy/issues/8560
    #[inline]
    fn withdraw(&mut self, asset: Asset) -> bool {
        self.withdraw(asset)
    }

    #[inline]
    fn clear(&mut self) {
        self.clear();
    }
}

/// Performs a withdraw on `balance` returning `false` if it would overflow.
#[inline]
fn withdraw(balance: Option<&mut AssetValue>, withdraw: AssetValue) -> bool {
    match balance {
        Some(balance) => {
            *balance = match balance.checked_sub(withdraw) {
                Some(balance) => balance,
                _ => return false,
            };
            true
        }
        _ => false,
    }
}

/// Adds implementation of [`BalanceState`] for a map type with the given `$entry` type.
macro_rules! impl_balance_state_map_body {
    ($entry:tt) => {
        #[inline]
        fn balance(&self, id: AssetId) -> AssetValue {
            self.get(&id).copied().unwrap_or_default()
        }

        #[inline]
        fn deposit(&mut self, asset: Asset) {
            if asset.is_zero() {
                return;
            }
            match self.entry(asset.id) {
                $entry::Vacant(entry) => {
                    entry.insert(asset.value);
                }
                $entry::Occupied(entry) => *entry.into_mut() += asset.value,
            }
        }

        #[inline]
        fn withdraw(&mut self, asset: Asset) -> bool {
            if !asset.is_zero() {
                withdraw(self.get_mut(&asset.id), asset.value)
            } else {
                true
            }
        }

        #[inline]
        fn clear(&mut self) {
            self.clear();
        }
    };
}

/// B-Tree Map [`BalanceState`] Implementation
pub type BTreeMapBalanceState = BTreeMap<AssetId, AssetValue>;

impl BalanceState for BTreeMapBalanceState {
    impl_balance_state_map_body! { BTreeMapEntry }
}

/// Hash Map [`BalanceState`] Implementation
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub type HashMapBalanceState<S = RandomState> = HashMap<AssetId, AssetValue, S>;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<S> BalanceState for HashMapBalanceState<S>
where
    S: BuildHasher + Default,
{
    impl_balance_state_map_body! { HashMapEntry }
}

/// Testing Framework
#[cfg(any(feature = "test", test))]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use manta_crypto::rand::{CryptoRng, RngCore, Sample};

    #[cfg(test)]
    use manta_crypto::rand::OsRng;

    /// Asserts that a random deposit and withdraw is always valid.
    #[inline]
    pub fn assert_valid_withdraw<S, R>(state: &mut S, rng: &mut R)
    where
        S: BalanceState,
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset = Asset::gen(rng);
        let initial_balance = state.balance(asset.id);
        state.deposit(asset);
        assert_eq!(
            initial_balance + asset.value,
            state.balance(asset.id),
            "Current balance and sum of initial balance and new deposit should have been equal."
        );
        state.withdraw(asset);
        assert_eq!(
            initial_balance,
            state.balance(asset.id),
            "Initial and final balances should have been equal."
        );
    }

    /// Tests valid withdrawals for an [`AssetList`] balance state.
    #[test]
    fn asset_list_valid_withdraw() {
        assert_valid_withdraw(&mut AssetList::new(), &mut OsRng);
    }

    /// Tests valid withdrawals for a [`BTreeMapBalanceState`] balance state.
    #[test]
    fn btree_map_valid_withdraw() {
        assert_valid_withdraw(&mut BTreeMapBalanceState::new(), &mut OsRng);
    }

    /// Tests valid withdrawals for a [`HashMapBalanceState`] balance state.
    #[cfg(feature = "std")]
    #[test]
    fn hash_map_valid_withdraw() {
        assert_valid_withdraw(&mut HashMapBalanceState::new(), &mut OsRng);
    }
}
