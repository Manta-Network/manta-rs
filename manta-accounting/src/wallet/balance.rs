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

    #[inline]
    fn deposit(&mut self, asset: Asset) {
        self.deposit(asset);
    }

    #[inline]
    fn withdraw(&mut self, asset: Asset) -> bool {
        self.withdraw(asset)
    }

    #[inline]
    fn clear(&mut self) {
        self.clear();
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
                if let $entry::Occupied(mut entry) = self.entry(asset.id) {
                    let balance = entry.get_mut();
                    if let Some(next_balance) = balance.checked_sub(asset.value) {
                        if next_balance == 0 {
                            entry.remove();
                        } else {
                            *balance = next_balance;
                        }
                        return true;
                    }
                }
                false
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

    /// Asserts that a maximal withdraw that leaves the state with no value should delete its memory
    /// for this process.
    #[inline]
    pub fn assert_full_withdraw_should_remove_entry<S, R>(rng: &mut R)
    where
        S: BalanceState,
        for<'s> &'s S: IntoIterator,
        for<'s> <&'s S as IntoIterator>::IntoIter: ExactSizeIterator,
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut state = S::default();
        let asset = Asset::gen(rng);
        let initial_length = state.into_iter().len();
        state.deposit(asset);
        assert_eq!(
            initial_length + 1,
            state.into_iter().len(),
            "Length should have increased by one after depositing a new asset."
        );
        let balance = state.balance(asset.id);
        state.withdraw(asset.id.with(balance));
        assert_eq!(
            state.balance(asset.id),
            0,
            "Balance in the removed AssetId should be zero."
        );
        assert_eq!(
            initial_length,
            state.into_iter().len(),
            "Removed AssetId should remove its entry in the database."
        );
    }

    /// Defines the tests across multiple different [`BalanceState`] types.
    macro_rules! define_tests {
        ($((
            $type:ty,
            $doc:expr,
            $valid_withdraw:ident,
            $full_withdraw:ident
        $(,)?)),*$(,)?) => {
            $(
                #[doc = "Tests valid withdrawals for an"]
                #[doc = $doc]
                #[doc = "balance state."]
                #[test]
                fn $valid_withdraw() {
                    let mut state = <$type>::default();
                    let mut rng = OsRng;
                    for _ in 0..0xFFFF {
                        assert_valid_withdraw(&mut state, &mut rng);
                    }
                }

                #[doc = "Tests that there are no empty entries in"]
                #[doc = $doc]
                #[doc = "with no value stored in them."]
                #[test]
                fn $full_withdraw() {
                    assert_full_withdraw_should_remove_entry::<$type, _>(&mut OsRng);
                }
            )*
        }
    }

    define_tests!(
        (
            AssetList,
            "[`AssetList`]",
            asset_list_valid_withdraw,
            asset_list_full_withdraw,
        ),
        (
            BTreeMapBalanceState,
            "[`BTreeMapBalanceState`]",
            btree_map_valid_withdraw,
            btree_map_full_withdraw,
        ),
    );

    /// Tests valid withdrawals for a [`HashMapBalanceState`] balance state.
    #[cfg(feature = "std")]
    #[test]
    fn hash_map_valid_withdraw() {
        assert_valid_withdraw(&mut HashMapBalanceState::new(), &mut OsRng);
    }

    ///
    #[cfg(feature = "std")]
    #[test]
    fn hash_map_full_withdraw() {
        assert_full_withdraw_should_remove_entry::<HashMapBalanceState, _>(&mut OsRng);
    }
}
