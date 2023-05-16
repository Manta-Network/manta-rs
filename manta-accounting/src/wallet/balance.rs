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

use crate::asset::{Asset, AssetList};
use alloc::collections::btree_map::{BTreeMap, Entry as BTreeMapEntry};
use core::ops::AddAssign;
use manta_util::{
    iter::{ConvertItemRef, ExactSizeIterable, RefItem},
    num::CheckedSub,
};

#[cfg(feature = "std")]
use std::{
    collections::hash_map::{Entry as HashMapEntry, HashMap, RandomState},
    hash::BuildHasher,
    hash::Hash,
};

/// Balance State
pub trait BalanceState<I, V>:
    Default + ExactSizeIterable + for<'t> ConvertItemRef<'t, (&'t I, &'t V), Item = RefItem<'t, Self>>
{
    /// Returns the current balance associated with this `id`.
    fn balance(&self, id: &I) -> V;

    /// Returns true if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    fn contains(&self, asset: &Asset<I, V>) -> bool
    where
        V: PartialOrd,
    {
        self.balance(&asset.id) >= asset.value
    }

    /// Deposits `asset` into the balance state, increasing the balance of the asset stored at
    /// `asset.id` by an amount equal to `asset.value`.
    fn deposit(&mut self, asset: Asset<I, V>);

    /// Deposits every asset in `assets` into the balance state.
    #[inline]
    fn deposit_all<A>(&mut self, assets: A)
    where
        A: IntoIterator<Item = Asset<I, V>>,
    {
        assets.into_iter().for_each(move |a| self.deposit(a));
    }

    /// Withdraws `asset` from the balance state returning `false` if it would overdraw the balance.
    fn withdraw(&mut self, asset: Asset<I, V>) -> bool;

    /// Withdraws every asset in `assets` from the balance state, returning `false` if it would
    /// overdraw the balance.
    fn withdraw_all<A>(&mut self, assets: A) -> bool
    where
        A: IntoIterator<Item = Asset<I, V>>;

    /// Clears the entire balance state.
    fn clear(&mut self);
}

impl<I, V> BalanceState<I, V> for AssetList<I, V>
where
    I: Ord + core::fmt::Debug,
    V: AddAssign + Clone + Default + PartialEq + core::fmt::Debug,
    for<'v> &'v V: CheckedSub<Output = V>,
{
    #[inline]
    fn balance(&self, id: &I) -> V {
        self.value(id)
    }

    #[inline]
    fn deposit(&mut self, asset: Asset<I, V>) {
        self.deposit(asset);
    }

    #[inline]
    fn withdraw(&mut self, asset: Asset<I, V>) -> bool {
        self.withdraw(&asset)
    }

    #[inline]
    fn withdraw_all<A>(&mut self, assets: A) -> bool
    where
        A: IntoIterator<Item = Asset<I, V>>,
    {
        for asset in AssetList::from_iter(assets) {
            if !self.withdraw(&asset) {
                return false;
            }
        }
        true
    }

    #[inline]
    fn clear(&mut self) {
        self.clear();
    }
}

/// Adds implementation of [`BalanceState`] for a map type with the given `$entry` type.
macro_rules! impl_balance_state_map_body {
    ($I:ty, $V:ty, $entry:tt) => {
        #[inline]
        fn balance(&self, id: &$I) -> $V {
            self.get(id).cloned().unwrap_or_default()
        }

        #[inline]
        fn deposit(&mut self, asset: Asset<$I, $V>) {
            if asset.value == Default::default() {
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
        fn withdraw(&mut self, asset: Asset<$I, $V>) -> bool {
            if asset.value != Default::default() {
                if let $entry::Occupied(mut entry) = self.entry(asset.id) {
                    let balance = entry.get_mut();
                    if let Some(next_balance) = balance.checked_sub(&asset.value) {
                        if next_balance == Default::default() {
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
        fn withdraw_all<A>(&mut self, assets: A) -> bool
        where
            A: IntoIterator<Item = Asset<I, V>>,
        {
            for asset in AssetList::from_iter(assets) {
                if !self.withdraw(asset) {
                    return false;
                }
            }
            true
        }

        #[inline]
        fn clear(&mut self) {
            self.clear();
        }
    };
}

/// B-Tree Map [`BalanceState`] Implementation
pub type BTreeMapBalanceState<I, V> = BTreeMap<I, V>;

impl<I, V> BalanceState<I, V> for BTreeMapBalanceState<I, V>
where
    I: Ord + core::fmt::Debug,
    V: AddAssign + Clone + Default + PartialEq + core::fmt::Debug,
    for<'v> &'v V: CheckedSub<Output = V>,
{
    impl_balance_state_map_body! { I, V, BTreeMapEntry }
}

/// Hash Map [`BalanceState`] Implementation
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub type HashMapBalanceState<I, V, S = RandomState> = HashMap<I, V, S>;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<I, V, S> BalanceState<I, V> for HashMapBalanceState<I, V, S>
where
    I: Eq + Hash + Ord + core::fmt::Debug,
    V: AddAssign + Clone + Default + PartialEq + core::fmt::Debug,
    for<'v> &'v V: CheckedSub<Output = V>,
    S: BuildHasher + Default,
{
    impl_balance_state_map_body! { I, V, HashMapEntry }
}

/// Testing Framework
#[cfg(any(feature = "test", test))]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use crate::{asset::Asset, wallet::BalanceState};
    use core::{fmt::Debug, ops::Add};
    use manta_crypto::rand::{CryptoRng, RngCore, Sample};

    /// Asserts that a random deposit and withdraw is always valid.
    #[inline]
    pub fn assert_valid_withdraw<I, V, S, R>(state: &mut S, rng: &mut R)
    where
        I: Clone + Sample,
        V: Add<Output = V> + Clone + Debug + PartialEq + Sample,
        S: BalanceState<I, V>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset = Asset::gen(rng);
        let initial_balance = state.balance(&asset.id);
        state.deposit(asset.clone());
        assert_eq!(
            initial_balance.clone() + asset.clone().value,
            state.balance(&asset.id),
            "Current balance and sum of initial balance and new deposit should have been equal."
        );
        state.withdraw(asset.clone());
        assert_eq!(
            initial_balance,
            state.balance(&asset.id),
            "Initial and final balances should have been equal."
        );
    }
    /// Asserts that a maximal withdraw that leaves the state with no value should delete its memory
    /// for this process.
    #[inline]
    pub fn assert_full_withdraw_should_remove_entry<I, V, S, R>(rng: &mut R)
    where
        I: Clone + Sample,
        V: Clone + Debug + Default + PartialEq + Sample,
        S: BalanceState<I, V>,
        for<'s> &'s S: IntoIterator,
        for<'s> <&'s S as IntoIterator>::IntoIter: ExactSizeIterator,
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut state = S::default();
        let asset = Asset::gen(rng);
        let initial_length = state.into_iter().len();
        state.deposit(asset.clone());
        assert_eq!(
            initial_length + 1,
            state.into_iter().len(),
            "Length should have increased by one after depositing a new asset."
        );
        let balance = state.balance(&asset.id);
        state.withdraw(Asset {
            id: asset.clone().id,
            value: balance,
        });
        assert_eq!(
            state.balance(&asset.id),
            Default::default(),
            "Balance in the removed AssetId should be zero."
        );
        assert_eq!(
            initial_length,
            state.into_iter().len(),
            "Removed AssetId should remove its entry in the database."
        );
    }
}
