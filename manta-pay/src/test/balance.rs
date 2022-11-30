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

//! Manta Pay Wallet Balance Testing

use crate::config::{AssetId, AssetValue};
use manta_accounting::{
    asset,
    wallet::balance::{
        self,
        test::{assert_full_withdraw_should_remove_entry, assert_valid_withdraw},
    },
};
use manta_crypto::rand::OsRng;

/// Asset List Type
type AssetList = asset::AssetList<AssetId, AssetValue>;

/// BTreeMap Balance State Type
type BTreeMapBalanceState = balance::BTreeMapBalanceState<AssetId, AssetValue>;

/// HashMap Balance State Type
#[cfg(feature = "std")]
type HashMapBalanceState = balance::HashMapBalanceState<AssetId, AssetValue>;

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
                        assert_full_withdraw_should_remove_entry::<_, _, $type, _>(&mut OsRng);
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
/// Tests that there are no empty entries in [`HashMapBalanceState`] with no value stored in them.
#[cfg(feature = "std")]
#[test]
fn hash_map_full_withdraw() {
    assert_full_withdraw_should_remove_entry::<_, _, HashMapBalanceState, _>(&mut OsRng);
}
