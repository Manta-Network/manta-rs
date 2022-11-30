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

//! Manta Pay Signer Tools

use manta_accounting::wallet::signer;

#[cfg(feature = "groth16")]
use crate::config::{utxo::Checkpoint, Config};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod client;

#[cfg(feature = "wallet")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "wallet")))]
pub mod base;

/// Synchronization Request
pub type SyncRequest = signer::SyncRequest<Config, Checkpoint>;

/// Synchronization Response
pub type SyncResponse = signer::SyncResponse<Config, Checkpoint>;

/// Synchronization Error
pub type SyncError = signer::SyncError<Checkpoint>;

/// Synchronization Result
pub type SyncResult = signer::SyncResult<Config, Checkpoint>;

/// Signing Request
pub type SignRequest = signer::SignRequest<Config>;

/// Signing Response
pub type SignResponse = signer::SignResponse<Config>;

/// Signing Error
pub type SignError = signer::SignError<Config>;

/// Signing Result
pub type SignResult = signer::SignResult<Config>;

/// Receiving Key Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GetRequest {
    /// GET
    #[default]
    Get,
}

/// Testing Framework
#[cfg(test)]
pub mod test {
    /* TODO: move these to manta-pay
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
        ///
        #[cfg(feature = "std")]
        #[test]
        fn hash_map_full_withdraw() {
            assert_full_withdraw_should_remove_entry::<HashMapBalanceState, _>(&mut OsRng);
        }
    */
}
