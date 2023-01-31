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

//! Manta Pay Stateless Signer

use crate::{
    config::{
        Address, Config, IdentifiedAsset, IdentityProof, Transaction, TransactionData,
        TransferPost, UtxoAccumulatorModel,
    },
    signer::{base::UtxoAccumulator, AccountTable, AssetMap, Checkpoint, SignerRng, SyncRequest},
};
use manta_accounting::wallet::{self, stateless_signer};

pub use wallet::stateless_signer::StatelessSignerConnection;

/// Stateless Signer Type
pub type StatelessSigner = wallet::stateless_signer::StatelessSigner<Config>;

/// Stateless Synchronization Request
pub type StatelessSyncRequest = stateless_signer::StatelessSyncRequest<Config>;

/// Stateless Synchronization Response
pub type StatelessSyncResponse = stateless_signer::StatelessSyncResponse<Config, Checkpoint>;

/// Stateless Synchronization Result
pub type StatelessSyncResult = stateless_signer::StatelessSyncResult<Config, Checkpoint>;

/// Stateless Signing Request
pub type StatelessSignRequest = stateless_signer::StatelessSignRequest<Config>;

/// Stateless Signing Response
pub type StatelessSignResponse = stateless_signer::StatelessSignResponse<Config>;

/// Stateless Signing Result
pub type StatelessSignResult = stateless_signer::StatelessSignResult<Config>;

/// Stateless Address Request
pub type StatelessAddressRequest = stateless_signer::StatelessAddressRequest<Config>;

/// Stateless Transaction Data Request
pub type StatelessTransactionDataRequest =
    stateless_signer::StatelessTransactionDataRequest<Config>;

/// Stateless Identity Proof Request
pub type StatelessIdentityRequest = stateless_signer::StatelessIdentityRequest<Config>;

/// Updates `assets`, `checkpoint` and `utxo_accumulator`, returning the new asset distribution.
#[allow(clippy::result_large_err)]
#[inline]
pub fn sync(
    stateless_signer: &StatelessSigner,
    accounts: &AccountTable,
    assets: AssetMap,
    checkpoint: Checkpoint,
    utxo_accumulator: UtxoAccumulator,
    request: SyncRequest,
    rng: &mut SignerRng,
) -> StatelessSyncResult {
    stateless_signer.sync(accounts, assets, checkpoint, utxo_accumulator, request, rng)
}

/// Signs the `transaction`, generating transfer posts.
#[inline]
pub fn sign(
    stateless_signer: &StatelessSigner,
    accounts: &AccountTable,
    assets: &AssetMap,
    utxo_accumulator: UtxoAccumulator,
    transaction: Transaction,
    rng: &mut SignerRng,
) -> StatelessSignResult {
    stateless_signer.sign(accounts, assets, utxo_accumulator, transaction, rng)
}

/// Returns the [`Address`] corresponding to `accounts`.
#[inline]
pub fn address(stateless_signer: &StatelessSigner, accounts: &AccountTable) -> Address {
    stateless_signer.address(accounts)
}

/// Returns the associated [`TransactionData`] of `post`. Returns `None` if `post` has an invalid shape,
/// or if `accounts` doesn't own the underlying assets in `post`.
#[inline]
pub fn transaction_data(
    stateless_signer: &StatelessSigner,
    accounts: &AccountTable,
    post: TransferPost,
) -> Option<TransactionData> {
    stateless_signer.transaction_data(accounts, post)
}

/// Generates an [`IdentityProof`] for `identified_asset` by signing a
/// virtual [`ToPublic`](manta_accounting::transfer::canonical::ToPublic) transaction.
#[inline]
pub fn identity_proof(
    stateless_signer: &StatelessSigner,
    accounts: &AccountTable,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    identified_asset: IdentifiedAsset,
    rng: &mut SignerRng,
) -> Option<IdentityProof> {
    stateless_signer.identity_proof(accounts, utxo_accumulator_model, identified_asset, rng)
}
