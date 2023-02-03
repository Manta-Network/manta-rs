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

//! Manta Pay Signer Methods

use crate::{
    config::{
        Address, IdentifiedAsset, IdentityProof, Transaction, TransactionData, TransferPost,
        UtxoAccumulatorModel,
    },
    signer::{
        base::{SignerParameters, UtxoAccumulator},
        AccountTable, AssetMap, Checkpoint, SignResult, SignerRng, SyncRequest, SyncResult,
    },
};
use manta_accounting::wallet::signer::methods;

/// Updates `assets`, `checkpoint` and `utxo_accumulator`, returning the new asset distribution.
#[allow(clippy::result_large_err)]
#[inline]
pub fn sync(
    parameters: &SignerParameters,
    accounts: &AccountTable,
    assets: &mut AssetMap,
    checkpoint: &mut Checkpoint,
    utxo_accumulator: &mut UtxoAccumulator,
    request: SyncRequest,
    rng: &mut SignerRng,
) -> SyncResult {
    methods::sync(
        parameters,
        accounts,
        assets,
        checkpoint,
        utxo_accumulator,
        request,
        rng,
    )
}

/// Signs the `transaction`, generating transfer posts.
#[inline]
pub fn sign(
    parameters: &SignerParameters,
    accounts: &AccountTable,
    assets: &AssetMap,
    utxo_accumulator: &mut UtxoAccumulator,
    transaction: Transaction,
    rng: &mut SignerRng,
) -> SignResult {
    methods::sign(
        parameters,
        accounts,
        assets,
        utxo_accumulator,
        transaction,
        rng,
    )
}

/// Returns the [`Address`] corresponding to `accounts`.
#[inline]
pub fn address(parameters: &SignerParameters, accounts: &AccountTable) -> Address {
    methods::address(parameters, accounts)
}

/// Returns the associated [`TransactionData`] of `post`. Returns `None` if `post` has an invalid shape,
/// or if `accounts` doesn't own the underlying assets in `post`.
#[inline]
pub fn transaction_data(
    parameters: &SignerParameters,
    accounts: &AccountTable,
    post: TransferPost,
) -> Option<TransactionData> {
    methods::transaction_data(parameters, accounts, post)
}

/// Generates an [`IdentityProof`] for `identified_asset` by signing a
/// virtual [`ToPublic`](manta_accounting::transfer::canonical::ToPublic) transaction.
#[inline]
pub fn identity_proof(
    parameters: &SignerParameters,
    accounts: &AccountTable,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    identified_asset: IdentifiedAsset,
    rng: &mut SignerRng,
) -> Option<IdentityProof> {
    methods::identity_proof(
        parameters,
        accounts,
        utxo_accumulator_model,
        identified_asset,
        rng,
    )
}