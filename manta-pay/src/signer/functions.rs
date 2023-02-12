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

//! Manta Pay Signer Functions

use crate::{
    config::{
        Address, Config, IdentifiedAsset, IdentityProof, MultiProvingContext, Parameters,
        Transaction, TransactionData, TransferPost, UtxoAccumulatorModel,
    },
    key::{KeySecret, Mnemonic},
    signer::{
        base::{Signer, SignerParameters, UtxoAccumulator},
        AccountTable, AssetMap, Checkpoint, SignResult, SignerRng, SyncRequest, SyncResult,
    },
};
use manta_accounting::wallet::signer::{functions, StorageState};
use manta_crypto::{accumulator::Accumulator, rand::FromEntropy};

/// Builds a new [`Signer`] from `mnemonic`, `password`, `parameters`, `proving_context`
/// and `utxo_accumulator`.
#[inline]
pub fn new_signer(
    mnemonic: Mnemonic,
    password: &str,
    parameters: Parameters,
    proving_context: MultiProvingContext,
    utxo_accumulator: UtxoAccumulator,
) -> Signer {
    Signer::new(
        AccountTable::new(KeySecret::new(mnemonic, password)),
        parameters,
        proving_context,
        utxo_accumulator,
        FromEntropy::from_entropy(),
    )
}

/// Builds a new [`Signer`] from `mnemonic`, `password`, `parameters`, `proving_context`
/// and `utxo_accumulator_model`.
///
/// # Implementation Note
///
/// The signer initialized in this way has an empty state and must be synchronized from scratch,
/// which is a time-consuming operation. One should favor the `new_signer` and
/// `initialize_signer_from_storage` functions when possible.
#[inline]
pub fn new_signer_from_model(
    mnemonic: Mnemonic,
    password: &str,
    parameters: Parameters,
    proving_context: MultiProvingContext,
    utxo_accumulator_model: &UtxoAccumulatorModel,
) -> Signer {
    Signer::new(
        AccountTable::new(KeySecret::new(mnemonic, password)),
        parameters,
        proving_context,
        Accumulator::empty(utxo_accumulator_model),
        FromEntropy::from_entropy(),
    )
}

/// Initializes a [`Signer`] from `storage_state`, `mnemonic`, `password`,
/// `parameters` and `proving_context`.
pub fn initialize_signer_from_storage(
    storage_state: &StorageState<Config>,
    mnemonic: Mnemonic,
    password: &str,
    parameters: Parameters,
    proving_context: MultiProvingContext,
) -> Signer {
    storage_state.initialize_signer(
        AccountTable::new(KeySecret::new(mnemonic, password)),
        parameters,
        proving_context,
    )
}

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
    functions::sync(
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
    functions::sign(
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
    functions::address(parameters, accounts)
}

/// Returns the associated [`TransactionData`] of `post`. Returns `None` if `post` has an invalid shape,
/// or if `accounts` doesn't own the underlying assets in `post`.
#[inline]
pub fn transaction_data(
    parameters: &SignerParameters,
    accounts: &AccountTable,
    post: TransferPost,
) -> Option<TransactionData> {
    functions::transaction_data(parameters, accounts, post)
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
    functions::identity_proof(
        parameters,
        accounts,
        utxo_accumulator_model,
        identified_asset,
        rng,
    )
}
