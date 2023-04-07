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
        Address, AuthorizationContext, Config, EmbeddedScalar, FullParameters, MultiProvingContext,
        Parameters, UtxoAccumulatorModel,
    },
    key::{KeySecret, Mnemonic},
    signer::{
        base::{Signer, UtxoAccumulator},
        AccountTable, StorageState, StorageStateOption,
    },
};
use manta_accounting::{key::DeriveAddress, wallet::signer::functions};
use manta_crypto::{accumulator::Accumulator, rand::FromEntropy};

/// Builds a new [`Signer`] from `parameters` and `proving_context`,
/// loading its state from `storage_state`, if possible.
#[inline]
pub fn new_signer(
    parameters: FullParameters,
    proving_context: MultiProvingContext,
    storage_state: &StorageStateOption,
) -> Signer {
    let mut signer = new_signer_from_model(
        parameters.base,
        proving_context,
        &parameters.utxo_accumulator_model,
    );
    if let Some(state) = storage_state {
        state.update_signer(&mut signer);
    }
    signer
}

/// Builds a new [`StorageStateOption`] from `signer`.
#[inline]
pub fn get_storage(signer: &Signer) -> StorageStateOption {
    Some(StorageState::from_signer(signer))
}

/// Tries to update `signer` from `storage_state`.
#[inline]
pub fn set_storage(signer: &mut Signer, storage_state: &StorageStateOption) -> bool {
    if let Some(storage_state) = storage_state {
        storage_state.update_signer(signer);
        return true;
    }
    false
}

/// Builds a new [`Signer`] `parameters`, `proving_context` and `utxo_accumulator`.
#[inline]
fn new_signer_from_accumulator(
    parameters: Parameters,
    proving_context: MultiProvingContext,
    utxo_accumulator: UtxoAccumulator,
) -> Signer {
    Signer::new(
        parameters,
        proving_context,
        utxo_accumulator,
        FromEntropy::from_entropy(),
    )
}

/// Builds a new [`Signer`] from `parameters`, `proving_context`
/// and `utxo_accumulator_model`.
///
/// # Implementation Note
///
/// The signer initialized in this way has an empty state and must be synchronized from scratch,
/// which is a time-consuming operation. One should favor the `new_signer` and
/// `initialize_signer_from_storage` functions when possible.
#[inline]
pub fn new_signer_from_model(
    parameters: Parameters,
    proving_context: MultiProvingContext,
    utxo_accumulator_model: &UtxoAccumulatorModel,
) -> Signer {
    new_signer_from_accumulator(
        parameters,
        proving_context,
        Accumulator::empty(utxo_accumulator_model),
    )
}

/// Creates an [`AccountTable`] from `mnemonic`.
#[inline]
pub fn accounts_from_mnemonic(mnemonic: Mnemonic) -> AccountTable {
    AccountTable::new(KeySecret::new(mnemonic, ""))
}

/// Creates an [`AuthorizationContext`] from `mnemonic` and `parameters`.
#[inline]
pub fn authorization_context_from_mnemonic(
    mnemonic: Mnemonic,
    parameters: &Parameters,
) -> AuthorizationContext {
    functions::default_authorization_context::<Config>(
        &AccountTable::new(KeySecret::new(mnemonic, "")),
        parameters,
    )
}

/// Creates a viewing key from `mnemonic`.
#[inline]
pub fn viewing_key_from_mnemonic(mnemonic: Mnemonic, parameters: &Parameters) -> EmbeddedScalar {
    *authorization_context_from_mnemonic(mnemonic, parameters)
        .viewing_key(&parameters.base.viewing_key_derivation_function, &mut ())
}

/// Creates an [`Address`] from `mnemonic`.
#[inline]
pub fn address_from_mnemonic(mnemonic: Mnemonic, parameters: &Parameters) -> Address {
    accounts_from_mnemonic(mnemonic)
        .get_default()
        .address(parameters)
}
