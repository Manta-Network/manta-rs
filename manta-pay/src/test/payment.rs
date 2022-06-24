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

//! Prove and Verify Functions for Benchmark and Test Purposes

use crate::config::{
    self, FullParameters, MerkleTreeConfiguration, Mint, MultiProvingContext, Parameters,
    PrivateTransfer, ProvingContext, Reclaim, UtxoAccumulatorModel,
};
use manta_accounting::{
    asset::{Asset, AssetId},
    transfer::SpendingKey,
};
use manta_crypto::{
    accumulator::Accumulator,
    merkle_tree::{forest::TreeArrayMerkleForest, full::Full},
    rand::{CryptoRng, Rand, RngCore, Sample},
};

/// UTXO Accumulator for Building Test Circuits
pub type UtxoAccumulator =
    TreeArrayMerkleForest<MerkleTreeConfiguration, Full<MerkleTreeConfiguration>, 256>;

/// Generates a proof for a [`Mint`] transaction.
#[inline]
pub fn prove_mint<R>(
    proving_context: &ProvingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    asset: Asset,
    rng: &mut R,
) -> config::TransferPost
where
    R: CryptoRng + RngCore + ?Sized,
{
    Mint::from_spending_key(parameters, &SpendingKey::gen(rng), asset, rng)
        .into_post(
            FullParameters::new(parameters, utxo_accumulator_model),
            proving_context,
            rng,
        )
        .expect("Unable to build MINT proof.")
}

/// Samples a [`Mint`] spender.
///
/// The spender is used in the [`prove_private_transfer`] and [`prove_reclaim`] functions for
/// benchmarking. Note that the [`Mint`] proof is not returned since it is not used when proving a
/// [`PrivateTransfer`] or [`Reclaim`].
#[inline]
pub fn sample_mint_spender<R>(
    parameters: &Parameters,
    utxo_accumulator: &mut UtxoAccumulator,
    asset: Asset,
    rng: &mut R,
) -> (config::SpendingKey, config::Sender)
where
    R: CryptoRng + RngCore + ?Sized,
{
    let spending_key = SpendingKey::new(rng.gen(), rng.gen());
    let (_, pre_sender) = Mint::internal_pair(parameters, &spending_key, asset, rng);
    let sender = pre_sender
        .insert_and_upgrade(utxo_accumulator)
        .expect("Just inserted so this should not fail.");
    (spending_key, sender)
}

/// Generates a proof for a [`PrivateTransfer`] transaction.
#[inline]
pub fn prove_private_transfer<R>(
    proving_context: &MultiProvingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    rng: &mut R,
) -> config::TransferPost
where
    R: CryptoRng + RngCore + ?Sized,
{
    let asset_id = AssetId(rng.gen());
    let asset_0 = asset_id.value(10_000);
    let asset_1 = asset_id.value(20_000);
    let mut utxo_accumulator = UtxoAccumulator::new(utxo_accumulator_model.clone());
    let (spending_key_0, sender_0) =
        sample_mint_spender(parameters, &mut utxo_accumulator, asset_0, rng);
    let (spending_key_1, sender_1) =
        sample_mint_spender(parameters, &mut utxo_accumulator, asset_1, rng);
    PrivateTransfer::build(
        [sender_0, sender_1],
        [
            spending_key_0.receiver(parameters, rng.gen(), asset_1),
            spending_key_1.receiver(parameters, rng.gen(), asset_0),
        ],
    )
    .into_post(
        FullParameters::new(parameters, utxo_accumulator.model()),
        &proving_context.private_transfer,
        rng,
    )
    .expect("Unable to build PRIVATE_TRANSFER proof.")
}

/// Generates a proof for a [`Reclaim`] transaction.
#[inline]
pub fn prove_reclaim<R>(
    proving_context: &MultiProvingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    rng: &mut R,
) -> config::TransferPost
where
    R: CryptoRng + RngCore + ?Sized,
{
    let asset_id = AssetId(rng.gen());
    let asset_0 = asset_id.value(10_000);
    let asset_1 = asset_id.value(20_000);
    let mut utxo_accumulator = UtxoAccumulator::new(utxo_accumulator_model.clone());
    let (spending_key_0, sender_0) =
        sample_mint_spender(parameters, &mut utxo_accumulator, asset_0, rng);
    let (_, sender_1) = sample_mint_spender(parameters, &mut utxo_accumulator, asset_1, rng);
    Reclaim::build(
        [sender_0, sender_1],
        [spending_key_0.receiver(parameters, rng.gen(), asset_1)],
        asset_0,
    )
    .into_post(
        FullParameters::new(parameters, utxo_accumulator.model()),
        &proving_context.reclaim,
        rng,
    )
    .expect("Unable to build RECLAIM proof.")
}
