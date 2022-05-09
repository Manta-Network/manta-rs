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

//! Precomputed Transactions

use manta_accounting::{
    asset::Asset,
    transfer::{self, SpendingKey},
};
use manta_crypto::{
    accumulator::Accumulator,
    constraint::ProofSystem as _,
    merkle_tree::{forest::TreeArrayMerkleForest, full::Full},
    rand::{CryptoRng, Rand, RngCore, Sample},
};
use manta_pay::config::{
    self, FullParameters, MerkleTreeConfiguration, Mint, MultiProvingContext,
    MultiVerifyingContext, Parameters, PrivateTransfer, ProofSystem, ProvingContext, Reclaim,
    UtxoAccumulatorModel, VerifyingContext,
};

/// UTXO Accumulator for Building Circuits
type UtxoAccumulator =
    TreeArrayMerkleForest<MerkleTreeConfiguration, Full<MerkleTreeConfiguration>, 256>;

/// Parameter Generation Seed
///
/// This is a nothing-up-my-sleve parameter generation number. Its just the numbers from `0` to `31`
/// as `u8` bytes.
///
/// # Warning
///
/// Right now, this seed is also used to generate to the proving and verifying keys for the ZKP
/// circuits. This is not safe, and a real system must use a Multi-Party-Computation to arrive at
/// the ZKP parameters.
pub const SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// Asserts that `post` represents a valid `Transfer` verifying against `verifying_context`.
#[inline]
pub fn assert_valid_proof(verifying_context: &VerifyingContext, post: &config::TransferPost) {
    assert!(
        ProofSystem::verify(
            verifying_context,
            &post.generate_proof_input(),
            &post.validity_proof,
        )
        .expect("Unable to verify proof."),
        "Invalid proof: {:?}.",
        post
    );
}

/// Samples the proof of a [`Mint`] transaction.
#[inline]
pub fn bench_mint_prove<R>(
    proving_context: &ProvingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    asset: Asset,
    rng: &mut R,
) -> config::TransferPost
where
    R: CryptoRng + RngCore + ?Sized,
{
    let mint = Mint::from_spending_key(parameters, &SpendingKey::gen(rng), asset, rng)
        .into_post(
            FullParameters::new(parameters, utxo_accumulator_model),
            proving_context,
            rng,
        )
        .expect("Unable to build MINT proof.");
    mint
}

/// Samples a [`Mint`] transaction.
#[inline]
pub fn bench_mint_prove_and_verify<R>(
    proving_context: &ProvingContext,
    verifying_context: &VerifyingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    asset: Asset,
    rng: &mut R,
) where
    R: CryptoRng + RngCore + ?Sized,
{
    let mint = bench_mint_prove(
        proving_context,
        parameters,
        utxo_accumulator_model,
        asset,
        rng,
    );
    assert_valid_proof(verifying_context, &mint);
}

/// Samples num [`Mint`]s
#[inline]
pub fn sample_num_mints<R>(
    num: usize,
    proving_context: &MultiProvingContext,
    verifying_context: &MultiVerifyingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    assets: &[Asset],
    rng: &mut R,
) -> (
    UtxoAccumulator,
    Vec<config::SpendingKey>,
    Vec<config::Sender>,
)
where
    R: CryptoRng + RngCore + ?Sized,
{
    let mut utxo_accumulator = UtxoAccumulator::new(utxo_accumulator_model.clone());
    let mut vec_spending_keys = Vec::with_capacity(num);
    let mut vec_senders = Vec::with_capacity(num);

    for i in 0..num {
        let spending_key = SpendingKey::new(rng.gen(), rng.gen());
        let (mint, pre_sender) = transfer::test::sample_mint(
            &proving_context.mint,
            FullParameters::new(parameters, utxo_accumulator.model()),
            &spending_key,
            assets[i],
            rng,
        )
        .expect("Unable to build MINT proof.");
        assert_valid_proof(&verifying_context.mint, &mint);
        let sender = pre_sender
            .insert_and_upgrade(&mut utxo_accumulator)
            .expect("Just inserted so this should not fail.");

        vec_spending_keys[i] = spending_key;
        vec_senders[i] = sender;
    }

    (utxo_accumulator, vec_spending_keys, vec_senders)
}

/// a wrapper for 2 mints and 1 private transfer
#[inline]
pub fn bench_private_transfer_wrapper<R>(
    proving_context: &MultiProvingContext,
    verifying_context: &MultiVerifyingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    assets: Vec<Asset>,
    rng: &mut R,
) where
    R: CryptoRng + RngCore + ?Sized,
{
    let mut utxo_accumulator = UtxoAccumulator::new(utxo_accumulator_model.clone());

    let spending_key_0 = SpendingKey::new(rng.gen(), rng.gen());
    let (mint_0, pre_sender_0) = transfer::test::sample_mint(
        &proving_context.mint,
        FullParameters::new(parameters, utxo_accumulator.model()),
        &spending_key_0,
        assets[0],
        rng,
    )
    .expect("Unable to build MINT proof.");
    assert_valid_proof(&verifying_context.mint, &mint_0);
    let sender_0 = pre_sender_0
        .insert_and_upgrade(&mut utxo_accumulator)
        .expect("Just inserted so this should not fail.");

    let spending_key_1 = SpendingKey::new(rng.gen(), rng.gen());
    let (mint_1, pre_sender_1) = transfer::test::sample_mint(
        &proving_context.mint,
        FullParameters::new(parameters, utxo_accumulator.model()),
        &spending_key_1,
        assets[1],
        rng,
    )
    .expect("Unable to build MINT proof.");
    assert_valid_proof(&verifying_context.mint, &mint_1);
    let sender_1 = pre_sender_1
        .insert_and_upgrade(&mut utxo_accumulator)
        .expect("Just inserted so this should not fail.");

    let private_transfer = PrivateTransfer::build(
        [sender_0, sender_1],
        [
            spending_key_0.receiver(parameters, rng.gen(), assets[1]),
            spending_key_1.receiver(parameters, rng.gen(), assets[0]),
        ],
    )
    .into_post(
        FullParameters::new(parameters, utxo_accumulator.model()),
        &proving_context.private_transfer,
        rng,
    )
    .expect("Unable to build PRIVATE_TRANSFER proof.");
    assert_valid_proof(&verifying_context.private_transfer, &private_transfer);
}

/// a wrapper for 2 mints and 1 reclaim
#[inline]
pub fn bench_reclaim_wrapper<R>(
    proving_context: &MultiProvingContext,
    verifying_context: &MultiVerifyingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    assets: Vec<Asset>,
    rng: &mut R,
) where
    R: CryptoRng + RngCore + ?Sized,
{
    let mut utxo_accumulator = UtxoAccumulator::new(utxo_accumulator_model.clone());

    let spending_key_0 = SpendingKey::new(rng.gen(), rng.gen());
    let (mint_0, pre_sender_0) = transfer::test::sample_mint(
        &proving_context.mint,
        FullParameters::new(parameters, utxo_accumulator.model()),
        &spending_key_0,
        assets[0],
        rng,
    )
    .expect("Unable to build MINT proof.");
    assert_valid_proof(&verifying_context.mint, &mint_0);
    let sender_0 = pre_sender_0
        .insert_and_upgrade(&mut utxo_accumulator)
        .expect("Just inserted so this should not fail.");

    let spending_key_1 = SpendingKey::new(rng.gen(), rng.gen());
    let (mint_1, pre_sender_1) = transfer::test::sample_mint(
        &proving_context.mint,
        FullParameters::new(parameters, utxo_accumulator.model()),
        &spending_key_1,
        assets[1],
        rng,
    )
    .expect("Unable to build MINT proof.");
    assert_valid_proof(&verifying_context.mint, &mint_1);
    let sender_1 = pre_sender_1
        .insert_and_upgrade(&mut utxo_accumulator)
        .expect("Just inserted so this should not fail.");

    let reclaim = Reclaim::build(
        [sender_0, sender_1],
        [spending_key_0.receiver(parameters, rng.gen(), assets[1])],
        assets[0],
    )
    .into_post(
        FullParameters::new(parameters, utxo_accumulator.model()),
        &proving_context.reclaim,
        rng,
    )
    .expect("Unable to build RECLAIM proof.");
    assert_valid_proof(&verifying_context.reclaim, &reclaim);
}
