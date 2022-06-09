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

//! ## Manta Pay UTXO Binary Compatibility
//! This test checks if current implementation is compatible with precomputed transactions in Manta SDK.

// This test is adapted from https://github.com/Manta-Network/Manta/blob/1c5c4b8750d06cb028fb555813414a5802554817/pallets/manta-pay/src/bin/precompute_coins.rs

use crate::config::{
    self, FullParameters, MerkleTreeConfiguration, Mint, MultiProvingContext,
    MultiVerifyingContext, NoteEncryptionScheme, Parameters, PrivateTransfer, ProofSystem,
    ProvingContext, Reclaim, TransferPost, UtxoAccumulatorModel, UtxoCommitmentScheme,
    VerifyingContext, VoidNumberCommitmentScheme,
};
use anyhow::Result;
use ark_std::rand::thread_rng;
use manta_accounting::{
    asset::{Asset, AssetId},
    transfer::{self, SpendingKey},
};
use manta_crypto::{
    accumulator::Accumulator,
    constraint::ProofSystem as _,
    merkle_tree::{forest::TreeArrayMerkleForest, full::Full},
    rand::{CryptoRng, Rand, RngCore, Sample},
};
use manta_util::codec::{Decode, IoReader};
use std::{fs::File, path::Path};

/// UTXO Accumulator for Building Circuits
type UtxoAccumulator =
    TreeArrayMerkleForest<MerkleTreeConfiguration, Full<MerkleTreeConfiguration>, 256>;

/// Loads parameters from the SDK, using `directory` as a temporary directory to store files.
#[inline]
fn load_parameters(
    directory: &Path,
) -> Result<(
    MultiProvingContext,
    MultiVerifyingContext,
    Parameters,
    UtxoAccumulatorModel,
)> {
    println!("Loading parameters...");
    let mint_path = directory.join("mint.dat");
    manta_sdk::pay::testnet::proving::Mint::download(&mint_path)?;
    let private_transfer_path = directory.join("private-transfer.dat");
    manta_sdk::pay::testnet::proving::PrivateTransfer::download(&private_transfer_path)?;
    let reclaim_path = directory.join("reclaim.dat");
    manta_sdk::pay::testnet::proving::Reclaim::download(&reclaim_path)?;
    let proving_context = MultiProvingContext {
        mint: ProvingContext::decode(IoReader(File::open(mint_path)?))
            .expect("Unable to decode MINT proving context."),
        private_transfer: ProvingContext::decode(IoReader(File::open(private_transfer_path)?))
            .expect("Unable to decode PRIVATE_TRANSFER proving context."),
        reclaim: ProvingContext::decode(IoReader(File::open(reclaim_path)?))
            .expect("Unable to decode RECLAIM proving context."),
    };
    let verifying_context = MultiVerifyingContext {
        mint: VerifyingContext::decode(
            manta_sdk::pay::testnet::verifying::Mint::get().expect("Checksum did not match."),
        )
        .expect("Unable to decode MINT verifying context."),
        private_transfer: VerifyingContext::decode(
            manta_sdk::pay::testnet::verifying::PrivateTransfer::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode PRIVATE_TRANSFER verifying context."),
        reclaim: VerifyingContext::decode(
            manta_sdk::pay::testnet::verifying::Reclaim::get().expect("Checksum did not match."),
        )
        .expect("Unable to decode RECLAIM verifying context."),
    };
    let parameters = Parameters {
        note_encryption_scheme: NoteEncryptionScheme::decode(
            manta_sdk::pay::testnet::parameters::NoteEncryptionScheme::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode NOTE_ENCRYPTION_SCHEME parameters."),
        utxo_commitment: UtxoCommitmentScheme::decode(
            manta_sdk::pay::testnet::parameters::UtxoCommitmentScheme::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode UTXO_COMMITMENT_SCHEME parameters."),
        void_number_commitment: VoidNumberCommitmentScheme::decode(
            manta_sdk::pay::testnet::parameters::VoidNumberCommitmentScheme::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode VOID_NUMBER_COMMITMENT_SCHEME parameters."),
    };
    println!("Loading parameters Done.");
    Ok((
        proving_context,
        verifying_context,
        parameters,
        UtxoAccumulatorModel::decode(
            manta_sdk::pay::testnet::parameters::UtxoAccumulatorModel::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode UTXO_ACCUMULATOR_MODEL."),
    ))
}

/// Asserts that `post` represents a valid `Transfer` verifying against `verifying_context`.
#[inline]
fn assert_valid_proof(verifying_context: &VerifyingContext, post: &config::TransferPost) {
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

/// Samples a [`Mint`] transaction.
#[inline]
fn sample_mint<R>(
    proving_context: &ProvingContext,
    verifying_context: &VerifyingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    asset: Asset,
    rng: &mut R,
) -> TransferPost
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
    assert_valid_proof(verifying_context, &mint);
    mint
}

/// Samples a [`PrivateTransfer`] transaction under two [`Mint`]s.
#[inline]
fn sample_private_transfer<R>(
    proving_context: &MultiProvingContext,
    verifying_context: &MultiVerifyingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    asset_0: Asset,
    asset_1: Asset,
    rng: &mut R,
) -> ([TransferPost; 2], TransferPost)
where
    R: CryptoRng + RngCore + ?Sized,
{
    let mut utxo_accumulator = UtxoAccumulator::new(utxo_accumulator_model.clone());
    let spending_key_0 = SpendingKey::new(rng.gen(), rng.gen());
    let (mint_0, pre_sender_0) = transfer::test::sample_mint(
        &proving_context.mint,
        FullParameters::new(parameters, utxo_accumulator.model()),
        &spending_key_0,
        asset_0,
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
        asset_1,
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
            spending_key_0.receiver(parameters, rng.gen(), asset_1),
            spending_key_1.receiver(parameters, rng.gen(), asset_0),
        ],
    )
    .into_post(
        FullParameters::new(parameters, utxo_accumulator.model()),
        &proving_context.private_transfer,
        rng,
    )
    .expect("Unable to build PRIVATE_TRANSFER proof.");
    assert_valid_proof(&verifying_context.private_transfer, &private_transfer);
    ([mint_0, mint_1], private_transfer)
}

/// Samples a [`Reclaim`] transaction under two [`Mint`]s.
#[inline]
fn sample_reclaim<R>(
    proving_context: &MultiProvingContext,
    verifying_context: &MultiVerifyingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    asset_0: Asset,
    asset_1: Asset,
    rng: &mut R,
) -> ([TransferPost; 2], TransferPost)
where
    R: CryptoRng + RngCore + ?Sized,
{
    let mut utxo_accumulator = UtxoAccumulator::new(utxo_accumulator_model.clone());
    let spending_key_0 = SpendingKey::new(rng.gen(), rng.gen());
    let (mint_0, pre_sender_0) = transfer::test::sample_mint(
        &proving_context.mint,
        FullParameters::new(parameters, utxo_accumulator.model()),
        &spending_key_0,
        asset_0,
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
        asset_1,
        rng,
    )
    .expect("Unable to build MINT proof.");
    assert_valid_proof(&verifying_context.mint, &mint_1);
    let sender_1 = pre_sender_1
        .insert_and_upgrade(&mut utxo_accumulator)
        .expect("Just inserted so this should not fail.");
    let reclaim = Reclaim::build(
        [sender_0, sender_1],
        [spending_key_0.receiver(parameters, rng.gen(), asset_1)],
        asset_0,
    )
    .into_post(
        FullParameters::new(parameters, utxo_accumulator.model()),
        &proving_context.reclaim,
        rng,
    )
    .expect("Unable to build RECLAIM proof.");
    assert_valid_proof(&verifying_context.reclaim, &reclaim);
    ([mint_0, mint_1], reclaim)
}

/// Test validity on sampled transactions.
#[test]
fn compatibility() {
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    println!("[INFO] Temporary Directory: {:?}", directory);

    let mut rng = thread_rng();
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("failed to load parameters");
    let asset_id: u32 = 8;

    let _ = sample_mint(
        &proving_context.mint,
        &verifying_context.mint,
        &parameters,
        &utxo_accumulator_model,
        AssetId(asset_id).value(100_000),
        &mut rng,
    );
    let _ = sample_private_transfer(
        &proving_context,
        &verifying_context,
        &parameters,
        &utxo_accumulator_model,
        AssetId(asset_id).value(10_000),
        AssetId(asset_id).value(20_000),
        &mut rng,
    );
    let _ = sample_reclaim(
        &proving_context,
        &verifying_context,
        &parameters,
        &utxo_accumulator_model,
        AssetId(asset_id).value(10_000),
        AssetId(asset_id).value(20_000),
        &mut rng,
    );
}
