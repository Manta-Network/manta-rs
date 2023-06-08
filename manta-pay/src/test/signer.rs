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

//! Signer Testing Suite

use crate::{
    config::{Asset, Config},
    key::Mnemonic,
    parameters::load_parameters,
    signer::{
        base::identity_verification,
        functions::{address_from_mnemonic, authorization_context_from_mnemonic},
    },
    simulation::{
        ledger::{Ledger, LedgerConnection, SharedLedger},
        sample_signer, sample_signer_from_seed,
    },
};
use alloc::sync::Arc;
use manta_accounting::{
    transfer::{canonical::Transaction, IdentifiedAsset, Identifier},
    wallet::{signer::ConsolidationPrerequest, Wallet},
};
use manta_crypto::{
    algebra::HasGenerator,
    arkworks::constraint::fp::Fp,
    rand::{fuzz::Fuzz, OsRng, Rand},
};
use manta_util::vec::VecExt;
use std::{env, fs::OpenOptions, io::Error};
use tokio::sync::RwLock;

/// Test Wallet type
type TestWallet = Wallet<Config, LedgerConnection>;

/// Checks the generation and verification of [`IdentityProof`](manta_accounting::transfer::IdentityProof)s.
#[test]
fn identity_proof_test() {
    let mut rng = OsRng;
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("Failed to load parameters");
    let mut signer = sample_signer(
        &proving_context,
        &parameters,
        &utxo_accumulator_model,
        &mut rng,
    );
    let identifier = Identifier::<Config>::new(false, rng.gen());
    let virtual_asset = IdentifiedAsset::<Config>::new(identifier, rng.gen());
    let public_account = rng.gen();
    let identity_proof = signer
        .identity_proof(virtual_asset, public_account)
        .expect("Error producing identity proof");
    let address = signer.address().expect("Sampled signer has a spending key");
    assert!(
        identity_verification(
            &identity_proof,
            &parameters,
            &verifying_context.to_public,
            &utxo_accumulator_model,
            virtual_asset,
            address,
            public_account
        )
        .is_ok(),
        "Verification failed"
    );
    assert!(
        identity_verification(
            &identity_proof,
            &parameters,
            &verifying_context.to_public,
            &utxo_accumulator_model,
            IdentifiedAsset::<Config>::new(
                Identifier::<Config>::new(true, identifier.utxo_commitment_randomness),
                virtual_asset.asset,
            ),
            address,
            public_account
        )
        .is_err(),
        "Verification should have failed"
    );
    assert!(
        identity_verification(
            &identity_proof,
            &parameters,
            &verifying_context.to_public,
            &utxo_accumulator_model,
            IdentifiedAsset::<Config>::new(
                Identifier::<Config>::new(
                    false,
                    Fp(identifier.utxo_commitment_randomness.0.fuzz(&mut rng)),
                ),
                virtual_asset.asset,
            ),
            address,
            public_account
        )
        .is_err(),
        "Verification should have failed"
    );
    assert!(
        identity_verification(
            &identity_proof,
            &parameters,
            &verifying_context.to_public,
            &utxo_accumulator_model,
            IdentifiedAsset::<Config>::new(
                virtual_asset.identifier,
                Asset::new(virtual_asset.asset.id, rng.gen()),
            ),
            address,
            public_account
        )
        .is_err(),
        "Verification should have failed"
    );
}

/// Signs a [`ToPrivate`](manta_accounting::transfer::canonical::ToPrivate) transaction, computes its
/// [`TransactionData`](manta_accounting::transfer::canonical::TransactionData), and checks its correctness.
#[test]
fn transaction_data_test() {
    let mut rng = OsRng;
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    let (proving_context, _, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("Failed to load parameters");
    let mut signer = sample_signer(
        &proving_context,
        &parameters,
        &utxo_accumulator_model,
        &mut rng,
    );
    let transaction = Transaction::ToPrivate(rng.gen());
    let response = signer
        .sign_with_transaction_data(transaction)
        .expect("Signing a ToPrivate transaction is not allowed to fail.")
        .0
        .take_first();
    let utxo = response.0.body.receiver_posts.take_first().utxo;
    assert!(
        response.1.check_transaction_data(
            &parameters,
            &signer.address().expect("Sampled signer has a spending key"),
            &vec![utxo]
        ),
        "Invalid Transaction Data"
    );
}

/// Checks that both methods to derive a receiving key from a [`Mnemonic`] give
/// the same result.
#[test]
pub fn derive_address_works() {
    let mut rng = OsRng;
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    let (_, _, parameters, _) =
        load_parameters(directory.path()).expect("Failed to load parameters");
    let mnemonic = Mnemonic::sample(&mut rng);
    let receiving_key_1 = address_from_mnemonic(mnemonic.clone(), &parameters).receiving_key;
    let receiving_key_2 = *authorization_context_from_mnemonic(mnemonic, &parameters)
        .receiving_key(
            parameters.base.group_generator.generator(),
            &parameters.base.viewing_key_derivation_function,
            &mut (),
        );
    assert_eq!(
        receiving_key_1, receiving_key_2,
        "Both receiving keys should be the same"
    );
}

/// Loads the precomputed ledger in the `data` folder.
pub fn load_ledger() -> Result<SharedLedger, Error> {
    let data_dir = env::current_dir()
        .expect("Failed to get current directory")
        .join("src/test/data");
    let target_file = OpenOptions::new()
        .create_new(false)
        .read(true)
        .open(data_dir.join("precomputed_ledger"))?;
    let ledger: Ledger = bincode::deserialize_from(&target_file).expect("Deserialization error");
    Ok(Arc::new(RwLock::new(ledger)))
}

/// Creates new wallet from `account_id`, `initial_balance`, `asset_id` and `ledger`.
async fn create_new_wallet(
    account_id: [u8; 32],
    initial_balance: u128,
    asset_id: u128,
    ledger: SharedLedger,
    seed: [u8; 32],
) -> TestWallet {
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    let (proving_context, _, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("Failed to load parameters");
    let signer =
        sample_signer_from_seed(&proving_context, &parameters, &utxo_accumulator_model, seed);
    let asset_id = asset_id.into();
    ledger
        .write()
        .await
        .set_public_balance(account_id, asset_id, initial_balance);
    let ledger_connection = LedgerConnection::new(account_id, ledger);
    TestWallet::new(ledger_connection, signer)
}

/// Tests that pruning is safe and doesn't delete necessary Merkle proofs.
#[ignore] // We don't run this test on the CI because it takes a long time to run.
#[tokio::test]
async fn pruning_test() {
    let mut rng = OsRng;
    let asset_id = 8;
    let ledger = load_ledger().expect("Error loading ledger");
    const NUMBER_OF_RUNS: usize = 10;
    let account_id = rng.gen();
    let mut public_balance = rng.gen_range(Default::default()..u32::MAX as u128);
    let mut wallet = create_new_wallet(
        account_id,
        public_balance,
        asset_id,
        ledger.clone(),
        rng.gen(),
    )
    .await;
    let mut private_balance = 0;
    for _ in 0..NUMBER_OF_RUNS {
        // 1) create new wallet, reset it, sync and prune.
        wallet.reset_state();
        wallet.load_initial_state().await.expect("Sync error");
        wallet.sync().await.expect("Sync error");
        wallet.signer_mut().prune();
        // 2) privatize `to_mint` tokens, sync and prune.
        let to_mint = rng.gen_range(Default::default()..public_balance);
        public_balance -= to_mint;
        private_balance += to_mint;
        let to_private = Transaction::<Config>::ToPrivate(Asset::new(asset_id.into(), to_mint));
        wallet
            .post(to_private, Default::default())
            .await
            .expect("Error posting ToPrivate");
        wallet.sync().await.expect("Sync error");
        wallet.signer_mut().prune();
        // 3) send `to_send` tokens to another zkAddress, sync and prune.
        let to_send = rng.gen_range(Default::default()..private_balance);
        private_balance -= to_send;
        let private_transfer =
            Transaction::<Config>::PrivateTransfer(Asset::new(asset_id.into(), to_send), rng.gen());
        wallet
            .post(private_transfer, Default::default())
            .await
            .expect("Error posting PrivateTransfer");
        wallet.sync().await.expect("Sync error");
        wallet.signer_mut().prune();
        // 4) reclaim `reclaim` tokens, sync and prune.
        let reclaim = rng.gen_range(Default::default()..private_balance);
        private_balance -= reclaim;
        public_balance += reclaim;
        let to_public =
            Transaction::<Config>::ToPublic(Asset::new(asset_id.into(), reclaim), account_id);
        wallet
            .post(to_public, Default::default())
            .await
            .expect("Error posting ToPublic");
        wallet.sync().await.expect("Sync error");
        wallet.signer_mut().prune();
    }
}

///
#[ignore] // We don't run this test on the CI because it takes a long time to run.
#[tokio::test]
async fn consolidation_test() {
    let mut rng = OsRng;
    let asset_id = 8;
    let ledger = load_ledger().expect("Error loading ledger");
    let account_id = rng.gen();
    let mut public_balance = rng.gen_range(Default::default()..u32::MAX as u128);
    let mut wallet = create_new_wallet(
        account_id,
        public_balance,
        asset_id,
        ledger.clone(),
        rng.gen(),
    )
    .await;
    // 1) create new wallet, reset it and sync.
    wallet.reset_state();
    wallet.load_initial_state().await.expect("Sync error");
    wallet.sync().await.expect("Sync error");
    // 2) privatize `to_mint` tokens, sync and prune.
    const NUMBER_OF_PRIVATE_UTXOS: usize = 9;
    for _ in 0..NUMBER_OF_PRIVATE_UTXOS {
        let to_mint = rng.gen_range(Default::default()..public_balance);
        public_balance -= to_mint;
        let to_private = Transaction::<Config>::ToPrivate(Asset::new(asset_id.into(), to_mint));
        wallet
            .post(to_private, Default::default())
            .await
            .expect("Error posting ToPrivate");
        wallet.sync().await.expect("Sync error");
    }
    let asset_list = wallet.signer().asset_list().0;
    let balance_before_consolidation = wallet.balance(&asset_id.into());
    assert_eq!(
        asset_list.len(),
        NUMBER_OF_PRIVATE_UTXOS,
        "The number of UTXOs in the asset list must be equal to the number of UTXOs minted."
    );
    wallet
        .post_consolidation(ConsolidationPrerequest::new(asset_list))
        .await
        .expect("Consolidation error");
    wallet.sync().await.expect("Sync error");
    let balance_after_consolidation = wallet.balance(&asset_id.into());
    assert_eq!(
        balance_before_consolidation, balance_after_consolidation,
        "Consolidation must preserve the total balance."
    );
    let asset_list_after_consolidation = wallet.signer().asset_list().0;
    assert_eq!(
        asset_list_after_consolidation.len(),
        1,
        "The number of UTXOs after consolidation must be 1"
    );
}
