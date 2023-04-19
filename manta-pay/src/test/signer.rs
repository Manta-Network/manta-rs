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
    simulation::{ledger::LedgerConnection, sample_signer},
};
use manta_accounting::{
    transfer::{canonical::Transaction, IdentifiedAsset, Identifier},
    wallet::test::PublicBalanceOracle,
};
use manta_crypto::{
    algebra::HasGenerator,
    arkworks::constraint::fp::Fp,
    rand::{fuzz::Fuzz, OsRng, Rand},
};
use manta_util::vec::VecExt;

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

/// Checks the generation and verification of [`IdentityProof`](manta_accounting::transfer::IdentityProof)s.
#[tokio::test]
async fn find_the_bug() {
    use crate::{
        config::{AssetId, AssetValue},
        signer::base::Signer,
        simulation::ledger::Ledger,
    };
    use alloc::sync::Arc;
    use manta_accounting::{
        asset::AssetList,
        wallet::{Wallet},
    };
    use tokio::sync::RwLock;
    let mut rng = OsRng;
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("Failed to load parameters");
    let signer = sample_signer(
        &proving_context,
        &parameters,
        &utxo_accumulator_model,
        &mut rng,
    );
    let account_id = rng.gen();
    let asset_id = 1.into();
    let address = rng.gen();
    let ledger = Arc::new(RwLock::new(Ledger::new(
        utxo_accumulator_model,
        verifying_context,
        parameters,
    )));
    let initial_balance = 10000;
    let to_send = 100;
    let back_to_public = 5000;
    ledger
        .write()
        .await
        .set_public_balance(account_id, asset_id, initial_balance);
    let ledger_connection = LedgerConnection::new(account_id, ledger);
    let mut wallet =
        Wallet::<Config, LedgerConnection, Signer, AssetList<AssetId, AssetValue>>::new(
            ledger_connection,
            signer,
        );
    let to_private = Transaction::<Config>::ToPrivate(Asset::new(asset_id, initial_balance));
    wallet
        .post(to_private, Default::default())
        .await
        .expect("Error posting ToPrivate");
    wallet.sync().await.expect("Sync error");
    let private_transfer = Transaction::<Config>::PrivateTransfer(Asset::new(asset_id, to_send), address);
    wallet
        .post(private_transfer, Default::default())
        .await
        .expect("Error posting PrivateTransfer");
    wallet.sync().await.expect("Sync error");
    let to_public = Transaction::<Config>::ToPublic(Asset::new(asset_id, back_to_public), account_id);
    wallet
        .post(to_public, Default::default())
        .await
        .expect("Error posting ToPublic");
    wallet.sync().await.expect("Sync error");
    let public_balance = match wallet.ledger().public_balances().await {
        Some(asset_list) => asset_list.value(&asset_id),
        None => 0,
    };
    let private_balance = wallet.balance(&asset_id);
    println!("Public Balance: {:?}", public_balance);
    println!("Private Balance: {:?}", private_balance);
    wallet.restart().await.expect("Error restarting");
    println!("Private Balance after restarting: {:?}", wallet.balance(&asset_id));
}

// cargo test --release --package manta-pay --lib --all-features -- test::signer::find_the_bug --exact --nocapture
