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

//! Manta Pay Protocol Simulation

// TODO: Move as much of this code into `manta-accounting` simulation as possible.
// TODO: How to model existential deposits and fee payments?
// TODO: Add in some concurrency (and measure how much we need it).

use crate::{
    config::{Config, FullParameters, MultiProvingContext, UtxoAccumulatorModel},
    signer::base::{Signer, UtxoAccumulator},
};
use alloc::{sync::Arc, vec::Vec};
use manta_accounting::{
    self,
    asset::{Asset, AssetId, AssetList, AssetValue},
    key::AccountTable,
    transfer,
    wallet::{
        test::{
            sim::{ActionSim, Simulator},
            ActionType, Actor, PublicBalanceOracle, Simulation,
        },
        BalanceState, Wallet,
    },
};
use manta_crypto::rand::{CryptoRng, Rand, RngCore, SeedableRng};
use parking_lot::RwLock;
use rand_chacha::ChaCha20Rng;

pub mod ledger;

/// Samples an empty wallet for `account` on `ledger`.
#[inline]
pub fn sample_wallet<R>(
    account: ledger::AccountId,
    ledger: &ledger::SharedLedger,
    cache: &MultiProvingContext,
    parameters: &transfer::Parameters<Config>,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    rng: &mut R,
) -> Wallet<Config, ledger::LedgerConnection, Signer>
where
    R: CryptoRng + RngCore + ?Sized,
{
    Wallet::new(
        ledger::LedgerConnection::new(account, ledger.clone()),
        Signer::new(
            AccountTable::new(rng.gen()),
            cache.clone(),
            parameters.clone(),
            UtxoAccumulator::new(utxo_accumulator_model.clone()),
            rng.seed_rng().expect("Failed to sample PRNG for signer."),
        ),
    )
}

/// Measures the public and secret balances for each wallet, summing them all together.
#[inline]
fn measure_balances<'w, I>(wallets: I) -> AssetList
where
    I: IntoIterator<Item = &'w mut Wallet<Config, ledger::LedgerConnection, Signer>>,
{
    let mut balances = AssetList::new();
    for wallet in wallets {
        wallet.sync().expect("Failed to synchronize wallet.");
        balances.deposit_all(wallet.ledger().public_balances().unwrap());
        balances.deposit_all(
            wallet
                .assets()
                .iter()
                .map(|(id, value)| Asset::new(*id, *value)),
        );
    }
    balances
}

/// Runs a simple simulation to test that the signer-wallet-ledger connection works.
#[inline]
pub fn simulate(actor_count: usize, actor_lifetime: usize) {
    let mut rng = ChaCha20Rng::from_entropy();
    let parameters = rng.gen();
    let utxo_accumulator_model = rng.gen();

    let (proving_context, verifying_context) = transfer::canonical::generate_context(
        &(),
        FullParameters::new(&parameters, &utxo_accumulator_model),
        &mut rng,
    )
    .expect("Failed to generate contexts.");

    let mut ledger = ledger::Ledger::new(utxo_accumulator_model.clone(), verifying_context);

    for i in 0..actor_count {
        ledger.set_public_balance(ledger::AccountId(i as u64), AssetId(0), AssetValue(1000000));
        ledger.set_public_balance(ledger::AccountId(i as u64), AssetId(1), AssetValue(1000000));
        ledger.set_public_balance(ledger::AccountId(i as u64), AssetId(2), AssetValue(1000000));
    }

    let ledger = Arc::new(RwLock::new(ledger));

    println!("[INFO] Building {:?} Wallets", actor_count);

    let actors = (0..actor_count)
        .map(|i| {
            Actor::new(
                sample_wallet(
                    ledger::AccountId(i as u64),
                    &ledger,
                    &proving_context,
                    &parameters,
                    &utxo_accumulator_model,
                    &mut rng,
                ),
                Default::default(),
                actor_lifetime,
            )
        })
        .collect::<Vec<_>>();

    let mut simulator = Simulator::new(ActionSim(Simulation::default()), actors);

    let initial_balances =
        measure_balances(simulator.actors.iter_mut().map(|actor| &mut actor.wallet));

    println!("[INFO] Starting Simulation\n");

    rayon::in_place_scope(|scope| {
        for event in simulator.run(move || ChaCha20Rng::from_rng(&mut rng).unwrap(), scope) {
            match event.event.action {
                ActionType::Skip | ActionType::GeneratePublicKey => {}
                _ => println!("{:?}", event),
            }
            if let Err(err) = event.event.result {
                println!("\n[ERROR] Simulation Error: {:?}\n", err);
                break;
            }
        }
    });

    println!("\n[INFO] Simulation Ended");

    let final_balances =
        measure_balances(simulator.actors.iter_mut().map(|actor| &mut actor.wallet));

    assert_eq!(
        initial_balances, final_balances,
        "Simulation balance mismatch."
    );
}
