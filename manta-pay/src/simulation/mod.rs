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

use crate::{
    config::{
        utxo::protocol_pay::{AssetId, AssetValue},
        Config, MultiProvingContext, MultiVerifyingContext, Parameters, UtxoAccumulatorModel,
    },
    signer::base::{Signer, UtxoAccumulator},
    simulation::ledger::{AccountId, Ledger, LedgerConnection},
    key::KeySecret,
};
use alloc::{format, sync::Arc};
use core::fmt::Debug;
use manta_accounting::{
    self,
    asset::AssetList,
    key::AccountTable,
    wallet::{
        self,
        test::{self, PublicBalanceOracle},
        Error,
    },
};
use manta_crypto::rand::{ChaCha20Rng, CryptoRng, Rand, RngCore, SeedableRng};
use tokio::{
    io::{self, AsyncWriteExt},
    sync::RwLock,
};

pub mod ledger;

/// Samples a new signer.
#[inline]
pub fn sample_signer<R>(
    proving_context: &MultiProvingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    rng: &mut R,
) -> Signer
where
    R: CryptoRng + RngCore + ?Sized,
{
    Signer::new(
        AccountTable::new(KeySecret::sample(rng.gen())),
        parameters.clone(),
        proving_context.clone(),
        UtxoAccumulator::new(utxo_accumulator_model.clone()),
        rng.seed_rng().expect("Failed to sample PRNG for signer."),
    )
}

/// Simulation Configuration
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Simulation {
    /// Actor Count
    pub actor_count: usize,

    /// Actor Lifetime
    pub actor_lifetime: usize,

    /// Asset Id Count
    pub asset_id_count: usize,

    /// Starting Balance
    pub starting_balance: AssetValue,
}

impl Simulation {
    /// Builds the test simulation configuration from `self`.
    #[inline]
    pub fn config(&self) -> test::Config {
        test::Config {
            actor_count: self.actor_count,
            actor_lifetime: self.actor_lifetime,
            action_distribution: Default::default(),
        }
    }

    /// Sets the correct public balances for `ledger` to set up the simulation.
    #[inline]
    pub fn setup(&self, ledger: &mut Ledger) {
        let starting_balance = self.starting_balance;
        for i in 0..self.actor_count {
            let account = AccountId(i as u64);
            for id in 0..self.asset_id_count {
                ledger.set_public_balance(
                    account,
                    AssetId::from((id + 1) as u128),
                    starting_balance,
                );
            }
        }
    }

    /// Runs a simple simulation to test that the signer-wallet-ledger connection works.
    #[inline]
    pub async fn run<R>(
        &self,
        parameters: &Parameters,
        utxo_accumulator_model: &UtxoAccumulatorModel,
        proving_context: &MultiProvingContext,
        verifying_context: MultiVerifyingContext,
        rng: &mut R,
    ) where
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut ledger = Ledger::new(
            utxo_accumulator_model.clone(),
            verifying_context,
            parameters.clone(),
        );
        self.setup(&mut ledger);
        let ledger = Arc::new(RwLock::new(ledger));
        self.run_with(
            move |i| LedgerConnection::new(AccountId(i as u64), ledger.clone()),
            move |_| sample_signer(proving_context, parameters, utxo_accumulator_model, rng),
        )
        .await
    }

    /// Runs the simulation with the given ledger connections and signer connections.
    ///
    /// # Note
    ///
    /// In this case, the ledger must be set up ahead of time with the [`setup`](Self::setup) method
    /// since this simulation only knows about connections to the ledger.
    #[inline]
    pub async fn run_with<L, S, GL, GS>(&self, ledger: GL, signer: GS)
    where
        L: wallet::test::Ledger<Config> + PublicBalanceOracle<Config>,
        S: wallet::signer::Connection<Config, Checkpoint = L::Checkpoint>,
        S::Error: Debug,
        GL: FnMut(usize) -> L,
        GS: FnMut(usize) -> S,
        Error<Config, L, S>: Debug,
    {
        // FIXME: rng
        assert!(
            self.config()
                .run::<_, _, _, AssetList<AssetId, AssetValue>, _, _, _, _, _, _>(ledger, signer, |i| ChaCha20Rng::from_seed([i as u8; 32]), |event| {
                    let event = format!("{event:?}\n");
                    async move {
                        let _ = write_stdout(event.as_bytes()).await;
                    }
                })
                .await
                .expect("An error occured during the simulation."),
            "ERROR: Simulation balance mismatch. Funds before and after the simulation do not match."
        );
    }
}

/// Writes `bytes` to STDOUT using `tokio`.
#[inline]
async fn write_stdout(bytes: &[u8]) -> io::Result<()> {
    tokio::io::stdout().write_all(bytes).await
}

#[tokio::test]
async fn test_to_private() {
    // cargo test --release --all-features test_to_private -- --nocapture
    use crate::config::{Asset, FullParametersRef};
    use manta_accounting::{
        transfer::canonical::{generate_context, Transaction},
        wallet::{test::measure_balances, Wallet},
    };
    use manta_crypto::rand::OsRng;

    let mut rng = OsRng;
    let parameters = rng.gen();
    let utxo_accumulator_model = rng.gen();
    let (proving_context, verifying_context) = generate_context(
        &(),
        FullParametersRef::new(&parameters, &utxo_accumulator_model),
        &mut rng,
    )
    .expect("Failed to generate contexts.");

    let simulation = Simulation {
        actor_count: 1,
        actor_lifetime: 1,
        asset_id_count: 1,
        starting_balance: 10,
    };
    let mut ledger = Ledger::new(
        utxo_accumulator_model.clone(),
        verifying_context,
        parameters.clone(),
    );
    simulation.setup(&mut ledger);
    let signer = sample_signer(
        &proving_context,
        &parameters,
        &utxo_accumulator_model,
        &mut rng,
    );

    let ledger = Arc::new(RwLock::new(ledger));
    let ledger_connection = LedgerConnection::new(AccountId(0u64), ledger.clone());
    let mut wallet =
        Wallet::<_, _, _, AssetList<AssetId, AssetValue>>::new(ledger_connection, signer);
    let asset = Asset {
        id: 0.into(),
        value: 4,
    };

    // Is wallet.assets() empty?
    println!(
        "The wallet contains {} assets before syncing",
        wallet.assets().len()
    );
    wallet.sync().await.expect("wallet sync error");
    // Is wallet.assets() empty?
    println!(
        "The wallet contains {} assets after syncing, before transfers",
        wallet.assets().len()
    );

    let initial_balance = measure_balances([&mut wallet]).await;
    let _temp = wallet.post(Transaction::ToPrivate(asset), None).await;
    let intermediate_balance = measure_balances([&mut wallet]).await;
    let _temp = wallet.post(Transaction::ToPrivate(asset), None).await;
    let final_balance = measure_balances([&mut wallet]).await;

    // Is wallet.assets() empty?
    println!(
        "The wallet contains {} assets after transfers",
        wallet.assets().len()
    );

    println!("Initial balance: {initial_balance:?}");
    println!("Intermed. balance: {intermediate_balance:?}");
    println!("Final balance: {final_balance:?}");
}
