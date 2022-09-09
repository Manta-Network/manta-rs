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
        Config, MultiProvingContext, MultiVerifyingContext, Parameters, UtxoAccumulatorModel,
    },
    signer::base::{Signer, UtxoAccumulator},
    simulation::ledger::{AccountId, Ledger, LedgerConnection},
};
use alloc::{format, sync::Arc};
use core::fmt::Debug;
use manta_accounting::{
    self,
    asset::{AssetId, AssetValue, AssetValueType},
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
        AccountTable::new(rng.gen()),
        proving_context.clone(),
        parameters.clone(),
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
    pub starting_balance: AssetValueType,
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
        let starting_balance = AssetValue(self.starting_balance);
        for i in 0..self.actor_count {
            let account = AccountId(i as u64);
            for id in 0..self.asset_id_count {
                ledger.set_public_balance(account, AssetId(id as u32), starting_balance);
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
        let mut ledger = Ledger::new(utxo_accumulator_model.clone(), verifying_context);
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
        L: wallet::test::Ledger<Config> + PublicBalanceOracle,
        S: wallet::signer::Connection<Config, Checkpoint = L::Checkpoint>,
        GL: FnMut(usize) -> L,
        GS: FnMut(usize) -> S,
        Error<Config, L, S>: Debug,
    {
        assert!(
            self.config()
                .run(ledger, signer, ChaCha20Rng::from_entropy, |event| {
                    let event = format!("{:?}\n", event);
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
