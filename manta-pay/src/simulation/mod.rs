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
        utxo::{AssetId, AssetValue},
        AccountId, Config, MultiProvingContext, MultiVerifyingContext, Parameters,
        UtxoAccumulatorModel,
    },
    key::KeySecret,
    signer::{
        base::{Signer, UtxoAccumulator},
        functions, InitialSyncData,
    },
    simulation::ledger::{Ledger, LedgerConnection},
};
use alloc::{format, sync::Arc};
use core::fmt::Debug;
use manta_accounting::{
    self,
    asset::AssetList,
    key::AccountTable,
    wallet::{
        self, signer,
        signer::SyncData,
        test::{self, PublicBalanceOracle},
        Error,
    },
};
use manta_crypto::{
    accumulator::Accumulator,
    rand::{ChaCha20Rng, CryptoRng, RngCore, SeedableRng},
};
use tokio::{
    io::{self, AsyncWriteExt},
    sync::RwLock,
};

pub mod ledger;

/// Creates an [`AccountId`] from `i`.
#[inline]
pub fn account_id_from_u64(i: u64) -> AccountId {
    let mut result = [0; 32];
    result[..8].copy_from_slice(&i.to_le_bytes());
    result
}

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
    let mut signer = functions::new_signer_from_model(
        parameters.clone(),
        proving_context.clone(),
        utxo_accumulator_model,
    );
    signer.load_accounts(AccountTable::new(KeySecret::sample(rng)));
    signer
}

/// Samples a new signer.
#[inline]
pub fn sample_signer_from_seed(
    proving_context: &MultiProvingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    seed: [u8; 32],
) -> Signer {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let accounts = AccountTable::new(KeySecret::sample(&mut rng));
    let mut signer = Signer::new(
        parameters.clone(),
        proving_context.clone(),
        UtxoAccumulator::empty(utxo_accumulator_model),
        rng,
    );
    signer.load_accounts(accounts);
    signer
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
            let account = account_id_from_u64(i as u64);
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
            move |i| LedgerConnection::new(account_id_from_u64(i as u64), ledger.clone()),
            move |_| sample_signer(proving_context, parameters, utxo_accumulator_model, rng),
            move |i| account_id_from_u64(i as u64),
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
    pub async fn run_with<L, S, GL, GS, GP>(&self, ledger: GL, signer: GS, public_account: GP)
    where
        L: wallet::test::Ledger<Config>
            + PublicBalanceOracle<Config>
            + wallet::ledger::Read<
                InitialSyncData,
                Checkpoint = <L as wallet::ledger::Read<SyncData<Config>>>::Checkpoint,
            >,
        S: wallet::signer::Connection<
            Config,
            Checkpoint = <L as wallet::ledger::Read<SyncData<Config>>>::Checkpoint,
        >,
        S::Checkpoint: signer::Checkpoint<Config>,
        S::Error: Debug,
        GL: FnMut(usize) -> L,
        GS: FnMut(usize) -> S,
        GP: FnMut(usize) -> AccountId,
        Error<Config, L, S>: Debug,
    {
        assert!(
            self.config()
                .run::<_, _, _, AssetList<AssetId, AssetValue>, _, _, _, _, _, _, _>(ledger, signer, public_account, |_| ChaCha20Rng::from_entropy(), |event| {
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
