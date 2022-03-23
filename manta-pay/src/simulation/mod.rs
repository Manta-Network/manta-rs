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
    config::{MultiProvingContext, Parameters, UtxoAccumulatorModel},
    signer::base::{Signer, UtxoAccumulator},
};
use alloc::{format, sync::Arc};
use manta_accounting::{
    self,
    asset::{AssetId, AssetValue, AssetValueType},
    key::AccountTable,
    wallet::test,
};
use manta_crypto::rand::{CryptoRng, Rand, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::{io::AsyncWriteExt, sync::RwLock};

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
    /// Runs a simple simulation to test that the signer-wallet-ledger connection works.
    #[inline]
    pub async fn run<R>(
        &self,
        parameters: &Parameters,
        utxo_accumulator_model: &UtxoAccumulatorModel,
        proving_context: &MultiProvingContext,
        mut ledger: ledger::Ledger,
        rng: &mut R,
    ) where
        R: CryptoRng + RngCore + ?Sized,
    {
        let starting_balance = AssetValue(self.starting_balance);
        for i in 0..self.actor_count {
            let account = ledger::AccountId(i as u64);
            for id in 0..self.asset_id_count {
                ledger.set_public_balance(account, AssetId(id as u32), starting_balance);
            }
        }
        let ledger = Arc::new(RwLock::new(ledger));
        assert!(
            test::Config {
                actor_count: self.actor_count,
                actor_lifetime: self.actor_lifetime
            }
            .run(
                |i| ledger::LedgerConnection::new(ledger::AccountId(i as u64), ledger.clone()),
                |_| sample_signer(proving_context, parameters, utxo_accumulator_model, rng),
                ChaCha20Rng::from_entropy,
                |event| {
                    let event_string = format!("{:?}", event);
                    async move {
                        let _ = tokio::io::stdout().write_all(event_string.as_bytes()).await;
                    }
                }
            )
            .await
            .expect("Error during simulation."),
            "Simulation balance mismatch!"
        );
    }
}
