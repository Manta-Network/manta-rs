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

//! Manta Pay Simulation

// TODO: Implement asynchronous/dynamic simulation and have this static simulation as a degenerate
//       form of this simulation when "asynchronousity" is turned down to zero.

use core::{cmp::min, ops::Range};
use indexmap::IndexMap;
use manta_accounting::asset::{Asset, AssetId, AssetValue};
use manta_crypto::rand::{CryptoRng, RngCore, Sample};
use rand::{distributions::Distribution, seq::SliceRandom, Rng};
use statrs::{
    distribution::{Categorical, Discrete, Poisson},
    StatsError,
};
use std::collections::HashMap;

/// Choose `count`-many elements from `vec` randomly and drop the remaining ones.
#[inline]
fn choose_multiple<T, R>(vec: &mut Vec<T>, count: usize, rng: &mut R)
where
    R: RngCore + ?Sized,
{
    let drop_count = vec.partial_shuffle(rng, count).1.len();
    vec.drain(0..drop_count);
}

/// Action Types
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Action {
    /// No Action
    None,

    /// Public Deposit Action
    PublicDeposit,

    /// Public Withdraw Action
    PublicWithdraw,

    /// Mint Action
    Mint,

    /// Private Transfer Action
    PrivateTransfer,

    /// Reclaim Action
    Reclaim,
}

/// Action Distribution Probability Mass Function
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ActionDistributionPMF<T = f64> {
    /// No Action Weight
    pub none: T,

    /// Public Deposit Action Weight
    pub public_deposit: T,

    /// Public Withdraw Action Weight
    pub public_withdraw: T,

    /// Mint Action Weight
    pub mint: T,

    /// Private Transfer Action Weight
    pub private_transfer: T,

    /// Reclaim Action Weight
    pub reclaim: T,
}

impl Default for ActionDistributionPMF {
    #[inline]
    fn default() -> Self {
        Self {
            none: 1.0,
            public_deposit: 1.0,
            public_withdraw: 1.0,
            mint: 1.0,
            private_transfer: 1.0,
            reclaim: 1.0,
        }
    }
}

impl From<ActionDistribution> for ActionDistributionPMF {
    #[inline]
    fn from(actions: ActionDistribution) -> Self {
        Self {
            none: actions.distribution.pmf(0),
            public_deposit: actions.distribution.pmf(1),
            public_withdraw: actions.distribution.pmf(2),
            mint: actions.distribution.pmf(3),
            private_transfer: actions.distribution.pmf(4),
            reclaim: actions.distribution.pmf(5),
        }
    }
}

/// Action Distribution
#[derive(Clone, Debug, PartialEq)]
pub struct ActionDistribution {
    /// Distribution over Actions
    distribution: Categorical,
}

impl Default for ActionDistribution {
    #[inline]
    fn default() -> Self {
        Self::try_from(ActionDistributionPMF::default()).unwrap()
    }
}

impl TryFrom<ActionDistributionPMF> for ActionDistribution {
    type Error = StatsError;

    #[inline]
    fn try_from(pmf: ActionDistributionPMF) -> Result<Self, StatsError> {
        Ok(Self {
            distribution: Categorical::new(&[
                pmf.none,
                pmf.public_deposit,
                pmf.public_withdraw,
                pmf.mint,
                pmf.private_transfer,
                pmf.reclaim,
            ])?,
        })
    }
}

impl Distribution<Action> for ActionDistribution {
    #[inline]
    fn sample<R>(&self, rng: &mut R) -> Action
    where
        R: RngCore + ?Sized,
    {
        match self.distribution.sample(rng) as usize {
            0 => Action::None,
            1 => Action::PublicDeposit,
            2 => Action::PublicWithdraw,
            3 => Action::Mint,
            4 => Action::PrivateTransfer,
            5 => Action::Reclaim,
            _ => unreachable!(),
        }
    }
}

impl Sample<ActionDistribution> for Action {
    #[inline]
    fn sample<R>(distribution: ActionDistribution, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        distribution.sample(rng)
    }
}

/// Balance State
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BalanceState {
    /// Asset Map
    map: HashMap<AssetId, AssetValue>,
}

impl BalanceState {
    /// Returns the asset balance associated to the assets with the given `id`.
    #[inline]
    pub fn balance(&self, id: AssetId) -> AssetValue {
        self.map.get(&id).copied().unwrap_or_default()
    }

    /// Returns `true` if `self` contains at least `value` amount of the asset with the given `id`.
    #[inline]
    pub fn contains(&self, id: AssetId, value: AssetValue) -> bool {
        self.balance(id) >= value
    }

    /// Deposit `asset` into `self`.
    #[inline]
    pub fn deposit(&mut self, asset: Asset) {
        *self.map.entry(asset.id).or_default() += asset.value;
    }

    /// Withdraw `asset` from `self`, returning `false` if it would overdraw the balance.
    #[inline]
    pub fn withdraw(&mut self, asset: Asset) -> bool {
        if asset.value == 0 {
            true
        } else {
            self.map
                .get_mut(&asset.id)
                .map(move |balance| {
                    if let Some(result) = balance.checked_sub(asset.value) {
                        *balance = result;
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false)
        }
    }
}

/// User Account
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Account {
    /// Public Balances
    pub public: BalanceState,

    /// Secret Balances
    pub secret: BalanceState,

    /// Action Distribution
    pub actions: ActionDistribution,
}

impl Account {
    /// Samples a new account sampled using `config` settings and `rng`.
    #[inline]
    pub fn sample<R>(config: &Config, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let mut public = BalanceState::default();
        // TODO: Use a better distribution to sample a starting balance.
        for _ in 0usize..rng.gen_range(0..50) {
            public.deposit(config.sample_asset(rng));
        }
        Self {
            public,
            secret: Default::default(),
            actions: ActionDistribution::try_from(ActionDistributionPMF {
                none: rng.gen_range(config.action_sampling_ranges.none.clone()),
                public_deposit: rng.gen_range(config.action_sampling_ranges.public_deposit.clone()),
                public_withdraw: rng
                    .gen_range(config.action_sampling_ranges.public_withdraw.clone()),
                mint: rng.gen_range(config.action_sampling_ranges.mint.clone()),
                private_transfer: rng
                    .gen_range(config.action_sampling_ranges.private_transfer.clone()),
                reclaim: rng.gen_range(config.action_sampling_ranges.reclaim.clone()),
            })
            .unwrap(),
        }
    }
}

/// Simulation Update
#[derive(Clone, Debug, PartialEq)]
pub enum Update {
    /// Create Account
    CreateAccount {
        /// Account to Create
        account: Account,
    },

    /// Deposit Public Balance
    PublicDeposit {
        /// Index of Target Account
        account_index: usize,

        /// Asset to Deposit
        asset: Asset,
    },

    /// Withdraw Public Balance
    PublicWithdraw {
        /// Index of Target Account
        account_index: usize,

        /// Asset to Withdraw
        asset: Asset,
    },

    /// Mint Asset
    Mint {
        /// Source Index
        source_index: usize,

        /// Asset to Mint
        asset: Asset,
    },

    /// Private Transfer Asset
    PrivateTransfer {
        /// Sender Index
        sender_index: usize,

        /// Receiver Index
        receiver_index: usize,

        /// Asset to Private Transfer
        asset: Asset,
    },

    /// Reclaim Asset
    Reclaim {
        /// Reclaim Index
        sender_index: usize,

        /// Asset to Reclaim
        asset: Asset,
    },
}

/// Simulation Configuration
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Number of starting accounts
    pub starting_account_count: u64,

    /// Number of simulation steps before creating new accounts
    pub new_account_sampling_cycle: u64,

    /// [`Poisson`] growth rate of the number of accounts
    ///
    /// This configuration setting is not used if `new_account_sampling_cycle == 0`.
    pub account_count_growth_rate: f64,

    /// Maximum number of accounts
    ///
    /// If this value is less than `starting_account_count`, the maximum count is ignored.
    pub maximum_account_count: u64,

    /// Which assets are allowed to be sampled and the maximum per sample
    pub allowed_asset_sampling: IndexMap<AssetId, AssetValue>,

    /// Action Sampling Ranges
    ///
    /// This is a distribution over an [`ActionDistribution`] which is used to sample an
    /// [`ActionDistribution`] for a particular account.
    pub action_sampling_ranges: ActionDistributionPMF<Range<f64>>,

    /// Maximum number of updates allowed per step
    ///
    /// If this value is `0`, it has no effect.
    pub maximum_updates_per_step: u32,

    /// Maximum number of total updates
    ///
    /// If this value is `0`, it has no effect.
    pub maximum_total_updates: u32,
}

impl Config {
    /// Returns `true` if `self` has an active account count maximum.
    #[inline]
    fn has_maximum_account_count(&self) -> bool {
        self.maximum_account_count >= self.starting_account_count
    }

    /// Returns `true` if `accounts` is equal to the account count maximum, if it is active.
    #[inline]
    fn maximum_account_count_has_been_reached(&self, accounts: u64) -> bool {
        self.has_maximum_account_count() && self.maximum_account_count == accounts
    }

    /// Returns `true` if new accounts should be created for the current `step_counter` and an
    /// account list with `accounts`-many elements.
    #[inline]
    fn should_create_new_accounts(&self, step_counter: u64, accounts: u64) -> bool {
        self.maximum_account_count != self.starting_account_count
            && !self.maximum_account_count_has_been_reached(accounts)
            && self.new_account_sampling_cycle != 0
            && step_counter % self.new_account_sampling_cycle == 0
    }

    /// Samples an allowed asset using `rng`.
    #[inline]
    fn sample_asset<R>(&self, rng: &mut R) -> Asset
    where
        R: RngCore + ?Sized,
    {
        let id = self.sample_asset_id(rng);
        Asset::new(id, self.sample_asset_value(id, rng))
    }

    /// Samples an allowed asset id using `rng`.
    #[inline]
    fn sample_asset_id<R>(&self, rng: &mut R) -> AssetId
    where
        R: RngCore + ?Sized,
    {
        let mut ids = self.allowed_asset_sampling.keys();
        *ids.nth(rng.gen_range(0..ids.len())).unwrap()
    }

    /// Samples an allowed asset value of the given `id` using `rng`.
    #[inline]
    fn sample_asset_value<R>(&self, id: AssetId, rng: &mut R) -> AssetValue
    where
        R: RngCore + ?Sized,
    {
        AssetValue(rng.gen_range(0..=self.allowed_asset_sampling[&id].0))
    }

    /// Samples an allowed withdraw from `balances`.
    #[inline]
    fn sample_withdraw<R>(&self, balances: &BalanceState, rng: &mut R) -> Asset
    where
        R: RngCore + ?Sized,
    {
        let mut ids = self.allowed_asset_sampling.keys().collect::<Vec<_>>();
        ids.shuffle(rng);
        for id in &ids {
            let balance = balances.balance(**id);
            if balance != 0 {
                return Asset::new(
                    **id,
                    AssetValue(
                        rng.gen_range(0..=min(balance.0, self.allowed_asset_sampling[*id].0)),
                    ),
                );
            }
        }
        Asset::zero(*ids[ids.len() - 1])
    }
}

/// Simulator
#[derive(Clone, Debug, PartialEq)]
pub struct Simulator {
    /// Configuration
    config: Config,

    /// Step Counter
    step_counter: u64,

    /// Accounts
    accounts: Vec<Account>,
}

impl Simulator {
    /// Builds a new [`Simulator`] from the given `config`, sampling from `rng`.
    #[inline]
    pub fn new<R>(config: Config, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self {
            accounts: (0..config.starting_account_count)
                .map(|_| Account::sample(&config, rng))
                .collect(),
            step_counter: Default::default(),
            config,
        }
    }

    /// Computes one step of the simulation using `rng`.
    #[inline]
    pub fn step<R>(&self, rng: &mut R) -> Vec<Update>
    where
        R: RngCore + ?Sized,
    {
        let mut updates = Vec::new();
        for (i, account) in self.accounts.iter().enumerate() {
            match account.actions.sample(rng) {
                Action::None => {}
                Action::PublicDeposit => {
                    updates.push(Update::PublicDeposit {
                        account_index: i,
                        asset: self.config.sample_asset(rng),
                    });
                }
                Action::PublicWithdraw => {
                    updates.push(Update::PublicWithdraw {
                        account_index: i,
                        asset: self.config.sample_withdraw(&account.public, rng),
                    });
                }
                Action::Mint => {
                    updates.push(Update::Mint {
                        source_index: i,
                        asset: self.config.sample_withdraw(&account.public, rng),
                    });
                }
                Action::PrivateTransfer => {
                    updates.push(Update::PrivateTransfer {
                        sender_index: i,
                        receiver_index: rng.gen_range(0..self.accounts.len()),
                        asset: self.config.sample_withdraw(&account.secret, rng),
                    });
                }
                Action::Reclaim => {
                    updates.push(Update::Reclaim {
                        sender_index: i,
                        asset: self.config.sample_withdraw(&account.secret, rng),
                    });
                }
            }
        }
        let accounts_len = self.accounts.len() as u64;
        if self
            .config
            .should_create_new_accounts(self.step_counter, accounts_len)
        {
            let mut new_accounts = Poisson::new(self.config.account_count_growth_rate)
                .unwrap()
                .sample(rng) as u64;
            if self.config.has_maximum_account_count() {
                new_accounts =
                    new_accounts.clamp(0, self.config.maximum_account_count - accounts_len);
            }
            for _ in 0..new_accounts {
                updates.push(Update::CreateAccount {
                    account: Account::sample(&self.config, rng),
                });
            }
        }
        if self.config.maximum_updates_per_step > 0 {
            choose_multiple(
                &mut updates,
                self.config.maximum_updates_per_step as usize,
                rng,
            );
        }
        updates
    }

    /// Applies `update` to the internal state of the simulator, returning the update back
    /// if an error occured.
    #[inline]
    pub fn apply(&mut self, update: Update) -> Result<(), Update> {
        match &update {
            Update::CreateAccount { account } => {
                self.accounts.push(account.clone());
                return Ok(());
            }
            Update::PublicDeposit {
                account_index,
                asset,
            } => {
                if let Some(balances) = self.accounts.get_mut(*account_index) {
                    balances.public.deposit(*asset);
                    return Ok(());
                }
            }
            Update::PublicWithdraw {
                account_index,
                asset,
            } => {
                if let Some(balances) = self.accounts.get_mut(*account_index) {
                    if balances.public.withdraw(*asset) {
                        return Ok(());
                    }
                }
            }
            Update::Mint {
                source_index,
                asset,
            } => {
                if let Some(balances) = self.accounts.get_mut(*source_index) {
                    if balances.public.withdraw(*asset) {
                        balances.secret.deposit(*asset);
                        return Ok(());
                    }
                }
            }
            Update::PrivateTransfer {
                sender_index,
                receiver_index,
                asset,
            } => {
                if let Some(sender) = self.accounts.get_mut(*sender_index) {
                    if sender.secret.withdraw(*asset) {
                        if let Some(receiver) = self.accounts.get_mut(*receiver_index) {
                            receiver.secret.deposit(*asset);
                            return Ok(());
                        }
                    }
                }
            }
            Update::Reclaim {
                sender_index,
                asset,
            } => {
                if let Some(balances) = self.accounts.get_mut(*sender_index) {
                    if balances.secret.withdraw(*asset) {
                        balances.public.deposit(*asset);
                        return Ok(());
                    }
                }
            }
        }
        Err(update)
    }

    /// Runs `self` for the given number of `steps`.
    #[inline]
    pub fn run<R>(&mut self, steps: usize, rng: &mut R) -> Simulation
    where
        R: RngCore + ?Sized,
    {
        let initial_accounts = self.accounts.clone();
        let mut updates = Vec::new();
        for _ in 0..steps {
            let mut next_updates = self.step(rng);
            let update_limit = self.config.maximum_total_updates as usize;
            if update_limit > 0 {
                match update_limit - updates.len() {
                    0 => break,
                    diff => next_updates.truncate(diff),
                }
            }
            for update in &next_updates {
                if let Err(update) = self.apply(update.clone()) {
                    panic!(
                        "ERROR: {}\n\n Panicked on the following state:\nSimulation: {:?}\nUpdate: {:?}",
                        "This is an internal simulation error. Please file a bug.",
                        self,
                        update
                    );
                }
            }
            updates.append(&mut next_updates);
            self.step_counter += 1;
        }
        Simulation {
            config: self.config.clone(),
            initial_accounts,
            final_accounts: self.accounts.clone(),
            updates,
        }
    }
}

/// Simulation Final State
#[derive(Clone, Debug, PartialEq)]
pub struct Simulation {
    /// Configuration
    pub config: Config,

    /// Initial Account State
    pub initial_accounts: Vec<Account>,

    /// Final Account State
    pub final_accounts: Vec<Account>,

    /// Updates
    pub updates: Vec<Update>,
}
