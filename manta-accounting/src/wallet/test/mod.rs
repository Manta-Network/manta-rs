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

//! Testing and Simulation Framework

// TODO: Perform delays instead of just `Skip` which doesn't really spread actors out in time.

use crate::{
    asset::{Asset, AssetList},
    transfer::{canonical::Transaction, Configuration, PublicKey, ReceivingKey},
    wallet::{self, ledger, signer, Wallet},
};
use alloc::sync::Arc;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use indexmap::IndexSet;
use manta_crypto::rand::{CryptoRng, RngCore, Sample};
use parking_lot::RwLock;
use rand::{distributions::Distribution, Rng};
use statrs::{
    distribution::{Categorical, Discrete},
    StatsError,
};

pub mod sim;

/// Simulation Action Space
pub enum Action<C>
where
    C: Configuration,
{
    /// No Action
    Skip,

    /// Post Transaction
    Post(Transaction<C>),

    /// Generate Public Key
    GeneratePublicKey,
}

/// Action Types
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActionType {
    /// No Action
    Skip,

    /// Mint Action
    Mint,

    /// Private Transfer Action
    PrivateTransfer,

    /// Reclaim Action
    Reclaim,

    /// Generate Public Key Action
    GeneratePublicKey,
}

/// Action Distribution Probability Mass Function
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ActionDistributionPMF<T = f64> {
    /// No Action Weight
    pub skip: T,

    /// Mint Action Weight
    pub mint: T,

    /// Private Transfer Action Weight
    pub private_transfer: T,

    /// Reclaim Action Weight
    pub reclaim: T,

    /// Generate Public Key
    pub generate_public_key: T,
}

impl Default for ActionDistributionPMF {
    #[inline]
    fn default() -> Self {
        Self {
            skip: 0.0,
            mint: 1.0,
            private_transfer: 2.0,
            reclaim: 0.5,
            generate_public_key: 0.5,
        }
    }
}

impl From<ActionDistribution> for ActionDistributionPMF {
    #[inline]
    fn from(actions: ActionDistribution) -> Self {
        Self {
            skip: actions.distribution.pmf(0),
            mint: actions.distribution.pmf(1),
            private_transfer: actions.distribution.pmf(2),
            reclaim: actions.distribution.pmf(3),
            generate_public_key: actions.distribution.pmf(4),
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
        Self::try_from(ActionDistributionPMF::default())
            .expect("The default distribution is a valid categorical distribution.")
    }
}

impl TryFrom<ActionDistributionPMF> for ActionDistribution {
    type Error = StatsError;

    #[inline]
    fn try_from(pmf: ActionDistributionPMF) -> Result<Self, StatsError> {
        Ok(Self {
            distribution: Categorical::new(&[
                pmf.skip,
                pmf.mint,
                pmf.private_transfer,
                pmf.reclaim,
                pmf.generate_public_key,
            ])?,
        })
    }
}

impl Distribution<ActionType> for ActionDistribution {
    #[inline]
    fn sample<R>(&self, rng: &mut R) -> ActionType
    where
        R: RngCore + ?Sized,
    {
        match self.distribution.sample(rng) as usize {
            0 => ActionType::Skip,
            1 => ActionType::Mint,
            2 => ActionType::PrivateTransfer,
            3 => ActionType::Reclaim,
            4 => ActionType::GeneratePublicKey,
            _ => unreachable!(),
        }
    }
}

impl Sample<ActionDistribution> for ActionType {
    #[inline]
    fn sample<R>(distribution: ActionDistribution, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        distribution.sample(rng)
    }
}

/// Public Balance Oracle
pub trait PublicBalanceOracle {
    /// Returns the public balances of `self`.
    fn public_balances(&self) -> Option<AssetList>;
}

/// Actor
pub struct Actor<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
{
    /// Wallet
    pub wallet: Wallet<C, L, S>,

    /// Action Distribution
    pub distribution: ActionDistribution,

    /// Actor Lifetime
    pub lifetime: usize,
}

impl<C, L, S> Actor<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
{
    /// Builds a new [`Actor`] with `wallet`, `distribution`, and `lifetime`.
    #[inline]
    pub fn new(wallet: Wallet<C, L, S>, distribution: ActionDistribution, lifetime: usize) -> Self {
        Self {
            wallet,
            distribution,
            lifetime,
        }
    }

    /// Reduces the lifetime of `self` returning `None` if the lifetime is zero.
    #[inline]
    fn reduce_lifetime(&mut self) -> Option<()> {
        self.lifetime = self.lifetime.checked_sub(1)?;
        Some(())
    }

    /// Samples a deposit from `self` using `rng` returning `None` if no deposit is possible.
    #[inline]
    fn sample_deposit<R>(&mut self, rng: &mut R) -> Option<Asset>
    where
        L: PublicBalanceOracle,
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = self.wallet.sync();
        let assets = self.wallet.ledger().public_balances()?;
        let len = assets.len();
        if len == 0 {
            return None;
        }
        let asset = assets.iter().nth(rng.gen_range(0..len)).unwrap();
        Some(asset.id.value(rng.gen_range(0..asset.value.0)))
    }

    /// Samples a withdraw from `self` using `rng` returning `None` if no withdrawal is possible.
    ///
    /// # Note
    ///
    /// This method samples from a uniform distribution over the asset IDs and asset values present
    /// in the balance state of `self`.
    #[inline]
    fn sample_withdraw<R>(&mut self, rng: &mut R) -> Option<Asset>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = self.wallet.sync();
        let assets = self.wallet.assets();
        let len = assets.len();
        if len == 0 {
            return None;
        }
        let (asset_id, asset_value) = assets.iter().nth(rng.gen_range(0..len)).unwrap();
        Some(asset_id.value(rng.gen_range(0..asset_value.0)))
    }
}

/// Simulation Event
#[derive(derivative::Derivative)]
#[derivative(Debug(bound = "wallet::Error<C, L, S>: Debug"))]
pub struct Event<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
{
    /// Action Type
    pub action: ActionType,

    /// Action Result
    pub result: Result<bool, wallet::Error<C, L, S>>,
}

/// Public Key Database
pub type PublicKeyDatabase<C> = IndexSet<ReceivingKey<C>>;

/// Shared Public Key Database
pub type SharedPublicKeyDatabase<C> = Arc<RwLock<PublicKeyDatabase<C>>>;

/// Simulation
#[derive(derivative::Derivative)]
#[derivative(Default(bound = ""))]
pub struct Simulation<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
    PublicKey<C>: Eq + Hash,
{
    /// Public Key Database
    public_keys: SharedPublicKeyDatabase<C>,

    /// Type Parameter Marker
    __: PhantomData<(L, S)>,
}

impl<C, L, S> Simulation<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
    PublicKey<C>: Eq + Hash,
{
    /// Builds a new [`Simulation`] with a starting set of public `keys`.
    #[inline]
    pub fn new<const N: usize>(keys: [ReceivingKey<C>; N]) -> Self {
        Self {
            public_keys: Arc::new(RwLock::new(keys.into_iter().collect())),
            __: PhantomData,
        }
    }
}

impl<C, L, S> sim::ActionSimulation for Simulation<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C> + PublicBalanceOracle,
    S: signer::Connection<C>,
    PublicKey<C>: Eq + Hash,
{
    type Actor = Actor<C, L, S>;
    type Action = Action<C>;
    type Event = Event<C, L, S>;

    #[inline]
    fn sample<R>(&self, actor: &mut Self::Actor, rng: &mut R) -> Option<Self::Action>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        actor.reduce_lifetime()?;
        let action = actor.distribution.sample(rng);
        Some(match action {
            ActionType::Skip => Action::Skip,
            ActionType::Mint => match actor.sample_deposit(rng) {
                Some(asset) => Action::Post(Transaction::Mint(asset)),
                _ => Action::Skip,
            },
            ActionType::PrivateTransfer => match actor.sample_withdraw(rng) {
                Some(asset) => {
                    let public_keys = self.public_keys.read();
                    let len = public_keys.len();
                    if len == 0 {
                        Action::GeneratePublicKey
                    } else {
                        Action::Post(Transaction::PrivateTransfer(
                            asset,
                            public_keys[rng.gen_range(0..len)].clone(),
                        ))
                    }
                }
                _ => match actor.sample_deposit(rng) {
                    Some(asset) => Action::Post(Transaction::Mint(asset)),
                    _ => Action::Skip,
                },
            },
            ActionType::Reclaim => match actor.sample_withdraw(rng) {
                Some(asset) => Action::Post(Transaction::Reclaim(asset)),
                _ => match actor.sample_deposit(rng) {
                    Some(asset) => Action::Post(Transaction::Mint(asset)),
                    _ => Action::Skip,
                },
            },
            ActionType::GeneratePublicKey => Action::GeneratePublicKey,
        })
    }

    #[inline]
    fn act(&self, actor: &mut Self::Actor, action: Self::Action) -> Self::Event {
        match action {
            Action::Skip => Event {
                action: ActionType::Skip,
                result: Ok(true),
            },
            Action::Post(transaction) => {
                let action = match &transaction {
                    Transaction::Mint(_) => ActionType::Mint,
                    Transaction::PrivateTransfer(_, _) => ActionType::PrivateTransfer,
                    Transaction::Reclaim(_) => ActionType::Reclaim,
                };
                let mut retries = 5; // TODO: Make this parameter tunable based on concurrency.
                loop {
                    let result = actor.wallet.post(transaction.clone());
                    if let Ok(false) = result {
                        if retries == 0 {
                            break Event { action, result };
                        } else {
                            retries -= 1;
                            continue;
                        }
                    } else {
                        break Event { action, result };
                    }
                }
            }
            Action::GeneratePublicKey => Event {
                action: ActionType::GeneratePublicKey,
                result: match actor.wallet.receiving_key() {
                    Ok(key) => {
                        self.public_keys.write().insert(key);
                        Ok(true)
                    }
                    Err(err) => Err(wallet::Error::SignerError(err)),
                },
            },
        }
    }
}
