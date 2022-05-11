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
// TODO: Generalize `PushResponse` so that we can test against more general wallet setups.

use crate::{
    asset::{Asset, AssetList},
    transfer::{self, canonical::Transaction, PublicKey, ReceivingKey, TransferPost},
    wallet::{
        ledger,
        signer::{self, ReceivingKeyRequest, SyncData},
        BalanceState, Error, Wallet,
    },
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{fmt::Debug, future::Future, hash::Hash, marker::PhantomData};
use futures::StreamExt;
use indexmap::IndexSet;
use manta_crypto::rand::{CryptoRng, RngCore, Sample};
use manta_util::future::LocalBoxFuture;
use parking_lot::RwLock;
use rand::{distributions::Distribution, Rng};
use statrs::{distribution::Categorical, StatsError};

pub mod sim;

/// Simulation Action Space
pub enum Action<C>
where
    C: transfer::Configuration,
{
    /// No Action
    Skip,

    /// Post Transaction
    Post(Transaction<C>),

    /// Generate Public Key
    GeneratePublicKey,

    /// Recover Wallet
    Recover,
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

    /// Recover Wallet
    Recover,
}

/// Action Distribution Probability Mass Function
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ActionDistributionPMF<T = u64> {
    /// No Action Weight
    pub skip: T,

    /// Mint Action Weight
    pub mint: T,

    /// Private Transfer Action Weight
    pub private_transfer: T,

    /// Reclaim Action Weight
    pub reclaim: T,

    /// Generate Public Key Weight
    pub generate_public_key: T,

    /// Recover Wallet Weight
    pub recover: T,
}

impl Default for ActionDistributionPMF {
    #[inline]
    fn default() -> Self {
        Self {
            skip: 0,
            mint: 4,
            private_transfer: 8,
            reclaim: 2,
            generate_public_key: 2,
            recover: 3,
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
                pmf.skip as f64,
                pmf.mint as f64,
                pmf.private_transfer as f64,
                pmf.reclaim as f64,
                pmf.generate_public_key as f64,
                pmf.recover as f64,
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
            5 => ActionType::Recover,
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
    fn public_balances(&self) -> LocalBoxFuture<Option<AssetList>>;
}

/// Ledger Alias Trait
///
/// This `trait` is used as an alias for the [`Read`](ledger::Read) and [`Write`](ledger::Write)
/// requirements for the simulation ledger.
pub trait Ledger<C>:
    ledger::Read<SyncData<C>> + ledger::Write<Vec<TransferPost<C>>, Response = bool>
where
    C: transfer::Configuration,
{
}

impl<C, L> Ledger<C> for L
where
    C: transfer::Configuration,
    L: ledger::Read<SyncData<C>> + ledger::Write<Vec<TransferPost<C>>, Response = bool>,
{
}

/// Actor
pub struct Actor<C, L, S>
where
    C: transfer::Configuration,
    L: Ledger<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
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
    C: transfer::Configuration,
    L: Ledger<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
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
    async fn sample_deposit<R>(&mut self, rng: &mut R) -> Option<Asset>
    where
        L: PublicBalanceOracle,
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = self.wallet.sync().await;
        let assets = self.wallet.ledger().public_balances().await?;
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
    async fn sample_withdraw<R>(&mut self, rng: &mut R) -> Option<Asset>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = self.wallet.sync().await;
        let assets = self.wallet.assets();
        let len = assets.len();
        if len == 0 {
            return None;
        }
        let (asset_id, asset_value) = assets.iter().nth(rng.gen_range(0..len)).unwrap();
        Some(asset_id.value(rng.gen_range(0..asset_value.0)))
    }

    /// Computes the current balance state of the wallet, performs a full recovery, and then
    /// checks that the balance state has the same or more funds than before the recovery.
    #[inline]
    async fn recover(&mut self) -> Result<bool, Error<C, L, S>> {
        self.wallet.sync().await?;
        let assets = AssetList::from_iter(self.wallet.assets().clone());
        self.wallet
            .recover()
            .await
            .map(move |_| self.wallet.contains_all(assets))
    }
}

/// Simulation Event
#[derive(derivative::Derivative)]
#[derivative(Debug(bound = "L::Response: Debug, Error<C, L, S>: Debug"))]
pub struct Event<C, L, S>
where
    C: transfer::Configuration,
    L: Ledger<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
{
    /// Action Type
    pub action: ActionType,

    /// Action Result
    pub result: Result<L::Response, Error<C, L, S>>,
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
    C: transfer::Configuration,
    L: Ledger<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
    PublicKey<C>: Eq + Hash,
{
    /// Public Key Database
    public_keys: SharedPublicKeyDatabase<C>,

    /// Type Parameter Marker
    __: PhantomData<(L, S)>,
}

impl<C, L, S> Simulation<C, L, S>
where
    C: transfer::Configuration,
    L: Ledger<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
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
    C: transfer::Configuration,
    L: Ledger<C> + PublicBalanceOracle,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
    PublicKey<C>: Eq + Hash,
{
    type Actor = Actor<C, L, S>;
    type Action = Action<C>;
    type Event = Event<C, L, S>;

    #[inline]
    fn sample<'s, R>(
        &'s self,
        actor: &'s mut Self::Actor,
        rng: &'s mut R,
    ) -> LocalBoxFuture<'s, Option<Self::Action>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Box::pin(async move {
            actor.reduce_lifetime()?;
            let action = actor.distribution.sample(rng);
            Some(match action {
                ActionType::Skip => Action::Skip,
                ActionType::Mint => match actor.sample_deposit(rng).await {
                    Some(asset) => Action::Post(Transaction::Mint(asset)),
                    _ => Action::Skip,
                },
                ActionType::PrivateTransfer => match actor.sample_withdraw(rng).await {
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
                    _ => match actor.sample_deposit(rng).await {
                        Some(asset) => Action::Post(Transaction::Mint(asset)),
                        _ => Action::Skip,
                    },
                },
                ActionType::Reclaim => match actor.sample_withdraw(rng).await {
                    Some(asset) => Action::Post(Transaction::Reclaim(asset)),
                    _ => match actor.sample_deposit(rng).await {
                        Some(asset) => Action::Post(Transaction::Mint(asset)),
                        _ => Action::Skip,
                    },
                },
                ActionType::GeneratePublicKey => Action::GeneratePublicKey,
                ActionType::Recover => Action::Recover,
            })
        })
    }

    #[inline]
    fn act<'s>(
        &'s self,
        actor: &'s mut Self::Actor,
        action: Self::Action,
    ) -> LocalBoxFuture<'s, Self::Event> {
        Box::pin(async move {
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
                        let result = actor.wallet.post(transaction.clone(), None).await;
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
                    result: match actor
                        .wallet
                        .receiving_keys(ReceivingKeyRequest::New { count: 1 })
                        .await
                    {
                        Ok(keys) => {
                            for key in keys {
                                self.public_keys.write().insert(key);
                            }
                            Ok(true)
                        }
                        Err(err) => Err(Error::SignerConnectionError(err)),
                    },
                },
                Action::Recover => Event {
                    action: ActionType::Recover,
                    result: actor.recover().await,
                },
            }
        })
    }
}

/// Measures the public and secret balances for each wallet, summing them all together.
#[inline]
pub async fn measure_balances<'w, C, L, S, I>(wallets: I) -> Result<AssetList, Error<C, L, S>>
where
    C: 'w + transfer::Configuration,
    L: 'w + Ledger<C> + PublicBalanceOracle,
    S: 'w + signer::Connection<C, Checkpoint = L::Checkpoint>,
    I: IntoIterator<Item = &'w mut Wallet<C, L, S>>,
{
    let mut balances = AssetList::new();
    for wallet in wallets {
        wallet.sync().await?;
        balances.deposit_all(wallet.ledger().public_balances().await.unwrap());
        balances.deposit_all(
            wallet
                .assets()
                .iter()
                .map(|(id, value)| Asset::new(*id, *value)),
        );
    }
    Ok(balances)
}

/// Simulation Configuration
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Config {
    /// Actor Count
    pub actor_count: usize,

    /// Actor Lifetime
    pub actor_lifetime: usize,

    /// Action Distribution
    pub action_distribution: ActionDistributionPMF,
}

impl Config {
    /// Runs the simulation on the configuration defined in `self`, sending events to the
    /// `event_subscriber`.
    #[inline]
    pub async fn run<C, L, S, R, GL, GS, F, ES, ESFut>(
        &self,
        mut ledger: GL,
        mut signer: GS,
        rng: F,
        mut event_subscriber: ES,
    ) -> Result<bool, Error<C, L, S>>
    where
        C: transfer::Configuration,
        L: Ledger<C> + PublicBalanceOracle,
        S: signer::Connection<C, Checkpoint = L::Checkpoint>,
        R: CryptoRng + RngCore,
        GL: FnMut(usize) -> L,
        GS: FnMut(usize) -> S,
        F: FnMut() -> R,
        ES: FnMut(&sim::Event<sim::ActionSim<Simulation<C, L, S>>>) -> ESFut,
        ESFut: Future<Output = ()>,
        Error<C, L, S>: Debug,
        PublicKey<C>: Eq + Hash,
    {
        let action_distribution = ActionDistribution::try_from(self.action_distribution)
            .expect("Unable to sample from action distribution.");
        let actors = (0..self.actor_count)
            .map(|i| {
                Actor::new(
                    Wallet::new(ledger(i), signer(i)),
                    action_distribution.clone(),
                    self.actor_lifetime,
                )
            })
            .collect();
        let mut simulator = sim::Simulator::new(sim::ActionSim(Simulation::default()), actors);
        let initial_balances =
            measure_balances(simulator.actors.iter_mut().map(|actor| &mut actor.wallet)).await?;
        let mut events = simulator.run(rng);
        while let Some(event) = events.next().await {
            event_subscriber(&event).await;
            if let Err(err) = event.event.result {
                return Err(err);
            }
        }
        drop(events);
        let final_balances =
            measure_balances(simulator.actors.iter_mut().map(|actor| &mut actor.wallet)).await?;
        Ok(initial_balances == final_balances)
    }
}
