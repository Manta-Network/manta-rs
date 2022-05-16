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
use parking_lot::Mutex;
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

    /// Post Transaction Data
    Post {
        /// Flag set to `true` whenever the `transaction` only rebalanaces internal assets without
        /// sending them out to another agent.
        is_self: bool,

        /// Transaction Data
        transaction: Transaction<C>,
    },

    /// Generate Receiving Key
    GenerateReceivingKey,

    /// Recover Wallet
    Recover,
}

impl<C> Action<C>
where
    C: transfer::Configuration,
{
    ///
    #[inline]
    pub fn post(is_self: bool, transaction: Transaction<C>) -> Self {
        Self::Post {
            is_self,
            transaction,
        }
    }

    ///
    #[inline]
    pub fn self_post(transaction: Transaction<C>) -> Self {
        Self::post(true, transaction)
    }

    ///
    #[inline]
    pub fn mint(asset: Asset) -> Self {
        Self::self_post(Transaction::Mint(asset))
    }

    ///
    #[inline]
    pub fn private_transfer(is_self: bool, asset: Asset, key: ReceivingKey<C>) -> Self {
        Self::post(is_self, Transaction::PrivateTransfer(asset, key))
    }

    ///
    #[inline]
    pub fn reclaim(asset: Asset) -> Self {
        Self::self_post(Transaction::Reclaim(asset))
    }

    ///
    #[inline]
    pub fn as_type(&self) -> ActionType {
        match self {
            Self::Skip => ActionType::Skip,
            Self::Post {
                is_self,
                transaction,
            } => match (is_self, transaction) {
                (_, Transaction::Mint { .. }) => ActionType::Mint,
                (true, Transaction::PrivateTransfer { .. }) => ActionType::SelfTransfer,
                (false, Transaction::PrivateTransfer { .. }) => ActionType::PrivateTransfer,
                (_, Transaction::Reclaim { .. }) => ActionType::Reclaim,
            },
            Self::GenerateReceivingKey => ActionType::GenerateReceivingKey,
            Self::Recover => ActionType::Recover,
        }
    }
}

/// Action Labelled Data
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ActionLabelled<T> {
    /// Action Type
    pub action: ActionType,

    /// Data Value
    pub value: T,
}

///
pub type ActionLabelledError<C, L, S> = ActionLabelled<Error<C, L, S>>;

/// Possible [`Action`] or an [`Error`] Variant
pub type MaybeAction<C, L, S> = Result<Action<C>, ActionLabelledError<C, L, S>>;

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

    /// Self Private Transfer Action
    SelfTransfer,

    /// Generate Receiving Key Action
    GenerateReceivingKey,

    /// Recover Wallet Action
    Recover,
}

impl ActionType {
    ///
    #[inline]
    pub fn label<T>(self, value: T) -> ActionLabelled<T> {
        ActionLabelled {
            action: self,
            value,
        }
    }
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

    /// Self Private Transfer Action Weight
    pub self_transfer: T,

    /// Generate Public Key Weight
    pub generate_public_key: T,

    /// Recover Wallet Weight
    pub recover: T,
}

impl Default for ActionDistributionPMF {
    #[inline]
    fn default() -> Self {
        Self {
            skip: 2,
            mint: 5,
            private_transfer: 9,
            reclaim: 3,
            self_transfer: 2,
            generate_public_key: 3,
            recover: 4,
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
                pmf.self_transfer as f64,
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
            4 => ActionType::SelfTransfer,
            5 => ActionType::GenerateReceivingKey,
            6 => ActionType::Recover,
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

    /// Returns the default receiving key for `self`.
    #[inline]
    async fn default_receiving_key(&self) -> Result<ReceivingKey<C>, Error<C, L, S>> {
        /*
        Ok(self
            .wallet
            .receiving_keys(ReceivingKeyRequest::Get {
                index: Default::default(),
            })
            .await?[0])
        */
        todo!()
    }

    /// Samples a deposit from `self` using `rng` returning `None` if no deposit is possible.
    #[inline]
    async fn sample_deposit<R>(&mut self, rng: &mut R) -> Result<Option<Asset>, Error<C, L, S>>
    where
        L: PublicBalanceOracle,
        R: CryptoRng + RngCore + ?Sized,
    {
        self.wallet.sync().await?;
        let assets = match self.wallet.ledger().public_balances().await {
            Some(assets) => assets,
            _ => return Ok(None),
        };
        let len = assets.len();
        if len == 0 {
            return Ok(None);
        }
        let asset = assets
            .iter()
            .nth(rng.gen_range(0..len))
            .expect("We query the length first so we can skip this bounds check.");
        Ok(Some(asset.id.value(rng.gen_range(0..asset.value.0))))
    }

    /// Samples a withdraw from `self` using `rng` returning `None` if no withdrawal is possible.
    ///
    /// # Note
    ///
    /// This method samples from a uniform distribution over the asset IDs and asset values present
    /// in the balance state of `self`.
    #[inline]
    async fn sample_withdraw<R>(&mut self, rng: &mut R) -> Result<Option<Asset>, Error<C, L, S>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        self.wallet.sync().await?;
        let assets = self.wallet.assets();
        let len = assets.len();
        if len == 0 {
            return Ok(None);
        }
        let (asset_id, asset_value) = assets
            .iter()
            .nth(rng.gen_range(0..len))
            .expect("We query the length first so we can skip this bounds check.");
        Ok(Some(asset_id.value(rng.gen_range(0..asset_value.0))))
    }

    ///
    #[inline]
    async fn sample_mint<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle,
        R: CryptoRng + RngCore + ?Sized,
    {
        match self.sample_deposit(rng).await {
            Ok(Some(asset)) => Ok(Action::mint(asset)),
            Ok(_) => Ok(Action::Skip),
            Err(err) => Err(ActionType::Mint.label(err)),
        }
    }

    ///
    #[inline]
    async fn sample_private_transfer<K, R>(
        &mut self,
        is_self: bool,
        rng: &mut R,
        key: K,
    ) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle,
        R: CryptoRng + RngCore + ?Sized,
        K: FnOnce(&mut R) -> Result<Option<ReceivingKey<C>>, Error<C, L, S>>,
    {
        let action = if is_self {
            ActionType::SelfTransfer
        } else {
            ActionType::PrivateTransfer
        };
        match self.sample_withdraw(rng).await {
            Ok(Some(asset)) => match key(rng) {
                Ok(Some(key)) => Ok(Action::private_transfer(is_self, asset, key)),
                Ok(_) => Ok(Action::GenerateReceivingKey),
                Err(err) => Err(action.label(err)),
            },
            Ok(_) => self.sample_mint(rng).await,
            Err(err) => Err(action.label(err)),
        }
    }

    ///
    #[inline]
    async fn sample_reclaim<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle,
        R: CryptoRng + RngCore + ?Sized,
    {
        match self.sample_withdraw(rng).await {
            Ok(Some(asset)) => Ok(Action::reclaim(asset)),
            Ok(_) => self.sample_mint(rng).await,
            Err(err) => Err(ActionType::Reclaim.label(err)),
        }
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
pub type Event<C, L, S> =
    ActionLabelled<Result<<L as ledger::Write<Vec<TransferPost<C>>>>::Response, Error<C, L, S>>>;

/// Receiving Key Database
pub type ReceivingKeyDatabase<C> = IndexSet<ReceivingKey<C>>;

/// Shared Receiving Key Database
pub type SharedReceivingKeyDatabase<C> = Arc<Mutex<ReceivingKeyDatabase<C>>>;

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
    /// Receiving Key Database
    receiving_keys: SharedReceivingKeyDatabase<C>,

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
            receiving_keys: Arc::new(Mutex::new(keys.into_iter().collect())),
            __: PhantomData,
        }
    }

    /// Samples a random receiving key from
    #[inline]
    pub fn sample_receiving_key<R>(&self, rng: &mut R) -> Option<ReceivingKey<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let receiving_keys = self.receiving_keys.lock();
        match receiving_keys.len() {
            0 => None,
            n => Some(receiving_keys[rng.gen_range(0..n)].clone()),
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
    type Action = MaybeAction<C, L, S>;
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
                ActionType::Skip => Ok(Action::Skip),
                ActionType::Mint => actor.sample_mint(rng).await,
                ActionType::PrivateTransfer => {
                    actor
                        .sample_private_transfer(false, rng, |rng| {
                            Ok(self.sample_receiving_key(rng))
                        })
                        .await
                }
                ActionType::Reclaim => actor.sample_reclaim(rng).await,
                ActionType::SelfTransfer => {
                    let key = actor.default_receiving_key().await;
                    actor
                        .sample_private_transfer(true, rng, |_| key.map(Some))
                        .await
                }
                ActionType::GenerateReceivingKey => Ok(Action::GenerateReceivingKey),
                ActionType::Recover => Ok(Action::Recover),
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
                Ok(action) => match action {
                    Action::Skip => Event {
                        action: ActionType::Skip,
                        value: Ok(true),
                    },
                    Action::Post {
                        is_self,
                        transaction,
                    } => {
                        let action = match &transaction {
                            Transaction::Mint(_) => ActionType::Mint,
                            Transaction::PrivateTransfer(_, _) => {
                                if is_self {
                                    ActionType::SelfTransfer
                                } else {
                                    ActionType::PrivateTransfer
                                }
                            }
                            Transaction::Reclaim(_) => ActionType::Reclaim,
                        };
                        let mut retries = 5; // TODO: Make this parameter tunable based on concurrency.
                        loop {
                            let result = actor.wallet.post(transaction.clone(), None).await;
                            if let Ok(false) = result {
                                if retries == 0 {
                                    break Event {
                                        action,
                                        value: result,
                                    };
                                } else {
                                    retries -= 1;
                                    continue;
                                }
                            } else {
                                break Event {
                                    action,
                                    value: result,
                                };
                            }
                        }
                    }
                    Action::GenerateReceivingKey => Event {
                        action: ActionType::GenerateReceivingKey,
                        value: match actor
                            .wallet
                            .receiving_keys(ReceivingKeyRequest::New { count: 1 })
                            .await
                        {
                            Ok(keys) => {
                                for key in keys {
                                    self.receiving_keys.lock().insert(key);
                                }
                                Ok(true)
                            }
                            Err(err) => Err(Error::SignerConnectionError(err)),
                        },
                    },
                    Action::Recover => Event {
                        action: ActionType::Recover,
                        value: actor.recover().await,
                    },
                },
                Err(err) => Event {
                    action: err.action,
                    value: Err(err.value),
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
        ES: Copy + FnMut(&sim::Event<sim::ActionSim<Simulation<C, L, S>>>) -> ESFut,
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
        simulator
            .run(rng)
            .for_each_concurrent(None, move |event| async move {
                event_subscriber(&event).await;
            })
            .await;
        let final_balances =
            measure_balances(simulator.actors.iter_mut().map(|actor| &mut actor.wallet)).await?;
        Ok(initial_balances == final_balances)
    }
}
