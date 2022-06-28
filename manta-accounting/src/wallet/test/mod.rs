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
use manta_crypto::rand::{CryptoRng, Distribution, Rand, RngCore, Sample};
use manta_util::{future::LocalBoxFuture, vec::VecExt};
use parking_lot::Mutex;
use statrs::{
    distribution::{Categorical, Poisson},
    StatsError,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

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
        /// sending them out to another agent. If this state is unknown, `false` should be chosen.
        is_self: bool,

        /// Flag set to `true` whenever the `transaction` moves all assets in or out of the private
        /// balance entirely. If this state is unknown, `false` should be chosen.
        is_maximal: bool,

        /// Transaction Data
        transaction: Transaction<C>,
    },

    /// Generate Receiving Keys
    GenerateReceivingKeys {
        /// Number of Keys to Generate
        count: usize,
    },

    /// Restart Wallet
    Restart,
}

impl<C> Action<C>
where
    C: transfer::Configuration,
{
    /// Generates a [`Post`](Self::Post) on `transaction` self-pointed if `is_self` is `true` and
    /// maximal if `is_maximal` is `true`.
    #[inline]
    pub fn post(is_self: bool, is_maximal: bool, transaction: Transaction<C>) -> Self {
        Self::Post {
            is_self,
            is_maximal,
            transaction,
        }
    }

    /// Generates a [`Post`](Self::Post) on `transaction` self-pointed which is maximal if
    /// `is_maximal` is `true`.
    #[inline]
    pub fn self_post(is_maximal: bool, transaction: Transaction<C>) -> Self {
        Self::post(true, is_maximal, transaction)
    }

    /// Generates a [`Transaction::Mint`] for `asset`.
    #[inline]
    pub fn mint(asset: Asset) -> Self {
        Self::self_post(false, Transaction::Mint(asset))
    }

    /// Generates a [`Transaction::PrivateTransfer`] for `asset` to `key` self-pointed if `is_self`
    /// is `true`.
    #[inline]
    pub fn private_transfer(is_self: bool, asset: Asset, key: ReceivingKey<C>) -> Self {
        Self::post(is_self, false, Transaction::PrivateTransfer(asset, key))
    }

    /// Generates a [`Transaction::Reclaim`] for `asset` which is maximal if `is_maximal` is `true`.
    #[inline]
    pub fn reclaim(is_maximal: bool, asset: Asset) -> Self {
        Self::self_post(is_maximal, Transaction::Reclaim(asset))
    }

    /// Computes the [`ActionType`] for a [`Post`](Self::Post) type with the `is_self`,
    /// `is_maximal`, and `transaction` parameters.
    #[inline]
    pub fn as_post_type(
        is_self: bool,
        is_maximal: bool,
        transaction: &Transaction<C>,
    ) -> ActionType {
        use Transaction::*;
        match (is_self, is_maximal, transaction.is_zero(), transaction) {
            (_, _, true, Mint { .. }) => ActionType::MintZero,
            (_, _, false, Mint { .. }) => ActionType::Mint,
            (true, _, true, PrivateTransfer { .. }) => ActionType::SelfTransferZero,
            (true, _, false, PrivateTransfer { .. }) => ActionType::SelfTransfer,
            (false, _, true, PrivateTransfer { .. }) => ActionType::PrivateTransferZero,
            (false, _, false, PrivateTransfer { .. }) => ActionType::PrivateTransfer,
            (_, true, _, Reclaim { .. }) => ActionType::FlushToPublic,
            (_, false, true, Reclaim { .. }) => ActionType::ReclaimZero,
            (_, false, false, Reclaim { .. }) => ActionType::Reclaim,
        }
    }

    /// Converts `self` into its corresponding [`ActionType`].
    #[inline]
    pub fn as_type(&self) -> ActionType {
        match self {
            Self::Skip => ActionType::Skip,
            Self::Post {
                is_self,
                is_maximal,
                transaction,
            } => Self::as_post_type(*is_self, *is_maximal, transaction),
            Self::GenerateReceivingKeys { .. } => ActionType::GenerateReceivingKeys,
            Self::Restart => ActionType::Restart,
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

/// [ActionLabelled`] Error Type
pub type ActionLabelledError<C, L, S> = ActionLabelled<Error<C, L, S>>;

/// Possible [`Action`] or an [`ActionLabelledError`] Variant
pub type MaybeAction<C, L, S> = Result<Action<C>, ActionLabelledError<C, L, S>>;

/// Action Types
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActionType {
    /// No Action
    Skip,

    /// Mint Action
    Mint,

    /// Mint Zero Action
    MintZero,

    /// Private Transfer Action
    PrivateTransfer,

    /// Private Transfer Zero Action
    PrivateTransferZero,

    /// Reclaim Action
    Reclaim,

    /// Reclaim Zero Action
    ReclaimZero,

    /// Self Private Transfer Action
    SelfTransfer,

    /// Self Private Transfer Zero Action
    SelfTransferZero,

    /// Flush-to-Public Transfer Action
    FlushToPublic,

    /// Generate Receiving Keys Action
    GenerateReceivingKeys,

    /// Restart Wallet Action
    Restart,
}

impl ActionType {
    /// Generates an [`ActionLabelled`] type over `value` with `self` as the [`ActionType`].
    #[inline]
    pub fn label<T>(self, value: T) -> ActionLabelled<T> {
        ActionLabelled {
            action: self,
            value,
        }
    }
}

/// Action Distribution Probability Mass Function
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ActionDistributionPMF<T = u64> {
    /// No Action Weight
    pub skip: T,

    /// Mint Action Weight
    pub mint: T,

    /// Mint Zero Action Weight
    pub mint_zero: T,

    /// Private Transfer Action Weight
    pub private_transfer: T,

    /// Private Transfer Zero Action Weight
    pub private_transfer_zero: T,

    /// Reclaim Action Weight
    pub reclaim: T,

    /// Reclaim Action Zero Weight
    pub reclaim_zero: T,

    /// Self Private Transfer Action Weight
    pub self_transfer: T,

    /// Self Private Transfer Zero Action Weight
    pub self_transfer_zero: T,

    /// Flush-to-Public Transfer Action Weight
    pub flush_to_public: T,

    /// Generate Receiving Keys Action Weight
    pub generate_receiving_keys: T,

    /// Restart Wallet Action Weight
    pub restart: T,
}

impl Default for ActionDistributionPMF {
    #[inline]
    fn default() -> Self {
        Self {
            skip: 2,
            mint: 5,
            mint_zero: 1,
            private_transfer: 9,
            private_transfer_zero: 1,
            reclaim: 3,
            reclaim_zero: 1,
            self_transfer: 2,
            self_transfer_zero: 1,
            flush_to_public: 1,
            generate_receiving_keys: 3,
            restart: 4,
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
                pmf.mint_zero as f64,
                pmf.private_transfer as f64,
                pmf.private_transfer_zero as f64,
                pmf.reclaim as f64,
                pmf.reclaim_zero as f64,
                pmf.self_transfer as f64,
                pmf.self_transfer_zero as f64,
                pmf.flush_to_public as f64,
                pmf.generate_receiving_keys as f64,
                pmf.restart as f64,
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
            2 => ActionType::MintZero,
            3 => ActionType::PrivateTransfer,
            4 => ActionType::PrivateTransferZero,
            5 => ActionType::Reclaim,
            6 => ActionType::ReclaimZero,
            7 => ActionType::SelfTransfer,
            8 => ActionType::SelfTransferZero,
            9 => ActionType::FlushToPublic,
            10 => ActionType::GenerateReceivingKeys,
            11 => ActionType::Restart,
            _ => unreachable!(),
        }
    }
}

impl Sample<ActionDistribution> for ActionType {
    #[inline]
    fn sample<R>(distribution: ActionDistribution, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
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
    async fn default_receiving_key(&mut self) -> Result<ReceivingKey<C>, Error<C, L, S>> {
        self.wallet
            .receiving_keys(ReceivingKeyRequest::Get {
                index: Default::default(),
            })
            .await
            .map_err(Error::SignerConnectionError)
            .map(Vec::take_first)
    }

    /// Returns the latest public balances from the ledger.
    #[inline]
    async fn public_balances(&mut self) -> Result<Option<AssetList>, Error<C, L, S>>
    where
        L: PublicBalanceOracle,
    {
        self.wallet.sync().await?;
        Ok(self.wallet.ledger().public_balances().await)
    }

    /// Synchronizes with the ledger, attaching the `action` marker for the possible error branch.
    #[inline]
    async fn sync_with(&mut self, action: ActionType) -> Result<(), ActionLabelledError<C, L, S>> {
        self.wallet.sync().await.map_err(|err| action.label(err))
    }

    /// Samples a deposit from `self` using `rng` returning `None` if no deposit is possible.
    #[inline]
    async fn sample_deposit<R>(&mut self, rng: &mut R) -> Result<Option<Asset>, Error<C, L, S>>
    where
        L: PublicBalanceOracle,
        R: RngCore + ?Sized,
    {
        let assets = match self.public_balances().await? {
            Some(assets) => assets,
            _ => return Ok(None),
        };
        match rng.select_item(assets) {
            Some(asset) => Ok(Some(asset.id.sample_up_to(asset.value, rng))),
            _ => Ok(None),
        }
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
        R: RngCore + ?Sized,
    {
        self.wallet.sync().await?;
        match rng.select_item(self.wallet.assets()) {
            Some((id, value)) => Ok(Some(id.sample_up_to(*value, rng))),
            _ => Ok(None),
        }
    }

    /// Samples an asset balance from the wallet of `self`, labelling the possible error with
    /// `action` if it occurs during synchronization.
    #[inline]
    async fn sample_asset<R>(
        &mut self,
        action: ActionType,
        rng: &mut R,
    ) -> Result<Option<Asset>, ActionLabelledError<C, L, S>>
    where
        R: RngCore + ?Sized,
    {
        self.sync_with(action).await?;
        Ok(rng
            .select_item(self.wallet.assets())
            .map(|(id, value)| Asset::new(*id, *value)))
    }

    /// Samples a [`Mint`] against `self` using `rng`, returning a [`Skip`] if [`Mint`] is
    /// impossible.
    ///
    /// [`Mint`]: ActionType::Mint
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_mint<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle,
        R: RngCore + ?Sized,
    {
        match self.sample_deposit(rng).await {
            Ok(Some(asset)) => Ok(Action::mint(asset)),
            Ok(_) => Ok(Action::Skip),
            Err(err) => Err(ActionType::Mint.label(err)),
        }
    }

    /// Samples a [`MintZero`] against `self` using `rng` to select the [`AssetId`], returning
    /// a [`Skip`] if [`MintZero`] is impossible.
    ///
    /// [`MintZero`]: ActionType::MintZero
    /// [`AssetId`]: crate::asset::AssetId
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_zero_mint<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle,
        R: RngCore + ?Sized,
    {
        match self.public_balances().await {
            Ok(Some(assets)) => match rng.select_item(assets) {
                Some(asset) => Ok(Action::mint(asset.id.value(0))),
                _ => Ok(Action::Skip),
            },
            Ok(_) => Ok(Action::Skip),
            Err(err) => Err(ActionType::MintZero.label(err)),
        }
    }

    /// Samples a [`PrivateTransfer`] against `self` using `rng`, returning a [`Mint`] if
    /// [`PrivateTransfer`] is impossible and then a [`Skip`] if the [`Mint`] is impossible.
    ///
    /// [`PrivateTransfer`]: ActionType::PrivateTransfer
    /// [`Mint`]: ActionType::Mint
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_private_transfer<K, R>(
        &mut self,
        is_self: bool,
        rng: &mut R,
        key: K,
    ) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle,
        R: RngCore + ?Sized,
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
                Ok(_) => Ok(Action::GenerateReceivingKeys { count: 1 }),
                Err(err) => Err(action.label(err)),
            },
            Ok(_) => self.sample_mint(rng).await,
            Err(err) => Err(action.label(err)),
        }
    }

    /// Samples a [`PrivateTransferZero`] against `self` using an `rng`, returning a [`Mint`] if
    /// [`PrivateTransfer`] is impossible and then a [`Skip`] if the [`Mint`] is impossible.
    ///
    /// [`PrivateTransferZero`]: ActionType::PrivateTransferZero
    /// [`PrivateTransfer`]: ActionType::PrivateTransfer
    /// [`Mint`]: ActionType::Mint
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_zero_private_transfer<K, R>(
        &mut self,
        is_self: bool,
        rng: &mut R,
        key: K,
    ) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle,
        R: RngCore + ?Sized,
        K: FnOnce(&mut R) -> Result<Option<ReceivingKey<C>>, Error<C, L, S>>,
    {
        let action = if is_self {
            ActionType::SelfTransfer
        } else {
            ActionType::PrivateTransfer
        };
        match self.sample_asset(action, rng).await {
            Ok(Some(asset)) => match key(rng) {
                Ok(Some(key)) => Ok(Action::private_transfer(is_self, asset.id.value(0), key)),
                Ok(_) => Ok(Action::GenerateReceivingKeys { count: 1 }),
                Err(err) => Err(action.label(err)),
            },
            Ok(_) => Ok(self.sample_zero_mint(rng).await?),
            Err(err) => Err(err),
        }
    }

    /// Samples a [`Reclaim`] against `self` using `rng`, returning a [`Skip`] if [`Reclaim`] is
    /// impossible.
    ///
    /// [`Reclaim`]: ActionType::Reclaim
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_reclaim<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle,
        R: RngCore + ?Sized,
    {
        match self.sample_withdraw(rng).await {
            Ok(Some(asset)) => Ok(Action::reclaim(false, asset)),
            Ok(_) => self.sample_mint(rng).await,
            Err(err) => Err(ActionType::Reclaim.label(err)),
        }
    }

    /// Samples a [`ReclaimZero`] against `self` using `rng`, returning a [`Skip`] if
    /// [`ReclaimZero`] is impossible.
    ///
    /// [`ReclaimZero`]: ActionType::ReclaimZero
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_zero_reclaim<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        R: RngCore + ?Sized,
    {
        Ok(self
            .sample_asset(ActionType::ReclaimZero, rng)
            .await?
            .map(|asset| Action::reclaim(false, asset.id.value(0)))
            .unwrap_or(Action::Skip))
    }

    /// Reclaims all of the private balance of a random [`AssetId`] to public balance or [`Skip`] if
    /// the private balance is empty.
    ///
    /// [`AssetId`]: crate::asset::AssetId
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn flush_to_public<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        R: RngCore + ?Sized,
    {
        Ok(self
            .sample_asset(ActionType::FlushToPublic, rng)
            .await?
            .map(|asset| Action::reclaim(true, asset))
            .unwrap_or(Action::Skip))
    }

    /// Computes the current balance state of the wallet, performs a wallet restart, and then checks
    /// that the balance state has the same or more funds than before the restart.
    #[inline]
    async fn restart(&mut self) -> Result<bool, Error<C, L, S>> {
        self.wallet.sync().await?;
        let assets = AssetList::from_iter(self.wallet.assets().clone());
        self.wallet
            .restart()
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
        R: RngCore + ?Sized,
    {
        rng.select_item(self.receiving_keys.lock().iter())
            .map(Clone::clone)
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
                ActionType::MintZero => actor.sample_zero_mint(rng).await,
                ActionType::PrivateTransfer => {
                    actor
                        .sample_private_transfer(false, rng, |rng| {
                            Ok(self.sample_receiving_key(rng))
                        })
                        .await
                }
                ActionType::PrivateTransferZero => {
                    actor
                        .sample_zero_private_transfer(false, rng, |rng| {
                            Ok(self.sample_receiving_key(rng))
                        })
                        .await
                }
                ActionType::Reclaim => actor.sample_reclaim(rng).await,
                ActionType::ReclaimZero => actor.sample_zero_reclaim(rng).await,
                ActionType::SelfTransfer => {
                    let key = actor.default_receiving_key().await;
                    actor
                        .sample_private_transfer(true, rng, |_| key.map(Some))
                        .await
                }
                ActionType::SelfTransferZero => {
                    let key = actor.default_receiving_key().await;
                    actor
                        .sample_zero_private_transfer(true, rng, |_| key.map(Some))
                        .await
                }
                ActionType::FlushToPublic => actor.flush_to_public(rng).await,
                ActionType::GenerateReceivingKeys => Ok(Action::GenerateReceivingKeys {
                    count: Poisson::new(1.0)
                        .expect("The Poisson parameter is greater than zero.")
                        .sample(rng)
                        .ceil() as usize,
                }),
                ActionType::Restart => Ok(Action::Restart),
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
                        is_maximal,
                        transaction,
                    } => {
                        let action = Action::as_post_type(is_self, is_maximal, &transaction);
                        let mut retries = 5; // TODO: Make this parameter tunable based on concurrency.
                        loop {
                            let event = Event {
                                action,
                                value: actor.wallet.post(transaction.clone(), None).await,
                            };
                            if let Ok(false) = event.value {
                                if retries == 0 {
                                    break event;
                                } else {
                                    retries -= 1;
                                    continue;
                                }
                            } else {
                                break event;
                            }
                        }
                    }
                    Action::GenerateReceivingKeys { count } => Event {
                        action: ActionType::GenerateReceivingKeys,
                        value: match actor
                            .wallet
                            .receiving_keys(ReceivingKeyRequest::New { count })
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
                    Action::Restart => Event {
                        action: ActionType::Restart,
                        value: actor.restart().await,
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
