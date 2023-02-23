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
    asset::AssetList,
    transfer::{canonical::Transaction, Address, Asset, Configuration, TransferPost},
    wallet::{
        ledger,
        signer::{self, SyncData},
        BalanceState, Error, Wallet,
    },
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{fmt::Debug, future::Future, hash::Hash, marker::PhantomData, ops::AddAssign};
use futures::StreamExt;
use indexmap::IndexSet;
use manta_crypto::rand::{CryptoRng, Distribution, Rand, RngCore, Sample, SampleUniform};
use manta_util::{future::LocalBoxFuture, iter::Iterable, num::CheckedSub};
use parking_lot::Mutex;
use statrs::{distribution::Categorical, StatsError};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod sim;

/// Simulation Action Space
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Transaction<C>: Deserialize<'de>",
            serialize = "Transaction<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Transaction<C>: Clone"),
    Copy(bound = "Transaction<C>: Copy"),
    Debug(bound = "Transaction<C>: Debug"),
    Eq(bound = "Transaction<C>: Eq"),
    Hash(bound = "Transaction<C>: Hash"),
    PartialEq(bound = "Transaction<C>: PartialEq")
)]
pub enum Action<C>
where
    C: Configuration,
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

    /// Restart Wallet
    Restart,
}

impl<C> Action<C>
where
    C: Configuration,
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

    /// Generates a [`Transaction::ToPrivate`] for `asset`.
    #[inline]
    pub fn to_private(asset: Asset<C>) -> Self {
        Self::self_post(false, Transaction::ToPrivate(asset))
    }

    /// Generates a [`Transaction::PrivateTransfer`] for `asset` to `address` self-pointed if
    /// `is_self` is `true`.
    #[inline]
    pub fn private_transfer(is_self: bool, asset: Asset<C>, address: Address<C>) -> Self {
        Self::post(is_self, false, Transaction::PrivateTransfer(asset, address))
    }

    /// Generates a [`Transaction::ToPublic`] for `asset` which is maximal if `is_maximal` is `true`.
    #[inline]
    pub fn to_public(is_maximal: bool, asset: Asset<C>) -> Self {
        Self::self_post(is_maximal, Transaction::ToPublic(asset))
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
            (_, _, true, ToPrivate { .. }) => ActionType::ToPrivateZero,
            (_, _, false, ToPrivate { .. }) => ActionType::ToPrivate,
            (true, _, true, PrivateTransfer { .. }) => ActionType::SelfTransferZero,
            (true, _, false, PrivateTransfer { .. }) => ActionType::SelfTransfer,
            (false, _, true, PrivateTransfer { .. }) => ActionType::PrivateTransferZero,
            (false, _, false, PrivateTransfer { .. }) => ActionType::PrivateTransfer,
            (_, true, _, ToPublic { .. }) => ActionType::FlushToPublic,
            (_, false, true, ToPublic { .. }) => ActionType::ToPublicZero,
            (_, false, false, ToPublic { .. }) => ActionType::ToPublic,
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
            Self::Restart => ActionType::Restart,
        }
    }
}

/// Action Labelled Data
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ActionLabelled<T> {
    /// Action Type
    pub action: ActionType,

    /// Data Value
    pub value: T,
}

/// [`ActionLabelled`] Error Type
pub type ActionLabelledError<C, L, S> = ActionLabelled<Error<C, L, S>>;

/// Possible [`Action`] or an [`ActionLabelledError`] Variant
pub type MaybeAction<C, L, S> = Result<Action<C>, ActionLabelledError<C, L, S>>;

/// Action Types
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActionType {
    /// No Action
    Skip,

    /// To-Private Action
    ToPrivate,

    /// To-Private Zero Action
    ToPrivateZero,

    /// Private Transfer Action
    PrivateTransfer,

    /// Private Transfer Zero Action
    PrivateTransferZero,

    /// To-Public Action
    ToPublic,

    /// To-Public Zero Action
    ToPublicZero,

    /// Self Private Transfer Action
    SelfTransfer,

    /// Self Private Transfer Zero Action
    SelfTransferZero,

    /// Flush-to-Public Transfer Action
    FlushToPublic,

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

    /// To-Private Action Weight
    pub to_private: T,

    /// To-Private Zero Action Weight
    pub to_private_zero: T,

    /// Private Transfer Action Weight
    pub private_transfer: T,

    /// Private Transfer Zero Action Weight
    pub private_transfer_zero: T,

    /// To-Public Action Weight
    pub to_public: T,

    /// To-Public Action Zero Weight
    pub to_public_zero: T,

    /// Self Private Transfer Action Weight
    pub self_transfer: T,

    /// Self Private Transfer Zero Action Weight
    pub self_transfer_zero: T,

    /// Flush-to-Public Transfer Action Weight
    pub flush_to_public: T,

    /// Restart Wallet Action Weight
    pub restart: T,
}

impl Default for ActionDistributionPMF {
    #[inline]
    fn default() -> Self {
        Self {
            skip: 2,
            to_private: 5,
            to_private_zero: 1,
            private_transfer: 9,
            private_transfer_zero: 1,
            to_public: 3,
            to_public_zero: 1,
            self_transfer: 2,
            self_transfer_zero: 1,
            flush_to_public: 1,
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
                pmf.to_private as f64,
                pmf.to_private_zero as f64,
                pmf.private_transfer as f64,
                pmf.private_transfer_zero as f64,
                pmf.to_public as f64,
                pmf.to_public_zero as f64,
                pmf.self_transfer as f64,
                pmf.self_transfer_zero as f64,
                pmf.flush_to_public as f64,
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
            1 => ActionType::ToPrivate,
            2 => ActionType::ToPrivateZero,
            3 => ActionType::PrivateTransfer,
            4 => ActionType::PrivateTransferZero,
            5 => ActionType::ToPublic,
            6 => ActionType::ToPublicZero,
            7 => ActionType::SelfTransfer,
            8 => ActionType::SelfTransferZero,
            9 => ActionType::FlushToPublic,
            10 => ActionType::Restart,
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
pub trait PublicBalanceOracle<C>
where
    C: Configuration,
{
    /// Returns the public balances of `self`.
    fn public_balances(&self) -> LocalBoxFuture<Option<AssetList<C::AssetId, C::AssetValue>>>;
}

/// Ledger Alias Trait
///
/// This `trait` is used as an alias for the [`Read`](ledger::Read) and [`Write`](ledger::Write)
/// requirements for the simulation ledger.
pub trait Ledger<C>:
    ledger::Read<SyncData<C>> + ledger::Write<Vec<TransferPost<C>>, Response = bool>
where
    C: Configuration,
{
}

impl<C, L> Ledger<C> for L
where
    C: Configuration,
    L: ledger::Read<SyncData<C>> + ledger::Write<Vec<TransferPost<C>>, Response = bool>,
{
}

/// Actor
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Wallet<C, L, S, B>: Clone"),
    Debug(bound = "Wallet<C, L, S, B>: Debug"),
    Default(bound = "Wallet<C, L, S, B>: Default"),
    Eq(bound = "Wallet<C, L, S, B>: Eq"),
    PartialEq(bound = "Wallet<C, L, S, B>: PartialEq")
)]
pub struct Actor<C, L, S, B>
where
    C: Configuration,
    L: Ledger<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
    B: BalanceState<C::AssetId, C::AssetValue>,
{
    /// Wallet
    pub wallet: Wallet<C, L, S, B>,

    /// Action Distribution
    pub distribution: ActionDistribution,

    /// Actor Lifetime
    pub lifetime: usize,
}

impl<C, L, S, B> Actor<C, L, S, B>
where
    C: Configuration,
    L: Ledger<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
    B: BalanceState<C::AssetId, C::AssetValue>,
{
    /// Builds a new [`Actor`] with `wallet`, `distribution`, and `lifetime`.
    #[inline]
    pub fn new(
        wallet: Wallet<C, L, S, B>,
        distribution: ActionDistribution,
        lifetime: usize,
    ) -> Self {
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

    /// Returns the default address for `self`.
    #[inline]
    async fn default_address(&mut self) -> Result<Address<C>, Error<C, L, S>> {
        self.wallet
            .address()
            .await
            .map_err(Error::SignerConnectionError)?
            .ok_or(Error::MissingSpendingKey)
    }

    /// Returns the latest public balances from the ledger.
    #[inline]
    async fn public_balances(
        &mut self,
    ) -> Result<Option<AssetList<C::AssetId, C::AssetValue>>, Error<C, L, S>>
    where
        L: PublicBalanceOracle<C>,
    {
        self.wallet.sync().await?;
        Ok(self.wallet.ledger().public_balances().await)
    }

    /// Synchronizes the [`Wallet`] in `self`.
    #[inline]
    async fn sync(&mut self) -> Result<(), Error<C, L, S>> {
        self.wallet.sync().await
    }

    /// Synchronizes with the ledger, attaching the `action` marker for the possible error branch.
    #[inline]
    async fn sync_with(&mut self, action: ActionType) -> Result<(), ActionLabelledError<C, L, S>> {
        self.sync().await.map_err(|err| action.label(err))
    }

    /// Posts `transaction` to the ledger, returning a success [`Response`](ledger::Write::Response) if the
    /// `transaction` was successfully posted.
    #[inline]
    async fn post(
        &mut self,
        transaction: Transaction<C>,
        metadata: Option<S::AssetMetadata>,
    ) -> Result<L::Response, Error<C, L, S>> {
        self.wallet.post(transaction, metadata).await
    }

    /// Returns the [`Address`].
    #[inline]
    pub async fn address(&mut self) -> Result<Option<Address<C>>, S::Error> {
        self.wallet.address().await
    }

    /// Samples a deposit from `self` using `rng` returning `None` if no deposit is possible.
    #[inline]
    async fn sample_deposit<R>(&mut self, rng: &mut R) -> Result<Option<Asset<C>>, Error<C, L, S>>
    where
        C::AssetValue: SampleUniform,
        L: PublicBalanceOracle<C>,
        R: RngCore + ?Sized,
    {
        let assets = match self.public_balances().await? {
            Some(assets) => assets,
            _ => return Ok(None),
        };
        match rng.select_item(assets) {
            Some(asset) => Ok(Some(Asset::<C>::new(
                asset.id,
                rng.gen_range(Default::default()..asset.value),
            ))),
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
    async fn sample_withdraw<R>(&mut self, rng: &mut R) -> Result<Option<Asset<C>>, Error<C, L, S>>
    where
        C::AssetValue: SampleUniform,
        R: RngCore + ?Sized,
    {
        self.sync().await?;
        match rng.select_item(self.wallet.assets().convert_iter()) {
            Some((id, value)) => Ok(Some(Asset::<C>::new(
                id.clone(),
                rng.gen_range(Default::default()..value.clone()),
            ))),
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
    ) -> Result<Option<Asset<C>>, ActionLabelledError<C, L, S>>
    where
        R: RngCore + ?Sized,
    {
        self.sync_with(action).await?;
        Ok(rng
            .select_item(self.wallet.assets().convert_iter())
            .map(|(id, value)| Asset::<C>::new(id.clone(), value.clone())))
    }

    /// Samples a [`ToPrivate`] against `self` using `rng`, returning a [`Skip`] if [`ToPrivate`] is
    /// impossible.
    ///
    /// [`ToPrivate`]: ActionType::ToPrivate
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_to_private<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        C::AssetValue: SampleUniform,
        L: PublicBalanceOracle<C>,
        R: RngCore + ?Sized,
    {
        match self.sample_deposit(rng).await {
            Ok(Some(asset)) => Ok(Action::to_private(asset)),
            Ok(_) => Ok(Action::Skip),
            Err(err) => Err(ActionType::ToPrivate.label(err)),
        }
    }

    /// Samples a [`ToPrivateZero`] against `self` using `rng` to select the `AssetId`, returning
    /// a [`Skip`] if [`ToPrivateZero`] is impossible.
    ///
    /// [`ToPrivateZero`]: ActionType::ToPrivateZero
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_zero_to_private<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle<C>,
        R: RngCore + ?Sized,
    {
        match self.public_balances().await {
            Ok(Some(assets)) => match rng.select_item(assets) {
                Some(asset) => Ok(Action::to_private(Asset::<C>::zero(asset.id))),
                _ => Ok(Action::Skip),
            },
            Ok(_) => Ok(Action::Skip),
            Err(err) => Err(ActionType::ToPrivateZero.label(err)),
        }
    }

    /// Samples a [`PrivateTransfer`] against `self` using `rng`, returning a [`ToPrivate`] if
    /// [`PrivateTransfer`] is impossible and then a [`Skip`] if the [`ToPrivate`] is impossible.
    ///
    /// [`PrivateTransfer`]: ActionType::PrivateTransfer
    /// [`ToPrivate`]: ActionType::ToPrivate
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_private_transfer<F, R>(
        &mut self,
        is_self: bool,
        rng: &mut R,
        address: F,
    ) -> MaybeAction<C, L, S>
    where
        C::AssetValue: SampleUniform,
        L: PublicBalanceOracle<C>,
        R: RngCore + ?Sized,
        F: FnOnce(&mut R) -> Result<Option<Address<C>>, Error<C, L, S>>,
    {
        let action = if is_self {
            ActionType::SelfTransfer
        } else {
            ActionType::PrivateTransfer
        };
        match self.sample_withdraw(rng).await {
            Ok(Some(asset)) => match address(rng) {
                Ok(Some(address)) => Ok(Action::private_transfer(is_self, asset, address)),
                Ok(_) => Ok(Action::Skip),
                Err(err) => Err(action.label(err)),
            },
            Ok(_) => self.sample_to_private(rng).await,
            Err(err) => Err(action.label(err)),
        }
    }

    /// Samples a [`PrivateTransferZero`] against `self` using an `rng`, returning a [`ToPrivate`]
    /// if [`PrivateTransfer`] is impossible and then a [`Skip`] if the [`ToPrivate`] is impossible.
    ///
    /// [`PrivateTransferZero`]: ActionType::PrivateTransferZero
    /// [`PrivateTransfer`]: ActionType::PrivateTransfer
    /// [`ToPrivate`]: ActionType::ToPrivate
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_zero_private_transfer<F, R>(
        &mut self,
        is_self: bool,
        rng: &mut R,
        address: F,
    ) -> MaybeAction<C, L, S>
    where
        L: PublicBalanceOracle<C>,
        R: RngCore + ?Sized,
        F: FnOnce(&mut R) -> Result<Option<Address<C>>, Error<C, L, S>>,
    {
        let action = if is_self {
            ActionType::SelfTransfer
        } else {
            ActionType::PrivateTransfer
        };
        match self.sample_asset(action, rng).await {
            Ok(Some(asset)) => match address(rng) {
                Ok(Some(address)) => Ok(Action::private_transfer(
                    is_self,
                    Asset::<C>::zero(asset.id),
                    address,
                )),
                Ok(_) => Ok(Action::Skip),
                Err(err) => Err(action.label(err)),
            },
            Ok(_) => Ok(self.sample_zero_to_private(rng).await?),
            Err(err) => Err(err),
        }
    }

    /// Samples a [`ToPublic`] against `self` using `rng`, returning a [`Skip`] if [`ToPublic`] is
    /// impossible.
    ///
    /// [`ToPublic`]: ActionType::ToPublic
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_to_public<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        C::AssetValue: SampleUniform,
        L: PublicBalanceOracle<C>,
        R: RngCore + ?Sized,
    {
        match self.sample_withdraw(rng).await {
            Ok(Some(asset)) => Ok(Action::to_public(false, asset)),
            Ok(_) => self.sample_to_private(rng).await,
            Err(err) => Err(ActionType::ToPublic.label(err)),
        }
    }

    /// Samples a [`ToPublicZero`] against `self` using `rng`, returning a [`Skip`] if
    /// [`ToPublicZero`] is impossible.
    ///
    /// [`ToPublicZero`]: ActionType::ToPublicZero
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn sample_zero_to_public<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        R: RngCore + ?Sized,
    {
        Ok(self
            .sample_asset(ActionType::ToPublicZero, rng)
            .await?
            .map(|asset| Action::to_public(false, Asset::<C>::zero(asset.id)))
            .unwrap_or(Action::Skip))
    }

    /// Reclaims all of the private balance of a random `AssetId` to public balance or [`Skip`] if
    /// the private balance is empty.
    ///
    /// [`Skip`]: ActionType::Skip
    #[inline]
    async fn flush_to_public<R>(&mut self, rng: &mut R) -> MaybeAction<C, L, S>
    where
        R: RngCore + ?Sized,
    {
        Ok(self
            .sample_asset(ActionType::FlushToPublic, rng)
            .await?
            .map(|asset| Action::to_public(true, asset))
            .unwrap_or(Action::Skip))
    }

    /// Computes the current balance state of the wallet, performs a wallet restart, and then checks
    /// that the balance state has the same or more funds than before the restart.
    #[inline]
    async fn restart(&mut self) -> Result<bool, Error<C, L, S>> {
        self.sync().await?;
        let assets = AssetList::from_iter(
            self.wallet
                .assets()
                .convert_iter()
                .map(|(i, v)| (i.clone(), v.clone())),
        );
        self.wallet
            .restart()
            .await
            .map(move |_| self.wallet.contains_all(assets))
    }
}

/// Simulation Event
pub type Event<C, L, S> =
    ActionLabelled<Result<<L as ledger::Write<Vec<TransferPost<C>>>>::Response, Error<C, L, S>>>;

/// Address Database
pub type AddressDatabase<C> = IndexSet<Address<C>>;

/// Shared Address Database
pub type SharedAddressDatabase<C> = Arc<Mutex<AddressDatabase<C>>>;

/// Simulation
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug(bound = "Address<C>: Debug"), Default(bound = ""))]
pub struct Simulation<C, L, S, B>
where
    C: Configuration,
    L: Ledger<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
    B: BalanceState<C::AssetId, C::AssetValue>,
{
    /// Address Database
    addresses: SharedAddressDatabase<C>,

    /// Type Parameter Marker
    __: PhantomData<(L, S, B)>,
}

impl<C, L, S, B> Simulation<C, L, S, B>
where
    C: Configuration,
    L: Ledger<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
    B: BalanceState<C::AssetId, C::AssetValue>,
    Address<C>: Clone + Eq + Hash,
{
    /// Builds a new [`Simulation`] with a starting set of public `addresses`.
    #[inline]
    pub fn new<const N: usize>(addresses: [Address<C>; N]) -> Self {
        Self {
            addresses: Arc::new(Mutex::new(addresses.into_iter().collect())),
            __: PhantomData,
        }
    }

    /// Samples a random address from `rng`.
    #[inline]
    pub fn sample_address<R>(&self, rng: &mut R) -> Option<Address<C>>
    where
        R: RngCore + ?Sized,
    {
        rng.select_item(self.addresses.lock().iter())
            .map(Clone::clone)
    }
}

impl<C, L, S, B> sim::ActionSimulation for Simulation<C, L, S, B>
where
    C: Configuration,
    C::AssetValue: SampleUniform,
    L: Ledger<C> + PublicBalanceOracle<C>,
    S: signer::Connection<C, Checkpoint = L::Checkpoint>,
    B: BalanceState<C::AssetId, C::AssetValue>,
    Address<C>: Clone + Eq + Hash,
{
    type Actor = Actor<C, L, S, B>;
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
                ActionType::ToPrivate => actor.sample_to_private(rng).await,
                ActionType::ToPrivateZero => actor.sample_zero_to_private(rng).await,
                ActionType::PrivateTransfer => {
                    actor
                        .sample_private_transfer(false, rng, |rng| Ok(self.sample_address(rng)))
                        .await
                }
                ActionType::PrivateTransferZero => {
                    actor
                        .sample_zero_private_transfer(
                            false,
                            rng,
                            |rng| Ok(self.sample_address(rng)),
                        )
                        .await
                }
                ActionType::ToPublic => actor.sample_to_public(rng).await,
                ActionType::ToPublicZero => actor.sample_zero_to_public(rng).await,
                ActionType::SelfTransfer => {
                    let address = actor.default_address().await;
                    actor
                        .sample_private_transfer(true, rng, |_| address.map(Some))
                        .await
                }
                ActionType::SelfTransferZero => {
                    let address = actor.default_address().await;
                    actor
                        .sample_zero_private_transfer(true, rng, |_| address.map(Some))
                        .await
                }
                ActionType::FlushToPublic => actor.flush_to_public(rng).await,
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
                                value: actor.post(transaction.clone(), None).await,
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
pub async fn measure_balances<'w, C, L, S, B, I>(
    wallets: I,
) -> Result<AssetList<C::AssetId, C::AssetValue>, Error<C, L, S>>
where
    C: 'w + Configuration,
    C::AssetId: Ord,
    C::AssetValue: AddAssign,
    for<'v> &'v C::AssetValue: CheckedSub<Output = C::AssetValue>,
    L: 'w + Ledger<C> + PublicBalanceOracle<C>,
    S: 'w + signer::Connection<C, Checkpoint = L::Checkpoint>,
    B: 'w + BalanceState<C::AssetId, C::AssetValue>,
    I: IntoIterator<Item = &'w mut Wallet<C, L, S, B>>,
{
    let mut balances = AssetList::<C::AssetId, C::AssetValue>::new();
    for wallet in wallets.into_iter() {
        wallet.sync().await?;
        let public_balance = wallet.ledger().public_balances().await.expect("");
        balances.deposit_all(public_balance);
        balances.deposit_all({
            wallet
                .assets()
                .convert_iter()
                .map(|(id, value)| Asset::<C>::new(id.clone(), value.clone()))
        });
    }
    Ok(balances)
}

/// Simulation Configuration
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
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
    pub async fn run<C, L, S, B, R, GL, GS, F, ES, ESFut>(
        &self,
        mut ledger: GL,
        mut signer: GS,
        rng: F,
        mut event_subscriber: ES,
    ) -> Result<bool, Error<C, L, S>>
    where
        C: Configuration,
        C::AssetValue: AddAssign + SampleUniform,
        for<'v> &'v C::AssetValue: CheckedSub<Output = C::AssetValue>,
        L: Ledger<C> + PublicBalanceOracle<C>,
        S: signer::Connection<C, Checkpoint = L::Checkpoint>,
        S::Error: Debug,
        B: BalanceState<C::AssetId, C::AssetValue>,
        R: CryptoRng + RngCore,
        GL: FnMut(usize) -> L,
        GS: FnMut(usize) -> S,
        F: FnMut(usize) -> R,
        ES: Copy + FnMut(&sim::Event<sim::ActionSim<Simulation<C, L, S, B>>>) -> ESFut,
        ESFut: Future<Output = ()>,
        Address<C>: Clone + Eq + Hash,
    {
        let action_distribution = ActionDistribution::try_from(self.action_distribution)
            .expect("Unable to sample from action distribution.");
        let mut actors: Vec<_> = (0..self.actor_count)
            .map(|i| {
                Actor::new(
                    Wallet::new(ledger(i), signer(i)),
                    action_distribution.clone(),
                    self.actor_lifetime,
                )
            })
            .collect();
        let simulation = Simulation::default();
        for actor in actors.iter_mut() {
            let address = actor
                .wallet
                .address()
                .await
                .expect("Wallet should have address")
                .expect("Missing spending key");
            simulation.addresses.lock().insert(address);
        }
        let mut simulator = sim::Simulator::new(sim::ActionSim(simulation), actors);
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
