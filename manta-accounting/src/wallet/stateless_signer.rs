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

//! Stateless Signer Methods

use crate::{
    asset::AssetMap,
    key::{Account, DeriveAddress},
    transfer::{
        self,
        batch::Join,
        canonical::{
            MultiProvingContext, PrivateTransfer, PrivateTransferShape, Selection, ToPrivate,
            ToPublic, Transaction, TransactionData, TransferShape,
        },
        receiver::ReceiverPost,
        requires_authorization,
        utxo::{auth::DeriveContext, DeriveDecryptionKey, DeriveSpend, Spend, UtxoReconstruct},
        Address, Asset, AssociatedData, Authorization, AuthorizationContext, FullParametersRef,
        IdentifiedAsset, Identifier, IdentityProof, Note, Nullifier, Parameters, PreSender,
        ProvingContext, Receiver, Sender, Shape, SpendingKey, Transfer, TransferPost, Utxo,
        UtxoAccumulatorItem, UtxoAccumulatorModel,
    },
    wallet::{
        ledger,
        signer::{
            AccountTable, BalanceUpdate, Checkpoint, Configuration, IdentityRequest,
            IdentityResponse, SignError, SignRequest, SignerParameters, SyncData, SyncError,
            SyncRequest, TransactionDataRequest, TransactionDataResponse,
        },
    },
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::{convert::Infallible, fmt::Debug, hash::Hash};
use manta_crypto::{
    accumulator::{Accumulator, ItemHashFunction, OptimizedAccumulator},
    rand::Rand,
};
use manta_util::{
    array_map, cmp::Independence, future::LocalBoxFutureResult, into_array_unchecked,
    iter::IteratorExt, persistence::Rollback, vec::VecExt,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Stateless Signer Connection
pub trait StatelessSignerConnection<C>
where
    C: Configuration,
{
    /// Error Type
    ///
    /// This is the error type for the connection itself, not for an error produced during one of
    /// the signer methods.
    type Error;

    /// Pushes updates from the ledger to the wallet, synchronizing
    /// `assets`, `checkpoint` and `utxo_accumulator` with the ledger state.
    fn sync<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
        assets: C::AssetMap,
        checkpoint: C::Checkpoint,
        utxo_accumulator: C::UtxoAccumulator,
        request: SyncRequest<C, C::Checkpoint>,
        rng: &'a mut C::Rng,
    ) -> LocalBoxFutureResult<StatelessSyncResult<C, C::Checkpoint>, Self::Error>;

    /// Signs a transaction and returns the ledger transfer posts if successful, as well as
    /// the updated utxo accumulator.
    fn sign<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
        assets: &'a C::AssetMap,
        utxo_accumulator: C::UtxoAccumulator,
        request: SignRequest<C::AssetMetadata, C>,
        rng: &'a mut C::Rng,
    ) -> LocalBoxFutureResult<StatelessSignResult<C>, Self::Error>;

    /// Returns the [`Address`] corresponding to `accounts`.
    fn address<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
    ) -> LocalBoxFutureResult<Address<C>, Self::Error>;

    /// Returns the [`TransactionData`] of the [`TransferPost`]s in `request` owned by `accounts`.
    fn transaction_data<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
        request: TransactionDataRequest<C>,
    ) -> LocalBoxFutureResult<TransactionDataResponse<C>, Self::Error>;

    /// Generates an [`IdentityProof`] for `accounts` which can be verified against
    /// the [`IdentifiedAsset`]s in `request`.
    fn identity_proof<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
        utxo_accumulator_model: &'a UtxoAccumulatorModel<C>,
        request: IdentityRequest<C>,
        rng: &'a mut C::Rng,
    ) -> LocalBoxFutureResult<IdentityResponse<C>, Self::Error>;
}

/// Stateless Synchronization Result
pub type StatelessSyncResult<C, T> = Result<StatelessSyncResponse<C, T>, SyncError<T>>;

/// Stateless Signing Result
pub type StatelessSignResult<C> = Result<StatelessSignResponse<C>, SignError<C>>;

/// Stateless Batched Transaction Type
pub type StatelessBatchedTransaction<C> = (
    [Sender<C>; PrivateTransferShape::SENDERS],
    <C as Configuration>::UtxoAccumulator,
);

/// Stateless Synchronization Response
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"T: Deserialize<'de>, 
                BalanceUpdate<C>: Deserialize<'de>, 
                C::UtxoAccumulator: Deserialize<'de>, 
                C::AssetMap: Deserialize<'de>",
            serialize = r"T: Serialize, 
                BalanceUpdate<C>: Serialize, 
                C::UtxoAccumulator: Serialize, 
                C::AssetMap: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(
        bound = "T: Clone, BalanceUpdate<C>: Clone, C::UtxoAccumulator: Clone, C::AssetMap: Clone"
    ),
    Copy(bound = "T: Copy, BalanceUpdate<C>: Copy, C::UtxoAccumulator: Copy, C::AssetMap: Copy"),
    Debug(
        bound = "T: Debug, BalanceUpdate<C>: Debug, C::UtxoAccumulator: Debug, C::AssetMap: Debug"
    ),
    Default(
        bound = "T: Default, BalanceUpdate<C>: Default, C::UtxoAccumulator: Default, C::AssetMap: Default"
    ),
    Eq(bound = "T: Eq, BalanceUpdate<C>: Eq, C::UtxoAccumulator: Eq, C::AssetMap: Eq"),
    Hash(bound = "T: Hash, BalanceUpdate<C>: Hash, C::UtxoAccumulator: Hash, C::AssetMap: Hash"),
    PartialEq(
        bound = "T: PartialEq, BalanceUpdate<C>: PartialEq, C::UtxoAccumulator: PartialEq, C::AssetMap: PartialEq"
    )
)]
pub struct StatelessSyncResponse<C, T>
where
    C: Configuration,
    T: ledger::Checkpoint,
{
    /// Checkpoint
    pub checkpoint: T,

    /// Balance Update
    pub balance_update: BalanceUpdate<C>,

    /// Utxo Accumulator
    pub utxo_accumulator: C::UtxoAccumulator,

    /// Assets
    pub assets: C::AssetMap,
}

/// Stateless Signing Response
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "TransferPost<C>: Deserialize<'de>, C::UtxoAccumulator: Deserialize<'de>",
            serialize = "TransferPost<C>: Serialize, C::UtxoAccumulator: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "TransferPost<C>: Clone, C::UtxoAccumulator: Clone"),
    Debug(bound = "TransferPost<C>: Debug, C::UtxoAccumulator: Debug"),
    Eq(bound = "TransferPost<C>: Eq, C::UtxoAccumulator: Eq"),
    Hash(bound = "TransferPost<C>: Hash, C::UtxoAccumulator: Hash"),
    PartialEq(bound = "TransferPost<C>: PartialEq, C::UtxoAccumulator: PartialEq")
)]
pub struct StatelessSignResponse<C>
where
    C: Configuration,
{
    /// Transfer Posts
    pub posts: Vec<TransferPost<C>>,

    /// Utxo Accumulator
    pub utxo_accumulator: C::UtxoAccumulator,
}

impl<C> StatelessSignResponse<C>
where
    C: Configuration,
{
    /// Creates a new [`StatelessSignResponse`] from `posts` and `utxo_accumulator`.
    pub fn new(posts: Vec<TransferPost<C>>, utxo_accumulator: C::UtxoAccumulator) -> Self {
        Self {
            posts,
            utxo_accumulator,
        }
    }
}

/// Returns the default account for `accounts`.
#[inline]
pub fn default_account<C>(accounts: &AccountTable<C>) -> Account<C::Account>
where
    C: Configuration,
{
    accounts.get_default()
}

/// Returns the default spending key for `accounts`.
#[inline]
fn default_spending_key<C>(accounts: &AccountTable<C>, parameters: &C::Parameters) -> SpendingKey<C>
where
    C: Configuration,
{
    let _ = parameters;
    accounts.get_default().spending_key()
}

/// Returns the default authorization context for `accounts`.
#[inline]
fn default_authorization_context<C>(
    accounts: &AccountTable<C>,
    parameters: &C::Parameters,
) -> AuthorizationContext<C>
where
    C: Configuration,
{
    parameters.derive_context(&default_spending_key::<C>(accounts, parameters))
}

/// Returns the authorization for the default spending key of `accounts`.
#[inline]
fn authorization_for_default_spending_key<C>(
    accounts: &AccountTable<C>,
    parameters: &C::Parameters,
    rng: &mut C::Rng,
) -> Authorization<C>
where
    C: Configuration,
{
    Authorization::<C>::from_spending_key(
        parameters,
        &default_spending_key::<C>(accounts, parameters),
        rng,
    )
}

/// Returns the address for the default account of `accounts`.
#[inline]
fn default_address<C>(accounts: &AccountTable<C>, parameters: &C::Parameters) -> Address<C>
where
    C: Configuration,
{
    accounts.get_default().address(parameters)
}

/// Hashes `utxo` using the [`UtxoAccumulatorItemHash`](transfer::Configuration::UtxoAccumulatorItemHash)
/// in the transfer [`Configuration`](transfer::Configuration).
#[inline]
fn item_hash<C>(parameters: &C::Parameters, utxo: &Utxo<C>) -> UtxoAccumulatorItem<C>
where
    C: Configuration,
{
    parameters
        .utxo_accumulator_item_hash()
        .item_hash(utxo, &mut ())
}

/// Inserts the hash of `utxo` in `utxo_accumulator`.
#[allow(clippy::too_many_arguments)]
#[inline]
fn insert_next_item<C>(
    authorization_context: &mut AuthorizationContext<C>,
    utxo_accumulator: &mut C::UtxoAccumulator,
    assets: &mut C::AssetMap,
    parameters: &Parameters<C>,
    utxo: Utxo<C>,
    identified_asset: IdentifiedAsset<C>,
    nullifiers: &mut Vec<Nullifier<C>>,
    deposit: &mut Vec<Asset<C>>,
    rng: &mut C::Rng,
) where
    C: Configuration,
{
    let IdentifiedAsset::<C> { identifier, asset } = identified_asset;
    let (_, computed_utxo, nullifier) = parameters.derive_spend(
        authorization_context,
        identifier.clone(),
        asset.clone(),
        rng,
    );
    if computed_utxo.is_related(&utxo) {
        if let Some(index) = nullifiers
            .iter()
            .position(move |n| n.is_related(&nullifier))
        {
            nullifiers.remove(index);
        } else {
            utxo_accumulator.insert(&item_hash::<C>(parameters, &utxo));
            if !asset.is_zero() {
                deposit.push(asset.clone());
            }
            assets.insert(identifier, asset);
            return;
        }
    }
    utxo_accumulator.insert_nonprovable(&item_hash::<C>(parameters, &utxo));
}

/// Checks if `asset` matches with `nullifier`, removing it from the `utxo_accumulator` and
/// inserting it into the `withdraw` set if this is the case.
#[allow(clippy::too_many_arguments)]
#[inline]
fn is_asset_unspent<C>(
    authorization_context: &mut AuthorizationContext<C>,
    utxo_accumulator: &mut C::UtxoAccumulator,
    parameters: &Parameters<C>,
    identifier: Identifier<C>,
    asset: Asset<C>,
    nullifiers: &mut Vec<Nullifier<C>>,
    withdraw: &mut Vec<Asset<C>>,
    rng: &mut C::Rng,
) -> bool
where
    C: Configuration,
{
    let (_, utxo, nullifier) =
        parameters.derive_spend(authorization_context, identifier, asset.clone(), rng);
    if let Some(index) = nullifiers
        .iter()
        .position(move |n| n.is_related(&nullifier))
    {
        nullifiers.remove(index);
        utxo_accumulator.remove_proof(&item_hash::<C>(parameters, &utxo));
        if !asset.is_zero() {
            withdraw.push(asset);
        }
        false
    } else {
        true
    }
}

/// Updates the internal ledger state, returning the new asset distribution.
#[allow(clippy::too_many_arguments)]
#[inline]
fn sync_with<C, I>(
    accounts: &AccountTable<C>,
    mut assets: C::AssetMap,
    mut checkpoint: C::Checkpoint,
    mut utxo_accumulator: C::UtxoAccumulator,
    parameters: &Parameters<C>,
    inserts: I,
    mut nullifiers: Vec<Nullifier<C>>,
    is_partial: bool,
    rng: &mut C::Rng,
) -> StatelessSyncResponse<C, C::Checkpoint>
where
    C: Configuration,
    I: Iterator<Item = (Utxo<C>, Note<C>)>,
{
    let nullifier_count = nullifiers.len();
    let mut deposit = Vec::new();
    let mut withdraw = Vec::new();
    let mut authorization_context = default_authorization_context::<C>(accounts, parameters);
    let decryption_key = parameters.derive_decryption_key(&mut authorization_context);
    for (utxo, note) in inserts {
        if let Some((identifier, asset)) = parameters.open_with_check(&decryption_key, &utxo, note)
        {
            insert_next_item::<C>(
                &mut authorization_context,
                &mut utxo_accumulator,
                &mut assets,
                parameters,
                utxo,
                transfer::utxo::IdentifiedAsset::new(identifier, asset),
                &mut nullifiers,
                &mut deposit,
                rng,
            );
        } else {
            utxo_accumulator.insert_nonprovable(&item_hash::<C>(parameters, &utxo));
        }
    }
    assets.retain(|identifier, assets| {
        assets.retain(|asset| {
            is_asset_unspent::<C>(
                &mut authorization_context,
                &mut utxo_accumulator,
                parameters,
                identifier.clone(),
                asset.clone(),
                &mut nullifiers,
                &mut withdraw,
                rng,
            )
        });
        !assets.is_empty()
    });
    checkpoint.update_from_nullifiers(nullifier_count);
    checkpoint.update_from_utxo_accumulator(&utxo_accumulator);
    StatelessSyncResponse {
        checkpoint,
        balance_update: if is_partial {
            // TODO: Whenever we are doing a full update, don't even build the `deposit` and
            //       `withdraw` vectors, since we won't be needing them.
            BalanceUpdate::Partial { deposit, withdraw }
        } else {
            BalanceUpdate::Full {
                assets: assets.assets().into(),
            }
        },
        utxo_accumulator,
        assets,
    }
}

/// Builds the [`PreSender`] associated to `identifier` and `asset`.
#[inline]
fn build_pre_sender<C>(
    accounts: &AccountTable<C>,
    parameters: &Parameters<C>,
    identifier: Identifier<C>,
    asset: Asset<C>,
    rng: &mut C::Rng,
) -> PreSender<C>
where
    C: Configuration,
{
    PreSender::<C>::sample(
        parameters,
        &mut default_authorization_context::<C>(accounts, parameters),
        identifier,
        asset,
        rng,
    )
}

/// Builds the [`Receiver`] associated with `address` and `asset`.
#[inline]
fn receiver<C>(
    parameters: &Parameters<C>,
    address: Address<C>,
    asset: Asset<C>,
    associated_data: AssociatedData<C>,
    rng: &mut C::Rng,
) -> Receiver<C>
where
    C: Configuration,
{
    Receiver::<C>::sample(parameters, address, asset, associated_data, rng)
}

/// Builds the [`Receiver`] associated with the default address and `asset`.
#[inline]
fn default_receiver<C>(
    accounts: &AccountTable<C>,
    parameters: &Parameters<C>,
    asset: Asset<C>,
    rng: &mut C::Rng,
) -> Receiver<C>
where
    C: Configuration,
{
    let default_address = default_address::<C>(accounts, parameters);
    receiver::<C>(parameters, default_address, asset, Default::default(), rng)
}

/// Selects the pre-senders which collectively own at least `asset`, returning any change.
#[inline]
fn select<C>(
    accounts: &AccountTable<C>,
    assets: &C::AssetMap,
    parameters: &Parameters<C>,
    asset: &Asset<C>,
    rng: &mut C::Rng,
) -> Result<Selection<C>, SignError<C>>
where
    C: Configuration,
{
    let selection = assets.select(asset);
    if !asset.is_zero() && selection.is_empty() {
        return Err(SignError::InsufficientBalance(asset.clone()));
    }
    Selection::new(selection, move |k, v| {
        Ok(build_pre_sender::<C>(
            accounts,
            parameters,
            k,
            Asset::<C>::new(asset.id.clone(), v),
            rng,
        ))
    })
}

/// Builds a [`TransferPost`] for the given `transfer`.
#[inline]
fn build_post_inner<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
>(
    parameters: FullParametersRef<C>,
    proving_context: &ProvingContext<C>,
    spending_key: Option<&SpendingKey<C>>,
    transfer: Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
    rng: &mut C::Rng,
) -> Result<TransferPost<C>, SignError<C>>
where
    C: Configuration,
{
    transfer
        .into_post(parameters, proving_context, spending_key, rng)
        .map(|p| p.expect("Internally, all transfer posts are constructed correctly."))
        .map_err(SignError::ProofSystemError)
}

/// Builds a [`TransferPost`] for the given `transfer`.
#[inline]
fn build_post<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
>(
    accounts: &AccountTable<C>,
    utxo_accumulator_model: &UtxoAccumulatorModel<C>,
    parameters: &Parameters<C>,
    proving_context: &ProvingContext<C>,
    transfer: Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
    rng: &mut C::Rng,
) -> Result<TransferPost<C>, SignError<C>>
where
    C: Configuration,
{
    let spending_key = default_spending_key::<C>(accounts, parameters);
    build_post_inner(
        FullParametersRef::<C>::new(parameters, utxo_accumulator_model),
        proving_context,
        requires_authorization(SENDERS).then_some(&spending_key),
        transfer,
        rng,
    )
}

/// Computes the next [`Join`](Join) element for an asset rebalancing round.
#[allow(clippy::type_complexity)] // NOTE: Clippy is too harsh here.
#[inline]
fn next_join<C>(
    accounts: &AccountTable<C>,
    parameters: &Parameters<C>,
    asset_id: &C::AssetId,
    total: C::AssetValue,
    rng: &mut C::Rng,
) -> Result<([Receiver<C>; PrivateTransferShape::RECEIVERS], Join<C>), SignError<C>>
where
    C: Configuration,
{
    Ok(Join::new(
        parameters,
        &mut default_authorization_context::<C>(accounts, parameters),
        default_address::<C>(accounts, parameters),
        Asset::<C>::new(asset_id.clone(), total),
        rng,
    ))
}

/// Prepares the final pre-senders for the last part of the transaction.
#[allow(clippy::too_many_arguments)]
#[inline]
fn prepare_final_pre_senders<C>(
    accounts: &AccountTable<C>,
    assets: &C::AssetMap,
    utxo_accumulator: &C::UtxoAccumulator,
    parameters: &Parameters<C>,
    asset_id: &C::AssetId,
    mut new_zeroes: Vec<PreSender<C>>,
    pre_senders: Vec<PreSender<C>>,
    rng: &mut C::Rng,
) -> Result<Vec<Sender<C>>, SignError<C>>
where
    C: Configuration,
{
    let mut senders = pre_senders
        .into_iter()
        .map(|s| s.try_upgrade(parameters, utxo_accumulator))
        .collect::<Option<Vec<_>>>()
        .expect("Unable to upgrade expected UTXOs.");
    let mut needed_zeroes = PrivateTransferShape::SENDERS - senders.len();
    if needed_zeroes == 0 {
        return Ok(senders);
    }
    let zeroes = assets.zeroes(needed_zeroes, asset_id);
    needed_zeroes -= zeroes.len();
    for zero in zeroes {
        let pre_sender = build_pre_sender::<C>(
            accounts,
            parameters,
            zero,
            Asset::<C>::new(asset_id.clone(), Default::default()),
            rng,
        );
        senders.push(
            pre_sender
                .try_upgrade(parameters, utxo_accumulator)
                .expect("Unable to upgrade expected UTXOs."),
        );
    }
    if needed_zeroes == 0 {
        return Ok(senders);
    }
    let needed_fake_zeroes = needed_zeroes.saturating_sub(new_zeroes.len());
    for _ in 0..needed_zeroes {
        match new_zeroes.pop() {
            Some(zero) => senders.push(
                zero.try_upgrade(parameters, utxo_accumulator)
                    .expect("Unable to upgrade expected UTXOs."),
            ),
            _ => break,
        }
    }
    if needed_fake_zeroes == 0 {
        return Ok(senders);
    }
    for _ in 0..needed_fake_zeroes {
        let identifier = rng.gen();
        senders.push(
            build_pre_sender::<C>(
                accounts,
                parameters,
                identifier,
                Asset::<C>::new(asset_id.clone(), Default::default()),
                rng,
            )
            .upgrade_unchecked(Default::default()),
        );
    }
    Ok(senders)
}

/// Builds two virtual [`Sender`]s for `pre_sender`.
#[inline]
fn virtual_senders<C>(
    accounts: &AccountTable<C>,
    utxo_accumulator_model: &UtxoAccumulatorModel<C>,
    parameters: &Parameters<C>,
    asset_id: &C::AssetId,
    pre_sender: PreSender<C>,
    rng: &mut C::Rng,
) -> Result<[Sender<C>; PrivateTransferShape::SENDERS], SignError<C>>
where
    C: Configuration,
{
    let mut utxo_accumulator = C::UtxoAccumulator::empty(utxo_accumulator_model);
    let sender = pre_sender
        .insert_and_upgrade(parameters, &mut utxo_accumulator)
        .expect("Unable to upgrade expected UTXO.");
    let mut senders = Vec::new();
    senders.push(sender);
    let identifier = rng.gen();
    senders.push(
        build_pre_sender::<C>(
            accounts,
            parameters,
            identifier,
            Asset::<C>::new(asset_id.clone(), Default::default()),
            rng,
        )
        .upgrade_unchecked(Default::default()),
    );
    Ok(into_array_unchecked(senders))
}

/// Computes the batched transactions for rebalancing before a final transfer.
#[allow(clippy::too_many_arguments)]
#[inline]
fn compute_batched_transactions<C>(
    accounts: &AccountTable<C>,
    assets: &C::AssetMap,
    mut utxo_accumulator: C::UtxoAccumulator,
    parameters: &Parameters<C>,
    proving_context: &MultiProvingContext<C>,
    asset_id: &C::AssetId,
    mut pre_senders: Vec<PreSender<C>>,
    posts: &mut Vec<TransferPost<C>>,
    rng: &mut C::Rng,
) -> Result<StatelessBatchedTransaction<C>, SignError<C>>
where
    C: Configuration,
{
    let mut new_zeroes = Vec::new();
    while pre_senders.len() > PrivateTransferShape::SENDERS {
        let mut joins = Vec::new();
        let mut iter = pre_senders
            .into_iter()
            .chunk_by::<{ PrivateTransferShape::SENDERS }>();
        for chunk in &mut iter {
            let senders = array_map(chunk, |s| {
                s.try_upgrade(parameters, &utxo_accumulator)
                    .expect("Unable to upgrade expected UTXO.")
            });
            let (receivers, mut join) = next_join(
                accounts,
                parameters,
                asset_id,
                senders.iter().map(|s| s.asset().value).sum(),
                rng,
            )?;
            let authorization =
                authorization_for_default_spending_key::<C>(accounts, parameters, rng);
            posts.push(build_post(
                accounts,
                utxo_accumulator.model(),
                parameters,
                &proving_context.private_transfer,
                PrivateTransfer::build(authorization, senders, receivers),
                rng,
            )?);
            join.insert_utxos(parameters, &mut utxo_accumulator);
            joins.push(join.pre_sender);
            new_zeroes.append(&mut join.zeroes);
        }
        joins.append(&mut iter.remainder());
        pre_senders = joins;
    }
    let final_presenders = prepare_final_pre_senders(
        accounts,
        assets,
        &utxo_accumulator,
        parameters,
        asset_id,
        new_zeroes,
        pre_senders,
        rng,
    )?;
    Ok((into_array_unchecked(final_presenders), utxo_accumulator))
}

/// Stateless Signer
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "SignerParameters<C>: Deserialize<'de>",
            serialize = "SignerParameters<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "SignerParameters<C>: Clone"),
    Debug(bound = "SignerParameters<C>: Debug"),
    Eq(bound = "SignerParameters<C>: Eq"),
    Hash(bound = "SignerParameters<C>: Hash"),
    PartialEq(bound = "SignerParameters<C>: PartialEq")
)]
pub struct StatelessSigner<C>
where
    C: Configuration,
{
    /// Signer Parameters
    parameters: SignerParameters<C>,
}

impl<C> StatelessSigner<C>
where
    C: Configuration,
{
    /// Builds a new [`StatelessSigner`] from `parameters`.
    #[inline]
    pub fn from_parameters(parameters: SignerParameters<C>) -> Self {
        Self { parameters }
    }

    /// Returns a shared reference to the signer parameters.
    #[inline]
    pub fn parameters(&self) -> &SignerParameters<C> {
        &self.parameters
    }

    /// Updates `assets`, `checkpoint` and `utxo_accumulator`, returning the new asset distribution.
    #[inline]
    pub fn sync(
        &self,
        accounts: &AccountTable<C>,
        assets: C::AssetMap,
        checkpoint: C::Checkpoint,
        utxo_accumulator: C::UtxoAccumulator,
        mut request: SyncRequest<C, C::Checkpoint>,
        rng: &mut C::Rng,
    ) -> Result<StatelessSyncResponse<C, C::Checkpoint>, SyncError<C::Checkpoint>> {
        // TODO: Do a capacity check on the current UTXO accumulator?
        //
        // if utxo_accumulator.capacity() < starting_index {
        //    panic!("full capacity")
        // }
        if checkpoint < request.origin_checkpoint {
            Err(SyncError::InconsistentSynchronization {
                checkpoint: checkpoint.clone(),
            })
        } else {
            let has_pruned = request.prune(
                self.parameters.parameters.utxo_accumulator_item_hash(),
                &checkpoint,
            );
            let SyncData {
                utxo_note_data,
                nullifier_data,
            } = request.data;
            let mut response = sync_with::<C, _>(
                accounts,
                assets,
                checkpoint,
                utxo_accumulator,
                &self.parameters.parameters,
                utxo_note_data.into_iter(),
                nullifier_data,
                !has_pruned,
                rng,
            );
            response.utxo_accumulator.commit();
            Ok(response)
        }
    }

    /// Signs a withdraw transaction for `asset` sent to `address`.
    #[inline]
    fn sign_withdraw(
        &self,
        accounts: &AccountTable<C>,
        assets: &C::AssetMap,
        utxo_accumulator: C::UtxoAccumulator,
        asset: Asset<C>,
        address: Option<Address<C>>,
        rng: &mut C::Rng,
    ) -> Result<StatelessSignResponse<C>, SignError<C>> {
        let selection = select(accounts, assets, &self.parameters.parameters, &asset, rng)?;
        let mut posts = Vec::new();
        let (senders, utxo_accumulator) = compute_batched_transactions(
            accounts,
            assets,
            utxo_accumulator,
            &self.parameters.parameters,
            &self.parameters.proving_context,
            &asset.id,
            selection.pre_senders,
            &mut posts,
            rng,
        )?;
        let change = default_receiver::<C>(
            accounts,
            &self.parameters.parameters,
            Asset::<C>::new(asset.id.clone(), selection.change),
            rng,
        );
        let authorization =
            authorization_for_default_spending_key::<C>(accounts, &self.parameters.parameters, rng);
        let final_post = match address {
            Some(address) => {
                let receiver = receiver::<C>(
                    &self.parameters.parameters,
                    address,
                    asset,
                    Default::default(),
                    rng,
                );
                build_post(
                    accounts,
                    utxo_accumulator.model(),
                    &self.parameters.parameters,
                    &self.parameters.proving_context.private_transfer,
                    PrivateTransfer::build(authorization, senders, [change, receiver]),
                    rng,
                )?
            }
            _ => build_post(
                accounts,
                utxo_accumulator.model(),
                &self.parameters.parameters,
                &self.parameters.proving_context.to_public,
                ToPublic::build(authorization, senders, [change], asset),
                rng,
            )?,
        };
        posts.push(final_post);
        Ok(StatelessSignResponse::new(posts, utxo_accumulator))
    }

    /// Generates an [`IdentityProof`] for `identified_asset` by
    /// signing a virtual [`ToPublic`] transaction.
    #[inline]
    pub fn identity_proof(
        &self,
        accounts: &AccountTable<C>,
        utxo_accumulator_model: &UtxoAccumulatorModel<C>,
        identified_asset: IdentifiedAsset<C>,
        rng: &mut C::Rng,
    ) -> Option<IdentityProof<C>> {
        let presender = build_pre_sender::<C>(
            accounts,
            &self.parameters.parameters,
            identified_asset.identifier,
            identified_asset.asset.clone(),
            rng,
        );
        let senders = virtual_senders::<C>(
            accounts,
            utxo_accumulator_model,
            &self.parameters.parameters,
            &identified_asset.asset.id,
            presender,
            rng,
        )
        .ok()?;
        let change = default_receiver::<C>(
            accounts,
            &self.parameters.parameters,
            Asset::<C>::new(identified_asset.asset.id.clone(), Default::default()),
            rng,
        );
        let authorization =
            authorization_for_default_spending_key::<C>(accounts, &self.parameters.parameters, rng);
        let transfer_post = build_post(
            accounts,
            utxo_accumulator_model,
            &self.parameters.parameters,
            &self.parameters.proving_context.to_public,
            ToPublic::build(authorization, senders, [change], identified_asset.asset),
            rng,
        )
        .ok()?;
        Some(IdentityProof { transfer_post })
    }

    /// Signs the `transaction`, generating transfer posts without releasing resources.
    #[inline]
    fn sign_internal(
        &self,
        accounts: &AccountTable<C>,
        assets: &C::AssetMap,
        utxo_accumulator: C::UtxoAccumulator,
        transaction: Transaction<C>,
        rng: &mut C::Rng,
    ) -> Result<StatelessSignResponse<C>, SignError<C>> {
        match transaction {
            Transaction::ToPrivate(asset) => {
                let receiver = default_receiver::<C>(
                    accounts,
                    &self.parameters.parameters,
                    asset.clone(),
                    rng,
                );
                Ok(StatelessSignResponse::new(
                    vec![build_post(
                        accounts,
                        utxo_accumulator.model(),
                        &self.parameters.parameters,
                        &self.parameters.proving_context.to_private,
                        ToPrivate::build(asset, receiver),
                        rng,
                    )?],
                    utxo_accumulator,
                ))
            }
            Transaction::PrivateTransfer(asset, address) => self.sign_withdraw(
                accounts,
                assets,
                utxo_accumulator,
                asset,
                Some(address),
                rng,
            ),
            Transaction::ToPublic(asset) => {
                self.sign_withdraw(accounts, assets, utxo_accumulator, asset, None, rng)
            }
        }
    }

    /// Signs the `transaction`, generating transfer posts.
    #[inline]
    pub fn sign(
        &self,
        accounts: &AccountTable<C>,
        assets: &C::AssetMap,
        utxo_accumulator: C::UtxoAccumulator,
        transaction: Transaction<C>,
        rng: &mut C::Rng,
    ) -> Result<StatelessSignResponse<C>, SignError<C>> {
        let mut result =
            self.sign_internal(accounts, assets, utxo_accumulator, transaction, rng)?;
        result.utxo_accumulator.rollback();
        Ok(result)
    }

    /// Returns a vector with the [`IdentityProof`] corresponding to each [`IdentifiedAsset`] in `identified_assets`.
    #[inline]
    pub fn batched_identity_proof(
        &self,
        accounts: &AccountTable<C>,
        utxo_accumulator_model: &UtxoAccumulatorModel<C>,
        identified_assets: Vec<IdentifiedAsset<C>>,
        rng: &mut C::Rng,
    ) -> IdentityResponse<C> {
        IdentityResponse(
            identified_assets
                .into_iter()
                .map(|identified_asset| {
                    self.identity_proof(accounts, utxo_accumulator_model, identified_asset, rng)
                })
                .collect(),
        )
    }

    /// Returns the [`Address`] corresponding to `self`.
    #[inline]
    pub fn address(&self, accounts: &AccountTable<C>) -> Address<C> {
        let account = default_account::<C>(accounts);
        account.address(&self.parameters.parameters)
    }

    /// Returns the associated [`TransactionData`] of `post`, namely the [`Asset`] and the
    /// [`Identifier`]. Returns `None` if `post` has an invalid shape, or if `self` doesn't own the
    /// underlying assets in `post`.
    #[inline]
    pub fn transaction_data(
        &self,
        accounts: &AccountTable<C>,
        post: TransferPost<C>,
    ) -> Option<TransactionData<C>> {
        let shape = TransferShape::from_post(&post)?;
        let parameters = &self.parameters.parameters;
        let mut authorization_context = default_authorization_context::<C>(accounts, parameters);
        let decryption_key = parameters.derive_decryption_key(&mut authorization_context);
        match shape {
            TransferShape::ToPrivate => {
                let ReceiverPost { utxo, note } = post.body.receiver_posts.take_first();
                let (identifier, asset) =
                    parameters.open_with_check(&decryption_key, &utxo, note)?;
                Some(TransactionData::<C>::ToPrivate(identifier, asset))
            }
            TransferShape::PrivateTransfer => {
                let mut transaction_data = Vec::new();
                let receiver_posts = post.body.receiver_posts;
                for receiver_post in receiver_posts.into_iter() {
                    let ReceiverPost { utxo, note } = receiver_post;
                    if let Some(identified_asset) =
                        parameters.open_with_check(&decryption_key, &utxo, note)
                    {
                        transaction_data.push(identified_asset);
                    }
                }
                if transaction_data.is_empty() {
                    None
                } else {
                    Some(TransactionData::<C>::PrivateTransfer(transaction_data))
                }
            }
            TransferShape::ToPublic => {
                let ReceiverPost { utxo, note } = post.body.receiver_posts.take_first();
                let (identifier, asset) =
                    parameters.open_with_check(&decryption_key, &utxo, note)?;
                Some(TransactionData::<C>::ToPublic(identifier, asset))
            }
        }
    }

    /// Returns a vector with the [`TransactionData`] of each well-formed [`TransferPost`] owned by
    /// `self`.
    #[inline]
    pub fn batched_transaction_data(
        &self,
        accounts: &AccountTable<C>,
        posts: Vec<TransferPost<C>>,
    ) -> TransactionDataResponse<C> {
        TransactionDataResponse(
            posts
                .into_iter()
                .map(|p| self.transaction_data(accounts, p))
                .collect(),
        )
    }
}

impl<C> StatelessSignerConnection<C> for StatelessSigner<C>
where
    C: Configuration,
{
    type Error = Infallible;

    #[inline]
    fn sync<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
        assets: C::AssetMap,
        checkpoint: C::Checkpoint,
        utxo_accumulator: C::UtxoAccumulator,
        request: SyncRequest<C, C::Checkpoint>,
        rng: &'a mut C::Rng,
    ) -> LocalBoxFutureResult<StatelessSyncResult<C, C::Checkpoint>, Self::Error> {
        Box::pin(async move {
            Ok(self.sync(accounts, assets, checkpoint, utxo_accumulator, request, rng))
        })
    }

    #[inline]
    fn sign<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
        assets: &'a C::AssetMap,
        utxo_accumulator: C::UtxoAccumulator,
        request: SignRequest<C::AssetMetadata, C>,
        rng: &'a mut C::Rng,
    ) -> LocalBoxFutureResult<StatelessSignResult<C>, Self::Error> {
        Box::pin(async move {
            Ok(self.sign(accounts, assets, utxo_accumulator, request.transaction, rng))
        })
    }

    #[inline]
    fn address<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
    ) -> LocalBoxFutureResult<Address<C>, Self::Error> {
        Box::pin(async move { Ok(self.address(accounts)) })
    }

    #[inline]
    fn transaction_data<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
        request: TransactionDataRequest<C>,
    ) -> LocalBoxFutureResult<TransactionDataResponse<C>, Self::Error> {
        Box::pin(async move { Ok(self.batched_transaction_data(accounts, request.0)) })
    }

    #[inline]
    fn identity_proof<'a>(
        &'a self,
        accounts: &'a AccountTable<C>,
        utxo_accumulator_model: &'a UtxoAccumulatorModel<C>,
        request: IdentityRequest<C>,
        rng: &'a mut C::Rng,
    ) -> LocalBoxFutureResult<IdentityResponse<C>, Self::Error> {
        Box::pin(async move {
            Ok(self.batched_identity_proof(accounts, utxo_accumulator_model, request.0, rng))
        })
    }
}
