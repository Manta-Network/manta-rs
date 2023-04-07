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

//! Signer Functions

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
        utxo::{
            auth::DeriveContext, DeriveAddress as _, DeriveDecryptionKey, DeriveSpend, Spend,
            UtxoReconstruct,
        },
        Address, Asset, AssociatedData, Authorization, AuthorizationContext, FullParametersRef,
        IdentifiedAsset, Identifier, IdentityProof, Note, Nullifier, Parameters, PreSender,
        ProvingContext, Receiver, Sender, Shape, SpendingKey, Transfer, TransferPost, Utxo,
        UtxoAccumulatorItem, UtxoAccumulatorModel, UtxoAccumulatorWitness,
    },
    wallet::signer::{
        AccountTable, BalanceUpdate, Checkpoint, Configuration, InitialSyncRequest, SignError,
        SignResponse, SignWithTransactionDataResponse, SignWithTransactionDataResult,
        SignerParameters, SyncData, SyncError, SyncRequest, SyncResponse,
    },
};
use alloc::{vec, vec::Vec};
use manta_crypto::{
    accumulator::{
        Accumulator, BatchInsertion, FromItemsAndWitnesses, ItemHashFunction, OptimizedAccumulator,
    },
    rand::Rand,
};
use manta_util::{
    array_map, cmp::Independence, into_array_unchecked, iter::IteratorExt, persistence::Rollback,
    vec::VecExt,
};

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
pub fn default_authorization_context<C>(
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

/// Returns the address for `authorization_context`.
#[inline]
fn address_from_authorization_context<C>(
    authorization_context: &mut AuthorizationContext<C>,
    parameters: &C::Parameters,
) -> Address<C>
where
    C: Configuration,
{
    parameters.derive_address(&parameters.derive_decryption_key(authorization_context))
}

/// Hashes `utxo` using the [`UtxoAccumulatorItemHash`](transfer::Configuration::UtxoAccumulatorItemHash)
/// in the transfer [`Configuration`](transfer::Configuration).
#[inline]
pub fn item_hash<C>(parameters: &C::Parameters, utxo: &Utxo<C>) -> UtxoAccumulatorItem<C>
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
    identified_asset: IdentifiedAsset<C>,
    nullifiers: &mut Vec<Nullifier<C>>,
    deposit: &mut Vec<Asset<C>>,
    rng: &mut C::Rng,
) where
    C: Configuration,
{
    let IdentifiedAsset::<C> { identifier, asset } = identified_asset;
    let (_, utxo, nullifier) = parameters.derive_spend(
        authorization_context,
        identifier.clone(),
        asset.clone(),
        rng,
    );
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
    authorization_context: &mut AuthorizationContext<C>,
    assets: &mut C::AssetMap,
    checkpoint: &mut C::Checkpoint,
    utxo_accumulator: &mut C::UtxoAccumulator,
    parameters: &Parameters<C>,
    inserts: I,
    mut nullifiers: Vec<Nullifier<C>>,
    is_partial: bool,
    rng: &mut C::Rng,
) -> SyncResponse<C, C::Checkpoint>
where
    C: Configuration,
    I: Iterator<Item = (Utxo<C>, Note<C>)>,
{
    let nullifier_count = nullifiers.len();
    let mut deposit = Vec::new();
    let mut withdraw = Vec::new();
    let decryption_key = parameters.derive_decryption_key(authorization_context);
    let mut nonprovable_inserts = Vec::new();
    for (utxo, note) in inserts {
        if let Some((identifier, asset)) = parameters.open_with_check(&decryption_key, &utxo, note)
        {
            if !nonprovable_inserts.is_empty() {
                utxo_accumulator.batch_insert_nonprovable(&nonprovable_inserts);
                nonprovable_inserts.clear();
            }
            insert_next_item::<C>(
                authorization_context,
                utxo_accumulator,
                assets,
                parameters,
                transfer::utxo::IdentifiedAsset::new(identifier, asset),
                &mut nullifiers,
                &mut deposit,
                rng,
            );
        } else {
            nonprovable_inserts.push(item_hash::<C>(parameters, &utxo));
        }
    }
    if !nonprovable_inserts.is_empty() {
        utxo_accumulator.batch_insert_nonprovable(&nonprovable_inserts);
    }
    assets.retain(|identifier, assets| {
        assets.retain(|asset| {
            is_asset_unspent::<C>(
                authorization_context,
                utxo_accumulator,
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
    checkpoint.update_from_utxo_accumulator(utxo_accumulator);
    SyncResponse {
        checkpoint: checkpoint.clone(),
        balance_update: if is_partial {
            // TODO: Whenever we are doing a full update, don't even build the `deposit` and
            //       `withdraw` vectors, since we won't be needing them.
            BalanceUpdate::Partial { deposit, withdraw }
        } else {
            BalanceUpdate::Full {
                assets: assets.assets().into(),
            }
        },
    }
}

/// Updates the internal ledger state, returning the new asset distribution.
#[allow(clippy::too_many_arguments)]
#[inline]
fn sbt_sync_with<C, I>(
    authorization_context: &mut AuthorizationContext<C>,
    assets: &mut C::AssetMap,
    checkpoint: &mut C::Checkpoint,
    parameters: &Parameters<C>,
    inserts: I,
    utxo_count: Vec<usize>,
    nullifier_count: usize,
    is_partial: bool,
) -> SyncResponse<C, C::Checkpoint>
where
    C: Configuration,
    I: Iterator<Item = (Utxo<C>, Note<C>)>,
{
    let mut deposit = Vec::new();
    let decryption_key = parameters.derive_decryption_key(authorization_context);
    for (utxo, note) in inserts {
        if let Some((identifier, asset)) = parameters.open_with_check(&decryption_key, &utxo, note)
        {
            if !asset.is_zero() {
                deposit.push(asset.clone());
            }
            assets.insert(identifier, asset);
        }
    }
    checkpoint.update_from_nullifiers(nullifier_count);
    checkpoint.update_from_utxo_count(utxo_count);
    SyncResponse {
        checkpoint: checkpoint.clone(),
        balance_update: if is_partial {
            // TODO: Whenever we are doing a full update, don't even build the `deposit` and
            //       `withdraw` vectors, since we won't be needing them.
            BalanceUpdate::Partial {
                deposit,
                withdraw: Default::default(),
            }
        } else {
            BalanceUpdate::Full {
                assets: assets.assets().into(),
            }
        },
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

/// Builds the [`Receiver`] associated with `authorization_context` and `asset`.
#[inline]
fn receiver_from_authorization_context<C>(
    authorization_context: &mut AuthorizationContext<C>,
    parameters: &Parameters<C>,
    asset: Asset<C>,
    rng: &mut C::Rng,
) -> Receiver<C>
where
    C: Configuration,
{
    let address = address_from_authorization_context::<C>(authorization_context, parameters);
    receiver::<C>(parameters, address, asset, Default::default(), rng)
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
    sink_accounts: Vec<C::AccountId>,
    rng: &mut C::Rng,
) -> Result<TransferPost<C>, SignError<C>>
where
    C: Configuration,
{
    transfer
        .into_post(
            parameters,
            proving_context,
            spending_key,
            sink_accounts,
            rng,
        )
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
    accounts: Option<&AccountTable<C>>,
    utxo_accumulator_model: &UtxoAccumulatorModel<C>,
    parameters: &Parameters<C>,
    proving_context: &ProvingContext<C>,
    transfer: Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
    sink_accounts: Vec<C::AccountId>,
    rng: &mut C::Rng,
) -> Result<TransferPost<C>, SignError<C>>
where
    C: Configuration,
{
    let spending_key = if requires_authorization(SENDERS) {
        Some(default_spending_key::<C>(
            accounts.ok_or(SignError::MissingSpendingKey)?,
            parameters,
        ))
    } else {
        None
    };
    build_post_inner(
        FullParametersRef::<C>::new(parameters, utxo_accumulator_model),
        proving_context,
        spending_key.as_ref(),
        transfer,
        sink_accounts,
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
    utxo_accumulator: &mut C::UtxoAccumulator,
    parameters: &Parameters<C>,
    proving_context: &MultiProvingContext<C>,
    asset_id: &C::AssetId,
    mut pre_senders: Vec<PreSender<C>>,
    posts: &mut Vec<TransferPost<C>>,
    rng: &mut C::Rng,
) -> Result<[Sender<C>; PrivateTransferShape::SENDERS], SignError<C>>
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
                s.try_upgrade(parameters, utxo_accumulator)
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
                Some(accounts),
                utxo_accumulator.model(),
                parameters,
                &proving_context.private_transfer,
                PrivateTransfer::build(authorization, senders, receivers),
                Vec::new(),
                rng,
            )?);
            join.insert_utxos(parameters, utxo_accumulator);
            joins.push(join.pre_sender);
            new_zeroes.append(&mut join.zeroes);
        }
        joins.append(&mut iter.remainder());
        pre_senders = joins;
    }
    let final_presenders = prepare_final_pre_senders(
        accounts,
        assets,
        utxo_accumulator,
        parameters,
        asset_id,
        new_zeroes,
        pre_senders,
        rng,
    )?;
    Ok(into_array_unchecked(final_presenders))
}

/// Returns the [`Address`] corresponding to `authorization_context`.
#[inline]
pub fn address<C>(
    parameters: &SignerParameters<C>,
    authorization_context: &mut AuthorizationContext<C>,
) -> Address<C>
where
    C: Configuration,
{
    address_from_authorization_context::<C>(authorization_context, &parameters.parameters)
}

/// Checks that the origin checkpoint in `request` is less or equal than `checkpoint`.
/// If it is strictly less, it prunes the data in `request` accordingly.
#[inline]
fn prune_sync_request<C>(
    parameters: &SignerParameters<C>,
    checkpoint: &C::Checkpoint,
    mut request: SyncRequest<C, C::Checkpoint>,
) -> Result<(bool, SyncData<C>), SyncError<C::Checkpoint>>
where
    C: Configuration,
{
    // TODO: Do a capacity check on the current UTXO accumulator?
    //
    // if utxo_accumulator.capacity() < starting_index {
    //    panic!("full capacity")
    // }
    if checkpoint < &mut request.origin_checkpoint {
        Err(SyncError::InconsistentSynchronization {
            checkpoint: checkpoint.clone(),
        })
    } else {
        let has_pruned = request.prune(
            parameters.parameters.utxo_accumulator_item_hash(),
            checkpoint,
        );
        Ok((has_pruned, request.data))
    }
}

/// Updates `assets` and `checkpoint`, returning the new asset distribution.
#[inline]
pub fn sbt_sync<C>(
    parameters: &SignerParameters<C>,
    authorization_context: &mut AuthorizationContext<C>,
    assets: &mut C::AssetMap,
    checkpoint: &mut C::Checkpoint,
    request: SyncRequest<C, C::Checkpoint>,
) -> Result<SyncResponse<C, C::Checkpoint>, SyncError<C::Checkpoint>>
where
    C: Configuration,
{
    let utxo_count = request.utxo_count(&parameters.parameters);
    let (
        has_pruned,
        SyncData {
            utxo_note_data,
            nullifier_data,
        },
    ) = prune_sync_request(parameters, checkpoint, request)?;
    Ok(sbt_sync_with(
        authorization_context,
        assets,
        checkpoint,
        &parameters.parameters,
        utxo_note_data.into_iter(),
        utxo_count,
        nullifier_data.len(),
        !has_pruned,
    ))
}

/// Updates `assets`, `checkpoint` and `utxo_accumulator`, returning the new asset distribution.
#[inline]
pub fn sync<C>(
    parameters: &SignerParameters<C>,
    authorization_context: &mut AuthorizationContext<C>,
    assets: &mut C::AssetMap,
    checkpoint: &mut C::Checkpoint,
    utxo_accumulator: &mut C::UtxoAccumulator,
    request: SyncRequest<C, C::Checkpoint>,
    rng: &mut C::Rng,
) -> Result<SyncResponse<C, C::Checkpoint>, SyncError<C::Checkpoint>>
where
    C: Configuration,
{
    let (
        has_pruned,
        SyncData {
            utxo_note_data,
            nullifier_data,
        },
    ) = prune_sync_request(parameters, checkpoint, request)?;
    let response = sync_with::<C, _>(
        authorization_context,
        assets,
        checkpoint,
        utxo_accumulator,
        &parameters.parameters,
        utxo_note_data.into_iter(),
        nullifier_data,
        !has_pruned,
        rng,
    );
    utxo_accumulator.commit();
    Ok(response)
}

/// Signs a withdraw transaction for `asset` sent to `address`.
#[allow(clippy::too_many_arguments)]
#[inline]
fn sign_withdraw<C>(
    parameters: &SignerParameters<C>,
    accounts: &AccountTable<C>,
    assets: &C::AssetMap,
    utxo_accumulator: &mut C::UtxoAccumulator,
    asset: Asset<C>,
    address: Option<Address<C>>,
    sink_accounts: Vec<C::AccountId>,
    rng: &mut C::Rng,
) -> Result<SignResponse<C>, SignError<C>>
where
    C: Configuration,
{
    let selection = select(accounts, assets, &parameters.parameters, &asset, rng)?;
    let mut posts = Vec::new();
    let senders = compute_batched_transactions(
        accounts,
        assets,
        utxo_accumulator,
        &parameters.parameters,
        &parameters.proving_context,
        &asset.id,
        selection.pre_senders,
        &mut posts,
        rng,
    )?;
    let change = default_receiver::<C>(
        accounts,
        &parameters.parameters,
        Asset::<C>::new(asset.id.clone(), selection.change),
        rng,
    );
    let authorization =
        authorization_for_default_spending_key::<C>(accounts, &parameters.parameters, rng);
    let final_post = match address {
        Some(address) => {
            let receiver = receiver::<C>(
                &parameters.parameters,
                address,
                asset,
                Default::default(),
                rng,
            );
            build_post(
                Some(accounts),
                utxo_accumulator.model(),
                &parameters.parameters,
                &parameters.proving_context.private_transfer,
                PrivateTransfer::build(authorization, senders, [change, receiver]),
                Vec::new(),
                rng,
            )?
        }
        _ => build_post(
            Some(accounts),
            utxo_accumulator.model(),
            &parameters.parameters,
            &parameters.proving_context.to_public,
            ToPublic::build(authorization, senders, [change], asset),
            sink_accounts,
            rng,
        )?,
    };
    posts.push(final_post);
    Ok(SignResponse::new(posts))
}

/// Signs the `transaction`, generating transfer posts without releasing resources.
#[inline]
fn sign_internal<C>(
    parameters: &SignerParameters<C>,
    accounts: Option<&AccountTable<C>>,
    authorization_context: Option<&mut AuthorizationContext<C>>,
    assets: &C::AssetMap,
    utxo_accumulator: &mut C::UtxoAccumulator,
    transaction: Transaction<C>,
    rng: &mut C::Rng,
) -> Result<SignResponse<C>, SignError<C>>
where
    C: Configuration,
{
    match transaction {
        Transaction::ToPrivate(asset) => {
            let receiver = receiver_from_authorization_context::<C>(
                authorization_context.ok_or(SignError::MissingProofAuthorizationKey)?,
                &parameters.parameters,
                asset.clone(),
                rng,
            );
            Ok(SignResponse::new(vec![build_post(
                None,
                utxo_accumulator.model(),
                &parameters.parameters,
                &parameters.proving_context.to_private,
                ToPrivate::build(asset, receiver),
                Vec::new(),
                rng,
            )?]))
        }
        Transaction::PrivateTransfer(asset, address) => sign_withdraw(
            parameters,
            accounts.ok_or(SignError::MissingSpendingKey)?,
            assets,
            utxo_accumulator,
            asset,
            Some(address),
            Vec::new(),
            rng,
        ),
        Transaction::ToPublic(asset, public_account) => sign_withdraw(
            parameters,
            accounts.ok_or(SignError::MissingSpendingKey)?,
            assets,
            utxo_accumulator,
            asset,
            None,
            Vec::from([public_account]),
            rng,
        ),
    }
}

/// Signs the `transaction`, generating transfer posts.
#[inline]
pub fn sign<C>(
    parameters: &SignerParameters<C>,
    accounts: Option<&AccountTable<C>>,
    authorization_context: Option<&mut AuthorizationContext<C>>,
    assets: &C::AssetMap,
    utxo_accumulator: &mut C::UtxoAccumulator,
    transaction: Transaction<C>,
    rng: &mut C::Rng,
) -> Result<SignResponse<C>, SignError<C>>
where
    C: Configuration,
{
    let result = sign_internal(
        parameters,
        accounts,
        authorization_context,
        assets,
        utxo_accumulator,
        transaction,
        rng,
    )?;
    utxo_accumulator.rollback();
    Ok(result)
}

/// Generates an [`IdentityProof`] for `identified_asset` by
/// signing a virtual [`ToPublic`] transaction.
#[inline]
pub fn identity_proof<C>(
    parameters: &SignerParameters<C>,
    accounts: &AccountTable<C>,
    utxo_accumulator_model: &UtxoAccumulatorModel<C>,
    identified_asset: IdentifiedAsset<C>,
    public_account: C::AccountId,
    rng: &mut C::Rng,
) -> Option<IdentityProof<C>>
where
    C: Configuration,
{
    let presender = build_pre_sender::<C>(
        accounts,
        &parameters.parameters,
        identified_asset.identifier,
        identified_asset.asset.clone(),
        rng,
    );
    let senders = virtual_senders::<C>(
        accounts,
        utxo_accumulator_model,
        &parameters.parameters,
        &identified_asset.asset.id,
        presender,
        rng,
    )
    .ok()?;
    let change = default_receiver::<C>(
        accounts,
        &parameters.parameters,
        Asset::<C>::new(identified_asset.asset.id.clone(), Default::default()),
        rng,
    );
    let authorization =
        authorization_for_default_spending_key::<C>(accounts, &parameters.parameters, rng);
    let transfer_post = build_post(
        Some(accounts),
        utxo_accumulator_model,
        &parameters.parameters,
        &parameters.proving_context.to_public,
        ToPublic::build(authorization, senders, [change], identified_asset.asset),
        Vec::from([public_account]),
        rng,
    )
    .ok()?;
    Some(IdentityProof { transfer_post })
}

/// Returns the associated [`TransactionData`] of `post`, namely the [`Asset`] and the
/// [`Identifier`]. Returns `None` if `post` has an invalid shape, or if `authorization_context`
/// can't decrypt the underlying assets in `post`.
#[inline]
pub fn transaction_data<C>(
    parameters: &SignerParameters<C>,
    authorization_context: &mut AuthorizationContext<C>,
    post: TransferPost<C>,
) -> Option<TransactionData<C>>
where
    C: Configuration,
{
    let shape = TransferShape::from_post(&post)?;
    let parameters = &parameters.parameters;
    let decryption_key = parameters.derive_decryption_key(authorization_context);
    match shape {
        TransferShape::ToPrivate => {
            let ReceiverPost { utxo, note } = post.body.receiver_posts.take_first();
            let (identifier, asset) = parameters.open_with_check(&decryption_key, &utxo, note)?;
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
            let (identifier, asset) = parameters.open_with_check(&decryption_key, &utxo, note)?;
            Some(TransactionData::<C>::ToPublic(identifier, asset))
        }
    }
}

/// Signs the `transaction`, generating transfer posts
/// and returning their [`TransactionData`].
#[inline]
pub fn sign_with_transaction_data<C>(
    parameters: &SignerParameters<C>,
    accounts: Option<&AccountTable<C>>,
    authorization_context: &mut AuthorizationContext<C>,
    assets: &C::AssetMap,
    utxo_accumulator: &mut C::UtxoAccumulator,
    transaction: Transaction<C>,
    rng: &mut C::Rng,
) -> SignWithTransactionDataResult<C>
where
    C: Configuration,
    TransferPost<C>: Clone,
{
    Ok(SignWithTransactionDataResponse(
        sign(
            parameters,
            accounts,
            Some(authorization_context),
            assets,
            utxo_accumulator,
            transaction,
            rng,
        )?
        .posts
        .into_iter()
        .map(|post| {
            (post.clone(), transaction_data(parameters, authorization_context, post)
    .expect("Retrieving transaction data from your own TransferPosts is not allowed to fail"))
        })
        .collect(),
    ))
}

/// Updates `assets`, `checkpoint` and `utxo_accumulator`, returning the new asset distribution.
#[inline]
pub fn intial_sync<C>(
    assets: &mut C::AssetMap,
    checkpoint: &mut C::Checkpoint,
    utxo_accumulator: &mut C::UtxoAccumulator,
    request: InitialSyncRequest<C>,
) -> Result<SyncResponse<C, C::Checkpoint>, SyncError<C::Checkpoint>>
where
    C: Configuration,
    C::AssetMap: Default,
    C::Checkpoint: Default,
{
    let InitialSyncRequest {
        utxo_data,
        membership_proof_data,
        nullifier_count,
    } = request;
    *checkpoint = Default::default();
    *assets = Default::default();
    let (accumulator, response) = initial_sync_with::<C>(
        assets,
        checkpoint,
        utxo_accumulator.model(),
        utxo_data,
        membership_proof_data,
        nullifier_count,
    );
    *utxo_accumulator = accumulator;
    utxo_accumulator.commit();
    Ok(response)
}

/// Updates the internal ledger state from `utxos`, `membership_proof_data`
/// and `nullifier_count`.
#[inline]
fn initial_sync_with<C>(
    assets: &C::AssetMap,
    checkpoint: &mut C::Checkpoint,
    utxo_accumulator_model: &UtxoAccumulatorModel<C>,
    utxos: Vec<Vec<UtxoAccumulatorItem<C>>>,
    membership_proof_data: Vec<UtxoAccumulatorWitness<C>>,
    nullifier_count: u128,
) -> (C::UtxoAccumulator, SyncResponse<C, C::Checkpoint>)
where
    C: Configuration,
{
    let accumulator = C::UtxoAccumulator::from_items_and_witnesses(
        utxo_accumulator_model,
        utxos,
        membership_proof_data,
    );
    checkpoint.update_from_nullifiers(nullifier_count as usize);
    checkpoint.update_from_utxo_accumulator(&accumulator);
    (
        accumulator,
        SyncResponse {
            checkpoint: checkpoint.clone(),
            balance_update: BalanceUpdate::Full {
                assets: assets.assets().into(),
            },
        },
    )
}
