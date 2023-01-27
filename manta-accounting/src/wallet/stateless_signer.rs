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
    key::{self, Account, AccountCollection, DeriveAddress, DeriveAddresses},
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
        ProofSystemError, ProvingContext, Receiver, Sender, Shape, SpendingKey, Transfer,
        TransferPost, Utxo, UtxoAccumulatorItem, UtxoAccumulatorModel, UtxoMembershipProof,
    },
    wallet::{
        ledger::{self, Data},
        signer::{AccountTable, BalanceUpdate, Checkpoint, Configuration},
    },
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::{convert::Infallible, fmt::Debug, hash::Hash, marker::PhantomData};
use manta_crypto::{
    accumulator::{Accumulator, ExactSizeAccumulator, ItemHashFunction, OptimizedAccumulator},
    rand::{CryptoRng, FromEntropy, Rand, RngCore},
};
use manta_util::{
    array_map, cmp::Independence, future::LocalBoxFutureResult, into_array_unchecked,
    iter::IteratorExt, persistence::Rollback, vec::VecExt,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

use super::signer::SignError;

///
pub struct SyncResponse<C, T>
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

/// Signer No State
pub struct SignerNoState<C>(PhantomData<C>)
where
    C: Configuration;

impl<C> SignerNoState<C>
where
    C: Configuration,
{
    /// Returns the default account for `accounts`.
    #[inline]
    pub fn default_account(accounts: &AccountTable<C>) -> Account<C::Account> {
        accounts.get_default()
    }

    /// Returns the default spending key for `accounts`.
    #[inline]
    fn default_spending_key(
        accounts: &AccountTable<C>,
        parameters: &C::Parameters,
    ) -> SpendingKey<C> {
        let _ = parameters;
        accounts.get_default().spending_key()
    }

    /// Returns the default authorization context for `accounts`.
    #[inline]
    fn default_authorization_context(
        accounts: &AccountTable<C>,
        parameters: &C::Parameters,
    ) -> AuthorizationContext<C> {
        parameters.derive_context(&Self::default_spending_key(accounts, parameters))
    }

    /// Returns the authorization for the default spending key of `accounts`.
    #[inline]
    fn authorization_for_default_spending_key(
        accounts: &AccountTable<C>,
        parameters: &C::Parameters,
        rng: &mut C::Rng,
    ) -> Authorization<C> {
        Authorization::<C>::from_spending_key(
            parameters,
            &Self::default_spending_key(accounts, parameters),
            rng,
        )
    }

    /// Returns the address for the default account of `self`.
    #[inline]
    fn default_address(accounts: &AccountTable<C>, parameters: &C::Parameters) -> Address<C> {
        accounts.get_default().address(parameters)
    }

    /// Hashes `utxo` using the [`UtxoAccumulatorItemHash`](transfer::Configuration::UtxoAccumulatorItemHash)
    /// in the transfer [`Configuration`](transfer::Configuration).
    #[inline]
    fn item_hash(parameters: &C::Parameters, utxo: &Utxo<C>) -> UtxoAccumulatorItem<C> {
        parameters
            .utxo_accumulator_item_hash()
            .item_hash(utxo, &mut ())
    }

    /// Inserts the hash of `utxo` in `utxo_accumulator`.
    #[allow(clippy::too_many_arguments)] // FIXME: Use a better abstraction here.
    #[inline]
    fn insert_next_item<R>(
        authorization_context: &mut AuthorizationContext<C>,
        utxo_accumulator: &mut C::UtxoAccumulator,
        assets: &mut C::AssetMap,
        parameters: &Parameters<C>,
        utxo: Utxo<C>,
        identified_asset: IdentifiedAsset<C>,
        nullifiers: &mut Vec<Nullifier<C>>,
        deposit: &mut Vec<Asset<C>>,
        rng: &mut R,
    ) where
        R: CryptoRng + RngCore + ?Sized,
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
                utxo_accumulator.insert(&Self::item_hash(parameters, &utxo));
                if !asset.is_zero() {
                    deposit.push(asset.clone());
                }
                assets.insert(identifier, asset);
                return;
            }
        }
        utxo_accumulator.insert_nonprovable(&Self::item_hash(parameters, &utxo));
    }

    /// Checks if `asset` matches with `nullifier`, removing it from the `utxo_accumulator` and
    /// inserting it into the `withdraw` set if this is the case.
    #[allow(clippy::too_many_arguments)] // FIXME: Use a better abstraction here.
    #[inline]
    fn is_asset_unspent<R>(
        authorization_context: &mut AuthorizationContext<C>,
        utxo_accumulator: &mut C::UtxoAccumulator,
        parameters: &Parameters<C>,
        identifier: Identifier<C>,
        asset: Asset<C>,
        nullifiers: &mut Vec<Nullifier<C>>,
        withdraw: &mut Vec<Asset<C>>,
        rng: &mut R,
    ) -> bool
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let (_, utxo, nullifier) =
            parameters.derive_spend(authorization_context, identifier, asset.clone(), rng);
        if let Some(index) = nullifiers
            .iter()
            .position(move |n| n.is_related(&nullifier))
        {
            nullifiers.remove(index);
            utxo_accumulator.remove_proof(&Self::item_hash(parameters, &utxo));
            if !asset.is_zero() {
                withdraw.push(asset);
            }
            false
        } else {
            true
        }
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    fn sync_with<I>(
        accounts: &AccountTable<C>,
        mut utxo_accumulator: C::UtxoAccumulator,
        mut assets: C::AssetMap,
        mut checkpoint: C::Checkpoint,
        parameters: &Parameters<C>,
        inserts: I,
        mut nullifiers: Vec<Nullifier<C>>,
        is_partial: bool,
        rng: &mut C::Rng,
    ) -> SyncResponse<C, C::Checkpoint>
    where
        I: Iterator<Item = (Utxo<C>, Note<C>)>,
    {
        let nullifier_count = nullifiers.len();
        let mut deposit = Vec::new();
        let mut withdraw = Vec::new();
        let mut authorization_context = Self::default_authorization_context(accounts, parameters);
        let decryption_key = parameters.derive_decryption_key(&mut authorization_context);
        for (utxo, note) in inserts {
            if let Some((identifier, asset)) =
                parameters.open_with_check(&decryption_key, &utxo, note)
            {
                Self::insert_next_item(
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
                utxo_accumulator.insert_nonprovable(&Self::item_hash(parameters, &utxo));
            }
        }
        assets.retain(|identifier, assets| {
            assets.retain(|asset| {
                Self::is_asset_unspent(
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
        SyncResponse {
            checkpoint: checkpoint,
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
    fn build_pre_sender(
        accounts: &AccountTable<C>,
        parameters: &Parameters<C>,
        identifier: Identifier<C>,
        asset: Asset<C>,
        rng: &mut C::Rng,
    ) -> PreSender<C> {
        PreSender::<C>::sample(
            parameters,
            &mut Self::default_authorization_context(accounts, parameters),
            identifier,
            asset,
            rng,
        )
    }

    /// Builds the [`Receiver`] associated with `address` and `asset`.
    #[inline]
    fn receiver(
        parameters: &Parameters<C>,
        address: Address<C>,
        asset: Asset<C>,
        associated_data: AssociatedData<C>,
        rng: &mut C::Rng,
    ) -> Receiver<C> {
        Receiver::<C>::sample(parameters, address, asset, associated_data, rng)
    }

    /// Builds the [`Receiver`] associated with the default address and `asset`.
    #[inline]
    fn default_receiver(
        accounts: &AccountTable<C>,
        parameters: &Parameters<C>,
        asset: Asset<C>,
        rng: &mut C::Rng,
    ) -> Receiver<C> {
        let default_address = Self::default_address(accounts, parameters);
        Self::receiver(parameters, default_address, asset, Default::default(), rng)
    }

    /// Selects the pre-senders which collectively own at least `asset`, returning any change.
    #[inline]
    fn select(
        accounts: &AccountTable<C>,
        assets: &C::AssetMap,
        parameters: &Parameters<C>,
        asset: &Asset<C>,
        rng: &mut C::Rng,
    ) -> Result<Selection<C>, SignError<C>> {
        let selection = assets.select(asset);
        if !asset.is_zero() && selection.is_empty() {
            return Err(SignError::InsufficientBalance(asset.clone()));
        }
        Selection::new(selection, move |k, v| {
            Ok(Self::build_pre_sender(
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
    ) -> Result<TransferPost<C>, SignError<C>> {
        transfer
            .into_post(parameters, proving_context, spending_key, rng)
            .map(|p| p.expect("Internally, all transfer posts are constructed correctly."))
            .map_err(SignError::ProofSystemError)
    }

    /// Builds a [`TransferPost`] for the given `transfer`.
    #[inline]
    fn build_post<
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
    ) -> Result<TransferPost<C>, SignError<C>> {
        let spending_key = Self::default_spending_key(accounts, parameters);
        Self::build_post_inner(
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
    fn next_join(
        accounts: &AccountTable<C>,
        parameters: &Parameters<C>,
        asset_id: &C::AssetId,
        total: C::AssetValue,
        rng: &mut C::Rng,
    ) -> Result<([Receiver<C>; PrivateTransferShape::RECEIVERS], Join<C>), SignError<C>> {
        Ok(Join::new(
            parameters,
            &mut Self::default_authorization_context(accounts, parameters),
            Self::default_address(accounts, parameters),
            Asset::<C>::new(asset_id.clone(), total),
            rng,
        ))
    }

    /// Prepares the final pre-senders for the last part of the transaction.
    #[inline]
    fn prepare_final_pre_senders(
        accounts: &AccountTable<C>,
        mut utxo_accumulator: C::UtxoAccumulator,
        assets: &C::AssetMap,
        parameters: &Parameters<C>,
        asset_id: &C::AssetId,
        mut new_zeroes: Vec<PreSender<C>>,
        pre_senders: Vec<PreSender<C>>,
        rng: &mut C::Rng,
    ) -> Result<(Vec<Sender<C>>, C::UtxoAccumulator), SignError<C>> {
        let mut senders = pre_senders
            .into_iter()
            .map(|s| s.try_upgrade(parameters, &mut utxo_accumulator))
            .collect::<Option<Vec<_>>>()
            .expect("Unable to upgrade expected UTXOs.");
        let mut needed_zeroes = PrivateTransferShape::SENDERS - senders.len();
        if needed_zeroes == 0 {
            return Ok((senders, utxo_accumulator));
        }
        let zeroes = assets.zeroes(needed_zeroes, asset_id);
        needed_zeroes -= zeroes.len();
        for zero in zeroes {
            let pre_sender = Self::build_pre_sender(
                accounts,
                parameters,
                zero,
                Asset::<C>::new(asset_id.clone(), Default::default()),
                rng,
            );
            senders.push(
                pre_sender
                    .try_upgrade(parameters, &mut utxo_accumulator)
                    .expect("Unable to upgrade expected UTXOs."),
            );
        }
        if needed_zeroes == 0 {
            return Ok((senders, utxo_accumulator));
        }
        let needed_fake_zeroes = needed_zeroes.saturating_sub(new_zeroes.len());
        for _ in 0..needed_zeroes {
            match new_zeroes.pop() {
                Some(zero) => senders.push(
                    zero.try_upgrade(parameters, &mut utxo_accumulator)
                        .expect("Unable to upgrade expected UTXOs."),
                ),
                _ => break,
            }
        }
        if needed_fake_zeroes == 0 {
            return Ok((senders, utxo_accumulator));
        }
        for _ in 0..needed_fake_zeroes {
            let identifier = rng.gen();
            senders.push(
                Self::build_pre_sender(
                    accounts,
                    parameters,
                    identifier,
                    Asset::<C>::new(asset_id.clone(), Default::default()),
                    rng,
                )
                .upgrade_unchecked(Default::default()),
            );
        }
        Ok((senders, utxo_accumulator))
    }

    /// Builds two virtual [`Sender`]s for `pre_sender`.
    #[inline]
    fn virtual_senders(
        accounts: &AccountTable<C>,
        utxo_accumulator_model: &UtxoAccumulatorModel<C>,
        parameters: &Parameters<C>,
        asset_id: &C::AssetId,
        pre_sender: PreSender<C>,
        rng: &mut C::Rng,
    ) -> Result<[Sender<C>; PrivateTransferShape::SENDERS], SignError<C>> {
        let mut utxo_accumulator = C::UtxoAccumulator::empty(utxo_accumulator_model);
        let sender = pre_sender
            .insert_and_upgrade(parameters, &mut utxo_accumulator)
            .expect("Unable to upgrade expected UTXO.");
        let mut senders = Vec::new();
        senders.push(sender);
        let identifier = rng.gen();
        senders.push(
            Self::build_pre_sender(
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
    #[inline]
    fn compute_batched_transactions(
        &mut self,
        accounts: &AccountTable<C>,
        assets: &C::AssetMap,
        mut utxo_accumulator: C::UtxoAccumulator,
        parameters: &Parameters<C>,
        proving_context: &MultiProvingContext<C>,
        asset_id: &C::AssetId,
        mut pre_senders: Vec<PreSender<C>>,
        posts: &mut Vec<TransferPost<C>>,
        rng: &mut C::Rng,
    ) -> Result<
        (
            [Sender<C>; PrivateTransferShape::SENDERS],
            C::UtxoAccumulator,
        ),
        SignError<C>,
    > {
        let mut new_zeroes = Vec::new();
        while pre_senders.len() > PrivateTransferShape::SENDERS {
            let mut joins = Vec::new();
            let mut iter = pre_senders
                .into_iter()
                .chunk_by::<{ PrivateTransferShape::SENDERS }>();
            for chunk in &mut iter {
                let senders = array_map(chunk, |s| {
                    s.try_upgrade(parameters, &mut utxo_accumulator)
                        .expect("Unable to upgrade expected UTXO.")
                });
                let (receivers, mut join) = Self::next_join(
                    accounts,
                    parameters,
                    asset_id,
                    senders.iter().map(|s| s.asset().value).sum(),
                    rng,
                )?;
                let authorization =
                    Self::authorization_for_default_spending_key(accounts, parameters, rng);
                posts.push(Self::build_post(
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
        let (final_presenders, utxo_accumulator) = Self::prepare_final_pre_senders(
            accounts,
            utxo_accumulator,
            assets,
            parameters,
            asset_id,
            new_zeroes,
            pre_senders,
            rng,
        )?;
        Ok((into_array_unchecked(final_presenders), utxo_accumulator))
    }
}
