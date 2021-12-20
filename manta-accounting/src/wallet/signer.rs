// Copyright 2019-2021 Manta Network.
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

//! Wallet Signer

// FIXME: Change the name of `TransferAccumulator`, its not an `Accumulator`.
// TODO:  Add wallet recovery i.e. remove the assumption that a new signer represents a completely
//        new derived secret key generator.
// TODO:  Allow for non-atomic signing, i.e. rollback state to something in-between two calls to
//        sign`. Will have to upgrade `Rollback` and `manta_crypto::merkle_tree::fork` as well.
// TODO:  Add checkpointing/garbage-collection in `utxo_set` so we can remove old UTXOs once they
//        are irrelevant. Once we create a sender and its transaction succeeds we can drop the UTXO.
//        See `OptimizedAccumulator::remove_proof`.
// TODO:  Should have a mode on the signer where we return a generic error which reveals no detail
//        about what went wrong during signing. The kind of error returned from a signing could
//        reveal information about the internal state (privacy leak, not a secrecy leak).
// TODO:  Setup multi-account wallets using `crate::key::AccountTable`.

use crate::{
    asset::{Asset, AssetId, AssetMap, AssetValue},
    key::{self, AccountKeys, HierarchicalKeyDerivationScheme},
    transfer::{
        self,
        canonical::{
            Mint, PrivateTransfer, PrivateTransferShape, Reclaim, Selection, Shape, Transaction,
        },
        CommitmentSchemeParameters, EncryptedNote, EphemeralKeyParameters, Parameters, PreSender,
        ProofSystemError, ProvingContext, PublicKey, Receiver, ReceivingKey, SecretKey, Sender,
        SpendingKey, Transfer, TransferPost, Utxo, VoidNumber,
    },
};
use alloc::{vec, vec::Vec};
use core::{
    convert::Infallible,
    fmt::Debug,
    future::{self, Future, Ready},
    hash::Hash,
    mem,
    ops::Range,
};
use manta_crypto::{
    accumulator::{
        Accumulator, ConstantCapacityAccumulator, ExactSizeAccumulator, OptimizedAccumulator,
        Verifier,
    },
    encryption::DecryptedMessage,
    key::KeyAgreementScheme,
    rand::{CryptoRng, Rand, RngCore},
};
use manta_util::{fallible_array_map, into_array_unchecked, iter::IteratorExt};

/// Rollback Trait
pub trait Rollback {
    /// Rolls back `self` to the previous state.
    ///
    /// # Implementation Note
    ///
    /// Rolling back to the previous state must be idempotent, i.e. two consecutive calls to
    /// [`rollback`](Self::rollback) should do the same as one call.
    fn rollback(&mut self);
}

/// Signer Connection
pub trait Connection<H, C>
where
    H: HierarchicalKeyDerivationScheme<SecretKey = SecretKey<C>>,
    C: transfer::Configuration,
{
    /// Sync Future Type
    ///
    /// Future for the [`sync`](Self::sync) method.
    type SyncFuture: Future<Output = SyncResult<H, C, Self>>;

    /// Sign Future Type
    ///
    /// Future for the [`sign`](Self::sign) method.
    type SignFuture: Future<Output = SignResult<H, C, Self>>;

    /// Receiving Key Future Type
    ///
    /// Future for the [`receiving_key`](Self::receiving_key) method.
    type ReceivingKeyFuture: Future<Output = ReceivingKeyResult<H, C, Self>>;

    /// Error Type
    type Error;

    /// Pushes updates from the ledger to the wallet, synchronizing it with the ledger state and
    /// returning an updated asset distribution.
    fn sync<I, R>(
        &mut self,
        insert_starting_index: usize,
        inserts: I,
        removes: R,
    ) -> Self::SyncFuture
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedNote<C>)>,
        R: IntoIterator<Item = VoidNumber<C>>;

    /// Signs a `transaction` and returns the ledger transfer posts if successful.
    ///
    /// # Safety
    ///
    /// The caller of this method should call [`finish`](Self::finish) once the posts have been
    /// returned from the ledger to preserve the signer's internal state.
    fn sign(&mut self, transaction: Transaction<C>) -> Self::SignFuture;

    /// Returns a [`ReceivingKey`] for `self` to receive assets with `index`.
    ///
    /// # Safety
    ///
    /// This method can be called at any point, since it is independent of the signing state.
    fn receiving_key(&mut self, index: key::Index<H>) -> Self::ReceivingKeyFuture;
}

/// Synchronization Result
///
/// See the [`sync`](Connection::sync) method on [`Connection`] for more.
pub type SyncResult<H, C, S> = Result<SyncResponse, Error<H, C, <S as Connection<H, C>>::Error>>;

/// Signing Result
///
/// See the [`sign`](Connection::sign) method on [`Connection`] for more.
pub type SignResult<H, C, S> = Result<SignResponse<C>, Error<H, C, <S as Connection<H, C>>::Error>>;

/// Receving Key Result
///
/// See the [`receiving_key`](Connection::receiving_key) method on [`Connection`] for more.
pub type ReceivingKeyResult<H, C, S> =
    Result<ReceivingKey<C>, Error<H, C, <S as Connection<H, C>>::Error>>;

/// Signer Synchronization Response
///
/// This `struct` is created by the [`sync`](Connection::sync) method on [`Connection`].
/// See its documentation for more.
pub struct SyncResponse {
    /// Updates to the Asset Distribution
    pub assets: Vec<Asset>,
}

impl SyncResponse {
    /// Builds a new [`SyncResponse`] from `assets`.
    #[inline]
    pub fn new(assets: Vec<Asset>) -> Self {
        Self { assets }
    }
}

/// Signer Signing Response
///
/// This `struct` is created by the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
pub struct SignResponse<C>
where
    C: transfer::Configuration,
{
    /// Transfer Posts
    pub posts: Vec<TransferPost<C>>,
}

impl<C> SignResponse<C>
where
    C: transfer::Configuration,
{
    /// Builds a new [`SignResponse`] from `posts`.
    #[inline]
    pub fn new(posts: Vec<TransferPost<C>>) -> Self {
        Self { posts }
    }
}

/// Signer Error
pub enum Error<H, C, CE = Infallible>
where
    H: HierarchicalKeyDerivationScheme<SecretKey = SecretKey<C>>,
    C: transfer::Configuration,
{
    /// Hierarchical Key Derivation Scheme Error
    HierarchicalKeyDerivationSchemeError(key::Error<H>),

    /// Missing [`Utxo`] Membership Proof
    MissingUtxoMembershipProof,

    /// Insufficient Balance
    InsufficientBalance(Asset),

    /// Proof System Error
    ProofSystemError(ProofSystemError<C>),

    /// Inconsistent Synchronization State
    InconsistentSynchronization,

    /// Signer Connection Error
    ConnectionError(CE),
}

impl<H, C, CE> From<key::Error<H>> for Error<H, C, CE>
where
    H: HierarchicalKeyDerivationScheme<SecretKey = SecretKey<C>>,
    C: transfer::Configuration,
{
    #[inline]
    fn from(err: key::Error<H>) -> Self {
        Self::HierarchicalKeyDerivationSchemeError(err)
    }
}

/// Signer Configuration
pub trait Configuration: transfer::Configuration {
    /// Hierarchical Key Derivation Scheme
    type HierarchicalKeyDerivationScheme: HierarchicalKeyDerivationScheme<
        SecretKey = SecretKey<Self>,
    >;

    /// [`Utxo`] Accumulator Type
    type UtxoSet: Accumulator<
            Item = <Self::UtxoSetVerifier as Verifier>::Item,
            Verifier = Self::UtxoSetVerifier,
        > + ConstantCapacityAccumulator
        + ExactSizeAccumulator
        + OptimizedAccumulator
        + Rollback;

    /// Asset Map Type
    type AssetMap: AssetMap<Key = AssetMapKey<Self>>;

    /// Random Number Generator Type
    type Rng: CryptoRng + RngCore;
}

/// Index Type
pub type Index<C> = key::Index<<C as Configuration>::HierarchicalKeyDerivationScheme>;

/// Hierarchical Key Derivation Scheme Index
type HierarchicalKeyDerivationSchemeIndex<C> =
    <<C as Configuration>::HierarchicalKeyDerivationScheme as HierarchicalKeyDerivationScheme>::Index;

/// Spend Index Type
pub type SpendIndex<C> = HierarchicalKeyDerivationSchemeIndex<C>;

/// View Index Type
pub type ViewIndex<C> = HierarchicalKeyDerivationSchemeIndex<C>;

/// Asset Map Key Type
pub type AssetMapKey<C> = (SpendIndex<C>, PublicKey<C>);

/// Account Table Type
pub type AccountTable<C> = key::AccountTable<<C as Configuration>::HierarchicalKeyDerivationScheme>;

/// Signer
pub struct Signer<C>
where
    C: Configuration,
{
    /// Account Table
    account_table: AccountTable<C>,

    /// Proving Context
    proving_context: ProvingContext<C>,

    /// Ephemeral Key Parameters
    ephemeral_key_parameters: EphemeralKeyParameters<C>,

    /// Commitment Scheme Parameters
    commitment_scheme_parameters: CommitmentSchemeParameters<C>,

    /// UTXO Set
    utxo_set: C::UtxoSet,

    /// Asset Distribution
    assets: C::AssetMap,

    /// Random Number Generator
    rng: C::Rng,
}

impl<C> Signer<C>
where
    C: Configuration,
{
    /// Builds a new [`Signer`].
    #[inline]
    fn new_inner(
        account_table: AccountTable<C>,
        proving_context: ProvingContext<C>,
        ephemeral_key_parameters: EphemeralKeyParameters<C>,
        commitment_scheme_parameters: CommitmentSchemeParameters<C>,
        utxo_set: C::UtxoSet,
        assets: C::AssetMap,
        rng: C::Rng,
    ) -> Self {
        Self {
            account_table,
            proving_context,
            ephemeral_key_parameters,
            commitment_scheme_parameters,
            utxo_set,
            assets,
            rng,
        }
    }

    /// Builds a new [`Signer`] from a fresh `account_table`.
    ///
    /// # Warning
    ///
    /// This method assumes that `account_table` has never been used before, and does not attempt
    /// to perform wallet recovery on this table.
    #[inline]
    pub fn new(
        account_table: AccountTable<C>,
        proving_context: ProvingContext<C>,
        ephemeral_key_parameters: EphemeralKeyParameters<C>,
        commitment_scheme_parameters: CommitmentSchemeParameters<C>,
        utxo_set: C::UtxoSet,
        rng: C::Rng,
    ) -> Self {
        Self::new_inner(
            account_table,
            proving_context,
            ephemeral_key_parameters,
            commitment_scheme_parameters,
            utxo_set,
            Default::default(),
            rng,
        )
    }

    /// Returns the hierarchical key indices for the current account.
    #[inline]
    fn account(&self) -> AccountKeys<C::HierarchicalKeyDerivationScheme> {
        // FIXME: Implement multiple accounts.
        self.account_table.get(Default::default()).unwrap()
    }

    /// Inserts the new `utxo`-`encrypted_note` pair if a known key can decrypt the note and
    /// validate the utxo.
    #[inline]
    fn insert_next_item(
        &mut self,
        utxo: Utxo<C>,
        encrypted_note: EncryptedNote<C>,
        void_numbers: &mut Vec<VoidNumber<C>>,
        assets: &mut Vec<Asset>,
    ) -> Result<(), Error<C::HierarchicalKeyDerivationScheme, C>> {
        let mut finder = DecryptedMessage::find(encrypted_note);
        if let Some((
            index,
            key,
            DecryptedMessage {
                plaintext: asset,
                ephemeral_public_key,
            },
        )) = self
            .account()
            .find_index(move |k| finder.decrypt(k))
            .map_err(key::Error::KeyDerivationError)?
        {
            if let Some(void_number) = C::check_full_asset(
                &self.commitment_scheme_parameters,
                &key.spend,
                &ephemeral_public_key,
                &asset,
                &utxo,
            ) {
                if let Some(index) = void_numbers.iter().position(move |v| v == &void_number) {
                    void_numbers.remove(index);
                } else {
                    assets.push(asset);
                    self.assets
                        .insert((index.spend, ephemeral_public_key), asset);
                    self.utxo_set.insert(&utxo);
                    return Ok(());
                }
            }
        }
        self.utxo_set.insert_nonprovable(&utxo);
        Ok(())
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    fn sync_with<I>(
        &mut self,
        inserts: I,
        mut void_numbers: Vec<VoidNumber<C>>,
    ) -> SyncResult<C::HierarchicalKeyDerivationScheme, C, Self>
    where
        I: Iterator<Item = (Utxo<C>, EncryptedNote<C>)>,
    {
        // TODO: Do this loop in parallel.
        let mut assets = Vec::new();
        for (utxo, encrypted_note) in inserts {
            self.insert_next_item(utxo, encrypted_note, &mut void_numbers, &mut assets)?;
        }
        // FIXME: Do we need to check the void numbers which survived the above loop?
        Ok(SyncResponse::new(assets))
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    pub fn sync<I, R>(
        &mut self,
        insert_starting_index: usize,
        inserts: I,
        removes: R,
    ) -> SyncResult<C::HierarchicalKeyDerivationScheme, C, Self>
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedNote<C>)>,
        R: IntoIterator<Item = VoidNumber<C>>,
    {
        // FIXME: Do a capacity check on the current UTXO set?
        //
        // if self.utxo_set.capacity() < starting_index {
        //    panic!("something is very wrong here")
        // }
        //
        // TODO: Use a smarter object than `Vec` for `removes.into_iter().collect()` like a
        //       `HashSet` or some other set-like container with fast membership and remove ops.

        match self.utxo_set.len().checked_sub(insert_starting_index) {
            Some(diff) => self.sync_with(
                inserts.into_iter().skip(diff),
                removes.into_iter().collect(),
            ),
            _ => Err(Error::InconsistentSynchronization),
        }
    }

    /// Builds the pre-sender associated to `spend_index`, `ephemeral_key`, and `asset`.
    #[inline]
    fn build_pre_sender(
        &self,
        spend_index: SpendIndex<C>,
        ephemeral_key: PublicKey<C>,
        asset: Asset,
    ) -> Result<PreSender<C>, Error<C::HierarchicalKeyDerivationScheme, C>> {
        let spend_key = self.account().spend_key(spend_index)?;
        Ok(PreSender::new(
            &self.commitment_scheme_parameters,
            spend_key,
            ephemeral_key,
            asset,
        ))
    }

    /// Builds the pre-receiver associated to `spend_index`, `view_index`, and `asset`.
    #[inline]
    fn build_receiver(
        &mut self,
        spend_index: SpendIndex<C>,
        view_index: ViewIndex<C>,
        asset: Asset,
    ) -> Result<Receiver<C>, Error<C::HierarchicalKeyDerivationScheme, C>> {
        let keypair = self
            .account()
            .keypair_with(spend_index, view_index)?
            .derive::<C::KeyAgreementScheme>();
        Ok(Receiver::new(
            &self.ephemeral_key_parameters,
            &self.commitment_scheme_parameters,
            self.rng.gen(),
            keypair.spend,
            keypair.view,
            asset,
        ))
    }

    /// Selects the pre-senders which collectively own at least `asset`, returning any change.
    #[inline]
    fn select(
        &mut self,
        asset: Asset,
    ) -> Result<Selection<C>, Error<C::HierarchicalKeyDerivationScheme, C>> {
        let selection = self.assets.select(asset);
        if selection.is_empty() {
            return Err(Error::InsufficientBalance(asset));
        }
        Selection::new(selection, move |(i, ek), v| {
            self.build_pre_sender(i, ek, asset.id.with(v))
        })
    }

    /// Builds a [`TransferPost`] for the given `transfer`.
    #[inline]
    fn build_post<
        const SOURCES: usize,
        const SENDERS: usize,
        const RECEIVERS: usize,
        const SINKS: usize,
    >(
        &mut self,
        transfer: Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
    ) -> Result<TransferPost<C>, Error<C::HierarchicalKeyDerivationScheme, C>> {
        transfer
            .into_post(
                Parameters::new(
                    &self.ephemeral_key_parameters,
                    &self.commitment_scheme_parameters,
                    self.utxo_set.parameters(),
                ),
                &self.proving_context,
                &mut self.rng,
            )
            .map_err(Error::ProofSystemError)
    }

    /* TODO:
    /// Accumulate transfers using the `SENDERS -> RECEIVERS` shape.
    #[inline]
    fn accumulate_transfers<const SENDERS: usize, const RECEIVERS: usize>(
        &mut self,
        asset_id: AssetId,
        mut pre_senders: Vec<PreSender<C>>,
        posts: &mut Vec<TransferPost<C>>,
    ) -> Result<[Sender<C>; SENDERS], Error<C::DerivedSecretKeyGenerator, C>> {
        assert!(
            (SENDERS > 1) && (RECEIVERS > 1),
            "The transfer shape must include at least two senders and two receivers."
        );
        assert!(
            !pre_senders.is_empty(),
            "The set of initial senders cannot be empty."
        );

        let mut new_zeroes = Vec::new();

        while pre_senders.len() > SENDERS {
            let mut accumulators = Vec::new();
            let mut iter = pre_senders.into_iter().chunk_by::<SENDERS>();
            for chunk in &mut iter {
                let senders = fallible_array_map(chunk, |ps| {
                    ps.try_upgrade(&self.utxo_set)
                        .ok_or(Error::MissingUtxoMembershipProof)
                })?;

                let mut accumulator = self.signer.next_accumulator::<_, _, RECEIVERS>(
                    &self.commitment_scheme,
                    asset_id,
                    senders.iter().map(Sender::asset_value).sum(),
                    &mut self.rng,
                )?;

                posts.push(self.build_post(SecretTransfer::new(senders, accumulator.receivers))?);

                for zero in &accumulator.zeroes {
                    zero.as_ref().insert_utxo(&mut self.utxo_set);
                }
                accumulator.pre_sender.insert_utxo(&mut self.utxo_set);

                new_zeroes.append(&mut accumulator.zeroes);
                accumulators.push(accumulator.pre_sender);
            }

            accumulators.append(&mut iter.remainder());
            pre_senders = accumulators;
        }

        self.prepare_final_pre_senders::<SENDERS>(asset_id, new_zeroes, &mut pre_senders, posts)?;

        Ok(into_array_unchecked(
            pre_senders
                .into_iter()
                .map(move |ps| ps.try_upgrade(&self.utxo_set))
                .collect::<Option<Vec<_>>>()
                .ok_or(Error::MissingUtxoMembershipProof)?,
        ))
    }

    /// Prepare final pre-senders for the transaction.
    #[inline]
    fn prepare_final_pre_senders<const SENDERS: usize>(
        &mut self,
        asset_id: AssetId,
        mut new_zeroes: Vec<InternalKeyOwned<C::DerivedSecretKeyGenerator, PreSender<C>>>,
        pre_senders: &mut Vec<PreSender<C>>,
        posts: &mut Vec<TransferPost<C>>,
    ) -> Result<(), Error<C::DerivedSecretKeyGenerator, C>> {
        let mut needed_zeroes = SENDERS - pre_senders.len();
        if needed_zeroes == 0 {
            return Ok(());
        }

        let zeroes = self.assets.zeroes(needed_zeroes, asset_id);
        needed_zeroes -= zeroes.len();

        for zero in zeroes {
            pre_senders.push(self.get_pre_sender(zero, Asset::zero(asset_id))?);
        }

        if needed_zeroes == 0 {
            return Ok(());
        }

        let needed_mints = needed_zeroes.saturating_sub(new_zeroes.len());

        for _ in 0..needed_zeroes {
            match new_zeroes.pop() {
                Some(zero) => pre_senders.push(zero.unwrap()),
                _ => break,
            }
        }

        if needed_mints == 0 {
            return Ok(());
        }

        for _ in 0..needed_mints {
            let (mint, pre_sender) =
                self.signer
                    .mint_zero(&self.commitment_scheme, asset_id, &mut self.rng)?;
            pre_senders.push(pre_sender);
            posts.push(self.build_post(mint)?);
        }

        Ok(())
    }
    */

    ///
    #[inline]
    fn compute_batched_transaction<const SENDERS: usize, const RECEIVERS: usize>(
        &mut self,
    ) -> Result<[Sender<C>; SENDERS], Error<C::HierarchicalKeyDerivationScheme, C>> {
        todo!()
    }

    /// Returns the next change receiver for `asset`.
    #[inline]
    fn next_change(
        &mut self,
        asset_id: AssetId,
        change: AssetValue,
    ) -> Result<Receiver<C>, Error<C::HierarchicalKeyDerivationScheme, C>> {
        let default_index = Default::default();
        self.build_receiver(default_index, default_index, asset_id.with(change))
    }

    /// Prepares a given [`ReceivingKey`] for receiving `asset`.
    #[inline]
    pub fn prepare_receiver(&mut self, asset: Asset, receiver: ReceivingKey<C>) -> Receiver<C> {
        receiver.into_receiver(
            &self.ephemeral_key_parameters,
            &self.commitment_scheme_parameters,
            self.rng.gen(),
            asset,
        )
    }

    /// Signs a withdraw transaction without resetting on error.
    #[inline]
    fn sign_withdraw(
        &mut self,
        asset: Asset,
        receiver: Option<ReceivingKey<C>>,
    ) -> SignResult<C::HierarchicalKeyDerivationScheme, C, Self> {
        const SENDERS: usize = PrivateTransferShape::SENDERS;
        const RECEIVERS: usize = PrivateTransferShape::RECEIVERS;

        let selection = self.select(asset)?;

        let mut posts = Vec::new();

        /*
        let senders = self.accumulate_transfers::<SENDERS, RECEIVERS>(
            asset.id,
            selection.pre_senders,
            &mut posts,
        )?;
        */

        let senders = self.compute_batched_transaction::<SENDERS, RECEIVERS>()?;
        let change = self.next_change(asset.id, selection.change)?;
        let final_post = match receiver {
            Some(receiver) => {
                let receiver = self.prepare_receiver(asset, receiver);
                self.build_post(PrivateTransfer::build(senders, [change, receiver]))?
            }
            _ => self.build_post(Reclaim::build(senders, [change], asset))?,
        };
        posts.push(final_post);
        self.utxo_set.rollback();
        Ok(SignResponse::new(posts))
    }

    /// Signs the `transaction`, generating transfer posts.
    #[inline]
    pub fn sign(
        &mut self,
        transaction: Transaction<C>,
    ) -> SignResult<C::HierarchicalKeyDerivationScheme, C, Self> {
        match transaction {
            Transaction::Mint(asset) => {
                let default_index = Default::default();
                let receiver = self.build_receiver(default_index, default_index, asset)?;
                let mint_post = self.build_post(Mint::build(asset, receiver))?;
                Ok(SignResponse::new(vec![mint_post]))
            }
            Transaction::PrivateTransfer(asset, receiver) => {
                self.sign_withdraw(asset, Some(receiver))
            }
            Transaction::Reclaim(asset) => self.sign_withdraw(asset, None),
        }
    }

    /// Returns a [`ReceivingKey`] for `self` to receive assets with `index`.
    #[inline]
    pub fn receiving_key(
        &mut self,
        index: Index<C>,
    ) -> ReceivingKeyResult<C::HierarchicalKeyDerivationScheme, C, Self> {
        /*
        let _ = self
            .account()
            .keypair(index)?
            .derive::<C::KeyAgreementScheme>();
        */
        todo!()
    }
}

impl<C> Connection<C::HierarchicalKeyDerivationScheme, C> for Signer<C>
where
    C: Configuration,
{
    type SyncFuture = Ready<SyncResult<C::HierarchicalKeyDerivationScheme, C, Self>>;

    type SignFuture = Ready<SignResult<C::HierarchicalKeyDerivationScheme, C, Self>>;

    type ReceivingKeyFuture =
        Ready<ReceivingKeyResult<C::HierarchicalKeyDerivationScheme, C, Self>>;

    type Error = Infallible;

    #[inline]
    fn sync<I, R>(
        &mut self,
        insert_starting_index: usize,
        inserts: I,
        removes: R,
    ) -> Self::SyncFuture
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedNote<C>)>,
        R: IntoIterator<Item = VoidNumber<C>>,
    {
        future::ready(self.sync(insert_starting_index, inserts, removes))
    }

    #[inline]
    fn sign(&mut self, transaction: Transaction<C>) -> Self::SignFuture {
        future::ready(self.sign(transaction))
    }

    #[inline]
    fn receiving_key(&mut self, index: Index<C>) -> Self::ReceivingKeyFuture {
        future::ready(self.receiving_key(index))
    }
}

/* TODO:
/// Pre-Sender Selection
struct Selection<C>
where
    C: transfer::Configuration,
{
    /// Selection Change
    pub change: AssetValue,

    /// Selection Pre-Senders
    pub pre_senders: Vec<PreSender<C>>,
}

impl<C> Selection<C>
where
    C: transfer::Configuration,
{
    /// Builds a new [`Selection`] from `change` and `pre_senders`.
    #[inline]
    pub fn new(change: AssetValue, pre_senders: Vec<PreSender<C>>) -> Self {
        Self {
            change,
            pre_senders,
        }
    }
}

impl<D> Signer<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a new [`Signer`] for `account` from a `secret_key_source`.
    #[inline]
    pub fn new(secret_key_source: D, account: D::Account) -> Self {
        Self::with_account(secret_key_source, Account::new(account))
    }

    /// Builds a new [`Signer`] for `account` from a `secret_key_source`.
    #[inline]
    pub fn with_account(secret_key_source: D, account: Account<D>) -> Self {
        Self {
            secret_key_source,
            account,
        }
    }

    /// Builds a new [`Signer`] for `account` from a `secret_key_source` with starting ranges
    /// `external_indices` and `internal_indices`.
    #[inline]
    pub fn with_ranges(
        secret_key_source: D,
        account: D::Account,
        external_indices: Range<D::Index>,
        internal_indices: Range<D::Index>,
    ) -> Self {
        Self::with_account(
            secret_key_source,
            Account::with_ranges(account, external_indices, internal_indices),
        )
    }

    /// Returns the next [`Signer`] after `self`, incrementing the account number.
    #[inline]
    pub fn next(self) -> Self {
        Self::with_account(self.secret_key_source, self.account.next())
    }


    /// Returns a [`PreSender`] for the key at the given `index`.
    #[inline]
    pub fn get_pre_sender<C>(
        &self,
        index: Index<D>,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
    ) -> Result<PreSender<C>, D::Error>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self.get(&index)?.into_pre_sender(commitment_scheme, asset))
    }

    /// Generates the next external identity for this signer.
    #[inline]
    fn next_external_identity<C>(&mut self) -> Result<Identity<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self
            .account
            .next_external_key(&self.secret_key_source)?
            .map(Identity::new)
            .unwrap())
    }

    /// Generates the next internal identity for this signer.
    #[inline]
    fn next_internal_identity<C>(&mut self) -> Result<InternalKeyOwned<D, Identity<C>>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self
            .account
            .next_internal_key(&self.secret_key_source)?
            .map(Identity::new))
    }

    /// Generates a new [`ShieldedIdentity`] to receive assets to this account via an external
    /// transaction.
    #[inline]
    pub fn next_shielded<C>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<ShieldedIdentity<C>, D::Error>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self
            .next_external_identity()?
            .into_shielded(commitment_scheme))
    }

    /// Generates a new [`InternalIdentity`] to receive assets in this account via an internal
    /// transaction.
    #[inline]
    pub fn next_internal<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalKeyOwned<D, InternalIdentity<C>>, InternalIdentityError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        self.next_internal_identity()
            .map_err(InternalIdentityError::SecretKeyError)?
            .map_ok(move |identity| {
                identity
                    .into_internal(commitment_scheme, asset, rng)
                    .map_err(InternalIdentityError::EncryptionError)
            })
    }

    /// Builds the next transfer accumulator.
    #[inline]
    pub fn next_accumulator<C, R, const RECEIVERS: usize>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
        sender_sum: AssetValue,
        rng: &mut R,
    ) -> Result<TransferAccumulator<D, C, RECEIVERS>, InternalIdentityError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut receivers = Vec::with_capacity(RECEIVERS);
        let mut zero_pre_senders = Vec::with_capacity(RECEIVERS - 1);

        for _ in 0..RECEIVERS - 1 {
            let (internal, index) = self
                .next_internal(commitment_scheme, Asset::zero(asset_id), rng)?
                .into();
            receivers.push(internal.receiver);
            zero_pre_senders.push(KeyOwned::new(internal.pre_sender, index));
        }

        let internal = self
            .next_internal(commitment_scheme, asset_id.with(sender_sum), rng)?
            .unwrap();

        receivers.push(internal.receiver);

        Ok(TransferAccumulator::new(
            into_array_unchecked(receivers),
            zero_pre_senders,
            internal.pre_sender,
        ))
    }

    /// Builds the change receiver for the end of a transaction.
    #[inline]
    pub fn next_change<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalKeyOwned<D, Receiver<C>>, InternalIdentityError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        self.next_internal_identity()
            .map_err(InternalIdentityError::SecretKeyError)?
            .map_ok(move |identity| identity.into_receiver(commitment_scheme, asset, rng))
            .map_err(InternalIdentityError::EncryptionError)
    }

    /// Builds a [`Mint`] transaction to mint `asset` and returns the index for that asset.
    #[inline]
    pub fn mint<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalKeyOwned<D, Mint<C>>, InternalIdentityError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        self.next_internal_identity()
            .map_err(InternalIdentityError::SecretKeyError)?
            .map_ok(|identity| {
                Mint::from_identity(identity, commitment_scheme, asset, rng)
                    .map_err(InternalIdentityError::EncryptionError)
            })
    }

    /// Builds a [`Mint`] transaction to mint a zero asset with the given `asset_id`, returning a
    /// [`PreSender`] for that asset.
    #[inline]
    pub fn mint_zero<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
        rng: &mut R,
    ) -> Result<(Mint<C>, PreSender<C>), InternalIdentityError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        Mint::zero(
            self.next_internal_identity()
                .map_err(InternalIdentityError::SecretKeyError)?
                .unwrap(),
            commitment_scheme,
            asset_id,
            rng,
        )
        .map_err(InternalIdentityError::EncryptionError)
    }

    /// Tries to decrypt `encrypted_asset` using the `secret_key`.
    #[inline]
    fn try_open_asset<C>(
        secret_key: Result<ExternalSecretKey<D>, D::Error>,
        encrypted_asset: &EncryptedAsset<C>,
    ) -> Option<ExternalKeyOwned<D, Asset>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
    {
        let KeyOwned { inner, index } = secret_key.ok()?;
        Some(
            index.wrap(
                Identity::<C>::new(inner)
                    .try_open(encrypted_asset)
                    .ok()?
                    .into_asset(),
            ),
        )
    }

    /// Looks for an index that can decrypt the given `encrypted_asset`.
    #[inline]
    pub fn find_external_asset<C>(
        &mut self,
        encrypted_asset: &EncryptedAsset<C>,
    ) -> Option<ExternalKeyOwned<D, Asset>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
    {
        let asset = self
            .account
            .external_keys(&self.secret_key_source)
            .find_map(move |k| Self::try_open_asset::<C>(k, encrypted_asset))?;
        self.account
            .conditional_increment_external_range(&asset.index.index);
        Some(asset)
    }
}

impl<D> Load for Signer<D>
where
    D: DerivedSecretKeyGenerator + LoadWith<Account<D>>,
{
    type Path = D::Path;

    type LoadingKey = D::LoadingKey;

    type Error = <D as Load>::Error;

    #[inline]
    fn load<P>(path: P, loading_key: &Self::LoadingKey) -> Result<Self, Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        let (secret_key_source, account) = D::load_with(path, loading_key)?;
        Ok(Self::with_account(secret_key_source, account))
    }
}

impl<D> Save for Signer<D>
where
    D: DerivedSecretKeyGenerator + SaveWith<Account<D>>,
{
    type Path = D::Path;

    type SavingKey = D::SavingKey;

    type Error = <D as Save>::Error;

    #[inline]
    fn save<P>(self, path: P, saving_key: &Self::SavingKey) -> Result<(), Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        self.secret_key_source
            .save_with(self.account, path, saving_key)
    }
}

/// Signer Configuration
pub trait Configuration {
    ///
    type TransferConfiguration: transfer::Configuration;

    ///
    type TransferProofSystemConfiguration:
        transfer::ProofSystemConfiguration<Self::TransferConfiguration>;

    ///
    type AccountKeyTable: AccountKeyTable<SecretKey = SecretKey<Self::TransferConfiguration>>;

    /// [`Utxo`] Accumulator Type
    type UtxoSet: Accumulator<
            Item = <Self::UtxoSetVerifier as Verifier>::Item,
            Verifier = Self::UtxoSetVerifier,
        > + ConstantCapacityAccumulator
        + ExactSizeAccumulator
        + OptimizedAccumulator
        + Rollback;

    /// Asset Map Type
    type AssetMap: AssetMap<Key = ??>;

    /// Random Number Generator Type
    type Rng: CryptoRng + RngCore;
}

/// Full Signer
pub struct Signer<C>
where
    C: Configuration,
{
    /// Signer
    signer: Signer<C::DerivedSecretKeyGenerator>,

    /// Commitment Scheme
    commitment_scheme: C::CommitmentScheme,

    /// Proving Context
    proving_context: ProvingContext<C>,

    /// UTXO Set
    utxo_set: C::UtxoSet,

    /// Asset Distribution
    assets: C::AssetMap,

    /// Random Number Generator
    rng: C::Rng,
}


/// Internal Identity Error
///
/// This `enum` is the error state for any construction of an [`InternalIdentity`] from a derived
/// secret key generator.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "D::Error: Clone, IntegratedEncryptionSchemeError<C>: Clone"),
    Copy(bound = "D::Error: Copy, IntegratedEncryptionSchemeError<C>: Copy"),
    Debug(bound = "D::Error: Debug, IntegratedEncryptionSchemeError<C>: Debug"),
    Eq(bound = "D::Error: Eq, IntegratedEncryptionSchemeError<C>: Eq"),
    Hash(bound = "D::Error: Hash, IntegratedEncryptionSchemeError<C>: Hash"),
    PartialEq(bound = "D::Error: PartialEq, IntegratedEncryptionSchemeError<C>: PartialEq")
)]
pub enum InternalIdentityError<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Secret Key Generator Error
    SecretKeyError(D::Error),

    /// Encryption Error
    EncryptionError(IntegratedEncryptionSchemeError<C>),
}

/// Transfer Accumulator
pub struct TransferAccumulator<D, C, const RECEIVERS: usize>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Receivers
    pub receivers: [Receiver<C>; RECEIVERS],

    /// Zero Balance Pre-Senders
    pub zeroes: Vec<InternalKeyOwned<D, PreSender<C>>>,

    /// Accumulated Balance Pre-Sender
    pub pre_sender: PreSender<C>,
}

impl<D, C, const RECEIVERS: usize> TransferAccumulator<D, C, RECEIVERS>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Builds a new [`TransferAccumulator`] from `receivers`, `zeroes`, and `pre_sender`.
    #[inline]
    pub fn new(
        receivers: [Receiver<C>; RECEIVERS],
        zeroes: Vec<InternalKeyOwned<D, PreSender<C>>>,
        pre_sender: PreSender<C>,
    ) -> Self {
        Self {
            receivers,
            zeroes,
            pre_sender,
        }
    }
}
*/
