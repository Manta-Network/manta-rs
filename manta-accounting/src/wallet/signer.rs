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
        self, batch,
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
    fn sign(&mut self, transaction: Transaction<C>) -> Self::SignFuture;

    /// Returns a [`ReceivingKey`] for `self` to receive assets with `index`.
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
        //
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
        key: AssetMapKey<C>,
        asset: Asset,
    ) -> Result<PreSender<C>, Error<C::HierarchicalKeyDerivationScheme, C>> {
        let (spend_index, ephemeral_key) = key;
        Ok(PreSender::new(
            &self.commitment_scheme_parameters,
            self.account().spend_key(spend_index)?,
            ephemeral_key,
            asset,
        ))
    }

    /// Builds the pre-receiver associated to `spend_index`, `view_index`, and `asset`.
    #[inline]
    fn build_receiver(
        &mut self,
        asset: Asset,
    ) -> Result<Receiver<C>, Error<C::HierarchicalKeyDerivationScheme, C>> {
        let keypair = self
            .account()
            .default_keypair()
            .map_err(key::Error::KeyDerivationError)?;
        Ok(SpendingKey::new(keypair.spend, keypair.view).receiver(
            &self.ephemeral_key_parameters,
            &self.commitment_scheme_parameters,
            self.rng.gen(),
            asset,
        ))
    }

    ///
    #[inline]
    fn mint_zero(
        &mut self,
        asset_id: AssetId,
    ) -> Result<(Mint<C>, PreSender<C>), Error<C::HierarchicalKeyDerivationScheme, C>> {
        let asset = Asset::zero(asset_id);
        let keypair = self
            .account()
            .default_keypair()
            .map_err(key::Error::KeyDerivationError)?;
        let (receiver, pre_sender) = SpendingKey::new(keypair.spend, keypair.view).internal_pair(
            &self.ephemeral_key_parameters,
            &self.commitment_scheme_parameters,
            self.rng.gen(),
            asset,
        );
        Ok((Mint::build(asset, receiver), pre_sender))
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
        Selection::new(selection, move |k, v| {
            self.build_pre_sender(k, asset.id.with(v))
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

    ///
    #[inline]
    fn next_join<const RECEIVERS: usize>(
        &mut self,
        asset_id: AssetId,
        total: AssetValue,
    ) -> Result<
        ([Receiver<C>; RECEIVERS], batch::Join<C>),
        Error<C::HierarchicalKeyDerivationScheme, C>,
    > {
        let keypair = self
            .account()
            .default_keypair()
            .map_err(key::Error::KeyDerivationError)?;
        Ok(batch::Join::new(
            &self.ephemeral_key_parameters,
            &self.commitment_scheme_parameters,
            asset_id.with(total),
            &SpendingKey::new(keypair.spend, keypair.view),
            &mut self.rng,
        ))
    }

    ///
    #[inline]
    fn prepare_final_pre_senders<const SENDERS: usize>(
        &mut self,
        asset_id: AssetId,
        mut new_zeroes: Vec<PreSender<C>>,
        pre_senders: &mut Vec<PreSender<C>>,
        posts: &mut Vec<TransferPost<C>>,
    ) -> Result<(), Error<C::HierarchicalKeyDerivationScheme, C>> {
        let mut needed_zeroes = SENDERS - pre_senders.len();
        if needed_zeroes == 0 {
            return Ok(());
        }
        let zeroes = self.assets.zeroes(needed_zeroes, asset_id);
        needed_zeroes -= zeroes.len();
        for zero in zeroes {
            pre_senders.push(self.build_pre_sender(zero, Asset::zero(asset_id))?);
        }
        if needed_zeroes == 0 {
            return Ok(());
        }
        let needed_mints = needed_zeroes.saturating_sub(new_zeroes.len());
        for _ in 0..needed_zeroes {
            match new_zeroes.pop() {
                Some(zero) => pre_senders.push(zero),
                _ => break,
            }
        }
        if needed_mints == 0 {
            return Ok(());
        }
        for _ in 0..needed_mints {
            let (mint, pre_sender) = self.mint_zero(asset_id)?;
            posts.push(self.build_post(mint)?);
            pre_senders.push(pre_sender);
        }
        Ok(())
    }

    ///
    #[inline]
    fn compute_batched_transaction<const SENDERS: usize, const RECEIVERS: usize>(
        &mut self,
        asset_id: AssetId,
        mut pre_senders: Vec<PreSender<C>>,
        posts: &mut Vec<TransferPost<C>>,
    ) -> Result<[Sender<C>; SENDERS], Error<C::HierarchicalKeyDerivationScheme, C>> {
        assert!(
            (SENDERS >= 2) && (RECEIVERS >= 2),
            "The transfer shape must include at least two senders and two receivers."
        );
        assert!(
            !pre_senders.is_empty(),
            "The set of initial senders cannot be empty."
        );

        let mut new_zeroes = Vec::new();

        while pre_senders.len() > SENDERS {
            let mut joins = Vec::new();
            let mut iter = pre_senders.into_iter().chunk_by::<SENDERS>();

            for chunk in &mut iter {
                let senders = fallible_array_map(chunk, |s| {
                    s.try_upgrade(&self.utxo_set)
                        .ok_or(Error::MissingUtxoMembershipProof)
                })?;

                let (receivers, mut join) = self.next_join::<RECEIVERS>(
                    asset_id,
                    senders.iter().map(Sender::asset_value).sum(),
                )?;

                posts.push(self.build_post(Transfer::new(None, [], senders, receivers, []))?);

                join.insert_utxos(&mut self.utxo_set);

                joins.push(join.pre_sender);
                new_zeroes.append(&mut join.zeroes);
            }

            joins.append(&mut iter.remainder());
            pre_senders = joins;
        }

        self.prepare_final_pre_senders::<SENDERS>(asset_id, new_zeroes, &mut pre_senders, posts)?;

        Ok(into_array_unchecked(
            pre_senders
                .into_iter()
                .map(move |s| s.try_upgrade(&self.utxo_set))
                .collect::<Option<Vec<_>>>()
                .ok_or(Error::MissingUtxoMembershipProof)?,
        ))
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

    /// Signs a withdraw transaction.
    #[inline]
    fn sign_withdraw(
        &mut self,
        asset: Asset,
        receiver: impl Into<Option<ReceivingKey<C>>>,
    ) -> SignResult<C::HierarchicalKeyDerivationScheme, C, Self> {
        const SENDERS: usize = PrivateTransferShape::SENDERS;
        const RECEIVERS: usize = PrivateTransferShape::RECEIVERS;
        let selection = self.select(asset)?;
        let change = self.build_receiver(asset.id.with(selection.change))?;
        let mut posts = Vec::new();
        let senders = self.compute_batched_transaction::<SENDERS, RECEIVERS>(
            asset.id,
            selection.pre_senders,
            &mut posts,
        )?;
        let final_post = match receiver.into() {
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
                let receiver = self.build_receiver(asset)?;
                Ok(SignResponse::new(vec![
                    self.build_post(Mint::build(asset, receiver))?
                ]))
            }
            Transaction::PrivateTransfer(asset, receiver) => self.sign_withdraw(asset, receiver),
            Transaction::Reclaim(asset) => self.sign_withdraw(asset, None),
        }
    }

    /// Returns a [`ReceivingKey`] for `self` to receive assets with `index`.
    #[inline]
    pub fn receiving_key(
        &mut self,
        index: Index<C>,
    ) -> ReceivingKeyResult<C::HierarchicalKeyDerivationScheme, C, Self> {
        let keypair = self.account().keypair(index)?;
        Ok(SpendingKey::new(keypair.spend, keypair.view).derive())
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

/* TODO[remove]:
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
*/
