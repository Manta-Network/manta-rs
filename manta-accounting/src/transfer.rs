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

//! Transfer Protocols

use crate::{
    asset::{
        sample_asset_balances, Asset, AssetBalance, AssetBalanceVar, AssetBalances, AssetId,
        AssetIdVar,
    },
    identity::{
        IdentityProofSystemConfiguration, Receiver, ReceiverPost, ReceiverVar, Sender, SenderPost,
        SenderVar, Utxo, VoidNumber,
    },
    ledger::{Ledger, PostError},
};
use alloc::vec::Vec;
use core::ops::AddAssign;
use manta_crypto::{
    constraint::{
        Alloc, AllocEq, BooleanSystem, Constant, Derived, ProofSystem, Public, PublicOrSecret,
        Secret,
    },
    ies::{EncryptedMessage, IntegratedEncryptionScheme},
    set::{constraint::VerifiedSetVariable, VerifiedSet},
};
use manta_util::{array_map, mixed_chain, Either};
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};

/// Public Transfer Protocol
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicTransfer<const SOURCES: usize, const SINKS: usize> {
    /// Asset Id
    pub asset_id: Option<AssetId>,

    /// Public Asset Sources
    pub sources: AssetBalances<SOURCES>,

    /// Public Asset Sinks
    pub sinks: AssetBalances<SINKS>,
}

#[allow(clippy::derivable_impls)] // NOTE: We only want default on the `<0, 0>` setting.
impl Default for PublicTransfer<0, 0> {
    #[inline]
    fn default() -> Self {
        Self {
            asset_id: None,
            sources: [],
            sinks: [],
        }
    }
}

impl<const SOURCES: usize, const SINKS: usize> PublicTransfer<SOURCES, SINKS> {
    /// Builds a new [`PublicTransfer`].
    #[inline]
    pub const fn new(
        asset_id: AssetId,
        sources: AssetBalances<SOURCES>,
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self {
            asset_id: if SOURCES == 0 && SINKS == 0 {
                None
            } else {
                Some(asset_id)
            },
            sources,
            sinks,
        }
    }

    /// Returns the sum of the asset values of the sources in this transfer.
    #[inline]
    pub fn source_sum(&self) -> AssetBalance {
        self.sources.iter().sum()
    }

    /// Returns the sum of the asset values of the sinks in this transfer.
    #[inline]
    pub fn sink_sum(&self) -> AssetBalance {
        self.sinks.iter().sum()
    }

    /// Validates the transaction by checking that the [`source_sum`](Self::source_sum)
    /// equals the [`sink_sum`](Self::sink_sum).
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.source_sum() == self.sink_sum()
    }
}

impl<const SOURCES: usize, const SINKS: usize> Distribution<PublicTransfer<SOURCES, SINKS>>
    for Standard
{
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> PublicTransfer<SOURCES, SINKS> {
        PublicTransfer::new(
            rng.gen(),
            sample_asset_balances(rng),
            sample_asset_balances(rng),
        )
    }
}

/// Transfer Configuration
pub trait TransferConfiguration:
    IdentityProofSystemConfiguration<BooleanSystem = Self::ProofSystem>
{
    /// Proof System
    type ProofSystem: ProofSystem;

    /// Integrated Encryption Scheme for [`Asset`]
    type IntegratedEncryptionScheme: IntegratedEncryptionScheme<Plaintext = Asset>;

    /// Verified Set Public Input
    type UtxoSetPublicInput: Alloc<Self::ProofSystem, Mode = Public>;

    /// Verified Set Secret Witness
    type UtxoSetSecretWitness: Alloc<Self::ProofSystem, Mode = Secret>;

    /// Verified Set for [`Utxo`]
    type UtxoSet: VerifiedSet<
            Item = Utxo<Self>,
            Public = Self::UtxoSetPublicInput,
            Secret = Self::UtxoSetSecretWitness,
        > + Alloc<Self::ProofSystem, Mode = Constant, Variable = Self::UtxoSetVar>;

    /// Verified Set Variable for [`Utxo`]
    type UtxoSetVar: VerifiedSetVariable<Self::ProofSystem, Mode = Constant, Type = Self::UtxoSet>;
}

/// Secret Sender Type
pub type SecretSender<T> = Sender<T, <T as TransferConfiguration>::UtxoSet>;

/// Secret Receiver Type
pub type SecretReceiver<T> = Receiver<T, <T as TransferConfiguration>::IntegratedEncryptionScheme>;

/// Secret Sender Variable Type
pub type SecretSenderVar<T> = SenderVar<T, <T as TransferConfiguration>::UtxoSet>;

/// Secret Receiver Type
pub type SecretReceiverVar<T> =
    ReceiverVar<T, <T as TransferConfiguration>::IntegratedEncryptionScheme>;

/// Secret Transfer Proof Type
pub type Proof<T> = <<T as TransferConfiguration>::ProofSystem as ProofSystem>::Proof;

/// Secret Transfer Protocol
pub struct SecretTransfer<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: TransferConfiguration,
{
    /// Secret Senders
    pub senders: [SecretSender<T>; SENDERS],

    /// Secret Receivers
    pub receivers: [SecretReceiver<T>; RECEIVERS],
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransfer<T, SENDERS, RECEIVERS>
where
    T: TransferConfiguration,
{
    /// Maximum Number of Senders
    pub const MAXIMUM_SENDER_COUNT: usize = 32;

    /// Maximum Number of Receivers
    pub const MAXIMUM_RECEIVER_COUNT: usize = 32;

    /// Builds a new [`SecretTransfer`].
    #[inline]
    pub fn new(
        senders: [SecretSender<T>; SENDERS],
        receivers: [SecretReceiver<T>; RECEIVERS],
    ) -> Self {
        Self::check_sender_side();
        Self::check_receiver_side();
        Self::check_size_overflow();
        Self::new_unchecked(senders, receivers)
    }

    /// Checks that the sender side is not empty.
    #[inline]
    fn check_sender_side() {
        if SENDERS == 0 {
            panic!("Not enough senders.")
        }
    }

    /// Checks that the receiver side is not empty.
    #[inline]
    fn check_receiver_side() {
        if RECEIVERS == 0 {
            panic!("Not enough receivers.")
        }
    }

    /// Checks that the number of senders and/or receivers does not exceed the allocation limit.
    #[inline]
    fn check_size_overflow() {
        // FIXME: Should we have arrays of senders and receivers or use vectors?
        match (
            SENDERS > Self::MAXIMUM_SENDER_COUNT,
            RECEIVERS > Self::MAXIMUM_RECEIVER_COUNT,
        ) {
            (true, true) => panic!("Allocated too many senders and receivers."),
            (true, _) => panic!("Allocated too many senders."),
            (_, true) => panic!("Allocated too many receivers."),
            _ => {}
        }
    }

    /// Builds a new [`SecretTransfer`] without checking the number of senders and receivers.
    #[inline]
    fn new_unchecked(
        senders: [SecretSender<T>; SENDERS],
        receivers: [SecretReceiver<T>; RECEIVERS],
    ) -> Self {
        Self { senders, receivers }
    }

    /// Returns an iterator over all the asset ids in this transfer.
    #[inline]
    fn asset_id_iter(&self) -> impl '_ + Iterator<Item = AssetId> {
        self.senders
            .iter()
            .map(Sender::asset_id)
            .chain(self.receivers.iter().map(Receiver::asset_id))
    }

    /// Checks that the asset ids of all the senders and receivers matches.
    #[inline]
    pub fn has_unique_asset_id(&self) -> bool {
        let mut asset_id = None;
        self.asset_id_iter()
            .all(move |i| asset_id.replace(i) == Some(i))
    }

    /// Returns the sum of the asset values of the senders in this transfer.
    #[inline]
    pub fn sender_sum(&self) -> AssetBalance {
        self.senders.iter().map(Sender::asset_value).sum()
    }

    /// Returns the sum of the asset values of the receivers in this transfer.
    #[inline]
    pub fn receiver_sum(&self) -> AssetBalance {
        self.receivers.iter().map(Receiver::asset_value).sum()
    }

    /// Checks that the [`sender_sum`](Self::sender_sum) equals the
    /// [`receiver_sum`](Self::receiver_sum).
    #[inline]
    pub fn is_balanced(&self) -> bool {
        self.sender_sum() == self.receiver_sum()
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post(
        self,
        commitment_scheme: &T::CommitmentScheme,
        utxo_set: &T::UtxoSet,
    ) -> Option<SecretTransferPost<T, SENDERS, RECEIVERS>>
    where
        AssetId: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalance: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalanceVar<T::ProofSystem>: AddAssign<AssetBalanceVar<T::ProofSystem>>,
    {
        Some(SecretTransferPost {
            validity_proof: Transfer::<T, 0, SENDERS, RECEIVERS, 0>::generate_validity_proof(
                None,
                &[],
                &self.senders,
                &self.receivers,
                &[],
                commitment_scheme,
                utxo_set,
            )?,
            sender_posts: array_map(self.senders, Sender::into_post),
            receiver_posts: array_map(self.receivers, Receiver::into_post),
        })
    }
}

/// Secret Sender Post Type
pub type SecretSenderPost<T> = SenderPost<T, <T as TransferConfiguration>::UtxoSet>;

/// Secret Receiver Post Type
pub type SecretReceiverPost<T> =
    ReceiverPost<T, <T as TransferConfiguration>::IntegratedEncryptionScheme>;

/// Secret Transfer Post
pub struct SecretTransferPost<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: TransferConfiguration,
{
    /// Sender Posts
    pub sender_posts: [SecretSenderPost<T>; SENDERS],

    /// Receiver Posts
    pub receiver_posts: [SecretReceiverPost<T>; RECEIVERS],

    /// Validity Proof
    pub validity_proof: Proof<T>,
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransferPost<T, SENDERS, RECEIVERS>
where
    T: TransferConfiguration,
{
    /// Posts the [`SecretTransferPost`] to the `ledger`.
    #[inline]
    pub fn post<L>(self, ledger: &mut L) -> Result<(), PostError<L>>
    where
        L: Ledger<
                VoidNumber = VoidNumber<T>,
                Utxo = Utxo<T>,
                UtxoSet = T::UtxoSet,
                EncryptedAsset = EncryptedMessage<T::IntegratedEncryptionScheme>,
                ProofSystem = T::ProofSystem,
            > + ?Sized,
    {
        TransferPost::<T, 0, SENDERS, RECEIVERS, 0>::from(self).post(ledger)
    }
}

impl<T, const SENDERS: usize, const RECEIVERS: usize>
    From<SecretTransferPost<T, SENDERS, RECEIVERS>> for TransferPost<T, 0, SENDERS, RECEIVERS, 0>
where
    T: TransferConfiguration,
{
    #[inline]
    fn from(post: SecretTransferPost<T, SENDERS, RECEIVERS>) -> Self {
        TransferPost {
            public_transfer: Default::default(),
            secret_sender_posts: post.sender_posts,
            secret_receiver_posts: post.receiver_posts,
            validity_proof: Some(post.validity_proof),
        }
    }
}

/// Transfer Protocol
pub struct Transfer<
    T,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    T: TransferConfiguration,
{
    /// Public Part of the Transfer
    public: PublicTransfer<SOURCES, SINKS>,

    /// Secret Part of the Transfer
    secret: SecretTransfer<T, SENDERS, RECEIVERS>,
}

impl<T, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<T, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    T: TransferConfiguration,
{
    /// Builds a new [`Transfer`] from a [`PublicTransfer`] and a [`SecretTransfer`].
    #[inline]
    pub fn new(
        asset_id: AssetId,
        sources: AssetBalances<SOURCES>,
        senders: [SecretSender<T>; SENDERS],
        receivers: [SecretReceiver<T>; RECEIVERS],
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self::check_sender_side();
        Self::check_receiver_side();
        SecretTransfer::<T, SENDERS, RECEIVERS>::check_size_overflow();
        Self::new_unchecked(asset_id, sources, senders, receivers, sinks)
    }

    /// Checks that the sender side is not empty.
    #[inline]
    fn check_sender_side() {
        if SOURCES + SENDERS == 0 {
            panic!("Not enough participants on the sender side.");
        }
    }

    /// Checks that the receiver side is not empty.
    #[inline]
    fn check_receiver_side() {
        if RECEIVERS + SINKS == 0 {
            panic!("Not enough participants on the receiver side.");
        }
    }

    /// Builds a new [`Transfer`] without checking the number of participants on the sender and
    /// receiver side.
    #[inline]
    fn new_unchecked(
        asset_id: AssetId,
        sources: AssetBalances<SOURCES>,
        senders: [SecretSender<T>; SENDERS],
        receivers: [SecretReceiver<T>; RECEIVERS],
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self {
            public: PublicTransfer::new(asset_id, sources, sinks),
            secret: SecretTransfer::new_unchecked(senders, receivers),
        }
    }

    /// Checks that there is one unique asset id for all participants in this transfer.
    #[inline]
    pub fn has_unique_asset_id(&self) -> bool {
        if let Some(asset_id) = self.public.asset_id {
            self.secret.asset_id_iter().all(move |i| asset_id == i)
        } else {
            self.secret.has_unique_asset_id()
        }
    }

    /// Returns the sum of the asset values of the sources in this transfer.
    #[inline]
    pub fn source_sum(&self) -> AssetBalance {
        self.public.source_sum()
    }

    /// Returns the sum of the asset values of the senders in this transfer.
    #[inline]
    pub fn sender_sum(&self) -> AssetBalance {
        self.secret.sender_sum()
    }

    /// Returns the sum of the asset values of the receivers in this transfer.
    #[inline]
    pub fn receiver_sum(&self) -> AssetBalance {
        self.secret.receiver_sum()
    }

    /// Returns the sum of the asset values of the sinks in this transfer.
    #[inline]
    pub fn sink_sum(&self) -> AssetBalance {
        self.public.sink_sum()
    }

    /// Checks that the transaction is balanced.
    #[inline]
    pub fn is_balanced(&self) -> bool {
        self.source_sum() + self.sender_sum() == self.receiver_sum() + self.sink_sum()
    }

    /// Builds constraints for transfer validity proof.
    #[allow(clippy::too_many_arguments)] // NOTE: We don't want to make a new `struct` for this.
    #[inline]
    fn verify<Sources, Senders, Receivers, Sinks>(
        ps: &mut T::ProofSystem,
        commitment_scheme: &T::CommitmentSchemeVar,
        utxo_set: &T::UtxoSetVar,
        base_asset_id: Option<AssetIdVar<T::ProofSystem>>,
        sources: Sources,
        senders: Senders,
        receivers: Receivers,
        sinks: Sinks,
    ) where
        Sources: Iterator<Item = AssetBalanceVar<T::ProofSystem>>,
        Senders: Iterator<Item = SecretSenderVar<T>>,
        Receivers: Iterator<Item = SecretReceiverVar<T>>,
        Sinks: Iterator<Item = AssetBalanceVar<T::ProofSystem>>,
        AssetId: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalance: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalanceVar<T::ProofSystem>: AddAssign<AssetBalanceVar<T::ProofSystem>>,
    {
        let mut sender_sum = AssetBalance(0).as_known(ps, Secret);
        let mut receiver_sum = AssetBalance(0).as_known(ps, Secret);

        sources.for_each(|source| sender_sum += source);
        sinks.for_each(|sink| receiver_sum += sink);

        #[allow(clippy::needless_collect)] // NOTE: `ps` is being mutated, we need to collect.
        let secret_asset_ids = mixed_chain(senders, receivers, |c| match c {
            Either::Left(sender) => {
                let asset = sender.get_well_formed_asset(ps, commitment_scheme, utxo_set);
                sender_sum += asset.value;
                asset.id
            }
            Either::Right(receiver) => {
                let asset = receiver.get_well_formed_asset(ps, commitment_scheme);
                receiver_sum += asset.value;
                asset.id
            }
        })
        .collect::<Vec<_>>();

        match base_asset_id {
            Some(asset_id) => ps.assert_all_eq_to_base(&asset_id, secret_asset_ids.iter()),
            _ => ps.assert_all_eq(secret_asset_ids.iter()),
        }

        ps.assert_eq(&sender_sum, &receiver_sum);
    }

    /// Generates a validity proof for this transfer.
    #[inline]
    fn generate_validity_proof(
        base_asset_id: Option<AssetId>,
        sources: &AssetBalances<SOURCES>,
        senders: &[SecretSender<T>; SENDERS],
        receivers: &[SecretReceiver<T>; RECEIVERS],
        sinks: &AssetBalances<SINKS>,
        commitment_scheme: &T::CommitmentScheme,
        utxo_set: &T::UtxoSet,
    ) -> Option<Proof<T>>
    where
        AssetId: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalance: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalanceVar<T::ProofSystem>: AddAssign<AssetBalanceVar<T::ProofSystem>>,
    {
        // FIXME: Find a better way to allocate variables without so much hassle.

        let mut ps = <T::ProofSystem as Default>::default();

        let base_asset_id = base_asset_id.map(|id| id.as_known(&mut ps, Public));

        #[allow(clippy::needless_collect)] // NOTE: `ps` is being mutated, we need to collect.
        let sources = sources
            .iter()
            .map(|source| source.as_known(&mut ps, Public))
            .collect::<Vec<_>>();

        #[allow(clippy::needless_collect)] // NOTE: `ps` is being mutated, we need to collect.
        let senders = senders
            .iter()
            .map(|sender| sender.as_known(&mut ps, Derived))
            .collect::<Vec<_>>();

        #[allow(clippy::needless_collect)] // NOTE: `ps` is being mutated, we need to collect.
        let receivers = receivers
            .iter()
            .map(|receiver| receiver.as_known(&mut ps, Derived))
            .collect::<Vec<_>>();

        #[allow(clippy::needless_collect)] // NOTE: `ps` is being mutated, we need to collect.
        let sinks = sinks
            .iter()
            .map(|sink| sink.as_known(&mut ps, Public))
            .collect::<Vec<_>>();

        let commitment_scheme = commitment_scheme.as_known(&mut ps, Public);
        let utxo_set = utxo_set.as_known(&mut ps, Public);

        Self::verify(
            &mut ps,
            &commitment_scheme,
            &utxo_set,
            base_asset_id,
            sources.into_iter(),
            senders.into_iter(),
            receivers.into_iter(),
            sinks.into_iter(),
        );

        ps.finish().ok()
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post(
        self,
        commitment_scheme: &T::CommitmentScheme,
        utxo_set: &T::UtxoSet,
    ) -> Option<TransferPost<T, SOURCES, SENDERS, RECEIVERS, SINKS>>
    where
        AssetId: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalance: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalanceVar<T::ProofSystem>: AddAssign<AssetBalanceVar<T::ProofSystem>>,
    {
        Some(TransferPost {
            validity_proof: if SENDERS == 0 {
                None
            } else {
                Some(Self::generate_validity_proof(
                    self.public.asset_id,
                    &self.public.sources,
                    &self.secret.senders,
                    &self.secret.receivers,
                    &self.public.sinks,
                    commitment_scheme,
                    utxo_set,
                )?)
            },
            public_transfer: self.public,
            secret_sender_posts: array_map(self.secret.senders, Sender::into_post),
            secret_receiver_posts: array_map(self.secret.receivers, Receiver::into_post),
        })
    }
}

/// Transfer Post
pub struct TransferPost<
    T,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    T: TransferConfiguration,
{
    /// Public Transfer
    public_transfer: PublicTransfer<SOURCES, SINKS>,

    /// Secret Sender Posts
    secret_sender_posts: [SecretSenderPost<T>; SENDERS],

    /// Secret Receiver Posts
    secret_receiver_posts: [SecretReceiverPost<T>; RECEIVERS],

    /// Validity Proof
    validity_proof: Option<Proof<T>>,
}

impl<T, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    TransferPost<T, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    T: TransferConfiguration,
{
    /// Posts the [`TransferPost`] to the `ledger`.
    #[inline]
    pub fn post<L>(self, ledger: &mut L) -> Result<(), PostError<L>>
    where
        L: Ledger<
                VoidNumber = VoidNumber<T>,
                Utxo = Utxo<T>,
                EncryptedAsset = EncryptedMessage<T::IntegratedEncryptionScheme>,
                UtxoSet = T::UtxoSet,
                ProofSystem = T::ProofSystem,
            > + ?Sized,
    {
        // FIXME: Does the public transfer component need to be validated?
        //
        //   > Probably not. The public part of a transfer comes from the same place that the
        //     ledger is stored so the ledger can check whether the balances come from accounts
        //     which have the right amount of assets to spend. Eventually, we either inherit that
        //     logic from another library or we implement it here in `manta-rs`.
        //
        let _ = self.public_transfer;

        for sender_post in IntoIterator::into_iter(self.secret_sender_posts) {
            sender_post.post(ledger)?;
        }
        for receiver_post in IntoIterator::into_iter(self.secret_receiver_posts) {
            receiver_post.post(ledger)?;
        }
        if let Some(proof) = self.validity_proof {
            ledger.check_proof(proof)?;
        }
        Ok(())
    }
}

/// Sealed Trait Module
mod sealed {
    /// Sealed Trait
    pub trait Sealed {}
}

/// Transfer Shapes
///
/// This trait identifies a transfer shape, i.e. the number and type of participants on the sender
/// and receiver side of the transaction. This trait is sealed and can only be used with the
/// existing implementations.
pub trait Shape: sealed::Sealed {
    /// Number of Sources
    const SOURCES: usize;

    /// Number of Senders
    const SENDERS: usize;

    /// Number of Receivers
    const RECEIVERS: usize;

    /// Number of Sinks
    const SINKS: usize;
}

/// Canonical Transaction Types
pub mod canonical {
    use super::*;

    /// Implements [`Shape`] for a given shape type.
    macro_rules! impl_shape {
        ($shape:tt, $sources:expr, $senders:expr, $receivers:expr, $sinks:expr) => {
            impl sealed::Sealed for $shape {}
            impl Shape for $shape {
                const SOURCES: usize = $sources;
                const SENDERS: usize = $senders;
                const RECEIVERS: usize = $receivers;
                const SINKS: usize = $sinks;
            }
        };
    }

    /// Builds a new alias using the given shape type.
    macro_rules! alias_type {
        ($type:tt, $t:ident, $shape:tt) => {
            $type<
                $t,
                { $shape::SOURCES },
                { $shape::SENDERS },
                { $shape::RECEIVERS },
                { $shape::SINKS },
            >
        }
    }

    /// Builds a new [`Transfer`] alias using the given shape type.
    macro_rules! transfer_alias {
        ($t:ident, $shape:tt) => {
            alias_type!(Transfer, $t, $shape)
        };
    }

    /// Builds a new [`TransferPost`] alias using the given shape type.
    macro_rules! transfer_post_alias {
        ($t:ident, $shape:tt) => {
            alias_type!(TransferPost, $t, $shape)
        };
    }

    /// Mint Transaction Shape
    ///
    /// ```
    /// <1, 0, 1, 0>
    /// ```
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct MintShape;

    impl_shape!(MintShape, 1, 0, 1, 0);

    /// Mint Transaction
    pub type Mint<T> = transfer_alias!(T, MintShape);

    /// Mint Transaction Ledger Post
    pub type MintPost<T> = transfer_post_alias!(T, MintShape);

    /// Private Transfer Transaction Shape
    ///
    /// ```
    /// <0, 2, 2, 0>
    /// ```
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct PrivateTransferShape;

    impl_shape!(PrivateTransferShape, 0, 2, 2, 0);

    /// Private Transfer Transaction
    pub type PrivateTransfer<T> = transfer_alias!(T, PrivateTransferShape);

    /// Private Transfer Transaction Post
    pub type PrivateTransferPost<T> = transfer_post_alias!(T, PrivateTransferShape);

    /// Reclaim Transaction Shape
    ///
    /// ```
    /// <0, 2, 1, 1>
    /// ```
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct ReclaimShape;

    impl_shape!(ReclaimShape, 0, 2, 1, 1);

    /// Reclaim Transaction
    pub type Reclaim<T> = transfer_alias!(T, ReclaimShape);

    /// Reclaim Transaction Post
    pub type ReclaimPost<T> = transfer_post_alias!(T, ReclaimShape);
}
