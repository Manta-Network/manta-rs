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
    asset::{sample_asset_balances, Asset, AssetBalance, AssetBalanceVar, AssetBalances, AssetId},
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
        AllocEq, BooleanSystem, Derived, HasVariable, ProofSystem, Public, PublicOrSecret, Secret,
    },
    ies::{EncryptedMessage, IntegratedEncryptionScheme},
    set::{constraint::VerifiedSetProofSystem, VerifiedSet},
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
    pub asset_id: AssetId,

    /// Public Asset Sources
    pub sources: AssetBalances<SOURCES>,

    /// Public Asset Sinks
    pub sinks: AssetBalances<SINKS>,
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
            asset_id,
            sources,
            sinks,
        }
    }

    /// Returns the sum of the asset values of the sources.
    #[inline]
    pub fn source_sum(&self) -> AssetBalance {
        self.sources.iter().sum()
    }

    /// Returns the sum of the asset values of the sinks.
    #[inline]
    pub fn sink_sum(&self) -> AssetBalance {
        self.sinks.iter().sum()
    }

    /// Validates the transaction by checking that the source sum equals the sink sum.
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

/// Secret Transfer Configuration
pub trait SecretTransferConfiguration:
    IdentityProofSystemConfiguration<BooleanSystem = Self::ProofSystem>
{
    /// Proof System
    type ProofSystem: ProofSystem
        + VerifiedSetProofSystem<
            Self::UtxoSet,
            ItemMode = PublicOrSecret,
            PublicMode = Public,
            SecretMode = Secret,
        >;

    /// Integrated Encryption Scheme for [`Asset`]
    type IntegratedEncryptionScheme: IntegratedEncryptionScheme<Plaintext = Asset>;

    /// Verified Set for [`Utxo`]
    type UtxoSet: VerifiedSet<Item = Utxo<Self>>;
}

/// Secret Sender Type
pub type SecretSender<T> = Sender<T, <T as SecretTransferConfiguration>::UtxoSet>;

/// Secret Receiver Type
pub type SecretReceiver<T> =
    Receiver<T, <T as SecretTransferConfiguration>::IntegratedEncryptionScheme>;

/// Secret Sender Variable Type
pub type SecretSenderVar<T> = SenderVar<T, <T as SecretTransferConfiguration>::UtxoSet>;

/// Secret Receiver Type
pub type SecretReceiverVar<T> =
    ReceiverVar<T, <T as SecretTransferConfiguration>::IntegratedEncryptionScheme>;

/// Secret Transfer Protocol
pub struct SecretTransfer<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: SecretTransferConfiguration,
{
    /// Secret Senders
    pub senders: [SecretSender<T>; SENDERS],

    /// Secret Receivers
    pub receivers: [SecretReceiver<T>; RECEIVERS],
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransfer<T, SENDERS, RECEIVERS>
where
    T: SecretTransferConfiguration,
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
        // FIXME: Should we have arrays of senders and receivers or use vectors?
        if SENDERS > Self::MAXIMUM_SENDER_COUNT {
            panic!("Allocated too many senders.");
        }
        if RECEIVERS > Self::MAXIMUM_RECEIVER_COUNT {
            panic!("Allocated too many receivers.");
        }
        Self { senders, receivers }
    }

    /// Checks that the asset ids of all the senders and receivers matches.
    #[inline]
    pub fn has_unique_asset_id(&self) -> bool {
        let mut asset_id = None;
        self.senders
            .iter()
            .map(Sender::asset_id)
            .chain(self.receivers.iter().map(Receiver::asset_id))
            .all(move |i| asset_id.replace(i).eq(&Some(i)))
            && asset_id.is_some()
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
        self.sender_sum().eq(&self.receiver_sum())
    }

    /// Builds constraints for secret transfer validity proof.
    #[inline]
    fn verify<S, R>(
        ps: &mut T::ProofSystem,
        commitment_scheme: &T::CommitmentScheme,
        senders: S,
        receivers: R,
    ) where
        S: IntoIterator<Item = SecretSenderVar<T>>,
        R: IntoIterator<Item = SecretReceiverVar<T>>,
        AssetId: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalance: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalanceVar<T::ProofSystem>: AddAssign<AssetBalanceVar<T::ProofSystem>>,
    {
        let commitment_scheme = ps.allocate((commitment_scheme, Public));

        let mut sender_sum = ps.allocate((&AssetBalance(0), Secret.into()));
        let mut receiver_sum = ps.allocate((&AssetBalance(0), Secret.into()));

        #[allow(clippy::needless_collect)] // NOTE: `ps` is being mutated, we need to collect.
        let asset_ids = mixed_chain(senders, receivers, |c| match c {
            Either::Left(sender) => {
                let asset = sender.get_well_formed_asset(ps, &commitment_scheme);
                sender_sum += asset.value;
                asset.id
            }
            Either::Right(receiver) => {
                let asset = receiver.get_well_formed_asset(ps, &commitment_scheme);
                receiver_sum += asset.value;
                asset.id
            }
        })
        .collect::<Vec<_>>();

        ps.assert_all_eq(asset_ids.iter());
        ps.assert_eq(&sender_sum, &receiver_sum);
    }

    #[inline]
    fn generate_validity_proof(
        &self,
        commitment_scheme: &T::CommitmentScheme,
    ) -> Option<<T::ProofSystem as ProofSystem>::Proof>
    where
        AssetId: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalance: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalanceVar<T::ProofSystem>: AddAssign<AssetBalanceVar<T::ProofSystem>>,
    {
        let mut ps = <T::ProofSystem as Default>::default();

        #[allow(clippy::needless_collect)] // NOTE: `ps` is being mutated, we need to collect.
        let senders = self
            .senders
            .iter()
            .map(|sender| ps.allocate((sender, Derived)))
            .collect::<Vec<_>>();

        #[allow(clippy::needless_collect)] // NOTE: `ps` is being mutated, we need to collect.
        let receivers = self
            .receivers
            .iter()
            .map(|receiver| ps.allocate((receiver, Derived)))
            .collect::<Vec<_>>();

        Self::verify(
            &mut ps,
            commitment_scheme,
            senders.into_iter(),
            receivers.into_iter(),
        );

        ps.finish().ok()
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post(
        self,
        commitment_scheme: &T::CommitmentScheme,
    ) -> Option<SecretTransferPost<T, SENDERS, RECEIVERS>>
    where
        AssetId: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalance: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalanceVar<T::ProofSystem>: AddAssign<AssetBalanceVar<T::ProofSystem>>,
    {
        let validity_proof = self.generate_validity_proof(commitment_scheme)?;
        Some(SecretTransferPost {
            sender_posts: array_map(self.senders, Sender::into_post),
            receiver_posts: array_map(self.receivers, Receiver::into_post),
            validity_proof,
        })
    }
}

/// Secret Sender Post Type
pub type SecretSenderPost<T> = SenderPost<T, <T as SecretTransferConfiguration>::UtxoSet>;

/// Secret Receiver Post Type
pub type SecretReceiverPost<T> =
    ReceiverPost<T, <T as SecretTransferConfiguration>::IntegratedEncryptionScheme>;

/// Secret Transfer Post
pub struct SecretTransferPost<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: SecretTransferConfiguration,
{
    /// Sender Posts
    pub sender_posts: [SecretSenderPost<T>; SENDERS],

    /// Receiver Posts
    pub receiver_posts: [SecretReceiverPost<T>; RECEIVERS],

    /// Validity Proof
    pub validity_proof: <T::ProofSystem as ProofSystem>::Proof,
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransferPost<T, SENDERS, RECEIVERS>
where
    T: SecretTransferConfiguration,
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
        for sender_post in IntoIterator::into_iter(self.sender_posts) {
            sender_post.post(ledger)?;
        }
        for receiver_post in IntoIterator::into_iter(self.receiver_posts) {
            receiver_post.post(ledger)?;
        }
        ledger.check_proof(self.validity_proof)?;
        Ok(())
    }
}

/// Transfer Protocol
pub struct Transfer<
    T,
    const SOURCES: usize,
    const SINKS: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
> where
    T: SecretTransferConfiguration,
{
    /// Public Transfer
    pub public: PublicTransfer<SOURCES, SINKS>,

    /// Secret Transfer
    pub secret: SecretTransfer<T, SENDERS, RECEIVERS>,
}

impl<T, const SOURCES: usize, const SINKS: usize, const SENDERS: usize, const RECEIVERS: usize>
    Transfer<T, SOURCES, SINKS, SENDERS, RECEIVERS>
where
    T: SecretTransferConfiguration,
{
    /// Builds a new [`Transfer`] from a [`PublicTransfer`] and a [`SecretTransfer`].
    #[inline]
    pub fn new(
        public: PublicTransfer<SOURCES, SINKS>,
        secret: SecretTransfer<T, SENDERS, RECEIVERS>,
    ) -> Self {
        Self { public, secret }
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post(
        self,
        commitment_scheme: &T::CommitmentScheme,
    ) -> Option<TransferPost<T, SOURCES, SINKS, SENDERS, RECEIVERS>>
    where
        AssetId: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalance: AllocEq<T::ProofSystem, Mode = PublicOrSecret>,
        AssetBalanceVar<T::ProofSystem>: AddAssign<AssetBalanceVar<T::ProofSystem>>,
    {
        Some(TransferPost {
            public_transfer_post: self.public,
            secret_transfer_post: self.secret.into_post(commitment_scheme)?,
        })
    }
}

/// Transfer Post
pub struct TransferPost<
    T,
    const SOURCES: usize,
    const SINKS: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
> where
    T: SecretTransferConfiguration,
{
    /// Public Transfer Post
    pub public_transfer_post: PublicTransfer<SOURCES, SINKS>,

    /// Secret Transfer Post
    pub secret_transfer_post: SecretTransferPost<T, SENDERS, RECEIVERS>,
}

impl<T, const SOURCES: usize, const SINKS: usize, const SENDERS: usize, const RECEIVERS: usize>
    TransferPost<T, SOURCES, SINKS, SENDERS, RECEIVERS>
where
    T: SecretTransferConfiguration,
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
        // FIXME: self.public_transfer_post.post(ledger)?;
        self.secret_transfer_post.post(ledger)?;
        Ok(())
    }
}
