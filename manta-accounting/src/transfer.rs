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
    asset::{sample_asset_balances, Asset, AssetBalance, AssetBalances, AssetId},
    identity::{
        IdentityConfiguration, Receiver, ReceiverPost, Sender, SenderPost, Utxo, VoidNumber,
    },
    ledger::{Ledger, PostError},
};
use manta_crypto::{ies::EncryptedMessage, IntegratedEncryptionScheme, VerifiedSet};
use manta_util::array_map;
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

/// Secret Transfer Configuration Trait
pub trait SecretTransferConfiguration: IdentityConfiguration {
    /// Integrated Encryption Scheme for [`Asset`]
    type IntegratedEncryptionScheme: IntegratedEncryptionScheme<Plaintext = Asset>;

    /// Verified Set for [`Utxo`]
    type UtxoSet: VerifiedSet<Item = Utxo<Self>>;
}

/// Secret Transfer Protocol
pub struct SecretTransfer<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: SecretTransferConfiguration,
{
    /// Secret Senders
    pub senders: [Sender<T, T::UtxoSet>; SENDERS],

    /// Secret Receivers
    pub receivers: [Receiver<T, T::IntegratedEncryptionScheme>; RECEIVERS],
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransfer<T, SENDERS, RECEIVERS>
where
    T: SecretTransferConfiguration,
{
    /// Builds a new [`SecretTransfer`].
    #[inline]
    pub fn new(
        senders: [Sender<T, T::UtxoSet>; SENDERS],
        receivers: [Receiver<T, T::IntegratedEncryptionScheme>; RECEIVERS],
    ) -> Self {
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

    #[inline]
    fn generate_validity_proof(&self) {
        // FIXME: build zkp
        todo!()
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post(self) -> SecretTransferPost<T, SENDERS, RECEIVERS> {
        let validity_proof = self.generate_validity_proof();
        SecretTransferPost {
            sender_posts: array_map(self.senders, Sender::into_post),
            receiver_posts: array_map(self.receivers, Receiver::into_post),
            validity_proof,
        }
    }
}

/// Secret Transfer Post
pub struct SecretTransferPost<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: SecretTransferConfiguration,
{
    /// Sender Posts
    pub sender_posts: [SenderPost<T, T::UtxoSet>; SENDERS],

    /// Receiver Posts
    pub receiver_posts: [ReceiverPost<T, T::IntegratedEncryptionScheme>; RECEIVERS],

    /// Validity Proof
    pub validity_proof: (),
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
            > + ?Sized,
    {
        for sender_post in IntoIterator::into_iter(self.sender_posts) {
            sender_post.post(ledger)?;
        }
        for receiver_post in IntoIterator::into_iter(self.receiver_posts) {
            receiver_post.post(ledger)?;
        }
        // FIXME: proof.post(ledger)?;
        //        - returns `PostError::InvalidSecretTransfer` on error?
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
    pub fn into_post(self) -> TransferPost<T, SOURCES, SINKS, SENDERS, RECEIVERS> {
        TransferPost {
            public_transfer_post: self.public,
            secret_transfer_post: self.secret.into_post(),
        }
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
            > + ?Sized,
    {
        // FIXME: self.public_transfer_post.post(ledger)?;
        self.secret_transfer_post.post(ledger)?;
        Ok(())
    }
}
