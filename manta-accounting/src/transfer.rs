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
        AssetVar,
    },
    identity::{
        CommitmentSchemeOutput, CommitmentSchemeOutputVar, CommitmentSchemeRandomness,
        CommitmentSchemeRandomnessVar, CommitmentSchemeVar, IdentityConfiguration,
        PseudorandomFunctionFamilyInput, PseudorandomFunctionFamilyOutput, PublicKeyVar, Receiver,
        ReceiverPost, ReceiverVar, SecretKey, Sender, SenderPost, SenderVar, Utxo, VoidNumber,
        VoidNumberCommitmentVar, VoidNumberGeneratorVar,
    },
    ledger::{Ledger, PostError},
};
use alloc::vec::Vec;
use core::iter::Sum;
use manta_crypto::{
    commitment::{CommitmentScheme, Input as CommitmentInput},
    constraint::{Const, Constant, Equal, ProofSystem, PublicOrSecret, Secret, Var},
    ies::{EncryptedMessage, IntegratedEncryptionScheme},
    set::{ContainmentProof, VerifiedSet},
};
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
pub trait SecretTransferConfiguration: IdentityConfiguration {
    /// Integrated Encryption Scheme for [`Asset`]
    type IntegratedEncryptionScheme: IntegratedEncryptionScheme<Plaintext = Asset>;

    /// Verified Set for [`Utxo`]
    type UtxoSet: VerifiedSet<Item = Utxo<Self>>;
}

/// Secret Transfer Proof System
pub trait SecretTransferProofSystem: SecretTransferConfiguration + ProofSystem {}

/// Secret Sender Type
pub type SecretSender<T> = Sender<T, <T as SecretTransferConfiguration>::UtxoSet>;

/// Secret Receiver Type
pub type SecretReceiver<T> =
    Receiver<T, <T as SecretTransferConfiguration>::IntegratedEncryptionScheme>;

/// Secret Sender Variable Type
pub type SecretSenderVar<T> = SenderVar<T, <T as SecretTransferConfiguration>::UtxoSet, T>;

/// Secret Receiver Type
pub type SecretReceiverVar<T> =
    ReceiverVar<T, <T as SecretTransferConfiguration>::IntegratedEncryptionScheme, T>;

/// Secret Transfer Protocol
pub struct SecretTransfer<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: SecretTransferProofSystem,
{
    /// Secret Senders
    pub senders: [SecretSender<T>; SENDERS],

    /// Secret Receivers
    pub receivers: [SecretReceiver<T>; RECEIVERS],
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransfer<T, SENDERS, RECEIVERS>
where
    T: SecretTransferProofSystem,
{
    /// Maximum Number of Senders
    pub const MAXIMUM_SENDER_COUNT: usize = 10;

    /// Maximum Number of Receivers
    pub const MAXIMUM_RECEIVER_COUNT: usize = 10;

    /// Builds a new [`SecretTransfer`].
    #[inline]
    pub fn new(
        senders: [SecretSender<T>; SENDERS],
        receivers: [SecretReceiver<T>; RECEIVERS],
    ) -> Self {
        if SENDERS > Self::MAXIMUM_SENDER_COUNT {
            panic!("Allocated too many senders.");
        }
        if RECEIVERS > Self::MAXIMUM_RECEIVER_COUNT {
            panic!("Allocated too many receivers.");
        }
        Self { senders, receivers }
    }

    /* TODO: do we still want these?
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
    */

    /// Builds constraints for secret transfer validity proof.
    #[inline]
    fn verify(
        ps: &mut T,
        commitment_scheme: &T::CommitmentScheme,
        senders: Vec<SecretSenderVar<T>>,
        receivers: Vec<SecretReceiverVar<T>>,
    ) where
        T::CommitmentScheme: Const<T>,
        AssetId: Equal<T, PublicOrSecret>,
        AssetBalance: Equal<T, PublicOrSecret>,
        for<'i> &'i AssetBalanceVar<T>: Sum,
        SecretKey<T>: Var<T, Secret>,
        PseudorandomFunctionFamilyInput<T>: Var<T, Secret>,
        PseudorandomFunctionFamilyOutput<T>: Equal<T, PublicOrSecret>,
        CommitmentSchemeRandomness<T>: Var<T, Secret>,
        CommitmentSchemeOutput<T>: Equal<T, PublicOrSecret>,
        ContainmentProof<T::UtxoSet>: Var<T, Secret>,
        Constant<T::CommitmentScheme, T>: CommitmentScheme<
            Randomness = CommitmentSchemeRandomnessVar<T, T>,
            Output = CommitmentSchemeOutputVar<T, T>,
        >,
        PublicKeyVar<T, T>: CommitmentInput<CommitmentSchemeVar<T, T>>,
        VoidNumberGeneratorVar<T, T>: CommitmentInput<CommitmentSchemeVar<T, T>>,
        AssetVar<T>: CommitmentInput<CommitmentSchemeVar<T, T>>,
        VoidNumberCommitmentVar<T, T>: CommitmentInput<CommitmentSchemeVar<T, T>>,
    {
        // TODO: find a way to do this without having to build intermediate `Vec<_>`

        let commitment_scheme = commitment_scheme.as_constant(ps);

        // 1. Check that all senders are well-formed.
        /* FIXME:
        for sender in &senders {
            sender.verify_well_formed(ps, &commitment_scheme);
        }
        */

        // 2. Check that all receivers are well-formed.
        for receiver in &receivers {
            receiver.verify_well_formed(ps, &commitment_scheme);
        }

        // 3. Check that there is a unique asset id for all the assets.
        let sender_ids = senders.iter().map(SenderVar::asset_id);
        let receiver_ids = receivers.iter().map(ReceiverVar::asset_id);
        ps.assert_all_eq(sender_ids.chain(receiver_ids));

        // 4. Check that the transaction is balanced.
        ps.assert_eq(
            senders.iter().map(SenderVar::asset_value).sum(),
            receivers.iter().map(ReceiverVar::asset_value).sum(),
        );
    }

    #[inline]
    fn generate_validity_proof(&self) -> Option<T::Proof> {
        // FIXME: Build secret transfer zero knowledge proof:

        let proof_system = T::default();

        /* TODO:

        // When we know the variables:
        let senders = self
            .senders
            .iter()
            .map(|s| s.as_variable(&mut proof_system))
            .collect::<Vec<_>>();
        let receivers = self
            .receivers
            .iter()
            .map(|r| r.as_variable(&mut proof_system))
            .collect::<Vec<_>>();

        // When we don't:
        let senders = self
            .senders
            .iter()
            .map(|_| SenderVariable::unknown(&mut proof_system))
            .collect::<Vec<_>>();
        let receivers = self
            .receivers
            .iter()
            .map(|_| ReceiverVariable::unknown(&mut proof_system))
            .collect::<Vec<_>>();

        Self::build_proof_content(&mut proof_system, senders, receivers);
        */

        proof_system.finish().ok()
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post(self) -> Option<SecretTransferPost<T, SENDERS, RECEIVERS>> {
        let validity_proof = self.generate_validity_proof()?;
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
    T: SecretTransferProofSystem,
{
    /// Sender Posts
    pub sender_posts: [SecretSenderPost<T>; SENDERS],

    /// Receiver Posts
    pub receiver_posts: [SecretReceiverPost<T>; RECEIVERS],

    /// Validity Proof
    pub validity_proof: T::Proof,
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransferPost<T, SENDERS, RECEIVERS>
where
    T: SecretTransferProofSystem,
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

impl<T, const SENDERS: usize, const RECEIVERS: usize> From<SecretTransfer<T, SENDERS, RECEIVERS>>
    for Option<SecretTransferPost<T, SENDERS, RECEIVERS>>
where
    T: SecretTransferProofSystem,
{
    #[inline]
    fn from(secret_transfer: SecretTransfer<T, SENDERS, RECEIVERS>) -> Self {
        secret_transfer.into_post()
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
    T: SecretTransferProofSystem,
{
    /// Public Transfer
    pub public: PublicTransfer<SOURCES, SINKS>,

    /// Secret Transfer
    pub secret: SecretTransfer<T, SENDERS, RECEIVERS>,
}

impl<T, const SOURCES: usize, const SINKS: usize, const SENDERS: usize, const RECEIVERS: usize>
    Transfer<T, SOURCES, SINKS, SENDERS, RECEIVERS>
where
    T: SecretTransferProofSystem,
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
    pub fn into_post(self) -> Option<TransferPost<T, SOURCES, SINKS, SENDERS, RECEIVERS>> {
        Some(TransferPost {
            public_transfer_post: self.public,
            secret_transfer_post: self.secret.into_post()?,
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
    T: SecretTransferProofSystem,
{
    /// Public Transfer Post
    pub public_transfer_post: PublicTransfer<SOURCES, SINKS>,

    /// Secret Transfer Post
    pub secret_transfer_post: SecretTransferPost<T, SENDERS, RECEIVERS>,
}

impl<T, const SOURCES: usize, const SINKS: usize, const SENDERS: usize, const RECEIVERS: usize>
    TransferPost<T, SOURCES, SINKS, SENDERS, RECEIVERS>
where
    T: SecretTransferProofSystem,
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
