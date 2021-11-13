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

//! Sender and Receiver Identities

use crate::address;
use core::marker::PhantomData;
use manta_crypto::{
    accumulator::{Accumulator, MembershipProof, Verifier},
    commitment::{CommitmentScheme, Input as CommitmentInput},
    encryption::{EncryptedMessage, HybridPublicKeyEncryptionScheme},
    key::KeyAgreementScheme,
};

/// Identity Configuration
pub trait Configuration {
    /// Asset Type
    type Asset;

    /// Key Scheme Type
    type KeyScheme: KeyAgreementScheme;

    /// Commitment Scheme Type
    type CommitmentScheme: CommitmentScheme<Randomness = <Self::KeyScheme as KeyAgreementScheme>::SharedSecret>
        + CommitmentInput<Self::Asset>
        + CommitmentInput<<Self::KeyScheme as KeyAgreementScheme>::SecretKey>;
}

/// Spending Key Type
pub type SpendingKey<C> = address::SpendingKey<<C as Configuration>::KeyScheme>;

/// Receiving Key Type
pub type ReceivingKey<C> = address::ReceivingKey<<C as Configuration>::KeyScheme>;

/// Secret Key Type
pub type SecretKey<C> = <<C as Configuration>::KeyScheme as KeyAgreementScheme>::SecretKey;

/// Public Key Type
pub type PublicKey<C> = <<C as Configuration>::KeyScheme as KeyAgreementScheme>::PublicKey;

/// Trapdoor Type
pub type Trapdoor<C> = <<C as Configuration>::KeyScheme as KeyAgreementScheme>::SharedSecret;

/// UTXO Type
pub type Utxo<C> = <<C as Configuration>::CommitmentScheme as CommitmentScheme>::Output;

/// Void Number Type
pub type VoidNumber<C> = <<C as Configuration>::CommitmentScheme as CommitmentScheme>::Output;

/// Pre-Sender
pub struct PreSender<C>
where
    C: Configuration,
{
    /// Spending Key
    spending_key: SpendingKey<C>,

    /// Ephemeral Public Key
    ephemeral_public_key: PublicKey<C>,

    /// Trapdoor
    trapdoor: Trapdoor<C>,

    /// Asset
    asset: C::Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C> PreSender<C>
where
    C: Configuration,
{
    /// Builds a new [`PreSender`] for `spending_key` to spend `asset` with
    /// `ephemeral_public_key`.
    #[inline]
    pub fn new(
        spending_key: SpendingKey<C>,
        ephemeral_public_key: PublicKey<C>,
        asset: C::Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Self {
        let trapdoor = spending_key.spending_secret(&ephemeral_public_key);
        Self {
            utxo: commitment_scheme.commit_one(&asset, &trapdoor),
            void_number: commitment_scheme.commit_one(&spending_key.spend.secret_key, &trapdoor),
            spending_key,
            ephemeral_public_key,
            asset,
            trapdoor,
        }
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_set` with the intention of
    /// returning a proof later by a call to [`get_proof`](Self::get_proof).
    #[inline]
    pub fn insert_utxo<S>(&self, utxo_set: &mut S) -> bool
    where
        S: Accumulator<Item = Utxo<C>>,
    {
        utxo_set.insert(&self.utxo)
    }

    /// Requests the membership proof of the [`Utxo`] corresponding to `self` from `utxo_set` to
    /// prepare the conversion from `self` into a [`Sender`].
    #[inline]
    pub fn get_proof<S>(&self, utxo_set: &S) -> Option<SenderProof<C, S::Verifier>>
    where
        S: Accumulator<Item = Utxo<C>>,
    {
        Some(SenderProof {
            utxo_membership_proof: utxo_set.prove(&self.utxo)?,
            __: PhantomData,
        })
    }

    /// Converts `self` into a [`Sender`] by attaching `proof` to it.
    ///
    /// # Note
    ///
    /// When using this method, be sure to check that [`SenderProof::can_upgrade`] returns `true`.
    /// Otherwise, using the sender returned here will most likely return an error when posting to
    /// the ledger.
    #[inline]
    pub fn upgrade<V>(self, proof: SenderProof<C, V>) -> Sender<C, V>
    where
        V: Verifier<Item = Utxo<C>> + ?Sized,
    {
        Sender {
            spending_key: self.spending_key,
            ephemeral_public_key: self.ephemeral_public_key,
            trapdoor: self.trapdoor,
            asset: self.asset,
            utxo: self.utxo,
            utxo_membership_proof: proof.utxo_membership_proof,
            void_number: self.void_number,
        }
    }

    /// Tries to convert `self` into a [`Sender`] by getting a proof from `utxo_set`.
    #[inline]
    pub fn try_upgrade<S>(self, utxo_set: &S) -> Option<Sender<C, S::Verifier>>
    where
        S: Accumulator<Item = Utxo<C>>,
    {
        Some(self.get_proof(utxo_set)?.upgrade(self))
    }
}

/// Sender Proof
///
/// This `struct` is created by the [`get_proof`](PreSender::get_proof) method on [`PreSender`].
/// See its documentation for more.
pub struct SenderProof<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>> + ?Sized,
{
    /// UTXO Membership Proof
    utxo_membership_proof: MembershipProof<V>,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, V> SenderProof<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>> + ?Sized,
{
    /// Returns `true` if a [`PreSender`] could be upgraded using `self` given the `utxo_set`.
    #[inline]
    pub fn can_upgrade<S>(&self, utxo_set: &S) -> bool
    where
        S: Accumulator<
            Item = V::Item,
            Checkpoint = V::Checkpoint,
            Witness = V::Witness,
            Verifier = V,
        >,
    {
        self.utxo_membership_proof.matching_checkpoint(utxo_set)
    }

    /// Upgrades the `pre_sender` to a [`Sender`] by attaching `self` to it.
    ///
    /// # Note
    ///
    /// When using this method, be sure to check that [`can_upgrade`](Self::can_upgrade) returns
    /// `true`. Otherwise, using the sender returned here will most likely return an error when
    /// posting to the ledger.
    #[inline]
    pub fn upgrade(self, pre_sender: PreSender<C>) -> Sender<C, V> {
        pre_sender.upgrade(self)
    }
}

/// Sender
pub struct Sender<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>> + ?Sized,
{
    /// Spending Key
    spending_key: SpendingKey<C>,

    /// Ephemeral Public Key
    ephemeral_public_key: PublicKey<C>,

    /// Trapdoor
    trapdoor: Trapdoor<C>,

    /// Asset
    asset: C::Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// UTXO Membership Proof
    utxo_membership_proof: MembershipProof<V>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C, V> Sender<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
{
    /// Reverts `self` back into a [`PreSender`].
    ///
    /// This method should be called if the [`Utxo`] membership proof attached to `self` was deemed
    /// invalid or had expired.
    #[inline]
    pub fn downgrade(self) -> PreSender<C> {
        PreSender {
            spending_key: self.spending_key,
            ephemeral_public_key: self.ephemeral_public_key,
            trapdoor: self.trapdoor,
            asset: self.asset,
            utxo: self.utxo,
            void_number: self.void_number,
        }
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> SenderPost<C, V> {
        SenderPost {
            utxo_checkpoint: self.utxo_membership_proof.into_checkpoint(),
            void_number: self.void_number,
        }
    }
}

/// Sender Ledger
pub trait SenderLedger<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
{
    /// Valid [`VoidNumber`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`VoidNumber`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`is_matching_checkpoint`](Self::is_matching_checkpoint).
    type ValidVoidNumber;

    /// Valid Utxo State Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`S::Checkpoint`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`is_matching_checkpoint`](Self::is_matching_checkpoint).
    ///
    /// [`S::Checkpoint`]: Verifier::Checkpoint
    type ValidUtxoCheckpoint;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`SenderLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks if the ledger already contains the `void_number` in its set of void numbers.
    ///
    /// Existence of such a void number could indicate a possible double-spend.
    fn is_unspent(&self, void_number: VoidNumber<C>) -> Option<Self::ValidVoidNumber>;

    /// Checks if the `checkpoint` matches the current checkpoint of the UTXO set that is stored on
    /// the ledger.
    ///
    /// Failure to match the ledger state means that the sender was constructed under an invalid or
    /// older state of the ledger.
    fn is_matching_checkpoint(
        &self,
        checkpoint: V::Checkpoint,
    ) -> Option<Self::ValidUtxoCheckpoint>;

    /// Posts the `void_number` to the ledger, spending the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `void_number` is not already stored on
    /// the ledger. See [`is_unspent`](Self::is_unspent).
    fn spend(
        &mut self,
        utxo_checkpoint: Self::ValidUtxoCheckpoint,
        void_number: Self::ValidVoidNumber,
        super_key: &Self::SuperPostingKey,
    );
}

/// Sender Post Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SenderPostError {
    /// Asset Spent Error
    ///
    /// The asset has already been spent.
    AssetSpent,

    /// Invalid UTXO Checkpoint Error
    ///
    /// The sender was not constructed under the current state of the UTXO set.
    InvalidUtxoCheckpoint,
}

/// Sender Post
pub struct SenderPost<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
{
    /// UTXO Checkpoint
    utxo_checkpoint: V::Checkpoint,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C, V> SenderPost<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
{
    /// Validates `self` on the sender `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<SenderPostingKey<C, V, L>, SenderPostError>
    where
        L: SenderLedger<C, V>,
    {
        Ok(SenderPostingKey {
            utxo_checkpoint: ledger
                .is_matching_checkpoint(self.utxo_checkpoint)
                .ok_or(SenderPostError::InvalidUtxoCheckpoint)?,
            void_number: ledger
                .is_unspent(self.void_number)
                .ok_or(SenderPostError::AssetSpent)?,
        })
    }
}

impl<C, V> From<Sender<C, V>> for SenderPost<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
{
    #[inline]
    fn from(sender: Sender<C, V>) -> Self {
        sender.into_post()
    }
}

/// Sender Posting Key
pub struct SenderPostingKey<C, V, L>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
    L: SenderLedger<C, V>,
{
    /// UTXO Checkpoint Posting Key
    utxo_checkpoint: L::ValidUtxoCheckpoint,

    /// Void Number Posting Key
    void_number: L::ValidVoidNumber,
}

impl<C, V, L> SenderPostingKey<C, V, L>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
    L: SenderLedger<C, V>,
{
    /// Posts `self` to the sender `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.spend(self.utxo_checkpoint, self.void_number, super_key);
    }
}

/// Receiver
pub struct Receiver<C>
where
    C: Configuration,
{
    /// Receiving Key
    receiving_key: ReceivingKey<C>,

    /// Ephemeral Secret Key
    ephemeral_secret_key: SecretKey<C>,

    /// Trapdoor
    trapdoor: Trapdoor<C>,

    /// Asset
    asset: C::Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,
}

impl<C> Receiver<C>
where
    C: Configuration,
{
    /// Builds a new [`Receiver`] for `receiving_key` to receive `asset` with
    /// `ephemeral_secret_key`.
    #[inline]
    pub fn new(
        receiving_key: ReceivingKey<C>,
        ephemeral_secret_key: SecretKey<C>,
        asset: C::Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Self {
        let trapdoor = receiving_key.spending_secret(&ephemeral_secret_key);
        Self {
            utxo: commitment_scheme.commit_one(&asset, &trapdoor),
            receiving_key,
            trapdoor,
            ephemeral_secret_key,
            asset,
        }
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> ReceiverPost<C>
    where
        C::KeyScheme: HybridPublicKeyEncryptionScheme<Plaintext = C::Asset>,
    {
        ReceiverPost {
            utxo: self.utxo,
            note: self
                .receiving_key
                .encrypt(self.ephemeral_secret_key, self.asset),
        }
    }
}

/// Receiver Ledger
pub trait ReceiverLedger<C>
where
    C: Configuration,
    C::KeyScheme: HybridPublicKeyEncryptionScheme<Plaintext = C::Asset>,
{
    /// Valid [`Utxo`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`Utxo`] which can only be constructed by this
    /// implementation of [`ReceiverLedger`]. This is to prevent that [`register`](Self::register)
    /// is called before [`is_not_registered`](Self::is_not_registered).
    type ValidUtxo;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`ReceiverLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks if the ledger already contains the `utxo` in its set of UTXOs.
    ///
    /// Existence of such a UTXO could indicate a possible double-spend.
    fn is_not_registered(&self, utxo: Utxo<C>) -> Option<Self::ValidUtxo>;

    /// Posts the `utxo` and `encrypted_asset` to the ledger, registering the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `utxo` is not already stored on the
    /// ledger. See [`is_not_registered`](Self::is_not_registered).
    fn register(
        &mut self,
        utxo: Self::ValidUtxo,
        note: EncryptedMessage<C::KeyScheme>,
        super_key: &Self::SuperPostingKey,
    );
}

/// Receiver Post Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReceiverPostError {
    /// Asset Registered Error
    ///
    /// The asset has already been registered with the ledger.
    AssetRegistered,
}

/// Receiver Post
pub struct ReceiverPost<C>
where
    C: Configuration,
    C::KeyScheme: HybridPublicKeyEncryptionScheme<Plaintext = C::Asset>,
{
    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Encrypted Note
    note: EncryptedMessage<C::KeyScheme>,
}

impl<C> ReceiverPost<C>
where
    C: Configuration,
    C::KeyScheme: HybridPublicKeyEncryptionScheme<Plaintext = C::Asset>,
{
    /// Validates `self` on the receiver `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<ReceiverPostingKey<C, L>, ReceiverPostError>
    where
        L: ReceiverLedger<C>,
    {
        Ok(ReceiverPostingKey {
            utxo: ledger
                .is_not_registered(self.utxo)
                .ok_or(ReceiverPostError::AssetRegistered)?,
            note: self.note,
        })
    }
}

impl<C> From<Receiver<C>> for ReceiverPost<C>
where
    C: Configuration,
    C::KeyScheme: HybridPublicKeyEncryptionScheme<Plaintext = C::Asset>,
{
    #[inline]
    fn from(receiver: Receiver<C>) -> ReceiverPost<C> {
        receiver.into_post()
    }
}

/// Receiver Posting Key
pub struct ReceiverPostingKey<C, L>
where
    C: Configuration,
    C::KeyScheme: HybridPublicKeyEncryptionScheme<Plaintext = C::Asset>,
    L: ReceiverLedger<C>,
{
    /// UTXO Posting Key
    utxo: L::ValidUtxo,

    /// Encrypted Note
    note: EncryptedMessage<C::KeyScheme>,
}

impl<C, L> ReceiverPostingKey<C, L>
where
    C: Configuration,
    C::KeyScheme: HybridPublicKeyEncryptionScheme<Plaintext = C::Asset>,
    L: ReceiverLedger<C>,
{
    /// Posts `self` to the receiver `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.register(self.utxo, self.note, super_key);
    }
}

/// Constraint System Gadgets for Identities
pub mod constraint {
    use super::*;
    use crate::asset::{AssetId, AssetValue, AssetVar};
    use manta_crypto::{
        accumulator::constraint::{MembershipProofVar, VerifierVariable},
        constraint::{reflection::HasVariable, ConstraintSystem, Equal, PublicOrSecret},
    };

    impl<C, V> Sender<C, V>
    where
        C: Configuration,
        V: Verifier<Item = Utxo<C>> + ?Sized,
    {
        ///
        #[inline]
        pub fn get_well_formed_asset<CS>(
            self,
            commitment_scheme: &C::CommitmentScheme,
            utxo_set_verifier: &V,
            cs: &mut CS,
        ) -> C::Asset
        where
            CS: ConstraintSystem,
            Trapdoor<C>: Equal<CS>,
            Utxo<C>: Equal<CS>,
            VoidNumber<C>: Equal<CS>,
            V: Verifier<Verification = CS::Bool>,
        {
            cs.assert_eq(
                &self.trapdoor,
                &self
                    .spending_key
                    .spending_secret(&self.ephemeral_public_key),
            );
            cs.assert_eq(
                &self.utxo,
                &commitment_scheme.commit_one(&self.asset, &self.trapdoor),
            );
            cs.assert_eq(
                &self.void_number,
                &commitment_scheme.commit_one(&self.spending_key.spend.secret_key, &self.trapdoor),
            );
            cs.assert(
                self.utxo_membership_proof
                    .verify(&self.utxo, utxo_set_verifier),
            );
            self.asset
        }
    }

    impl<C> Receiver<C>
    where
        C: Configuration,
    {
        ///
        #[inline]
        pub fn get_well_formed_asset<CS>(
            self,
            commitment_scheme: &C::CommitmentScheme,
            cs: &mut CS,
        ) -> C::Asset
        where
            CS: ConstraintSystem,
            Utxo<C>: Equal<CS>,
        {
            cs.assert_eq(
                &self.utxo,
                &commitment_scheme.commit_one(
                    &self.asset,
                    &self
                        .receiving_key
                        .spending_secret(&self.ephemeral_secret_key),
                ),
            );
            self.asset
        }
    }
}
