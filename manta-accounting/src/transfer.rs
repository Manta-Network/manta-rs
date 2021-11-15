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

//! Transfer Protocol

use crate::asset::{Asset, AssetId, AssetValue};
use alloc::vec::Vec;
use core::{marker::PhantomData, ops::Add};
use manta_crypto::{
    accumulator::{Accumulator, MembershipProof, Verifier},
    commitment::{CommitmentScheme, Input as CommitmentInput},
    constraint::{
        reflection::{HasEqual, HasVariable, Var},
        Allocation, Constant, ConstraintSystem, Derived, Equal, ProofSystem, Public,
        PublicOrSecret, Secret, Variable, VariableSource,
    },
    encryption::{self, DecryptedMessage, EncryptedMessage, HybridPublicKeyEncryptionScheme},
    key::KeyAgreementScheme,
    rand::{CryptoRng, Rand, RngCore},
};
use manta_util::create_seal;

/// Returns `true` if the transfer with this shape would have no public participants.
#[inline]
pub const fn has_no_public_participants(
    sources: usize,
    senders: usize,
    receivers: usize,
    sinks: usize,
) -> bool {
    let _ = (senders, receivers);
    sources == 0 && sinks == 0
}

/// Transfer Configuration
pub trait Configuration {
    /// Key Agreement Scheme
    type KeyAgreementScheme: KeyAgreementScheme;

    /// Secret Key Variable
    type SecretKeyVar: Variable<Self::ConstraintSystem, Type = SecretKey<Self>, Mode = Secret>;

    /// Public Key Variable
    type PublicKeyVar: Variable<Self::ConstraintSystem, Type = PublicKey<Self>, Mode = Secret>;

    /// Key Agreement Scheme Variable
    type KeyAgreementSchemeVar: KeyAgreementScheme<SecretKey = Self::SecretKeyVar, PublicKey = Self::PublicKeyVar>
        + Variable<Self::ConstraintSystem, Type = Self::KeyAgreementScheme, Mode = Constant>;

    /// Commitment Scheme Output
    type CommitmentSchemeOutput: PartialEq;

    /// Commitment Scheme Output Variable
    type CommitmentSchemeOutputVar: Variable<Self::ConstraintSystem, Type = Self::CommitmentSchemeOutput, Mode = PublicOrSecret>
        + Equal<Self::ConstraintSystem>;

    /// Commitment Scheme
    type CommitmentScheme: CommitmentScheme<Trapdoor = SharedSecret<Self>, Output = Self::CommitmentSchemeOutput>
        + CommitmentInput<Asset>
        + CommitmentInput<SecretKey<Self>>;

    /// Commitment Scheme Variable
    type CommitmentSchemeVar: CommitmentScheme<Trapdoor = SharedSecretVar<Self>, Output = Self::CommitmentSchemeOutputVar>
        + CommitmentInput<AssetVar<Self>>
        + CommitmentInput<Self::SecretKeyVar>
        + Variable<Self::ConstraintSystem, Type = Self::CommitmentScheme, Mode = Constant>;

    /// UTXO Set Verifier
    type UtxoSetVerifier: Verifier<Item = Utxo<Self>, Verification = bool>;

    /// UTXO Set Verifier Variable
    type UtxoSetVerifierVar: Verifier<
            Item = UtxoVar<Self>,
            Verification = <Self::ConstraintSystem as ConstraintSystem>::Bool,
        > + Variable<Self::ConstraintSystem, Type = Self::UtxoSetVerifier, Mode = Constant>;

    /// Asset Id Variable
    type AssetIdVar: Variable<Self::ConstraintSystem, Type = AssetId, Mode = PublicOrSecret>
        + Equal<Self::ConstraintSystem>;

    /// Asset Value Variable
    type AssetValueVar: Variable<Self::ConstraintSystem, Type = AssetValue, Mode = PublicOrSecret>
        + Equal<Self::ConstraintSystem>
        + Add<Output = Self::AssetValueVar>;

    /// Constraint System Type
    type ConstraintSystem: ConstraintSystem;

    /// Proof System Type
    type ProofSystem: ProofSystem<ConstraintSystem = Self::ConstraintSystem, Verification = bool>;

    /// Note Encryption Scheme Type
    type NoteEncryptionScheme: HybridPublicKeyEncryptionScheme<
        Plaintext = Asset,
        KeyAgreementScheme = Self::KeyAgreementScheme,
    >;
}

///
pub type AssetVar<C> = Asset<<C as Configuration>::AssetIdVar, <C as Configuration>::AssetValueVar>;

///
pub type SecretKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;

///
pub type PublicKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;

///
pub type SharedSecret<C> =
    <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret;

///
pub type SharedSecretVar<C> =
    <<C as Configuration>::KeyAgreementSchemeVar as KeyAgreementScheme>::SharedSecret;

///
pub type Trapdoor<C> = <<C as Configuration>::CommitmentScheme as CommitmentScheme>::Trapdoor;

///
pub type TrapdoorVar<C> = <<C as Configuration>::CommitmentSchemeVar as CommitmentScheme>::Trapdoor;

///
pub type CommitmentSchemeOutput<C> = <C as Configuration>::CommitmentSchemeOutput;

///
pub type CommitmentSchemeOutputVar<C> = <C as Configuration>::CommitmentSchemeOutputVar;

///
pub type Utxo<C> = CommitmentSchemeOutput<C>;

///
pub type UtxoVar<C> = CommitmentSchemeOutputVar<C>;

///
pub type UtxoAccumulatorOutput<C> = <<C as Configuration>::UtxoSetVerifier as Verifier>::Output;

///
pub type UtxoAccumulatorOutputVar<C> =
    <<C as Configuration>::UtxoSetVerifierVar as Verifier>::Output;

///
pub type UtxoMembershipProof<C> = MembershipProof<<C as Configuration>::UtxoSetVerifier>;

///
pub type UtxoMembershipProofVar<C> = MembershipProof<<C as Configuration>::UtxoSetVerifierVar>;

///
pub type VoidNumber<C> = CommitmentSchemeOutput<C>;

///
pub type VoidNumberVar<C> = CommitmentSchemeOutputVar<C>;

///
pub type EncryptedNote<C> = EncryptedMessage<<C as Configuration>::NoteEncryptionScheme>;

///
pub type Note<C> = DecryptedMessage<<C as Configuration>::NoteEncryptionScheme>;

/// Transfer Proof System Type
type ProofSystemType<C> = <C as Configuration>::ProofSystem;

/// Transfer Proof System Error Type
pub type ProofSystemError<C> = <ProofSystemType<C> as ProofSystem>::Error;

/// Transfer Proving Context Type
pub type ProvingContext<C> = <ProofSystemType<C> as ProofSystem>::ProvingContext;

/// Transfer Verifying Context Type
pub type VerifyingContext<C> = <ProofSystemType<C> as ProofSystem>::VerifyingContext;

/// Transfer Validity Proof Type
pub type Proof<C> = <ProofSystemType<C> as ProofSystem>::Proof;

/// Spending Key
pub struct SpendingKey<C>
where
    C: Configuration,
{
    /// Spend Part of the Spending Key
    spend: SecretKey<C>,

    /// View Part of the Spending Key
    view: SecretKey<C>,
}

impl<C> SpendingKey<C>
where
    C: Configuration,
{
    /// Builds a new [`SpendingKey`] from `spend` and `view`.
    #[inline]
    pub fn new(spend: SecretKey<C>, view: SecretKey<C>) -> Self {
        Self { spend, view }
    }

    /// Derives the receiving key for `self`.
    #[inline]
    pub fn derive(&self) -> ReceivingKey<C> {
        ReceivingKey {
            spend: C::KeyAgreementScheme::derive(&self.spend),
            view: C::KeyAgreementScheme::derive(&self.view),
        }
    }

    /// Tries to decrypt `encrypted_note` with the viewing key associated to `self`.
    #[inline]
    pub fn decrypt(&self, encrypted_note: EncryptedNote<C>) -> Result<Note<C>, EncryptedNote<C>> {
        encrypted_note.decrypt(&self.view)
    }

    /// Validates the `utxo` against `self` and the given `ephemeral_key` and `asset`.
    #[inline]
    pub fn validate_utxo(
        &self,
        ephemeral_key: &PublicKey<C>,
        asset: &Asset,
        utxo: &Utxo<C>,
        commitment_scheme: &C::CommitmentScheme,
    ) -> bool {
        &commitment_scheme.commit_one(
            asset,
            &C::KeyAgreementScheme::agree(&self.spend, ephemeral_key),
        ) == utxo
    }

    /// Prepares `self` for spending `asset` with the given `ephemeral_key`.
    #[inline]
    pub fn sender(
        &self,
        ephemeral_key: PublicKey<C>,
        asset: Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> PreSender<C>
    where
        SecretKey<C>: Clone,
    {
        PreSender::new(self.spend.clone(), ephemeral_key, asset, commitment_scheme)
    }

    /// Prepares `self` for receiving `asset`.
    #[inline]
    pub fn receiver(&self, asset: Asset) -> PreReceiver<C> {
        self.derive().into_receiver(asset)
    }
}

/// Receiving Key
pub struct ReceivingKey<C>
where
    C: Configuration,
{
    /// Spend Part of the Receiving Key
    pub spend: PublicKey<C>,

    /// View Part of the Receiving Key
    pub view: PublicKey<C>,
}

impl<C> ReceivingKey<C>
where
    C: Configuration,
{
    /// Prepares `self` for receiving `asset`.
    #[inline]
    pub fn into_receiver(self, asset: Asset) -> PreReceiver<C> {
        PreReceiver::new(self.spend, self.view, asset)
    }
}

/// Pre-Sender
pub struct PreSender<C>
where
    C: Configuration,
{
    /// Secret Spend Key
    spend: SecretKey<C>,

    /// Ephemeral Public Spend Key
    ephemeral_key: PublicKey<C>,

    /// Asset
    asset: Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C> PreSender<C>
where
    C: Configuration,
{
    /// Builds a new [`PreSender`] for `spend` to spend `asset` with `ephemeral_key`.
    #[inline]
    pub fn new(
        spend: SecretKey<C>,
        ephemeral_key: PublicKey<C>,
        asset: Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Self {
        let trapdoor = C::KeyAgreementScheme::agree(&spend, &ephemeral_key);
        Self {
            utxo: commitment_scheme.commit_one(&asset, &trapdoor),
            void_number: commitment_scheme.commit_one(&spend, &trapdoor),
            spend,
            ephemeral_key,
            asset,
        }
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_set` with the intention of
    /// returning a proof later by a call to [`get_proof`](Self::get_proof).
    #[inline]
    pub fn insert_utxo<S>(&self, utxo_set: &mut S) -> bool
    where
        S: Accumulator<Item = Utxo<C>, Verifier = C::UtxoSetVerifier>,
    {
        utxo_set.insert(&self.utxo)
    }

    /// Requests the membership proof of the [`Utxo`] corresponding to `self` from `utxo_set` to
    /// prepare the conversion from `self` into a [`Sender`].
    #[inline]
    pub fn get_proof<S>(&self, utxo_set: &S) -> Option<SenderProof<C>>
    where
        S: Accumulator<Item = Utxo<C>, Verifier = C::UtxoSetVerifier>,
    {
        Some(SenderProof {
            utxo_membership_proof: utxo_set.prove(&self.utxo)?,
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
    pub fn upgrade(self, proof: SenderProof<C>) -> Sender<C> {
        Sender {
            spend: self.spend,
            ephemeral_key: self.ephemeral_key,
            asset: self.asset,
            utxo: self.utxo,
            utxo_membership_proof: proof.utxo_membership_proof,
            void_number: self.void_number,
        }
    }

    /// Tries to convert `self` into a [`Sender`] by getting a proof from `utxo_set`.
    #[inline]
    pub fn try_upgrade<S>(self, utxo_set: &S) -> Option<Sender<C>>
    where
        S: Accumulator<Item = Utxo<C>, Verifier = C::UtxoSetVerifier>,
    {
        Some(self.get_proof(utxo_set)?.upgrade(self))
    }
}

/// Sender Proof
///
/// This `struct` is created by the [`get_proof`](PreSender::get_proof) method on [`PreSender`].
/// See its documentation for more.
pub struct SenderProof<C>
where
    C: Configuration,
{
    /// UTXO Membership Proof
    utxo_membership_proof: UtxoMembershipProof<C>,
}

impl<C> SenderProof<C>
where
    C: Configuration,
{
    /// Returns `true` if a [`PreSender`] could be upgraded using `self` given the `utxo_set`.
    #[inline]
    pub fn can_upgrade<S>(&self, utxo_set: &S) -> bool
    where
        S: Accumulator<Item = Utxo<C>, Verifier = C::UtxoSetVerifier>,
    {
        self.utxo_membership_proof.matching_output(utxo_set)
    }

    /// Upgrades the `pre_sender` to a [`Sender`] by attaching `self` to it.
    ///
    /// # Note
    ///
    /// When using this method, be sure to check that [`can_upgrade`](Self::can_upgrade) returns
    /// `true`. Otherwise, using the sender returned here will most likely return an error when
    /// posting to the ledger.
    #[inline]
    pub fn upgrade(self, pre_sender: PreSender<C>) -> Sender<C> {
        pre_sender.upgrade(self)
    }
}

/// Sender
pub struct Sender<C>
where
    C: Configuration,
{
    /// Secret Spend Key
    spend: SecretKey<C>,

    /// Ephemeral Public Spend Key
    ephemeral_key: PublicKey<C>,

    /// Asset
    asset: Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// UTXO Membership Proof
    utxo_membership_proof: UtxoMembershipProof<C>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C> Sender<C>
where
    C: Configuration,
{
    /// Reverts `self` back into a [`PreSender`].
    ///
    /// This method should be called if the [`Utxo`] membership proof attached to `self` was deemed
    /// invalid or had expired.
    #[inline]
    pub fn downgrade(self) -> PreSender<C> {
        PreSender {
            spend: self.spend,
            ephemeral_key: self.ephemeral_key,
            asset: self.asset,
            utxo: self.utxo,
            void_number: self.void_number,
        }
    }

    /* TODO:
    /// Returns the asset for `self`, checking if `self` is well-formed in the given constraint
    /// system `cs`.
    #[inline]
    pub fn get_well_formed_asset<CS>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &V,
        cs: &mut CS,
    ) -> C::Asset
    where
        CS: ConstraintSystem,
        Commitment<C>: Equal<CS>,
        V: Verifier<Verification = CS::Bool>,
    {
        let trapdoor = C::into_trapdoor(C::KeyAgreementScheme::agree(
            &self.spend,
            &self.ephemeral_key,
        ));
        cs.assert(self.utxo_membership_proof.verify(
            &commitment_scheme.commit_one(&self.asset, &trapdoor),
            utxo_set_verifier,
        ));
        cs.assert_eq(
            &self.void_number,
            &commitment_scheme.commit_one(&self.spend, &trapdoor),
        );
        self.asset
    }
    */

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> SenderPost<C> {
        SenderPost {
            utxo_accumulator_output: self.utxo_membership_proof.into_output(),
            void_number: self.void_number,
        }
    }
}

/// Sender Ledger
pub trait SenderLedger<C>
where
    C: Configuration,
{
    /// Valid [`VoidNumber`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`VoidNumber`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`has_matching_utxo_accumulator_output`](Self::has_matching_utxo_accumulator_output).
    type ValidVoidNumber;

    /// Valid UTXO Accumulator Output Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`S::Output`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`has_matching_utxo_accumulator_output`](Self::has_matching_utxo_accumulator_output).
    ///
    /// [`S::Output`]: Verifier::Output
    type ValidUtxoAccumulatorOutput;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`SenderLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks if the ledger already contains the `void_number` in its set of void numbers.
    ///
    /// Existence of such a void number could indicate a possible double-spend.
    fn is_unspent(&self, void_number: VoidNumber<C>) -> Option<Self::ValidVoidNumber>;

    /// Checks if `output` matches the current accumulated value of the UTXO set that is stored on
    /// the ledger.
    ///
    /// Failure to match the ledger state means that the sender was constructed under an invalid or
    /// older state of the ledger.
    fn has_matching_utxo_accumulator_output(
        &self,
        output: UtxoAccumulatorOutput<C>,
    ) -> Option<Self::ValidUtxoAccumulatorOutput>;

    /// Posts the `void_number` to the ledger, spending the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `void_number` is not already stored on
    /// the ledger. See [`is_unspent`](Self::is_unspent).
    fn spend(
        &mut self,
        utxo_accumulator_output: Self::ValidUtxoAccumulatorOutput,
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

    /// Invalid UTXO Accumulator Error
    ///
    /// The sender was not constructed under the current state of the UTXO set.
    InvalidUtxoAccumulator,
}

/// Sender Post
pub struct SenderPost<C>
where
    C: Configuration,
{
    /// UTXO Accumulator Output
    utxo_accumulator_output: UtxoAccumulatorOutput<C>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C> SenderPost<C>
where
    C: Configuration,
{
    /// Validates `self` on the sender `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<SenderPostingKey<C, L>, SenderPostError>
    where
        L: SenderLedger<C>,
    {
        Ok(SenderPostingKey {
            utxo_accumulator_output: ledger
                .has_matching_utxo_accumulator_output(self.utxo_accumulator_output)
                .ok_or(SenderPostError::InvalidUtxoAccumulator)?,
            void_number: ledger
                .is_unspent(self.void_number)
                .ok_or(SenderPostError::AssetSpent)?,
        })
    }
}

/// Sender Posting Key
pub struct SenderPostingKey<C, L>
where
    C: Configuration,
    L: SenderLedger<C>,
{
    /// UTXO Accumulator Output Posting Key
    utxo_accumulator_output: L::ValidUtxoAccumulatorOutput,

    /// Void Number Posting Key
    void_number: L::ValidVoidNumber,
}

impl<C, L> SenderPostingKey<C, L>
where
    C: Configuration,
    L: SenderLedger<C>,
{
    /// Posts `self` to the sender `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.spend(self.utxo_accumulator_output, self.void_number, super_key);
    }
}

/// Pre-Receiver
pub struct PreReceiver<C>
where
    C: Configuration,
{
    /// Public Spend Key
    spend: PublicKey<C>,

    /// Public View Key
    view: PublicKey<C>,

    /// Asset
    asset: Asset,
}

impl<C> PreReceiver<C>
where
    C: Configuration,
{
    /// Builds a new [`PreReceiver`] for `spend` to receive `asset`, encrypted with `view`.
    #[inline]
    pub fn new(spend: PublicKey<C>, view: PublicKey<C>, asset: Asset) -> Self {
        Self { spend, view, asset }
    }

    /// Upgrades `self` into a [`Receiver`] with the designated `ephemeral_key`.
    #[inline]
    pub fn upgrade(
        self,
        ephemeral_key: SecretKey<C>,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Receiver<C> {
        Receiver::new(
            self.spend,
            self.view,
            ephemeral_key,
            self.asset,
            commitment_scheme,
        )
    }
}

/// Receiver
pub struct Receiver<C>
where
    C: Configuration,
{
    /// Public Spend Key
    spend: PublicKey<C>,

    /// Public View Key
    view: PublicKey<C>,

    /// Ephemeral Secret Spend Key
    ephemeral_key: SecretKey<C>,

    /// Asset
    asset: Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,
}

impl<C> Receiver<C>
where
    C: Configuration,
{
    /// Builds a new [`Receiver`] for `spend` to receive `asset` with `ephemeral_key`.
    #[inline]
    pub fn new(
        spend: PublicKey<C>,
        view: PublicKey<C>,
        ephemeral_key: SecretKey<C>,
        asset: Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Self {
        Self {
            utxo: commitment_scheme.commit_one(
                &asset,
                &C::KeyAgreementScheme::agree(&ephemeral_key, &spend),
            ),
            spend,
            view,
            ephemeral_key,
            asset,
        }
    }

    /* TODO:
    /// Returns the asset for `self`, checking if `self` is well-formed in the given constraint
    /// system `cs`.
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
            &Self::generate_utxo(
                &self.spending_key,
                &self.ephemeral_key,
                &self.asset,
                commitment_scheme,
            ),
        );
        self.asset
    }
    */

    /// Converts `self` into its [`PreReceiver`], dropping the ephemeral key.
    #[inline]
    pub fn downgrade(self) -> PreReceiver<C> {
        PreReceiver::new(self.spend, self.view, self.asset)
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> ReceiverPost<C> {
        ReceiverPost {
            utxo: self.utxo,
            note: EncryptedMessage::new(&self.view, self.ephemeral_key, self.asset),
        }
    }
}

/// Receiver Ledger
pub trait ReceiverLedger<C>
where
    C: Configuration,
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
        note: EncryptedNote<C>,
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
{
    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Encrypted Note
    note: EncryptedNote<C>,
}

impl<C> ReceiverPost<C>
where
    C: Configuration,
{
    /// Returns the ephemeral key associated to `self`.
    #[inline]
    pub fn ephemeral_key(&self) -> &PublicKey<C> {
        self.note.ephemeral_public_key()
    }

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

/// Receiver Posting Key
pub struct ReceiverPostingKey<C, L>
where
    C: Configuration,
    L: ReceiverLedger<C>,
{
    /// UTXO Posting Key
    utxo: L::ValidUtxo,

    /// Encrypted Note
    note: EncryptedNote<C>,
}

impl<C, L> ReceiverPostingKey<C, L>
where
    C: Configuration,
    L: ReceiverLedger<C>,
{
    /// Posts `self` to the receiver `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.register(self.utxo, self.note, super_key);
    }
}

/// Transfer
pub struct Transfer<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    C: Configuration,
{
    /// Asset Id
    asset_id: Option<AssetId>,

    /// Sources
    sources: [AssetValue; SOURCES],

    /// Senders
    senders: [PreSender<C>; SENDERS],

    /// Receivers
    receivers: [PreReceiver<C>; RECEIVERS],

    /// Sinks
    sinks: [AssetValue; SINKS],
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Builds a new [`Transfer`].
    #[inline]
    fn new(
        asset_id: Option<AssetId>,
        sources: [AssetValue; SOURCES],
        senders: [PreSender<C>; SENDERS],
        receivers: [PreReceiver<C>; RECEIVERS],
        sinks: [AssetValue; SINKS],
    ) -> Self {
        Self::check_shape(asset_id.is_some());
        Self::new_unchecked(asset_id, sources, senders, receivers, sinks)
    }

    /// Checks that the [`Transfer`] has a valid shape.
    #[inline]
    fn check_shape(has_visible_asset_id: bool) {
        Self::has_nonempty_input_shape();
        Self::has_nonempty_output_shape();
        Self::has_visible_asset_id_when_required(has_visible_asset_id);
    }

    /// Checks that the input side of the transfer is not empty.
    #[inline]
    fn has_nonempty_input_shape() {
        assert_ne!(
            SOURCES + SENDERS,
            0,
            "Not enough participants on the input side."
        );
    }

    /// Checks that the output side of the transfer is not empty.
    #[inline]
    fn has_nonempty_output_shape() {
        assert_ne!(
            RECEIVERS + SINKS,
            0,
            "Not enough participants on the output side."
        );
    }

    /// Checks that the given `asset_id` for [`Transfer`] building is visible exactly when required.
    #[inline]
    fn has_visible_asset_id_when_required(has_visible_asset_id: bool) {
        if SOURCES > 0 || SINKS > 0 {
            assert!(
                has_visible_asset_id,
                "Missing public asset id when required."
            );
        } else {
            assert!(
                !has_visible_asset_id,
                "Given public asset id when not required."
            );
        }
    }

    /// Builds a new [`Transfer`] without checking the number of participants on the input and
    /// output sides.
    #[inline]
    fn new_unchecked(
        asset_id: Option<AssetId>,
        sources: [AssetValue; SOURCES],
        senders: [PreSender<C>; SENDERS],
        receivers: [PreReceiver<C>; RECEIVERS],
        sinks: [AssetValue; SINKS],
    ) -> Self {
        Self {
            asset_id,
            sources,
            senders,
            receivers,
            sinks,
        }
    }

    /// Generates the constraint system for an unknown transfer.
    #[inline]
    fn unknown_constraints(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
    ) -> C::ConstraintSystem {
        let mut cs = C::ProofSystem::for_unknown();
        TransferVar::<C, SOURCES, SENDERS, RECEIVERS, SINKS>::new_unknown(&mut cs, Derived)
            .build_validity_constraints(
                &commitment_scheme.as_known(&mut cs, Public),
                &utxo_set_verifier.as_known(&mut cs, Public),
                &mut cs,
            );
        cs
    }

    /// Generates a proving and verifying context for this transfer shape.
    #[inline]
    pub fn generate_context<R>(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        rng: &mut R,
    ) -> Result<(ProvingContext<C>, VerifyingContext<C>), ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::unknown_constraints(commitment_scheme, utxo_set_verifier)
            .generate_context::<C::ProofSystem, _>(rng)
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post<S, R>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set: &S,
        ledger_accumulator_output: UtxoAccumulatorOutput<C>,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        S: Accumulator<Item = Utxo<C>, Verifier = C::UtxoSetVerifier>,
        R: CryptoRng + RngCore + ?Sized,
    {
        /* TODO:
        if !utxo_set.matching_output(&ledger_accumulator_output) {
            todo!("ERROR")
        }

        let senders = IntoIterator::into_iter(self.senders)
            .map(move |s| s.try_upgrade(utxo_set))
            .collect::<Option<Vec<_>>>()
            .expect("TODO: deal with error.");

        let fair_trapdoor = rng.gen();
        let mut fair = commitment_scheme.start().update(&ledger_accumulator_output);
        for s in &senders {
            fair.update(&s.spend);
        }
        fair = fair.commit(&fair_trapdoor);

        let receivers = IntoIterator::into_iter(self.receivers)
            .enumerate()
            .map(move |(i, r)| {
                let ephemeral_key = commitment_scheme
                    .start()
                    .update(&(i as u8))
                    .update(&r.spend)
                    .commit(fair);
                r.upgrade(ephemeral_key, commitment_scheme)
            })
            .collect::<Vec<_>>();
        */

        /* TODO:
        Ok(TransferPost {
            validity_proof: self.is_valid(commitment_scheme, utxo_set_verifier, context, rng)?,
            asset_id: self.asset_id,
            sources: self.sources.into(),
            sender_posts: IntoIterator::into_iter(self.senders)
                .map(Sender::into_post)
                .collect(),
            receiver_posts: IntoIterator::into_iter(self.receivers)
                .map(FullReceiver::into_post)
                .collect(),
            sinks: self.sinks.into(),
        })
        */
        todo!()
    }
}

/// Transfer Variable
pub struct TransferVar<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    C: Configuration,
{
    ///
    asset_id: Option<C::AssetIdVar>,

    ///
    sources: [C::AssetValueVar; SOURCES],

    ///
    // TODO: senders: [SenderVar<C>; SENDERS],

    ///
    // TODO: receivers: [ReceiverVar<C>; RECEIVERS],

    ///
    sinks: [C::AssetValueVar; SINKS],

    ///
    ledger_accumulator_output: UtxoAccumulatorOutputVar<C>,

    ///
    fair_trapdoor: TrapdoorVar<C>,

    ///
    fair: CommitmentSchemeOutputVar<C>,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    ///
    #[inline]
    fn build_validity_constraints(
        self,
        commitment_scheme: &C::CommitmentSchemeVar,
        utxo_set_verifier: &C::UtxoSetVerifierVar,
        cs: &mut C::ConstraintSystem,
    ) {
        let mut secret_asset_ids = Vec::with_capacity(SENDERS + RECEIVERS);

        /* TODO:
        let input_sum = self
            .senders
            .into_iter()
            .map(|s| {
                let asset = s.get_well_formed_asset(&commitment_scheme, &utxo_set_verifier, cs);
                secret_asset_ids.push(asset.id);
                asset.value
            })
            .chain(self.sources)
            .reduce(Add::add)
            .unwrap();

        let output_sum = self
            .receivers
            .into_iter()
            .map(|r| {
                let asset = r.get_well_formed_asset(&commitment_scheme, cs);
                secret_asset_ids.push(asset.id);
                asset.value
            })
            .chain(self.sinks)
            .reduce(Add::add)
            .unwrap();

        cs.assert_eq(&input_sum, &output_sum);
        */

        match self.asset_id {
            Some(asset_id) => cs.assert_all_eq_to_base(&asset_id, secret_asset_ids.iter()),
            _ => cs.assert_all_eq(secret_asset_ids.iter()),
        }
    }
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Variable<C::ConstraintSystem> for TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    type Type = Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut C::ConstraintSystem, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        /* TODO:
        match allocation {
            Allocation::Known(this, mode) => Self {
                sources: this
                    .sources
                    .iter()
                    .map(|source| source.as_known(cs, Public))
                    .collect(),
                senders: this
                    .senders
                    .iter()
                    .map(|sender| {
                        //
                        todo!()
                    })
                    .collect(),
                receivers: this
                    .receivers
                    .iter()
                    .map(|receiver| {
                        //
                        todo!()
                    })
                    .collect(),
                sinks: this
                    .sinks
                    .iter()
                    .map(|sink| sink.as_known(cs, Public))
                    .collect(),
            },
            Allocation::Unknown(mode) => Self {
                sources: (0..SOURCES)
                    .into_iter()
                    .map(|_| AssetValueVar::<C>::new_unknown(cs, Public))
                    .collect(),
                senders: (0..SENDERS)
                    .into_iter()
                    .map(|_| {
                        //
                        todo!()
                    })
                    .collect(),
                receivers: (0..RECEIVERS)
                    .into_iter()
                    .map(|_| {
                        //
                        todo!()
                    })
                    .collect(),
                sinks: (0..SINKS)
                    .into_iter()
                    .map(|_| AssetValueVar::<C>::new_unknown(cs, Public))
                    .collect(),
            },
        }
        */
        todo!()
    }
}

/*
impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Generates the unknown variables for the transfer validity proof.
    #[inline]
    fn unknown_variables(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        cs: &mut C::ConstraintSystem,
    ) -> (
        Option<C::AssetIdVar>,
        // TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        C::CommitmentSchemeVar,
        C::UtxoSetVerifierVar,
    ) {
        let base_asset_id = if has_no_public_participants(SOURCES, SENDERS, RECEIVERS, SINKS) {
            None
        } else {
            Some(C::AssetIdVar::new_unknown(cs, Public))
        };
        (
            base_asset_id,
            // TransferParticipantsVar::new_unknown(cs, Derived),
            commitment_scheme.as_known(cs, Public),
            utxo_set_verifier.as_known(cs, Public),
        )
    }

    /// Generates the known variables for the transfer validity proof.
    #[inline]
    fn known_variables(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        cs: &mut C::ConstraintSystem,
    ) -> (
        Option<AssetIdVar<C>>,
        TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        CommitmentSchemeVar<C>,
        UtxoSetVerifierVar<C>,
    ) {
        /* TODO:
        (
            self.public.asset_id.map(|id| id.as_known(cs, Public)),
            TransferParticipantsVar::new_known(cs, self, Derived),
            commitment_scheme.as_known(cs, Public),
            utxo_set_verifier.as_known(cs, Public),
        )
        */
        todo!()
    }
}
*/

/// Transfer Post
pub struct TransferPost<C>
where
    C: Configuration,
{
    /// Asset Id
    asset_id: Option<AssetId>,

    /// Sources
    sources: Vec<AssetValue>,

    /// Sender Posts
    sender_posts: Vec<SenderPost<C>>,

    /// Receiver Posts
    receiver_posts: Vec<ReceiverPost<C>>,

    /// Sinks
    sinks: Vec<AssetValue>,

    /// Ledger Accumulator Output
    ledger_accumulator_output: UtxoAccumulatorOutput<C>,

    /// Validity Proof
    validity_proof: Proof<C>,
}

impl<C> TransferPost<C>
where
    C: Configuration,
{
    /* TODO:
    /// Returns the ephemeral keys associated to the receiver posts of `self`.
    #[inline]
    pub fn receiver_ephemeral_keys(&self) -> Vec<&PublicKey<C>> {
        self.receiver_posts
            .iter()
            .map(ReceiverPost::ephemeral_key)
            .collect()
    }
    */
}

create_seal! {}

/// Transfer Shapes
///
/// This trait identifies a transfer shape, i.e. the number and type of participants on the input
/// and output sides of the transaction. This trait is sealed and can only be used with the
/// [existing canonical implementations](canonical).
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
    use manta_util::seal;

    /// Implements [`Shape`] for a given shape type.
    macro_rules! impl_shape {
        ($shape:tt, $sources:expr, $senders:expr, $receivers:expr, $sinks:expr) => {
            seal!($shape);
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

    /// Mint Transaction Shape
    ///
    /// ```text
    /// <1, 0, 1, 0>
    /// ```
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct MintShape;

    impl_shape!(MintShape, 1, 0, 1, 0);

    /// Mint Transaction
    pub type Mint<C> = transfer_alias!(C, MintShape);

    impl<C> Mint<C>
    where
        C: Configuration,
    {
        /// Builds a [`Mint`] from `asset` and `receiver`.
        #[inline]
        pub fn build(asset: Asset, receiver: PreReceiver<C>) -> Self {
            Self::new(
                Some(asset.id),
                [asset.value],
                Default::default(),
                [receiver],
                Default::default(),
            )
        }
    }

    /// Private Transfer Transaction Shape
    ///
    /// ```text
    /// <0, 2, 2, 0>
    /// ```
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct PrivateTransferShape;

    impl_shape!(PrivateTransferShape, 0, 2, 2, 0);

    /// Private Transfer Transaction
    pub type PrivateTransfer<C> = transfer_alias!(C, PrivateTransferShape);

    impl<C> PrivateTransfer<C>
    where
        C: Configuration,
    {
        /// Builds a [`PrivateTransfer`] from `senders` and `receivers`.
        #[inline]
        pub fn build(
            senders: [PreSender<C>; PrivateTransferShape::SENDERS],
            receivers: [PreReceiver<C>; PrivateTransferShape::RECEIVERS],
        ) -> Self {
            Self::new(
                Default::default(),
                Default::default(),
                senders,
                receivers,
                Default::default(),
            )
        }
    }

    /// Reclaim Transaction Shape
    ///
    /// ```text
    /// <0, 2, 1, 1>
    /// ```
    ///
    /// The [`ReclaimShape`] is defined in terms of the [`PrivateTransferShape`]. It is defined to
    /// have the same number of senders and one secret receiver turned into a public sink.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct ReclaimShape;

    impl_shape!(
        ReclaimShape,
        0,
        PrivateTransferShape::SENDERS,
        PrivateTransferShape::RECEIVERS - 1,
        1
    );

    /// Reclaim Transaction
    pub type Reclaim<C> = transfer_alias!(C, ReclaimShape);

    impl<C> Reclaim<C>
    where
        C: Configuration,
    {
        /// Builds a [`Reclaim`] from `senders`, `receivers`, and `reclaim`.
        #[inline]
        pub fn build(
            senders: [PreSender<C>; ReclaimShape::SENDERS],
            receivers: [PreReceiver<C>; ReclaimShape::RECEIVERS],
            reclaim: Asset,
        ) -> Self {
            Self::new(
                Some(reclaim.id),
                Default::default(),
                senders,
                receivers,
                [reclaim.value],
            )
        }
    }

    /// Canonical Transaction Type
    pub enum Transaction<C>
    where
        C: Configuration,
    {
        /// Mint Private Asset
        Mint(Asset),

        /// Private Transfer Asset to Receiver
        PrivateTransfer(Asset, ReceivingKey<C>),

        /// Reclaim Private Asset
        Reclaim(Asset),
    }

    impl<C> Transaction<C>
    where
        C: Configuration,
    {
        /// Checks that `self` can be executed for a given `balance` state, returning the
        /// transaction kind if successful, and returning the asset back if the balance was
        /// insufficient.
        #[inline]
        pub fn check<F>(&self, balance: F) -> Result<TransactionKind, Asset>
        where
            F: FnOnce(Asset) -> bool,
        {
            match self {
                Self::Mint(asset) => Ok(TransactionKind::Deposit(*asset)),
                Self::PrivateTransfer(asset, _) | Self::Reclaim(asset) => {
                    if balance(*asset) {
                        Ok(TransactionKind::Withdraw(*asset))
                    } else {
                        Err(*asset)
                    }
                }
            }
        }
    }

    /// Transaction Kind
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub enum TransactionKind {
        /// Deposit Transaction
        ///
        /// A transaction of this kind will result in a deposit of `asset`.
        Deposit(Asset),

        /// Withdraw Transaction
        ///
        /// A transaction of this kind will result in a withdraw of `asset`.
        Withdraw(Asset),
    }
}
