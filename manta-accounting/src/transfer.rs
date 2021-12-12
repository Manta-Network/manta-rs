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
use core::ops::Add;
use manta_crypto::{
    accumulator::{self, Accumulator, MembershipProof, Verifier},
    commitment::{self, CommitmentScheme, Input as CommitmentInput},
    constraint::{
        Allocation, Constant, ConstraintSystem, Derived, Equal, Input as ProofSystemInput,
        ProofSystem, Public, PublicOrSecret, Secret, Variable, VariableSource,
    },
    encryption::{DecryptedMessage, EncryptedMessage, HybridPublicKeyEncryptionScheme},
    key::{self, KeyAgreementScheme, KeyDerivationFunction},
    rand::{CryptoRng, Rand, RngCore, Sample},
};
use manta_util::{create_seal, from_variant_impl};

/// Returns `true` if the transfer with this shape would have public participants.
#[inline]
pub const fn has_public_participants(
    sources: usize,
    senders: usize,
    receivers: usize,
    sinks: usize,
) -> bool {
    let _ = (senders, receivers);
    sources > 0 || sinks > 0
}

/// Generates a commitment trapdoor from a key agreement with `secret_key` and `public_key`.
#[inline]
fn generate_trapdoor<KA, F>(secret_key: &KA::SecretKey, public_key: &KA::PublicKey) -> F::Output
where
    KA: KeyAgreementScheme,
    F: KeyDerivationFunction<KA::SharedSecret>,
{
    F::derive(KA::agree(secret_key, public_key))
}

/// Generates a UTXO, commiting `asset` with the given `trapdoor`.
#[inline]
fn generate_utxo<C, I, V>(
    parameters: &C::Parameters,
    trapdoor: &C::Trapdoor,
    asset: &Asset<I, V>,
) -> C::Output
where
    C: CommitmentScheme,
    C::Input: Default + CommitmentInput<I> + CommitmentInput<V>,
{
    C::start(parameters, trapdoor)
        .update(&asset.id)
        .update(&asset.value)
        .commit()
}

///
#[inline]
fn generate_full_utxo<KA, F, C, I, V>(
    parameters: &C::Parameters,
    secret_key: &KA::SecretKey,
    public_key: &KA::PublicKey,
    asset: &Asset<I, V>,
) -> C::Output
where
    KA: KeyAgreementScheme,
    F: KeyDerivationFunction<KA::SharedSecret, Output = C::Trapdoor>,
    C: CommitmentScheme,
    C::Input: Default + CommitmentInput<I> + CommitmentInput<V>,
{
    generate_utxo::<C, I, V>(
        parameters,
        &generate_trapdoor::<KA, F>(secret_key, public_key),
        asset,
    )
}

/// Generates a void number, commiting `secret_key` with the given `trapdoor`.
#[inline]
fn generate_void_number<C, SK>(
    parameters: &C::Parameters,
    trapdoor: &C::Trapdoor,
    secret_key: &SK,
) -> C::Output
where
    C: CommitmentScheme,
    C::Input: Default + CommitmentInput<SK>,
{
    C::start(parameters, trapdoor).update(secret_key).commit()
}

/// Generates an ephemeral secret key, commiting to the `spend` key at the given `index` with the
/// current `ledger_checkpoint`.
#[inline]
fn generate_ephemeral_secret_key<C, L, B, PK>(
    parameters: &C::Parameters,
    trapdoor: &C::Trapdoor,
    ledger_checkpoint: &L,
    index: &B,
    spend: &PK,
) -> C::Output
where
    C: CommitmentScheme,
    C::Input: Default + CommitmentInput<L> + CommitmentInput<B> + CommitmentInput<PK>,
{
    C::start(parameters, trapdoor)
        .update(ledger_checkpoint)
        .update(index)
        .update(spend)
        .commit()
}

/// Transfer Configuration
pub trait Configuration {
    /// Secret Key
    type SecretKey: Clone;

    /// Key Agreement Scheme
    type KeyAgreementScheme: KeyAgreementScheme<SecretKey = Self::SecretKey>;

    /// Trapdoor Derivation Function
    type TrapdoorDerivationFunction: KeyDerivationFunction<
        SharedSecret<Self>,
        Output = Trapdoor<Self>,
    >;

    /// Ephemeral Key Trapdoor
    type EphemeralKeyTrapdoor: Sample;

    /// Ephemeral Key Commitment Scheme Input
    type EphemeralKeyCommitmentSchemeInput: Default
        + CommitmentInput<Self::LedgerCheckpoint>
        + CommitmentInput<u8>
        + CommitmentInput<PublicKey<Self>>;

    ///
    type EphemeralKeyCommitmentSchemeInputVar: Default
        + CommitmentInput<Self::LedgerCheckpointVar>
        + CommitmentInput<Self::ByteVar>
        + CommitmentInput<PublicKeyVar<Self>>;

    /// Ephemeral Key Commitment Scheme
    type EphemeralKeyCommitmentScheme: CommitmentScheme<
        Trapdoor = Self::EphemeralKeyTrapdoor,
        Output = SecretKey<Self>,
    >;

    /// Commitment Scheme Input
    type CommitmentSchemeInput: Default
        + CommitmentInput<AssetId>
        + CommitmentInput<AssetValue>
        + CommitmentInput<SecretKey<Self>>;

    /// Commitment Scheme Input Variable
    type CommitmentSchemeInputVar: Default
        + CommitmentInput<Self::AssetIdVar>
        + CommitmentInput<Self::AssetValueVar>
        + CommitmentInput<SecretKeyVar<Self>>;

    /// Commitment Scheme Output
    type CommitmentSchemeOutput: PartialEq;

    /// Commitment Scheme Output Variable
    type CommitmentSchemeOutputVar: Equal<Self::ConstraintSystem>;

    /// Commitment Scheme
    type CommitmentScheme: CommitmentScheme<
        Input = Self::CommitmentSchemeInput,
        Output = Self::CommitmentSchemeOutput,
    >;

    /// UTXO Set Verifier
    type UtxoSetVerifier: Verifier<Item = Utxo<Self>, Verification = bool>;

    /// Ledger Checkpoint Type
    type LedgerCheckpoint;

    /// Ledger Checkpoint Variable
    type LedgerCheckpointVar: Variable<
        Self::ConstraintSystem,
        Type = Self::LedgerCheckpoint,
        Mode = Public,
    >;

    /// Asset Id Variable
    type AssetIdVar: Variable<Self::ConstraintSystem, Type = AssetId, Mode = PublicOrSecret>
        + Equal<Self::ConstraintSystem>;

    /// Asset Value Variable
    type AssetValueVar: Variable<Self::ConstraintSystem, Type = AssetValue, Mode = PublicOrSecret>
        + Equal<Self::ConstraintSystem>
        + Add<Output = Self::AssetValueVar>;

    /// Byte Variable
    type ByteVar: Variable<Self::ConstraintSystem, Type = u8, Mode = Public>;

    /// Constraint System
    type ConstraintSystem: ConstraintSystem
        + key::constraint::KeyAgreementScheme<Self::KeyAgreementScheme>
        + commitment::constraint::CommitmentScheme<Self::EphemeralKeyCommitmentScheme>
        + commitment::constraint::CommitmentScheme<
            Self::CommitmentScheme,
            Input = Self::CommitmentSchemeInputVar,
            Output = Self::CommitmentSchemeOutputVar,
        > + accumulator::constraint::Verifier<Self::UtxoSetVerifier>;

    /// Proof System Type
    type ProofSystem: ProofSystem<ConstraintSystem = Self::ConstraintSystem, Verification = bool>
        + ProofSystemInput<AssetId>
        + ProofSystemInput<AssetValue>
        + ProofSystemInput<UtxoSetOutput<Self>>
        + ProofSystemInput<CommitmentSchemeOutput<Self>>
        + ProofSystemInput<Self::LedgerCheckpoint>;

    /// Note Encryption Scheme Type
    type NoteEncryptionScheme: HybridPublicKeyEncryptionScheme<
        Plaintext = Asset,
        KeyAgreementScheme = Self::KeyAgreementScheme,
    >;
}

/// Asset Variable Type
pub type AssetVar<C> = Asset<<C as Configuration>::AssetIdVar, <C as Configuration>::AssetValueVar>;

/// Secret Key Type
pub type SecretKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;

/// Secret Key Variable Type
pub type SecretKeyVar<C> =
    <<C as Configuration>::ConstraintSystem as key::constraint::KeyAgreementScheme<
        <C as Configuration>::KeyAgreementScheme,
    >>::SecretKey;

/// Public Key Type
pub type PublicKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;

/// Public Key Variable Type
pub type PublicKeyVar<C> =
    <<C as Configuration>::ConstraintSystem as key::constraint::KeyAgreementScheme<
        <C as Configuration>::KeyAgreementScheme,
    >>::PublicKey;

/// Shared Secret Type
pub type SharedSecret<C> =
    <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret;

/*
/// Shared Secret Variable Type
pub type SharedSecretVar<C> =
    <<C as Configuration>::KeyAgreementSchemeVar as KeyAgreementScheme>::SharedSecret;
*/

/// Ephemeral Key Trapdoor Type
pub type EphemeralKeyTrapdoor<C> =
    <<C as Configuration>::EphemeralKeyCommitmentScheme as CommitmentScheme>::Trapdoor;

/// Ephemeral Key Trapdoor Variable Type
pub type EphemeralKeyTrapdoorVar<C> =
    <<C as Configuration>::ConstraintSystem as commitment::constraint::CommitmentScheme<
        <C as Configuration>::EphemeralKeyCommitmentScheme,
    >>::Trapdoor;

/// Trapdoor Type
pub type Trapdoor<C> = <<C as Configuration>::CommitmentScheme as CommitmentScheme>::Trapdoor;

/*
/// Trapdoor Variable Type
pub type TrapdoorVar<C> = <<C as Configuration>::CommitmentSchemeVar as CommitmentScheme>::Trapdoor;
*/

/// Commitment Scheme Output Type
pub type CommitmentSchemeOutput<C> = <C as Configuration>::CommitmentSchemeOutput;

/// Commitment Scheme Output Variable Type
pub type CommitmentSchemeOutputVar<C> = <C as Configuration>::CommitmentSchemeOutputVar;

/// Unspend Transaction Output Type
pub type Utxo<C> = CommitmentSchemeOutput<C>;

/// Unspent Transaction Output Variable Type
pub type UtxoVar<C> = CommitmentSchemeOutputVar<C>;

/// UTXO Set Output Type
pub type UtxoSetOutput<C> = <<C as Configuration>::UtxoSetVerifier as Verifier>::Output;

/// UTXO Membership Proof Type
pub type UtxoMembershipProof<C> = MembershipProof<<C as Configuration>::UtxoSetVerifier>;

/// UTXO Membership Proof Variable Type
pub type UtxoMembershipProofVar<C> = accumulator::constraint::MembershipProof<
    <C as Configuration>::UtxoSetVerifier,
    <C as Configuration>::ConstraintSystem,
>;

/// Void Number Type
pub type VoidNumber<C> = CommitmentSchemeOutput<C>;

/// Void Number Variable Type
pub type VoidNumberVar<C> = CommitmentSchemeOutputVar<C>;

/// Encrypted Note Type
pub type EncryptedNote<C> = EncryptedMessage<<C as Configuration>::NoteEncryptionScheme>;

/// Decrypted Note Type
pub type Note<C> = DecryptedMessage<<C as Configuration>::NoteEncryptionScheme>;

/// Transfer Proof System Type
type ProofSystemType<C> = <C as Configuration>::ProofSystem;

/// Transfer Proof System Error Type
pub type ProofSystemError<C> = <ProofSystemType<C> as ProofSystem>::Error;

/// Transfer Proving Context Type
pub type ProvingContext<C> = <ProofSystemType<C> as ProofSystem>::ProvingContext;

/// Transfer Verifying Context Type
pub type VerifyingContext<C> = <ProofSystemType<C> as ProofSystem>::VerifyingContext;

/// Transfer Proof System Input Type
pub type ProofInput<C> = <<C as Configuration>::ProofSystem as ProofSystem>::Input;

/// Transfer Validity Proof Type
pub type Proof<C> = <ProofSystemType<C> as ProofSystem>::Proof;

/// Transfer Parameters
pub struct Parameters<C>
where
    C: Configuration,
{
    /// Ephemeral Key Commitment Scheme Parameters
    pub ephemeral_key_commitment_scheme:
        <C::EphemeralKeyCommitmentScheme as CommitmentScheme>::Parameters,

    /// Commitment Scheme Parameters
    pub commitment_scheme: <C::CommitmentScheme as CommitmentScheme>::Parameters,

    /// UTXO Set Verifier Parameters
    pub utxo_set_verifier: <C::UtxoSetVerifier as Verifier>::Parameters,
}

/// Transfer Parameters Variable
pub struct ParametersVar<C>
where
    C: Configuration,
{
    // FIXME: ...
    __: C,
}

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
        parameters: &<C::CommitmentScheme as CommitmentScheme>::Parameters,
        ephemeral_key: &PublicKey<C>,
        asset: &Asset,
        utxo: &Utxo<C>,
    ) -> bool {
        &generate_full_utxo::<
            C::KeyAgreementScheme,
            C::TrapdoorDerivationFunction,
            C::CommitmentScheme,
            _,
            _,
        >(parameters, &self.spend, ephemeral_key, asset)
            == utxo
    }

    /// Prepares `self` for spending `asset` with the given `ephemeral_key`.
    #[inline]
    pub fn sender(
        &self,
        parameters: &<C::CommitmentScheme as CommitmentScheme>::Parameters,
        ephemeral_key: PublicKey<C>,
        asset: Asset,
    ) -> PreSender<C> {
        PreSender::new(parameters, self.spend.clone(), ephemeral_key, asset)
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
        parameters: &<C::CommitmentScheme as CommitmentScheme>::Parameters,
        spend: SecretKey<C>,
        ephemeral_key: PublicKey<C>,
        asset: Asset,
    ) -> Self {
        let trapdoor = generate_trapdoor::<C::KeyAgreementScheme, C::TrapdoorDerivationFunction>(
            &spend,
            &ephemeral_key,
        );
        Self {
            utxo: generate_utxo::<C::CommitmentScheme, _, _>(parameters, &trapdoor, &asset),
            void_number: generate_void_number::<C::CommitmentScheme, _>(
                parameters, &trapdoor, &spend,
            ),
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

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> SenderPost<C> {
        SenderPost {
            utxo_set_output: self.utxo_membership_proof.into_output(),
            void_number: self.void_number,
        }
    }
}

/// Sender Variable
pub struct SenderVar<C>
where
    C: Configuration,
{
    /// Secret Spend Key
    spend: SecretKeyVar<C>,

    /// Ephemeral Public Spend Key
    ephemeral_key: PublicKeyVar<C>,

    /// Asset
    asset: AssetVar<C>,

    /// UTXO Membership Proof
    utxo_membership_proof: UtxoMembershipProofVar<C>,

    /// Void Number
    void_number: VoidNumberVar<C>,
}

impl<C> SenderVar<C>
where
    C: Configuration,
{
    /// Returns the asset for `self`, checking if `self` is well-formed in the given constraint
    /// system `cs`.
    #[inline]
    pub fn get_well_formed_asset(
        self,
        parameters: &ParametersVar<C>,
        cs: &mut C::ConstraintSystem,
    ) -> AssetVar<C> {
        /* TODO:
        let trapdoor = generate_trapdoor::<
            C::KeyAgreementSchemeVar,
            C::TrapdoorDerivationFunctionVar,
        >(&self.spend, &self.ephemeral_key);
        cs.assert(self.utxo_membership_proof.verify(
            &generate_utxo(commitment_scheme, &self.asset, &trapdoor),
            utxo_set_verifier,
        ));
        cs.assert_eq(
            &self.void_number,
            &generate_void_number(commitment_scheme, &self.spend, &trapdoor),
        );
        self.asset
        */
        todo!()
    }
}

impl<C> Variable<C::ConstraintSystem> for SenderVar<C>
where
    C: Configuration,
{
    type Type = Sender<C>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut C::ConstraintSystem, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        /* TODO:
        match allocation {
            Allocation::Known(this, mode) => Self {
                spend: this.spend.as_known(cs, mode),
                ephemeral_key: this.ephemeral_key.as_known(cs, mode),
                asset: this.asset.as_known(cs, mode),
                utxo_membership_proof: this.utxo_membership_proof.as_known(cs, mode),
                void_number: this.void_number.as_known(cs, Public),
            },
            Allocation::Unknown(mode) => Self {
                spend: C::SecretKeyVar::new_unknown(cs, mode),
                ephemeral_key: C::PublicKeyVar::new_unknown(cs, mode),
                asset: AssetVar::<C>::new_unknown(cs, mode),
                utxo_membership_proof: UtxoMembershipProofVar::<C>::new_unknown(cs, mode),
                void_number: VoidNumberVar::<C>::new_unknown(cs, Public),
            },
        }
        */
        todo!()
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
    /// [`has_matching_utxo_set_output`](Self::has_matching_utxo_set_output).
    type ValidVoidNumber;

    /// Valid UTXO Set Output Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`S::Output`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`has_matching_utxo_set_output`](Self::has_matching_utxo_set_output).
    ///
    /// [`S::Output`]: Verifier::Output
    type ValidUtxoSetOutput;

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
    fn has_matching_utxo_set_output(
        &self,
        output: UtxoSetOutput<C>,
    ) -> Option<Self::ValidUtxoSetOutput>;

    /// Posts the `void_number` to the ledger, spending the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `void_number` is not already stored on
    /// the ledger. See [`is_unspent`](Self::is_unspent).
    fn spend(
        &mut self,
        utxo_set_output: Self::ValidUtxoSetOutput,
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

    /// Invalid UTXO Set Output Error
    ///
    /// The sender was not constructed under the current state of the UTXO set.
    InvalidUtxoSetOutput,
}

/// Sender Post
pub struct SenderPost<C>
where
    C: Configuration,
{
    /// UTXO Set Output
    utxo_set_output: UtxoSetOutput<C>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C> SenderPost<C>
where
    C: Configuration,
{
    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        // TODO: Add a "public part" trait that extracts the public part of `Sender` (using
        //       `SenderVar` to determine the types), then generate this method automatically.
        C::ProofSystem::extend(input, &self.utxo_set_output);
        C::ProofSystem::extend(input, &self.void_number);
    }

    /// Validates `self` on the sender `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<SenderPostingKey<C, L>, SenderPostError>
    where
        L: SenderLedger<C>,
    {
        Ok(SenderPostingKey {
            utxo_set_output: ledger
                .has_matching_utxo_set_output(self.utxo_set_output)
                .ok_or(SenderPostError::InvalidUtxoSetOutput)?,
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
    L: SenderLedger<C> + ?Sized,
{
    /// UTXO Set Output Posting Key
    utxo_set_output: L::ValidUtxoSetOutput,

    /// Void Number Posting Key
    void_number: L::ValidVoidNumber,
}

impl<C, L> SenderPostingKey<C, L>
where
    C: Configuration,
    L: SenderLedger<C> + ?Sized,
{
    /// Posts `self` to the sender `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.spend(self.utxo_set_output, self.void_number, super_key);
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
        parameters: &<C::CommitmentScheme as CommitmentScheme>::Parameters,
        ephemeral_key: SecretKey<C>,
    ) -> Receiver<C> {
        Receiver::new(parameters, self.spend, self.view, ephemeral_key, self.asset)
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
        parameters: &<C::CommitmentScheme as CommitmentScheme>::Parameters,
        spend: PublicKey<C>,
        view: PublicKey<C>,
        ephemeral_key: SecretKey<C>,
        asset: Asset,
    ) -> Self {
        Self {
            utxo: generate_full_utxo::<
                C::KeyAgreementScheme,
                C::TrapdoorDerivationFunction,
                C::CommitmentScheme,
                _,
                _,
            >(parameters, &ephemeral_key, &spend, &asset),
            spend,
            view,
            ephemeral_key,
            asset,
        }
    }

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

/// Receiver Variable
pub struct ReceiverVar<C>
where
    C: Configuration,
{
    /// Public Spend Key
    spend: PublicKeyVar<C>,

    /// Asset
    asset: AssetVar<C>,

    /// Unspent Transaction Output
    utxo: UtxoVar<C>,
}

impl<C> ReceiverVar<C>
where
    C: Configuration,
{
    /// Returns the asset for `self`, checking if `self` is well-formed in the given constraint
    /// system `cs`.
    #[inline]
    pub fn get_well_formed_asset(
        self,
        parameters: &ParametersVar<C>,
        index: C::ByteVar,
        ledger_checkpoint: &C::LedgerCheckpointVar,
        ephemeral_key_trapdoor: &EphemeralKeyTrapdoorVar<C>,
        cs: &mut C::ConstraintSystem,
    ) -> AssetVar<C> {
        /* TODO:
        let ephemeral_key = generate_ephemeral_secret_key(
            ephemeral_key_commitment_scheme,
            ledger_checkpoint,
            &index,
            &self.spend,
            ephemeral_key_trapdoor,
        );
        cs.assert_eq(
            &self.utxo,
            &generate_utxo(
                commitment_scheme,
                &self.asset,
                &generate_trapdoor::<C::KeyAgreementSchemeVar, C::TrapdoorDerivationFunctionVar>(
                    &ephemeral_key,
                    &self.spend,
                ),
            ),
        );
        self.asset
        */
        todo!()
    }
}

impl<C> Variable<C::ConstraintSystem> for ReceiverVar<C>
where
    C: Configuration,
{
    type Type = Receiver<C>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut C::ConstraintSystem, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        /*
        match allocation {
            Allocation::Known(this, mode) => Self {
                spend: this.spend.as_known(cs, mode),
                asset: this.asset.as_known(cs, mode),
                utxo: this.utxo.as_known(cs, Public),
            },
            Allocation::Unknown(mode) => Self {
                spend: C::PublicKeyVar::new_unknown(cs, mode),
                asset: AssetVar::<C>::new_unknown(cs, mode),
                utxo: UtxoVar::<C>::new_unknown(cs, Public),
            },
        }
        */
        todo!()
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

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        // TODO: Add a "public part" trait that extracts the public part of `Receiver` (using
        //       `ReceiverVar` to determine the types), then generate this method automatically.
        C::ProofSystem::extend(input, &self.utxo);
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
    L: ReceiverLedger<C> + ?Sized,
{
    /// UTXO Posting Key
    utxo: L::ValidUtxo,

    /// Encrypted Note
    note: EncryptedNote<C>,
}

impl<C, L> ReceiverPostingKey<C, L>
where
    C: Configuration,
    L: ReceiverLedger<C> + ?Sized,
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
    senders: [Sender<C>; SENDERS],

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
        senders: [Sender<C>; SENDERS],
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
        if has_public_participants(SOURCES, SENDERS, RECEIVERS, SINKS) {
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
        senders: [Sender<C>; SENDERS],
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

    /*
    /// Generates a proving and verifying context for this transfer shape.
    #[inline]
    pub fn generate_context<R>(
        ephemeral_key_commitment_scheme: &C::EphemeralKeyCommitmentScheme,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        rng: &mut R,
    ) -> Result<(ProvingContext<C>, VerifyingContext<C>), ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut cs = C::ProofSystem::for_unknown();
        FullTransferVar::<C, SOURCES, SENDERS, RECEIVERS, SINKS>::new_unknown(&mut cs, Derived)
            .build_validity_constraints(
                &ephemeral_key_commitment_scheme.as_known(&mut cs, Public),
                &commitment_scheme.as_known(&mut cs, Public),
                &utxo_set_verifier.as_known(&mut cs, Public),
                &mut cs,
            );
        cs.generate_context::<C::ProofSystem, _>(rng)
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post<R>(
        self,
        ephemeral_key_commitment_scheme: &C::EphemeralKeyCommitmentScheme,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        ledger_checkpoint: C::LedgerCheckpoint,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let ephemeral_key_trapdoor = rng.gen();
        FullTransfer::<_, SOURCES, SENDERS, RECEIVERS, SINKS> {
            asset_id: self.asset_id,
            sources: self.sources,
            senders: self.senders,
            receivers: IntoIterator::into_iter(self.receivers)
                .enumerate()
                .map(|(i, r)| {
                    let ephemeral_key = generate_ephemeral_secret_key(
                        ephemeral_key_commitment_scheme,
                        &ledger_checkpoint,
                        &(i as u8),
                        &r.spend,
                        &ephemeral_key_trapdoor,
                    );
                    r.upgrade(ephemeral_key, commitment_scheme)
                })
                .collect::<Vec<_>>(),
            sinks: self.sinks,
            ephemeral_key_trapdoor,
            ledger_checkpoint,
        }
        .into_post(
            ephemeral_key_commitment_scheme,
            commitment_scheme,
            utxo_set_verifier,
            context,
            rng,
        )
    }
    */
}

/// Full Transfer
struct FullTransfer<
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
    senders: [Sender<C>; SENDERS],

    /// Receivers
    receivers: Vec<Receiver<C>>,

    /// Sinks
    sinks: [AssetValue; SINKS],

    /// Ephemeral Key Trapdoor
    ephemeral_key_trapdoor: C::EphemeralKeyTrapdoor,

    /// Ledger Checkpoint
    ledger_checkpoint: C::LedgerCheckpoint,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    FullTransfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /*
    /// Computes the [`TransferPost`] for `self`.
    #[inline]
    fn into_post<R>(
        self,
        ephemeral_key_commitment_scheme: &C::EphemeralKeyCommitmentScheme,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Ok(TransferPost {
            validity_proof: {
                let mut cs = C::ProofSystem::for_known();
                let transfer: FullTransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS> =
                    self.as_known(&mut cs, Derived);
                transfer.build_validity_constraints(
                    &ephemeral_key_commitment_scheme.as_known(&mut cs, Public),
                    &commitment_scheme.as_known(&mut cs, Public),
                    &utxo_set_verifier.as_known(&mut cs, Public),
                    &mut cs,
                );
                cs.prove::<C::ProofSystem, _>(context, rng)?
            },
            asset_id: self.asset_id,
            sources: self.sources.into(),
            sender_posts: IntoIterator::into_iter(self.senders)
                .map(Sender::into_post)
                .collect(),
            receiver_posts: self
                .receivers
                .into_iter()
                .map(Receiver::into_post)
                .collect(),
            sinks: self.sinks.into(),
            ledger_checkpoint: self.ledger_checkpoint,
        })
    }
    */
}

/// Full Transfer Variable
struct FullTransferVar<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    C: Configuration,
{
    /// Asset Id
    asset_id: Option<C::AssetIdVar>,

    /// Sources
    sources: Vec<C::AssetValueVar>,

    /// Senders
    senders: Vec<SenderVar<C>>,

    /// Receivers
    receivers: Vec<(C::ByteVar, ReceiverVar<C>)>,

    /// Sinks
    sinks: Vec<C::AssetValueVar>,

    /// Ephemeral Key Trapdoor
    ephemeral_key_trapdoor: EphemeralKeyTrapdoorVar<C>,

    /// Ledger Checkpoint
    ledger_checkpoint: C::LedgerCheckpointVar,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    FullTransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /*
    /// Builds constraints for the [`Transfer`] validity proof.
    #[inline]
    fn build_validity_constraints(
        self,
        ephemeral_key_commitment_scheme: &C::EphemeralKeyCommitmentSchemeVar,
        commitment_scheme: &C::CommitmentSchemeVar,
        utxo_set_verifier: &C::UtxoSetVerifierVar,
        cs: &mut C::ConstraintSystem,
    ) {
        let mut secret_asset_ids = Vec::with_capacity(SENDERS + RECEIVERS);

        let input_sum = self
            .senders
            .into_iter()
            .map(|s| {
                let asset = s.get_well_formed_asset(commitment_scheme, utxo_set_verifier, cs);
                secret_asset_ids.push(asset.id);
                asset.value
            })
            .chain(self.sources)
            .reduce(Add::add)
            .unwrap();

        let ledger_checkpoint = &self.ledger_checkpoint;
        let ephemeral_key_trapdoor = &self.ephemeral_key_trapdoor;

        let output_sum = self
            .receivers
            .into_iter()
            .map(|(index, r)| {
                let asset = r.get_well_formed_asset(
                    index,
                    ledger_checkpoint,
                    ephemeral_key_trapdoor,
                    ephemeral_key_commitment_scheme,
                    commitment_scheme,
                    cs,
                );
                secret_asset_ids.push(asset.id);
                asset.value
            })
            .chain(self.sinks)
            .reduce(Add::add)
            .unwrap();

        cs.assert_eq(&input_sum, &output_sum);

        match self.asset_id {
            Some(asset_id) => cs.assert_all_eq_to_base(&asset_id, secret_asset_ids.iter()),
            _ => cs.assert_all_eq(secret_asset_ids.iter()),
        }
    }
    */
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Variable<C::ConstraintSystem> for FullTransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    type Type = FullTransfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut C::ConstraintSystem, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        /*
        match allocation {
            Allocation::Known(this, mode) => Self {
                asset_id: this.asset_id.map(|id| id.as_known(cs, Public)),
                sources: this
                    .sources
                    .iter()
                    .map(|source| source.as_known(cs, Public))
                    .collect(),
                senders: this
                    .senders
                    .iter()
                    .map(|sender| sender.as_known(cs, mode))
                    .collect(),
                receivers: this
                    .receivers
                    .iter()
                    .enumerate()
                    .map(|(i, receiver)| {
                        ((i as u8).as_known(cs, mode), receiver.as_known(cs, mode))
                    })
                    .collect(),
                sinks: this
                    .sinks
                    .iter()
                    .map(|sink| sink.as_known(cs, Public))
                    .collect(),
                ephemeral_key_trapdoor: this.ephemeral_key_trapdoor.as_known(cs, mode),
                ledger_checkpoint: this.ledger_checkpoint.as_known(cs, mode),
            },
            Allocation::Unknown(mode) => Self {
                asset_id: has_public_participants(SOURCES, SENDERS, RECEIVERS, SINKS)
                    .then(|| C::AssetIdVar::new_unknown(cs, Public)),
                sources: (0..SOURCES)
                    .into_iter()
                    .map(|_| C::AssetValueVar::new_unknown(cs, Public))
                    .collect(),
                senders: (0..SENDERS)
                    .into_iter()
                    .map(|_| SenderVar::<C>::new_unknown(cs, mode))
                    .collect(),
                receivers: (0..RECEIVERS)
                    .into_iter()
                    .map(|_| {
                        (
                            C::ByteVar::new_unknown(cs, mode),
                            ReceiverVar::<C>::new_unknown(cs, mode),
                        )
                    })
                    .collect(),
                sinks: (0..SINKS)
                    .into_iter()
                    .map(|_| C::AssetValueVar::new_unknown(cs, Public))
                    .collect(),
                ephemeral_key_trapdoor: C::EphemeralKeyTrapdoorVar::new_unknown(cs, mode),
                ledger_checkpoint: C::LedgerCheckpointVar::new_unknown(cs, mode),
            },
        }
        */
        todo!()
    }
}

/// Transfer Ledger
pub trait TransferLedger<C>: SenderLedger<C, SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>)>
    + ReceiverLedger<C, SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>)>
where
    C: Configuration,
{
    /// Valid [`AssetValue`] for [`TransferPost`] source
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation of
    /// [`TransferLedger`].
    type ValidSourceBalance;

    /// Valid [`Proof`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation
    /// of [`TransferLedger`]. This is to prevent that [`SenderPostingKey::post`] and
    /// [`ReceiverPostingKey::post`] are called before [`SenderPost::validate`],
    /// [`ReceiverPost::validate`], [`check_source_balances`](Self::check_source_balances), and
    /// [`is_valid`](Self::is_valid).
    type ValidProof: Copy;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`TransferLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks that the balances associated to the source accounts are sufficient to withdraw the
    /// amount given in `sources`.
    fn check_source_balances(
        &self,
        sources: Vec<AssetValue>,
    ) -> Result<Vec<Self::ValidSourceBalance>, InsufficientPublicBalance>;

    /// Checks that the transfer `proof` is valid.
    #[allow(clippy::too_many_arguments)] // FIXME: Write a better abstraction for this.
    fn is_valid(
        &self,
        asset_id: Option<AssetId>,
        sources: &[Self::ValidSourceBalance],
        senders: &[SenderPostingKey<C, Self>],
        receivers: &[ReceiverPostingKey<C, Self>],
        sinks: &[AssetValue],
        ledger_checkpoint: &C::LedgerCheckpoint,
        proof: Proof<C>,
    ) -> Option<Self::ValidProof>;

    /// Updates the public balances in the ledger, finishing the transaction.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `proof` is a valid proof and that
    /// `senders` and `receivers` are valid participants in the transaction. See
    /// [`is_valid`](Self::is_valid) for more.
    fn update_public_balances(
        &mut self,
        asset_id: AssetId,
        sources: Vec<Self::ValidSourceBalance>,
        sinks: Vec<AssetValue>,
        proof: Self::ValidProof,
        super_key: &TransferLedgerSuperPostingKey<C, Self>,
    );
}

/// Transfer Source Posting Key Type
pub type SourcePostingKey<C, L> = <L as TransferLedger<C>>::ValidSourceBalance;

/// Transfer Ledger Super Posting Key Type
pub type TransferLedgerSuperPostingKey<C, L> = <L as TransferLedger<C>>::SuperPostingKey;

/// Insufficient Public Balance Error
///
/// This `enum` is the error state of the [`TransferLedger::check_source_balances`] method. See its
/// documentation for more.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InsufficientPublicBalance {
    /// Index of the Public Address
    pub index: usize,

    /// Current Balance
    pub balance: AssetValue,

    /// Amount Attempting to Withdraw
    pub withdraw: AssetValue,
}

/// Transfer Post Error
///
/// This `enum` is the error state of the [`TransferPost::validate`] method. See its documentation
/// for more.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransferPostError {
    /// Insufficient Public Balance
    InsufficientPublicBalance(InsufficientPublicBalance),

    /// Sender Post Error
    Sender(SenderPostError),

    /// Receiver Post Error
    Receiver(ReceiverPostError),

    /// Invalid Transfer Proof Error
    ///
    /// Validity of the transfer could not be proved by the ledger.
    InvalidProof,
}

from_variant_impl!(TransferPostError, Sender, SenderPostError);
from_variant_impl!(TransferPostError, Receiver, ReceiverPostError);

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

    /// Ledger Checkpoint
    ledger_checkpoint: C::LedgerCheckpoint,

    /// Validity Proof
    validity_proof: Proof<C>,
}

impl<C> TransferPost<C>
where
    C: Configuration,
{
    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        let mut input = Default::default();
        if let Some(asset_id) = self.asset_id {
            C::ProofSystem::extend(&mut input, &asset_id);
        }
        self.sources
            .iter()
            .for_each(|source| C::ProofSystem::extend(&mut input, source));
        self.sender_posts
            .iter()
            .for_each(|post| post.extend_input(&mut input));
        self.receiver_posts
            .iter()
            .for_each(|post| post.extend_input(&mut input));
        self.sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(&mut input, sink));
        C::ProofSystem::extend(&mut input, &self.ledger_checkpoint);
        input
    }

    /// Validates `self` on the transfer `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<TransferPostingKey<C, L>, TransferPostError>
    where
        L: TransferLedger<C>,
    {
        let source_posting_keys = ledger
            .check_source_balances(self.sources)
            .map_err(TransferPostError::InsufficientPublicBalance)?;
        for (i, p) in self.sender_posts.iter().enumerate() {
            if self
                .sender_posts
                .iter()
                .skip(i + 1)
                .any(move |q| p.void_number == q.void_number)
            {
                return Err(SenderPostError::AssetSpent.into());
            }
        }
        let sender_posting_keys = self
            .sender_posts
            .into_iter()
            .map(move |s| s.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        let receiver_posting_keys = self
            .receiver_posts
            .into_iter()
            .map(move |r| r.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TransferPostingKey {
            validity_proof: match ledger.is_valid(
                self.asset_id,
                &source_posting_keys,
                &sender_posting_keys,
                &receiver_posting_keys,
                &self.sinks,
                &self.ledger_checkpoint,
                self.validity_proof,
            ) {
                Some(key) => key,
                _ => return Err(TransferPostError::InvalidProof),
            },
            asset_id: self.asset_id,
            source_posting_keys,
            sender_posting_keys,
            receiver_posting_keys,
            sinks: self.sinks,
        })
    }
}

/// Transfer Posting Key
pub struct TransferPostingKey<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    /// Asset Id
    asset_id: Option<AssetId>,

    /// Source Posting Keys
    source_posting_keys: Vec<SourcePostingKey<C, L>>,

    /// Sender Posting Keys
    sender_posting_keys: Vec<SenderPostingKey<C, L>>,

    /// Receiver Posting Keys
    receiver_posting_keys: Vec<ReceiverPostingKey<C, L>>,

    /// Sinks
    sinks: Vec<AssetValue>,

    /// Validity Proof Posting Key
    validity_proof: L::ValidProof,
}

impl<C, L> TransferPostingKey<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    /// Posts `self` to the transfer `ledger`.
    ///
    /// # Safety
    ///
    /// This method assumes that posting `self` to `ledger` is atomic and cannot fail. See
    /// [`SenderLedger::spend`] and [`ReceiverLedger::register`] for more information on the
    /// contract for this method.
    #[inline]
    pub fn post(self, super_key: &TransferLedgerSuperPostingKey<C, L>, ledger: &mut L) {
        let proof = self.validity_proof;
        for key in self.sender_posting_keys {
            key.post(&(proof, *super_key), ledger);
        }
        for key in self.receiver_posting_keys {
            key.post(&(proof, *super_key), ledger);
        }
        if let Some(asset_id) = self.asset_id {
            ledger.update_public_balances(
                asset_id,
                self.source_posting_keys,
                self.sinks,
                proof,
                super_key,
            );
        }
    }
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
            senders: [Sender<C>; PrivateTransferShape::SENDERS],
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
            senders: [Sender<C>; ReclaimShape::SENDERS],
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
