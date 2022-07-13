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

//! Transfer Protocol
//!
//! This module defines a protocol for the zero-knowledge transfer of private assets. We define the
//! following structures:
//!
//! - Global Configuration: [`Configuration`]
//! - Sender Abstraction: [`Sender`], [`SenderPost`], [`SenderLedger`](
//! - Receiver Abstraction: [`Receiver`], [`ReceiverPost`], [`ReceiverLedger`]
//! - Transfer Abstraction: [`Transfer`], [`TransferPost`], [`TransferLedger`]
//! - Canonical Transactions: [`canonical`]
//! - Batched Transactions: [`batch`]
//!
//! See the [`crate::wallet`] module for more on how this transfer protocol is used in a wallet
//! protocol for the keeping of accounts for private assets.

/*
use crate::asset::{Asset, AssetId, AssetValue};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData, ops::Deref};
use manta_crypto::{
    accumulator::{AssertValidVerification, MembershipProof, Model},
    constraint::{
        self, Add, Allocate, Allocator, AssertEq, Bool, Constant, Derived, ProofSystem,
        ProofSystemInput, Public, Secret, Variable,
    },
    encryption::{self, hybrid::Hybrid, EncryptedMessage},
    key::{self, agreement::Derive},
    rand::{CryptoRng, RngCore, Sample},
};
use manta_util::SizeLimit;
*/

use crate::{
    asset,
    transfer::{
        receiver::{ReceiverLedger, ReceiverPostError},
        sender::{SenderLedger, SenderPostError},
        utxo::{sign_authorization, Mint, Note, Nullifier, Spend, Utxo, VerifyAuthorization},
    },
};
use core::{fmt::Debug, hash::Hash};
use manta_crypto::{
    accumulator,
    constraint::{
        self, Add, Allocate, Allocator, Assert, AssertEq, Constant, Derived, ProofSystem,
        ProofSystemInput, Public, Secret, Variable,
    },
    rand::{CryptoRng, Rand, RngCore, Sample},
    signature::{self, Verify},
};
use manta_util::vec::{all_unequal, Vec};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

// TODO: pub mod batch;
pub mod canonical;
pub mod receiver;
pub mod sender;
pub mod utxo;

/* TODO:
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test;
*/

pub use canonical::Shape;

/// Returns `true` if the [`Transfer`] with this shape would have public participants.
#[inline]
pub const fn has_public_participants(sources: usize, sinks: usize) -> bool {
    (sources + sinks) > 0
}

/// Returns `true` if the [`Transfer`] with this shape would have secret participants.
#[inline]
pub const fn has_secret_participants(senders: usize, receivers: usize) -> bool {
    (senders + receivers) > 0
}

/*
/// UTXO Commitment Scheme
pub trait UtxoCommitmentScheme<COM = ()> {
    /// Ephemeral Secret Key Type
    type EphemeralSecretKey;

    /// Public Spend Key Type
    type PublicSpendKey;

    /// Asset Type
    type Asset;

    /// Unspent Transaction Output Type
    type Utxo;

    /// Commits to the `ephemeral_secret_key`, `public_spend_key`, and `asset` for a UTXO.
    fn commit(
        &self,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        public_spend_key: &Self::PublicSpendKey,
        asset: &Self::Asset,
        compiler: &mut COM,
    ) -> Self::Utxo;
}

/// Void Number Commitment Scheme
pub trait VoidNumberCommitmentScheme<COM = ()> {
    /// Secret Spend Key Type
    type SecretSpendKey;

    /// Unspent Transaction Output Type
    type Utxo;

    /// Void Number Type
    type VoidNumber;

    /// Commits to the `secret_spend_key` and `utxo` for a Void Number.
    fn commit(
        &self,
        secret_spend_key: &Self::SecretSpendKey,
        utxo: &Self::Utxo,
        compiler: &mut COM,
    ) -> Self::VoidNumber;
}

/// Transfer Configuration
pub trait Configuration {
    /// Secret Key Type
    type SecretKey: Clone + Sample + SizeLimit;

    /// Public Key Type
    type PublicKey: Clone;

    /// Key Agreement Scheme Type
    type KeyAgreementScheme: key::agreement::Types<SecretKey = SecretKey<Self>, PublicKey = PublicKey<Self>>
        + key::agreement::Agree
        + key::agreement::Derive;

    /// Secret Key Variable Type
    type SecretKeyVar: Variable<Secret, Self::Compiler, Type = SecretKey<Self>>;

    /// Public Key Variable Type
    type PublicKeyVar: Variable<Secret, Self::Compiler, Type = PublicKey<Self>>
        + constraint::PartialEq<Self::PublicKeyVar, Self::Compiler>;

    /// Key Agreement Scheme Variable Type
    type KeyAgreementSchemeVar: Constant<Self::Compiler, Type = Self::KeyAgreementScheme>
        + key::agreement::Types<SecretKey = SecretKeyVar<Self>, PublicKey = PublicKeyVar<Self>>
        + key::agreement::Agree<Self::Compiler>
        + key::agreement::Derive<Self::Compiler>;

    /// Unspent Transaction Output Type
    type Utxo: PartialEq;

    /// UTXO Commitment Scheme Type
    type UtxoCommitmentScheme: UtxoCommitmentScheme<
        EphemeralSecretKey = SecretKey<Self>,
        PublicSpendKey = PublicKey<Self>,
        Asset = Asset,
        Utxo = Utxo<Self>,
    >;

    /// UTXO Variable Type
    type UtxoVar: Variable<Public, Self::Compiler, Type = Utxo<Self>>
        + Variable<Secret, Self::Compiler, Type = Utxo<Self>>
        + constraint::PartialEq<Self::UtxoVar, Self::Compiler>;

    /// UTXO Commitment Scheme Variable Type
    type UtxoCommitmentSchemeVar: Constant<Self::Compiler, Type = Self::UtxoCommitmentScheme>
        + UtxoCommitmentScheme<
            Self::Compiler,
            EphemeralSecretKey = SecretKeyVar<Self>,
            PublicSpendKey = PublicKeyVar<Self>,
            Asset = AssetVar<Self>,
            Utxo = UtxoVar<Self>,
        >;

    /// Void Number Type
    type VoidNumber: PartialEq;

    /// Void Number Commitment Scheme Type
    type VoidNumberCommitmentScheme: VoidNumberCommitmentScheme<
        SecretSpendKey = SecretKey<Self>,
        Utxo = Utxo<Self>,
        VoidNumber = VoidNumber<Self>,
    >;

    /// Void Number Variable Type
    type VoidNumberVar: Variable<Public, Self::Compiler, Type = Self::VoidNumber>
        + constraint::PartialEq<Self::VoidNumberVar, Self::Compiler>;

    /// Void Number Commitment Scheme Variable Type
    type VoidNumberCommitmentSchemeVar: Constant<Self::Compiler, Type = Self::VoidNumberCommitmentScheme>
        + VoidNumberCommitmentScheme<
            Self::Compiler,
            SecretSpendKey = SecretKeyVar<Self>,
            Utxo = UtxoVar<Self>,
            VoidNumber = VoidNumberVar<Self>,
        >;

    /// UTXO Accumulator Model Type
    type UtxoAccumulatorModel: Model<Item = Self::Utxo, Verification = bool>;

    /// UTXO Accumulator Witness Variable Type
    type UtxoAccumulatorWitnessVar: Variable<
        Secret,
        Self::Compiler,
        Type = UtxoAccumulatorWitness<Self>,
    >;

    /// UTXO Accumulator Output Variable Type
    type UtxoAccumulatorOutputVar: Variable<
        Public,
        Self::Compiler,
        Type = UtxoAccumulatorOutput<Self>,
    >;

    /// UTXO Accumulator Model Variable Type
    type UtxoAccumulatorModelVar: Constant<Self::Compiler, Type = Self::UtxoAccumulatorModel>
        + AssertValidVerification<Self::Compiler>
        + Model<
            Self::Compiler,
            Item = Self::UtxoVar,
            Witness = Self::UtxoAccumulatorWitnessVar,
            Output = Self::UtxoAccumulatorOutputVar,
            Verification = Bool<Self::Compiler>,
        >;

    /// Asset Id Variable Type
    type AssetIdVar: Variable<Public, Self::Compiler, Type = AssetId>
        + Variable<Secret, Self::Compiler, Type = AssetId>
        + constraint::PartialEq<Self::AssetIdVar, Self::Compiler>;

    /// Asset Value Variable Type
    type AssetValueVar: Variable<Public, Self::Compiler, Type = AssetValue>
        + Variable<Secret, Self::Compiler, Type = AssetValue>
        + Add<Self::AssetValueVar, Self::Compiler, Output = Self::AssetValueVar>
        + constraint::PartialEq<Self::AssetValueVar, Self::Compiler>;

    /// Constraint System Type
    type Compiler: AssertEq;

    /// Proof System Type
    type ProofSystem: ProofSystem<Compiler = Self::Compiler>
        + ProofSystemInput<AssetId>
        + ProofSystemInput<AssetValue>
        + ProofSystemInput<UtxoAccumulatorOutput<Self>>
        + ProofSystemInput<Utxo<Self>>
        + ProofSystemInput<VoidNumber<Self>>
        + ProofSystemInput<PublicKey<Self>>;

    /// Note Base Encryption Scheme Type
    type NoteEncryptionScheme: encryption::Encrypt<
            EncryptionKey = SharedSecret<Self>,
            Randomness = (),
            Header = (),
            Plaintext = Note<Self>,
        > + encryption::Decrypt<
            DecryptionKey = SharedSecret<Self>,
            DecryptedPlaintext = Option<Note<Self>>,
        >;
}

/// Asset Variable Type
pub type AssetVar<C> = Asset<<C as Configuration>::AssetIdVar, <C as Configuration>::AssetValueVar>;

/// Secret Key Type
pub type SecretKey<C> = <C as Configuration>::SecretKey;

/// Secret Key Variable Type
pub type SecretKeyVar<C> = <C as Configuration>::SecretKeyVar;

/// Public Key Type
pub type PublicKey<C> = <C as Configuration>::PublicKey;

/// Public Key Variable Type
pub type PublicKeyVar<C> = <C as Configuration>::PublicKeyVar;

/// Shared Secret Type
pub type SharedSecret<C> = key::agreement::SharedSecret<<C as Configuration>::KeyAgreementScheme>;

/// Unspend Transaction Output Type
pub type Utxo<C> = <C as Configuration>::Utxo;

/// Unspent Transaction Output Variable Type
pub type UtxoVar<C> = <C as Configuration>::UtxoVar;

/// Void Number Type
pub type VoidNumber<C> = <C as Configuration>::VoidNumber;

/// Void Number Variable Type
pub type VoidNumberVar<C> = <C as Configuration>::VoidNumberVar;

/// UTXO Accumulator Witness Type
pub type UtxoAccumulatorWitness<C> = <<C as Configuration>::UtxoAccumulatorModel as Model>::Witness;

/// UTXO Accumulator Output Type
pub type UtxoAccumulatorOutput<C> = <<C as Configuration>::UtxoAccumulatorModel as Model>::Output;

/// UTXO Membership Proof Type
pub type UtxoMembershipProof<C> = MembershipProof<<C as Configuration>::UtxoAccumulatorModel>;

/// UTXO Membership Proof Variable Type
pub type UtxoMembershipProofVar<C> =
    MembershipProof<<C as Configuration>::UtxoAccumulatorModelVar, Compiler<C>>;

/// Encrypted Note Type
pub type EncryptedNote<C> = EncryptedMessage<
    Hybrid<<C as Configuration>::KeyAgreementScheme, <C as Configuration>::NoteEncryptionScheme>,
>;

/// Transfer Configuration Compiler Type
pub type Compiler<C> = <C as Configuration>::Compiler;

/// Transfer Proof System Type
type ProofSystemType<C> = <C as Configuration>::ProofSystem;

/// Transfer Proof System Error Type
pub type ProofSystemError<C> = <ProofSystemType<C> as ProofSystem>::Error;

/// Transfer Proof System Public Parameters Type
pub type ProofSystemPublicParameters<C> = <ProofSystemType<C> as ProofSystem>::PublicParameters;

/// Transfer Proving Context Type
pub type ProvingContext<C> = <ProofSystemType<C> as ProofSystem>::ProvingContext;

/// Transfer Verifying Context Type
pub type VerifyingContext<C> = <ProofSystemType<C> as ProofSystem>::VerifyingContext;

/// Transfer Proof System Input Type
pub type ProofInput<C> = <<C as Configuration>::ProofSystem as ProofSystem>::Input;

/// Transfer Validity Proof Type
pub type Proof<C> = <ProofSystemType<C> as ProofSystem>::Proof;

/// Transfer Parameters
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = r"
        C::KeyAgreementScheme: Clone,
        C::NoteEncryptionScheme: Clone,
        C::UtxoCommitmentScheme: Clone,
        C::VoidNumberCommitmentScheme: Clone
    "),
    Copy(bound = r"
        C::KeyAgreementScheme: Copy,
        C::NoteEncryptionScheme: Copy,
        C::UtxoCommitmentScheme: Copy,
        C::VoidNumberCommitmentScheme: Copy
    "),
    Debug(bound = r"
        C::KeyAgreementScheme: Debug,
        C::NoteEncryptionScheme: Debug,
        C::UtxoCommitmentScheme: Debug,
        C::VoidNumberCommitmentScheme: Debug
    "),
    Default(bound = r"
        C::KeyAgreementScheme: Default,
        C::NoteEncryptionScheme: Default,
        C::UtxoCommitmentScheme: Default,
        C::VoidNumberCommitmentScheme: Default
    "),
    Eq(bound = r"
        C::KeyAgreementScheme: Eq,
        C::NoteEncryptionScheme: Eq,
        C::UtxoCommitmentScheme: Eq,
        C::VoidNumberCommitmentScheme: Eq
    "),
    Hash(bound = r"
        C::KeyAgreementScheme: Hash,
        C::NoteEncryptionScheme: Hash,
        C::UtxoCommitmentScheme: Hash,
        C::VoidNumberCommitmentScheme: Hash
    "),
    PartialEq(bound = r"
        C::KeyAgreementScheme: PartialEq,
        C::NoteEncryptionScheme: PartialEq,
        C::UtxoCommitmentScheme: PartialEq,
        C::VoidNumberCommitmentScheme: PartialEq
    ")
)]
pub struct Parameters<C>
where
    C: Configuration + ?Sized,
{
    /// Note Encryption Scheme
    pub note_encryption_scheme: Hybrid<C::KeyAgreementScheme, C::NoteEncryptionScheme>,

    /// UTXO Commitment Scheme
    pub utxo_commitment: C::UtxoCommitmentScheme,

    /// Void Number Commitment Scheme
    pub void_number_commitment: C::VoidNumberCommitmentScheme,
}

impl<C> Parameters<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`Parameters`] container from `note_encryption_scheme`, `utxo_commitment`, and
    /// `void_number_commitment`.
    #[inline]
    pub fn new(
        key_agreement_scheme: C::KeyAgreementScheme,
        note_encryption_scheme: C::NoteEncryptionScheme,
        utxo_commitment: C::UtxoCommitmentScheme,
        void_number_commitment: C::VoidNumberCommitmentScheme,
    ) -> Self {
        Self {
            note_encryption_scheme: Hybrid {
                key_agreement_scheme,
                encryption_scheme: note_encryption_scheme,
            },
            utxo_commitment,
            void_number_commitment,
        }
    }

    /// Returns the [`KeyAgreementScheme`](Configuration::KeyAgreementScheme) associated to `self`.
    #[inline]
    pub fn key_agreement_scheme(&self) -> &C::KeyAgreementScheme {
        &self.note_encryption_scheme.key_agreement_scheme
    }

    /// Derives a [`PublicKey`] from a borrowed `secret_key`.
    #[inline]
    pub fn derive(&self, secret_key: &SecretKey<C>) -> PublicKey<C> {
        self.note_encryption_scheme
            .key_agreement_scheme
            .derive(secret_key, &mut ())
    }

    /// Computes the [`Utxo`] associated to `ephemeral_secret_key`, `public_spend_key`, and `asset`.
    #[inline]
    pub fn utxo(
        &self,
        ephemeral_secret_key: &SecretKey<C>,
        public_spend_key: &PublicKey<C>,
        asset: &Asset,
    ) -> Utxo<C> {
        self.utxo_commitment
            .commit(ephemeral_secret_key, public_spend_key, asset, &mut ())
    }

    /// Computes the [`VoidNumber`] associated to `secret_spend_key` and `utxo`.
    #[inline]
    pub fn void_number(&self, secret_spend_key: &SecretKey<C>, utxo: &Utxo<C>) -> VoidNumber<C> {
        self.void_number_commitment
            .commit(secret_spend_key, utxo, &mut ())
    }

    /// Validates the `utxo` against the `secret_spend_key` and the given `ephemeral_secret_key`
    /// and `asset`, returning the void number if the `utxo` is valid.
    #[inline]
    pub fn check_full_asset(
        &self,
        secret_spend_key: &SecretKey<C>,
        ephemeral_secret_key: &SecretKey<C>,
        asset: &Asset,
        utxo: &Utxo<C>,
    ) -> Option<VoidNumber<C>> {
        (&self.utxo(ephemeral_secret_key, &self.derive(secret_spend_key), asset) == utxo)
            .then(move || self.void_number(secret_spend_key, utxo))
    }
}

/// Transfer Full Parameters
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""))]
pub struct FullParameters<'p, C>
where
    C: Configuration,
{
    /// Base Parameters
    pub base: &'p Parameters<C>,

    /// UTXO Accumulator Model
    pub utxo_accumulator_model: &'p C::UtxoAccumulatorModel,
}

impl<'p, C> FullParameters<'p, C>
where
    C: Configuration,
{
    /// Builds a new [`FullParameters`] from `base` and `utxo_accumulator_model`.
    #[inline]
    pub fn new(
        base: &'p Parameters<C>,
        utxo_accumulator_model: &'p C::UtxoAccumulatorModel,
    ) -> Self {
        Self {
            base,
            utxo_accumulator_model,
        }
    }
}

impl<'p, C> AsRef<Parameters<C>> for FullParameters<'p, C>
where
    C: Configuration,
{
    #[inline]
    fn as_ref(&self) -> &Parameters<C> {
        self.base
    }
}

impl<'p, C> Deref for FullParameters<'p, C>
where
    C: Configuration,
{
    type Target = Parameters<C>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.base
    }
}

/// Transfer Full Parameters Variables
pub struct FullParametersVar<'p, C>
where
    C: Configuration,
{
    /// Key Agreement Scheme
    key_agreement: C::KeyAgreementSchemeVar,

    /// UTXO Commitment Scheme
    utxo_commitment: C::UtxoCommitmentSchemeVar,

    /// Void Number Commitment Scheme
    void_number_commitment: C::VoidNumberCommitmentSchemeVar,

    /// UTXO Accumulator Model
    utxo_accumulator_model: C::UtxoAccumulatorModelVar,

    /// Type Parameter Marker
    __: PhantomData<&'p ()>,
}

impl<'p, C> FullParametersVar<'p, C>
where
    C: Configuration,
{
    /// Derives a [`PublicKeyVar`] from `secret_key`.
    #[inline]
    fn derive(&self, secret_key: &SecretKeyVar<C>, compiler: &mut C::Compiler) -> PublicKeyVar<C> {
        self.key_agreement.derive(secret_key, compiler)
    }

    /// Computes the [`UtxoVar`] associated to `ephemeral_secret_key`, `public_spend_key`, and
    /// `asset`.
    #[inline]
    fn utxo(
        &self,
        ephemeral_secret_key: &SecretKeyVar<C>,
        public_spend_key: &PublicKeyVar<C>,
        asset: &AssetVar<C>,
        compiler: &mut C::Compiler,
    ) -> UtxoVar<C> {
        self.utxo_commitment
            .commit(ephemeral_secret_key, public_spend_key, asset, compiler)
    }

    /// Computes the [`VoidNumberVar`] associated to `secret_spend_key` and `utxo`.
    #[inline]
    fn void_number(
        &self,
        secret_spend_key: &SecretKeyVar<C>,
        utxo: &UtxoVar<C>,
        compiler: &mut C::Compiler,
    ) -> VoidNumberVar<C> {
        self.void_number_commitment
            .commit(secret_spend_key, utxo, compiler)
    }
}

impl<'p, C> Constant<C::Compiler> for FullParametersVar<'p, C>
where
    C: Configuration,
    Parameters<C>: 'p,
{
    type Type = FullParameters<'p, C>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
        Self {
            key_agreement: this
                .note_encryption_scheme
                .key_agreement_scheme
                .as_constant(compiler),
            utxo_commitment: this.utxo_commitment.as_constant(compiler),
            void_number_commitment: this.void_number_commitment.as_constant(compiler),
            utxo_accumulator_model: this.utxo_accumulator_model.as_constant(compiler),
            __: PhantomData,
        }
    }
}

/// Spending Key
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
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
    pub fn derive(&self, parameters: &C::KeyAgreementScheme) -> ReceivingKey<C> {
        ReceivingKey {
            spend: parameters.derive(&self.spend, &mut ()),
            view: parameters.derive(&self.view, &mut ()),
        }
    }

    /// Validates the `utxo` against `self` and the given `ephemeral_secret_key` and `asset`,
    /// returning the void number if the `utxo` is valid.
    #[inline]
    pub fn check_full_asset(
        &self,
        parameters: &Parameters<C>,
        ephemeral_secret_key: &SecretKey<C>,
        asset: &Asset,
        utxo: &Utxo<C>,
    ) -> Option<VoidNumber<C>> {
        parameters.check_full_asset(&self.spend, ephemeral_secret_key, asset, utxo)
    }

    /// Prepares `self` for spending `asset` with the given `ephemeral_secret_key`.
    #[inline]
    pub fn sender(
        &self,
        parameters: &Parameters<C>,
        ephemeral_secret_key: SecretKey<C>,
        asset: Asset,
    ) -> PreSender<C> {
        PreSender::new(parameters, self.spend.clone(), ephemeral_secret_key, asset)
    }

    /// Prepares `self` for receiving `asset`.
    #[inline]
    pub fn receiver(
        &self,
        parameters: &Parameters<C>,
        ephemeral_secret_key: SecretKey<C>,
        asset: Asset,
    ) -> Receiver<C> {
        self.derive(parameters.key_agreement_scheme())
            .into_receiver(parameters, ephemeral_secret_key, asset)
    }

    /// Returns an receiver-sender pair for internal transactions.
    #[inline]
    pub fn internal_pair(
        &self,
        parameters: &Parameters<C>,
        ephemeral_secret_key: SecretKey<C>,
        asset: Asset,
    ) -> (Receiver<C>, PreSender<C>) {
        let receiver = self.receiver(parameters, ephemeral_secret_key.clone(), asset);
        let sender = self.sender(parameters, ephemeral_secret_key, asset);
        (receiver, sender)
    }

    /// Returns an receiver-sender pair of zeroes for internal transactions.
    #[inline]
    pub fn internal_zero_pair(
        &self,
        parameters: &Parameters<C>,
        ephemeral_secret_key: SecretKey<C>,
        asset_id: AssetId,
    ) -> (Receiver<C>, PreSender<C>) {
        self.internal_pair(parameters, ephemeral_secret_key, Asset::zero(asset_id))
    }
}

impl<C, D> Sample<D> for SpendingKey<C>
where
    C: Configuration,
    D: Clone,
    SecretKey<C>: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(
            Sample::sample(distribution.clone(), rng),
            Sample::sample(distribution, rng),
        )
    }
}

/// Receiving Key
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "PublicKey<C>: Deserialize<'de>",
            serialize = "PublicKey<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = "PublicKey<C>: Copy"),
    Debug(bound = "PublicKey<C>: Debug"),
    Eq(bound = "PublicKey<C>: Eq"),
    Hash(bound = "PublicKey<C>: Hash"),
    PartialEq(bound = "PublicKey<C>: PartialEq")
)]
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
    pub fn into_receiver(
        self,
        parameters: &Parameters<C>,
        ephemeral_secret_key: SecretKey<C>,
        asset: Asset,
    ) -> Receiver<C> {
        Receiver::new(
            parameters,
            self.spend,
            self.view,
            ephemeral_secret_key,
            asset,
        )
    }
}

/// Note
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "SecretKey<C>: Clone"),
    Copy(bound = "SecretKey<C>: Copy"),
    Debug(bound = "SecretKey<C>: Debug"),
    Eq(bound = "SecretKey<C>: Eq"),
    Hash(bound = "SecretKey<C>: Hash"),
    PartialEq(bound = "SecretKey<C>: PartialEq")
)]
pub struct Note<C>
where
    C: Configuration + ?Sized,
{
    /// Ephemeral Secret Key
    pub ephemeral_secret_key: SecretKey<C>,

    /// Asset
    pub asset: Asset,
}

impl<C> Note<C>
where
    C: Configuration,
{
    /// Builds a new plaintext [`Note`] from `ephemeral_secret_key` and `asset`.
    #[inline]
    pub fn new(ephemeral_secret_key: SecretKey<C>, asset: Asset) -> Self {
        Self {
            ephemeral_secret_key,
            asset,
        }
    }
}

impl<C, SD, AD> Sample<(SD, AD)> for Note<C>
where
    C: Configuration,
    SecretKey<C>: Sample<SD>,
    Asset: Sample<AD>,
{
    #[inline]
    fn sample<R>(distribution: (SD, AD), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(
            Sample::sample(distribution.0, rng),
            Sample::sample(distribution.1, rng),
        )
    }
}

impl<C> SizeLimit for Note<C>
where
    C: Configuration,
{
    const SIZE: usize = SecretKey::<C>::SIZE + Asset::SIZE;
}

*/

/// Configuration
pub trait Configuration {
    /// Compiler Type
    type Compiler: Assert;

    /// Asset Id Type
    type AssetId;

    /// Asset Value Type
    type AssetValue;

    /// Unspent Transaction Output Type
    type Utxo: PartialEq;

    /// Nullifier Type
    type Nullifier: PartialEq;

    /// Authorization Signature Randomness
    type AuthorizationSignatureRandomness: Sample;

    /// Authorization Signature Scheme
    type AuthorizationSignatureScheme: signature::Sign<
            Randomness = Self::AuthorizationSignatureRandomness,
            Message = TransferPostBody<Self>,
        > + signature::Verify<VerifyingKey = Authorization<Self>, Verification = bool>
        + VerifyAuthorization<
            Authorization = Authorization<Self>,
            VerifyingKey = AuthorizationSigningKey<Self>,
        >;

    /// Parameters Type
    type Parameters: utxo::AssetType<Asset = Asset<Self>>
        + utxo::UtxoType<Utxo = Self::Utxo>
        + Mint
        + Spend<Nullifier = Self::Nullifier>;

    /// Authority Variable Type
    type AuthorityVar: Variable<Secret, Self::Compiler, Type = Authority<Self>>;

    /// Authorization Variable Type
    type AuthorizationVar: Variable<Public, Self::Compiler, Type = Authorization<Self>>;

    /// Asset Id Variable Type
    type AssetIdVar: Variable<Secret, Self::Compiler, Type = Self::AssetId>
        + Variable<Public, Self::Compiler, Type = Self::AssetId>
        + constraint::PartialEq<Self::AssetIdVar, Self::Compiler>;

    /// Asset Value Variable Type
    type AssetValueVar: Variable<Secret, Self::Compiler, Type = Self::AssetValue>
        + Variable<Public, Self::Compiler, Type = Self::AssetValue>
        + Add<Self::AssetValueVar, Self::Compiler, Output = Self::AssetValueVar>
        + constraint::PartialEq<Self::AssetValueVar, Self::Compiler>;

    /// Unspent Transaction Output Variable Type
    type UtxoVar: Variable<Secret, Self::Compiler, Type = Self::Utxo>
        + Variable<Public, Self::Compiler, Type = Self::Utxo>;

    /// Note Variable Type
    type NoteVar: Variable<Public, Self::Compiler, Type = <Self::Parameters as Mint>::Note>;

    /// Nullifier Variable Type
    type NullifierVar: Variable<Public, Self::Compiler, Type = Self::Nullifier>;

    /// UTXO Accumulator Witness Variable Type
    type UtxoAccumulatorWitnessVar: Variable<
        Secret,
        Self::Compiler,
        Type = UtxoAccumulatorWitness<Self>,
    >;

    /// UTXO Accumulator Output Variable Type
    type UtxoAccumulatorOutputVar: Variable<
        Public,
        Self::Compiler,
        Type = UtxoAccumulatorOutput<Self>,
    >;

    /// UTXO Accumulator Model Variable Type
    type UtxoAccumulatorModelVar: Constant<Self::Compiler, Type = UtxoAccumulatorModel<Self>>
        + accumulator::Model<
            Self::Compiler,
            Witness = Self::UtxoAccumulatorWitnessVar,
            Output = Self::UtxoAccumulatorOutputVar,
        >;

    /// Mint Secret Variable Type
    type MintSecret: Variable<Secret, Self::Compiler, Type = <Self::Parameters as Mint>::Secret>;

    /// Spend Secret Variable Type
    type SpendSecret: Variable<Secret, Self::Compiler, Type = <Self::Parameters as Spend>::Secret>;

    /// Parameters Variable Type
    type ParametersVar: Constant<Self::Compiler, Type = Self::Parameters>
        + utxo::AssetType<Asset = AssetVar<Self>>
        + utxo::UtxoType<Utxo = Self::UtxoVar>
        + Mint<Self::Compiler, Secret = Self::MintSecret, Note = Self::NoteVar>
        + Spend<
            Self::Compiler,
            Authority = Self::AuthorityVar,
            Authorization = Self::AuthorizationVar,
            UtxoAccumulatorModel = Self::UtxoAccumulatorModelVar,
            Secret = Self::SpendSecret,
            Nullifier = Self::NullifierVar,
        >;

    /// Proof System Type
    type ProofSystem: ProofSystem<Compiler = Self::Compiler>
        + ProofSystemInput<Authorization<Self>>
        + ProofSystemInput<Self::AssetId>
        + ProofSystemInput<Self::AssetValue>
        + ProofSystemInput<UtxoAccumulatorOutput<Self>>
        + ProofSystemInput<Utxo<Self::Parameters>>
        + ProofSystemInput<Note<Self::Parameters>>
        + ProofSystemInput<Nullifier<Self::Parameters>>;
}

/// Transfer Compiler Type
pub type Compiler<C> = <C as Configuration>::Compiler;

/// Transfer Proof System Type
type ProofSystemType<C> = <C as Configuration>::ProofSystem;

/// Transfer Proof System Error Type
pub type ProofSystemError<C> = <ProofSystemType<C> as ProofSystem>::Error;

/// Transfer Proof System Public Parameters Type
pub type ProofSystemPublicParameters<C> = <ProofSystemType<C> as ProofSystem>::PublicParameters;

/// Transfer Proving Context Type
pub type ProvingContext<C> = <ProofSystemType<C> as ProofSystem>::ProvingContext;

/// Transfer Verifying Context Type
pub type VerifyingContext<C> = <ProofSystemType<C> as ProofSystem>::VerifyingContext;

/// Transfer Proof System Input Type
pub type ProofInput<C> = <ProofSystemType<C> as ProofSystem>::Input;

/// Transfer Validity Proof Type
pub type Proof<C> = <ProofSystemType<C> as ProofSystem>::Proof;

/// Transfer Parameters Type
pub type Parameters<C> = <C as Configuration>::Parameters;

/// Transfer Parameters Variable Type
pub type ParametersVar<C> = <C as Configuration>::ParametersVar;

/// Transfer Full Parameters Type
pub type FullParameters<'p, C> = utxo::FullParameters<'p, Parameters<C>>;

/// Transfer Full Parameters Variable Type
pub type FullParametersVar<'p, C> = utxo::FullParameters<'p, ParametersVar<C>, Compiler<C>>;

/// Transfer Full Parameters Reference Type
pub type FullParametersRef<'p, C> = utxo::FullParametersRef<'p, Parameters<C>>;

/// Transfer Full Parameters Reference Variable Type
pub type FullParametersRefVar<'p, C> = utxo::FullParametersRef<'p, ParametersVar<C>, Compiler<C>>;

/// Transfer UTXO Accumulator Model Type
pub type UtxoAccumulatorModel<C> = utxo::UtxoAccumulatorModel<Parameters<C>>;

/// Transfer UTXO Accumulator Model Variable Type
pub type UtxoAccumulatorModelVar<C> = utxo::UtxoAccumulatorModel<ParametersVar<C>, Compiler<C>>;

/// Transfer UTXO Accumulator Witness Type
pub type UtxoAccumulatorWitness<C> = utxo::UtxoAccumulatorWitness<Parameters<C>>;

/// Transfer UTXO Accumulator Output Type
pub type UtxoAccumulatorOutput<C> = utxo::UtxoAccumulatorOutput<Parameters<C>>;

/// Transfer Asset Type
pub type Asset<C> = asset::Asset<<C as Configuration>::AssetId, <C as Configuration>::AssetValue>;

/// Transfer Asset Variable Type
pub type AssetVar<C> =
    asset::Asset<<C as Configuration>::AssetIdVar, <C as Configuration>::AssetValueVar>;

/// Transfer Authority Type
pub type Authority<C> = utxo::Authority<Parameters<C>>;

/// Transfer Authority Variable Type
pub type AuthorityVar<C> = utxo::Authority<ParametersVar<C>>;

/// Transfer Authorization Type
pub type Authorization<C> = utxo::Authorization<Parameters<C>>;

/// Transfer Authorization Variable Type
pub type AuthorizationVar<C> = utxo::Authorization<ParametersVar<C>>;

/// Transfer Authorization Proof Type
pub type AuthorizationProof<C> = utxo::AuthorizationProof<Parameters<C>>;

/// Transfer Authorization Proof Variable Type
pub type AuthorizationProofVar<C> = utxo::AuthorizationProof<ParametersVar<C>>;

/// Transfer Authorization Signing Key Type
pub type AuthorizationSigningKey<C> =
    signature::SigningKey<<C as Configuration>::AuthorizationSignatureScheme>;

/// Transfer Authorization Signature Type
pub type AuthorizationSignature<C> =
    signature::Signature<<C as Configuration>::AuthorizationSignatureScheme>;

/// Transfer Pre-Sender Type
pub type PreSender<C> = sender::PreSender<Parameters<C>>;

/// Transfer Sender Type
pub type Sender<C> = sender::Sender<Parameters<C>>;

/// Transfer Sender Variable Type
pub type SenderVar<C> = sender::Sender<ParametersVar<C>, Compiler<C>>;

/// Transfer Sender Post Type
pub type SenderPost<C> = sender::SenderPost<Parameters<C>>;

/// Transfer Receiver Type
pub type Receiver<C> = receiver::Receiver<Parameters<C>>;

/// Transfer Receiver Variable Type
pub type ReceiverVar<C> = receiver::Receiver<ParametersVar<C>, Compiler<C>>;

/// Transfer Receiver Post Type
pub type ReceiverPost<C> = receiver::ReceiverPost<Parameters<C>>;

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
    /// Authorization Proof
    authorization_proof: Option<AuthorizationProof<C>>,

    /// Asset Id
    asset_id: Option<C::AssetId>,

    /// Sources
    sources: [C::AssetValue; SOURCES],

    /// Senders
    senders: [Sender<C>; SENDERS],

    /// Receivers
    receivers: [Receiver<C>; RECEIVERS],

    /// Sinks
    sinks: [C::AssetValue; SINKS],
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Builds a new [`Transfer`] from its component parts.
    #[inline]
    pub fn new(
        authorization_proof: impl Into<Option<AuthorizationProof<C>>>,
        asset_id: impl Into<Option<C::AssetId>>,
        sources: [C::AssetValue; SOURCES],
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
        sinks: [C::AssetValue; SINKS],
    ) -> Self {
        let authorization_proof = authorization_proof.into();
        let asset_id = asset_id.into();
        Self::check_shape(authorization_proof.is_some(), asset_id.is_some());
        Self::new_unchecked(
            authorization_proof,
            asset_id,
            sources,
            senders,
            receivers,
            sinks,
        )
    }

    /// Checks that the [`Transfer`] has a valid shape.
    #[inline]
    pub fn check_shape(has_authorization_proof: bool, has_visible_asset_id: bool) {
        Self::has_nonempty_input_shape();
        Self::has_nonempty_output_shape();
        Self::has_authorization_proof_when_required(has_authorization_proof);
        Self::has_visible_asset_id_when_required(has_visible_asset_id);
    }

    /// Checks that the input side of the transfer is not empty.
    #[inline]
    pub fn has_nonempty_input_shape() {
        assert_ne!(
            SOURCES + SENDERS,
            0,
            "Not enough participants on the input side."
        );
    }

    /// Checks that the output side of the transfer is not empty.
    #[inline]
    pub fn has_nonempty_output_shape() {
        assert_ne!(
            RECEIVERS + SINKS,
            0,
            "Not enough participants on the output side."
        );
    }

    /// Checks that the given `authorization_proof` for [`Transfer`] building is present exactly
    /// when required.
    #[inline]
    pub fn has_authorization_proof_when_required(has_authorization_proof: bool) {
        if SENDERS > 0 {
            assert!(
                has_authorization_proof,
                "Missing authorization proof when required."
            );
        } else {
            assert!(
                !has_authorization_proof,
                "Given authorization proof when not required."
            );
        }
    }

    /// Checks that the given `asset_id` for [`Transfer`] building is visible exactly when required.
    #[inline]
    pub fn has_visible_asset_id_when_required(has_visible_asset_id: bool) {
        if has_public_participants(SOURCES, SINKS) {
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
        authorization_proof: Option<AuthorizationProof<C>>,
        asset_id: Option<C::AssetId>,
        sources: [C::AssetValue; SOURCES],
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
        sinks: [C::AssetValue; SINKS],
    ) -> Self {
        Self {
            authorization_proof,
            asset_id,
            sources,
            senders,
            receivers,
            sinks,
        }
    }

    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        let mut input = Default::default();
        if let Some(authorization_proof) = &self.authorization_proof {
            authorization_proof.extend_input::<C::ProofSystem>(&mut input);
        }
        if let Some(asset_id) = &self.asset_id {
            C::ProofSystem::extend(&mut input, asset_id);
        }
        self.sources
            .iter()
            .for_each(|source| C::ProofSystem::extend(&mut input, source));
        self.senders
            .iter()
            .for_each(|sender| sender.extend_input::<C::ProofSystem>(&mut input));
        self.receivers
            .iter()
            .for_each(|receiver| receiver.extend_input::<C::ProofSystem>(&mut input));
        self.sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(&mut input, sink));
        input
    }

    /// Builds a constraint system which asserts constraints against unknown variables.
    #[inline]
    pub fn unknown_constraints(parameters: FullParametersRef<C>) -> C::Compiler {
        let mut compiler = C::ProofSystem::context_compiler();
        TransferVar::<C, SOURCES, SENDERS, RECEIVERS, SINKS>::new_unknown(&mut compiler)
            .build_validity_constraints(&parameters.as_constant(&mut compiler), &mut compiler);
        compiler
    }

    /// Builds a constraint system which asserts constraints against known variables.
    #[inline]
    pub fn known_constraints(&self, parameters: FullParametersRef<C>) -> C::Compiler {
        let mut compiler = C::ProofSystem::proof_compiler();
        let transfer: TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS> =
            self.as_known(&mut compiler);
        transfer.build_validity_constraints(&parameters.as_constant(&mut compiler), &mut compiler);
        compiler
    }

    /// Generates a proving and verifying context for this transfer shape.
    #[inline]
    pub fn generate_context<R>(
        public_parameters: &ProofSystemPublicParameters<C>,
        parameters: FullParametersRef<C>,
        rng: &mut R,
    ) -> Result<(ProvingContext<C>, VerifyingContext<C>), ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        C::ProofSystem::compile(
            public_parameters,
            Self::unknown_constraints(parameters),
            rng,
        )
    }

    /// Converts `self` into its [`TransferPostBody`] by building the [`Transfer`] validity proof.
    #[inline]
    pub fn into_post_body<R>(
        self,
        parameters: FullParametersRef<C>,
        proving_context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPostBody<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Ok(TransferPostBody {
            validity_proof: C::ProofSystem::prove(
                proving_context,
                self.known_constraints(parameters),
                rng,
            )?,
            authorization: self.authorization_proof.map(|p| p.authorization),
            asset_id: self.asset_id,
            sources: self.sources.into(),
            sender_posts: self
                .senders
                .into_iter()
                .map(Sender::<C>::into_post)
                .collect(),
            receiver_posts: self
                .receivers
                .into_iter()
                .map(Receiver::<C>::into_post)
                .collect(),
            sinks: self.sinks.into(),
        })
    }
}

/// Transfer Variable
struct TransferVar<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    C: Configuration,
{
    /// Authorization Proof
    authorization_proof: Option<AuthorizationProofVar<C>>,

    /// Asset Id
    asset_id: Option<C::AssetIdVar>,

    /// Sources
    sources: Vec<C::AssetValueVar>,

    /// Senders
    senders: Vec<SenderVar<C>>,

    /// Receivers
    receivers: Vec<ReceiverVar<C>>,

    /// Sinks
    sinks: Vec<C::AssetValueVar>,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Builds constraints for the [`Transfer`] validity proof.
    #[inline]
    fn build_validity_constraints(
        self,
        parameters: &FullParametersVar<C>,
        compiler: &mut C::Compiler,
    ) {
        let mut secret_asset_ids = Vec::with_capacity(SENDERS + RECEIVERS);
        let input_sum = Self::input_sum(
            parameters,
            &mut secret_asset_ids,
            self.authorization_proof,
            self.senders,
            self.sources,
            compiler,
        );
        let output_sum = Self::output_sum(
            parameters,
            &mut secret_asset_ids,
            self.receivers,
            self.sinks,
            compiler,
        );
        compiler.assert_eq(&input_sum, &output_sum);
        match self.asset_id {
            Some(asset_id) => compiler.assert_all_eq_to_base(&asset_id, secret_asset_ids.iter()),
            _ => compiler.assert_all_eq(secret_asset_ids.iter()),
        }
    }

    /// Computes the sum over all the input assets, asserting that they are all well-formed.
    #[inline]
    fn input_sum(
        parameters: &FullParametersVar<C>,
        secret_asset_ids: &mut Vec<C::AssetIdVar>,
        authorization_proof: Option<AuthorizationProofVar<C>>,
        senders: Vec<SenderVar<C>>,
        sources: Vec<C::AssetValueVar>,
        compiler: &mut C::Compiler,
    ) -> C::AssetValueVar {
        if let Some(authorization_proof) = authorization_proof {
            authorization_proof.assert_valid(&parameters.base, compiler);
            Self::value_sum(
                senders
                    .into_iter()
                    .map(|s| {
                        let asset = s.well_formed_asset(
                            &parameters.base,
                            &parameters.utxo_accumulator_model,
                            &authorization_proof.authority,
                            compiler,
                        );
                        secret_asset_ids.push(asset.id);
                        asset.value
                    })
                    .chain(sources)
                    .collect::<Vec<_>>(),
                compiler,
            )
        } else {
            Self::value_sum(sources, compiler)
        }
    }

    /// Computes the sum over all the output assets, asserting that they are all well-formed.
    #[inline]
    fn output_sum(
        parameters: &FullParametersVar<C>,
        secret_asset_ids: &mut Vec<C::AssetIdVar>,
        receivers: Vec<ReceiverVar<C>>,
        sinks: Vec<C::AssetValueVar>,
        compiler: &mut C::Compiler,
    ) -> C::AssetValueVar {
        Self::value_sum(
            receivers
                .into_iter()
                .map(|r| {
                    let asset = r.well_formed_asset(&parameters.base, compiler);
                    secret_asset_ids.push(asset.id);
                    asset.value
                })
                .chain(sinks)
                .collect::<Vec<_>>(),
            compiler,
        )
    }

    /// Computes the sum of the asset values over `iter`.
    #[inline]
    fn value_sum<I>(iter: I, compiler: &mut C::Compiler) -> C::AssetValueVar
    where
        I: IntoIterator<Item = C::AssetValueVar>,
    {
        // TODO: Add a `Sum` trait for `compiler` and just do a sum here.
        iter.into_iter()
            .reduce(move |l, r| Add::add(l, r, compiler))
            .unwrap()
    }
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Variable<Derived, C::Compiler> for TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    type Type = Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>;

    #[inline]
    fn new_unknown(compiler: &mut C::Compiler) -> Self {
        Self {
            authorization_proof: (SENDERS > 0)
                .then(|| compiler.allocate_unknown::<Derived<(Secret, Public)>, _>()),
            asset_id: has_public_participants(SOURCES, SINKS)
                .then(|| compiler.allocate_unknown::<Public, _>()),
            sources: (0..SOURCES)
                .into_iter()
                .map(|_| compiler.allocate_unknown::<Public, _>())
                .collect(),
            senders: (0..SENDERS)
                .into_iter()
                .map(|_| compiler.allocate_unknown())
                .collect(),
            receivers: (0..RECEIVERS)
                .into_iter()
                .map(|_| compiler.allocate_unknown())
                .collect(),
            sinks: (0..SINKS)
                .into_iter()
                .map(|_| compiler.allocate_unknown::<Public, _>())
                .collect(),
        }
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
        Self {
            authorization_proof: this
                .authorization_proof
                .as_ref()
                .map(|proof| proof.as_known::<Derived<(Secret, Public)>, _>(compiler)),
            asset_id: this
                .asset_id
                .as_ref()
                .map(|id| id.as_known::<Public, _>(compiler)),
            sources: this
                .sources
                .iter()
                .map(|source| source.as_known::<Public, _>(compiler))
                .collect(),
            senders: this
                .senders
                .iter()
                .map(|sender| sender.as_known(compiler))
                .collect(),
            receivers: this
                .receivers
                .iter()
                .map(|receiver| receiver.as_known(compiler))
                .collect(),
            sinks: this
                .sinks
                .iter()
                .map(|sink| sink.as_known::<Public, _>(compiler))
                .collect(),
        }
    }
}

/// Transfer Ledger
///
/// This is the validation trait for ensuring that a particular instance of [`Transfer`] is valid
/// according to the ledger state. These methods are the minimum required for a ledger which accepts
/// the [`Transfer`] abstraction. This `trait` inherits from [`SenderLedger`] and [`ReceiverLedger`]
/// which validate the [`Sender`] and [`Receiver`] parts of any [`Transfer`]. See their
/// documentation for more.
pub trait TransferLedger<C>:
    SenderLedger<
        Parameters<C>,
        SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>),
    > + ReceiverLedger<
        Parameters<C>,
        SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>),
    >
where
    C: Configuration + ?Sized,
{
    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`TransferLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Account Identifier
    type AccountId;

    /// Ledger Event
    type Event;

    /// State Update Error
    ///
    /// This error type is used if the ledger can fail when updating the public state. The
    /// [`update_public_balances`](Self::update_public_balances) method uses this error type to
    /// track this condition.
    type UpdateError;

    /// Valid [`AssetValue`](Configuration::AssetValue) for [`TransferPost`] Source
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation of
    /// [`TransferLedger`].
    type ValidSourceAccount: AsRef<C::AssetValue>;

    /// Valid [`AssetValue`](Configuration::AssetValue) for [`TransferPost`] Sink
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation of
    /// [`TransferLedger`].
    type ValidSinkAccount: AsRef<C::AssetValue>;

    /// Valid [`Proof`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation
    /// of [`TransferLedger`]. This is to prevent that [`SenderPostingKey::post`] and
    /// [`ReceiverPostingKey::post`] are called before [`SenderPost::validate`],
    /// [`ReceiverPost::validate`], [`check_source_accounts`](Self::check_source_accounts),
    /// [`check_sink_accounts`](Self::check_sink_accounts) and [`is_valid`](Self::is_valid).
    type ValidProof: Copy;

    /// Checks that the balances associated to the source accounts are sufficient to withdraw the
    /// amount given in `sources`.
    fn check_source_accounts<I>(
        &self,
        asset_id: &C::AssetId,
        sources: I,
    ) -> Result<Vec<Self::ValidSourceAccount>, InvalidSourceAccount<C, Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, C::AssetValue)>;

    /// Checks that the sink accounts exist and balance can be increased by the specified amounts.
    fn check_sink_accounts<I>(
        &self,
        asset_id: &C::AssetId,
        sinks: I,
    ) -> Result<Vec<Self::ValidSinkAccount>, InvalidSinkAccount<C, Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, C::AssetValue)>;

    /// Checks that the transfer `proof` is valid.
    fn is_valid(
        &self,
        posting_key: TransferPostingKeyRef<C, Self>,
    ) -> Option<(Self::ValidProof, Self::Event)>;

    /// Updates the public balances in the ledger, finishing the transaction.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `proof` is a valid proof and that
    /// `senders` and `receivers` are valid participants in the transaction. See
    /// [`is_valid`](Self::is_valid) for more.
    fn update_public_balances(
        &mut self,
        super_key: &TransferLedgerSuperPostingKey<C, Self>,
        asset_id: C::AssetId,
        sources: Vec<SourcePostingKey<C, Self>>,
        sinks: Vec<SinkPostingKey<C, Self>>,
        proof: Self::ValidProof,
    ) -> Result<(), Self::UpdateError>;
}

/// Transfer Source Posting Key Type
pub type SourcePostingKey<C, L> = <L as TransferLedger<C>>::ValidSourceAccount;

/// Transfer Sink Posting Key Type
pub type SinkPostingKey<C, L> = <L as TransferLedger<C>>::ValidSinkAccount;

/// Transfer Sender Posting Key Type
pub type SenderPostingKey<C, L> = sender::SenderPostingKey<Parameters<C>, L>;

/// Transfer Receiver Posting Key Type
pub type ReceiverPostingKey<C, L> = receiver::ReceiverPostingKey<Parameters<C>, L>;

/// Transfer Ledger Super Posting Key Type
pub type TransferLedgerSuperPostingKey<C, L> = <L as TransferLedger<C>>::SuperPostingKey;

/// Invalid Authorization Signature Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidAuthorizationSignature {
    /// Missing Signature
    MissingSignature,

    /// Missing Authorization
    MissingAuthorization,

    /// Bad Signature
    BadSignature,
}

/// Invalid Source Accounts
///
/// This `struct` is the error state of the [`TransferLedger::check_source_accounts`] method. See
/// its documentation for more.
/* TODO:
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
*/
pub struct InvalidSourceAccount<C, AccountId>
where
    C: Configuration + ?Sized,
{
    /// Account Id
    pub account_id: AccountId,

    /// Asset Id
    pub asset_id: C::AssetId,

    /// Amount Attempting to Withdraw
    pub withdraw: C::AssetValue,
}

/// Invalid Sink Accounts
///
/// This `struct` is the error state of the [`TransferLedger::check_sink_accounts`] method. See its
/// documentation for more.
/* TODO:
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
*/
pub struct InvalidSinkAccount<C, AccountId>
where
    C: Configuration + ?Sized,
{
    /// Account Id
    pub account_id: AccountId,

    /// Asset Id
    pub asset_id: C::AssetId,

    /// Amount Attempting to Deposit
    pub deposit: C::AssetValue,
}

/// Transfer Post Error
///
/// This `enum` is the error state of the [`TransferPost::validate`] method. See its documentation
/// for more.
/* TODO:
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
*/
pub enum TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    /// Invalid Transfer Post Shape
    InvalidShape,

    /// Invalid Authorization Signature
    ///
    /// The authorization signature for the [`TransferPost`] was not valid.
    InvalidAuthorizationSignature(InvalidAuthorizationSignature),

    /// Invalid Source Accounts
    InvalidSourceAccount(InvalidSourceAccount<C, AccountId>),

    /// Invalid Sink Accounts
    InvalidSinkAccount(InvalidSinkAccount<C, AccountId>),

    /// Sender Post Error
    Sender(SenderPostError),

    /// Receiver Post Error
    Receiver(ReceiverPostError),

    /// Duplicate Spend Error
    DuplicateSpend,

    /// Duplicate Mint Error
    DuplicateMint,

    /// Invalid Transfer Proof Error
    ///
    /// Validity of the transfer could not be proved by the ledger.
    InvalidProof,

    /// Update Error
    ///
    /// An error occured while updating the ledger state.
    UpdateError(UpdateError),
}

impl<C, AccountId, UpdateError> From<InvalidAuthorizationSignature>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: InvalidAuthorizationSignature) -> Self {
        Self::InvalidAuthorizationSignature(err)
    }
}

impl<C, AccountId, UpdateError> From<InvalidSourceAccount<C, AccountId>>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: InvalidSourceAccount<C, AccountId>) -> Self {
        Self::InvalidSourceAccount(err)
    }
}

impl<C, AccountId, UpdateError> From<InvalidSinkAccount<C, AccountId>>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: InvalidSinkAccount<C, AccountId>) -> Self {
        Self::InvalidSinkAccount(err)
    }
}

impl<C, AccountId, UpdateError> From<sender::SenderPostError>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: sender::SenderPostError) -> Self {
        Self::Sender(err)
    }
}

impl<C, AccountId, UpdateError> From<receiver::ReceiverPostError>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: receiver::ReceiverPostError) -> Self {
        Self::Receiver(err)
    }
}

/// Transfer Post Body
/* TODO:
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                SenderPost<C>: Deserialize<'de>,
                ReceiverPost<C>: Deserialize<'de>,
                Proof<C>: Deserialize<'de>,
            ",
            serialize = r"
                SenderPost<C>: Serialize,
                ReceiverPost<C>: Serialize,
                Proof<C>: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "SenderPost<C>: Clone, ReceiverPost<C>: Clone, Proof<C>: Clone"),
    Debug(bound = "SenderPost<C>: Debug, ReceiverPost<C>: Debug, Proof<C>: Debug"),
    Eq(bound = "SenderPost<C>: Eq, ReceiverPost<C>: Eq, Proof<C>: Eq"),
    Hash(bound = "SenderPost<C>: Hash, ReceiverPost<C>: Hash, Proof<C>: Hash"),
    PartialEq(bound = "SenderPost<C>: PartialEq, ReceiverPost<C>: PartialEq, Proof<C>: PartialEq")
)]
*/
pub struct TransferPostBody<C>
where
    C: Configuration + ?Sized,
{
    /// Authorization
    pub authorization: Option<Authorization<C>>,

    /// Asset Id
    pub asset_id: Option<C::AssetId>,

    /// Sources
    pub sources: Vec<C::AssetValue>,

    /// Sender Posts
    pub sender_posts: Vec<SenderPost<C>>,

    /// Receiver Posts
    pub receiver_posts: Vec<ReceiverPost<C>>,

    /// Sinks
    pub sinks: Vec<C::AssetValue>,

    /// Validity Proof
    pub validity_proof: Proof<C>,
}

impl<C> TransferPostBody<C>
where
    C: Configuration + ?Sized,
{
    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        let mut input = Default::default();
        if let Some(authorization) = &self.authorization {
            C::ProofSystem::extend(&mut input, authorization);
        }
        if let Some(asset_id) = &self.asset_id {
            C::ProofSystem::extend(&mut input, asset_id);
        }
        self.sources
            .iter()
            .for_each(|source| C::ProofSystem::extend(&mut input, source));
        self.sender_posts
            .iter()
            .for_each(|post| post.extend_input::<C::ProofSystem>(&mut input));
        self.receiver_posts
            .iter()
            .for_each(|post| post.extend_input::<C::ProofSystem>(&mut input));
        self.sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(&mut input, sink));
        input
    }

    /// Verifies the validity proof of `self` according to the `verifying_context`.
    #[inline]
    pub fn has_valid_proof(
        &self,
        verifying_context: &VerifyingContext<C>,
    ) -> Result<bool, ProofSystemError<C>> {
        C::ProofSystem::verify(
            verifying_context,
            &self.generate_proof_input(),
            &self.validity_proof,
        )
    }

    /// Signs `self` with the authorization `signing_key`.
    #[inline]
    pub fn sign<R>(
        self,
        authorization_signature_scheme: &C::AuthorizationSignatureScheme,
        signing_key: &AuthorizationSigningKey<C>,
        rng: &mut R,
    ) -> Option<TransferPost<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        TransferPost::signed(authorization_signature_scheme, signing_key, self, rng)
    }
}

/// Transfer Post
/* TODO:
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                SenderPost<C>: Deserialize<'de>,
                ReceiverPost<C>: Deserialize<'de>,
                Proof<C>: Deserialize<'de>,
            ",
            serialize = r"
                SenderPost<C>: Serialize,
                ReceiverPost<C>: Serialize,
                Proof<C>: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "SenderPost<C>: Clone, ReceiverPost<C>: Clone, Proof<C>: Clone"),
    Debug(bound = "SenderPost<C>: Debug, ReceiverPost<C>: Debug, Proof<C>: Debug"),
    Eq(bound = "SenderPost<C>: Eq, ReceiverPost<C>: Eq, Proof<C>: Eq"),
    Hash(bound = "SenderPost<C>: Hash, ReceiverPost<C>: Hash, Proof<C>: Hash"),
    PartialEq(bound = "SenderPost<C>: PartialEq, ReceiverPost<C>: PartialEq, Proof<C>: PartialEq")
)]
*/
pub struct TransferPost<C>
where
    C: Configuration + ?Sized,
{
    /// Authorization Signature
    pub authorization_signature: Option<AuthorizationSignature<C>>,

    /// Transfer Post Body
    pub body: TransferPostBody<C>,
}

impl<C> TransferPost<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new signed [`TransferPost`].
    #[inline]
    pub fn signed<R>(
        authorization_signature_scheme: &C::AuthorizationSignatureScheme,
        signing_key: &AuthorizationSigningKey<C>,
        body: TransferPostBody<C>,
        rng: &mut R,
    ) -> Option<Self>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        if let Some(authorization) = &body.authorization {
            Some(Self::new_unchecked(
                sign_authorization(
                    authorization_signature_scheme,
                    signing_key,
                    authorization,
                    &rng.gen(),
                    &body,
                ),
                body,
            ))
        } else {
            None
        }
    }

    /// Builds a new unsigned [`TransferPost`].
    #[inline]
    pub fn unsigned(body: TransferPostBody<C>) -> Option<Self> {
        body.authorization
            .is_none()
            .then(|| Self::new_unchecked(None, body))
    }

    /// Builds a new [`TransferPost`] without checking the consistency conditions between the `body`
    /// and the `authorization_signature`.
    #[inline]
    pub fn new_unchecked(
        authorization_signature: Option<AuthorizationSignature<C>>,
        body: TransferPostBody<C>,
    ) -> Self {
        Self {
            authorization_signature,
            body,
        }
    }

    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        self.body.generate_proof_input()
    }

    /// Verifies the validity proof of `self` according to the `verifying_context`.
    #[inline]
    pub fn has_valid_proof(
        &self,
        verifying_context: &VerifyingContext<C>,
    ) -> Result<bool, ProofSystemError<C>> {
        self.body.has_valid_proof(verifying_context)
    }

    /// Verifies that the authorization signature for `self` is valid according to the
    /// `authorization_signature_scheme`.
    #[inline]
    pub fn has_valid_authorization_signature(
        &self,
        authorization_signature_scheme: &C::AuthorizationSignatureScheme,
    ) -> Result<(), InvalidAuthorizationSignature> {
        match (&self.authorization_signature, &self.body.authorization) {
            (Some(authorization_signature), Some(authorization)) => {
                if authorization_signature_scheme.verify(
                    authorization,
                    &self.body,
                    authorization_signature,
                    &mut (),
                ) {
                    Ok(())
                } else {
                    Err(InvalidAuthorizationSignature::BadSignature)
                }
            }
            (Some(_), None) => Err(InvalidAuthorizationSignature::MissingAuthorization),
            (None, Some(_)) => Err(InvalidAuthorizationSignature::MissingSignature),
            _ => Ok(()),
        }
    }

    /// Checks that the public participant data is well-formed and runs `ledger` validation on
    /// source and sink accounts.
    #[allow(clippy::type_complexity)] // FIXME: Use a better abstraction for this.
    #[inline]
    fn check_public_participants<L>(
        asset_id: &Option<C::AssetId>,
        source_accounts: Vec<L::AccountId>,
        source_values: Vec<C::AssetValue>,
        sink_accounts: Vec<L::AccountId>,
        sink_values: Vec<C::AssetValue>,
        ledger: &L,
    ) -> Result<
        (Vec<L::ValidSourceAccount>, Vec<L::ValidSinkAccount>),
        TransferPostError<C, L::AccountId, L::UpdateError>,
    >
    where
        L: TransferLedger<C>,
    {
        let sources = source_values.len();
        let sinks = sink_values.len();
        if has_public_participants(sources, sinks) != asset_id.is_some() {
            return Err(TransferPostError::InvalidShape);
        }
        if source_accounts.len() != sources {
            return Err(TransferPostError::InvalidShape);
        }
        if sink_accounts.len() != sinks {
            return Err(TransferPostError::InvalidShape);
        }
        let sources = if sources > 0 {
            ledger.check_source_accounts(
                asset_id.as_ref().unwrap(),
                source_accounts.into_iter().zip(source_values),
            )?
        } else {
            Vec::new()
        };
        let sinks = if sinks > 0 {
            ledger.check_sink_accounts(
                asset_id.as_ref().unwrap(),
                sink_accounts.into_iter().zip(sink_values),
            )?
        } else {
            Vec::new()
        };
        Ok((sources, sinks))
    }

    /// Validates `self` on the transfer `ledger`.
    #[allow(clippy::type_complexity)] // FIXME: Use a better abstraction for this.
    #[inline]
    pub fn validate<L>(
        self,
        authorization_signature_scheme: &C::AuthorizationSignatureScheme,
        ledger: &L,
        source_accounts: Vec<L::AccountId>,
        sink_accounts: Vec<L::AccountId>,
    ) -> Result<TransferPostingKey<C, L>, TransferPostError<C, L::AccountId, L::UpdateError>>
    where
        L: TransferLedger<C>,
    {
        self.has_valid_authorization_signature(authorization_signature_scheme)?;
        let (source_posting_keys, sink_posting_keys) = Self::check_public_participants(
            &self.body.asset_id,
            source_accounts,
            self.body.sources,
            sink_accounts,
            self.body.sinks,
            ledger,
        )?;
        if !all_unequal(&self.body.sender_posts, |p, q| p.nullifier == q.nullifier) {
            return Err(TransferPostError::DuplicateSpend);
        }
        if !all_unequal(&self.body.receiver_posts, |p, q| p.utxo == q.utxo) {
            return Err(TransferPostError::DuplicateMint);
        }
        let sender_posting_keys = self
            .body
            .sender_posts
            .into_iter()
            .map(move |s| s.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        let receiver_posting_keys = self
            .body
            .receiver_posts
            .into_iter()
            .map(move |r| r.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        let (validity_proof, event) = match ledger.is_valid(TransferPostingKeyRef {
            authorization: &self.body.authorization,
            asset_id: &self.body.asset_id,
            sources: &source_posting_keys,
            senders: &sender_posting_keys,
            receivers: &receiver_posting_keys,
            sinks: &sink_posting_keys,
            proof: self.body.validity_proof,
        }) {
            Some((validity_proof, event)) => (validity_proof, event),
            _ => return Err(TransferPostError::InvalidProof),
        };
        Ok(TransferPostingKey {
            asset_id: self.body.asset_id,
            source_posting_keys,
            sender_posting_keys,
            receiver_posting_keys,
            sink_posting_keys,
            validity_proof,
            event,
        })
    }

    /// Validates `self` on the transfer `ledger` and then posts the updated state to the `ledger`
    /// if validation succeeded.
    #[inline]
    pub fn post<L>(
        self,
        authorization_signature_scheme: &C::AuthorizationSignatureScheme,
        ledger: &mut L,
        super_key: &TransferLedgerSuperPostingKey<C, L>,
        source_accounts: Vec<L::AccountId>,
        sink_accounts: Vec<L::AccountId>,
    ) -> Result<L::Event, TransferPostError<C, L::AccountId, L::UpdateError>>
    where
        L: TransferLedger<C>,
    {
        self.validate(
            authorization_signature_scheme,
            ledger,
            source_accounts,
            sink_accounts,
        )?
        .post(ledger, super_key)
        .map_err(TransferPostError::UpdateError)
    }
}

/// Transfer Posting Key
pub struct TransferPostingKey<C, L>
where
    C: Configuration + ?Sized,
    L: TransferLedger<C>,
{
    /// Asset Id
    asset_id: Option<C::AssetId>,

    /// Source Posting Keys
    source_posting_keys: Vec<SourcePostingKey<C, L>>,

    /// Sender Posting Keys
    sender_posting_keys: Vec<SenderPostingKey<C, L>>,

    /// Receiver Posting Keys
    receiver_posting_keys: Vec<ReceiverPostingKey<C, L>>,

    /// Sink Posting Keys
    sink_posting_keys: Vec<SinkPostingKey<C, L>>,

    /// Validity Proof Posting Key
    validity_proof: L::ValidProof,

    /// Ledger Event
    event: L::Event,
}

impl<C, L> TransferPostingKey<C, L>
where
    C: Configuration + ?Sized,
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
    pub fn post(
        self,
        ledger: &mut L,
        super_key: &TransferLedgerSuperPostingKey<C, L>,
    ) -> Result<L::Event, L::UpdateError> {
        let proof = self.validity_proof;
        SenderPostingKey::<C, _>::post_all(self.sender_posting_keys, ledger, &(proof, *super_key));
        ReceiverPostingKey::<C, _>::post_all(
            self.receiver_posting_keys,
            ledger,
            &(proof, *super_key),
        );
        if let Some(asset_id) = self.asset_id {
            ledger.update_public_balances(
                super_key,
                asset_id,
                self.source_posting_keys,
                self.sink_posting_keys,
                proof,
            )?;
        }
        Ok(self.event)
    }
}

/// Transfer Posting Key Reference
pub struct TransferPostingKeyRef<'k, C, L>
where
    C: Configuration + ?Sized,
    L: TransferLedger<C> + ?Sized,
{
    /// Authorization
    pub authorization: &'k Option<Authorization<C>>,

    /// Asset Id
    pub asset_id: &'k Option<C::AssetId>,

    /// Sources
    pub sources: &'k [SourcePostingKey<C, L>],

    /// Senders
    pub senders: &'k [SenderPostingKey<C, L>],

    /// Receivers
    pub receivers: &'k [ReceiverPostingKey<C, L>],

    /// Sinks
    pub sinks: &'k [SinkPostingKey<C, L>],

    /// Proof
    pub proof: Proof<C>,
}

impl<'k, C, L> TransferPostingKeyRef<'k, C, L>
where
    C: Configuration + ?Sized,
    L: TransferLedger<C> + ?Sized,
{
    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        let mut input = Default::default();
        if let Some(authorization) = &self.authorization {
            C::ProofSystem::extend(&mut input, authorization);
        }
        if let Some(asset_id) = &self.asset_id {
            C::ProofSystem::extend(&mut input, asset_id);
        }
        self.sources
            .iter()
            .for_each(|source| C::ProofSystem::extend(&mut input, source.as_ref()));
        self.senders
            .iter()
            .for_each(|post| post.extend_input::<C::ProofSystem>(&mut input));
        self.receivers
            .iter()
            .for_each(|post| post.extend_input::<C::ProofSystem>(&mut input));
        self.sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(&mut input, sink.as_ref()));
        input
    }
}
