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
//! - Sender Abstraction: [`Sender`], [`SenderVar`], [`SenderPost`], [`SenderLedger`]
//! - Receiver Abstraction: [`Receiver`], [`ReceiverVar`], [`ReceiverPost`], [`ReceiverLedger`]
//! - Transfer Abstraction: [`Transfer`], [`TransferPost`], [`TransferLedger`]
//! - Canonical Transactions: [`canonical`]
//! - Batched Transactions: [`batch`]
//!
//! See the [`crate::wallet`] module for more on how this transfer protocol is used in a wallet
//! protocol for the keeping of accounts for private assets.

use crate::asset::{Asset, AssetId, AssetValue};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData, ops::Deref};
use manta_crypto::{
    accumulator::{self, AssertValidVerification, MembershipProof, Model},
    constraint::{HasInput, ProofSystem},
    eclair::{
        self,
        alloc::{
            mode::{Derived, Public, Secret},
            Allocate, Allocator, Constant, Variable,
        },
        bool::{AssertEq, Bool},
        ops::Add,
    },
    encryption::{self, hybrid::Hybrid, EncryptedMessage},
    key::{self, agreement::Derive},
    rand::{CryptoRng, RngCore, Sample},
};
use manta_util::SizeLimit;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

mod receiver;
mod sender;

pub mod batch;
pub mod canonical;

#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test;

pub use canonical::Shape;
pub use receiver::*;
pub use sender::*;

/// Returns `true` if the [`Transfer`] with this shape would have public participants.
#[inline]
pub const fn has_public_participants(sources: usize, sinks: usize) -> bool {
    (sources + sinks) > 0
}

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
        + eclair::cmp::PartialEq<Self::PublicKeyVar, Self::Compiler>;

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
        + eclair::cmp::PartialEq<Self::UtxoVar, Self::Compiler>;

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
        + eclair::cmp::PartialEq<Self::VoidNumberVar, Self::Compiler>;

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
        + eclair::cmp::PartialEq<Self::AssetIdVar, Self::Compiler>;

    /// Asset Value Variable Type
    type AssetValueVar: Variable<Public, Self::Compiler, Type = AssetValue>
        + Variable<Secret, Self::Compiler, Type = AssetValue>
        + Add<Self::AssetValueVar, Self::Compiler, Output = Self::AssetValueVar>
        + eclair::cmp::PartialEq<Self::AssetValueVar, Self::Compiler>;

    /// Constraint System Type
    type Compiler: AssertEq;

    /// Proof System Type
    type ProofSystem: ProofSystem<Compiler = Self::Compiler>
        + HasInput<AssetId>
        + HasInput<AssetValue>
        + HasInput<UtxoAccumulatorOutput<Self>>
        + HasInput<Utxo<Self>>
        + HasInput<VoidNumber<Self>>
        + HasInput<PublicKey<Self>>;

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
pub type UtxoAccumulatorWitness<C> =
    <<C as Configuration>::UtxoAccumulatorModel as accumulator::Types>::Witness;

/// UTXO Accumulator Output Type
pub type UtxoAccumulatorOutput<C> =
    <<C as Configuration>::UtxoAccumulatorModel as accumulator::Types>::Output;

/// UTXO Membership Proof Type
pub type UtxoMembershipProof<C> = MembershipProof<<C as Configuration>::UtxoAccumulatorModel>;

/// UTXO Membership Proof Variable Type
pub type UtxoMembershipProofVar<C> = MembershipProof<<C as Configuration>::UtxoAccumulatorModelVar>;

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
    receivers: [Receiver<C>; RECEIVERS],

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
    pub fn new(
        asset_id: impl Into<Option<AssetId>>,
        sources: [AssetValue; SOURCES],
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
        sinks: [AssetValue; SINKS],
    ) -> Self {
        let asset_id = asset_id.into();
        Self::check_shape(asset_id.is_some());
        Self::new_unchecked(asset_id, sources, senders, receivers, sinks)
    }

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
        self.senders
            .iter()
            .for_each(|sender| sender.extend_input(&mut input));
        self.receivers
            .iter()
            .for_each(|receiver| receiver.extend_input(&mut input));
        self.sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(&mut input, sink));
        input
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
        asset_id: Option<AssetId>,
        sources: [AssetValue; SOURCES],
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
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

    /// Builds a constraint system which asserts constraints against unknown variables.
    #[inline]
    pub fn unknown_constraints(parameters: FullParameters<C>) -> C::Compiler {
        let mut compiler = C::ProofSystem::context_compiler();
        TransferVar::<C, SOURCES, SENDERS, RECEIVERS, SINKS>::new_unknown(&mut compiler)
            .build_validity_constraints(&parameters.as_constant(&mut compiler), &mut compiler);
        compiler
    }

    /// Builds a constraint system which asserts constraints against known variables.
    #[inline]
    pub fn known_constraints(&self, parameters: FullParameters<C>) -> C::Compiler {
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
        parameters: FullParameters<C>,
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

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post<R>(
        self,
        parameters: FullParameters<C>,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Ok(TransferPost {
            validity_proof: C::ProofSystem::prove(
                context,
                self.known_constraints(parameters),
                rng,
            )?,
            asset_id: self.asset_id,
            sources: self.sources.into(),
            sender_posts: self.senders.into_iter().map(Sender::into_post).collect(),
            receiver_posts: self
                .receivers
                .into_iter()
                .map(Receiver::into_post)
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
        let input_sum = Self::value_sum(
            self.senders
                .into_iter()
                .map(|s| {
                    let asset = s.get_well_formed_asset(parameters, compiler);
                    secret_asset_ids.push(asset.id);
                    asset.value
                })
                .chain(self.sources)
                .collect::<Vec<_>>(),
            compiler,
        );
        let output_sum = Self::value_sum(
            self.receivers
                .into_iter()
                .map(|r| {
                    let asset = r.get_well_formed_asset(parameters, compiler);
                    secret_asset_ids.push(asset.id);
                    asset.value
                })
                .chain(self.sinks)
                .collect::<Vec<_>>(),
            compiler,
        );
        compiler.assert_eq(&input_sum, &output_sum);
        match self.asset_id {
            Some(asset_id) => compiler.assert_all_eq_to_base(&asset_id, secret_asset_ids.iter()),
            _ => compiler.assert_all_eq(secret_asset_ids.iter()),
        }
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
    fn new_known(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
        Self {
            asset_id: this.asset_id.map(|id| id.as_known::<Public, _>(compiler)),
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

    #[inline]
    fn new_unknown(compiler: &mut C::Compiler) -> Self {
        Self {
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
}

/// Transfer Ledger
///
/// This is the validation trait for ensuring that a particular instance of [`Transfer`] is valid
/// according to the ledger state. These methods are the minimum required for a ledger which accepts
/// the [`Transfer`] abstraction. This `trait` inherits from [`SenderLedger`] and [`ReceiverLedger`]
/// which validate the [`Sender`] and [`Receiver`] parts of any [`Transfer`]. See their
/// documentation for more.
pub trait TransferLedger<C>: SenderLedger<C, SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>)>
    + ReceiverLedger<C, SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>)>
where
    C: Configuration,
{
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

    /// Valid [`AssetValue`] for [`TransferPost`] Source
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation of
    /// [`TransferLedger`].
    type ValidSourceAccount: AsRef<AssetValue>;

    /// Valid [`AssetValue`] for [`TransferPost`] Sink
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation of
    /// [`TransferLedger`].
    type ValidSinkAccount: AsRef<AssetValue>;

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

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`TransferLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks that the balances associated to the source accounts are sufficient to withdraw the
    /// amount given in `sources`.
    fn check_source_accounts<I>(
        &self,
        asset_id: AssetId,
        sources: I,
    ) -> Result<Vec<Self::ValidSourceAccount>, InvalidSourceAccount<Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, AssetValue)>;

    /// Checks that the sink accounts exist and balance can be increased by the specified amounts.
    fn check_sink_accounts<I>(
        &self,
        asset_id: AssetId,
        sinks: I,
    ) -> Result<Vec<Self::ValidSinkAccount>, InvalidSinkAccount<Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, AssetValue)>;

    /// Checks that the transfer `proof` is valid.
    fn is_valid(
        &self,
        asset_id: Option<AssetId>,
        sources: &[SourcePostingKey<C, Self>],
        senders: &[SenderPostingKey<C, Self>],
        receivers: &[ReceiverPostingKey<C, Self>],
        sinks: &[SinkPostingKey<C, Self>],
        proof: Proof<C>,
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
        asset_id: AssetId,
        sources: Vec<SourcePostingKey<C, Self>>,
        sinks: Vec<SinkPostingKey<C, Self>>,
        proof: Self::ValidProof,
        super_key: &TransferLedgerSuperPostingKey<C, Self>,
    ) -> Result<(), Self::UpdateError>;
}

/// Transfer Source Posting Key Type
pub type SourcePostingKey<C, L> = <L as TransferLedger<C>>::ValidSourceAccount;

/// Transfer Sink Posting Key Type
pub type SinkPostingKey<C, L> = <L as TransferLedger<C>>::ValidSinkAccount;

/// Transfer Ledger Super Posting Key Type
pub type TransferLedgerSuperPostingKey<C, L> = <L as TransferLedger<C>>::SuperPostingKey;

/// Invalid Source Accounts
///
/// This `struct` is the error state of the [`TransferLedger::check_source_accounts`] method. See
/// its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InvalidSourceAccount<AccountId> {
    /// Account Id
    pub account_id: AccountId,

    /// Asset Id
    pub asset_id: AssetId,

    /// Amount Attempting to Withdraw
    pub withdraw: AssetValue,
}

/// Invalid Sink Accounts
///
/// This `struct` is the error state of the [`TransferLedger::check_sink_accounts`] method. See its
/// documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InvalidSinkAccount<AccountId> {
    /// Account Id
    pub account_id: AccountId,

    /// Asset Id
    pub asset_id: AssetId,

    /// Amount Attempting to Deposit
    pub deposit: AssetValue,
}

/// Transfer Post Error
///
/// This `enum` is the error state of the [`TransferPost::validate`] method. See its documentation
/// for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransferPostError<AccountId, UpdateError> {
    /// Invalid Transfer Post Shape
    InvalidShape,

    /// Invalid Source Accounts
    InvalidSourceAccount(InvalidSourceAccount<AccountId>),

    /// Invalid Sink Accounts
    InvalidSinkAccount(InvalidSinkAccount<AccountId>),

    /// Sender Post Error
    Sender(SenderPostError),

    /// Receiver Post Error
    Receiver(ReceiverPostError),

    /// Duplicate Spend Error
    DuplicateSpend,

    /// Duplicate Register Error
    DuplicateRegister,

    /// Invalid Transfer Proof Error
    ///
    /// Validity of the transfer could not be proved by the ledger.
    InvalidProof,

    /// Update Error
    ///
    /// An error occured while updating the ledger state.
    UpdateError(UpdateError),
}

impl<AccountId, UpdateError> From<InvalidSourceAccount<AccountId>>
    for TransferPostError<AccountId, UpdateError>
{
    #[inline]
    fn from(err: InvalidSourceAccount<AccountId>) -> Self {
        Self::InvalidSourceAccount(err)
    }
}

impl<AccountId, UpdateError> From<InvalidSinkAccount<AccountId>>
    for TransferPostError<AccountId, UpdateError>
{
    #[inline]
    fn from(err: InvalidSinkAccount<AccountId>) -> Self {
        Self::InvalidSinkAccount(err)
    }
}

impl<AccountId, UpdateError> From<SenderPostError> for TransferPostError<AccountId, UpdateError> {
    #[inline]
    fn from(err: SenderPostError) -> Self {
        Self::Sender(err)
    }
}

impl<AccountId, UpdateError> From<ReceiverPostError> for TransferPostError<AccountId, UpdateError> {
    #[inline]
    fn from(err: ReceiverPostError) -> Self {
        Self::Receiver(err)
    }
}

/// Transfer Post
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
pub struct TransferPost<C>
where
    C: Configuration,
{
    /// Asset Id
    pub asset_id: Option<AssetId>,

    /// Sources
    pub sources: Vec<AssetValue>,

    /// Sender Posts
    pub sender_posts: Vec<SenderPost<C>>,

    /// Receiver Posts
    pub receiver_posts: Vec<ReceiverPost<C>>,

    /// Sinks
    pub sinks: Vec<AssetValue>,

    /// Validity Proof
    pub validity_proof: Proof<C>,
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

    /// Checks that the public participant data is well-formed and runs `ledger` validation on
    /// source and sink accounts.
    #[allow(clippy::type_complexity)] // FIXME: Use a better abstraction for this.
    #[inline]
    fn check_public_participants<L>(
        asset_id: Option<AssetId>,
        source_accounts: Vec<L::AccountId>,
        source_values: Vec<AssetValue>,
        sink_accounts: Vec<L::AccountId>,
        sink_values: Vec<AssetValue>,
        ledger: &L,
    ) -> Result<
        (Vec<L::ValidSourceAccount>, Vec<L::ValidSinkAccount>),
        TransferPostError<L::AccountId, L::UpdateError>,
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
                asset_id.unwrap(),
                source_accounts.into_iter().zip(source_values),
            )?
        } else {
            Vec::new()
        };
        let sinks = if sinks > 0 {
            ledger.check_sink_accounts(
                asset_id.unwrap(),
                sink_accounts.into_iter().zip(sink_values),
            )?
        } else {
            Vec::new()
        };
        Ok((sources, sinks))
    }

    /// Validates `self` on the transfer `ledger`.
    #[inline]
    pub fn validate<L>(
        self,
        source_accounts: Vec<L::AccountId>,
        sink_accounts: Vec<L::AccountId>,
        ledger: &L,
    ) -> Result<TransferPostingKey<C, L>, TransferPostError<L::AccountId, L::UpdateError>>
    where
        L: TransferLedger<C>,
    {
        let (source_posting_keys, sink_posting_keys) = Self::check_public_participants(
            self.asset_id,
            source_accounts,
            self.sources,
            sink_accounts,
            self.sinks,
            ledger,
        )?;
        for (i, p) in self.sender_posts.iter().enumerate() {
            if self
                .sender_posts
                .iter()
                .skip(i + 1)
                .any(move |q| p.void_number == q.void_number)
            {
                return Err(TransferPostError::DuplicateSpend);
            }
        }
        for (i, p) in self.receiver_posts.iter().enumerate() {
            if self
                .receiver_posts
                .iter()
                .skip(i + 1)
                .any(move |q| p.utxo == q.utxo)
            {
                return Err(TransferPostError::DuplicateRegister);
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
        let (validity_proof, event) = match ledger.is_valid(
            self.asset_id,
            &source_posting_keys,
            &sender_posting_keys,
            &receiver_posting_keys,
            &sink_posting_keys,
            self.validity_proof,
        ) {
            Some((validity_proof, event)) => (validity_proof, event),
            _ => return Err(TransferPostError::InvalidProof),
        };
        Ok(TransferPostingKey {
            asset_id: self.asset_id,
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
        source_accounts: Vec<L::AccountId>,
        sink_accounts: Vec<L::AccountId>,
        super_key: &TransferLedgerSuperPostingKey<C, L>,
        ledger: &mut L,
    ) -> Result<L::Event, TransferPostError<L::AccountId, L::UpdateError>>
    where
        L: TransferLedger<C>,
    {
        self.validate(source_accounts, sink_accounts, ledger)?
            .post(super_key, ledger)
            .map_err(TransferPostError::UpdateError)
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

    /// Sink Posting Keys
    sink_posting_keys: Vec<SinkPostingKey<C, L>>,

    /// Validity Proof Posting Key
    validity_proof: L::ValidProof,

    /// Ledger Event
    event: L::Event,
}

impl<C, L> TransferPostingKey<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(
        asset_id: Option<AssetId>,
        sources: &[SourcePostingKey<C, L>],
        senders: &[SenderPostingKey<C, L>],
        receivers: &[ReceiverPostingKey<C, L>],
        sinks: &[SinkPostingKey<C, L>],
    ) -> ProofInput<C> {
        let mut input = Default::default();
        if let Some(asset_id) = asset_id {
            C::ProofSystem::extend(&mut input, &asset_id);
        }
        sources
            .iter()
            .for_each(|source| C::ProofSystem::extend(&mut input, source.as_ref()));
        senders
            .iter()
            .for_each(|post| post.extend_input(&mut input));
        receivers
            .iter()
            .for_each(|post| post.extend_input(&mut input));
        sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(&mut input, sink.as_ref()));
        input
    }

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
        super_key: &TransferLedgerSuperPostingKey<C, L>,
        ledger: &mut L,
    ) -> Result<L::Event, L::UpdateError> {
        let proof = self.validity_proof;
        SenderPostingKey::post_all(self.sender_posting_keys, &(proof, *super_key), ledger);
        ReceiverPostingKey::post_all(self.receiver_posting_keys, &(proof, *super_key), ledger);
        if let Some(asset_id) = self.asset_id {
            ledger.update_public_balances(
                asset_id,
                self.source_posting_keys,
                self.sink_posting_keys,
                proof,
                super_key,
            )?;
        }
        Ok(self.event)
    }
}
