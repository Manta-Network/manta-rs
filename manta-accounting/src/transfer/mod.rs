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
use core::{fmt::Debug, hash::Hash, iter, marker::PhantomData};
use manta_crypto::{
    accumulator::{Accumulator, MembershipProof, Model},
    commitment::CommitmentScheme,
    constraint::{
        Add, Allocator, Constant, ConstraintSystem, Derived, Equal, ProofSystem, ProofSystemInput,
        Public, Secret, ValueSource, Variable,
    },
    encryption::hybrid::{DecryptedMessage, EncryptedMessage, HybridPublicKeyEncryptionScheme},
    hash::BinaryHashFunction,
    key::KeyAgreementScheme,
    rand::{CryptoRng, RngCore, Sample},
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod batch;
pub mod canonical;

#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test;

#[doc(inline)]
pub use canonical::Shape;

/// Returns `true` if the [`Transfer`] with this shape would have public participants.
#[inline]
pub const fn has_public_participants(sources: usize, sinks: usize) -> bool {
    (sources + sinks) > 0
}

/// Transfer Configuration
pub trait Configuration {
    /// Secret Key Type
    type SecretKey: Clone + Sample;

    /// Public Key Type
    type PublicKey: Clone;

    /// Key Agreement Scheme Type
    type KeyAgreementScheme: KeyAgreementScheme<
        SecretKey = Self::SecretKey,
        PublicKey = Self::PublicKey,
    >;

    /// Secret Key Variable Type
    type SecretKeyVar: Variable<Secret, Self::Compiler, Type = SecretKey<Self>>;

    /// Public Key Variable Type
    type PublicKeyVar: Variable<Public, Self::Compiler, Type = PublicKey<Self>>
        + Variable<Secret, Self::Compiler, Type = PublicKey<Self>>
        + Equal<Self::Compiler>;

    /// Key Agreement Scheme Variable Type
    type KeyAgreementSchemeVar: KeyAgreementScheme<
            Self::Compiler,
            SecretKey = Self::SecretKeyVar,
            PublicKey = Self::PublicKeyVar,
        > + Constant<Self::Compiler, Type = Self::KeyAgreementScheme>;

    /// Unspent Transaction Output Type
    type Utxo: PartialEq;

    /// UTXO Commitment Scheme Type
    type UtxoCommitmentScheme: CommitmentScheme<
        Randomness = Trapdoor<Self>,
        Input = Asset,
        Output = Self::Utxo,
    >;

    /// UTXO Variable Type
    type UtxoVar: Variable<Public, Self::Compiler, Type = Self::Utxo>
        + Variable<Secret, Self::Compiler, Type = Self::Utxo>
        + Equal<Self::Compiler>;

    /// UTXO Commitment Scheme Variable Type
    type UtxoCommitmentSchemeVar: CommitmentScheme<
            Self::Compiler,
            Randomness = TrapdoorVar<Self>,
            Input = AssetVar<Self>,
            Output = Self::UtxoVar,
        > + Constant<Self::Compiler, Type = Self::UtxoCommitmentScheme>;

    /// Void Number Type
    type VoidNumber: PartialEq;

    /// Void Number Hash Function Type
    type VoidNumberHashFunction: BinaryHashFunction<
        Left = Self::Utxo,
        Right = Self::SecretKey,
        Output = Self::VoidNumber,
    >;

    /// Void Number Variable Type
    type VoidNumberVar: Variable<Public, Self::Compiler, Type = Self::VoidNumber>
        + Equal<Self::Compiler>;

    /// Void Number Hash Function Variable Type
    type VoidNumberHashFunctionVar: BinaryHashFunction<
            Self::Compiler,
            Left = Self::UtxoVar,
            Right = Self::SecretKeyVar,
            Output = Self::VoidNumberVar,
        > + Constant<Self::Compiler, Type = Self::VoidNumberHashFunction>;

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
    type UtxoAccumulatorModelVar: Model<
            Self::Compiler,
            Item = Self::UtxoVar,
            Witness = Self::UtxoAccumulatorWitnessVar,
            Output = Self::UtxoAccumulatorOutputVar,
            Verification = <Self::Compiler as ConstraintSystem>::Bool,
        > + Constant<Self::Compiler, Type = Self::UtxoAccumulatorModel>;

    /// Asset Id Variable Type
    type AssetIdVar: Variable<Public, Self::Compiler, Type = AssetId>
        + Variable<Secret, Self::Compiler, Type = AssetId>
        + Equal<Self::Compiler>;

    /// Asset Value Variable Type
    type AssetValueVar: Variable<Public, Self::Compiler, Type = AssetValue>
        + Variable<Secret, Self::Compiler, Type = AssetValue>
        + Add<Self::Compiler>
        + Equal<Self::Compiler>;

    /// Constraint System Type
    type Compiler: ConstraintSystem;

    /// Proof System Type
    type ProofSystem: ProofSystem<ConstraintSystem = Self::Compiler>
        + ProofSystemInput<AssetId>
        + ProofSystemInput<AssetValue>
        + ProofSystemInput<UtxoAccumulatorOutput<Self>>
        + ProofSystemInput<Utxo<Self>>
        + ProofSystemInput<VoidNumber<Self>>
        + ProofSystemInput<PublicKey<Self>>;

    /// Note Encryption Scheme Type
    type NoteEncryptionScheme: HybridPublicKeyEncryptionScheme<
        Plaintext = Asset,
        KeyAgreementScheme = Self::KeyAgreementScheme,
    >;

    /// Derives a public key variable from a secret key variable.
    #[inline]
    fn ephemeral_public_key_var(
        parameters: &Self::KeyAgreementSchemeVar,
        secret_key: &SecretKeyVar<Self>,
        compiler: &mut Self::Compiler,
    ) -> PublicKeyVar<Self> {
        parameters.derive_in(secret_key, compiler)
    }

    /// Generates the commitment trapdoor associated to `secret_key` and `public_key`.
    #[inline]
    fn trapdoor(
        key_agreement: &Self::KeyAgreementScheme,
        secret_key: &SecretKey<Self>,
        public_key: &PublicKey<Self>,
    ) -> Trapdoor<Self> {
        key_agreement.agree(secret_key, public_key)
    }

    /// Generates the commitment trapdoor associated to `secret_key` and `public_key`.
    #[inline]
    fn trapdoor_var(
        key_agreement: &Self::KeyAgreementSchemeVar,
        secret_key: &SecretKeyVar<Self>,
        public_key: &PublicKeyVar<Self>,
        compiler: &mut Self::Compiler,
    ) -> TrapdoorVar<Self> {
        key_agreement.agree_in(secret_key, public_key, compiler)
    }

    /// Generates the trapdoor associated to `secret_key` and `public_key` and then uses it to
    /// generate the UTXO associated to `asset`.
    #[inline]
    fn utxo(
        key_agreement: &Self::KeyAgreementScheme,
        utxo_commitment: &Self::UtxoCommitmentScheme,
        secret_key: &SecretKey<Self>,
        public_key: &PublicKey<Self>,
        asset: &Asset,
    ) -> Utxo<Self> {
        let trapdoor = Self::trapdoor(key_agreement, secret_key, public_key);
        utxo_commitment.commit(&trapdoor, asset)
    }

    /// Generates the trapdoor associated to `secret_key` and `public_key` and then uses it to
    /// generate the UTXO associated to `asset`.
    #[inline]
    fn utxo_var(
        key_agreement: &Self::KeyAgreementSchemeVar,
        utxo_commitment: &Self::UtxoCommitmentSchemeVar,
        secret_key: &SecretKeyVar<Self>,
        public_key: &PublicKeyVar<Self>,
        asset: &AssetVar<Self>,
        compiler: &mut Self::Compiler,
    ) -> UtxoVar<Self> {
        let trapdoor = Self::trapdoor_var(key_agreement, secret_key, public_key, compiler);
        utxo_commitment.commit_in(&trapdoor, asset, compiler)
    }

    /// Generates the void number associated to `utxo` and `secret_key` using `parameters`.
    #[inline]
    fn void_number(
        parameters: &Self::VoidNumberHashFunction,
        utxo: &Utxo<Self>,
        secret_key: &SecretKey<Self>,
    ) -> VoidNumber<Self> {
        parameters.hash(utxo, secret_key)
    }

    /// Generates the void number associated to `utxo` and `secret_key` using `parameters`.
    #[inline]
    fn void_number_var(
        parameters: &Self::VoidNumberHashFunctionVar,
        utxo: &UtxoVar<Self>,
        secret_key: &SecretKeyVar<Self>,
        compiler: &mut Self::Compiler,
    ) -> VoidNumberVar<Self> {
        parameters.hash_in(utxo, secret_key, compiler)
    }

    /// Checks that the `utxo` is correctly constructed from the `secret_key`, `public_key`, and
    /// `asset`, returning the void number for the asset if so.
    #[inline]
    fn check_full_asset(
        parameters: &Parameters<Self>,
        secret_key: &SecretKey<Self>,
        public_key: &PublicKey<Self>,
        asset: &Asset,
        utxo: &Utxo<Self>,
    ) -> Option<VoidNumber<Self>> {
        (&Self::utxo(
            &parameters.key_agreement,
            &parameters.utxo_commitment,
            secret_key,
            public_key,
            asset,
        ) == utxo)
            .then(move || Self::void_number(&parameters.void_number_hash, utxo, secret_key))
    }
}

/// Asset Variable Type
pub type AssetVar<C> = Asset<<C as Configuration>::AssetIdVar, <C as Configuration>::AssetValueVar>;

/// Secret Key Type
pub type SecretKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;

/// Secret Key Variable Type
pub type SecretKeyVar<C> =
    <<C as Configuration>::KeyAgreementSchemeVar as KeyAgreementScheme<Compiler<C>>>::SecretKey;

/// Public Key Type
pub type PublicKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;

/// Public Key Variable Type
pub type PublicKeyVar<C> =
    <<C as Configuration>::KeyAgreementSchemeVar as KeyAgreementScheme<Compiler<C>>>::PublicKey;

/// UTXO Trapdoor Type
pub type Trapdoor<C> =
    <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret;

/// UTXO Trapdoor Variable Type
pub type TrapdoorVar<C> =
    <<C as Configuration>::KeyAgreementSchemeVar as KeyAgreementScheme<Compiler<C>>>::SharedSecret;

/// Unspend Transaction Output Type
pub type Utxo<C> = <<C as Configuration>::UtxoCommitmentScheme as CommitmentScheme>::Output;

/// Unspent Transaction Output Variable Type
pub type UtxoVar<C> =
    <<C as Configuration>::UtxoCommitmentSchemeVar as CommitmentScheme<Compiler<C>>>::Output;

/// Void Number Type
pub type VoidNumber<C> =
    <<C as Configuration>::VoidNumberHashFunction as BinaryHashFunction>::Output;

/// Void Number Variable Type
pub type VoidNumberVar<C> =
    <<C as Configuration>::VoidNumberHashFunctionVar as BinaryHashFunction<Compiler<C>>>::Output;

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
pub type EncryptedNote<C> = EncryptedMessage<<C as Configuration>::NoteEncryptionScheme>;

/// Decrypted Note Type
pub type Note<C> = DecryptedMessage<<C as Configuration>::NoteEncryptionScheme>;

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
        C::UtxoCommitmentScheme: Clone,
        C::VoidNumberHashFunction: Clone
    "),
    Copy(bound = r"
        C::KeyAgreementScheme: Copy,
        C::UtxoCommitmentScheme: Copy,
        C::VoidNumberHashFunction: Copy
    "),
    Debug(bound = r"
        C::KeyAgreementScheme: Debug,
        C::UtxoCommitmentScheme: Debug,
        C::VoidNumberHashFunction: Debug
    "),
    Default(bound = r"
        C::KeyAgreementScheme: Default,
        C::UtxoCommitmentScheme: Default,
        C::VoidNumberHashFunction: Default
    "),
    Eq(bound = r"
        C::KeyAgreementScheme: Eq,
        C::UtxoCommitmentScheme: Eq,
        C::VoidNumberHashFunction: Eq
    "),
    Hash(bound = r"
        C::KeyAgreementScheme: Hash,
        C::UtxoCommitmentScheme: Hash,
        C::VoidNumberHashFunction: Hash
    "),
    PartialEq(bound = r"
        C::KeyAgreementScheme: PartialEq,
        C::UtxoCommitmentScheme: PartialEq,
        C::VoidNumberHashFunction: PartialEq
    ")
)]
pub struct Parameters<C>
where
    C: Configuration + ?Sized,
{
    /// Key Agreement Scheme
    pub key_agreement: C::KeyAgreementScheme,

    /// UTXO Commitment Scheme
    pub utxo_commitment: C::UtxoCommitmentScheme,

    /// Void Number Hash Function
    pub void_number_hash: C::VoidNumberHashFunction,
}

impl<C> Parameters<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`Parameters`].
    #[inline]
    pub fn new(
        key_agreement: C::KeyAgreementScheme,
        utxo_commitment: C::UtxoCommitmentScheme,
        void_number_hash: C::VoidNumberHashFunction,
    ) -> Self {
        Self {
            key_agreement,
            utxo_commitment,
            void_number_hash,
        }
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

/// Transfer Full Parameters Variables
pub struct FullParametersVar<'p, C>
where
    C: Configuration,
{
    /// Key Agreement Scheme
    key_agreement: C::KeyAgreementSchemeVar,

    /// UTXO Commitment Scheme
    utxo_commitment: C::UtxoCommitmentSchemeVar,

    /// Void Number Hash Function
    void_number_hash: C::VoidNumberHashFunctionVar,

    /// UTXO Accumulator Model
    utxo_accumulator_model: C::UtxoAccumulatorModelVar,

    /// Type Parameter Marker
    __: PhantomData<&'p ()>,
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
            key_agreement: this.base.key_agreement.as_constant(compiler),
            utxo_commitment: this.base.utxo_commitment.as_constant(compiler),
            void_number_hash: this.base.void_number_hash.as_constant(compiler),
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
            spend: parameters.derive(&self.spend),
            view: parameters.derive(&self.view),
        }
    }

    /// Validates the `utxo` against `self` and the given `ephemeral_key` and `asset`, returning
    /// the void number if the `utxo` is valid.
    #[inline]
    pub fn check_full_asset(
        &self,
        parameters: &Parameters<C>,
        ephemeral_key: &PublicKey<C>,
        asset: &Asset,
        utxo: &Utxo<C>,
    ) -> Option<VoidNumber<C>> {
        C::check_full_asset(parameters, &self.spend, ephemeral_key, asset, utxo)
    }

    /// Prepares `self` for spending `asset` with the given `ephemeral_key`.
    #[inline]
    pub fn sender(
        &self,
        parameters: &Parameters<C>,
        ephemeral_key: PublicKey<C>,
        asset: Asset,
    ) -> PreSender<C> {
        PreSender::new(parameters, self.spend.clone(), ephemeral_key, asset)
    }

    /// Prepares `self` for receiving `asset`.
    #[inline]
    pub fn receiver(
        &self,
        parameters: &Parameters<C>,
        ephemeral_key: SecretKey<C>,
        asset: Asset,
    ) -> Receiver<C> {
        self.derive(&parameters.key_agreement)
            .into_receiver(parameters, ephemeral_key, asset)
    }

    /// Returns an receiver-sender pair for internal transactions.
    #[inline]
    pub fn internal_pair(
        &self,
        parameters: &Parameters<C>,
        ephemeral_key: SecretKey<C>,
        asset: Asset,
    ) -> (Receiver<C>, PreSender<C>) {
        let receiver = self.receiver(parameters, ephemeral_key, asset);
        let sender = self.sender(parameters, receiver.ephemeral_public_key().clone(), asset);
        (receiver, sender)
    }

    /// Returns an receiver-sender pair of zeroes for internal transactions.
    #[inline]
    pub fn internal_zero_pair(
        &self,
        parameters: &Parameters<C>,
        ephemeral_key: SecretKey<C>,
        asset_id: AssetId,
    ) -> (Receiver<C>, PreSender<C>) {
        self.internal_pair(parameters, ephemeral_key, Asset::zero(asset_id))
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
        R: CryptoRng + RngCore + ?Sized,
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
        ephemeral_key: SecretKey<C>,
        asset: Asset,
    ) -> Receiver<C> {
        Receiver::new(parameters, ephemeral_key, self.spend, self.view, asset)
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
    ephemeral_public_key: PublicKey<C>,

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
    /// Builds a new [`PreSender`] for `spend` to spend `asset` with `ephemeral_public_key`.
    #[inline]
    pub fn new(
        parameters: &Parameters<C>,
        spend: SecretKey<C>,
        ephemeral_public_key: PublicKey<C>,
        asset: Asset,
    ) -> Self {
        let utxo = C::utxo(
            &parameters.key_agreement,
            &parameters.utxo_commitment,
            &spend,
            &ephemeral_public_key,
            &asset,
        );
        Self {
            void_number: C::void_number(&parameters.void_number_hash, &utxo, &spend),
            spend,
            ephemeral_public_key,
            asset,
            utxo,
        }
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_accumulator` with the intention
    /// of returning a proof later by a call to [`get_proof`](Self::get_proof).
    #[inline]
    pub fn insert_utxo<A>(&self, utxo_accumulator: &mut A) -> bool
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        utxo_accumulator.insert(&self.utxo)
    }

    /// Requests the membership proof of the [`Utxo`] corresponding to `self` from
    /// `utxo_accumulator` to prepare the conversion from `self` into a [`Sender`].
    #[inline]
    pub fn get_proof<A>(&self, utxo_accumulator: &A) -> Option<SenderProof<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        Some(SenderProof {
            utxo_membership_proof: utxo_accumulator.prove(&self.utxo)?,
        })
    }

    /// Converts `self` into a [`Sender`] by attaching `proof` to it.
    #[inline]
    pub fn upgrade(self, proof: SenderProof<C>) -> Sender<C> {
        Sender {
            spend: self.spend,
            ephemeral_public_key: self.ephemeral_public_key,
            asset: self.asset,
            utxo: self.utxo,
            utxo_membership_proof: proof.utxo_membership_proof,
            void_number: self.void_number,
        }
    }

    /// Tries to convert `self` into a [`Sender`] by getting a proof from `utxo_accumulator`.
    #[inline]
    pub fn try_upgrade<A>(self, utxo_accumulator: &A) -> Option<Sender<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        Some(self.get_proof(utxo_accumulator)?.upgrade(self))
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_accumulator` and upgrades to a
    /// full [`Sender`] if the insertion succeeded.
    #[inline]
    pub fn insert_and_upgrade<A>(self, utxo_accumulator: &mut A) -> Option<Sender<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        if self.insert_utxo(utxo_accumulator) {
            self.try_upgrade(utxo_accumulator)
        } else {
            None
        }
    }

    /// Returns `true` whenever `self.utxo` and `rhs.utxo` can be inserted in any order into the
    /// `utxo_accumulator`.
    #[inline]
    pub fn is_independent_from<A>(&self, rhs: &Self, utxo_accumulator: &A) -> bool
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        utxo_accumulator.are_independent(&self.utxo, &rhs.utxo)
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
    /// Upgrades the `pre_sender` to a [`Sender`] by attaching `self` to it.
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
    ephemeral_public_key: PublicKey<C>,

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
    /// Returns the asset value sent by `self` in the transaction.
    #[inline]
    pub fn asset_value(&self) -> AssetValue {
        self.asset.value
    }

    /// Returns `true` whenever `self.utxo` and `rhs.utxo` can be inserted in any order into the
    /// `utxo_accumulator`.
    #[inline]
    pub fn is_independent_from<A>(&self, rhs: &Self, utxo_accumulator: &A) -> bool
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        utxo_accumulator.are_independent(&self.utxo, &rhs.utxo)
    }

    /// Reverts `self` back into a [`PreSender`].
    ///
    /// This method should be called if the [`Utxo`] membership proof attached to `self` was deemed
    /// invalid or had expired.
    #[inline]
    pub fn downgrade(self) -> PreSender<C> {
        PreSender {
            spend: self.spend,
            ephemeral_public_key: self.ephemeral_public_key,
            asset: self.asset,
            utxo: self.utxo,
            void_number: self.void_number,
        }
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> SenderPost<C> {
        SenderPost {
            utxo_accumulator_output: self.utxo_membership_proof.into_output(),
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
    ephemeral_public_key: PublicKeyVar<C>,

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
    /// system `compiler`.
    #[inline]
    pub fn get_well_formed_asset(
        self,
        parameters: &FullParametersVar<C>,
        compiler: &mut C::Compiler,
    ) -> AssetVar<C> {
        let utxo = C::utxo_var(
            &parameters.key_agreement,
            &parameters.utxo_commitment,
            &self.spend,
            &self.ephemeral_public_key,
            &self.asset,
            compiler,
        );
        let is_valid_proof = self.utxo_membership_proof.verify_in(
            &parameters.utxo_accumulator_model,
            &utxo,
            compiler,
        );
        compiler.assert(is_valid_proof);
        let void_number =
            C::void_number_var(&parameters.void_number_hash, &utxo, &self.spend, compiler);
        compiler.assert_eq(&self.void_number, &void_number);
        self.asset
    }
}

impl<C> Variable<Derived, C::Compiler> for SenderVar<C>
where
    C: Configuration,
{
    type Type = Sender<C>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
        Self {
            spend: this.spend.as_known(compiler),
            ephemeral_public_key: this.ephemeral_public_key.as_known::<Secret, _>(compiler),
            asset: this.asset.as_known(compiler),
            utxo_membership_proof: this.utxo_membership_proof.as_known(compiler),
            void_number: this.void_number.as_known(compiler),
        }
    }

    #[inline]
    fn new_unknown(compiler: &mut C::Compiler) -> Self {
        Self {
            spend: compiler.allocate_unknown(),
            ephemeral_public_key: compiler.allocate_unknown::<Secret, _>(),
            asset: compiler.allocate_unknown(),
            utxo_membership_proof: compiler.allocate_unknown(),
            void_number: compiler.allocate_unknown(),
        }
    }
}

/// Sender Ledger
///
/// This is the validation trait for ensuring that a particular instance of [`Sender`] is valid
/// according to the ledger state. These methods are the minimum required for a ledger which accepts
/// the [`Sender`] abstraction.
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
    type ValidVoidNumber: AsRef<VoidNumber<C>>;

    /// Valid UTXO Accumulator Output Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`S::Output`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`has_matching_utxo_accumulator_output`](Self::has_matching_utxo_accumulator_output).
    ///
    /// [`S::Output`]: Model::Output
    type ValidUtxoAccumulatorOutput: AsRef<UtxoAccumulatorOutput<C>>;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`SenderLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks if the ledger already contains the `void_number` in its set of void numbers.
    ///
    /// Existence of such a void number could indicate a possible double-spend.
    fn is_unspent(&self, void_number: VoidNumber<C>) -> Option<Self::ValidVoidNumber>;

    /// Checks if `output` matches the current accumulated value of the UTXO accumulator that is
    /// stored on the ledger.
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
    /// the ledger. See [`is_unspent`](Self::is_unspent) for more.
    ///
    /// # Implementation Note
    ///
    /// This method, by defualt, calls the [`spend_all`] method on an iterator of length one
    /// containing `(utxo, note)`. Either [`spend`] or [`spend_all`] can be implemented
    /// depending on which is more efficient.
    ///
    /// [`spend`]: Self::spend
    /// [`spend_all`]: Self::spend_all
    #[inline]
    fn spend(
        &mut self,
        utxo_accumulator_output: Self::ValidUtxoAccumulatorOutput,
        void_number: Self::ValidVoidNumber,
        super_key: &Self::SuperPostingKey,
    ) {
        self.spend_all(
            iter::once((utxo_accumulator_output, void_number)),
            super_key,
        )
    }

    /// Posts all of the [`VoidNumber`] to the ledger, spending the assets.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that all the [`VoidNumber`] are not already
    /// stored on the ledger. See [`is_unspent`](Self::is_unspent) for more.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for multiple calls to [`spend`] and by default just
    /// iterates over `iter` calling [`spend`] on each item returned. Either [`spend`] or
    /// [`spend_all`] can be implemented depending on which is more efficient.
    ///
    /// [`spend`]: Self::spend
    /// [`spend_all`]: Self::spend_all
    #[inline]
    fn spend_all<I>(&mut self, iter: I, super_key: &Self::SuperPostingKey)
    where
        I: IntoIterator<Item = (Self::ValidUtxoAccumulatorOutput, Self::ValidVoidNumber)>,
    {
        for (utxo_accumulator_output, void_number) in iter {
            self.spend(utxo_accumulator_output, void_number, super_key)
        }
    }
}

/// Sender Post Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SenderPostError {
    /// Asset Spent Error
    ///
    /// The asset has already been spent.
    AssetSpent,

    /// Invalid UTXO Accumulator Output Error
    ///
    /// The sender was not constructed under the current state of the UTXO accumulator.
    InvalidUtxoAccumulatorOutput,
}

/// Sender Post
///
/// This `struct` represents the public data required to verify that a particular instance of a
/// [`Sender`] should be valid according to the [`SenderLedger`]. The rest of the information
/// required to verify a [`Transfer`] is stored in the [`TransferPost`] which includes the [`Proof`]
/// of validity.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "UtxoAccumulatorOutput<C>: Deserialize<'de>, VoidNumber<C>: Deserialize<'de>",
            serialize = "UtxoAccumulatorOutput<C>: Serialize, VoidNumber<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "UtxoAccumulatorOutput<C>: Clone, VoidNumber<C>: Clone"),
    Copy(bound = "UtxoAccumulatorOutput<C>: Copy, VoidNumber<C>: Copy"),
    Debug(bound = "UtxoAccumulatorOutput<C>: Debug, VoidNumber<C>: Debug"),
    Eq(bound = "UtxoAccumulatorOutput<C>: Eq, VoidNumber<C>: Eq"),
    Hash(bound = "UtxoAccumulatorOutput<C>: Hash, VoidNumber<C>: Hash"),
    PartialEq(bound = "UtxoAccumulatorOutput<C>: PartialEq, VoidNumber<C>: PartialEq")
)]
pub struct SenderPost<C>
where
    C: Configuration,
{
    /// UTXO Accumulator Output
    pub utxo_accumulator_output: UtxoAccumulatorOutput<C>,

    /// Void Number
    pub void_number: VoidNumber<C>,
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
        C::ProofSystem::extend(input, &self.utxo_accumulator_output);
        C::ProofSystem::extend(input, &self.void_number);
    }

    /// Validates `self` on the sender `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<SenderPostingKey<C, L>, SenderPostError>
    where
        L: SenderLedger<C>,
    {
        Ok(SenderPostingKey {
            utxo_accumulator_output: ledger
                .has_matching_utxo_accumulator_output(self.utxo_accumulator_output)
                .ok_or(SenderPostError::InvalidUtxoAccumulatorOutput)?,
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
    /// UTXO Accumulator Output Posting Key
    utxo_accumulator_output: L::ValidUtxoAccumulatorOutput,

    /// Void Number Posting Key
    void_number: L::ValidVoidNumber,
}

impl<C, L> SenderPostingKey<C, L>
where
    C: Configuration,
    L: SenderLedger<C> + ?Sized,
{
    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        C::ProofSystem::extend(input, self.utxo_accumulator_output.as_ref());
        C::ProofSystem::extend(input, self.void_number.as_ref());
    }

    /// Posts `self` to the sender `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.spend(self.utxo_accumulator_output, self.void_number, super_key);
    }

    /// Posts all of the [`SenderPostingKey`] in `iter` to the sender `ledger`.
    #[inline]
    pub fn post_all<I>(iter: I, super_key: &L::SuperPostingKey, ledger: &mut L)
    where
        I: IntoIterator<Item = Self>,
    {
        ledger.spend_all(
            iter.into_iter()
                .map(move |k| (k.utxo_accumulator_output, k.void_number)),
            super_key,
        )
    }
}

/// Receiver
pub struct Receiver<C>
where
    C: Configuration,
{
    /// Ephemeral Secret Spend Key
    ephemeral_secret_key: SecretKey<C>,

    /// Public Spend Key
    spend: PublicKey<C>,

    /// Asset
    asset: Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Encrypted Asset Note
    note: EncryptedNote<C>,
}

impl<C> Receiver<C>
where
    C: Configuration,
{
    /// Builds a new [`Receiver`] for `spend` to receive `asset` with `ephemeral_secret_key`.
    #[inline]
    pub fn new(
        parameters: &Parameters<C>,
        ephemeral_secret_key: SecretKey<C>,
        spend: PublicKey<C>,
        view: PublicKey<C>,
        asset: Asset,
    ) -> Self {
        Self {
            utxo: C::utxo(
                &parameters.key_agreement,
                &parameters.utxo_commitment,
                &ephemeral_secret_key,
                &spend,
                &asset,
            ),
            note: EncryptedMessage::new(
                &parameters.key_agreement,
                &view,
                &ephemeral_secret_key,
                asset,
            ),
            ephemeral_secret_key,
            spend,
            asset,
        }
    }

    /// Returns the ephemeral public key associated to `self`.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &PublicKey<C> {
        self.note.ephemeral_public_key()
    }

    /// Returns `true` whenever `self.utxo` and `rhs.utxo` can be inserted in any order into the
    /// `utxo_accumulator`.
    #[inline]
    pub fn is_independent_from<A>(&self, rhs: &Self, utxo_accumulator: &A) -> bool
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        utxo_accumulator.are_independent(&self.utxo, &rhs.utxo)
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> ReceiverPost<C> {
        ReceiverPost {
            utxo: self.utxo,
            note: self.note,
        }
    }
}

/// Receiver Variable
pub struct ReceiverVar<C>
where
    C: Configuration,
{
    /// Ephemeral Secret Spend Key
    ephemeral_secret_key: SecretKeyVar<C>,

    /// Ephemeral Public Spend Key
    ephemeral_public_key: PublicKeyVar<C>,

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
    /// system `compiler`.
    #[inline]
    pub fn get_well_formed_asset(
        self,
        parameters: &FullParametersVar<C>,
        compiler: &mut C::Compiler,
    ) -> AssetVar<C> {
        let ephemeral_public_key = C::ephemeral_public_key_var(
            &parameters.key_agreement,
            &self.ephemeral_secret_key,
            compiler,
        );
        compiler.assert_eq(&self.ephemeral_public_key, &ephemeral_public_key);
        let utxo = C::utxo_var(
            &parameters.key_agreement,
            &parameters.utxo_commitment,
            &self.ephemeral_secret_key,
            &self.spend,
            &self.asset,
            compiler,
        );
        compiler.assert_eq(&self.utxo, &utxo);
        self.asset
    }
}

impl<C> Variable<Derived, C::Compiler> for ReceiverVar<C>
where
    C: Configuration,
{
    type Type = Receiver<C>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
        Self {
            ephemeral_secret_key: this.ephemeral_secret_key.as_known(compiler),
            ephemeral_public_key: this.ephemeral_public_key().as_known::<Public, _>(compiler),
            spend: this.spend.as_known::<Secret, _>(compiler),
            asset: this.asset.as_known(compiler),
            utxo: this.utxo.as_known::<Public, _>(compiler),
        }
    }

    #[inline]
    fn new_unknown(compiler: &mut C::Compiler) -> Self {
        Self {
            ephemeral_secret_key: compiler.allocate_unknown(),
            ephemeral_public_key: compiler.allocate_unknown::<Public, _>(),
            spend: compiler.allocate_unknown::<Secret, _>(),
            asset: compiler.allocate_unknown(),
            utxo: compiler.allocate_unknown::<Public, _>(),
        }
    }
}

/// Receiver Ledger
///
/// This is the validation trait for ensuring that a particular instance of [`Receiver`] is valid
/// according to the ledger state. These methods are the minimum required for a ledger which accepts
/// the [`Receiver`] abstraction.
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
    type ValidUtxo: AsRef<Utxo<C>>;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`ReceiverLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks if the ledger already contains the `utxo` in its set of UTXOs.
    ///
    /// Existence of such a UTXO could indicate a possible double-spend.
    fn is_not_registered(&self, utxo: Utxo<C>) -> Option<Self::ValidUtxo>;

    /// Posts the `utxo` and `note` to the ledger, registering the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `utxo` is not already stored on the
    /// ledger. See [`is_not_registered`](Self::is_not_registered) for more.
    ///
    /// # Implementation Note
    ///
    /// This method, by default, calls the [`register_all`] method on an iterator of length one
    /// containing `(utxo, note)`. Either [`register`] or [`register_all`] can be implemented
    /// depending on which is more efficient.
    ///
    /// [`register`]: Self::register
    /// [`register_all`]: Self::register_all
    #[inline]
    fn register(
        &mut self,
        utxo: Self::ValidUtxo,
        note: EncryptedNote<C>,
        super_key: &Self::SuperPostingKey,
    ) {
        self.register_all(iter::once((utxo, note)), super_key)
    }

    /// Posts all of the [`Utxo`] and [`EncryptedNote`] to the ledger, registering the assets.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that all the [`Utxo`] and [`EncryptedNote`] are
    /// not already stored on the ledger. See [`is_not_registered`](Self::is_not_registered) for
    /// more.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for multiple calls to [`register`] and by default just
    /// iterates over `iter` calling [`register`] on each item returned. Either [`register`] or
    /// [`register_all`] can be implemented depending on which is more efficient.
    ///
    /// [`register`]: Self::register
    /// [`register_all`]: Self::register_all
    #[inline]
    fn register_all<I>(&mut self, iter: I, super_key: &Self::SuperPostingKey)
    where
        I: IntoIterator<Item = (Self::ValidUtxo, EncryptedNote<C>)>,
    {
        for (utxo, note) in iter {
            self.register(utxo, note, super_key)
        }
    }
}

/// Receiver Post Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReceiverPostError {
    /// Asset Registered Error
    ///
    /// The asset has already been registered with the ledger.
    AssetRegistered,
}

/// Receiver Post
///
/// This `struct` represents the public data required to verify that a particular instance of a
/// [`Receiver`] should be valid according to the [`ReceiverLedger`]. The rest of the information
/// required to verify a [`Transfer`] is stored in the [`TransferPost`] which includes the [`Proof`]
/// of validity.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Utxo<C>: Deserialize<'de>, EncryptedNote<C>: Deserialize<'de>",
            serialize = "Utxo<C>: Serialize, EncryptedNote<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Utxo<C>: Clone, EncryptedNote<C>: Clone"),
    Copy(bound = "Utxo<C>: Copy, EncryptedNote<C>: Copy"),
    Debug(bound = "Utxo<C>: Debug, EncryptedNote<C>: Debug"),
    Eq(bound = "Utxo<C>: Eq, EncryptedNote<C>: Eq"),
    Hash(bound = "Utxo<C>: Hash, EncryptedNote<C>: Hash"),
    PartialEq(bound = "Utxo<C>: PartialEq, EncryptedNote<C>: PartialEq")
)]
pub struct ReceiverPost<C>
where
    C: Configuration,
{
    /// Unspent Transaction Output
    pub utxo: Utxo<C>,

    /// Encrypted Note
    pub note: EncryptedNote<C>,
}

impl<C> ReceiverPost<C>
where
    C: Configuration,
{
    /// Returns the ephemeral public key associated to `self`.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &PublicKey<C> {
        self.note.ephemeral_public_key()
    }

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        // TODO: Add a "public part" trait that extracts the public part of `Receiver` (using
        //       `ReceiverVar` to determine the types), then generate this method automatically.
        C::ProofSystem::extend(input, self.ephemeral_public_key());
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
    /// Returns the ephemeral public key associated to `self`.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &PublicKey<C> {
        self.note.ephemeral_public_key()
    }

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        C::ProofSystem::extend(input, self.ephemeral_public_key());
        C::ProofSystem::extend(input, self.utxo.as_ref());
    }

    /// Posts `self` to the receiver `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.register(self.utxo, self.note, super_key);
    }

    /// Posts all the of the [`ReceiverPostingKey`] in `iter` to the receiver `ledger`.
    #[inline]
    pub fn post_all<I>(iter: I, super_key: &L::SuperPostingKey, ledger: &mut L)
    where
        I: IntoIterator<Item = Self>,
    {
        ledger.register_all(iter.into_iter().map(move |k| (k.utxo, k.note)), super_key)
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
        let mut compiler = C::ProofSystem::for_unknown();
        TransferVar::<C, SOURCES, SENDERS, RECEIVERS, SINKS>::new_unknown(&mut compiler)
            .build_validity_constraints(&parameters.as_constant(&mut compiler), &mut compiler);
        compiler
    }

    /// Builds a constraint system which asserts constraints against known variables.
    #[inline]
    pub fn known_constraints(&self, parameters: FullParameters<C>) -> C::Compiler {
        let mut compiler = C::ProofSystem::for_known();
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
        C::ProofSystem::generate_context(
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

    /// Computes the sum of the asset values over `iter` inside of `compiler`.
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
    ) -> Result<(), LedgerInternalError>;
}

/// Transfer Source Posting Key Type
pub type SourcePostingKey<C, L> = <L as TransferLedger<C>>::ValidSourceAccount;

/// Transfer Sink Posting Key Type
pub type SinkPostingKey<C, L> = <L as TransferLedger<C>>::ValidSinkAccount;

/// Transfer Ledger Super Posting Key Type
pub type TransferLedgerSuperPostingKey<C, L> = <L as TransferLedger<C>>::SuperPostingKey;

/// Account Balance
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AccountBalance {
    /// Known Balance
    Known(AssetValue),

    /// Unknown Account
    UnknownAccount,
}

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
pub enum TransferPostError<AccountId> {
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

    /// Ledger Internal Error
    LedgerInternalError,
}

/// Ledger interal error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LedgerInternalError;

impl<AccountId> From<InvalidSourceAccount<AccountId>> for TransferPostError<AccountId> {
    #[inline]
    fn from(err: InvalidSourceAccount<AccountId>) -> Self {
        Self::InvalidSourceAccount(err)
    }
}

impl<AccountId> From<InvalidSinkAccount<AccountId>> for TransferPostError<AccountId> {
    #[inline]
    fn from(err: InvalidSinkAccount<AccountId>) -> Self {
        Self::InvalidSinkAccount(err)
    }
}

impl<AccountId> From<SenderPostError> for TransferPostError<AccountId> {
    #[inline]
    fn from(err: SenderPostError) -> Self {
        Self::Sender(err)
    }
}

impl<AccountId> From<ReceiverPostError> for TransferPostError<AccountId> {
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
        TransferPostError<L::AccountId>,
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
                sink_accounts.into_iter().zip(sink_values))?
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
    ) -> Result<TransferPostingKey<C, L>, TransferPostError<L::AccountId>>
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
    ) -> Result<L::Event, TransferPostError<L::AccountId>>
    where
        L: TransferLedger<C>,
    {
        self.validate(source_accounts, sink_accounts, ledger)?
            .post(super_key, ledger).or(Err(TransferPostError::LedgerInternalError))
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
    pub fn post(self, super_key: &TransferLedgerSuperPostingKey<C, L>, ledger: &mut L) -> Result<L::Event, LedgerInternalError> {
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
