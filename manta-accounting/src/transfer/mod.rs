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
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use manta_crypto::{
    accumulator::{self, Accumulator, MembershipProof, Verifier},
    commitment::CommitmentScheme,
    constraint::{
        Add, Allocation, Constant, ConstraintSystem, Derived, Equal, Input as ProofSystemInput,
        ProofSystem, Public, PublicOrSecret, Secret, Variable, VariableSource,
    },
    encryption::{DecryptedMessage, EncryptedMessage, HybridPublicKeyEncryptionScheme},
    key::{KeyAgreementScheme, KeyDerivationFunction},
    rand::{CryptoRng, RngCore, Sample},
};
use manta_util::from_variant_impl;

pub mod batch;
pub mod canonical;

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

/// Transfer Configuration
pub trait Configuration {
    /// Secret Key Type
    type SecretKey: Clone;

    /// Public Key Type
    type PublicKey: Clone;

    /// Secret Key Variable Type
    type SecretKeyVar: Variable<Self::Compiler, Type = SecretKey<Self>, Mode = Secret>;

    /// Public Key Variable Type
    type PublicKeyVar: Variable<Self::Compiler, Type = PublicKey<Self>, Mode = Public>
        + Equal<Self::Compiler>;

    /// Key Agreement Scheme Type
    type KeyAgreementScheme: KeyAgreementScheme<SecretKey = Self::SecretKey, PublicKey = Self::PublicKey>
        + KeyAgreementScheme<
            Self::Compiler,
            SecretKey = Self::SecretKeyVar,
            PublicKey = Self::PublicKeyVar,
        >;

    /// Ephemeral Key Trapdoor Type
    type EphemeralKeyTrapdoor: Sample;

    /// Ephemeral Key Trapdoor Variable Type
    type EphemeralKeyTrapdoorVar: Variable<
        Self::Compiler,
        Type = Self::EphemeralKeyTrapdoor,
        Mode = Secret,
    >;

    /// Ephemeral Key Commitment Scheme Parameters Variable Type
    type EphemeralKeyParametersVar: Variable<
        Self::Compiler,
        Type = EphemeralKeyParameters<Self>,
        Mode = Constant,
    >;

    /// Ephemeral Key Commitment Scheme Type
    type EphemeralKeyCommitmentScheme: CommitmentScheme<
            Trapdoor = Self::EphemeralKeyTrapdoor,
            Input = Asset,
            Output = Self::SecretKey,
        > + CommitmentScheme<
            Self::Compiler,
            Parameters = Self::EphemeralKeyParametersVar,
            Trapdoor = Self::EphemeralKeyTrapdoorVar,
            Input = AssetVar<Self>,
            Output = Self::SecretKeyVar,
        >;

    /// Trapdoor Derivation Function Type
    type TrapdoorDerivationFunction: KeyDerivationFunction<Key = SharedSecret<Self>, Output = Trapdoor<Self>>
        + KeyDerivationFunction<
            Self::Compiler,
            Key = SharedSecretVar<Self>,
            Output = TrapdoorVar<Self>,
        >;

    /// UTXO Commitment Parameters Variable Type
    type UtxoCommitmentParametersVar: Variable<
        Self::Compiler,
        Type = UtxoCommitmentParameters<Self>,
        Mode = Constant,
    >;

    /// Unspent Transaction Output Type
    type Utxo: PartialEq;

    /// UTXO Variable Type
    type UtxoVar: Variable<Self::Compiler, Type = Self::Utxo, Mode = PublicOrSecret>
        + Equal<Self::Compiler>;

    /// UTXO Commitment Scheme Type
    type UtxoCommitmentScheme: CommitmentScheme<Input = Asset, Output = Self::Utxo>
        + CommitmentScheme<
            Self::Compiler,
            Parameters = Self::UtxoCommitmentParametersVar,
            Input = AssetVar<Self>,
            Output = Self::UtxoVar,
        >;

    /// Void Number Commitment Scheme Parameters Variable Type
    type VoidNumberCommitmentParametersVar: Variable<
        Self::Compiler,
        Type = VoidNumberCommitmentParameters<Self>,
        Mode = Constant,
    >;

    /// Void Number Type
    type VoidNumber: PartialEq;

    /// Void Number Variable Type
    type VoidNumberVar: Variable<Self::Compiler, Type = Self::VoidNumber, Mode = Public>
        + Equal<Self::Compiler>;

    /// Void Number Commitment Scheme Type
    type VoidNumberCommitmentScheme: CommitmentScheme<
            Trapdoor = Trapdoor<Self>,
            Input = Self::SecretKey,
            Output = Self::VoidNumber,
        > + CommitmentScheme<
            Self::Compiler,
            Parameters = Self::VoidNumberCommitmentParametersVar,
            Trapdoor = TrapdoorVar<Self>,
            Input = Self::SecretKeyVar,
            Output = Self::VoidNumberVar,
        >;

    /// UTXO Set Parameters Variable Type
    type UtxoSetParametersVar: Variable<
        Self::Compiler,
        Type = UtxoSetParameters<Self>,
        Mode = Constant,
    >;

    /// UTXO Set Witness Variable Type
    type UtxoSetWitnessVar: Variable<Self::Compiler, Type = UtxoSetWitness<Self>, Mode = Secret>;

    /// UTXO Set Output Variable Type
    type UtxoSetOutputVar: Variable<Self::Compiler, Type = UtxoSetOutput<Self>, Mode = Public>;

    /// UTXO Set Verifier Type
    type UtxoSetVerifier: Verifier<Item = Self::Utxo, Verification = bool>
        + Verifier<
            Self::Compiler,
            Parameters = Self::UtxoSetParametersVar,
            Item = Self::UtxoVar,
            Witness = Self::UtxoSetWitnessVar,
            Output = Self::UtxoSetOutputVar,
            Verification = <Self::Compiler as ConstraintSystem>::Bool,
        >;

    /// Asset Id Variable Type
    type AssetIdVar: Variable<Self::Compiler, Type = AssetId, Mode = PublicOrSecret>
        + Equal<Self::Compiler>;

    /// Asset Value Variable Type
    type AssetValueVar: Variable<Self::Compiler, Type = AssetValue, Mode = PublicOrSecret>
        + Equal<Self::Compiler>
        + Add<Self::Compiler>;

    /// Constraint System Type
    type Compiler: ConstraintSystem;

    /// Proof System Type
    type ProofSystem: ProofSystem<ConstraintSystem = Self::Compiler, Verification = bool>
        + ProofSystemInput<AssetId>
        + ProofSystemInput<AssetValue>
        + ProofSystemInput<UtxoSetOutput<Self>>
        + ProofSystemInput<Utxo<Self>>
        + ProofSystemInput<VoidNumber<Self>>
        + ProofSystemInput<PublicKey<Self>>;

    /// Note Encryption Scheme Type
    type NoteEncryptionScheme: HybridPublicKeyEncryptionScheme<
        Plaintext = Asset,
        KeyAgreementScheme = Self::KeyAgreementScheme,
    >;

    /// Generates the ephemeral secret key from `parameters`, `trapdoor`, and `asset`.
    #[inline]
    fn ephemeral_secret_key(
        parameters: &EphemeralKeyParameters<Self>,
        trapdoor: &EphemeralKeyTrapdoor<Self>,
        asset: Asset,
    ) -> SecretKey<Self> {
        Self::EphemeralKeyCommitmentScheme::commit(&mut (), parameters, trapdoor, &asset)
    }

    /// Generates the ephemeral secret key from `parameters`, `trapdoor`, and `asset`.
    #[inline]
    fn ephemeral_secret_key_var(
        cs: &mut Self::Compiler,
        parameters: &EphemeralKeyParametersVar<Self>,
        trapdoor: &EphemeralKeyTrapdoorVar<Self>,
        asset: &AssetVar<Self>,
    ) -> SecretKeyVar<Self> {
        Self::EphemeralKeyCommitmentScheme::commit(cs, parameters, trapdoor, asset)
    }

    /// Derives a public key variable from a secret key variable.
    #[inline]
    fn ephemeral_public_key_var(
        cs: &mut Self::Compiler,
        secret_key: &SecretKeyVar<Self>,
    ) -> PublicKeyVar<Self> {
        Self::KeyAgreementScheme::derive(cs, secret_key)
    }

    /// Generates the commitment trapdoor associated to `secret_key` and `public_key`.
    #[inline]
    fn trapdoor(secret_key: &SecretKey<Self>, public_key: &PublicKey<Self>) -> Trapdoor<Self> {
        let shared_secret = Self::KeyAgreementScheme::agree(&mut (), secret_key, public_key);
        Self::TrapdoorDerivationFunction::derive(&mut (), shared_secret)
    }

    /// Generates the commitment trapdoor associated to `secret_key` and `public_key`.
    #[inline]
    fn trapdoor_var(
        cs: &mut Self::Compiler,
        secret_key: &SecretKeyVar<Self>,
        public_key: &PublicKeyVar<Self>,
    ) -> TrapdoorVar<Self> {
        let shared_secret = Self::KeyAgreementScheme::agree(cs, secret_key, public_key);
        Self::TrapdoorDerivationFunction::derive(cs, shared_secret)
    }

    /// Generates the UTXO associated to `trapdoor` and `asset` from `parameters`.
    #[inline]
    fn utxo(
        parameters: &UtxoCommitmentParameters<Self>,
        trapdoor: &Trapdoor<Self>,
        asset: &Asset,
    ) -> Utxo<Self> {
        Self::UtxoCommitmentScheme::commit(&mut (), parameters, trapdoor, asset)
    }

    /// Generates the UTXO associated to `trapdoor` and `asset` from `parameters`.
    #[inline]
    fn utxo_var(
        cs: &mut Self::Compiler,
        parameters: &UtxoCommitmentParametersVar<Self>,
        trapdoor: &TrapdoorVar<Self>,
        asset: &AssetVar<Self>,
    ) -> UtxoVar<Self> {
        Self::UtxoCommitmentScheme::commit(cs, parameters, trapdoor, asset)
    }

    /// Generates the trapdoor associated to `secret_key` and `public_key` and then uses it to
    /// generate the UTXO associated to `asset`.
    #[inline]
    fn full_utxo(
        parameters: &UtxoCommitmentParameters<Self>,
        secret_key: &SecretKey<Self>,
        public_key: &PublicKey<Self>,
        asset: &Asset,
    ) -> Utxo<Self> {
        Self::utxo(parameters, &Self::trapdoor(secret_key, public_key), asset)
    }

    /// Generates the trapdoor associated to `secret_key` and `public_key` and then uses it to
    /// generate the UTXO associated to `asset`.
    #[inline]
    fn full_utxo_var(
        cs: &mut Self::Compiler,
        parameters: &UtxoCommitmentParametersVar<Self>,
        secret_key: &SecretKeyVar<Self>,
        public_key: &PublicKeyVar<Self>,
        asset: &AssetVar<Self>,
    ) -> UtxoVar<Self> {
        let trapdoor = Self::trapdoor_var(cs, secret_key, public_key);
        Self::utxo_var(cs, parameters, &trapdoor, asset)
    }

    /// Generates the void number associated to `trapdoor` and `secret_key` using `parameters`.
    #[inline]
    fn void_number(
        parameters: &VoidNumberCommitmentParameters<Self>,
        trapdoor: &Trapdoor<Self>,
        secret_key: &SecretKey<Self>,
    ) -> VoidNumber<Self> {
        Self::VoidNumberCommitmentScheme::commit(&mut (), parameters, trapdoor, secret_key)
    }

    /// Generates the void number associated to `trapdoor` and `secret_key` using `parameters`.
    #[inline]
    fn void_number_var(
        cs: &mut Self::Compiler,
        parameters: &VoidNumberCommitmentParametersVar<Self>,
        trapdoor: &TrapdoorVar<Self>,
        secret_key: &SecretKeyVar<Self>,
    ) -> VoidNumberVar<Self> {
        Self::VoidNumberCommitmentScheme::commit(cs, parameters, trapdoor, secret_key)
    }

    /// Checks that the `utxo` is correctly constructed from the `secret_key`, `public_key`, and
    /// `asset`, returning the void number for the asset if so.
    #[inline]
    fn check_full_asset(
        utxo_parameters: &UtxoCommitmentParameters<Self>,
        void_number_parameters: &VoidNumberCommitmentParameters<Self>,
        secret_key: &SecretKey<Self>,
        public_key: &PublicKey<Self>,
        asset: &Asset,
        utxo: &Utxo<Self>,
    ) -> Option<VoidNumber<Self>> {
        let trapdoor = Self::trapdoor(secret_key, public_key);
        (&Self::utxo(utxo_parameters, &trapdoor, asset) == utxo)
            .then(move || Self::void_number(void_number_parameters, &trapdoor, secret_key))
    }
}

/// Asset Variable Type
pub type AssetVar<C> = Asset<<C as Configuration>::AssetIdVar, <C as Configuration>::AssetValueVar>;

/// Secret Key Type
pub type SecretKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;

/// Secret Key Variable Type
pub type SecretKeyVar<C> = <C as Configuration>::SecretKeyVar;

/// Public Key Type
pub type PublicKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;

/// Public Key Variable Type
pub type PublicKeyVar<C> = <C as Configuration>::PublicKeyVar;

/// Shared Secret Type
pub type SharedSecret<C> =
    <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret;

/// Shared Secret Variable Type
pub type SharedSecretVar<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme<
    <C as Configuration>::Compiler,
>>::SharedSecret;

/// Ephemeral Key Commitment Scheme Parameters Type
pub type EphemeralKeyParameters<C> =
    <<C as Configuration>::EphemeralKeyCommitmentScheme as CommitmentScheme>::Parameters;

/// Ephemeral Key Commitment Scheme Parameters Variable Type
pub type EphemeralKeyParametersVar<C> = <C as Configuration>::EphemeralKeyParametersVar;

/// Ephemeral Key Trapdoor Type
pub type EphemeralKeyTrapdoor<C> =
    <<C as Configuration>::EphemeralKeyCommitmentScheme as CommitmentScheme>::Trapdoor;

/// Ephemeral Key Trapdoor Variable Type
pub type EphemeralKeyTrapdoorVar<C> = <C as Configuration>::EphemeralKeyTrapdoorVar;

/// Trapdoor Type
pub type Trapdoor<C> = <<C as Configuration>::UtxoCommitmentScheme as CommitmentScheme>::Trapdoor;

/// Trapdoor Variable Type
pub type TrapdoorVar<C> = <<C as Configuration>::UtxoCommitmentScheme as CommitmentScheme<
    <C as Configuration>::Compiler,
>>::Trapdoor;

/// UTXO Commitment Scheme Parameters Type
pub type UtxoCommitmentParameters<C> =
    <<C as Configuration>::UtxoCommitmentScheme as CommitmentScheme>::Parameters;

/// UTXO Commitment Scheme Parameters Variable Type
pub type UtxoCommitmentParametersVar<C> = <C as Configuration>::UtxoCommitmentParametersVar;

/// Unspend Transaction Output Type
pub type Utxo<C> = <<C as Configuration>::UtxoCommitmentScheme as CommitmentScheme>::Output;

/// Unspent Transaction Output Variable Type
pub type UtxoVar<C> = <C as Configuration>::UtxoVar;

/// UTXO Set Accumulator Verifier Parameters Type
pub type UtxoSetParameters<C> = <<C as Configuration>::UtxoSetVerifier as Verifier>::Parameters;

/// UTXO Set Accumulator Verifier Parameters Variable Type
pub type UtxoSetParametersVar<C> = <C as Configuration>::UtxoSetParametersVar;

/// UTXO Set Witness Type
pub type UtxoSetWitness<C> = <<C as Configuration>::UtxoSetVerifier as Verifier>::Witness;

/// UTXO Set Output Type
pub type UtxoSetOutput<C> = <<C as Configuration>::UtxoSetVerifier as Verifier>::Output;

/// UTXO Membership Proof Type
pub type UtxoMembershipProof<C> = MembershipProof<<C as Configuration>::UtxoSetVerifier>;

/// UTXO Membership Proof Variable Type
pub type UtxoMembershipProofVar<C> = accumulator::MembershipProof<
    <C as Configuration>::UtxoSetVerifier,
    <C as Configuration>::Compiler,
>;

/// Void Number Commitment Scheme Parameters Type
pub type VoidNumberCommitmentParameters<C> =
    <<C as Configuration>::VoidNumberCommitmentScheme as CommitmentScheme>::Parameters;

/// Void Number Commitment Scheme Parameters Variable Type
pub type VoidNumberCommitmentParametersVar<C> =
    <C as Configuration>::VoidNumberCommitmentParametersVar;

/// Void Number Type
pub type VoidNumber<C> =
    <<C as Configuration>::VoidNumberCommitmentScheme as CommitmentScheme>::Output;

/// Void Number Variable Type
pub type VoidNumberVar<C> = <C as Configuration>::VoidNumberVar;

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
pub struct Parameters<'p, C>
where
    C: Configuration,
{
    /// Ephemeral Key Commitment Scheme Parameters
    pub ephemeral_key: &'p EphemeralKeyParameters<C>,

    /// UTXO Commitment Scheme Parameters
    pub utxo_commitment: &'p UtxoCommitmentParameters<C>,

    /// Void Number Commitment Scheme Parameters
    pub void_number_commitment: &'p VoidNumberCommitmentParameters<C>,

    /// UTXO Set Verifier Parameters
    pub utxo_set_verifier: &'p UtxoSetParameters<C>,
}

impl<'p, C> Parameters<'p, C>
where
    C: Configuration,
{
    /// Builds a new [`Parameters`] from `ephemeral_key`, `utxo_commitment`,
    /// `void_number_commitment`, and `utxo_set_verifier` parameters.
    #[inline]
    pub fn new(
        ephemeral_key: &'p EphemeralKeyParameters<C>,
        utxo_commitment: &'p UtxoCommitmentParameters<C>,
        void_number_commitment: &'p VoidNumberCommitmentParameters<C>,
        utxo_set_verifier: &'p UtxoSetParameters<C>,
    ) -> Self {
        Self {
            ephemeral_key,
            utxo_commitment,
            void_number_commitment,
            utxo_set_verifier,
        }
    }
}

/// Transfer Parameters Variables
pub struct ParametersVar<'p, C>
where
    C: Configuration,
{
    /// Ephemeral Key Commitment Scheme Parameters
    pub ephemeral_key: EphemeralKeyParametersVar<C>,

    /// UTXO Commitment Scheme Parameters
    pub utxo_commitment: UtxoCommitmentParametersVar<C>,

    /// Void Number Commitment Scheme Parameters
    pub void_number_commitment: VoidNumberCommitmentParametersVar<C>,

    /// UTXO Set Verifier Parameters
    pub utxo_set_verifier: UtxoSetParametersVar<C>,

    /// Type Parameter Marker
    __: PhantomData<&'p ()>,
}

impl<'p, C> Variable<C::Compiler> for ParametersVar<'p, C>
where
    C: Configuration,
    EphemeralKeyParameters<C>: 'p,
    UtxoCommitmentParameters<C>: 'p,
    VoidNumberCommitmentParameters<C>: 'p,
    UtxoSetParameters<C>: 'p,
{
    type Type = Parameters<'p, C>;

    type Mode = Constant;

    #[inline]
    fn new(cs: &mut C::Compiler, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self {
                ephemeral_key: this.ephemeral_key.as_known(cs, mode),
                utxo_commitment: this.utxo_commitment.as_known(cs, mode),
                void_number_commitment: this.void_number_commitment.as_known(cs, mode),
                utxo_set_verifier: this.utxo_set_verifier.as_known(cs, mode),
                __: PhantomData,
            },
            _ => unreachable!("Constant variables cannot be unknown."),
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
    pub fn derive(&self) -> ReceivingKey<C> {
        ReceivingKey {
            spend: C::KeyAgreementScheme::derive(&mut (), &self.spend),
            view: C::KeyAgreementScheme::derive(&mut (), &self.view),
        }
    }

    /// Tries to decrypt `encrypted_note` with the viewing key associated to `self`.
    #[inline]
    pub fn decrypt(&self, encrypted_note: EncryptedNote<C>) -> Result<Note<C>, EncryptedNote<C>> {
        encrypted_note.decrypt(&self.view)
    }

    /// Validates the `utxo` against `self` and the given `ephemeral_key` and `asset`, returning
    /// the void number if the `utxo` is valid.
    #[inline]
    pub fn check_full_asset(
        &self,
        utxo_parameters: &UtxoCommitmentParameters<C>,
        void_number_parameters: &VoidNumberCommitmentParameters<C>,
        ephemeral_key: &PublicKey<C>,
        asset: &Asset,
        utxo: &Utxo<C>,
    ) -> Option<VoidNumber<C>> {
        C::check_full_asset(
            utxo_parameters,
            void_number_parameters,
            &self.spend,
            ephemeral_key,
            asset,
            utxo,
        )
    }

    /// Prepares `self` for spending `asset` with the given `ephemeral_key`.
    #[inline]
    pub fn sender(
        &self,
        utxo_parameters: &UtxoCommitmentParameters<C>,
        void_number_parameters: &VoidNumberCommitmentParameters<C>,
        ephemeral_key: PublicKey<C>,
        asset: Asset,
    ) -> PreSender<C> {
        // TODO: See if this clone is really needed.
        PreSender::new(
            utxo_parameters,
            void_number_parameters,
            self.spend.clone(),
            ephemeral_key,
            asset,
        )
    }

    /// Prepares `self` for receiving `asset`.
    #[inline]
    pub fn receiver(
        &self,
        ephemeral_key_parameters: &EphemeralKeyParameters<C>,
        utxo_parameters: &UtxoCommitmentParameters<C>,
        ephemeral_key_trapdoor: EphemeralKeyTrapdoor<C>,
        asset: Asset,
    ) -> Receiver<C> {
        self.derive().into_receiver(
            ephemeral_key_parameters,
            utxo_parameters,
            ephemeral_key_trapdoor,
            asset,
        )
    }

    /// Returns an receiver-sender pair for internal transactions.
    #[inline]
    pub fn internal_pair(
        &self,
        ephemeral_key_parameters: &EphemeralKeyParameters<C>,
        utxo_parameters: &UtxoCommitmentParameters<C>,
        void_number_parameters: &VoidNumberCommitmentParameters<C>,
        ephemeral_key_trapdoor: EphemeralKeyTrapdoor<C>,
        asset: Asset,
    ) -> (Receiver<C>, PreSender<C>) {
        let receiver = self.receiver(
            ephemeral_key_parameters,
            utxo_parameters,
            ephemeral_key_trapdoor,
            asset,
        );
        let sender = self.sender(
            utxo_parameters,
            void_number_parameters,
            receiver.ephemeral_public_key().clone(),
            asset,
        );
        (receiver, sender)
    }

    /// Returns an receiver-sender pair of zeroes for internal transactions.
    #[inline]
    pub fn internal_zero_pair(
        &self,
        ephemeral_key_parameters: &EphemeralKeyParameters<C>,
        utxo_parameters: &UtxoCommitmentParameters<C>,
        void_number_parameters: &VoidNumberCommitmentParameters<C>,
        ephemeral_key_trapdoor: EphemeralKeyTrapdoor<C>,
        asset_id: AssetId,
    ) -> (Receiver<C>, PreSender<C>) {
        self.internal_pair(
            ephemeral_key_parameters,
            utxo_parameters,
            void_number_parameters,
            ephemeral_key_trapdoor,
            Asset::zero(asset_id),
        )
    }
}

/// Receiving Key
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
        ephemeral_key_parameters: &EphemeralKeyParameters<C>,
        utxo_parameters: &UtxoCommitmentParameters<C>,
        ephemeral_key_trapdoor: EphemeralKeyTrapdoor<C>,
        asset: Asset,
    ) -> Receiver<C> {
        Receiver::new(
            ephemeral_key_parameters,
            utxo_parameters,
            ephemeral_key_trapdoor,
            self.spend,
            self.view,
            asset,
        )
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
        utxo_parameters: &UtxoCommitmentParameters<C>,
        void_number_parameters: &VoidNumberCommitmentParameters<C>,
        spend: SecretKey<C>,
        ephemeral_public_key: PublicKey<C>,
        asset: Asset,
    ) -> Self {
        let trapdoor = C::trapdoor(&spend, &ephemeral_public_key);
        Self {
            utxo: C::utxo(utxo_parameters, &trapdoor, &asset),
            void_number: C::void_number(void_number_parameters, &trapdoor, &spend),
            spend,
            ephemeral_public_key,
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
    /// system `cs`.
    #[inline]
    pub fn get_well_formed_asset(
        self,
        parameters: &ParametersVar<C>,
        cs: &mut C::Compiler,
    ) -> AssetVar<C> {
        let trapdoor = C::trapdoor_var(cs, &self.spend, &self.ephemeral_public_key);
        let utxo = C::utxo_var(cs, &parameters.utxo_commitment, &trapdoor, &self.asset);
        let is_valid_proof = self.utxo_membership_proof.verify_with_compiler(
            &parameters.utxo_set_verifier,
            &utxo,
            cs,
        );
        cs.assert(is_valid_proof);
        let void_number = C::void_number_var(
            cs,
            &parameters.void_number_commitment,
            &trapdoor,
            &self.spend,
        );
        cs.assert_eq(&self.void_number, &void_number);
        self.asset
    }
}

impl<C> Variable<C::Compiler> for SenderVar<C>
where
    C: Configuration,
{
    type Type = Sender<C>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut C::Compiler, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self {
                spend: this.spend.as_known(cs, mode),
                ephemeral_public_key: this.ephemeral_public_key.as_known(cs, mode),
                asset: this.asset.as_known(cs, mode),
                utxo_membership_proof: this.utxo_membership_proof.as_known(cs, mode),
                void_number: this.void_number.as_known(cs, Public),
            },
            Allocation::Unknown(mode) => Self {
                spend: SecretKeyVar::<C>::new_unknown(cs, mode),
                ephemeral_public_key: PublicKeyVar::<C>::new_unknown(cs, mode),
                asset: AssetVar::<C>::new_unknown(cs, mode),
                utxo_membership_proof: UtxoMembershipProofVar::<C>::new_unknown(cs, mode),
                void_number: VoidNumberVar::<C>::new_unknown(cs, Public),
            },
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

/// Receiver
pub struct Receiver<C>
where
    C: Configuration,
{
    /// Ephemeral Secret Spend Key Trapdoor
    ephemeral_key_trapdoor: EphemeralKeyTrapdoor<C>,

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
        ephemeral_key_parameters: &EphemeralKeyParameters<C>,
        utxo_parameters: &UtxoCommitmentParameters<C>,
        ephemeral_key_trapdoor: EphemeralKeyTrapdoor<C>,
        spend: PublicKey<C>,
        view: PublicKey<C>,
        asset: Asset,
    ) -> Self {
        let ephemeral_secret_key =
            C::ephemeral_secret_key(ephemeral_key_parameters, &ephemeral_key_trapdoor, asset);
        Self {
            utxo: C::full_utxo(utxo_parameters, &ephemeral_secret_key, &spend, &asset),
            note: EncryptedMessage::new(&view, &ephemeral_secret_key, asset),
            ephemeral_key_trapdoor,
            spend,
            asset,
        }
    }

    /// Returns the ephemeral public key associated to `self`.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &PublicKey<C> {
        self.note.ephemeral_public_key()
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
    /// Ephemeral Secret Spend Key Trapdoor
    ephemeral_key_trapdoor: EphemeralKeyTrapdoorVar<C>,

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
    /// system `cs`.
    #[inline]
    pub fn get_well_formed_asset(
        self,
        parameters: &ParametersVar<C>,
        cs: &mut C::Compiler,
    ) -> AssetVar<C> {
        let ephemeral_secret_key = C::ephemeral_secret_key_var(
            cs,
            &parameters.ephemeral_key,
            &self.ephemeral_key_trapdoor,
            &self.asset,
        );
        let ephemeral_public_key = C::ephemeral_public_key_var(cs, &ephemeral_secret_key);
        cs.assert_eq(&self.ephemeral_public_key, &ephemeral_public_key);
        let utxo = C::full_utxo_var(
            cs,
            &parameters.utxo_commitment,
            &ephemeral_secret_key,
            &self.spend,
            &self.asset,
        );
        cs.assert_eq(&self.utxo, &utxo);
        self.asset
    }
}

impl<C> Variable<C::Compiler> for ReceiverVar<C>
where
    C: Configuration,
{
    type Type = Receiver<C>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut C::Compiler, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self {
                ephemeral_key_trapdoor: this.ephemeral_key_trapdoor.as_known(cs, mode),
                ephemeral_public_key: this.ephemeral_public_key().as_known(cs, mode),
                spend: this.spend.as_known(cs, mode),
                asset: this.asset.as_known(cs, mode),
                utxo: this.utxo.as_known(cs, Public),
            },
            Allocation::Unknown(mode) => Self {
                ephemeral_key_trapdoor: EphemeralKeyTrapdoorVar::<C>::new_unknown(cs, mode),
                ephemeral_public_key: PublicKeyVar::<C>::new_unknown(cs, mode),
                spend: PublicKeyVar::<C>::new_unknown(cs, mode),
                asset: AssetVar::<C>::new_unknown(cs, mode),
                utxo: UtxoVar::<C>::new_unknown(cs, Public),
            },
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
        C::ProofSystem::extend(input, &self.utxo);
        C::ProofSystem::extend(input, self.ephemeral_public_key());
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

    /// Generates a proving and verifying context for this transfer shape.
    #[inline]
    pub fn generate_context<R>(
        parameters: Parameters<C>,
        rng: &mut R,
    ) -> Result<(ProvingContext<C>, VerifyingContext<C>), ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut cs = C::ProofSystem::for_unknown();
        TransferVar::<C, SOURCES, SENDERS, RECEIVERS, SINKS>::new_unknown(&mut cs, Derived)
            .build_validity_constraints(&parameters.as_known(&mut cs, Public), &mut cs);
        cs.generate_context::<C::ProofSystem, _>(rng)
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post<'p, R>(
        self,
        parameters: Parameters<'p, C>,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Ok(TransferPost {
            validity_proof: {
                let mut cs = C::ProofSystem::for_known();
                let transfer: TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS> =
                    self.as_known(&mut cs, Derived);
                transfer.build_validity_constraints(&parameters.as_known(&mut cs, Public), &mut cs);
                cs.prove::<C::ProofSystem, _>(context, rng)?
            },
            asset_id: self.asset_id,
            sources: self.sources.into(),
            sender_posts: IntoIterator::into_iter(self.senders)
                .map(Sender::into_post)
                .collect(),
            receiver_posts: IntoIterator::into_iter(self.receivers)
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
    fn build_validity_constraints(self, parameters: &ParametersVar<C>, cs: &mut C::Compiler) {
        let mut secret_asset_ids = Vec::with_capacity(SENDERS + RECEIVERS);

        let input_sum = Self::value_sum(
            self.senders
                .into_iter()
                .map(|s| {
                    let asset = s.get_well_formed_asset(parameters, cs);
                    secret_asset_ids.push(asset.id);
                    asset.value
                })
                .chain(self.sources)
                .collect::<Vec<_>>(),
            cs,
        );

        let output_sum = Self::value_sum(
            self.receivers
                .into_iter()
                .map(|r| {
                    let asset = r.get_well_formed_asset(parameters, cs);
                    secret_asset_ids.push(asset.id);
                    asset.value
                })
                .chain(self.sinks)
                .collect::<Vec<_>>(),
            cs,
        );

        cs.assert_eq(&input_sum, &output_sum);

        match self.asset_id {
            Some(asset_id) => cs.assert_all_eq_to_base(&asset_id, secret_asset_ids.iter()),
            _ => cs.assert_all_eq(secret_asset_ids.iter()),
        }
    }

    /// Computes the sum of the asset values over `iter` inside of `cs`.
    #[inline]
    fn value_sum<I>(iter: I, cs: &mut C::Compiler) -> C::AssetValueVar
    where
        I: IntoIterator<Item = C::AssetValueVar>,
    {
        iter.into_iter()
            .reduce(move |l, r| Add::add(cs, l, r))
            .unwrap()
    }
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Variable<C::Compiler> for TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    type Type = Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut C::Compiler, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
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
                    .map(|receiver| receiver.as_known(cs, mode))
                    .collect(),
                sinks: this
                    .sinks
                    .iter()
                    .map(|sink| sink.as_known(cs, Public))
                    .collect(),
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
                    .map(|_| ReceiverVar::<C>::new_unknown(cs, mode))
                    .collect(),
                sinks: (0..SINKS)
                    .into_iter()
                    .map(|_| C::AssetValueVar::new_unknown(cs, Public))
                    .collect(),
            },
        }
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

    /// Duplicate Spend Error
    DuplicateSpend,

    /// Duplicate Register Error
    DuplicateRegister,

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
        Ok(TransferPostingKey {
            validity_proof: match ledger.is_valid(
                self.asset_id,
                &source_posting_keys,
                &sender_posting_keys,
                &receiver_posting_keys,
                &self.sinks,
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
