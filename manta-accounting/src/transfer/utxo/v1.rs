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

//! UTXO Version 1 Protocol

use crate::{
    asset,
    transfer::utxo::{self, auth},
};
use alloc::vec::Vec;
use core::{cmp, fmt::Debug, hash::Hash};
use manta_crypto::{
    accumulator::{self, ItemHashFunction, MembershipProof},
    algebra::{
        diffie_hellman::StandardDiffieHellman, security::ComputationalDiffieHellmanHardness,
        HasGenerator, Ring, ScalarMul, ScalarMulGroup,
    },
    constraint::{HasInput, Input},
    eclair::{
        alloc::{
            mode::{Derived, Public, Secret},
            Allocate, Allocator, Const, Constant, Var, Variable,
        },
        bool::{Assert, AssertEq, Bool, ConditionalSelect},
        cmp::PartialEq,
        num::Zero,
        ops::{BitAnd, BitOr},
        Has,
    },
    encryption::{self, hybrid::Hybrid, Decrypt, EmptyHeader, Encrypt, EncryptedMessage},
    rand::{Rand, RngCore, Sample},
    signature::{self, schnorr, Sign, Verify},
};
use manta_util::{
    cmp::Independence,
    codec::{Encode, Write},
    convert::Field,
};

/// UTXO Version Number
pub const VERSION: u8 = 1;

/// UTXO Visibility
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Visibility {
    /// Opaque UTXO
    #[default]
    Opaque,

    /// Transparent UTXO
    Transparent,
}

impl Visibility {
    /// Returns `true` if `self` represents the opaque visibility mode.
    #[inline]
    pub const fn is_opaque(self) -> bool {
        matches!(self, Self::Opaque)
    }

    /// Returns `true` if `self` represents the transparent visibility mode.
    #[inline]
    pub const fn is_transparent(self) -> bool {
        matches!(self, Self::Transparent)
    }

    /// Returns `value` if `self` is [`Opaque`](Self::Opaque) and the default value otherwise.
    #[inline]
    pub fn secret<T>(self, value: &T) -> T
    where
        T: Clone + Default,
    {
        match self {
            Self::Opaque => value.clone(),
            _ => Default::default(),
        }
    }

    /// Returns `value` if `self` is [`Transparent`](Self::Transparent) and the default value
    /// otherwise.
    #[inline]
    pub fn public<T>(self, value: &T) -> T
    where
        T: Clone + Default,
    {
        match self {
            Self::Transparent => value.clone(),
            _ => Default::default(),
        }
    }
}

impl Sample for Visibility {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        if bool::sample(distribution, rng) {
            Self::Opaque
        } else {
            Self::Transparent
        }
    }
}

/// UTXO Commitment Scheme
pub trait UtxoCommitmentScheme<COM = ()>
where
    COM: Has<bool>,
{
    /// Asset Id
    type AssetId;

    /// Asset Value
    type AssetValue;

    /// Receiving Key
    type ReceivingKey;

    /// UTXO Commitment Randomness Type
    type Randomness: Clone;

    /// UTXO Commitment Type
    type Commitment: PartialEq<Self::Commitment, COM>;

    /// Commits to the UTXO data `asset_id`, `asset_value`, and `receiving_key`.
    fn commit(
        &self,
        randomness: &Self::Randomness,
        asset_id: &Self::AssetId,
        asset_value: &Self::AssetValue,
        receiving_key: &Self::ReceivingKey,
        compiler: &mut COM,
    ) -> Self::Commitment;
}

/// Viewing Key Derivation Function
pub trait ViewingKeyDerivationFunction<COM = ()> {
    /// Proof Authorization Key
    type ProofAuthorizationKey;

    /// Viewing Key
    type ViewingKey;

    /// Computes the [`ViewingKey`](Self::ViewingKey) from `proof_authorization_key`.
    fn viewing_key(
        &self,
        proof_authorization_key: &Self::ProofAuthorizationKey,
        compiler: &mut COM,
    ) -> Self::ViewingKey;
}

/// UTXO Accumulator Item Hash
pub trait UtxoAccumulatorItemHash<COM = ()> {
    /// Boolean Type
    type Bool;

    /// Asset Id Type
    type AssetId;

    /// Asset Value Type
    type AssetValue;

    /// UTXO Commitment Type
    type Commitment;

    /// Item Type
    type Item;

    /// Computes the accumulator item by hashing `is_transparent`, `public_asset_id`,
    /// `public_asset_value`, and `commitment`.
    fn hash(
        &self,
        is_transparent: &Self::Bool,
        public_asset_id: &Self::AssetId,
        public_asset_value: &Self::AssetValue,
        commitment: &Self::Commitment,
        compiler: &mut COM,
    ) -> Self::Item;
}

/// Nullifier Commitment Scheme
pub trait NullifierCommitmentScheme<COM = ()>
where
    COM: Has<bool>,
{
    /// Proof Authorization Key
    type ProofAuthorizationKey;

    /// UTXO Accumulator Item
    type UtxoAccumulatorItem;

    /// Nullifier Commitment
    type Commitment: PartialEq<Self::Commitment, COM>;

    /// Commits to the `item` using `proof_authorization_key`.
    fn commit(
        &self,
        proof_authorization_key: &Self::ProofAuthorizationKey,
        item: &Self::UtxoAccumulatorItem,
        compiler: &mut COM,
    ) -> Self::Commitment;
}

/// UTXO Configuration
pub trait BaseConfiguration<COM = ()>
where
    COM: Has<bool, Type = Self::Bool>,
{
    /// Boolean Type
    type Bool: Constant<COM, Type = bool>
        + BitAnd<Self::Bool, COM, Output = Self::Bool>
        + BitOr<Self::Bool, COM, Output = Self::Bool>
        + PartialEq<Self::Bool, COM>;

    /// Asset Id Type
    type AssetId: ConditionalSelect<COM>
        + PartialEq<Self::AssetId, COM>
        + Zero<COM, Verification = Self::Bool>;

    /// Asset Value Type
    type AssetValue: ConditionalSelect<COM>
        + PartialEq<Self::AssetValue, COM>
        + Zero<COM, Verification = Self::Bool>;

    /// Scalar Type
    type Scalar: Clone + PartialEq<Self::Scalar, COM>;

    /// Group Type
    type Group: Clone
        + ComputationalDiffieHellmanHardness
        + ScalarMulGroup<Self::Scalar, COM, Output = Self::Group>
        + PartialEq<Self::Group, COM>;

    /// Group Generator
    type GroupGenerator: HasGenerator<Self::Group, COM, Generator = Self::Group>;

    /// UTXO Commitment Scheme
    type UtxoCommitmentScheme: UtxoCommitmentScheme<
        COM,
        AssetId = Self::AssetId,
        AssetValue = Self::AssetValue,
        ReceivingKey = Self::Group,
    >;

    /// Viewing Key Derivation Function
    type ViewingKeyDerivationFunction: ViewingKeyDerivationFunction<
        COM,
        ProofAuthorizationKey = Self::Group,
        ViewingKey = Self::Scalar,
    >;

    /// Incoming Ciphertext Type
    type IncomingCiphertext: PartialEq<Self::IncomingCiphertext, COM>;

    /// Base Encryption Scheme for [`IncomingNote`]
    type IncomingBaseEncryptionScheme: Clone
        + Encrypt<
            COM,
            EncryptionKey = Self::Group,
            Header = EmptyHeader<COM>,
            Plaintext = IncomingPlaintext<Self, COM>,
            Ciphertext = Self::IncomingCiphertext,
        >;

    /// UTXO Accumulator Item Hash
    type UtxoAccumulatorItemHash: UtxoAccumulatorItemHash<
        COM,
        Bool = Self::Bool,
        AssetId = Self::AssetId,
        AssetValue = Self::AssetValue,
        Commitment = UtxoCommitment<Self, COM>,
    >;

    /// UTXO Accumulator Model
    type UtxoAccumulatorModel: accumulator::Model<
        COM,
        Item = UtxoAccumulatorItem<Self, COM>,
        Verification = Self::Bool,
    >;

    /// Nullifier Commitment Scheme Type
    type NullifierCommitmentScheme: NullifierCommitmentScheme<
        COM,
        ProofAuthorizationKey = Self::Group,
        UtxoAccumulatorItem = UtxoAccumulatorItem<Self, COM>,
    >;

    /// Outgoing Ciphertext Type
    type OutgoingCiphertext: PartialEq<Self::OutgoingCiphertext, COM>;

    /// Base Encryption Scheme for [`OutgoingNote`]
    type OutgoingBaseEncryptionScheme: Clone
        + Encrypt<
            COM,
            EncryptionKey = Self::Group,
            Header = EmptyHeader<COM>,
            Plaintext = Asset<Self, COM>,
            Ciphertext = Self::OutgoingCiphertext,
        >;
}

/// UTXO Configuration
pub trait Configuration: BaseConfiguration<Bool = bool> {
    /// Schnorr Hash Function
    type SchnorrHashFunction: Clone
        + schnorr::HashFunction<Scalar = Self::Scalar, Group = Self::Group, Message = Vec<u8>>;
}

/// Asset Type
pub type Asset<C, COM = ()> =
    asset::Asset<<C as BaseConfiguration<COM>>::AssetId, <C as BaseConfiguration<COM>>::AssetValue>;

/// UTXO Commitment
pub type UtxoCommitment<C, COM = ()> =
    <<C as BaseConfiguration<COM>>::UtxoCommitmentScheme as UtxoCommitmentScheme<COM>>::Commitment;

/// UTXO Commitment Randomness
pub type UtxoCommitmentRandomness<C, COM = ()> =
    <<C as BaseConfiguration<COM>>::UtxoCommitmentScheme as UtxoCommitmentScheme<COM>>::Randomness;

/// Incoming Encryption Scheme
pub type IncomingEncryptionScheme<C, COM = ()> = Hybrid<
    StandardDiffieHellman<
        <C as BaseConfiguration<COM>>::Scalar,
        <C as BaseConfiguration<COM>>::Group,
    >,
    <C as BaseConfiguration<COM>>::IncomingBaseEncryptionScheme,
>;

/// Incoming Randomness
pub type IncomingRandomness<C, COM = ()> = encryption::Randomness<IncomingEncryptionScheme<C, COM>>;

/// Incoming Encrypted Note
pub type IncomingNote<C, COM = ()> = EncryptedMessage<IncomingEncryptionScheme<C, COM>>;

/// UTXO Accumulator Item
pub type UtxoAccumulatorItem<C, COM = ()> =
    <<C as BaseConfiguration<COM>>::UtxoAccumulatorItemHash as UtxoAccumulatorItemHash<COM>>::Item;

/// UTXO Membership Proof
pub type UtxoMembershipProof<C, COM = ()> =
    MembershipProof<<C as BaseConfiguration<COM>>::UtxoAccumulatorModel>;

/// Nullifier Commitment
pub type NullifierCommitment<C, COM = ()> =
    <<C as BaseConfiguration<COM>>::NullifierCommitmentScheme as NullifierCommitmentScheme<COM>>::Commitment;

/// Outgoing Encryption Scheme
pub type OutgoingEncryptionScheme<C, COM = ()> = Hybrid<
    StandardDiffieHellman<
        <C as BaseConfiguration<COM>>::Scalar,
        <C as BaseConfiguration<COM>>::Group,
    >,
    <C as BaseConfiguration<COM>>::OutgoingBaseEncryptionScheme,
>;

/// Outgoing Randomness
pub type OutgoingRandomness<C, COM = ()> = encryption::Randomness<OutgoingEncryptionScheme<C, COM>>;

/// Outgoing Note
pub type OutgoingNote<C, COM = ()> = EncryptedMessage<OutgoingEncryptionScheme<C, COM>>;

/// Signature Scheme
pub type SignatureScheme<C> = schnorr::Schnorr<<C as Configuration>::SchnorrHashFunction>;

/// UTXO Model Base Parameters
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = r"
        C::GroupGenerator: Clone,
        C::UtxoCommitmentScheme: Clone,
        C::IncomingBaseEncryptionScheme: Clone,
        C::ViewingKeyDerivationFunction: Clone,
        C::UtxoAccumulatorItemHash: Clone,
        C::NullifierCommitmentScheme: Clone,
        C::OutgoingBaseEncryptionScheme: Clone,
    "),
    Debug(bound = r"
        C::GroupGenerator: Debug,
        C::UtxoCommitmentScheme: Debug,
        C::IncomingBaseEncryptionScheme: Debug,
        C::ViewingKeyDerivationFunction: Debug,
        C::UtxoAccumulatorItemHash: Debug,
        C::NullifierCommitmentScheme: Debug,
        C::OutgoingBaseEncryptionScheme: Debug,
    ")
)]
pub struct BaseParameters<C, COM = ()>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Group Generator
    pub group_generator: C::GroupGenerator,

    /// UTXO Commitment Scheme
    pub utxo_commitment_scheme: C::UtxoCommitmentScheme,

    /// Incoming Base Encryption Scheme
    pub incoming_base_encryption_scheme: C::IncomingBaseEncryptionScheme,

    /// Viewing Key Derivation Function
    pub viewing_key_derivation_function: C::ViewingKeyDerivationFunction,

    /// UTXO Accumulator Item Hash
    pub utxo_accumulator_item_hash: C::UtxoAccumulatorItemHash,

    /// Nullifier Commitment Scheme
    pub nullifier_commitment_scheme: C::NullifierCommitmentScheme,

    /// Outgoing Base Encryption Scheme
    pub outgoing_base_encryption_scheme: C::OutgoingBaseEncryptionScheme,
}

impl<C, COM> auth::AuthorizationContextType for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type AuthorizationContext = AuthorizationContext<C, COM>;
}

impl<C, COM> auth::AuthorizationKeyType for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type AuthorizationKey = C::Group;
}

impl<C, COM> auth::AuthorizationProofType for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type AuthorizationProof = AuthorizationProof<C, COM>;
}

impl<C, COM> utxo::AssetType for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Asset = Asset<C, COM>;
}

impl<C, COM> utxo::AddressType for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Address = Address<C, COM>;
}

impl<C, COM> utxo::NoteType for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Note = IncomingNote<C, COM>;
}

impl<C, COM> utxo::UtxoType for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Utxo = Utxo<C, COM>;
}

impl<C, COM> utxo::NullifierType for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Nullifier = Nullifier<C, COM>;
}

impl<C, COM> utxo::IdentifierType for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    type Identifier = Identifier<C, COM>;
}

impl<C, COM> auth::AssertAuthorized<COM> for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    #[inline]
    fn assert_authorized(
        &self,
        authorization_context: &Self::AuthorizationContext,
        authorization_proof: &Self::AuthorizationProof,
        compiler: &mut COM,
    ) {
        let randomized_proof_authorization_key = authorization_context
            .proof_authorization_key
            .scalar_mul(&authorization_proof.randomness, compiler);
        compiler.assert_eq(
            &randomized_proof_authorization_key,
            &authorization_proof.randomized_proof_authorization_key,
        );
    }
}

impl<C, COM> utxo::Mint<COM> for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Secret = MintSecret<C, COM>;

    #[inline]
    fn well_formed_asset(
        &self,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        note: &Self::Note,
        compiler: &mut COM,
    ) -> Self::Asset {
        secret.well_formed_asset(
            self.group_generator.generator(),
            &self.utxo_commitment_scheme,
            &self.incoming_base_encryption_scheme,
            utxo,
            note,
            compiler,
        )
    }
}

impl<C, COM> accumulator::ItemHashFunction<Utxo<C, COM>, COM> for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Item = UtxoAccumulatorItem<C, COM>;

    #[inline]
    fn item_hash(&self, utxo: &Utxo<C, COM>, compiler: &mut COM) -> Self::Item {
        self.utxo_accumulator_item_hash.hash(
            &utxo.is_transparent,
            &utxo.public_asset.id,
            &utxo.public_asset.value,
            &utxo.commitment,
            compiler,
        )
    }
}

impl<C, COM> utxo::Spend<COM> for BaseParameters<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type UtxoAccumulatorWitness = utxo::UtxoAccumulatorWitness<Self, COM>;
    type UtxoAccumulatorOutput = utxo::UtxoAccumulatorOutput<Self, COM>;
    type UtxoAccumulatorModel = C::UtxoAccumulatorModel;
    type Secret = SpendSecret<C, COM>;

    #[inline]
    fn well_formed_asset(
        &self,
        utxo_accumulator_model: &Self::UtxoAccumulatorModel,
        authorization_context: &mut Self::AuthorizationContext,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        utxo_membership_proof: &UtxoMembershipProof<C, COM>,
        compiler: &mut COM,
    ) -> (Self::Asset, Self::Nullifier) {
        secret.well_formed_asset(
            self,
            utxo_accumulator_model,
            authorization_context,
            utxo,
            utxo_membership_proof,
            compiler,
        )
    }

    #[inline]
    fn assert_equal_nullifiers(
        &self,
        lhs: &Self::Nullifier,
        rhs: &Self::Nullifier,
        compiler: &mut COM,
    ) {
        compiler.assert_eq(lhs, rhs)
    }
}

impl<C, COM> Constant<COM> for BaseParameters<C, COM>
where
    COM: Assert + Has<bool, Type = C::Bool>,
    C: BaseConfiguration<COM> + Constant<COM>,
    C::Type: Configuration<
        Bool = bool,
        GroupGenerator = Const<C::GroupGenerator, COM>,
        UtxoCommitmentScheme = Const<C::UtxoCommitmentScheme, COM>,
        IncomingBaseEncryptionScheme = Const<C::IncomingBaseEncryptionScheme, COM>,
        ViewingKeyDerivationFunction = Const<C::ViewingKeyDerivationFunction, COM>,
        UtxoAccumulatorItemHash = Const<C::UtxoAccumulatorItemHash, COM>,
        NullifierCommitmentScheme = Const<C::NullifierCommitmentScheme, COM>,
        OutgoingBaseEncryptionScheme = Const<C::OutgoingBaseEncryptionScheme, COM>,
    >,
    C::GroupGenerator: Constant<COM>,
    C::UtxoCommitmentScheme: Constant<COM>,
    C::IncomingBaseEncryptionScheme: Constant<COM>,
    C::ViewingKeyDerivationFunction: Constant<COM>,
    C::UtxoAccumulatorItemHash: Constant<COM>,
    C::NullifierCommitmentScheme: Constant<COM>,
    C::OutgoingBaseEncryptionScheme: Constant<COM>,
{
    type Type = Parameters<C::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self {
            group_generator: this.base.group_generator.as_constant(compiler),
            utxo_commitment_scheme: this.base.utxo_commitment_scheme.as_constant(compiler),
            incoming_base_encryption_scheme: this
                .base
                .incoming_base_encryption_scheme
                .as_constant(compiler),
            viewing_key_derivation_function: this
                .base
                .viewing_key_derivation_function
                .as_constant(compiler),
            utxo_accumulator_item_hash: this.base.utxo_accumulator_item_hash.as_constant(compiler),
            nullifier_commitment_scheme: this
                .base
                .nullifier_commitment_scheme
                .as_constant(compiler),
            outgoing_base_encryption_scheme: this
                .base
                .outgoing_base_encryption_scheme
                .as_constant(compiler),
        }
    }
}

impl<C, DGG, DUCS, DIBES, DVKDF, DUAIH, DNCS, DOBES>
    Sample<(DGG, DUCS, DIBES, DVKDF, DUAIH, DNCS, DOBES)> for BaseParameters<C>
where
    C: BaseConfiguration<Bool = bool>,
    C::GroupGenerator: Sample<DGG>,
    C::UtxoCommitmentScheme: Sample<DUCS>,
    C::IncomingBaseEncryptionScheme: Sample<DIBES>,
    C::ViewingKeyDerivationFunction: Sample<DVKDF>,
    C::UtxoAccumulatorItemHash: Sample<DUAIH>,
    C::NullifierCommitmentScheme: Sample<DNCS>,
    C::OutgoingBaseEncryptionScheme: Sample<DOBES>,
{
    #[inline]
    fn sample<R>(distribution: (DGG, DUCS, DIBES, DVKDF, DUAIH, DNCS, DOBES), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self {
            group_generator: rng.sample(distribution.0),
            utxo_commitment_scheme: rng.sample(distribution.1),
            incoming_base_encryption_scheme: rng.sample(distribution.2),
            viewing_key_derivation_function: rng.sample(distribution.3),
            utxo_accumulator_item_hash: rng.sample(distribution.4),
            nullifier_commitment_scheme: rng.sample(distribution.5),
            outgoing_base_encryption_scheme: rng.sample(distribution.6),
        }
    }
}

/// UTXO Model Parameters
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "BaseParameters<C>: Clone, C::SchnorrHashFunction: Clone"),
    Copy(bound = "BaseParameters<C>: Copy, C::SchnorrHashFunction: Copy"),
    Debug(bound = "BaseParameters<C>: Debug, C::SchnorrHashFunction: Debug"),
    Default(bound = "BaseParameters<C>: Default, C::SchnorrHashFunction: Default"),
    Eq(bound = "BaseParameters<C>: Eq, C::SchnorrHashFunction: Eq"),
    Hash(bound = "BaseParameters<C>: Hash, C::SchnorrHashFunction: Hash"),
    PartialEq(bound = "BaseParameters<C>: cmp::PartialEq, C::SchnorrHashFunction: cmp::PartialEq")
)]
pub struct Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    /// Base Parameters
    pub base: BaseParameters<C>,

    /// Schnorr Hash Function
    pub schnorr_hash_function: C::SchnorrHashFunction,
}

impl<C> auth::SpendingKeyType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type SpendingKey = C::Scalar;
}

impl<C> auth::AuthorizationContextType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type AuthorizationContext = AuthorizationContext<C>;
}

impl<C> auth::AuthorizationKeyType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type AuthorizationKey = C::Group;
}

impl<C> auth::AuthorizationProofType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type AuthorizationProof = AuthorizationProof<C>;
}

impl<C> auth::SigningKeyType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type SigningKey = C::Scalar;
}

impl<C> auth::SignatureType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type Signature = signature::Signature<SignatureScheme<C>>;
}

impl<C> utxo::AssetType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type Asset = Asset<C>;
}

impl<C> utxo::AssociatedDataType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type AssociatedData = Visibility;
}

impl<C> utxo::AddressType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type Address = Address<C>;
}

impl<C> utxo::NoteType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type Note = IncomingNote<C>;
}

impl<C> utxo::UtxoType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type Utxo = Utxo<C>;
}

impl<C> utxo::NullifierType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type Nullifier = Nullifier<C>;
}

impl<C> utxo::IdentifierType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type Identifier = Identifier<C>;
}

impl<C> auth::DeriveContext for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    #[inline]
    fn derive(&self, spending_key: &Self::SpendingKey) -> Self::AuthorizationContext {
        AuthorizationContext::new(
            self.base
                .group_generator
                .generator()
                .scalar_mul(spending_key, &mut ()),
        )
    }
}

impl<C> auth::ProveAuthorization for Parameters<C>
where
    C: Configuration<Bool = bool>,
    C::Scalar: Sample,
{
    #[inline]
    fn prove<R>(
        &self,
        spending_key: &Self::SpendingKey,
        authorization_context: &Self::AuthorizationContext,
        rng: &mut R,
    ) -> Self::AuthorizationProof
    where
        R: RngCore + ?Sized,
    {
        let _ = spending_key;
        let randomness = rng.gen();
        let randomized_proof_authorization_key = authorization_context
            .proof_authorization_key
            .scalar_mul(&randomness, &mut ());
        AuthorizationProof::new(randomness, randomized_proof_authorization_key)
    }
}

impl<C> auth::VerifyAuthorization for Parameters<C>
where
    C: Configuration<Bool = bool>,
    C::Group: core::cmp::PartialEq,
{
    #[inline]
    fn verify(
        &self,
        spending_key: &Self::SpendingKey,
        authorization_context: &Self::AuthorizationContext,
        authorization_proof: &Self::AuthorizationProof,
    ) -> bool {
        (authorization_context == &auth::DeriveContext::derive(self, spending_key))
            && (authorization_proof.randomized_proof_authorization_key
                == authorization_context
                    .proof_authorization_key
                    .scalar_mul(&authorization_proof.randomness, &mut ()))
    }
}

impl<C> auth::DeriveSigningKey for Parameters<C>
where
    C: Configuration<Bool = bool>,
    C::Scalar: Ring,
{
    #[inline]
    fn derive(
        &self,
        spending_key: &Self::SpendingKey,
        authorization_context: &Self::AuthorizationContext,
        authorization_proof: &Self::AuthorizationProof,
    ) -> Self::SigningKey {
        let _ = authorization_context;
        spending_key.mul(&authorization_proof.randomness, &mut ())
    }
}

impl<C, M> auth::Sign<M> for Parameters<C>
where
    C: Configuration<Bool = bool>,
    C::Scalar: Sample,
    M: Encode,
{
    #[inline]
    fn sign<R>(&self, signing_key: &Self::SigningKey, message: &M, rng: &mut R) -> Self::Signature
    where
        R: RngCore + ?Sized,
    {
        SignatureScheme::<C>::new(
            self.schnorr_hash_function.clone(),
            self.base.group_generator.generator().clone(),
        )
        .sign(signing_key, &rng.gen(), &message.to_vec(), &mut ())
    }
}

impl<C, M> auth::VerifySignature<M> for Parameters<C>
where
    C: Configuration<Bool = bool>,
    M: Encode,
{
    #[inline]
    fn verify(
        &self,
        authorization_key: &Self::AuthorizationKey,
        signature: &Self::Signature,
        message: &M,
    ) -> bool {
        SignatureScheme::<C>::new(
            self.schnorr_hash_function.clone(),
            self.base.group_generator.generator().clone(),
        )
        .verify(authorization_key, &message.to_vec(), signature, &mut ())
    }
}

impl<C> utxo::Mint for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type Secret = MintSecret<C>;

    #[inline]
    fn well_formed_asset(
        &self,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        note: &Self::Note,
        compiler: &mut (),
    ) -> Self::Asset {
        self.base.well_formed_asset(secret, utxo, note, compiler)
    }
}

impl<C> utxo::DeriveMint for Parameters<C>
where
    C: Configuration<Bool = bool>,
    C::AssetId: Clone + Default,
    C::AssetValue: Clone + Default,
    C::Scalar: Sample,
    encryption::Randomness<C::IncomingBaseEncryptionScheme>: Sample,
    UtxoCommitmentRandomness<C>: Sample,
{
    #[inline]
    fn derive<R>(
        &self,
        address: Self::Address,
        asset: Self::Asset,
        associated_data: Self::AssociatedData,
        rng: &mut R,
    ) -> (Self::Secret, Self::Utxo, Self::Note)
    where
        R: RngCore + ?Sized,
    {
        let secret = MintSecret::<C>::new(
            address.receiving_key,
            rng.gen(),
            IncomingPlaintext::new(rng.gen(), associated_data.secret(&asset)),
        );
        let utxo_commitment = self.base.utxo_commitment_scheme.commit(
            &secret.plaintext.utxo_commitment_randomness,
            &secret.plaintext.asset.id,
            &secret.plaintext.asset.value,
            &secret.receiving_key,
            &mut (),
        );
        let incoming_note = Hybrid::new(
            StandardDiffieHellman::new(self.base.group_generator.generator().clone()),
            self.base.incoming_base_encryption_scheme.clone(),
        )
        .encrypt_into(
            &secret.receiving_key,
            &secret.incoming_randomness,
            EmptyHeader::default(),
            &secret.plaintext,
            &mut (),
        );
        (
            secret,
            Utxo::new(
                associated_data.is_transparent(),
                associated_data.public(&asset),
                utxo_commitment,
            ),
            incoming_note,
        )
    }
}

impl<C> accumulator::ItemHashFunction<Utxo<C>> for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type Item = UtxoAccumulatorItem<C>;

    #[inline]
    fn item_hash(&self, utxo: &Utxo<C>, compiler: &mut ()) -> Self::Item {
        self.base.item_hash(utxo, compiler)
    }
}

impl<C> utxo::Spend for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type UtxoAccumulatorWitness = utxo::UtxoAccumulatorWitness<Self>;
    type UtxoAccumulatorOutput = utxo::UtxoAccumulatorOutput<Self>;
    type UtxoAccumulatorModel = C::UtxoAccumulatorModel;
    type Secret = SpendSecret<C>;

    #[inline]
    fn well_formed_asset(
        &self,
        utxo_accumulator_model: &Self::UtxoAccumulatorModel,
        authorization_context: &mut Self::AuthorizationContext,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        utxo_membership_proof: &UtxoMembershipProof<C>,
        compiler: &mut (),
    ) -> (Self::Asset, Self::Nullifier) {
        self.base.well_formed_asset(
            utxo_accumulator_model,
            authorization_context,
            secret,
            utxo,
            utxo_membership_proof,
            compiler,
        )
    }

    #[inline]
    fn assert_equal_nullifiers(
        &self,
        lhs: &Self::Nullifier,
        rhs: &Self::Nullifier,
        compiler: &mut (),
    ) {
        self.base.assert_equal_nullifiers(lhs, rhs, compiler)
    }
}

impl<C> utxo::DeriveSpend for Parameters<C>
where
    C: Configuration<Bool = bool>,
    C::AssetId: Clone + Default,
    C::AssetValue: Clone + Default,
    C::Scalar: Sample,
    encryption::Randomness<C::OutgoingBaseEncryptionScheme>: Sample,
{
    #[inline]
    fn derive<R>(
        &self,
        authorization_context: &mut Self::AuthorizationContext,
        identifier: Self::Identifier,
        asset: Self::Asset,
        rng: &mut R,
    ) -> (Self::Secret, Self::Utxo, Self::Nullifier)
    where
        R: RngCore + ?Sized,
    {
        let associated_data = if identifier.is_transparent {
            Visibility::Transparent
        } else {
            Visibility::Opaque
        };
        let secret = SpendSecret::<C>::new(
            rng.gen(),
            IncomingPlaintext::new(
                identifier.utxo_commitment_randomness,
                associated_data.secret(&asset),
            ),
        );
        let receiving_key = authorization_context.receiving_key(
            self.base.group_generator.generator(),
            &self.base.viewing_key_derivation_function,
            &mut (),
        );
        let utxo_commitment = self.base.utxo_commitment_scheme.commit(
            &secret.plaintext.utxo_commitment_randomness,
            &secret.plaintext.asset.id,
            &secret.plaintext.asset.value,
            receiving_key,
            &mut (),
        );
        let utxo = Utxo::<C>::new(
            identifier.is_transparent,
            associated_data.public(&asset),
            utxo_commitment,
        );
        let outgoing_note = Hybrid::new(
            StandardDiffieHellman::new(self.base.group_generator.generator().clone()),
            self.base.outgoing_base_encryption_scheme.clone(),
        )
        .encrypt_into(
            receiving_key,
            &secret.outgoing_randomness,
            EmptyHeader::default(),
            &secret.plaintext.asset,
            &mut (),
        );
        let nullifier_commitment = self.base.nullifier_commitment_scheme.commit(
            &authorization_context.proof_authorization_key,
            &self.item_hash(&utxo, &mut ()),
            &mut (),
        );
        (
            secret,
            utxo,
            Nullifier::new(nullifier_commitment, outgoing_note),
        )
    }
}

impl<C> utxo::DeriveDecryptionKey for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type DecryptionKey = C::Scalar;

    #[inline]
    fn derive(
        &self,
        authorization_context: &mut Self::AuthorizationContext,
    ) -> Self::DecryptionKey {
        authorization_context
            .viewing_key(&self.base.viewing_key_derivation_function, &mut ())
            .clone()
    }
}

impl<C> utxo::NoteOpen for Parameters<C>
where
    C: Configuration<Bool = bool>,
    C::IncomingBaseEncryptionScheme:
        Decrypt<DecryptionKey = C::Group, DecryptedPlaintext = Option<IncomingPlaintext<C>>>,
{
    #[inline]
    fn open(
        &self,
        decryption_key: &Self::DecryptionKey,
        utxo: &Self::Utxo,
        note: Self::Note,
    ) -> Option<(Self::Identifier, Self::Asset)> {
        let plaintext = self.base.incoming_base_encryption_scheme.decrypt(
            &note
                .ephemeral_public_key()
                .scalar_mul(decryption_key, &mut ()),
            &EmptyHeader::default(),
            &note.ciphertext.ciphertext,
            &mut (),
        )?;
        Some((
            Identifier::new(utxo.is_transparent, plaintext.utxo_commitment_randomness),
            plaintext.asset,
        ))
    }
}

impl<C, DBP, DSHF> Sample<(DBP, DSHF)> for Parameters<C>
where
    C: Configuration<Bool = bool>,
    BaseParameters<C>: Sample<DBP>,
    C::SchnorrHashFunction: Sample<DSHF>,
{
    #[inline]
    fn sample<R>(distribution: (DBP, DSHF), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self {
            base: rng.sample(distribution.0),
            schnorr_hash_function: rng.sample(distribution.1),
        }
    }
}

/// Address
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = "C::Scalar: Clone, C::Group: Clone"))]
pub struct Address<C, COM = ()>
where
    C: BaseConfiguration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Receiving Key
    pub receiving_key: C::Group,
}

impl<C, COM> Address<C, COM>
where
    C: BaseConfiguration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`Address`] from `receiving_key`.
    #[inline]
    pub fn new(receiving_key: C::Group) -> Self {
        Self { receiving_key }
    }
}

impl<C> Sample for Address<C>
where
    C: BaseConfiguration<Bool = bool> + ?Sized,
    C::Group: Sample,
{
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.gen())
    }
}

/// Incoming Note Plaintext
pub struct IncomingPlaintext<C, COM = ()>
where
    C: BaseConfiguration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// UTXO Commitment Randomness
    pub utxo_commitment_randomness: UtxoCommitmentRandomness<C, COM>,

    /// Secret Asset
    pub asset: Asset<C, COM>,
}

impl<C, COM> IncomingPlaintext<C, COM>
where
    C: BaseConfiguration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`IncomingPlaintext`] from `utxo_commitment_randomness`, and `asset`.
    #[inline]
    pub fn new(
        utxo_commitment_randomness: UtxoCommitmentRandomness<C, COM>,
        asset: Asset<C, COM>,
    ) -> Self {
        Self {
            utxo_commitment_randomness,
            asset,
        }
    }
}

impl<C, COM> Variable<Secret, COM> for IncomingPlaintext<C, COM>
where
    C: BaseConfiguration<COM> + Constant<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
    C::Type: BaseConfiguration<Bool = bool>,
    UtxoCommitmentRandomness<C, COM>:
        Variable<Secret, COM, Type = UtxoCommitmentRandomness<C::Type>>,
    Asset<C, COM>: Variable<Secret, COM, Type = Asset<C::Type>>,
    C::Scalar: Variable<Secret, COM, Type = <C::Type as BaseConfiguration>::Scalar>,
{
    type Type = IncomingPlaintext<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.utxo_commitment_randomness.as_known(compiler),
            this.asset.as_known(compiler),
        )
    }
}

/// Unspent Transaction Output
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "C::Bool: Clone, Asset<C, COM>: Clone, UtxoCommitment<C, COM>: Clone"),
    Copy(bound = "C::Bool: Copy, Asset<C, COM>: Copy, UtxoCommitment<C, COM>: Copy"),
    Debug(bound = "C::Bool: Debug, Asset<C, COM>: Debug, UtxoCommitment<C, COM>: Debug")
)]
pub struct Utxo<C, COM = ()>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Transparency Flag
    pub is_transparent: C::Bool,

    /// Public Asset Data
    pub public_asset: Asset<C, COM>,

    /// UTXO Commitment
    pub commitment: UtxoCommitment<C, COM>,
}

impl<C, COM> Utxo<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`Utxo`] from `is_transparent`, `public_asset`, and `commitment`.
    #[inline]
    pub fn new(
        is_transparent: C::Bool,
        public_asset: Asset<C, COM>,
        commitment: UtxoCommitment<C, COM>,
    ) -> Self {
        Self {
            is_transparent,
            public_asset,
            commitment,
        }
    }

    /// Computes the item hash of `self` using `hasher`.
    #[inline]
    pub fn item_hash(
        &self,
        hasher: &C::UtxoAccumulatorItemHash,
        compiler: &mut COM,
    ) -> UtxoAccumulatorItem<C, COM> {
        hasher.hash(
            &self.is_transparent,
            &self.public_asset.id,
            &self.public_asset.value,
            &self.commitment,
            compiler,
        )
    }
}

impl<C, COM> PartialEq<Self, COM> for Utxo<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.is_transparent
            .eq(&rhs.is_transparent, compiler)
            .bitand(self.public_asset.eq(&rhs.public_asset, compiler), compiler)
            .bitand(self.commitment.eq(&rhs.commitment, compiler), compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        compiler.assert_eq(&self.is_transparent, &rhs.is_transparent);
        compiler.assert_eq(&self.public_asset, &rhs.public_asset);
        compiler.assert_eq(&self.commitment, &rhs.commitment);
    }
}

impl<C, COM, M> Variable<M, COM> for Utxo<C, COM>
where
    C: BaseConfiguration<COM> + Constant<COM>,
    COM: Has<bool, Type = C::Bool>,
    C::Type: BaseConfiguration<Bool = bool>,
    C::Bool: Variable<M, COM, Type = <C::Type as BaseConfiguration>::Bool>,
    Asset<C, COM>: Variable<M, COM, Type = Asset<C::Type>>,
    UtxoCommitment<C, COM>: Variable<M, COM, Type = UtxoCommitment<C::Type>>,
{
    type Type = Utxo<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.is_transparent.as_known(compiler),
            this.public_asset.as_known(compiler),
            this.commitment.as_known(compiler),
        )
    }
}

impl<C> Independence<utxo::UtxoIndependence> for Utxo<C>
where
    C: BaseConfiguration<Bool = bool>,
{
    #[inline]
    fn is_independent(&self, rhs: &Self) -> bool {
        self.ne(rhs, &mut ())
    }
}

impl<C> Encode for Utxo<C>
where
    C: BaseConfiguration<Bool = bool>,
    C::AssetId: Encode,
    C::AssetValue: Encode,
    UtxoCommitment<C>: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.is_transparent.encode(&mut writer)?;
        self.public_asset.encode(&mut writer)?;
        self.commitment.encode(&mut writer)?;
        Ok(())
    }
}

impl<C, P> Input<P> for Utxo<C>
where
    C: BaseConfiguration<Bool = bool>,
    P: HasInput<C::Bool> + HasInput<Asset<C>> + HasInput<UtxoCommitment<C>> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.is_transparent);
        P::extend(input, &self.public_asset);
        P::extend(input, &self.commitment);
    }
}

/// Secret required to Mint a UTXO
pub struct MintSecret<C, COM = ()>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Receiving Key
    receiving_key: C::Group,

    /// Incoming Randomness
    incoming_randomness: IncomingRandomness<C, COM>,

    /// Plaintext
    plaintext: IncomingPlaintext<C, COM>,
}

impl<C, COM> MintSecret<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`MintSecret`] from `receiving_key`, `incoming_randomness`, and `plaintext`.
    #[inline]
    pub fn new(
        receiving_key: C::Group,
        incoming_randomness: IncomingRandomness<C, COM>,
        plaintext: IncomingPlaintext<C, COM>,
    ) -> Self {
        Self {
            receiving_key,
            incoming_randomness,
            plaintext,
        }
    }

    /// Returns the UTXO commitment for `self` under `utxo_commitment_scheme`.
    #[inline]
    pub fn utxo_commitment(
        &self,
        utxo_commitment_scheme: &C::UtxoCommitmentScheme,
        compiler: &mut COM,
    ) -> UtxoCommitment<C, COM> {
        utxo_commitment_scheme.commit(
            &self.plaintext.utxo_commitment_randomness,
            &self.plaintext.asset.id,
            &self.plaintext.asset.value,
            &self.receiving_key,
            compiler,
        )
    }

    /// Returns the incoming note for `self` under `encryption_scheme`.
    #[inline]
    pub fn incoming_note(
        &self,
        group_generator: &C::Group,
        encryption_scheme: &C::IncomingBaseEncryptionScheme,
        compiler: &mut COM,
    ) -> IncomingNote<C, COM> {
        Hybrid::new(
            StandardDiffieHellman::new(group_generator.clone()),
            encryption_scheme.clone(),
        )
        .encrypt_into(
            &self.receiving_key,
            &self.incoming_randomness,
            EmptyHeader::default(),
            &self.plaintext,
            compiler,
        )
    }

    /// Returns the representative [`Asset`] from `self` and its public-form `utxo` asserting that
    /// it is well-formed.
    #[inline]
    pub fn well_formed_asset(
        &self,
        group_generator: &C::Group,
        utxo_commitment_scheme: &C::UtxoCommitmentScheme,
        encryption_scheme: &C::IncomingBaseEncryptionScheme,
        utxo: &Utxo<C, COM>,
        note: &IncomingNote<C, COM>,
        compiler: &mut COM,
    ) -> Asset<C, COM>
    where
        COM: AssertEq,
    {
        let is_transparent = self.plaintext.asset.is_empty(compiler);
        compiler.assert_eq(&utxo.is_transparent, &is_transparent);
        let asset = Asset::<C, _>::select(
            &utxo.is_transparent,
            &utxo.public_asset,
            &self.plaintext.asset,
            compiler,
        );
        let utxo_commitment = self.utxo_commitment(utxo_commitment_scheme, compiler);
        compiler.assert_eq(&utxo.commitment, &utxo_commitment);
        let incoming_note = self.incoming_note(group_generator, encryption_scheme, compiler);
        compiler.assert_eq(note, &incoming_note);
        asset
    }
}

impl<C, COM> utxo::IdentifierType for MintSecret<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    type Identifier = Identifier<C, COM>;
}

impl<C, COM> utxo::UtxoType for MintSecret<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    type Utxo = Utxo<C, COM>;
}

impl<C> utxo::QueryIdentifier for MintSecret<C>
where
    C: BaseConfiguration<Bool = bool>,
{
    #[inline]
    fn query_identifier(&self, utxo: &Self::Utxo) -> Self::Identifier {
        Identifier::new(
            utxo.is_transparent,
            self.plaintext.utxo_commitment_randomness.clone(),
        )
    }
}

impl<C, COM> Variable<Secret, COM> for MintSecret<C, COM>
where
    C: BaseConfiguration<COM> + Constant<COM>,
    COM: Has<bool, Type = C::Bool>,
    C::Type: BaseConfiguration<Bool = bool>,
    C::Group: Variable<Secret, COM, Type = <C::Type as BaseConfiguration>::Group>,
    IncomingRandomness<C, COM>: Variable<Secret, COM, Type = IncomingRandomness<C::Type>>,
    IncomingPlaintext<C, COM>: Variable<Secret, COM, Type = IncomingPlaintext<C::Type>>,
{
    type Type = MintSecret<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.receiving_key.as_known(compiler),
            this.incoming_randomness.as_known(compiler),
            this.plaintext.as_known(compiler),
        )
    }
}

/// Authorization Context
pub struct AuthorizationContext<C, COM = ()>
where
    C: BaseConfiguration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Proof Authorization Key
    proof_authorization_key: C::Group,

    /// Viewing Key
    viewing_key: Option<C::Scalar>,

    /// Receiving Key
    receiving_key: Option<C::Group>,
}

impl<C, COM> AuthorizationContext<C, COM>
where
    C: BaseConfiguration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`AuthorizationContext`] from `proof_authorization_key`.
    #[inline]
    pub fn new(proof_authorization_key: C::Group) -> Self {
        Self {
            proof_authorization_key,
            viewing_key: None,
            receiving_key: None,
        }
    }

    ///
    #[inline]
    fn compute_viewing_key<'s>(
        viewing_key: &'s mut Option<C::Scalar>,
        proof_authorization_key: &'s C::Group,
        viewing_key_derivation_function: &C::ViewingKeyDerivationFunction,
        compiler: &mut COM,
    ) -> &'s C::Scalar {
        viewing_key.get_or_insert_with(|| {
            viewing_key_derivation_function.viewing_key(proof_authorization_key, compiler)
        })
    }

    /// Computes the viewing key from `viewing_key_derivation_function`.
    #[inline]
    pub fn viewing_key(
        &mut self,
        viewing_key_derivation_function: &C::ViewingKeyDerivationFunction,
        compiler: &mut COM,
    ) -> &C::Scalar {
        Self::compute_viewing_key(
            &mut self.viewing_key,
            &self.proof_authorization_key,
            viewing_key_derivation_function,
            compiler,
        )
    }

    /// Returns the receiving key.
    #[inline]
    pub fn receiving_key(
        &mut self,
        group_generator: &C::Group,
        viewing_key_derivation_function: &C::ViewingKeyDerivationFunction,
        compiler: &mut COM,
    ) -> &C::Group {
        self.receiving_key.get_or_insert_with(|| {
            group_generator.scalar_mul(
                Self::compute_viewing_key(
                    &mut self.viewing_key,
                    &self.proof_authorization_key,
                    viewing_key_derivation_function,
                    compiler,
                ),
                compiler,
            )
        })
    }
}

impl<C> core::cmp::PartialEq for AuthorizationContext<C>
where
    C: BaseConfiguration<Bool = bool>,
    C::Group: core::cmp::PartialEq,
{
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        self.proof_authorization_key == rhs.proof_authorization_key
    }
}

impl<C, COM> Variable<Secret, COM> for AuthorizationContext<C, COM>
where
    COM: Has<bool, Type = C::Bool>,
    C: BaseConfiguration<COM> + Constant<COM>,
    C::Group: Variable<Secret, COM>,
    C::Type: BaseConfiguration<Bool = bool, Group = Var<C::Group, Secret, COM>>,
{
    type Type = AuthorizationContext<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(this.proof_authorization_key.as_known(compiler))
    }
}

/// Authorization Proof
pub struct AuthorizationProof<C, COM = ()>
where
    C: BaseConfiguration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Randomness
    randomness: C::Scalar,

    /// Randomized Proof Authorization Key
    randomized_proof_authorization_key: C::Group,
}

impl<C, COM> AuthorizationProof<C, COM>
where
    C: BaseConfiguration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`AuthorizationProof`] from `randomness` and
    /// `randomized_proof_authorization_key`.
    #[inline]
    pub fn new(randomness: C::Scalar, randomized_proof_authorization_key: C::Group) -> Self {
        Self {
            randomness,
            randomized_proof_authorization_key,
        }
    }
}

impl<C, COM> Field<C::Group> for AuthorizationProof<C, COM>
where
    C: BaseConfiguration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    #[inline]
    fn get(&self) -> &C::Group {
        &self.randomized_proof_authorization_key
    }

    #[inline]
    fn get_mut(&mut self) -> &mut C::Group {
        &mut self.randomized_proof_authorization_key
    }

    #[inline]
    fn into(self) -> C::Group {
        self.randomized_proof_authorization_key
    }
}

impl<C, COM> Variable<Derived, COM> for AuthorizationProof<C, COM>
where
    COM: Has<bool, Type = C::Bool>,
    C: BaseConfiguration<COM> + Constant<COM>,
    C::Scalar: Variable<Secret, COM>,
    C::Group: Variable<Public, COM>,
    C::Type: BaseConfiguration<
        Bool = bool,
        Scalar = Var<C::Scalar, Secret, COM>,
        Group = Var<C::Group, Public, COM>,
    >,
{
    type Type = AuthorizationProof<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.randomness.as_known(compiler),
            this.randomized_proof_authorization_key.as_known(compiler),
        )
    }
}

/// Identifier
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = "C::Bool: Clone, UtxoCommitmentRandomness<C, COM>: Clone"))]
pub struct Identifier<C, COM = ()>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Transparency Flag
    pub is_transparent: C::Bool,

    /// UTXO Commitment Randomness
    pub utxo_commitment_randomness: UtxoCommitmentRandomness<C, COM>,
}

impl<C, COM> Identifier<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`Identifier`] from `is_transparent` and `utxo_commitment_randomness`.
    #[inline]
    pub fn new(
        is_transparent: C::Bool,
        utxo_commitment_randomness: UtxoCommitmentRandomness<C, COM>,
    ) -> Self {
        Self {
            is_transparent,
            utxo_commitment_randomness,
        }
    }
}

impl<C> Sample for Identifier<C>
where
    C: BaseConfiguration<Bool = bool>,
    UtxoCommitmentRandomness<C>: Sample,
{
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        // FIXME: Should we sample the transparency flag.
        Self::new(false, rng.gen())
    }
}

/// Spend Secret
pub struct SpendSecret<C, COM = ()>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Outgoing Randomness
    outgoing_randomness: OutgoingRandomness<C, COM>,

    /// Plaintext
    plaintext: IncomingPlaintext<C, COM>,
}

impl<C, COM> SpendSecret<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`SpendSecret`] from `outgoing_randomness`, and `plaintext`.
    #[inline]
    pub fn new(
        outgoing_randomness: OutgoingRandomness<C, COM>,
        plaintext: IncomingPlaintext<C, COM>,
    ) -> Self {
        Self {
            outgoing_randomness,
            plaintext,
        }
    }

    /// Returns the UTXO commitment for `self` with the given `receiving_key` under
    /// `utxo_commitment_scheme`.
    #[inline]
    pub fn utxo_commitment(
        &self,
        utxo_commitment_scheme: &C::UtxoCommitmentScheme,
        receiving_key: &C::Group,
        compiler: &mut COM,
    ) -> UtxoCommitment<C, COM> {
        utxo_commitment_scheme.commit(
            &self.plaintext.utxo_commitment_randomness,
            &self.plaintext.asset.id,
            &self.plaintext.asset.value,
            receiving_key,
            compiler,
        )
    }

    /// Returns the outgoing note for `self` with the given `receiving_key` under
    /// `encryption_scheme`.
    #[inline]
    pub fn outgoing_note(
        &self,
        group_generator: &C::Group,
        outgoing_base_encryption_scheme: &C::OutgoingBaseEncryptionScheme,
        receiving_key: &C::Group,
        compiler: &mut COM,
    ) -> OutgoingNote<C, COM> {
        Hybrid::new(
            StandardDiffieHellman::new(group_generator.clone()),
            outgoing_base_encryption_scheme.clone(),
        )
        .encrypt_into(
            receiving_key,
            &self.outgoing_randomness,
            EmptyHeader::default(),
            &self.plaintext.asset,
            compiler,
        )
    }

    /// Returns the representative [`Asset`] from `self` and its public-form `utxo` asserting that
    /// it is well-formed.
    #[inline]
    pub fn well_formed_asset(
        &self,
        parameters: &BaseParameters<C, COM>,
        utxo_accumulator_model: &C::UtxoAccumulatorModel,
        authorization_context: &mut AuthorizationContext<C, COM>,
        utxo: &Utxo<C, COM>,
        utxo_membership_proof: &UtxoMembershipProof<C, COM>,
        compiler: &mut COM,
    ) -> (Asset<C, COM>, Nullifier<C, COM>)
    where
        COM: AssertEq,
    {
        let is_transparent = self.plaintext.asset.is_empty(compiler);
        compiler.assert_eq(&utxo.is_transparent, &is_transparent);
        let asset = Asset::<C, _>::select(
            &utxo.is_transparent,
            &utxo.public_asset,
            &self.plaintext.asset,
            compiler,
        );
        let receiving_key = authorization_context.receiving_key(
            parameters.group_generator.generator(),
            &parameters.viewing_key_derivation_function,
            compiler,
        );
        let utxo_commitment =
            self.utxo_commitment(&parameters.utxo_commitment_scheme, receiving_key, compiler);
        compiler.assert_eq(&utxo.commitment, &utxo_commitment);
        let receiving_key = authorization_context.receiving_key(
            parameters.group_generator.generator(),
            &parameters.viewing_key_derivation_function,
            compiler,
        );
        let outgoing_note = self.outgoing_note(
            parameters.group_generator.generator(),
            &parameters.outgoing_base_encryption_scheme,
            receiving_key,
            compiler,
        );
        let item = parameters.item_hash(utxo, compiler);
        let has_valid_membership = &asset.value.is_zero(compiler).bitor(
            utxo_membership_proof.verify(utxo_accumulator_model, &item, compiler),
            compiler,
        );
        compiler.assert(has_valid_membership);
        let nullifier_commitment = parameters.nullifier_commitment_scheme.commit(
            &authorization_context.proof_authorization_key,
            &item,
            compiler,
        );
        (asset, Nullifier::new(nullifier_commitment, outgoing_note))
    }
}

impl<C, COM> utxo::AssetType for SpendSecret<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    type Asset = Asset<C, COM>;
}

impl<C, COM> utxo::UtxoType for SpendSecret<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    type Utxo = Utxo<C, COM>;
}

impl<C> utxo::QueryAsset for SpendSecret<C>
where
    C: BaseConfiguration<Bool = bool>,
    C::AssetId: Clone,
    C::AssetValue: Clone,
{
    #[inline]
    fn query_asset(&self, utxo: &Self::Utxo) -> Self::Asset {
        if utxo.is_transparent {
            utxo.public_asset.clone()
        } else {
            self.plaintext.asset.clone()
        }
    }
}

impl<C, COM> Variable<Secret, COM> for SpendSecret<C, COM>
where
    C: BaseConfiguration<COM> + Constant<COM>,
    C::Type: BaseConfiguration<Bool = bool>,
    COM: Has<bool, Type = C::Bool>,
    OutgoingRandomness<C, COM>: Variable<Secret, COM, Type = OutgoingRandomness<C::Type>>,
    IncomingPlaintext<C, COM>: Variable<Secret, COM, Type = IncomingPlaintext<C::Type>>,
{
    type Type = SpendSecret<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.outgoing_randomness.as_known(compiler),
            this.plaintext.as_known(compiler),
        )
    }
}

/// Nullifier
#[derive(derivative::Derivative)]
#[derivative(Debug(bound = "NullifierCommitment<C, COM>: Debug, OutgoingNote<C, COM>: Debug"))]
pub struct Nullifier<C, COM = ()>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Nullifier Commitment
    pub commitment: NullifierCommitment<C, COM>,

    /// Outgoing Note
    pub outgoing_note: OutgoingNote<C, COM>,
}

impl<C, COM> Nullifier<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`Nullifier`] from `commitment` and `outgoing_note`.
    #[inline]
    pub fn new(
        commitment: NullifierCommitment<C, COM>,
        outgoing_note: OutgoingNote<C, COM>,
    ) -> Self {
        Self {
            commitment,
            outgoing_note,
        }
    }
}

impl<C, COM> PartialEq<Self, COM> for Nullifier<C, COM>
where
    C: BaseConfiguration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.commitment.eq(&rhs.commitment, compiler).bitand(
            self.outgoing_note.eq(&rhs.outgoing_note, compiler),
            compiler,
        )
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        compiler.assert_eq(&self.commitment, &rhs.commitment);
        compiler.assert_eq(&self.outgoing_note, &rhs.outgoing_note);
    }
}

impl<C, COM> Variable<Public, COM> for Nullifier<C, COM>
where
    C: BaseConfiguration<COM> + Constant<COM>,
    C::Type: BaseConfiguration<Bool = bool>,
    COM: Has<bool, Type = C::Bool>,
    NullifierCommitment<C, COM>: Variable<Public, COM, Type = NullifierCommitment<C::Type>>,
    OutgoingNote<C, COM>: Variable<Public, COM, Type = OutgoingNote<C::Type>>,
{
    type Type = Nullifier<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.commitment.as_known(compiler),
            this.outgoing_note.as_known(compiler),
        )
    }
}

impl<C> Independence<utxo::NullifierIndependence> for Nullifier<C>
where
    C: BaseConfiguration<Bool = bool>,
{
    #[inline]
    fn is_independent(&self, rhs: &Self) -> bool {
        self.commitment.ne(&rhs.commitment, &mut ())
    }
}

impl<C> Encode for Nullifier<C>
where
    C: BaseConfiguration<Bool = bool>,
    NullifierCommitment<C>: Encode,
    OutgoingNote<C>: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.commitment.encode(&mut writer)?;
        self.outgoing_note.encode(&mut writer)?;
        Ok(())
    }
}

impl<C, P> Input<P> for Nullifier<C>
where
    C: BaseConfiguration<Bool = bool>,
    P: HasInput<NullifierCommitment<C>> + HasInput<OutgoingNote<C>> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.commitment);
        P::extend(input, &self.outgoing_note);
    }
}
