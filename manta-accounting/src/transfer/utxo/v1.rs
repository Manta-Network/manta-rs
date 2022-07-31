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

use crate::{asset, transfer::utxo};
use core::marker::PhantomData;
use manta_crypto::{
    accumulator::{self, ItemHashFunction, MembershipProof},
    algebra::{security::ComputationalDiffieHellmanHardness, DiffieHellman, Group, Scalar},
    constraint::{
        Allocate, Allocator, Assert, AssertEq, BitAnd, BitOr, Bool, ConditionalSelect, Constant,
        Has, PartialEq, Public, Secret, Variable, Zero,
    },
    encryption::{self, hybrid::Hybrid, Decrypt, Encrypt, EncryptedMessage},
    rand::{CryptoRng, Rand, RngCore, Sample},
};
use manta_util::cmp::Independence;

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
    type Randomness;

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

    /// Asset Type
    type Asset;

    /// UTXO Commitment Type
    type Commitment;

    /// Item Type
    type Item;

    /// Computes the accumulator item by hashing `is_transparent`, `public_asset`, and `commitment`.
    fn hash(
        &self,
        is_transparent: &Self::Bool,
        public_asset: &Self::Asset,
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
pub trait Configuration<COM = ()>
where
    COM: Has<bool, Type = Self::Bool>,
{
    /// Boolean Type
    type Bool: Constant<COM, Type = bool>
        + BitAnd<Self::Bool, COM, Output = Self::Bool>
        + BitOr<Self::Bool, COM, Output = Self::Bool>
        + PartialEq<Self::Bool, COM>;

    /// Asset Id Type
    type AssetId: ConditionalSelect<COM> + Zero<COM, Verification = Self::Bool>;

    /// Asset Value Type
    type AssetValue: ConditionalSelect<COM> + Zero<COM, Verification = Self::Bool>;

    /// Scalar Type
    type Scalar: Clone + Scalar<COM>;

    /// Group Type
    type Group: Clone
        + ComputationalDiffieHellmanHardness
        + Group<COM, Scalar = Self::Scalar>
        + PartialEq<Self::Group, COM>;

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
            Header = EmptyHeader<Self, COM>,
            Plaintext = IncomingPlaintext<Self, COM>,
            Ciphertext = Self::IncomingCiphertext,
        >;

    /// UTXO Accumulator Item Hash
    type UtxoAccumulatorItemHash: UtxoAccumulatorItemHash<
        COM,
        Bool = Self::Bool,
        Asset = Asset<Self, COM>,
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
            Header = EmptyHeader<Self, COM>,
            Plaintext = Asset<Self, COM>,
            Ciphertext = Self::OutgoingCiphertext,
        >;
}

/// Asset Type
pub type Asset<C, COM = ()> =
    asset::Asset<<C as Configuration<COM>>::AssetId, <C as Configuration<COM>>::AssetValue>;

/// UTXO Commitment
pub type UtxoCommitment<C, COM = ()> =
    <<C as Configuration<COM>>::UtxoCommitmentScheme as UtxoCommitmentScheme<COM>>::Commitment;

/// UTXO Commitment Randomness
pub type UtxoCommitmentRandomness<C, COM = ()> =
    <<C as Configuration<COM>>::UtxoCommitmentScheme as UtxoCommitmentScheme<COM>>::Randomness;

/// Incoming Encryption Scheme
pub type IncomingEncryptionScheme<C, COM = ()> = Hybrid<
    DiffieHellman<<C as Configuration<COM>>::Group, COM>,
    <C as Configuration<COM>>::IncomingBaseEncryptionScheme,
>;

/// Incoming Randomness
pub type IncomingRandomness<C, COM = ()> = encryption::Randomness<IncomingEncryptionScheme<C, COM>>;

/// Incoming Encrypted Note
pub type IncomingNote<C, COM = ()> = EncryptedMessage<IncomingEncryptionScheme<C, COM>>;

/// UTXO Accumulator Item
pub type UtxoAccumulatorItem<C, COM = ()> =
    <<C as Configuration<COM>>::UtxoAccumulatorItemHash as UtxoAccumulatorItemHash<COM>>::Item;

/// UTXO Membership Proof
pub type UtxoMembershipProof<C, COM = ()> =
    MembershipProof<<C as Configuration<COM>>::UtxoAccumulatorModel>;

/// Nullifier Commitment
pub type NullifierCommitment<C, COM = ()> =
    <<C as Configuration<COM>>::NullifierCommitmentScheme as NullifierCommitmentScheme<COM>>::Commitment;

/// Outgoing Encryption Scheme
pub type OutgoingEncryptionScheme<C, COM = ()> = Hybrid<
    DiffieHellman<<C as Configuration<COM>>::Group, COM>,
    <C as Configuration<COM>>::OutgoingBaseEncryptionScheme,
>;

/// Outgoing Randomness
pub type OutgoingRandomness<C, COM = ()> = encryption::Randomness<OutgoingEncryptionScheme<C, COM>>;

/// Outgoing Note
pub type OutgoingNote<C, COM = ()> = EncryptedMessage<OutgoingEncryptionScheme<C, COM>>;

/// Empty Header
///
/// The header is unused for this version of the UTXO protocol.
#[derive(derivative::Derivative)]
#[derivative(Default)]
pub struct EmptyHeader<C, COM = ()>(PhantomData<C>, PhantomData<COM>)
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>;

impl<C, COM> PartialEq<Self, COM> for EmptyHeader<C, COM>
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        let _ = rhs;
        C::Bool::new_constant(&true, compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM) {
        let _ = (rhs, compiler);
    }
}

/// UTXO Model Parameters
pub struct Parameters<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
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

impl<C, COM> utxo::auth::AuthorizationKeyType for Parameters<C, COM>
where
    C: Configuration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type AuthorizationKey = AuthorizationKey<C, COM>;
}

impl<C, COM> utxo::auth::RandomnessType for Parameters<C, COM>
where
    C: Configuration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Randomness = C::Scalar;
}

impl<C, COM> utxo::AssetType for Parameters<C, COM>
where
    C: Configuration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Asset = Asset<C, COM>;
}

impl<C> utxo::AssociatedDataType for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type AssociatedData = Visibility;
}

impl<C, COM> utxo::AddressType for Parameters<C, COM>
where
    C: Configuration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Address = Address<C, COM>;
}

impl<C, COM> utxo::NoteType for Parameters<C, COM>
where
    C: Configuration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Note = IncomingNote<C, COM>;
}

impl<C, COM> utxo::UtxoType for Parameters<C, COM>
where
    C: Configuration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Utxo = Utxo<C, COM>;
}

impl<C, COM> utxo::NullifierType for Parameters<C, COM>
where
    C: Configuration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Nullifier = Nullifier<C, COM>;
}

impl<C, COM> utxo::Mint<COM> for Parameters<C, COM>
where
    C: Configuration<COM>,
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
            &self.utxo_commitment_scheme,
            &self.incoming_base_encryption_scheme,
            utxo,
            note,
            compiler,
        )
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
        R: CryptoRng + RngCore + ?Sized,
    {
        let secret = MintSecret::<C>::new(
            address.receiving_key,
            rng.gen(),
            IncomingPlaintext::new(
                rng.gen(),
                associated_data.secret(&asset),
                address.key_diversifier,
            ),
        );
        let utxo_commitment = self.utxo_commitment_scheme.commit(
            &secret.plaintext.utxo_commitment_randomness,
            &secret.plaintext.asset.id,
            &secret.plaintext.asset.value,
            &secret.receiving_key,
            &mut (),
        );
        let incoming_note = Hybrid::new(
            DiffieHellman::new(secret.plaintext.key_diversifier.clone()),
            self.incoming_base_encryption_scheme.clone(),
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

impl<C, COM> accumulator::ItemHashFunction<Utxo<C, COM>, COM> for Parameters<C, COM>
where
    C: Configuration<COM>,
    COM: Assert + Has<bool, Type = C::Bool>,
{
    type Item = UtxoAccumulatorItem<C, COM>;

    #[inline]
    fn item_hash(&self, utxo: &Utxo<C, COM>, compiler: &mut COM) -> Self::Item {
        self.utxo_accumulator_item_hash.hash(
            &utxo.is_transparent,
            &utxo.public_asset,
            &utxo.commitment,
            compiler,
        )
    }
}

impl<C, COM> utxo::Spend<COM> for Parameters<C, COM>
where
    C: Configuration<COM>,
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
        authorization_key: &mut Self::AuthorizationKey,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        utxo_membership_proof: &UtxoMembershipProof<C, COM>,
        compiler: &mut COM,
    ) -> (Self::Asset, Self::Nullifier) {
        secret.well_formed_asset(
            self,
            utxo_accumulator_model,
            authorization_key,
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
        authorization_key: &mut Self::AuthorizationKey,
        identifier: Self::Identifier,
        asset: Self::Asset,
        rng: &mut R,
    ) -> (Self::Secret, Self::Utxo, Self::Nullifier)
    where
        R: CryptoRng + RngCore + ?Sized,
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
                identifier.key_diversifier,
            ),
        );
        let receiving_key = authorization_key.receiving_key(
            &self.viewing_key_derivation_function,
            &secret.plaintext.key_diversifier,
            &mut (),
        );
        let utxo_commitment = self.utxo_commitment_scheme.commit(
            &secret.plaintext.utxo_commitment_randomness,
            &secret.plaintext.asset.id,
            &secret.plaintext.asset.value,
            &receiving_key,
            &mut (),
        );
        let utxo = Utxo::<C>::new(
            identifier.is_transparent,
            associated_data.public(&asset),
            utxo_commitment,
        );

        let nullifier_commitment = self.nullifier_commitment_scheme.commit(
            &authorization_key.proof_authorization_key,
            &self.item_hash(&utxo, &mut ()),
            &mut (),
        );
        let outgoing_note = Hybrid::new(
            DiffieHellman::new(secret.plaintext.key_diversifier.clone()),
            self.outgoing_base_encryption_scheme.clone(),
        )
        .encrypt_into(
            &receiving_key,
            &secret.outgoing_randomness,
            EmptyHeader::default(),
            &secret.plaintext.asset,
            &mut (),
        );
        (
            secret,
            utxo,
            Nullifier::new(nullifier_commitment, outgoing_note),
        )
    }
}

impl<C, COM> utxo::IdentifierType for Parameters<C, COM>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    type Identifier = Identifier<C, COM>;
}

impl<C> utxo::DeriveDecryptionKey for Parameters<C>
where
    C: Configuration<Bool = bool>,
{
    type DecryptionKey = C::Scalar;

    #[inline]
    fn derive(&self, authorization_key: &mut Self::AuthorizationKey) -> Self::DecryptionKey {
        authorization_key
            .viewing_key(&self.viewing_key_derivation_function, &mut ())
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
        let plaintext = self.incoming_base_encryption_scheme.decrypt(
            &note.ephemeral_public_key().mul(decryption_key, &mut ()),
            &EmptyHeader::default(),
            &note.ciphertext.ciphertext,
            &mut (),
        )?;
        Some((
            Identifier::new(
                utxo.is_transparent,
                plaintext.utxo_commitment_randomness,
                plaintext.key_diversifier,
            ),
            plaintext.asset,
        ))
    }
}

/// Address
pub struct Address<C, COM = ()>
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Key Diversifier
    pub key_diversifier: C::Group,

    /// Receiving Key
    pub receiving_key: C::Group,
}

/// Incoming Note Plaintext
pub struct IncomingPlaintext<C, COM = ()>
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// UTXO Commitment Randomness
    pub utxo_commitment_randomness: UtxoCommitmentRandomness<C, COM>,

    /// Secret Asset
    pub asset: Asset<C, COM>,

    /// Key Diversifier
    pub key_diversifier: C::Group,
}

impl<C, COM> IncomingPlaintext<C, COM>
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`IncomingPlaintext`] from `utxo_commitment_randomness`, `asset`, and
    /// `key_diversifier`.
    #[inline]
    pub fn new(
        utxo_commitment_randomness: UtxoCommitmentRandomness<C, COM>,
        asset: Asset<C, COM>,
        key_diversifier: C::Group,
    ) -> Self {
        Self {
            utxo_commitment_randomness,
            asset,
            key_diversifier,
        }
    }
}

impl<C, COM> Variable<Secret, COM> for IncomingPlaintext<C, COM>
where
    C: Configuration<COM> + Constant<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
    C::Type: Configuration<Bool = bool>,
    UtxoCommitmentRandomness<C, COM>:
        Variable<Secret, COM, Type = UtxoCommitmentRandomness<C::Type>>,
    Asset<C, COM>: Variable<Secret, COM, Type = Asset<C::Type>>,
    C::Group: Variable<Secret, COM, Type = <C::Type as Configuration>::Group>,
{
    type Type = IncomingPlaintext<C::Type>;

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
            this.utxo_commitment_randomness.as_known(compiler),
            this.asset.as_known(compiler),
            this.key_diversifier.as_known(compiler),
        )
    }
}

/// UTXO
pub struct Utxo<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Transparency Flag
    is_transparent: C::Bool,

    /// Public Asset Data
    public_asset: Asset<C, COM>,

    /// UTXO Commitment
    commitment: UtxoCommitment<C, COM>,
}

impl<C, COM> Utxo<C, COM>
where
    C: Configuration<COM>,
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
}

impl<C> Independence<utxo::UtxoIndependence> for Utxo<C>
where
    C: Configuration<Bool = bool>,
{
    #[inline]
    fn is_independent(&self, rhs: &Self) -> bool {
        // TODO: self.neq(rhs)
        todo!()
    }
}

impl<C, COM, M> Variable<M, COM> for Utxo<C, COM>
where
    C: Configuration<COM> + Constant<COM>,
    COM: Has<bool, Type = C::Bool>,
    C::Type: Configuration<Bool = bool>,
    C::Bool: Variable<M, COM, Type = <C::Type as Configuration>::Bool>,
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

/// Secret required to Mint a UTXO
pub struct MintSecret<C, COM = ()>
where
    C: Configuration<COM>,
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
    C: Configuration<COM>,
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
        encryption_scheme: &C::IncomingBaseEncryptionScheme,
        compiler: &mut COM,
    ) -> IncomingNote<C, COM> {
        Hybrid::new(
            DiffieHellman::new(self.plaintext.key_diversifier.clone()),
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
        let incoming_note = self.incoming_note(encryption_scheme, compiler);
        compiler.assert_eq(note, &incoming_note);
        asset
    }
}

impl<C, COM> Variable<Secret, COM> for MintSecret<C, COM>
where
    C: Configuration<COM> + Constant<COM>,
    COM: Has<bool, Type = C::Bool>,
    C::Type: Configuration<Bool = bool>,
    C::Group: Variable<Secret, COM, Type = <C::Type as Configuration>::Group>,
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

/// Authorization Key
pub struct AuthorizationKey<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Proof Authorization Key
    proof_authorization_key: C::Group,

    /// ViewingKey
    viewing_key: Option<C::Scalar>,
}

impl<C, COM> AuthorizationKey<C, COM>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`AuthorizationKey`] from `proof_authorization_key`.
    #[inline]
    pub fn new(proof_authorization_key: C::Group) -> Self {
        Self {
            proof_authorization_key,
            viewing_key: None,
        }
    }

    /// Computes the viewing key from `viewing_key_derivation_function`.
    #[inline]
    pub fn viewing_key(
        &mut self,
        viewing_key_derivation_function: &C::ViewingKeyDerivationFunction,
        compiler: &mut COM,
    ) -> &C::Scalar {
        self.viewing_key.get_or_insert_with(|| {
            viewing_key_derivation_function.viewing_key(&self.proof_authorization_key, compiler)
        })
    }

    /// Returns the receiving key over `key_diversifier` for this [`AuthorizationKey`].
    #[inline]
    pub fn receiving_key(
        &mut self,
        viewing_key_derivation_function: &C::ViewingKeyDerivationFunction,
        key_diversifier: &C::Group,
        compiler: &mut COM,
    ) -> C::Group {
        key_diversifier.mul(
            self.viewing_key(viewing_key_derivation_function, compiler),
            compiler,
        )
    }
}

/// Identifier
pub struct Identifier<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Transparency Flag
    pub is_transparent: C::Bool,

    /// UTXO Commitment Randomness
    pub utxo_commitment_randomness: UtxoCommitmentRandomness<C, COM>,

    /// Key Diversifier
    pub key_diversifier: C::Group,
}

impl<C, COM> Identifier<C, COM>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`Identifier`] from `is_transparent`, `utxo_commitment_randomness`, and
    /// `key_diversifier`.
    #[inline]
    pub fn new(
        is_transparent: C::Bool,
        utxo_commitment_randomness: UtxoCommitmentRandomness<C, COM>,
        key_diversifier: C::Group,
    ) -> Self {
        Self {
            is_transparent,
            utxo_commitment_randomness,
            key_diversifier,
        }
    }
}

impl<C> Sample for Identifier<C>
where
    C: Configuration<Bool = bool>,
    UtxoCommitmentRandomness<C>: Sample,
    C::Group: Sample,
{
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(false, rng.gen(), rng.gen())
    }
}

/// Spend Secret
pub struct SpendSecret<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Outgoing Randomness
    outgoing_randomness: OutgoingRandomness<C, COM>,

    /// Plaintext
    plaintext: IncomingPlaintext<C, COM>,
}

impl<C, COM> SpendSecret<C, COM>
where
    C: Configuration<COM>,
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
        outgoing_base_encryption_scheme: &C::OutgoingBaseEncryptionScheme,
        receiving_key: &C::Group,
        compiler: &mut COM,
    ) -> OutgoingNote<C, COM> {
        Hybrid::new(
            DiffieHellman::new(self.plaintext.key_diversifier.clone()),
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
        parameters: &Parameters<C, COM>,
        utxo_accumulator_model: &C::UtxoAccumulatorModel,
        authorization_key: &mut AuthorizationKey<C, COM>,
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
        let receiving_key = authorization_key.receiving_key(
            &parameters.viewing_key_derivation_function,
            &self.plaintext.key_diversifier,
            compiler,
        );
        let utxo_commitment =
            self.utxo_commitment(&parameters.utxo_commitment_scheme, &receiving_key, compiler);
        compiler.assert_eq(&utxo.commitment, &utxo_commitment);
        let item = parameters.item_hash(utxo, compiler);
        let has_valid_membership = &asset.value.is_zero(compiler).bitor(
            utxo_membership_proof.verify(utxo_accumulator_model, &item, compiler),
            compiler,
        );
        compiler.assert(has_valid_membership);
        let nullifier_commitment = parameters.nullifier_commitment_scheme.commit(
            &authorization_key.proof_authorization_key,
            &item,
            compiler,
        );
        let outgoing_note = self.outgoing_note(
            &parameters.outgoing_base_encryption_scheme,
            &receiving_key,
            compiler,
        );
        (asset, Nullifier::new(nullifier_commitment, outgoing_note))
    }
}

impl<C, COM> Variable<Secret, COM> for SpendSecret<C, COM>
where
    C: Configuration<COM> + Constant<COM>,
    C::Type: Configuration<Bool = bool>,
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
pub struct Nullifier<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Nullifier Commitment
    pub commitment: NullifierCommitment<C, COM>,

    /// Outgoing Note
    pub outgoing_note: OutgoingNote<C, COM>,
}

impl<C, COM> Nullifier<C, COM>
where
    C: Configuration<COM>,
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
    C: Configuration<COM>,
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
    C: Configuration<COM> + Constant<COM>,
    C::Type: Configuration<Bool = bool>,
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
    C: Configuration<Bool = bool>,
{
    #[inline]
    fn is_independent(&self, rhs: &Self) -> bool {
        // TODO: self.commitment.neq(&rhs.commitment)
        todo!()
    }
}
