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

use crate::transfer::utxo;
use core::marker::PhantomData;
use manta_crypto::{
    accumulator::{self, MembershipProof},
    algebra::{security::ComputationalDiffieHellmanHardness, DiffieHellman, Group, Scalar},
    constraint::{
        Allocate, Allocator, Assert, AssertEq, BitAnd, BitOr, Bool, ConditionalSelect, Constant,
        Has, PartialEq, Public, Secret, Variable, Zero,
    },
    encryption::{hybrid::Hybrid, Encrypt, EncryptedMessage, RandomnessType},
};

/// UTXO Version Number
pub const VERSION: u8 = 1;

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
pub trait NullifierCommitmentScheme<COM = ()> {
    /// Proof Authorization Key
    type ProofAuthorizationKey;

    /// UTXO Accumulator Item
    type UtxoAccumulatorItem;

    /// Nullifier Commitment
    type Commitment;

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
    type Scalar: Scalar<COM>;

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
    type OutgoingCiphertext: PartialEq<Self::IncomingCiphertext, COM>;

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
pub type IncomingRandomness<C, COM = ()> =
    <IncomingEncryptionScheme<C, COM> as RandomnessType>::Randomness;

/// Incoming Encrypted Note
pub type IncomingNote<C, COM = ()> = EncryptedMessage<IncomingEncryptionScheme<C, COM>>;

/// UTXO Accumulator Item
pub type UtxoAccumulatorItem<C, COM = ()> =
    <<C as Configuration<COM>>::UtxoAccumulatorItemHash as UtxoAccumulatorItemHash<COM>>::Item;

/// UTXO Membership Proof
pub type UtxoMembershipProof<C, COM = ()> =
    MembershipProof<<C as Configuration<COM>>::UtxoAccumulatorModel, COM>;

/// Nullifier Commitment
pub type NullifierCommitment<C, COM = ()> =
    <<C as Configuration<COM>>::NullifierCommitmentScheme as NullifierCommitmentScheme<COM>>::Commitment;

/// Outgoing Encryption Scheme
pub type OutgoingEncryptionScheme<C, COM = ()> = Hybrid<
    DiffieHellman<<C as Configuration<COM>>::Group, COM>,
    <C as Configuration<COM>>::OutgoingBaseEncryptionScheme,
>;

/// Outgoing Randomness
pub type OutgoingRandomness<C, COM = ()> =
    <OutgoingEncryptionScheme<C, COM> as RandomnessType>::Randomness;

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

/// UTXO Model
pub struct Model<C, COM = ()>
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

    /// UTXO Accumulator Model
    pub utxo_accumulator_model: C::UtxoAccumulatorModel,

    /// Nullifier Commitment Scheme
    pub nullifier_commitment_scheme: C::NullifierCommitmentScheme,

    /// Outgoing Base Encryption Scheme
    pub outgoing_base_encryption_scheme: C::OutgoingBaseEncryptionScheme,
}

impl<C, COM> utxo::Types for Model<C, COM>
where
    C: Configuration<COM>,
    COM: AssertEq + Has<bool, Type = C::Bool>,
{
    type Asset = Asset<C, COM>;
    type Utxo = Utxo<C, COM>;
}

impl<C, COM> utxo::Mint<MintSecret<C, COM>, COM> for Model<C, COM>
where
    C: Configuration<COM>,
    COM: AssertEq + Has<bool, Type = C::Bool>,
{
    type Authority = ();
    type Note = IncomingNote<C, COM>;

    #[inline]
    fn well_formed_asset(
        &self,
        authority: &Self::Authority,
        secret: &MintSecret<C, COM>,
        utxo: &Self::Utxo,
        note: &Self::Note,
        compiler: &mut COM,
    ) -> Self::Asset {
        let _ = authority;
        secret.well_formed_asset(
            &self.utxo_commitment_scheme,
            &self.incoming_base_encryption_scheme,
            utxo,
            note,
            compiler,
        )
    }
}

impl<C, COM> utxo::Spend<SpendSecret<C, COM>, COM> for Model<C, COM>
where
    C: Configuration<COM>,
    COM: AssertEq + Has<bool, Type = C::Bool>,
{
    type Authority = ProofAuthority<C, COM>;
    type Nullifier = Nullifier<C, COM>;

    #[inline]
    fn well_formed_asset(
        &self,
        authority: &Self::Authority,
        secret: &SpendSecret<C, COM>,
        utxo: &Self::Utxo,
        compiler: &mut COM,
    ) -> (Self::Asset, Self::Nullifier) {
        secret.well_formed_asset(self, authority, utxo, compiler)
    }
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

/// Asset Definition
pub struct Asset<C, COM = ()>
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Asset Id
    pub id: C::AssetId,

    /// Asset Value
    pub value: C::AssetValue,
}

impl<C, COM> Asset<C, COM>
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`Asset`] from `id` and `value`.
    #[inline]
    pub fn new(id: C::AssetId, value: C::AssetValue) -> Self {
        Self { id, value }
    }

    /// Returns `true` if `self` is an empty [`Asset`], i.e. both the `id` and `value` are zero.
    #[inline]
    pub fn is_empty(&self, compiler: &mut COM) -> C::Bool {
        self.id
            .is_zero(compiler)
            .bitand(self.value.is_zero(compiler), compiler)
    }
}

impl<C, COM> ConditionalSelect<COM> for Asset<C, COM>
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
{
    #[inline]
    fn select(bit: &Bool<COM>, true_value: &Self, false_value: &Self, compiler: &mut COM) -> Self {
        Self::new(
            C::AssetId::select(bit, &true_value.id, &false_value.id, compiler),
            C::AssetValue::select(bit, &true_value.value, &false_value.value, compiler),
        )
    }
}

impl<C, COM, M> Variable<M, COM> for Asset<C, COM>
where
    C: Configuration<COM> + Constant<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>,
    C::Type: Configuration<Bool = bool>,
    C::AssetId: Variable<M, COM, Type = <C::Type as Configuration>::AssetId>,
    C::AssetValue: Variable<M, COM, Type = <C::Type as Configuration>::AssetValue>,
{
    type Type = Asset<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(this.id.as_known(compiler), this.value.as_known(compiler))
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
        let asset = Asset::select(
            &utxo.is_transparent,
            &utxo.public_asset,
            &self.plaintext.asset,
            compiler,
        );
        let utxo_commitment = utxo_commitment_scheme.commit(
            &self.plaintext.utxo_commitment_randomness,
            &self.plaintext.asset.id,
            &self.plaintext.asset.value,
            &self.receiving_key,
            compiler,
        );
        compiler.assert_eq(&utxo.commitment, &utxo_commitment);
        let incoming_note = Hybrid::new(
            DiffieHellman::<_, COM>::new(self.plaintext.key_diversifier.clone()),
            encryption_scheme.clone(),
        )
        .encrypt_into(
            &self.receiving_key,
            &self.incoming_randomness,
            EmptyHeader::default(),
            &self.plaintext,
            compiler,
        );
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

/// Proof Authority
pub struct ProofAuthority<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Proof Authorization Key
    proof_authorization_key: C::Group,

    /// Viewing Key
    viewing_key: C::Scalar,
}

impl<C, COM> ProofAuthority<C, COM>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`ProofAuthority`] over `proof_authorization_key`, asserting that the
    /// `randomized_proof_authorization_key` is derived from the `randomizer` and the
    /// `proof_authorization_key`.
    #[inline]
    pub fn new(
        viewing_key_derivation_function: &C::ViewingKeyDerivationFunction,
        randomizer: &C::Scalar,
        randomized_proof_authorization_key: &C::Group,
        proof_authorization_key: C::Group,
        compiler: &mut COM,
    ) -> Self
    where
        COM: Assert,
    {
        let computed_randomized_proof_authorization_key =
            proof_authorization_key.mul(randomizer, compiler);
        compiler.assert_eq(
            randomized_proof_authorization_key,
            &computed_randomized_proof_authorization_key,
        );
        Self {
            viewing_key: viewing_key_derivation_function
                .viewing_key(&proof_authorization_key, compiler),
            proof_authorization_key,
        }
    }

    /// Returns the receiving key over `key_diversifier` for this [`ProofAuthority`].
    #[inline]
    pub fn receiving_key(&self, key_diversifier: &C::Group, compiler: &mut COM) -> C::Group {
        key_diversifier.mul(&self.viewing_key, compiler)
    }
}

/// Spend Secret
pub struct SpendSecret<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// UTXO Membership Proof
    utxo_membership_proof: UtxoMembershipProof<C, COM>,

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
    /// Builds a new [`SpendSecret`] from `utxo_membership_proof`, `outgoing_randomness`, and
    /// `plaintext`.
    #[inline]
    pub fn new(
        utxo_membership_proof: UtxoMembershipProof<C, COM>,
        outgoing_randomness: OutgoingRandomness<C, COM>,
        plaintext: IncomingPlaintext<C, COM>,
    ) -> Self {
        Self {
            utxo_membership_proof,
            outgoing_randomness,
            plaintext,
        }
    }

    /// Returns the representative [`Asset`] from `self` and its public-form `utxo` asserting that
    /// it is well-formed.
    #[inline]
    pub fn well_formed_asset(
        &self,
        model: &Model<C, COM>,
        authority: &ProofAuthority<C, COM>,
        utxo: &Utxo<C, COM>,
        compiler: &mut COM,
    ) -> (Asset<C, COM>, Nullifier<C, COM>)
    where
        COM: AssertEq,
    {
        let is_transparent = self.plaintext.asset.is_empty(compiler);
        compiler.assert_eq(&utxo.is_transparent, &is_transparent);
        let asset = Asset::select(
            &utxo.is_transparent,
            &utxo.public_asset,
            &self.plaintext.asset,
            compiler,
        );
        let receiving_key = authority.receiving_key(&self.plaintext.key_diversifier, compiler);
        let utxo_commitment = model.utxo_commitment_scheme.commit(
            &self.plaintext.utxo_commitment_randomness,
            &self.plaintext.asset.id,
            &self.plaintext.asset.value,
            &receiving_key,
            compiler,
        );
        compiler.assert_eq(&utxo.commitment, &utxo_commitment);
        let item = model.utxo_accumulator_item_hash.hash(
            &utxo.is_transparent,
            &utxo.public_asset,
            &utxo.commitment,
            compiler,
        );
        let has_valid_membership = &asset.value.is_zero(compiler).bitor(
            self.utxo_membership_proof
                .verify(&model.utxo_accumulator_model, &item, compiler),
            compiler,
        );
        compiler.assert(has_valid_membership);
        let nullifier_commitment = model.nullifier_commitment_scheme.commit(
            &authority.proof_authorization_key,
            &item,
            compiler,
        );
        let outgoing_note = Hybrid::new(
            DiffieHellman::<_, COM>::new(self.plaintext.key_diversifier.clone()),
            model.outgoing_base_encryption_scheme.clone(),
        )
        .encrypt_into(
            &receiving_key,
            &self.outgoing_randomness,
            EmptyHeader::default(),
            &self.plaintext.asset,
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
    UtxoMembershipProof<C, COM>: Variable<Secret, COM, Type = UtxoMembershipProof<C::Type>>,
    OutgoingRandomness<C, COM>: Variable<Secret, COM, Type = OutgoingRandomness<C::Type>>,
    IncomingPlaintext<C, COM>: Variable<Secret, COM, Type = IncomingPlaintext<C::Type>>,
{
    type Type = SpendSecret<C::Type>;

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
            this.utxo_membership_proof.as_known(compiler),
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
