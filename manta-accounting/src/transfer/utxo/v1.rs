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

use crate::transfer::utxo::VersionType;
use core::marker::PhantomData;
use manta_crypto::{
    constraint::{
        Allocate, Allocator, AssertEq, BitAnd, Bool, ConditionalSelect, Constant, Has, PartialEq,
        Secret, Variable, Zero,
    },
    encryption::{Encrypt, EncryptedMessage, EncryptionKeyType, RandomnessType},
};

/// UTXO Version Number
pub const VERSION: u8 = 1;

/// UTXO Commitment Scheme
pub trait CommitmentScheme<COM = ()>
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

/// UTXO Configuration
pub trait Configuration<COM = ()>: VersionType
where
    COM: Has<bool, Type = Self::Bool>,
{
    /// Boolean Type
    type Bool: BitAnd<Self::Bool, COM, Output = Self::Bool> + PartialEq<Self::Bool, COM>;

    /// Asset Id Type
    type AssetId: ConditionalSelect<COM> + Zero<COM, Verification = Self::Bool>;

    /// Asset Value Type
    type AssetValue: ConditionalSelect<COM> + Zero<COM, Verification = Self::Bool>;

    /// Key Diversifier
    type KeyDiversifier;

    /// Receiving Key
    type ReceivingKey;

    /// Incoming Note Ciphertext Type
    type IncomingNoteCiphertext: PartialEq<Self::IncomingNoteCiphertext, COM>;

    /// UTXO Commitment Scheme
    type CommitmentScheme: CommitmentScheme<
        COM,
        AssetId = Self::AssetId,
        AssetValue = Self::AssetValue,
        ReceivingKey = Self::ReceivingKey,
    >;

    /// Encryption Scheme for [`IncomingNote`]
    type EncryptionScheme: Encrypt<
        COM,
        Header = IncomingNoteHeader<Self, COM>,
        Plaintext = (
            CommitmentRandomness<Self, COM>,
            Self::AssetId,
            Self::AssetValue,
            Self::KeyDiversifier,
        ),
        Ciphertext = Self::IncomingNoteCiphertext,
    >;
}

/// UTXO Commitment
pub type Commitment<C, COM = ()> =
    <<C as Configuration<COM>>::CommitmentScheme as CommitmentScheme<COM>>::Commitment;

/// UTXO Commitment Randomness
pub type CommitmentRandomness<C, COM = ()> =
    <<C as Configuration<COM>>::CommitmentScheme as CommitmentScheme<COM>>::Randomness;

/// UTXO Encryption Key
pub type EncryptionKey<C, COM = ()> =
    <<C as Configuration<COM>>::EncryptionScheme as EncryptionKeyType>::EncryptionKey;

/// UTXO Encryption Randomness
pub type EncryptionRandomness<C, COM = ()> =
    <<C as Configuration<COM>>::EncryptionScheme as RandomnessType>::Randomness;

/// Asset Definition
pub struct Asset<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Asset Id
    pub id: C::AssetId,

    /// Asset Value
    pub value: C::AssetValue,
}

impl<C, COM> Asset<C, COM>
where
    C: Configuration<COM>,
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
    C: Configuration<COM>,
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
    C: Configuration<COM> + Constant<COM>,
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

/// Shielded Address
pub struct ShieldedAddress<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Key Diversifier
    pub key_diversifier: C::KeyDiversifier,

    /// Receiving Key
    pub receiving_key: C::ReceivingKey,
}

impl<C, COM> ShieldedAddress<C, COM>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`ShieldedAddress`] from `key_diversifier` and `receiving_key`.
    #[inline]
    pub fn new(key_diversifier: C::KeyDiversifier, receiving_key: C::ReceivingKey) -> Self {
        Self {
            key_diversifier,
            receiving_key,
        }
    }
}

impl<C, COM, M> Variable<M, COM> for ShieldedAddress<C, COM>
where
    C: Configuration<COM> + Constant<COM>,
    COM: Has<bool, Type = C::Bool>,
    C::Type: Configuration<Bool = bool>,
    C::KeyDiversifier: Variable<M, COM, Type = <C::Type as Configuration>::KeyDiversifier>,
    C::ReceivingKey: Variable<M, COM, Type = <C::Type as Configuration>::ReceivingKey>,
{
    type Type = ShieldedAddress<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.key_diversifier.as_known(compiler),
            this.receiving_key.as_known(compiler),
        )
    }
}

/// Incoming Note Unused Header
///
/// The header is unused for this version of the UTXO protocol.
#[derive(derivative::Derivative)]
#[derivative(Default)]
pub struct IncomingNoteHeader<C, COM = ()>(PhantomData<C>, PhantomData<COM>)
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool, Type = C::Bool>;

/// Incoming Note Type
pub type IncomingNote<C, COM = ()> = EncryptedMessage<<C as Configuration<COM>>::EncryptionScheme>;

/// UTXO
pub struct Utxo<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Transparency Flag
    pub is_transparent: C::Bool,

    /// Public Asset Data
    pub public_asset: Asset<C, COM>,

    /// Commitment
    pub commitment: Commitment<C, COM>,

    /// Incoming Encrypted Note
    pub incoming_note: IncomingNote<C, COM>,
}

impl<C, COM> Utxo<C, COM>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`Utxo`] from `is_transparent`, `public_asset`, `commitment`, and
    /// `incoming_note`. To build a [`Utxo`] from its secret pre-image use
    /// [`UtxoSecret::into_well_formed_asset`].
    #[inline]
    pub fn new(
        is_transparent: C::Bool,
        public_asset: Asset<C, COM>,
        commitment: Commitment<C, COM>,
        incoming_note: IncomingNote<C, COM>,
    ) -> Self {
        Self {
            is_transparent,
            public_asset,
            commitment,
            incoming_note,
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
    Commitment<C, COM>: Variable<M, COM, Type = Commitment<C::Type>>,
    IncomingNote<C, COM>: Variable<M, COM, Type = IncomingNote<C::Type>>,
{
    type Type = Utxo<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(
            compiler.allocate_unknown(),
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
            this.incoming_note.as_known(compiler),
        )
    }
}

/// UTXO Secret
pub struct UtxoSecret<C, COM = ()>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Encryption Key
    pub encryption_key: EncryptionKey<C, COM>,

    /// Encryption Randomness
    pub encryption_randomness: EncryptionRandomness<C, COM>,

    /// Commitment Randomness
    pub commitment_randomness: CommitmentRandomness<C, COM>,

    /// Secret Asset
    pub asset: Asset<C, COM>,

    /// Shielded Address
    pub shielded_address: ShieldedAddress<C, COM>,
}

impl<C, COM> UtxoSecret<C, COM>
where
    C: Configuration<COM>,
    COM: Has<bool, Type = C::Bool>,
{
    /// Builds a new [`UtxoSecret`] from `encryption_key`, `encryption_randomness`,
    /// `commitment_randomness`, `asset`, and `shielded_address`.
    #[inline]
    pub fn new(
        encryption_key: EncryptionKey<C, COM>,
        encryption_randomness: EncryptionRandomness<C, COM>,
        commitment_randomness: CommitmentRandomness<C, COM>,
        asset: Asset<C, COM>,
        shielded_address: ShieldedAddress<C, COM>,
    ) -> Self {
        Self {
            encryption_key,
            encryption_randomness,
            commitment_randomness,
            asset,
            shielded_address,
        }
    }

    /// Returns the usable `asset` from `self` and its public-form `utxo` asserting that it is
    /// well-formed.
    #[inline]
    pub fn into_well_formed_asset(
        self,
        commitment_scheme: &C::CommitmentScheme,
        encryption_scheme: &C::EncryptionScheme,
        utxo: &Utxo<C, COM>,
        compiler: &mut COM,
    ) -> Asset<C, COM>
    where
        COM: AssertEq,
    {
        let is_transparent = self.asset.is_empty(compiler);
        compiler.assert_eq(&utxo.is_transparent, &is_transparent);
        let asset = Asset::select(
            &utxo.is_transparent,
            &utxo.public_asset,
            &self.asset,
            compiler,
        );
        let commitment = commitment_scheme.commit(
            &self.commitment_randomness,
            &self.asset.id,
            &self.asset.value,
            &self.shielded_address.receiving_key,
            compiler,
        );
        compiler.assert_eq(&utxo.commitment, &commitment);
        let ciphertext = encryption_scheme
            .encrypt_into(
                &self.encryption_key,
                &self.encryption_randomness,
                IncomingNoteHeader::default(),
                &(
                    self.commitment_randomness,
                    self.asset.id,
                    self.asset.value,
                    self.shielded_address.key_diversifier,
                ),
                compiler,
            )
            .ciphertext;
        compiler.assert_eq(&utxo.incoming_note.ciphertext, &ciphertext);
        asset
    }
}

impl<C, COM> Variable<Secret, COM> for UtxoSecret<C, COM>
where
    C: Configuration<COM> + Constant<COM>,
    COM: Has<bool, Type = C::Bool>,
    C::Type: Configuration<Bool = bool>,
    EncryptionKey<C, COM>: Variable<Secret, COM, Type = EncryptionKey<C::Type>>,
    EncryptionRandomness<C, COM>: Variable<Secret, COM, Type = EncryptionRandomness<C::Type>>,
    CommitmentRandomness<C, COM>: Variable<Secret, COM, Type = CommitmentRandomness<C::Type>>,
    Asset<C, COM>: Variable<Secret, COM, Type = Asset<C::Type>>,
    ShieldedAddress<C, COM>: Variable<Secret, COM, Type = ShieldedAddress<C::Type>>,
{
    type Type = UtxoSecret<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.encryption_key.as_known(compiler),
            this.encryption_randomness.as_known(compiler),
            this.commitment_randomness.as_known(compiler),
            this.asset.as_known(compiler),
            this.shielded_address.as_known(compiler),
        )
    }
}
