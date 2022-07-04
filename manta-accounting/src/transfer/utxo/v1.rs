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
use manta_crypto::{
    constraint::{Allocate, Allocator, BitAnd, Constant, Public, Secret, Var, Variable, Zero},
    encryption::{Encrypt, EncryptedMessage, EncryptionKeyType, RandomnessType},
};

/// UTXO Version Number
pub const VERSION: u8 = 1;

/// UTXO Commitment Scheme
pub trait CommitmentScheme<COM = ()> {
    /// Asset Id
    type AssetId;

    /// Asset Value
    type AssetValue;

    /// Receiving Key
    type ReceivingKey;

    /// UTXO Commitment Randomness Type
    type Randomness;

    /// UTXO Commitment Type
    type Commitment;

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
pub trait Configuration<COM = ()>: VersionType {
    /// Boolean Type
    type Bool: BitAnd<Self::Bool, COM, Output = Self::Bool>;

    /// Asset Id Type
    type AssetId: Zero<COM, Verification = Self::Bool>;

    /// Asset Value Type
    type AssetValue: Zero<COM, Verification = Self::Bool>;

    /// Key Diversifier
    type KeyDiversifier;

    /// Receiving Key
    type ReceivingKey;

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
        Plaintext = (
            CommitmentRandomness<Self, COM>,
            Self::AssetId,
            Self::AssetValue,
            Self::KeyDiversifier,
        ),
        Header = (),
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
{
    /// Asset Id
    pub id: C::AssetId,

    /// Asset Value
    pub value: C::AssetValue,
}

impl<C, COM> Asset<C, COM>
where
    C: Configuration<COM>,
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

impl<C, COM, M> Variable<M, COM> for Asset<C, COM>
where
    C: Configuration<COM> + Constant<COM>,
    C::AssetId: Variable<M, COM>,
    C::AssetValue: Variable<M, COM>,
    C::Type:
        Configuration<AssetId = Var<C::AssetId, M, COM>, AssetValue = Var<C::AssetValue, M, COM>>,
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
{
    /// Key Diversifier
    pub key_diversifier: C::KeyDiversifier,

    /// Receiving Key
    pub receiving_key: C::ReceivingKey,
}

impl<C, COM> ShieldedAddress<C, COM>
where
    C: Configuration<COM>,
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
    C::KeyDiversifier: Variable<M, COM>,
    C::ReceivingKey: Variable<M, COM>,
    C::Type: Configuration<
        KeyDiversifier = Var<C::KeyDiversifier, M, COM>,
        ReceivingKey = Var<C::ReceivingKey, M, COM>,
    >,
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

/// Incoming Note Type
pub type IncomingNote<C, COM = ()> = EncryptedMessage<<C as Configuration<COM>>::EncryptionScheme>;

/// UTXO
pub struct Utxo<C, COM = ()>
where
    C: Configuration<COM>,
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
{
    /// Builds a new [`Utxo`] from `is_transparent`, `public_asset`, `commitment`, and
    /// `incoming_note`. To build a [`Utxo`] from its secret pre-image use [`UtxoSecret::into_utxo`].
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

impl<C, COM> Variable<Public, COM> for Utxo<C, COM>
where
    C: Configuration<COM> + Constant<COM>,
    Commitment<C, COM>: Variable<Public, COM>,
    IncomingNote<C, COM>: Variable<Public, COM>,
    C::Type: Configuration,
{
    type Type = Utxo<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        /* TODO:
        Self::new(
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
        )
        */
        todo!()
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        /* TODO:
        Self::new(
            this.is_transparent.as_known(compiler),
            this.public_asset.as_known(compiler),
            this.commitment.as_known(compiler),
            this.incoming_note.as_known(compiler),
        )
        */
        todo!()
    }
}

/// UTXO Secret
pub struct UtxoSecret<C, COM = ()>
where
    C: Configuration<COM>,
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
{
    /// Builds the [`Utxo`] that `self` is the secret pre-image for, assigning `public_asset` to the
    /// [`Utxo`].
    #[inline]
    pub fn into_utxo(
        self,
        commitment_scheme: &C::CommitmentScheme,
        encryption_scheme: &C::EncryptionScheme,
        public_asset: Asset<C, COM>,
        compiler: &mut COM,
    ) -> Utxo<C, COM> {
        Utxo::new(
            self.asset.is_empty(compiler),
            public_asset,
            commitment_scheme.commit(
                &self.commitment_randomness,
                &self.asset.id,
                &self.asset.value,
                &self.shielded_address.receiving_key,
                compiler,
            ),
            encryption_scheme.encrypt_into(
                &self.encryption_key,
                &self.encryption_randomness,
                (),
                &(
                    self.commitment_randomness,
                    self.asset.id,
                    self.asset.value,
                    self.shielded_address.key_diversifier,
                ),
                compiler,
            ),
        )
    }
}

impl<C, COM> Variable<Secret, COM> for UtxoSecret<C, COM>
where
    C: Configuration<COM> + Constant<COM>,
    C::Type: Configuration,
{
    type Type = UtxoSecret<C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        /* TODO:
        Self {
            encryption_key: compiler.allocate_unknown(),
            encryption_randomness: compiler.allocate_unknown(),
            commitment_randomness: compiler.allocate_unknown(),
            asset: compiler.allocate_unknown(),
            shielded_address: compiler.allocate_unknown(),
        }
        */
        todo!()
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        todo!()
    }
}
