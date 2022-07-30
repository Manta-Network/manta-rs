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

//! UTXO Protocols
//!
//! The current protocol is referred to by [`protocol`] and older protocols are marked by their
//! version number. The [`VERSION`] number can be queried for the current protocol and can be used
//! to select the protocol version. The transfer protocol is built up from a given [`Mint`] and
//! [`Spend`] implementation.

use crate::transfer::utxo::auth::AuthorizationKeyType;
use core::{fmt::Debug, hash::Hash, marker::PhantomData, ops::Deref};
use manta_crypto::{
    accumulator::{self, ItemHashFunction, MembershipProof},
    eclair::alloc::{Allocate, Constant},
    rand::{CryptoRng, RngCore},
};

pub mod auth;
pub mod v1;

#[doc(inline)]
pub use v1 as protocol;

/// Current UTXO Protocol Version
pub const VERSION: u8 = protocol::VERSION;

/// Asset
pub trait AssetType {
    /// Asset Type
    type Asset;
}

/// Asset Type
pub type Asset<T> = <T as AssetType>::Asset;

/// Unspent Transaction Output
pub trait UtxoType {
    /// Unspent Transaction Output Type
    type Utxo;
}

/// Unspent Transaction Output Type
pub type Utxo<T> = <T as UtxoType>::Utxo;

/// Note
pub trait NoteType {
    /// Note Type
    type Note;
}

/// Note Type
pub type Note<T> = <T as NoteType>::Note;

/// Identifier
pub trait IdentifierType {
    /// Identifier Type
    type Identifier;
}

/// Identifier Type
pub type Identifier<T> = <T as IdentifierType>::Identifier;

/// Address
pub trait AddressType {
    /// Address Type
    type Address;
}

/// Address Type
pub type Address<T> = <T as AddressType>::Address;

/// Associated Data
pub trait AssociatedDataType {
    /// Associated Data Type
    type AssociatedData;
}

/// Associated Data Type
pub type AssociatedData<T> = <T as AssociatedDataType>::AssociatedData;

/// Full Asset
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T::Asset: Clone, T::AssociatedData: Clone"),
    Copy(bound = "T::Asset: Copy, T::AssociatedData: Copy"),
    Debug(bound = "T::Asset: Debug, T::AssociatedData: Debug"),
    Default(bound = "T::Asset: Default, T::AssociatedData: Default"),
    Eq(bound = "T::Asset: Eq, T::AssociatedData: Eq"),
    Hash(bound = "T::Asset: Hash, T::AssociatedData: Hash"),
    PartialEq(bound = "T::Asset: PartialEq, T::AssociatedData: PartialEq")
)]
pub struct FullAsset<T>
where
    T: AssetType + AssociatedDataType,
{
    /// Asset
    pub asset: T::Asset,

    /// Associated Data
    pub associated_data: T::AssociatedData,
}

impl<T> FullAsset<T>
where
    T: AssetType + AssociatedDataType,
{
    /// Builds a new [`FullAsset`] from `asset` and `associated_data`.
    #[inline]
    pub fn new(asset: T::Asset, associated_data: T::AssociatedData) -> Self {
        Self {
            asset,
            associated_data,
        }
    }

    /// Lifts an `asset` into a [`FullAsset`] by attaching the default associated data.
    #[inline]
    pub fn from_asset(asset: T::Asset) -> Self
    where
        T::AssociatedData: Default,
    {
        Self::new(asset, Default::default())
    }
}

/// Default Address
pub trait DefaultAddress<T>: AddressType {
    /// Constructs the default receiving address given the `base` secret.
    fn default_address(&self, base: &T) -> Self::Address;
}

/// Note Opening
pub trait NoteOpen: AssetType + IdentifierType + NoteType + UtxoType {
    /// Decryption Key Type
    type DecryptionKey;

    /// Tries to open `note` with `decryption_key`, returning a note [`Identifier`] and its stored
    /// [`Asset`].
    ///
    /// [`Identifier`]: IdentifierType::Identifier
    /// [`Asset`]: AssetType::Asset
    fn open(
        &self,
        decryption_key: &Self::DecryptionKey,
        utxo: &Self::Utxo,
        note: Self::Note,
    ) -> Option<(Self::Identifier, Self::Asset)>;
}

/// Query Identifier Value
pub trait QueryIdentifier: IdentifierType + UtxoType {
    /// Queries the underlying identifier from `self` and `utxo`.
    fn query_identifier(&self, utxo: &Self::Utxo) -> Self::Identifier;
}

/// UTXO Minting
pub trait Mint<COM = ()>: AssetType + NoteType + UtxoType {
    /// Mint Secret Type
    type Secret;

    /// Returns the asset inside of `utxo` asserting that `secret`, `utxo`, and `note` are
    /// well-formed.
    fn well_formed_asset(
        &self,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        note: &Self::Note,
        compiler: &mut COM,
    ) -> Self::Asset;
}

/// Derive Minting Data
pub trait DeriveMint: AddressType + AssociatedDataType + Mint {
    /// Derives the data required to mint to a target `address`, the `asset` to mint and
    /// `associated_data`.
    fn derive<R>(
        &self,
        address: Self::Address,
        asset: Self::Asset,
        associated_data: Self::AssociatedData,
        rng: &mut R,
    ) -> (Self::Secret, Self::Utxo, Self::Note)
    where
        R: CryptoRng + RngCore + ?Sized;
}

/// Query Asset Value
pub trait QueryAsset: AssetType + UtxoType {
    /// Queries the underlying asset from `self` and `utxo`.
    fn query_asset(&self, utxo: &Self::Utxo) -> Self::Asset;
}

/// UTXO Spending
pub trait Spend<COM = ()>:
    ItemHashFunction<Self::Utxo, COM> + AssetType + UtxoType + AuthorizationKeyType
{
    /// UTXO Accumulator Model Type
    type UtxoAccumulatorModel: accumulator::Model<COM, Item = Self::Item>;

    /// Spend Secret Type
    type Secret;

    /// Nullifier Type
    type Nullifier;

    /// Returns the asset and its nullifier inside of `utxo` asserting that `secret` and `utxo` are
    /// well-formed and that `utxo_membership_proof` is a valid proof.
    fn well_formed_asset(
        &self,
        utxo_accumulator_model: &Self::UtxoAccumulatorModel,
        authorization_key: &mut Self::AuthorizationKey,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        utxo_membership_proof: &UtxoMembershipProof<Self, COM>,
        compiler: &mut COM,
    ) -> (Self::Asset, Self::Nullifier);

    /// Asserts that the two nullifiers, `lhs` and `rhs`, are equal.
    fn assert_equal_nullifiers(
        &self,
        lhs: &Self::Nullifier,
        rhs: &Self::Nullifier,
        compiler: &mut COM,
    );
}

/// Derive Spending Data
pub trait DeriveSpend: Spend + IdentifierType {
    /// Derives the data required to spend with an `authorization_key`, the `asset` to spend and its
    /// `identifier`.
    fn derive<R>(
        &self,
        authorization_key: &mut Self::AuthorizationKey,
        identifier: Self::Identifier,
        asset: Self::Asset,
        rng: &mut R,
    ) -> (Self::Secret, Self::Utxo, Self::Nullifier)
    where
        R: CryptoRng + RngCore + ?Sized;
}

/// UTXO Accumulator Model Type
pub type UtxoAccumulatorModel<S, COM = ()> = <S as Spend<COM>>::UtxoAccumulatorModel;

/// UTXO Accumulator Item Type
pub type UtxoAccumulatorItem<S, COM = ()> =
    <UtxoAccumulatorModel<S, COM> as accumulator::Types>::Item;

/// UTXO Accumulator Witness Type
pub type UtxoAccumulatorWitness<S, COM = ()> =
    <UtxoAccumulatorModel<S, COM> as accumulator::Types>::Witness;

/// UTXO Accumulator Output Type
pub type UtxoAccumulatorOutput<S, COM = ()> =
    <UtxoAccumulatorModel<S, COM> as accumulator::Types>::Output;

/// UTXO Membership Proof Type
pub type UtxoMembershipProof<S, COM = ()> = MembershipProof<UtxoAccumulatorModel<S, COM>, COM>;

/// Nullifier Type
pub type Nullifier<S, COM = ()> = <S as Spend<COM>>::Nullifier;

/// Full Parameters Owned
///
/// This `struct` uses a lifetime marker to tie it down to a particular instance of
/// [`FullParametersRef`] during allocation.
pub struct FullParameters<'p, P, COM = ()>
where
    P: Mint<COM> + Spend<COM>,
{
    /// Base Parameters
    pub base: P,

    /// UTXO Accumulator Model
    pub utxo_accumulator_model: P::UtxoAccumulatorModel,

    /// Type Parameter Marker
    __: PhantomData<&'p ()>,
}

impl<'p, P, COM> FullParameters<'p, P, COM>
where
    P: Mint<COM> + Spend<COM>,
{
    /// Builds a new [`FullParameters`] from `base` and `utxo_accumulator_model`.
    #[inline]
    pub fn new(base: P, utxo_accumulator_model: P::UtxoAccumulatorModel) -> Self {
        Self {
            base,
            utxo_accumulator_model,
            __: PhantomData,
        }
    }
}

impl<'p, P, COM> Constant<COM> for FullParameters<'p, P, COM>
where
    P: Mint<COM> + Spend<COM> + Constant<COM>,
    P::UtxoAccumulatorModel: Constant<COM, Type = UtxoAccumulatorModel<P::Type>>,
    P::Type: 'p + Mint + Spend,
    UtxoAccumulatorModel<P::Type>: 'p,
{
    type Type = FullParametersRef<'p, P::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.base.as_constant(compiler),
            this.utxo_accumulator_model.as_constant(compiler),
        )
    }
}

/// Full Parameters Reference
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = "P: Debug, P::UtxoAccumulatorModel: Debug"),
    Eq(bound = "P: Eq, P::UtxoAccumulatorModel: Eq"),
    Hash(bound = "P: Hash, P::UtxoAccumulatorModel: Hash"),
    PartialEq(bound = "P: PartialEq, P::UtxoAccumulatorModel: PartialEq")
)]
pub struct FullParametersRef<'p, P, COM = ()>
where
    P: Mint<COM> + Spend<COM>,
{
    /// Base Parameters
    pub base: &'p P,

    /// UTXO Accumulator Model
    pub utxo_accumulator_model: &'p P::UtxoAccumulatorModel,
}

impl<'p, P, COM> FullParametersRef<'p, P, COM>
where
    P: Mint<COM> + Spend<COM>,
{
    /// Builds a new [`FullParametersRef`] from `base` and `utxo_accumulator_model`.
    #[inline]
    pub fn new(base: &'p P, utxo_accumulator_model: &'p P::UtxoAccumulatorModel) -> Self {
        Self {
            base,
            utxo_accumulator_model,
        }
    }
}

impl<'p, P, COM> AsRef<P> for FullParametersRef<'p, P, COM>
where
    P: Mint<COM> + Spend<COM>,
{
    #[inline]
    fn as_ref(&self) -> &P {
        self.base
    }
}

impl<'p, P, COM> Deref for FullParametersRef<'p, P, COM>
where
    P: Mint<COM> + Spend<COM>,
{
    type Target = P;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.base
    }
}
