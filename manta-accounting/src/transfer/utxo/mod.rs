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

use crate::transfer::utxo::auth::AuthorizationContextType;
use core::{fmt::Debug, hash::Hash, marker::PhantomData, ops::Deref};
use manta_crypto::{
    accumulator::{self, ItemHashFunction, MembershipProof},
    algebra::{HasGenerator, ScalarMul},
    eclair::alloc::{Allocate, Constant},
    rand::RngCore,
};
use manta_util::cmp::IndependenceContext;

pub mod auth;
pub mod v1;
pub mod v2;

#[doc(inline)]
pub use v2 as protocol;

use self::v2::ViewingKeyDerivationFunction;

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

/// UTXO Independence
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtxoIndependence;

impl IndependenceContext for UtxoIndependence {
    const DEFAULT: bool = false;
}

/// Note
pub trait NoteType {
    /// Note Type
    type Note;
}

/// Note Type
pub type Note<T> = <T as NoteType>::Note;

/// Nullifier
pub trait NullifierType {
    /// Nullifier Type
    type Nullifier;
}

/// Nullifier Type
pub type Nullifier<T> = <T as NullifierType>::Nullifier;

/// Nullifier Independence
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NullifierIndependence;

impl IndependenceContext for NullifierIndependence {
    const DEFAULT: bool = false;
}

/// Identifier
pub trait IdentifierType {
    /// Identifier Type
    type Identifier;
}

/// Identifier Type
pub type Identifier<T> = <T as IdentifierType>::Identifier;

/// Identified Asset
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T::Identifier: Clone, T::Asset: Clone"),
    Copy(bound = "T::Identifier: Copy, T::Asset: Copy"),
    Debug(bound = "T::Identifier: Debug, T::Asset: Debug"),
    Default(bound = "T::Identifier: Default, T::Asset: Default"),
    Eq(bound = "T::Identifier: Eq, T::Asset: Eq"),
    Hash(bound = "T::Identifier: Hash, T::Asset: Hash"),
    PartialEq(bound = "T::Identifier: PartialEq, T::Asset: PartialEq")
)]
pub struct IdentifiedAsset<T>
where
    T: AssetType + IdentifierType + ?Sized,
{
    /// Identifier
    pub identifier: T::Identifier,

    /// Asset
    pub asset: T::Asset,
}

impl<T> IdentifiedAsset<T>
where
    T: AssetType + IdentifierType + ?Sized,
{
    /// Builds a new [`IdentifiedAsset`] from `identifier` and `asset`.
    #[inline]
    pub fn new(identifier: T::Identifier, asset: T::Asset) -> Self {
        Self { identifier, asset }
    }
}

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
    T: AssetType + AssociatedDataType + ?Sized,
{
    /// Asset
    pub asset: T::Asset,

    /// Associated Data
    pub associated_data: T::AssociatedData,
}

impl<T> FullAsset<T>
where
    T: AssetType + AssociatedDataType + ?Sized,
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

/// Derive Decryption Key
pub trait DeriveDecryptionKey: AuthorizationContextType {
    /// Decryption Key Type
    type DecryptionKey;

    /// Derives the decryption key for notes from `authorization_context`.
    fn derive_decryption_key(
        &self,
        authorization_context: &mut Self::AuthorizationContext,
    ) -> Self::DecryptionKey;
}

/// Note Opening
pub trait NoteOpen: AssetType + DeriveDecryptionKey + IdentifierType + NoteType + UtxoType {
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

    /// Tries to open `note` with `decryption_key`, returning an [`IdentifiedAsset`].
    #[inline]
    fn open_into(
        &self,
        decryption_key: &Self::DecryptionKey,
        utxo: &Self::Utxo,
        note: Self::Note,
    ) -> Option<IdentifiedAsset<Self>> {
        self.open(decryption_key, utxo, note)
            .map(|(identifier, asset)| IdentifiedAsset::new(identifier, asset))
    }
}

/// Query Identifier Value
pub trait QueryIdentifier: IdentifierType + UtxoType {
    /// Queries the underlying identifier from `self` and `utxo`.
    fn query_identifier(&self, utxo: &Self::Utxo) -> Self::Identifier;
}

/// UTXO Minting
pub trait Mint<COM = ()>: AssetType + NoteType + UtxoType {
    /// Secret Type
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
    fn derive_mint<R>(
        &self,
        address: Self::Address,
        asset: Self::Asset,
        associated_data: Self::AssociatedData,
        rng: &mut R,
    ) -> (Self::Secret, Self::Utxo, Self::Note)
    where
        R: RngCore + ?Sized;
}

/// Query Asset Value
pub trait QueryAsset: AssetType + UtxoType {
    /// Queries the underlying asset from `self` and `utxo`.
    fn query_asset(&self, utxo: &Self::Utxo) -> Self::Asset;
}

/// UTXO Spending
pub trait Spend<COM = ()>: AuthorizationContextType + AssetType + UtxoType + NullifierType {
    /// UTXO Accumulator Witness Type
    type UtxoAccumulatorWitness;

    /// UTXO Accumulator Output Type
    type UtxoAccumulatorOutput;

    /// UTXO Accumulator Model Type
    type UtxoAccumulatorModel: accumulator::Model<
        COM,
        Witness = Self::UtxoAccumulatorWitness,
        Output = Self::UtxoAccumulatorOutput,
    >;

    /// UTXO Accumulator Item Hash Type
    type UtxoAccumulatorItemHash: ItemHashFunction<
        Self::Utxo,
        COM,
        Item = UtxoAccumulatorItem<Self, COM>,
    >;

    /// Spend Secret Type
    type Secret;

    ///
    fn utxo_accumulator_item_hash(&self) -> &Self::UtxoAccumulatorItemHash;

    /// Returns the asset and its nullifier inside of `utxo` asserting that `secret` and `utxo` are
    /// well-formed and that `utxo_membership_proof` is a valid proof.
    fn well_formed_asset(
        &self,
        utxo_accumulator_model: &Self::UtxoAccumulatorModel,
        authorization_context: &mut Self::AuthorizationContext,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        utxo_membership_proof: &UtxoMembershipProof<Self, COM>,
        compiler: &mut COM,
    ) -> (Self::Asset, Self::Nullifier);

    /// Asserts that `lhs` and `rhs` are exactly equal.
    fn assert_equal_nullifiers(
        &self,
        lhs: &Self::Nullifier,
        rhs: &Self::Nullifier,
        compiler: &mut COM,
    );
}

/// Derive Spending Data
pub trait DeriveSpend: Spend + IdentifierType {
    /// Derives the data required to spend with an `authorization_context`, the `asset` to spend and
    /// its `identifier`.
    fn derive_spend<R>(
        &self,
        authorization_context: &mut Self::AuthorizationContext,
        identifier: Self::Identifier,
        asset: Self::Asset,
        rng: &mut R,
    ) -> (Self::Secret, Self::Utxo, Self::Nullifier)
    where
        R: RngCore + ?Sized;
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
pub type UtxoMembershipProof<S, COM = ()> = MembershipProof<UtxoAccumulatorModel<S, COM>>;

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

/// Computes the address corresponding to `spending_key`.
#[inline]
pub fn address_from_spending_key<C>(
    spending_key: &C::Scalar,
    parameters: &protocol::Parameters<C>,
) -> protocol::Address<C>
where
    C: protocol::Configuration,
{
    let generator = parameters.base.group_generator.generator();
    protocol::Address::new(
        generator.scalar_mul(
            &parameters
                .base
                .viewing_key_derivation_function
                .viewing_key(&generator.scalar_mul(spending_key, &mut ()), &mut ()),
            &mut (),
        ),
    )
}
