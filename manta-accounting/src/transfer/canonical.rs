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

//! Canonical Transfer Types

// TODO: Add typing for `ProvingContext` and `VerifyingContext` against the canonical shapes.

use crate::{
    asset::{self, AssetMap},
    transfer::{
        has_public_participants, internal_pair, requires_authorization, utxo::UtxoReconstruct,
        Address, Asset, AssociatedData, Authorization, AuthorizationContext, Configuration,
        FullParametersRef, Identifier, Parameters, PreSender, ProofSystemError,
        ProofSystemPublicParameters, ProvingContext, Receiver, Sender, Transfer, TransferLedger,
        TransferPost, TransferPostingKeyRef, Utxo, VerifyingContext,
    },
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};
use manta_crypto::{
    arkworks::serialize::{
        CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
    },
    rand::{CryptoRng, RngCore},
};
use manta_util::{create_seal, seal};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

create_seal! {}

/// Transfer Shapes
///
/// This trait identifies a transfer shape, i.e. the number and type of participants on the input
/// and output sides of the transaction. This trait is sealed and can only be used with the
/// existing canonical implementations.
pub trait Shape: sealed::Sealed {
    /// Number of Sources
    const SOURCES: usize;

    /// Number of Senders
    const SENDERS: usize;

    /// Number of Receivers
    const RECEIVERS: usize;

    /// Number of Sinks
    const SINKS: usize;
}

/// Implements [`Shape`] for a given shape type.
macro_rules! impl_shape {
    ($shape:ty, $sources:expr, $senders:expr, $receivers:expr, $sinks:expr) => {
        seal!($shape);
        impl Shape for $shape {
            const SOURCES: usize = $sources;
            const SENDERS: usize = $senders;
            const RECEIVERS: usize = $receivers;
            const SINKS: usize = $sinks;
        }
    };
}

/// Builds a new alias using the given shape type.
macro_rules! alias_type {
    ($type:tt, $t:ident, $shape:tt) => {
        $type<$t, { $shape::SOURCES }, { $shape::SENDERS }, { $shape::RECEIVERS }, { $shape::SINKS }>
    };
}

/// Builds a new [`Transfer`] alias using the given shape type.
macro_rules! transfer_alias {
    ($t:ident, $shape:tt) => {
        alias_type!(Transfer, $t, $shape)
    };
}

/// [`ToPrivate`] Transfer Shape
///
/// ```text
/// <1, 0, 1, 0>
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct ToPrivateShape;

impl_shape!(ToPrivateShape, 1, 0, 1, 0);

/// [`ToPrivate`] Transfer Type
pub type ToPrivate<C> = transfer_alias!(C, ToPrivateShape);

impl<C> ToPrivate<C>
where
    C: Configuration,
{
    /// Builds a [`ToPrivate`] from `asset` and `receiver`.
    #[inline]
    pub fn build(asset: Asset<C>, receiver: Receiver<C>) -> Self {
        Self::new_unchecked(None, Some(asset.id), [asset.value], [], [receiver], [])
    }

    /// Builds a new [`ToPrivate`] from `address` and `asset`.
    #[inline]
    pub fn from_address<R>(
        parameters: &Parameters<C>,
        address: Address<C>,
        asset: Asset<C>,
        associated_data: AssociatedData<C>,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::build(
            asset.clone(),
            Receiver::<C>::sample(parameters, address, asset, associated_data, rng),
        )
    }

    /// Builds a new [`ToPrivate`] and [`PreSender`] pair from `authorization_context` and `asset`.
    #[inline]
    pub fn internal_pair<R>(
        parameters: &Parameters<C>,
        authorization_context: &mut AuthorizationContext<C>,
        address: Address<C>,
        asset: Asset<C>,
        associated_data: AssociatedData<C>,
        rng: &mut R,
    ) -> (Self, PreSender<C>)
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let (receiver, pre_sender) = internal_pair::<C, _>(
            parameters,
            authorization_context,
            address,
            asset.clone(),
            associated_data,
            rng,
        );
        (Self::build(asset, receiver), pre_sender)
    }
}

/// [`PrivateTransfer`] Transfer Shape
///
/// ```text
/// <0, 2, 2, 0>
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct PrivateTransferShape;

impl_shape!(PrivateTransferShape, 0, 2, 2, 0);

/// [`PrivateTransfer`] Transfer Type
pub type PrivateTransfer<C> = transfer_alias!(C, PrivateTransferShape);

impl<C> PrivateTransfer<C>
where
    C: Configuration,
{
    /// Builds a [`PrivateTransfer`] from `senders` and `receivers`.
    #[inline]
    pub fn build(
        authorization: Authorization<C>,
        senders: [Sender<C>; PrivateTransferShape::SENDERS],
        receivers: [Receiver<C>; PrivateTransferShape::RECEIVERS],
    ) -> Self {
        Self::new_unchecked(Some(authorization), None, [], senders, receivers, [])
    }
}

/// [`ToPublic`] Transfer Shape
///
/// ```text
/// <0, 2, 1, 1>
/// ```
///
/// The [`ToPublicShape`] is defined in terms of the [`PrivateTransferShape`]. It is defined to
/// have the same number of senders and one secret receiver turned into a public sink.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct ToPublicShape;

impl_shape!(
    ToPublicShape,
    PrivateTransferShape::SOURCES,
    PrivateTransferShape::SENDERS,
    PrivateTransferShape::RECEIVERS - 1,
    PrivateTransferShape::SINKS + 1
);

/// [`ToPublic`] Transfer
pub type ToPublic<C> = transfer_alias!(C, ToPublicShape);

impl<C> ToPublic<C>
where
    C: Configuration,
{
    /// Builds a [`ToPublic`] from `senders`, `receivers`, and `asset`.
    #[inline]
    pub fn build(
        authorization: Authorization<C>,
        senders: [Sender<C>; ToPublicShape::SENDERS],
        receivers: [Receiver<C>; ToPublicShape::RECEIVERS],
        asset: Asset<C>,
    ) -> Self {
        Self::new_unchecked(
            Some(authorization),
            Some(asset.id),
            [],
            senders,
            receivers,
            [asset.value],
        )
    }
}

/// Transfer Shape
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransferShape {
    /// [`ToPrivate`] Transfer
    ToPrivate,

    /// [`PrivateTransfer`] Transfer
    PrivateTransfer,

    /// [`ToPublic`] Transfer
    ToPublic,
}

impl TransferShape {
    /// Selects the [`TransferShape`] for the given shape if it matches a canonical shape.
    #[inline]
    pub fn select(
        has_authorization: bool,
        has_visible_asset_id: bool,
        sources: usize,
        senders: usize,
        receivers: usize,
        sinks: usize,
    ) -> Option<Self> {
        const TO_PRIVATE_HAS_AUTHORIZATION: bool = requires_authorization(ToPrivateShape::SENDERS);
        const TO_PRIVATE_HAS_VISIBLE_ASSET_ID: bool =
            has_public_participants(ToPrivateShape::SOURCES, ToPrivateShape::SINKS);
        const PRIVATE_TRANSFER_HAS_AUTHORIZATION: bool =
            requires_authorization(PrivateTransferShape::SENDERS);
        const PRIVATE_TRANSFER_HAS_VISIBLE_ASSET_ID: bool =
            has_public_participants(PrivateTransferShape::SOURCES, PrivateTransferShape::SINKS);
        const TO_PUBLIC_HAS_AUTHORIZATION: bool = requires_authorization(ToPublicShape::SENDERS);
        const TO_PUBLIC_HAS_VISIBLE_ASSET_ID: bool =
            has_public_participants(ToPublicShape::SOURCES, ToPublicShape::SINKS);
        match (
            has_authorization,
            has_visible_asset_id,
            sources,
            senders,
            receivers,
            sinks,
        ) {
            (
                TO_PRIVATE_HAS_AUTHORIZATION,
                TO_PRIVATE_HAS_VISIBLE_ASSET_ID,
                ToPrivateShape::SOURCES,
                ToPrivateShape::SENDERS,
                ToPrivateShape::RECEIVERS,
                ToPrivateShape::SINKS,
            ) => Some(Self::ToPrivate),
            (
                PRIVATE_TRANSFER_HAS_AUTHORIZATION,
                PRIVATE_TRANSFER_HAS_VISIBLE_ASSET_ID,
                PrivateTransferShape::SOURCES,
                PrivateTransferShape::SENDERS,
                PrivateTransferShape::RECEIVERS,
                PrivateTransferShape::SINKS,
            ) => Some(Self::PrivateTransfer),
            (
                TO_PUBLIC_HAS_AUTHORIZATION,
                TO_PUBLIC_HAS_VISIBLE_ASSET_ID,
                ToPublicShape::SOURCES,
                ToPublicShape::SENDERS,
                ToPublicShape::RECEIVERS,
                ToPublicShape::SINKS,
            ) => Some(Self::ToPublic),
            _ => None,
        }
    }

    /// Selects the [`TransferShape`] from `post`.
    #[inline]
    pub fn from_post<C>(post: &TransferPost<C>) -> Option<Self>
    where
        C: Configuration,
    {
        Self::select(
            post.authorization_signature.is_some(),
            post.body.asset_id.is_some(),
            post.body.sources.len(),
            post.body.sender_posts.len(),
            post.body.receiver_posts.len(),
            post.body.sinks.len(),
        )
    }

    /// Selects the [`TransferShape`] from `posting_key`.
    #[inline]
    pub fn from_posting_key_ref<C, L>(posting_key: &TransferPostingKeyRef<C, L>) -> Option<Self>
    where
        C: Configuration,
        L: TransferLedger<C>,
    {
        Self::select(
            posting_key.authorization_key.is_some(),
            posting_key.asset_id.is_some(),
            posting_key.sources.len(),
            posting_key.senders.len(),
            posting_key.receivers.len(),
            posting_key.sinks.len(),
        )
    }
}

/// Canonical Transaction Type
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"Asset<C>: Deserialize<'de>, 
                Address<C>: Deserialize<'de>, 
                C::AccountId: Deserialize<'de>",
            serialize = r"Asset<C>: Serialize, 
                Address<C>: Serialize, 
                C::AccountId: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Asset<C>: Clone, Address<C>: Clone, C::AccountId: Clone"),
    Copy(bound = "Asset<C>: Copy, Address<C>: Copy, C::AccountId: Copy"),
    Debug(bound = "Asset<C>: Debug, Address<C>: Debug, C::AccountId: Debug"),
    Eq(bound = "Asset<C>: Eq, Address<C>: Eq, C::AccountId: Eq"),
    Hash(bound = "Asset<C>: Hash, Address<C>: Hash, C::AccountId: Hash"),
    PartialEq(bound = "Asset<C>: PartialEq, Address<C>: PartialEq, C::AccountId: PartialEq")
)]
pub enum Transaction<C>
where
    C: Configuration,
{
    /// Convert Public Asset into Private Asset
    ToPrivate(Asset<C>),

    /// Private Transfer Asset to Address
    PrivateTransfer(Asset<C>, Address<C>),

    /// Convert Private Asset into Public Asset
    ToPublic(Asset<C>, C::AccountId),
}

impl<C> Transaction<C>
where
    C: Configuration,
{
    /// Checks that `self` can be executed for a given `balance` state, returning the
    /// transaction kind if successful, and returning the asset back if the balance was
    /// insufficient.
    #[inline]
    pub fn check<F>(&self, balance: F) -> Result<TransactionKind<C>, &Asset<C>>
    where
        F: FnOnce(&Asset<C>) -> bool,
    {
        match self {
            Self::ToPrivate(asset) => Ok(TransactionKind::Deposit(asset.clone())),
            Self::PrivateTransfer(asset, _) | Self::ToPublic(asset, _) => {
                if balance(asset) {
                    Ok(TransactionKind::Withdraw(asset.clone()))
                } else {
                    Err(asset)
                }
            }
        }
    }

    /// Returns the associated [`TransferShape`] for this [`Transaction`].
    #[inline]
    pub fn shape(&self) -> TransferShape {
        match self {
            Self::ToPrivate(_) => TransferShape::ToPrivate,
            Self::PrivateTransfer(_, _) => TransferShape::PrivateTransfer,
            Self::ToPublic(_, _) => TransferShape::ToPublic,
        }
    }

    /// Returns the amount of value being transfered in `self`.
    #[inline]
    pub fn value(&self) -> &C::AssetValue {
        match self {
            Self::ToPrivate(asset) => &asset.value,
            Self::PrivateTransfer(asset, _) => &asset.value,
            Self::ToPublic(asset, _) => &asset.value,
        }
    }

    /// Returns `true` if `self` is a [`Transaction`] which transfers zero value.
    #[inline]
    pub fn is_zero(&self) -> bool
    where
        C::AssetValue: Default + PartialEq,
    {
        self.value() == &Default::default()
    }
}

/// Transaction Kind
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Asset<C>: Deserialize<'de>",
            serialize = "Asset<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Asset<C>: Clone"),
    Copy(bound = "Asset<C>: Copy"),
    Debug(bound = "Asset<C>: Debug"),
    Hash(bound = "Asset<C>: Hash"),
    Eq(bound = "Asset<C>: Eq"),
    PartialEq(bound = "Asset<C>: Eq")
)]
pub enum TransactionKind<C>
where
    C: Configuration,
{
    /// Deposit Transaction
    ///
    /// A transaction of this kind will result in a deposit of `asset`.
    Deposit(Asset<C>),

    /// Withdraw Transaction
    ///
    /// A transaction of this kind will result in a withdraw of `asset`.
    Withdraw(Asset<C>),
}

/// Transfer Asset Selection
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "C::AssetValue: Deserialize<'de>, PreSender<C>: Deserialize<'de>",
            serialize = "C::AssetValue: Serialize, PreSender<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "C::AssetValue: Clone, PreSender<C>: Clone"),
    Debug(bound = "C::AssetValue: Debug, PreSender<C>: Debug"),
    Default(bound = "C::AssetValue: Default, PreSender<C>: Default"),
    Hash(bound = "C::AssetValue: Hash, PreSender<C>: Hash"),
    Eq(bound = "C::AssetValue: Eq, PreSender<C>: Eq"),
    PartialEq(bound = "C::AssetValue: PartialEq, PreSender<C>: PartialEq")
)]
pub struct Selection<C>
where
    C: Configuration,
{
    /// Change Value
    pub change: C::AssetValue,

    /// Pre-Senders
    pub pre_senders: Vec<PreSender<C>>,
}

impl<C> Selection<C>
where
    C: Configuration,
{
    /// Builds a new [`Selection`] from `change` and `pre_senders`.
    #[inline]
    fn build(change: C::AssetValue, pre_senders: Vec<PreSender<C>>) -> Self {
        Self {
            change,
            pre_senders,
        }
    }

    /// Builds a new [`Selection`] by mapping over an asset selection with `builder`.
    #[inline]
    pub fn new<M, E, F>(
        selection: asset::Selection<C::AssetId, C::AssetValue, M>,
        mut builder: F,
    ) -> Result<Self, E>
    where
        M: AssetMap<C::AssetId, C::AssetValue>,
        F: FnMut(M::Key, C::AssetValue) -> Result<PreSender<C>, E>,
    {
        Ok(Self::build(
            selection.change,
            selection
                .values
                .into_iter()
                .map(move |(k, v)| builder(k, v))
                .collect::<Result<_, _>>()?,
        ))
    }
}

/// Canonical Multi-Proving Contexts
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "ProvingContext<C>: Deserialize<'de>",
            serialize = "ProvingContext<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "ProvingContext<C>: Clone"),
    Copy(bound = "ProvingContext<C>: Copy"),
    Debug(bound = "ProvingContext<C>: Debug"),
    Default(bound = "ProvingContext<C>: Default"),
    Eq(bound = "ProvingContext<C>: Eq"),
    Hash(bound = "ProvingContext<C>: Hash"),
    PartialEq(bound = "ProvingContext<C>: PartialEq")
)]
pub struct MultiProvingContext<C>
where
    C: Configuration + ?Sized,
{
    /// [`ToPrivate`] Proving Context
    pub to_private: ProvingContext<C>,

    /// [`PrivateTransfer`] Proving Context
    pub private_transfer: ProvingContext<C>,

    /// [`ToPublic`] Proving Context
    pub to_public: ProvingContext<C>,
}

impl<C> MultiProvingContext<C>
where
    C: Configuration + ?Sized,
{
    /// Selects a [`ProvingContext`] based on `shape`.
    #[inline]
    pub fn select(&self, shape: TransferShape) -> &ProvingContext<C> {
        match shape {
            TransferShape::ToPrivate => &self.to_private,
            TransferShape::PrivateTransfer => &self.private_transfer,
            TransferShape::ToPublic => &self.to_public,
        }
    }
}

/// Canonical Multi-Verifying Contexts
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "VerifyingContext<C>: Deserialize<'de>",
            serialize = "VerifyingContext<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "VerifyingContext<C>: Clone"),
    Copy(bound = "VerifyingContext<C>: Copy"),
    Debug(bound = "VerifyingContext<C>: Debug"),
    Default(bound = "VerifyingContext<C>: Default"),
    Eq(bound = "VerifyingContext<C>: Eq"),
    Hash(bound = "VerifyingContext<C>: Hash"),
    PartialEq(bound = "VerifyingContext<C>: PartialEq")
)]
pub struct MultiVerifyingContext<C>
where
    C: Configuration + ?Sized,
{
    /// [`ToPrivate`] Verifying Context
    pub to_private: VerifyingContext<C>,

    /// [`PrivateTransfer`] Verifying Context
    pub private_transfer: VerifyingContext<C>,

    /// [`ToPublic`] Verifying Context
    pub to_public: VerifyingContext<C>,
}

impl<C> CanonicalSerialize for MultiVerifyingContext<C>
where
    C: Configuration + ?Sized,
    VerifyingContext<C>: CanonicalSerialize,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        self.to_private.serialize(&mut writer)?;
        self.private_transfer.serialize(&mut writer)?;
        self.to_public.serialize(&mut writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.to_private.serialized_size()
            + self.private_transfer.serialized_size()
            + self.to_public.serialized_size()
    }

    #[inline]
    fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        self.to_private.serialize_uncompressed(&mut writer)?;
        self.private_transfer.serialize_uncompressed(&mut writer)?;
        self.to_public.serialize_uncompressed(&mut writer)?;
        Ok(())
    }

    #[inline]
    fn serialize_unchecked<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        self.to_private.serialize_unchecked(&mut writer)?;
        self.private_transfer.serialize_unchecked(&mut writer)?;
        self.to_public.serialize_unchecked(&mut writer)?;
        Ok(())
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        self.to_private.uncompressed_size()
            + self.private_transfer.uncompressed_size()
            + self.to_public.uncompressed_size()
    }
}

impl<C> CanonicalDeserialize for MultiVerifyingContext<C>
where
    C: Configuration + ?Sized,
    VerifyingContext<C>: CanonicalDeserialize,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        Ok(Self {
            to_private: CanonicalDeserialize::deserialize(&mut reader)?,
            private_transfer: CanonicalDeserialize::deserialize(&mut reader)?,
            to_public: CanonicalDeserialize::deserialize(&mut reader)?,
        })
    }

    #[inline]
    fn deserialize_uncompressed<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        Ok(Self {
            to_private: CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
            private_transfer: CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
            to_public: CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
        })
    }

    #[inline]
    fn deserialize_unchecked<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        Ok(Self {
            to_private: CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
            private_transfer: CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
            to_public: CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
        })
    }
}

impl<C> MultiVerifyingContext<C>
where
    C: Configuration + ?Sized,
{
    /// Selects a [`VerifyingContext`] based on `shape`.
    #[inline]
    pub fn select(&self, shape: TransferShape) -> &VerifyingContext<C> {
        match shape {
            TransferShape::ToPrivate => &self.to_private,
            TransferShape::PrivateTransfer => &self.private_transfer,
            TransferShape::ToPublic => &self.to_public,
        }
    }
}

/// Generates proving and verifying multi-contexts for the canonical transfer shapes.
#[inline]
pub fn generate_context<C, R>(
    public_parameters: &ProofSystemPublicParameters<C>,
    parameters: FullParametersRef<C>,
    rng: &mut R,
) -> Result<(MultiProvingContext<C>, MultiVerifyingContext<C>), ProofSystemError<C>>
where
    C: Configuration,
    R: CryptoRng + RngCore + ?Sized,
{
    let to_private = ToPrivate::<C>::generate_context(public_parameters, parameters, rng)?;
    let private_transfer =
        PrivateTransfer::<C>::generate_context(public_parameters, parameters, rng)?;
    let to_public = ToPublic::<C>::generate_context(public_parameters, parameters, rng)?;
    Ok((
        MultiProvingContext {
            to_private: to_private.0,
            private_transfer: private_transfer.0,
            to_public: to_public.0,
        },
        MultiVerifyingContext {
            to_private: to_private.1,
            private_transfer: private_transfer.1,
            to_public: to_public.1,
        },
    ))
}

/// Transaction Data
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Asset<C>: Deserialize<'de>, Identifier<C>: Deserialize<'de>",
            serialize = "Asset<C>: Serialize, Identifier<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Asset<C>: Clone, Identifier<C>: Clone"),
    Debug(bound = "Asset<C>: Debug, Identifier<C>: Debug"),
    Eq(bound = "Asset<C>: Eq, Identifier<C>: Eq"),
    Hash(bound = "Asset<C>: Hash, Identifier<C>: Hash"),
    PartialEq(bound = "Asset<C>: PartialEq, Identifier<C>: PartialEq")
)]
pub enum TransactionData<C>
where
    C: Configuration,
{
    /// To Private Transaction Data
    ToPrivate(Identifier<C>, Asset<C>),

    /// Private Transfer Transaction Data
    PrivateTransfer(Vec<(Identifier<C>, Asset<C>)>),

    /// To Public Transaction Data
    ToPublic(Identifier<C>, Asset<C>),
}

impl<C> TransactionData<C>
where
    C: Configuration,
{
    /// Returns a vector of [`Identifier`]-[`Asset`] pairs, consuming `self`.
    #[inline]
    pub fn open(&self) -> Vec<(Identifier<C>, Asset<C>)> {
        match self {
            TransactionData::ToPrivate(identifier, asset) => {
                [(identifier.clone(), asset.clone())].to_vec()
            }
            TransactionData::PrivateTransfer(identified_assets) => identified_assets.clone(),
            TransactionData::ToPublic(identifier, asset) => {
                [(identifier.clone(), asset.clone())].to_vec()
            }
        }
    }

    /// Reconstructs the [`Utxo`] from `self` and `address`.
    #[inline]
    pub fn reconstruct_utxo(
        &self,
        parameters: &Parameters<C>,
        address: &Address<C>,
    ) -> Vec<Utxo<C>> {
        self.open()
            .into_iter()
            .map(|(identifier, asset)| parameters.utxo_reconstruct(&asset, &identifier, address))
            .collect()
    }

    /// Checks the correctness of `self` against `utxos`.
    #[inline]
    pub fn check_transaction_data(
        &self,
        parameters: &Parameters<C>,
        address: &Address<C>,
        utxos: &Vec<Utxo<C>>,
    ) -> bool
    where
        Utxo<C>: PartialEq,
    {
        self.reconstruct_utxo(parameters, address).eq(utxos)
    }

    /// Returns the [`TransferShape`] of `self`.
    #[inline]
    pub fn shape(&self) -> TransferShape {
        match self {
            Self::ToPrivate(_, _) => TransferShape::ToPrivate,
            Self::PrivateTransfer(_) => TransferShape::PrivateTransfer,
            Self::ToPublic(_, _) => TransferShape::ToPublic,
        }
    }

    /// Verifies `self` against `transferpost`.
    #[inline]
    pub fn verify(
        &self,
        parameters: &Parameters<C>,
        address: &Address<C>,
        transferpost: TransferPost<C>,
    ) -> bool
    where
        Utxo<C>: PartialEq,
    {
        if !TransferShape::from_post(&transferpost)
            .map(|shape| shape.eq(&self.shape()))
            .unwrap_or(false)
        {
            return false;
        }
        self.check_transaction_data(
            parameters,
            address,
            &transferpost
                .body
                .receiver_posts
                .into_iter()
                .map(|receiver_post| receiver_post.utxo)
                .collect(),
        )
    }
}
