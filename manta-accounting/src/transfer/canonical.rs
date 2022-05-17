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
    asset::{self, Asset, AssetMap, AssetMetadata, AssetValue},
    transfer::{
        has_public_participants, Configuration, FullParameters, Parameters, PreSender,
        ProofSystemError, ProofSystemPublicParameters, ProvingContext, Receiver, ReceivingKey,
        Sender, SpendingKey, Transfer, TransferPost, VerifyingContext,
    },
};
use alloc::{format, string::String, vec::Vec};
use core::{fmt::Debug, hash::Hash};
use manta_crypto::rand::{CryptoRng, Rand, RngCore};
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

/// [`Mint`] Transfer Shape
///
/// ```text
/// <1, 0, 1, 0>
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct MintShape;

impl_shape!(MintShape, 1, 0, 1, 0);

/// [`Mint`] Transfer Type
pub type Mint<C> = transfer_alias!(C, MintShape);

impl<C> Mint<C>
where
    C: Configuration,
{
    /// Builds a [`Mint`] from `asset` and `receiver`.
    #[inline]
    pub fn build(asset: Asset, receiver: Receiver<C>) -> Self {
        Self::new_unchecked(Some(asset.id), [asset.value], [], [receiver], [])
    }

    /// Builds a new [`Mint`] from a [`SpendingKey`] using [`SpendingKey::receiver`].
    #[inline]
    pub fn from_spending_key<R>(
        parameters: &Parameters<C>,
        spending_key: &SpendingKey<C>,
        asset: Asset,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::build(asset, spending_key.receiver(parameters, rng.gen(), asset))
    }

    /// Builds a new [`Mint`] and [`PreSender`] pair from a [`SpendingKey`] using
    /// [`SpendingKey::internal_pair`].
    #[inline]
    pub fn internal_pair<R>(
        parameters: &Parameters<C>,
        spending_key: &SpendingKey<C>,
        asset: Asset,
        rng: &mut R,
    ) -> (Self, PreSender<C>)
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let (receiver, pre_sender) = spending_key.internal_pair(parameters, rng.gen(), asset);
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
        senders: [Sender<C>; PrivateTransferShape::SENDERS],
        receivers: [Receiver<C>; PrivateTransferShape::RECEIVERS],
    ) -> Self {
        Self::new_unchecked(None, [], senders, receivers, [])
    }
}

/// [`Reclaim`] Transfer Shape
///
/// ```text
/// <0, 2, 1, 1>
/// ```
///
/// The [`ReclaimShape`] is defined in terms of the [`PrivateTransferShape`]. It is defined to
/// have the same number of senders and one secret receiver turned into a public sink.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct ReclaimShape;

impl_shape!(
    ReclaimShape,
    PrivateTransferShape::SOURCES,
    PrivateTransferShape::SENDERS,
    PrivateTransferShape::RECEIVERS - 1,
    PrivateTransferShape::SINKS + 1
);

/// [`Reclaim`] Transfer
pub type Reclaim<C> = transfer_alias!(C, ReclaimShape);

impl<C> Reclaim<C>
where
    C: Configuration,
{
    /// Builds a [`Reclaim`] from `senders`, `receivers`, and `reclaim`.
    #[inline]
    pub fn build(
        senders: [Sender<C>; ReclaimShape::SENDERS],
        receivers: [Receiver<C>; ReclaimShape::RECEIVERS],
        asset: Asset,
    ) -> Self {
        Self::new_unchecked(Some(asset.id), [], senders, receivers, [asset.value])
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
    /// [`Mint`] Transfer
    Mint,

    /// [`PrivateTransfer`] Transfer
    PrivateTransfer,

    /// [`Reclaim`] Transfer
    Reclaim,
}

impl TransferShape {
    /// Selects the [`TransferShape`] for the given shape if it matches a canonical shape.
    #[inline]
    pub fn select(
        asset_id_is_some: bool,
        sources: usize,
        senders: usize,
        receivers: usize,
        sinks: usize,
    ) -> Option<Self> {
        const MINT_VISIBLE_ASSET_ID: bool =
            has_public_participants(MintShape::SOURCES, MintShape::SINKS);
        const PRIVATE_TRANSFER_VISIBLE_ASSET_ID: bool =
            has_public_participants(PrivateTransferShape::SOURCES, PrivateTransferShape::SINKS);
        const RECLAIM_VISIBLE_ASSET_ID: bool =
            has_public_participants(ReclaimShape::SOURCES, ReclaimShape::SINKS);
        match (asset_id_is_some, sources, senders, receivers, sinks) {
            (
                MINT_VISIBLE_ASSET_ID,
                MintShape::SOURCES,
                MintShape::SENDERS,
                MintShape::RECEIVERS,
                MintShape::SINKS,
            ) => Some(Self::Mint),
            (
                PRIVATE_TRANSFER_VISIBLE_ASSET_ID,
                PrivateTransferShape::SOURCES,
                PrivateTransferShape::SENDERS,
                PrivateTransferShape::RECEIVERS,
                PrivateTransferShape::SINKS,
            ) => Some(Self::PrivateTransfer),
            (
                RECLAIM_VISIBLE_ASSET_ID,
                ReclaimShape::SOURCES,
                ReclaimShape::SENDERS,
                ReclaimShape::RECEIVERS,
                ReclaimShape::SINKS,
            ) => Some(Self::Reclaim),
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
            post.asset_id.is_some(),
            post.sources.len(),
            post.sender_posts.len(),
            post.receiver_posts.len(),
            post.sinks.len(),
        )
    }
}

/// Canonical Transaction Type
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "ReceivingKey<C>: Deserialize<'de>",
            serialize = "ReceivingKey<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "ReceivingKey<C>: Clone"),
    Copy(bound = "ReceivingKey<C>: Copy"),
    Debug(bound = "ReceivingKey<C>: Debug"),
    Eq(bound = "ReceivingKey<C>: Eq"),
    Hash(bound = "ReceivingKey<C>: Hash"),
    PartialEq(bound = "ReceivingKey<C>: PartialEq")
)]
pub enum Transaction<C>
where
    C: Configuration,
{
    /// Mint Private Asset
    Mint(Asset),

    /// Private Transfer Asset to Receiver
    PrivateTransfer(Asset, ReceivingKey<C>),

    /// Reclaim Private Asset
    Reclaim(Asset),
}

impl<C> Transaction<C>
where
    C: Configuration,
{
    /// Checks that `self` can be executed for a given `balance` state, returning the
    /// transaction kind if successful, and returning the asset back if the balance was
    /// insufficient.
    #[inline]
    pub fn check<F>(&self, balance: F) -> Result<TransactionKind, Asset>
    where
        F: FnOnce(Asset) -> bool,
    {
        match self {
            Self::Mint(asset) => Ok(TransactionKind::Deposit(*asset)),
            Self::PrivateTransfer(asset, _) | Self::Reclaim(asset) => {
                if balance(*asset) {
                    Ok(TransactionKind::Withdraw(*asset))
                } else {
                    Err(*asset)
                }
            }
        }
    }

    /// Returns the associated [`TransferShape`] for this [`Transaction`].
    #[inline]
    pub fn shape(&self) -> TransferShape {
        match self {
            Self::Mint(_) => TransferShape::Mint,
            Self::PrivateTransfer(_, _) => TransferShape::PrivateTransfer,
            Self::Reclaim(_) => TransferShape::Reclaim,
        }
    }

    /// Returns `true` if `self` is a [`Transaction`] which transfers zero value.
    #[inline]
    pub fn is_zero(&self) -> bool {
        match self {
            Self::Mint(asset) => asset.is_zero(),
            Self::PrivateTransfer(asset, _) => asset.is_zero(),
            Self::Reclaim(asset) => asset.is_zero(),
        }
    }

    /// Returns a transaction summary given the asset `metadata`.
    #[inline]
    pub fn display<F>(&self, metadata: &AssetMetadata, f: F) -> String
    where
        F: FnOnce(&ReceivingKey<C>) -> String,
    {
        match self {
            Self::Mint(Asset { value, .. }) => format!("Deposit {}", metadata.display(*value)),
            Self::PrivateTransfer(Asset { value, .. }, receiving_key) => {
                format!("Send {} to {}", metadata.display(*value), f(receiving_key))
            }
            Self::Reclaim(Asset { value, .. }) => format!("Withdraw {}", metadata.display(*value)),
        }
    }
}

/// Transaction Kind
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransactionKind {
    /// Deposit Transaction
    ///
    /// A transaction of this kind will result in a deposit of `asset`.
    Deposit(Asset),

    /// Withdraw Transaction
    ///
    /// A transaction of this kind will result in a withdraw of `asset`.
    Withdraw(Asset),
}

/// Transfer Asset Selection
pub struct Selection<C>
where
    C: Configuration,
{
    /// Change Value
    pub change: AssetValue,

    /// Pre-Senders
    pub pre_senders: Vec<PreSender<C>>,
}

impl<C> Selection<C>
where
    C: Configuration,
{
    /// Builds a new [`Selection`] from `change` and `pre_senders`.
    #[inline]
    fn build(change: AssetValue, pre_senders: Vec<PreSender<C>>) -> Self {
        Self {
            change,
            pre_senders,
        }
    }

    /// Builds a new [`Selection`] by mapping over an asset selection with `builder`.
    #[inline]
    pub fn new<M, E, F>(selection: asset::Selection<M>, mut builder: F) -> Result<Self, E>
    where
        M: AssetMap,
        F: FnMut(M::Key, AssetValue) -> Result<PreSender<C>, E>,
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
    /// Mint Proving Context
    pub mint: ProvingContext<C>,

    /// Private Transfer Proving Context
    pub private_transfer: ProvingContext<C>,

    /// Reclaim Proving Context
    pub reclaim: ProvingContext<C>,
}

impl<C> MultiProvingContext<C>
where
    C: Configuration + ?Sized,
{
    /// Selects a [`ProvingContext`] based on `shape`.
    #[inline]
    pub fn select(&self, shape: TransferShape) -> &ProvingContext<C> {
        match shape {
            TransferShape::Mint => &self.mint,
            TransferShape::PrivateTransfer => &self.private_transfer,
            TransferShape::Reclaim => &self.reclaim,
        }
    }
}

/// Canonical Multi-Verifying Contexts
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
    /// Mint Verifying Context
    pub mint: VerifyingContext<C>,

    /// Private Transfer Verifying Context
    pub private_transfer: VerifyingContext<C>,

    /// Reclaim Verifying Context
    pub reclaim: VerifyingContext<C>,
}

impl<C> MultiVerifyingContext<C>
where
    C: Configuration + ?Sized,
{
    /// Selects a [`VerifyingContext`] based on `shape`.
    #[inline]
    pub fn select(&self, shape: TransferShape) -> &VerifyingContext<C> {
        match shape {
            TransferShape::Mint => &self.mint,
            TransferShape::PrivateTransfer => &self.private_transfer,
            TransferShape::Reclaim => &self.reclaim,
        }
    }
}

/// Generates proving and verifying multi-contexts for the canonical transfer shapes.
#[inline]
pub fn generate_context<C, R>(
    public_parameters: &ProofSystemPublicParameters<C>,
    parameters: FullParameters<C>,
    rng: &mut R,
) -> Result<(MultiProvingContext<C>, MultiVerifyingContext<C>), ProofSystemError<C>>
where
    C: Configuration,
    R: CryptoRng + RngCore + ?Sized,
{
    let mint = Mint::generate_context(public_parameters, parameters, rng)?;
    let private_transfer = PrivateTransfer::generate_context(public_parameters, parameters, rng)?;
    let reclaim = Reclaim::generate_context(public_parameters, parameters, rng)?;
    Ok((
        MultiProvingContext {
            mint: mint.0,
            private_transfer: private_transfer.0,
            reclaim: reclaim.0,
        },
        MultiVerifyingContext {
            mint: mint.1,
            private_transfer: private_transfer.1,
            reclaim: reclaim.1,
        },
    ))
}
