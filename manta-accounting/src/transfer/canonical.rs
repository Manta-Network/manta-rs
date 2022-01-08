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

//! Canonical Transfer Types

use crate::{
    asset::{self, Asset, AssetValue},
    transfer::{self, Configuration, PreSender, Receiver, ReceivingKey, Sender, Transfer},
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};
use manta_util::{create_seal, seal};

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
    ($shape:tt, $sources:expr, $senders:expr, $receivers:expr, $sinks:expr) => {
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
        $type<
            $t,
            { $shape::SOURCES },
            { $shape::SENDERS },
            { $shape::RECEIVERS },
            { $shape::SINKS },
        >
    }
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
        Self::new(Some(asset.id), [asset.value], [], [receiver], [])
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
        Self::new(None, [], senders, receivers, [])
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
    0,
    PrivateTransferShape::SENDERS,
    PrivateTransferShape::RECEIVERS - 1,
    1
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
        reclaim: Asset,
    ) -> Self {
        Self::new(reclaim.id, [], senders, receivers, [reclaim.value])
    }
}

/// Transfer Shape
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
    #[allow(clippy::absurd_extreme_comparisons)] // NOTE: We want these comparisons as values..
    #[inline]
    pub fn select(
        asset_id_is_some: bool,
        sources: usize,
        senders: usize,
        receivers: usize,
        sinks: usize,
    ) -> Option<Self> {
        const MINT_VISIBLE_ID: bool = MintShape::SOURCES + MintShape::SINKS > 0;
        const PRIVATE_TRANSFER_VISIBLE_ID: bool =
            PrivateTransferShape::SOURCES + PrivateTransferShape::SINKS > 0;
        const RECLAIM_VISIBLE_ID: bool = ReclaimShape::SOURCES + ReclaimShape::SINKS > 0;
        match (asset_id_is_some, sources, senders, receivers, sinks) {
            (
                MINT_VISIBLE_ID,
                MintShape::SOURCES,
                MintShape::SENDERS,
                MintShape::RECEIVERS,
                MintShape::SINKS,
            ) => Some(Self::Mint),
            (
                PRIVATE_TRANSFER_VISIBLE_ID,
                PrivateTransferShape::SOURCES,
                PrivateTransferShape::SENDERS,
                PrivateTransferShape::RECEIVERS,
                PrivateTransferShape::SINKS,
            ) => Some(Self::PrivateTransfer),
            (
                RECLAIM_VISIBLE_ID,
                ReclaimShape::SOURCES,
                ReclaimShape::SENDERS,
                ReclaimShape::RECEIVERS,
                ReclaimShape::SINKS,
            ) => Some(Self::Reclaim),
            _ => None,
        }
    }
}

/// Canonical Transaction Type
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
}

/// Transaction Kind
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
        M: asset::AssetMap,
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

/// Canonical Proving Contexts
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "transfer::ProvingContext<C>: Clone"),
    Copy(bound = "transfer::ProvingContext<C>: Copy"),
    Debug(bound = "transfer::ProvingContext<C>: Debug"),
    Default(bound = "transfer::ProvingContext<C>: Default"),
    Eq(bound = "transfer::ProvingContext<C>: Eq"),
    Hash(bound = "transfer::ProvingContext<C>: Hash"),
    PartialEq(bound = "transfer::ProvingContext<C>: PartialEq")
)]
pub struct ProvingContext<C>
where
    C: Configuration,
{
    /// Mint Proving Context
    pub mint: transfer::ProvingContext<C>,

    /// Private Transfer Proving Context
    pub private_transfer: transfer::ProvingContext<C>,

    /// Reclaim Proving Context
    pub reclaim: transfer::ProvingContext<C>,
}

impl<C> ProvingContext<C>
where
    C: Configuration,
{
    /// Selects the proving context for the given shape if it matches a canonical shape.
    #[inline]
    pub fn select(
        &self,
        asset_id_is_some: bool,
        sources: usize,
        senders: usize,
        receivers: usize,
        sinks: usize,
    ) -> Option<&transfer::ProvingContext<C>> {
        match TransferShape::select(asset_id_is_some, sources, senders, receivers, sinks)? {
            TransferShape::Mint => Some(&self.mint),
            TransferShape::PrivateTransfer => Some(&self.private_transfer),
            TransferShape::Reclaim => Some(&self.reclaim),
        }
    }
}

/// Canonical Verifying Contexts
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "transfer::VerifyingContext<C>: Clone"),
    Copy(bound = "transfer::VerifyingContext<C>: Copy"),
    Debug(bound = "transfer::VerifyingContext<C>: Debug"),
    Default(bound = "transfer::VerifyingContext<C>: Default"),
    Eq(bound = "transfer::VerifyingContext<C>: Eq"),
    Hash(bound = "transfer::VerifyingContext<C>: Hash"),
    PartialEq(bound = "transfer::VerifyingContext<C>: PartialEq")
)]
pub struct VerifyingContext<C>
where
    C: Configuration,
{
    /// Mint Verifying Context
    pub mint: transfer::VerifyingContext<C>,

    /// Private Transfer Verifying Context
    pub private_transfer: transfer::VerifyingContext<C>,

    /// Reclaim Verifying Context
    pub reclaim: transfer::VerifyingContext<C>,
}

impl<C> VerifyingContext<C>
where
    C: Configuration,
{
    /// Selects the verifying context for the given shape if it matches a canonical shape.
    #[inline]
    pub fn select(
        &self,
        asset_id_is_some: bool,
        sources: usize,
        senders: usize,
        receivers: usize,
        sinks: usize,
    ) -> Option<&transfer::VerifyingContext<C>> {
        match TransferShape::select(asset_id_is_some, sources, senders, receivers, sinks)? {
            TransferShape::Mint => Some(&self.mint),
            TransferShape::PrivateTransfer => Some(&self.private_transfer),
            TransferShape::Reclaim => Some(&self.reclaim),
        }
    }
}
