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
//! Unverified Transfers
//!
//! # SAFETY
//!
//! This module is for testing purposes only. [`UnsafeTransferPost`] and [`UnsafeTransferPostBody`] do not
//! require proof nor proof validation and as such can only be used with trusted inputs.

use crate::transfer::{
    Asset, AuthorizationSignature, Configuration, FullParametersRef, Proof, ProofInput,
    ProvingContext, Receiver, ReceiverPost, Sender, SenderPost, SpendingKey, Transfer,
    TransferPost, TransferPostBody,
};
use core::{fmt::Debug, hash::Hash};
use manta_crypto::{
    constraint::{HasInput, Input},
    rand::{CryptoRng, RngCore},
};
use manta_util::codec::{Encode, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Unsafe Transfer Post Body
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                C::AssetId: Deserialize<'de>,
                C::AssetValue: Deserialize<'de>,
                SenderPost<C>: Deserialize<'de>,
                ReceiverPost<C>: Deserialize<'de>,
            ",
            serialize = r"
                C::AssetId: Serialize,
                C::AssetValue: Serialize,
                SenderPost<C>: Serialize,
                ReceiverPost<C>: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = r"
        C::AssetId: Clone,
        C::AssetValue: Clone,
        SenderPost<C>: Clone,
        ReceiverPost<C>: Clone,
    "),
    Debug(bound = r"
        C::AssetId: Debug,
        C::AssetValue: Debug,
        SenderPost<C>: Debug,
        ReceiverPost<C>: Debug,
    "),
    Eq(bound = r"
        C::AssetId: Eq,
        C::AssetValue: Eq,
        SenderPost<C>: Eq,
        ReceiverPost<C>: Eq,
    "),
    Hash(bound = r"
        C::AssetId: Hash,
        C::AssetValue: Hash,
        SenderPost<C>: Hash,
        ReceiverPost<C>: Hash,
    "),
    PartialEq(bound = r"
        C::AssetId: PartialEq,
        C::AssetValue: PartialEq,
        SenderPost<C>: PartialEq,
        ReceiverPost<C>: PartialEq,
    ")
)]
pub struct UnsafeTransferPostBody<C>
where
    C: Configuration + ?Sized,
{
    /// Asset Id
    pub asset_id: Option<C::AssetId>,

    /// Sources
    pub sources: Vec<C::AssetValue>,

    /// Sender Posts
    pub sender_posts: Vec<SenderPost<C>>,

    /// Receiver Posts
    pub receiver_posts: Vec<ReceiverPost<C>>,

    /// Sinks
    pub sinks: Vec<C::AssetValue>,
}

impl<C> UnsafeTransferPostBody<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`TransferPostBody`].
    #[inline]
    fn build<
        const SOURCES: usize,
        const SENDERS: usize,
        const RECEIVERS: usize,
        const SINKS: usize,
    >(
        asset_id: Option<C::AssetId>,
        sources: [C::AssetValue; SOURCES],
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
        sinks: [C::AssetValue; SINKS],
    ) -> Self {
        Self {
            asset_id,
            sources: sources.into(),
            sender_posts: senders.into_iter().map(Sender::<C>::into_post).collect(),
            receiver_posts: receivers
                .into_iter()
                .map(Receiver::<C>::into_post)
                .collect(),
            sinks: sinks.into(),
        }
    }

    /// Constructs an [`Asset`] against the `asset_id` of `self` and `value`.
    #[inline]
    fn construct_asset(&self, value: &C::AssetValue) -> Option<Asset<C>> {
        Some(Asset::<C>::new(self.asset_id.clone()?, value.clone()))
    }

    /// Returns the `k`-th source in the transfer.
    #[inline]
    pub fn source(&self, k: usize) -> Option<Asset<C>> {
        self.sources
            .get(k)
            .and_then(|value| self.construct_asset(value))
    }

    /// Returns the `k`-th sink in the transfer.
    #[inline]
    pub fn sink(&self, k: usize) -> Option<Asset<C>> {
        self.sinks
            .get(k)
            .and_then(|value| self.construct_asset(value))
    }
}

impl<C> Encode for UnsafeTransferPostBody<C>
where
    C: Configuration + ?Sized,
    C::AssetId: Encode,
    C::AssetValue: Encode,
    SenderPost<C>: Encode,
    ReceiverPost<C>: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.asset_id.encode(&mut writer)?;
        self.sources.encode(&mut writer)?;
        self.sender_posts.encode(&mut writer)?;
        self.receiver_posts.encode(&mut writer)?;
        self.sinks.encode(&mut writer)?;
        Ok(())
    }
}

impl<C> Input<C::ProofSystem> for UnsafeTransferPostBody<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut ProofInput<C>) {
        if let Some(asset_id) = &self.asset_id {
            C::ProofSystem::extend(input, asset_id);
        }
        self.sources
            .iter()
            .for_each(|source| C::ProofSystem::extend(input, source));
        self.sender_posts
            .iter()
            .for_each(|post| C::ProofSystem::extend(input, post));
        self.receiver_posts
            .iter()
            .for_each(|post| C::ProofSystem::extend(input, post));
        self.sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(input, sink));
    }
}

impl<C> From<UnsafeTransferPostBody<C>> for TransferPostBody<C>
where
    C: Configuration + ?Sized,
    Proof<C>: Default,
{
    fn from(unsafe_transfer_post_body: UnsafeTransferPostBody<C>) -> Self {
        Self {
            asset_id: unsafe_transfer_post_body.asset_id,
            sources: unsafe_transfer_post_body.sources,
            sender_posts: unsafe_transfer_post_body.sender_posts,
            receiver_posts: unsafe_transfer_post_body.receiver_posts,
            sinks: unsafe_transfer_post_body.sinks,
            proof: Default::default(),
        }
    }
}

impl<C> From<TransferPostBody<C>> for UnsafeTransferPostBody<C>
where
    C: Configuration + ?Sized,
{
    fn from(transfer_post_body: TransferPostBody<C>) -> Self {
        Self {
            asset_id: transfer_post_body.asset_id,
            sources: transfer_post_body.sources,
            sender_posts: transfer_post_body.sender_posts,
            receiver_posts: transfer_post_body.receiver_posts,
            sinks: transfer_post_body.sinks,
        }
    }
}

/// Unsafe Transfer Post
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                AuthorizationSignature<C>: Deserialize<'de>,
                UnsafeTransferPostBody<C>: Deserialize<'de>,
                C::AccountId: Deserialize<'de>,
            ",
            serialize = r"
                AuthorizationSignature<C>: Serialize,
                UnsafeTransferPostBody<C>: Serialize,
                C::AccountId: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(
        bound = "AuthorizationSignature<C>: Clone, UnsafeTransferPostBody<C>: Clone, C::AccountId: Clone"
    ),
    Debug(
        bound = "AuthorizationSignature<C>: Debug, UnsafeTransferPostBody<C>: Debug, C::AccountId: Debug"
    ),
    Eq(bound = "AuthorizationSignature<C>: Eq, UnsafeTransferPostBody<C>: Eq, C::AccountId: Eq"),
    Hash(
        bound = "AuthorizationSignature<C>: Hash, UnsafeTransferPostBody<C>: Hash, C::AccountId: Hash"
    ),
    PartialEq(
        bound = "AuthorizationSignature<C>: PartialEq, UnsafeTransferPostBody<C>: PartialEq, C::AccountId: PartialEq"
    )
)]
pub struct UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
{
    /// Transfer Post Body
    pub body: UnsafeTransferPostBody<C>,

    /// Sink accounts
    pub sink_accounts: Vec<C::AccountId>,
}

impl<C> UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
{
    ///
    #[inline]
    fn new_unchecked_with_sinks(
        body: UnsafeTransferPostBody<C>,
        sink_accounts: Vec<C::AccountId>,
    ) -> Self {
        Self {
            body,
            sink_accounts,
        }
    }

    /// Returns the `k`-th source in the transfer.
    #[inline]
    pub fn source(&self, k: usize) -> Option<Asset<C>> {
        self.body.source(k)
    }

    /// Returns the `k`-th sink in the transfer.
    #[inline]
    pub fn sink(&self, k: usize) -> Option<Asset<C>> {
        self.body.sink(k)
    }

    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        let mut input = Default::default();
        self.extend(&mut input);
        input
    }
}

impl<C> Encode for UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
    UnsafeTransferPostBody<C>: Encode,
    C::AccountId: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.body.encode(&mut writer)?;
        self.sink_accounts.encode(&mut writer)?;
        Ok(())
    }
}

impl<C> Input<C::ProofSystem> for UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut ProofInput<C>) {
        self.body.extend(input);
    }
}

impl<C> From<UnsafeTransferPost<C>> for TransferPost<C>
where
    C: Configuration + ?Sized,
    Proof<C>: Default,
{
    fn from(unsafe_transfer_post: UnsafeTransferPost<C>) -> Self {
        Self {
            authorization_signature: None,
            body: unsafe_transfer_post.body.into(),
            sink_accounts: unsafe_transfer_post.sink_accounts,
        }
    }
}

impl<C> From<TransferPost<C>> for UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
{
    fn from(transfer_post: TransferPost<C>) -> Self {
        Self {
            body: transfer_post.body.into(),
            sink_accounts: transfer_post.sink_accounts,
        }
    }
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Converts `self` into its [`UnsafeTransferPost`].
    #[inline]
    pub fn into_unsafe_post<R>(
        self,
        parameters: FullParametersRef<C>,
        proving_context: &ProvingContext<C>,
        spending_key: Option<&SpendingKey<C>>,
        sink_accounts: Vec<C::AccountId>,
        rng: &mut R,
    ) -> UnsafeTransferPost<C>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = spending_key;
        UnsafeTransferPost::new_unchecked_with_sinks(
            self.into_unsafe_post_body(parameters, proving_context, rng),
            sink_accounts,
        )
    }

    /// Converts `self` into its [`UnsafeTransferPostBody`].
    #[inline]
    pub fn into_unsafe_post_body<R>(
        self,
        parameters: FullParametersRef<C>,
        proving_context: &ProvingContext<C>,
        rng: &mut R,
    ) -> UnsafeTransferPostBody<C>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = (parameters, proving_context, rng);
        UnsafeTransferPostBody::build(
            self.asset_id,
            self.sources,
            self.senders,
            self.receivers,
            self.sinks,
        )
    }
}
