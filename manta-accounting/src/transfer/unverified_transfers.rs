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
use super::*;

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
            ",
            serialize = r"
                AuthorizationSignature<C>: Serialize,
                UnsafeTransferPostBody<C>: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "AuthorizationSignature<C>: Clone, UnsafeTransferPostBody<C>: Clone"),
    Debug(bound = "AuthorizationSignature<C>: Debug, UnsafeTransferPostBody<C>: Debug"),
    Eq(bound = "AuthorizationSignature<C>: Eq, UnsafeTransferPostBody<C>: Eq"),
    Hash(bound = "AuthorizationSignature<C>: Hash, UnsafeTransferPostBody<C>: Hash"),
    PartialEq(
        bound = "AuthorizationSignature<C>: PartialEq, UnsafeTransferPostBody<C>: PartialEq"
    )
)]
pub struct UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
{
    /// Authorization Signature
    pub authorization_signature: Option<AuthorizationSignature<C>>,

    /// Transfer Post Body
    pub body: UnsafeTransferPostBody<C>,
}

impl<C> UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`TransferPost`] without checking the consistency conditions between the `body`
    /// and the `authorization_signature`.
    #[inline]
    fn new_unchecked(
        authorization_signature: Option<AuthorizationSignature<C>>,
        body: UnsafeTransferPostBody<C>,
    ) -> Self {
        Self {
            authorization_signature,
            body,
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

    /// Verifies the validity proof of `self` according to the `verifying_context`.
    #[inline]
    pub fn has_valid_proof(
        &self,
        verifying_context: &VerifyingContext<C>,
    ) -> Result<bool, ProofSystemError<C>> {
        let _ = verifying_context;
        Ok(true)
    }

    /// Asserts that `self` has a valid proof. See [`has_valid_proof`](Self::has_valid_proof) for
    /// more.
    #[inline]
    pub fn assert_valid_proof(&self, verifying_context: &VerifyingContext<C>)
    where
        Self: Debug,
        ProofSystemError<C>: Debug,
    {
        assert!(
            self.has_valid_proof(verifying_context)
                .expect("Unable to verify proof."),
            "Invalid TransferPost: {:?}.",
            self,
        );
    }

    /// Verifies that the authorization signature for `self` is valid under the `parameters`.
    #[inline]
    pub fn has_valid_authorization_signature(
        &self,
        parameters: &C::Parameters,
    ) -> Result<(), InvalidAuthorizationSignature> {
        let _ = parameters;
        match (
            &self.authorization_signature,
            requires_authorization(self.body.sender_posts.len()),
        ) {
            (Some(_), true) => Ok(()),
            (Some(_), false) => Err(InvalidAuthorizationSignature::InvalidShape),
            (None, true) => Err(InvalidAuthorizationSignature::MissingSignature),
            (None, false) => Ok(()),
        }
    }

    /// Checks that the public participant data is well-formed and runs `ledger` validation on
    /// source and sink accounts.
    #[allow(clippy::type_complexity)] // FIXME: Use a better abstraction for this.
    #[inline]
    fn check_public_participants<L>(
        asset_id: &Option<C::AssetId>,
        source_accounts: Vec<L::AccountId>,
        source_values: Vec<C::AssetValue>,
        sink_accounts: Vec<L::AccountId>,
        sink_values: Vec<C::AssetValue>,
        ledger: &L,
    ) -> Result<
        (Vec<L::ValidSourceAccount>, Vec<L::ValidSinkAccount>),
        TransferPostError<C, L::AccountId, L::UpdateError>,
    >
    where
        L: TransferLedger<C>,
    {
        let sources = source_values.len();
        let sinks = sink_values.len();
        if has_public_participants(sources, sinks) != asset_id.is_some() {
            return Err(TransferPostError::InvalidShape);
        }
        if source_accounts.len() != sources {
            return Err(TransferPostError::InvalidShape);
        }
        if sink_accounts.len() != sinks {
            return Err(TransferPostError::InvalidShape);
        }
        let sources = if sources > 0 {
            ledger.check_source_accounts(
                asset_id.as_ref().unwrap(),
                source_accounts.into_iter().zip(source_values),
            )?
        } else {
            Vec::new()
        };
        let sinks = if sinks > 0 {
            ledger.check_sink_accounts(
                asset_id.as_ref().unwrap(),
                sink_accounts.into_iter().zip(sink_values),
            )?
        } else {
            Vec::new()
        };
        Ok((sources, sinks))
    }

    /// Doesn't perform a validation of `self` on the transfer `ledger`.
    #[allow(clippy::type_complexity)] // FIXME: Use a better abstraction for this.
    #[inline]
    pub fn unsafe_no_validate<L>(
        self,
        parameters: &C::Parameters,
        ledger: &L,
        source_accounts: Vec<L::AccountId>,
        sink_accounts: Vec<L::AccountId>,
    ) -> Result<TransferPostingKey<C, L>, TransferPostError<C, L::AccountId, L::UpdateError>>
    where
        L: TransferLedger<C>,
        L::Event: Default,
        L::ValidProof: Default,
    {
        self.has_valid_authorization_signature(parameters)?;
        let (source_posting_keys, sink_posting_keys) = Self::check_public_participants(
            &self.body.asset_id,
            source_accounts,
            self.body.sources,
            sink_accounts,
            self.body.sinks,
            ledger,
        )?;
        if !all_unequal(&self.body.sender_posts, |p, q| {
            p.nullifier.is_related(&q.nullifier)
        }) {
            return Err(TransferPostError::DuplicateSpend);
        }
        if !all_unequal(&self.body.receiver_posts, |p, q| p.utxo.is_related(&q.utxo)) {
            return Err(TransferPostError::DuplicateMint);
        }
        let sender_posting_keys = self
            .body
            .sender_posts
            .into_iter()
            .map(move |s| s.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        let receiver_posting_keys = self
            .body
            .receiver_posts
            .into_iter()
            .map(move |r| r.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        let (proof, event) = (Default::default(), Default::default());
        Ok(TransferPostingKey {
            asset_id: self.body.asset_id,
            source_posting_keys,
            sender_posting_keys,
            receiver_posting_keys,
            sink_posting_keys,
            proof,
            event,
        })
    }

    /// Validates `self` on the transfer `ledger` and then posts the updated state to the `ledger`
    /// if validation succeeded.
    #[inline]
    pub fn post<L>(
        self,
        parameters: &C::Parameters,
        ledger: &mut L,
        super_key: &TransferLedgerSuperPostingKey<C, L>,
        source_accounts: Vec<L::AccountId>,
        sink_accounts: Vec<L::AccountId>,
    ) -> Result<L::Event, TransferPostError<C, L::AccountId, L::UpdateError>>
    where
        L: TransferLedger<C>,
        L::Event: Default,
        L::ValidProof: Default,
    {
        self.unsafe_no_validate(parameters, ledger, source_accounts, sink_accounts)?
            .post(ledger, super_key)
            .map_err(TransferPostError::UpdateError)
    }
}

impl<C> Encode for UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
    AuthorizationSignature<C>: Encode,
    UnsafeTransferPostBody<C>: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.authorization_signature.encode(&mut writer)?;
        self.body.encode(&mut writer)?;
        Ok(())
    }
}

impl<C> Input<C::ProofSystem> for UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut ProofInput<C>) {
        if let Some(authorization_signature) = &self.authorization_signature {
            C::ProofSystem::extend(input, &authorization_signature.authorization_key);
        }
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
            authorization_signature: unsafe_transfer_post.authorization_signature,
            body: unsafe_transfer_post.body.into(),
        }
    }
}

impl<C> From<TransferPost<C>> for UnsafeTransferPost<C>
where
    C: Configuration + ?Sized,
{
    fn from(transfer_post: TransferPost<C>) -> Self {
        Self {
            authorization_signature: transfer_post.authorization_signature,
            body: transfer_post.body.into(),
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
        rng: &mut R,
    ) -> Result<Option<UnsafeTransferPost<C>>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
        Proof<C>: Default,
        C::AssetId: Clone,
        C::AssetValue: Clone,
        SenderPost<C>: Clone,
        ReceiverPost<C>: Clone,
    {
        match (
            requires_authorization(SENDERS),
            self.authorization.is_some(),
            spending_key,
        ) {
            (true, true, Some(spending_key)) => {
                let (body, authorization) = self.into_unsafe_post_body_with_authorization(
                    parameters,
                    proving_context,
                    rng,
                )?;
                match auth::sign(
                    parameters.base,
                    spending_key,
                    authorization.expect("It is known to be `Some` from the check above."),
                    &body.clone().into(),
                    rng,
                ) {
                    Some(authorization_signature) => Ok(Some(UnsafeTransferPost::new_unchecked(
                        Some(authorization_signature),
                        body,
                    ))),
                    _ => Ok(None),
                }
            }
            (false, false, None) => Ok(Some(UnsafeTransferPost::new_unchecked(
                None,
                self.into_unsafe_post_body(parameters, proving_context, rng)?,
            ))),
            _ => Ok(None),
        }
    }

    /// Converts `self` into its [`UnsafeTransferPostBody`].
    #[inline]
    pub fn into_unsafe_post_body<R>(
        self,
        parameters: FullParametersRef<C>,
        proving_context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<UnsafeTransferPostBody<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = (parameters, proving_context, rng);
        Ok(UnsafeTransferPostBody::build(
            self.asset_id,
            self.sources,
            self.senders,
            self.receivers,
            self.sinks,
        ))
    }

    /// Converts `self` into its [`UnsafeTransferPostBody`].
    #[allow(clippy::type_complexity)] // FIXME: Use a better abstraction here.
    #[inline]
    fn into_unsafe_post_body_with_authorization<R>(
        self,
        parameters: FullParametersRef<C>,
        proving_context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<(UnsafeTransferPostBody<C>, Option<Authorization<C>>), ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = (parameters, proving_context, rng);
        Ok((
            UnsafeTransferPostBody::build(
                self.asset_id,
                self.sources,
                self.senders,
                self.receivers,
                self.sinks,
            ),
            self.authorization,
        ))
    }
}
