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

//! Transfer Protocol Testing Framework

use crate::transfer::{
    canonical::ToPrivate, has_public_participants, requires_authorization, Address, Asset,
    AssociatedData, Authorization, AuthorizationContext, Configuration, FullParametersRef,
    Parameters, PreSender, ProofInput, ProofSystemError, ProofSystemPublicParameters,
    ProvingContext, Receiver, Sender, SpendingKey, Transfer, TransferPost, UtxoAccumulatorItem,
    UtxoAccumulatorModel, VerifyingContext,
};
use alloc::vec::Vec;
use core::{
    fmt::Debug,
    ops::{Rem, Sub},
};
use manta_crypto::{
    accumulator::Accumulator,
    rand::{CryptoRng, Rand, RngCore, Sample},
};
use manta_util::into_array_unchecked;

/// Samples a distribution over `count`-many values summing to `total`.
///
/// # Warning
///
/// This is a naive algorithm and should only be used for testing purposes.
#[inline]
pub fn value_distribution<V, R>(count: usize, total: V, rng: &mut R) -> Vec<V>
where
    V: Default + Ord + Sample,
    for<'v> &'v V: Rem<Output = V> + Sub<Output = V>,
    R: RngCore + ?Sized,
{
    if count == 0 {
        return Vec::default();
    }
    let mut result = Vec::with_capacity(count + 1);
    result.push(V::default());
    for _ in 1..count {
        result.push(&rng.gen::<_, V>() % &total);
    }
    result.push(total);
    result.sort_unstable();
    for i in 0..count {
        result[i] = &result[i + 1] - &result[i];
    }
    result
        .pop()
        .expect("There's always at least one element in this vector.");
    result
}

/// Samples asset values from `rng`.
///
/// # Warning
///
/// This is a naive algorithm and should only be used for testing purposes.
#[inline]
pub fn sample_asset_values<V, R, const N: usize>(total: V, rng: &mut R) -> [V; N]
where
    V: Default + Ord + Sample,
    for<'v> &'v V: Rem<Output = V> + Sub<Output = V>,
    R: RngCore + ?Sized,
{
    into_array_unchecked(value_distribution(N, total, rng))
}

/// Transfer Distribution
pub struct TransferDistribution<'p, C, A>
where
    C: Configuration,
    A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
{
    /// Parameters
    pub parameters: &'p Parameters<C>,

    /// UTXO Accumulator
    pub utxo_accumulator: &'p mut A,

    /// Authorization
    pub authorization: Option<Authorization<C>>,
}

impl<'p, C, A> TransferDistribution<'p, C, A>
where
    C: Configuration,
    A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
{
    /// Builds a new [`TransferDistribution`] from `parameters`, `utxo_accumulator`
    /// and `authorization`.
    #[inline]
    pub fn new(
        parameters: &'p Parameters<C>,
        utxo_accumulator: &'p mut A,
        authorization: Option<Authorization<C>>,
    ) -> Self {
        Self {
            parameters,
            utxo_accumulator,
            authorization,
        }
    }

    /// Builds a new [`TransferDistribution`] from `parameters`, `utxo_accumulator`
    /// and `spending_key`.
    #[inline]
    pub fn from_spending_key<R>(
        parameters: &'p Parameters<C>,
        utxo_accumulator: &'p mut A,
        spending_key: &SpendingKey<C>,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(
            parameters,
            utxo_accumulator,
            Some(Authorization::<C>::from_spending_key(
                parameters,
                spending_key,
                rng,
            )),
        )
    }
}

impl<'p, C, A> From<FixedTransferDistribution<'p, C, A>> for TransferDistribution<'p, C, A>
where
    C: Configuration,
    A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
{
    #[inline]
    fn from(distribution: FixedTransferDistribution<'p, C, A>) -> Self {
        distribution.base
    }
}

/// Fixed Transfer Distribution
///
/// # Note
///
/// This distribution does not check if the input sum is equal to the output sum, and lets the
/// [`Transfer`] mechanism check this itself.
pub struct FixedTransferDistribution<'p, C, A>
where
    C: Configuration,
    A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
{
    /// Base Transfer Distribution
    pub base: TransferDistribution<'p, C, A>,

    /// Asset Id for this Transfer
    pub asset_id: C::AssetId,

    /// Source Asset Value Sum
    pub source_sum: C::AssetValue,

    /// Sender Asset Value Sum
    pub sender_sum: C::AssetValue,

    /// Receiver Asset Value Sum
    pub receiver_sum: C::AssetValue,

    /// Sink Asset Value Sum
    pub sink_sum: C::AssetValue,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Generates a new [`TransferDistribution`] from `parameters`, `utxo_accumulator`, and
    /// `spending_key`.
    #[inline]
    fn generate_distribution<'s, 'p, A, R>(
        parameters: &'p Parameters<C>,
        utxo_accumulator: &'p mut A,
        spending_key: Option<&'s SpendingKey<C>>,
        rng: &mut R,
    ) -> (Option<&'s SpendingKey<C>>, TransferDistribution<'p, C, A>)
    where
        A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
        R: RngCore + ?Sized,
    {
        match (spending_key, requires_authorization(SENDERS)) {
            (Some(spending_key), true) => (
                Some(spending_key),
                TransferDistribution::<C, _>::from_spending_key(
                    parameters,
                    utxo_accumulator,
                    spending_key,
                    rng,
                ),
            ),
            (None, false) => (
                None,
                TransferDistribution::new(parameters, utxo_accumulator, None),
            ),
            _ => unreachable!("Authorization shape mismatch."),
        }
    }

    /// Samples a [`TransferPost`] from `parameters` and `utxo_accumulator` using `proving_context`
    /// and `rng`.
    #[inline]
    pub fn sample_post<A, R>(
        proving_context: &ProvingContext<C>,
        parameters: &Parameters<C>,
        utxo_accumulator: &mut A,
        spending_key: Option<&SpendingKey<C>>,
        rng: &mut R,
    ) -> Result<Option<TransferPost<C>>, ProofSystemError<C>>
    where
        A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
        for<'s> Self: Sample<TransferDistribution<'s, C, A>>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let (spending_key, distribution) =
            Self::generate_distribution(parameters, utxo_accumulator, spending_key, rng);
        Self::sample(distribution, rng).into_post(
            FullParametersRef::<C>::new(parameters, utxo_accumulator.model()),
            proving_context,
            spending_key,
            rng,
        )
    }

    /// Samples a new [`Transfer`] and builds a correctness proof for it, checking if it was
    /// validated.
    #[inline]
    pub fn sample_and_check_proof<A, R>(
        public_parameters: &ProofSystemPublicParameters<C>,
        parameters: &Parameters<C>,
        utxo_accumulator: &mut A,
        spending_key: Option<&SpendingKey<C>>,
        rng: &mut R,
    ) -> Result<bool, ProofSystemError<C>>
    where
        A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
        for<'s> Self: Sample<TransferDistribution<'s, C, A>>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let (proving_context, verifying_context) = Self::generate_context(
            public_parameters,
            FullParametersRef::<C>::new(parameters, utxo_accumulator.model()),
            rng,
        )?;
        Self::sample_and_check_proof_with_context(
            &proving_context,
            &verifying_context,
            parameters,
            utxo_accumulator,
            spending_key,
            rng,
        )
    }

    /// Samples a new [`Transfer`] and builds a correctness proof for it, checking if it was
    /// validated using the given `proving_context` and `verifying_context`.
    #[inline]
    pub fn sample_and_check_proof_with_context<A, R>(
        proving_context: &ProvingContext<C>,
        verifying_context: &VerifyingContext<C>,
        parameters: &Parameters<C>,
        utxo_accumulator: &mut A,
        spending_key: Option<&SpendingKey<C>>,
        rng: &mut R,
    ) -> Result<bool, ProofSystemError<C>>
    where
        A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
        for<'s> Self: Sample<TransferDistribution<'s, C, A>>,
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::sample_post(
            proving_context,
            parameters,
            utxo_accumulator,
            spending_key,
            rng,
        )?
        .expect("Sample post cannot return None.")
        .has_valid_proof(verifying_context)
    }

    /// Checks if `generate_proof_input` from [`Transfer`] and [`TransferPost`] gives the same
    /// [`ProofInput`].
    #[inline]
    pub fn sample_and_check_generate_proof_input_compatibility<A, R>(
        public_parameters: &ProofSystemPublicParameters<C>,
        parameters: &Parameters<C>,
        utxo_accumulator: &mut A,
        spending_key: Option<&SpendingKey<C>>,
        rng: &mut R,
    ) -> Result<bool, ProofSystemError<C>>
    where
        A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
        for<'s> Self: Sample<TransferDistribution<'s, C, A>>,
        R: CryptoRng + RngCore + ?Sized,
        ProofInput<C>: PartialEq + Debug,
        ProofSystemError<C>: Debug,
    {
        let (spending_key, distribution) =
            Self::generate_distribution(parameters, utxo_accumulator, spending_key, rng);
        let transfer = Self::sample(distribution, rng);
        let full_parameters = FullParametersRef::<C>::new(parameters, utxo_accumulator.model());
        let (proving_context, _) = Self::generate_context(public_parameters, full_parameters, rng)?;
        Ok(transfer.generate_proof_input()
            == transfer
                .into_post(full_parameters, &proving_context, spending_key, rng)?
                .expect("TransferPost should have been constructed correctly.")
                .generate_proof_input())
    }
}

/// Samples a set of [`Sender`]s and [`Receiver`]s.
#[inline]
fn sample_senders_and_receivers<C, A, R>(
    parameters: &Parameters<C>,
    mut authorization_context: Option<&mut AuthorizationContext<C>>,
    asset_id: C::AssetId,
    senders: Vec<C::AssetValue>,
    receivers: Vec<C::AssetValue>,
    utxo_accumulator: &mut A,
    rng: &mut R,
) -> (Vec<Sender<C>>, Vec<Receiver<C>>)
where
    C: Configuration,
    Address<C>: Sample,
    AssociatedData<C>: Sample,
    A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
    R: RngCore + ?Sized,
{
    let senders = match (
        authorization_context.take(),
        requires_authorization(senders.len()),
    ) {
        (Some(authorization_context), true) => senders
            .into_iter()
            .map(|v| {
                let pre_sender = PreSender::<C>::sample(
                    parameters,
                    authorization_context,
                    rng.gen(),
                    Asset::<C>::new(asset_id.clone(), v),
                    rng,
                );
                pre_sender
                    .insert_and_upgrade(parameters, utxo_accumulator)
                    .expect("Insertion and upgrading should not fail.")
            })
            .collect(),
        (None, false) => Vec::new(),
        _ => unreachable!("Badly shaped transaction."),
    };
    (
        senders,
        receivers
            .into_iter()
            .map(|v| {
                Receiver::<C>::sample(
                    parameters,
                    rng.gen(),
                    Asset::<C>::new(asset_id.clone(), v),
                    rng.gen(),
                    rng,
                )
            })
            .collect(),
    )
}

impl<
        C,
        A,
        const SOURCES: usize,
        const SENDERS: usize,
        const RECEIVERS: usize,
        const SINKS: usize,
    > Sample<TransferDistribution<'_, C, A>> for Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
    C::AssetId: Sample,
    C::AssetValue: Default + Ord + Sample,
    for<'v> &'v C::AssetValue: Rem<Output = C::AssetValue> + Sub<Output = C::AssetValue>,
    Address<C>: Sample,
    AssociatedData<C>: Sample,
    A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
{
    #[inline]
    fn sample<R>(mut distribution: TransferDistribution<'_, C, A>, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let authorization_context = distribution.authorization.as_mut().map(|k| &mut k.context);
        let asset = Asset::<C>::gen(rng);
        let mut input = value_distribution(SOURCES + SENDERS, asset.value.clone(), rng);
        let mut output = value_distribution(RECEIVERS + SINKS, asset.value, rng);
        let secret_input = input.split_off(SOURCES);
        let public_output = output.split_off(RECEIVERS);
        let (senders, receivers) = sample_senders_and_receivers::<C, _, _>(
            distribution.parameters,
            authorization_context,
            asset.id.clone(),
            secret_input,
            output,
            distribution.utxo_accumulator,
            rng,
        );
        Self::new(
            requires_authorization(SENDERS).then(|| {
                distribution
                    .authorization
                    .expect("The authorization exists whenever we require authorization.")
            }),
            has_public_participants(SOURCES, SINKS).then_some(asset.id),
            into_array_unchecked(input),
            into_array_unchecked(senders),
            into_array_unchecked(receivers),
            into_array_unchecked(public_output),
        )
    }
}

impl<
        C,
        A,
        const SOURCES: usize,
        const SENDERS: usize,
        const RECEIVERS: usize,
        const SINKS: usize,
    > Sample<FixedTransferDistribution<'_, C, A>>
    for Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
    C::AssetId: Sample,
    C::AssetValue: Default + Ord + Sample,
    for<'v> &'v C::AssetValue: Rem<Output = C::AssetValue> + Sub<Output = C::AssetValue>,
    Address<C>: Sample,
    AssociatedData<C>: Sample,
    A: Accumulator<Item = UtxoAccumulatorItem<C>, Model = UtxoAccumulatorModel<C>>,
{
    #[inline]
    fn sample<R>(mut distribution: FixedTransferDistribution<'_, C, A>, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let authorization_context = distribution
            .base
            .authorization
            .as_mut()
            .map(|k| &mut k.context);
        let (senders, receivers) = sample_senders_and_receivers::<C, _, _>(
            distribution.base.parameters,
            authorization_context,
            distribution.asset_id.clone(),
            value_distribution(SENDERS, distribution.sender_sum, rng),
            value_distribution(RECEIVERS, distribution.receiver_sum, rng),
            distribution.base.utxo_accumulator,
            rng,
        );
        Self::new(
            requires_authorization(SENDERS).then(|| {
                distribution
                    .base
                    .authorization
                    .expect("The authorization proof exists whenever we require authorization.")
            }),
            has_public_participants(SOURCES, SINKS).then_some(distribution.asset_id),
            sample_asset_values(distribution.source_sum, rng),
            into_array_unchecked(senders),
            into_array_unchecked(receivers),
            sample_asset_values(distribution.sink_sum, rng),
        )
    }
}

/// Samples a [`ToPrivate`] transfers and returns the corresponding [`TransferPost`]
/// and [`PreSender`].
#[inline]
pub fn sample_to_private<C, R>(
    parameters: FullParametersRef<C>,
    proving_context: &ProvingContext<C>,
    authorization_context: &mut AuthorizationContext<C>,
    address: Address<C>,
    asset: Asset<C>,
    associated_data: AssociatedData<C>,
    rng: &mut R,
) -> Result<(TransferPost<C>, PreSender<C>), ProofSystemError<C>>
where
    C: Configuration,
    R: CryptoRng + RngCore + ?Sized,
{
    let (transaction, pre_sender) = ToPrivate::internal_pair(
        parameters.base,
        authorization_context,
        address,
        asset,
        associated_data,
        rng,
    );
    Ok((
        transaction
            .into_post(parameters, proving_context, None, rng)?
            .expect("The `ToPrivate` transaction does not require authorization."),
        pre_sender,
    ))
}
