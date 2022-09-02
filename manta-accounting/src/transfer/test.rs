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

use crate::{
    asset::{Asset, AssetId, AssetValue, AssetValueType},
    transfer::{
        canonical::Mint, has_public_participants, Configuration, FullParameters, Parameters,
        PreSender, Proof, ProofSystemError, ProofSystemPublicParameters, ProvingContext, Receiver,
        Sender, SpendingKey, Transfer, TransferPost, Utxo, VerifyingContext,
    },
};
use alloc::vec::Vec;
use core::fmt::Debug;
use manta_crypto::{
    accumulator::Accumulator,
    constraint::ProofSystem,
    rand::{CryptoRng, Rand, RngCore, Sample},
};
use manta_util::into_array_unchecked;

use super::ProofInput;

/// Samples a distribution over `count`-many values summing to `total`.
///
/// # Warning
///
/// This is a naive algorithm and should only be used for testing purposes.
#[inline]
pub fn value_distribution<R>(count: usize, total: AssetValue, rng: &mut R) -> Vec<AssetValue>
where
    R: RngCore + ?Sized,
{
    if count == 0 {
        return Vec::default();
    }
    let mut result = Vec::with_capacity(count + 1);
    result.push(AssetValue(0));
    for _ in 1..count {
        result.push(AssetValue(AssetValueType::gen(rng) % total.0));
    }
    result.push(total);
    result.sort_unstable();
    for i in 0..count {
        result[i] = result[i + 1] - result[i];
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
pub fn sample_asset_values<R, const N: usize>(total: AssetValue, rng: &mut R) -> [AssetValue; N]
where
    R: RngCore + ?Sized,
{
    into_array_unchecked(value_distribution(N, total, rng))
}

/// Parameters Distribution
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParametersDistribution<K = (), E = (), U = (), V = ()> {
    /// Key Agreement Scheme Distribution
    pub key_agreement_scheme: K,

    /// Note Encryption Scheme Distribution
    pub note_encryption_scheme: E,

    /// UTXO Commitment Scheme Distribution
    pub utxo_commitment: U,

    /// Void Number Commitment Scheme Distribution
    pub void_number_commitment_scheme: V,
}

impl<K, E, U, V, C> Sample<ParametersDistribution<K, E, U, V>> for Parameters<C>
where
    C: Configuration,
    C::KeyAgreementScheme: Sample<K>,
    C::NoteEncryptionScheme: Sample<E>,
    C::UtxoCommitmentScheme: Sample<U>,
    C::VoidNumberCommitmentScheme: Sample<V>,
{
    #[inline]
    fn sample<R>(distribution: ParametersDistribution<K, E, U, V>, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Parameters::new(
            rng.sample(distribution.key_agreement_scheme),
            rng.sample(distribution.note_encryption_scheme),
            rng.sample(distribution.utxo_commitment),
            rng.sample(distribution.void_number_commitment_scheme),
        )
    }
}

/// Transfer Distribution
pub struct TransferDistribution<'p, C, A>
where
    C: Configuration,
    A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
{
    /// Parameters
    pub parameters: &'p Parameters<C>,

    /// UTXO Accumulator
    pub utxo_accumulator: &'p mut A,
}

impl<'p, C, A> From<FixedTransferDistribution<'p, C, A>> for TransferDistribution<'p, C, A>
where
    C: Configuration,
    A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
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
    A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
{
    /// Base Transfer Distribution
    pub base: TransferDistribution<'p, C, A>,

    /// Asset Id for this Transfer
    pub asset_id: AssetId,

    /// Source Asset Value Sum
    pub source_sum: AssetValue,

    /// Sender Asset Value Sum
    pub sender_sum: AssetValue,

    /// Receiver Asset Value Sum
    pub receiver_sum: AssetValue,

    /// Sink Asset Value Sum
    pub sink_sum: AssetValue,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Samples a [`TransferPost`] from `parameters` and `utxo_accumulator` using `proving_context`
    /// and `rng`.
    #[inline]
    pub fn sample_post<A, R>(
        proving_context: &ProvingContext<C>,
        parameters: &Parameters<C>,
        utxo_accumulator: &mut A,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::sample(
            TransferDistribution {
                parameters,
                utxo_accumulator,
            },
            rng,
        )
        .into_post(
            FullParameters::new(parameters, utxo_accumulator.model()),
            proving_context,
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
        rng: &mut R,
    ) -> Result<bool, ProofSystemError<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let (proving_context, verifying_context) = Self::generate_context(
            public_parameters,
            FullParameters::new(parameters, utxo_accumulator.model()),
            rng,
        )?;
        Self::sample_and_check_proof_with_context(
            &proving_context,
            &verifying_context,
            parameters,
            utxo_accumulator,
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
        rng: &mut R,
    ) -> Result<bool, ProofSystemError<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let post = Self::sample_post(proving_context, parameters, utxo_accumulator, rng)?;
        C::ProofSystem::verify(
            verifying_context,
            &post.generate_proof_input(),
            &post.validity_proof,
        )
    }

    /// Checks if `generate_proof_input` from [`Transfer`] and [`TransferPost`] gives the same [`ProofInput`].
    #[inline]
    pub fn sample_and_check_generate_proof_input_compatibility<A, R>(
        public_parameters: &ProofSystemPublicParameters<C>,
        parameters: &Parameters<C>,
        utxo_accumulator: &mut A,
        rng: &mut R,
    ) -> Result<bool, ProofSystemError<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
        R: CryptoRng + RngCore + ?Sized,
        ProofInput<C>: PartialEq,
        ProofSystemError<C>: Debug,
    {
        let transfer = Self::sample(
            TransferDistribution {
                parameters,
                utxo_accumulator,
            },
            rng,
        );
        let full_parameters = FullParameters::new(parameters, utxo_accumulator.model());
        let (proving_context, _) = Self::generate_context(public_parameters, full_parameters, rng)?;
        Ok(transfer.generate_proof_input()
            == transfer
                .into_post(full_parameters, &proving_context, rng)?
                .generate_proof_input())
    }
}

impl<C> TransferPost<C>
where
    C: Configuration,
{
    /// Asserts that `self` contains a valid proof according to the `verifying_context`, returning a
    /// reference to the proof.
    #[inline]
    pub fn assert_valid_proof(&self, verifying_context: &VerifyingContext<C>) -> &Proof<C>
    where
        ProofSystemError<C>: Debug,
    {
        assert!(
            self.has_valid_proof(verifying_context)
                .expect("Unable to verify proof."),
            "The proof should have been valid."
        );
        &self.validity_proof
    }
}

/// Samples a set of senders and receivers.
#[inline]
fn sample_senders_and_receivers<C, A, R>(
    parameters: &Parameters<C>,
    asset_id: AssetId,
    senders: &[AssetValue],
    receivers: &[AssetValue],
    utxo_accumulator: &mut A,
    rng: &mut R,
) -> (Vec<Sender<C>>, Vec<Receiver<C>>)
where
    C: Configuration,
    A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    R: RngCore + ?Sized,
{
    (
        senders
            .iter()
            .map(|v| {
                let sender = PreSender::new(parameters, rng.gen(), rng.gen(), asset_id.with(*v));
                sender.insert_utxo(utxo_accumulator);
                sender.try_upgrade(utxo_accumulator).unwrap()
            })
            .collect(),
        receivers
            .iter()
            .map(|v| {
                Receiver::new(
                    parameters,
                    parameters.derive(&rng.gen()),
                    parameters.derive(&rng.gen()),
                    rng.gen(),
                    asset_id.with(*v),
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
    A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
{
    #[inline]
    fn sample<R>(distribution: TransferDistribution<'_, C, A>, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let asset = Asset::gen(rng);
        let mut input = value_distribution(SOURCES + SENDERS, asset.value, rng);
        let mut output = value_distribution(RECEIVERS + SINKS, asset.value, rng);
        let secret_input = input.split_off(SOURCES);
        let public_output = output.split_off(RECEIVERS);
        let (senders, receivers) = sample_senders_and_receivers(
            distribution.parameters,
            asset.id,
            &secret_input,
            &output,
            distribution.utxo_accumulator,
            rng,
        );
        Self::new(
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
    A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
{
    #[inline]
    fn sample<R>(distribution: FixedTransferDistribution<'_, C, A>, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let (senders, receivers) = sample_senders_and_receivers(
            distribution.base.parameters,
            distribution.asset_id,
            &value_distribution(SENDERS, distribution.sender_sum, rng),
            &value_distribution(RECEIVERS, distribution.receiver_sum, rng),
            distribution.base.utxo_accumulator,
            rng,
        );
        Self::new(
            has_public_participants(SOURCES, SINKS).then_some(distribution.asset_id),
            sample_asset_values(distribution.source_sum, rng),
            into_array_unchecked(senders),
            into_array_unchecked(receivers),
            sample_asset_values(distribution.sink_sum, rng),
        )
    }
}

/// Samples a [`Mint`] transaction against `spending_key` and `asset` returning a [`TransferPost`]
/// and [`PreSender`].
#[inline]
pub fn sample_mint<C, R>(
    proving_context: &ProvingContext<C>,
    full_parameters: FullParameters<C>,
    spending_key: &SpendingKey<C>,
    asset: Asset,
    rng: &mut R,
) -> Result<(TransferPost<C>, PreSender<C>), ProofSystemError<C>>
where
    C: Configuration,
    R: CryptoRng + RngCore + ?Sized,
{
    let (mint, pre_sender) = Mint::internal_pair(full_parameters.base, spending_key, asset, rng);
    Ok((
        mint.into_post(full_parameters, proving_context, rng)?,
        pre_sender,
    ))
}

/// Asserts that `post` represents a valid `Transfer` verifying against `verifying_context`.
#[inline]
pub fn assert_valid_proof<C>(verifying_context: &VerifyingContext<C>, post: &TransferPost<C>)
where
    C: Configuration,
    <C::ProofSystem as ProofSystem>::Error: Debug,
    TransferPost<C>: Debug,
{
    assert!(
        C::ProofSystem::verify(
            verifying_context,
            &post.generate_proof_input(),
            &post.validity_proof,
        )
        .expect("Unable to verify proof."),
        "Invalid proof: {:?}.",
        post,
    );
}
