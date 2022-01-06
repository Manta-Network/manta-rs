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

//! Transfer Protocol Testing Framework

use crate::{
    asset::{Asset, AssetId, AssetValue, AssetValueType},
    transfer::{
        has_public_participants, Configuration, FullParameters, Parameters, ProofSystemError,
        Receiver, Sender, Transfer, Utxo,
    },
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use manta_crypto::{
    accumulator::Accumulator,
    constraint::ProofSystem,
    rand::{CryptoRng, Rand, RngCore, Sample, Standard},
};
use manta_util::into_array_unchecked;

/// Samples a distribution over `count`-many values summing to `total`.
///
/// # Warning
///
/// This is a naive algorithm and should only be used for testing purposes.
#[inline]
pub fn value_distribution<R>(count: usize, total: AssetValue, rng: &mut R) -> Vec<AssetValue>
where
    R: CryptoRng + RngCore + ?Sized,
{
    if count == 0 {
        return Default::default();
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
    R: CryptoRng + RngCore + ?Sized,
{
    into_array_unchecked(value_distribution(N, total, rng))
}

/// Parameters Distribution
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParametersDistribution<K = Standard, U = Standard, V = Standard> {
    /// Key Agreement Scheme Distribution
    pub key_agreement: K,

    /// UTXO Commitment Scheme Distribution
    pub utxo_commitment: U,

    /// Void Number Hash Function Distribution
    pub void_number_hash: V,
}

impl<K, U, V, C> Sample<ParametersDistribution<K, U, V>> for Parameters<C>
where
    C: Configuration,
    C::KeyAgreementScheme: Sample<K>,
    C::UtxoCommitmentScheme: Sample<U>,
    C::VoidNumberHashFunction: Sample<V>,
{
    #[inline]
    fn sample<R>(distribution: ParametersDistribution<K, U, V>, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Parameters::new(
            rng.sample(distribution.key_agreement),
            rng.sample(distribution.utxo_commitment),
            rng.sample(distribution.void_number_hash),
        )
    }
}

///
pub struct TransferDistribution<C>
where
    C: Configuration,
{
    ///
    __: PhantomData<C>,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    ///
    #[inline]
    pub fn sample_and_check_proof<A, R>(
        parameters: &Parameters<C>,
        utxo_set: A,
        rng: &mut R,
    ) -> Result<bool, ProofSystemError<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoSetModel>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let full_parameters = FullParameters::new(parameters, utxo_set.model());
        let (proving_context, verifying_context) = Self::generate_context(full_parameters, rng)?;
        let post = Self::sample(TransferDistribution { __: PhantomData }, rng).into_post(
            full_parameters,
            &proving_context,
            rng,
        )?;
        C::ProofSystem::verify(
            &post.generate_proof_input(),
            &post.validity_proof,
            &verifying_context,
        )
    }
}

///
#[inline]
fn sample_senders_and_receivers<C>(
    senders: &[AssetValue],
    receivers: &[AssetValue],
) -> (Vec<Sender<C>>, Vec<Receiver<C>>)
where
    C: Configuration,
{
    todo!()
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Sample<TransferDistribution<C>> for Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    #[inline]
    fn sample<R>(distribution: TransferDistribution<C>, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset: Asset = rng.gen();

        let mut input = value_distribution(SOURCES + SENDERS, asset.value, rng);
        let mut output = value_distribution(RECEIVERS + SINKS, asset.value, rng);
        let secret_input = input.split_off(SOURCES);
        let public_output = output.split_off(RECEIVERS);

        let (senders, receivers) = sample_senders_and_receivers(&secret_input, &output);

        Self::new(
            has_public_participants(SOURCES, SENDERS, RECEIVERS, SINKS).then(|| asset.id),
            into_array_unchecked(input),
            into_array_unchecked(senders),
            into_array_unchecked(receivers),
            into_array_unchecked(public_output),
        )

        /*
        Ok(Self {
            public: PublicTransfer::new(
                asset.id,
                into_array_unchecked(input),
                into_array_unchecked(public_output),
            ),
            secret: distribution::FixedSecretTransfer::try_sample_custom_distribution(
                asset.id,
                into_array_unchecked(secret_input),
                into_array_unchecked(output),
                distribution.base.commitment_scheme,
                distribution.base.utxo_set,
                rng,
            )?,
        })
        */
    }
}
