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

//! Prove and Verify Functions for Benchmark and Test Purposes

use crate::config::{
    self, utxo::v1::UtxoAccumulatorModel, Asset, AssetId, AuthorizationContext, FullParametersRef,
    Parameters, PrivateTransfer, ProvingContext, Receiver, Sender, ToPrivate, ToPublic,
    TransferPost,
};
use manta_accounting::transfer::{self, test::value_distribution, Authorization};
use manta_crypto::rand::{CryptoRng, Rand, RngCore, Sample};

/// Builds a new internal pair for use in [`private_transfer::prove`] and [`to_public::prove`].
#[inline]
pub fn internal_pair<R>(
    parameters: &Parameters,
    authorization_context: &mut AuthorizationContext,
    asset: Asset,
    rng: &mut R,
) -> (Receiver, Sender)
where
    R: CryptoRng + RngCore + ?Sized,
{
    let (receiver, pre_sender) = transfer::internal_pair::<config::Config, _>(
        parameters,
        authorization_context,
        rng.gen(),
        asset,
        Default::default(),
        rng,
    );
    (receiver, pre_sender.assign_default_proof_unchecked())
}

/// Utility Module for [`ToPrivate`]
pub mod to_private {
    use super::*;

    /// Generates a proof for a [`ToPrivate`] transaction.
    #[inline]
    pub fn prove<R>(
        proving_context: &ProvingContext,
        parameters: &Parameters,
        utxo_accumulator_model: &UtxoAccumulatorModel,
        rng: &mut R,
    ) -> TransferPost
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        ToPrivate::from_address(parameters, rng.gen(), rng.gen(), Default::default(), rng)
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator_model),
                proving_context,
                None,
                rng,
            )
            .expect("")
            .expect("")
    }
}

/// Utility Module for [`PrivateTransfer`]
pub mod private_transfer {
    use super::*;

    /// Generates a proof for a [`PrivateTransfer`] transaction.
    #[inline]
    pub fn prove<R>(
        proving_context: &ProvingContext,
        parameters: &Parameters,
        utxo_accumulator_model: &UtxoAccumulatorModel,
        rng: &mut R,
    ) -> TransferPost
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset_id = AssetId::gen(rng);
        let values = value_distribution(2, rng.gen(), rng);
        let spending_key = rng.gen();
        let mut authorization =
            Authorization::<config::Config>::from_spending_key(parameters, &spending_key, rng);
        let (receiver_0, sender_0) = internal_pair(
            parameters,
            &mut authorization.context,
            Asset::new(asset_id, values[0]),
            rng,
        );
        let (receiver_1, sender_1) = internal_pair(
            parameters,
            &mut authorization.context,
            Asset::new(asset_id, values[1]),
            rng,
        );
        PrivateTransfer::build(
            authorization,
            [sender_0, sender_1],
            [receiver_1, receiver_0],
        )
        .into_post(
            FullParametersRef::new(parameters, utxo_accumulator_model),
            proving_context,
            Some(&spending_key),
            rng,
        )
        .expect("Unable to build PRIVATE_TRANSFER proof.")
        .expect("")
    }
}

/// Utility Module for [`ToPublic`]
pub mod to_public {
    use super::*;

    /// Generates a proof for a [`ToPublic`] transaction.
    #[inline]
    pub fn prove<R>(
        proving_context: &ProvingContext,
        parameters: &Parameters,
        utxo_accumulator_model: &UtxoAccumulatorModel,
        rng: &mut R,
    ) -> TransferPost
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset_id = AssetId::gen(rng);
        let values = value_distribution(2, rng.gen(), rng);
        let asset_0 = Asset::new(asset_id, values[0]);
        let spending_key = rng.gen();
        let mut authorization =
            Authorization::<config::Config>::from_spending_key(parameters, &spending_key, rng);
        let (_, sender_0) = internal_pair(parameters, &mut authorization.context, asset_0, rng);
        let (receiver_1, sender_1) = internal_pair(
            parameters,
            &mut authorization.context,
            Asset::new(asset_id, values[1]),
            rng,
        );
        ToPublic::build(authorization, [sender_0, sender_1], [receiver_1], asset_0)
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator_model),
                proving_context,
                Some(&spending_key),
                rng,
            )
            .expect("Unable to build TO_PUBLIC proof.")
            .expect("")
    }
}
