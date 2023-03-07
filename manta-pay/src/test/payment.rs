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
    utxo::{MerkleTreeConfiguration, UtxoAccumulatorItem, UtxoAccumulatorModel},
    AccountId, Asset, AssetId, AssetValue, Authorization, Config, FullParametersRef,
    MultiProvingContext, Parameters, PrivateTransfer, ProvingContext, Receiver, ToPrivate,
    ToPublic, TransferPost,
};
use alloc::vec::Vec;
use manta_accounting::transfer::{self, internal_pair, test::value_distribution};
use manta_crypto::{
    accumulator::Accumulator,
    merkle_tree::{forest::TreeArrayMerkleForest, full::Full},
    rand::{CryptoRng, Rand, RngCore, Sample},
};

/// Spending Key Type
pub type SpendingKey = transfer::SpendingKey<Config>;

/// UTXO Accumulator for Building Test Circuits
pub type UtxoAccumulator =
    TreeArrayMerkleForest<MerkleTreeConfiguration, Full<MerkleTreeConfiguration>, 256>;

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
        let asset_0 = Asset::new(rng.gen(), rng.gen());
        let spending_key = rng.gen();
        let address = parameters.address_from_spending_key(&spending_key);
        let mut authorization = Authorization::from_spending_key(parameters, &spending_key, rng);
        let (to_private_0, _pre_sender_0) = ToPrivate::internal_pair(
            parameters,
            &mut authorization.context,
            address,
            asset_0,
            Default::default(),
            rng,
        );
        to_private_0
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator_model),
                proving_context,
                None,
                Vec::new(),
                rng,
            )
            .expect("Unable to build TO_PRIVATE proof.")
            .expect("Did not match transfer shape.")
    }

    /// Generates a proof for a [`ToPrivate`] transaction with custom `asset` as input.
    #[inline]
    pub fn prove_full<A, R>(
        proving_context: &ProvingContext,
        parameters: &Parameters,
        utxo_accumulator: &mut A,
        asset_id: AssetId,
        value: AssetValue,
        rng: &mut R,
    ) -> TransferPost
    where
        A: Accumulator<Item = UtxoAccumulatorItem, Model = UtxoAccumulatorModel>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset_0 = Asset::new(asset_id, value);
        let spending_key = rng.gen();
        let address = parameters.address_from_spending_key(&spending_key);
        let mut authorization = Authorization::from_spending_key(parameters, &spending_key, rng);

        let (to_private_0, pre_sender_0) = ToPrivate::internal_pair(
            parameters,
            &mut authorization.context,
            address,
            asset_0,
            Default::default(),
            rng,
        );
        let _ = pre_sender_0
            .insert_and_upgrade(parameters, utxo_accumulator)
            .expect("");
        to_private_0
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator.model()),
                proving_context,
                None,
                Vec::new(),
                rng,
            )
            .expect("Unable to build TO_PRIVATE proof.")
            .expect("Did not match transfer shape.")
    }
}

/// Utility Module for [`PrivateTransfer`]
pub mod private_transfer {
    use super::*;

    /// Generates a proof for a [`PrivateTransfer`] transaction including pre-requisite
    /// [`ToPrivate`] transactions.
    #[inline]
    pub fn prove_full<A, R>(
        proving_context: &MultiProvingContext,
        parameters: &Parameters,
        utxo_accumulator: &mut A,
        asset_id: AssetId,
        values: [AssetValue; 2],
        rng: &mut R,
    ) -> ([TransferPost; 2], TransferPost)
    where
        A: Accumulator<Item = UtxoAccumulatorItem, Model = UtxoAccumulatorModel>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset_0 = Asset::new(asset_id, values[0]);
        let asset_1 = Asset::new(asset_id, values[1]);
        let spending_key = rng.gen();
        let address = parameters.address_from_spending_key(&spending_key);
        let mut authorization = Authorization::from_spending_key(parameters, &spending_key, rng);

        let (to_private_0, pre_sender_0) = ToPrivate::internal_pair(
            parameters,
            &mut authorization.context,
            address,
            asset_0,
            Default::default(),
            rng,
        );
        let to_private_0 = to_private_0
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator.model()),
                &proving_context.to_private,
                None,
                Vec::new(),
                rng,
            )
            .expect("Unable to build TO_PRIVATE proof.")
            .expect("Did not match transfer shape.");
        let sender_0 = pre_sender_0
            .insert_and_upgrade(parameters, utxo_accumulator)
            .expect("");
        let receiver_0 = Receiver::sample(parameters, address, asset_0, Default::default(), rng);

        let (to_private_1, pre_sender_1) = ToPrivate::internal_pair(
            parameters,
            &mut authorization.context,
            address,
            asset_1,
            Default::default(),
            rng,
        );
        let to_private_1 = to_private_1
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator.model()),
                &proving_context.to_private,
                None,
                Vec::new(),
                rng,
            )
            .expect("Unable to build TO_PRIVATE proof.")
            .expect("Did not match transfer shape.");
        let sender_1 = pre_sender_1
            .insert_and_upgrade(parameters, utxo_accumulator)
            .expect("");
        let receiver_1 = Receiver::sample(parameters, address, asset_1, Default::default(), rng);

        receiver_1.insert_utxo(parameters, utxo_accumulator);
        receiver_0.insert_utxo(parameters, utxo_accumulator);

        let private_transfer = PrivateTransfer::build(
            authorization,
            [sender_0, sender_1],
            [receiver_1, receiver_0],
        )
        .into_post(
            FullParametersRef::new(parameters, utxo_accumulator.model()),
            &proving_context.private_transfer,
            Some(&spending_key),
            Vec::new(),
            rng,
        )
        .expect("Unable to build PRIVATE_TRANSFER proof.")
        .expect("Did not match transfer shape.");

        ([to_private_0, to_private_1], private_transfer)
    }

    /// Generates a proof for a [`PrivateTransfer`] transaction.
    #[inline]
    pub fn prove<A, R>(
        proving_context: &ProvingContext,
        parameters: &Parameters,
        utxo_accumulator: &mut A,
        rng: &mut R,
    ) -> TransferPost
    where
        A: Accumulator<Item = UtxoAccumulatorItem, Model = UtxoAccumulatorModel>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset_id = AssetId::gen(rng);
        let values = value_distribution(2, rng.gen(), rng);
        let spending_key = rng.gen();
        let address = parameters.address_from_spending_key(&spending_key);
        let mut authorization = Authorization::from_spending_key(parameters, &spending_key, rng);
        let (receiver_0, presender_0) = internal_pair::<Config, _>(
            parameters,
            &mut authorization.context,
            address,
            Asset::new(asset_id, values[0]),
            Default::default(),
            rng,
        );
        let sender_0 = presender_0
            .insert_and_upgrade(parameters, utxo_accumulator)
            .expect("");
        let (receiver_1, presender_1) = internal_pair::<Config, _>(
            parameters,
            &mut authorization.context,
            address,
            Asset::new(asset_id, values[1]),
            Default::default(),
            rng,
        );
        let sender_1 = presender_1
            .insert_and_upgrade(parameters, utxo_accumulator)
            .expect("");
        PrivateTransfer::build(
            authorization,
            [sender_0, sender_1],
            [receiver_1, receiver_0],
        )
        .into_post(
            FullParametersRef::new(parameters, utxo_accumulator.model()),
            proving_context,
            Some(&spending_key),
            Vec::new(),
            rng,
        )
        .expect("Unable to build PRIVATE_TRANSFER proof.")
        .expect("")
    }
}

/// Utility Module for [`ToPublic`]
pub mod to_public {
    use super::*;

    /// Generates a proof for a [`ToPublic`] transaction including pre-requisite [`ToPrivate`]
    /// transactions.
    #[inline]
    pub fn prove_full<A, R>(
        proving_context: &MultiProvingContext,
        parameters: &Parameters,
        utxo_accumulator: &mut A,
        asset_id: AssetId,
        values: [AssetValue; 2],
        public_account: AccountId,
        rng: &mut R,
    ) -> ([TransferPost; 2], TransferPost)
    where
        A: Accumulator<Item = UtxoAccumulatorItem, Model = UtxoAccumulatorModel>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset_0 = Asset::new(asset_id, values[0]);
        let asset_1 = Asset::new(asset_id, values[1]);
        let spending_key = rng.gen();
        let address = parameters.address_from_spending_key(&spending_key);
        let mut authorization = Authorization::from_spending_key(parameters, &spending_key, rng);

        let (to_private_0, pre_sender_0) = ToPrivate::internal_pair(
            parameters,
            &mut authorization.context,
            address,
            asset_0,
            Default::default(),
            rng,
        );
        let to_private_0 = to_private_0
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator.model()),
                &proving_context.to_private,
                None,
                Vec::new(),
                rng,
            )
            .expect("Unable to build TO_PRIVATE proof.")
            .expect("Did not match transfer shape.");
        let sender_0 = pre_sender_0
            .insert_and_upgrade(parameters, utxo_accumulator)
            .expect("");

        let (to_private_1, pre_sender_1) = ToPrivate::internal_pair(
            parameters,
            &mut authorization.context,
            address,
            asset_1,
            Default::default(),
            rng,
        );
        let to_private_1 = to_private_1
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator.model()),
                &proving_context.to_private,
                None,
                Vec::new(),
                rng,
            )
            .expect("Unable to build TO_PRIVATE proof.")
            .expect("Did not match transfer shape.");
        let sender_1 = pre_sender_1
            .insert_and_upgrade(parameters, utxo_accumulator)
            .expect("");
        let receiver_1 = Receiver::sample(parameters, address, asset_0, Default::default(), rng);
        receiver_1.insert_utxo(parameters, utxo_accumulator);

        let to_public = ToPublic::build(authorization, [sender_0, sender_1], [receiver_1], asset_1)
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator.model()),
                &proving_context.to_public,
                Some(&spending_key),
                Vec::from([public_account]),
                rng,
            )
            .expect("Unable to build TO_PUBLIC proof.")
            .expect("Did not match transfer shape.");

        ([to_private_0, to_private_1], to_public)
    }

    /// Generates a proof for a [`ToPublic`] transaction.
    #[inline]
    pub fn prove<A, R>(
        proving_context: &ProvingContext,
        parameters: &Parameters,
        utxo_accumulator: &mut A,
        public_account: AccountId,
        rng: &mut R,
    ) -> TransferPost
    where
        A: Accumulator<Item = UtxoAccumulatorItem, Model = UtxoAccumulatorModel>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let asset_id = AssetId::gen(rng);
        let values = value_distribution(2, rng.gen(), rng);
        let asset_0 = Asset::new(asset_id, values[0]);
        let spending_key = rng.gen();
        let address = parameters.address_from_spending_key(&spending_key);
        let mut authorization = Authorization::from_spending_key(parameters, &spending_key, rng);
        let (_, presender_0) = internal_pair::<Config, _>(
            parameters,
            &mut authorization.context,
            address,
            asset_0,
            Default::default(),
            rng,
        );
        let sender_0 = presender_0
            .insert_and_upgrade(parameters, utxo_accumulator)
            .expect("");
        let (receiver_1, presender_1) = internal_pair::<Config, _>(
            parameters,
            &mut authorization.context,
            address,
            Asset::new(asset_id, values[1]),
            Default::default(),
            rng,
        );
        let sender_1 = presender_1
            .insert_and_upgrade(parameters, utxo_accumulator)
            .expect("");
        ToPublic::build(authorization, [sender_0, sender_1], [receiver_1], asset_0)
            .into_post(
                FullParametersRef::new(parameters, utxo_accumulator.model()),
                proving_context,
                Some(&spending_key),
                Vec::from([public_account]),
                rng,
            )
            .expect("Unable to build TO_PUBLIC proof.")
            .expect("")
    }
}
