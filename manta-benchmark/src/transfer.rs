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

//! Transfer Benchmarking Suite

use manta_crypto::rand::{OsRng, Rand};
use manta_pay::{
    config::{self, MultiProvingContext, MultiVerifyingContext, Parameters, UtxoAccumulatorModel},
    parameters,
    test::payment::{
        private_transfer::prove_full as prove_private_transfer_full,
        to_private::prove_full as prove_to_private_full,
        to_public::prove_full as prove_to_public_full, UtxoAccumulator,
    },
};
use wasm_bindgen::prelude::wasm_bindgen;

/// Context Type
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Context {
    /// Proving Context
    proving_context: MultiProvingContext,

    /// Verifying Context
    verifying_context: MultiVerifyingContext,

    /// Parameters
    parameters: Parameters,

    /// Utxo Accumulator Model
    utxo_accumulator_model: UtxoAccumulatorModel,
}

#[wasm_bindgen]
impl Context {
    /// Constructs a new [`Context`] which can be used for proving and verifying [`TransferPost`].
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
            parameters::generate().expect("Unable to generate default parameters.");
        Self {
            proving_context,
            verifying_context,
            parameters,
            utxo_accumulator_model,
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// TransferPost
#[wasm_bindgen]
pub struct TransferPost(config::TransferPost);

/// Generates a to_private [`TransferPost`] given the [`Context`].
#[wasm_bindgen]
pub fn prove_to_private(context: &Context) -> TransferPost {
    let mut rng = OsRng;
    TransferPost(prove_to_private_full(
        &context.proving_context.to_private,
        &context.parameters,
        &mut UtxoAccumulator::new(context.utxo_accumulator_model.clone()),
        rng.gen(),
        rng.gen(),
        &mut rng,
    ))
}

/// Generates a private transfer [`TransferPost`] given the [`Context`].
#[wasm_bindgen]
pub fn prove_private_transfer(context: &Context) -> TransferPost {
    let mut rng = OsRng;
    TransferPost(
        prove_private_transfer_full(
            &context.proving_context,
            &context.parameters,
            &mut UtxoAccumulator::new(context.utxo_accumulator_model.clone()),
            rng.gen(),
            [rng.gen::<_, u128>() / 2, rng.gen::<_, u128>() / 2],
            &mut rng,
        )
        .1,
    )
}

/// Generates a to_public [`TransferPost`] given the [`Context`].
#[wasm_bindgen]
pub fn prove_to_public(context: &Context) -> TransferPost {
    let mut rng = OsRng;
    TransferPost(
        prove_to_public_full(
            &context.proving_context,
            &context.parameters,
            &mut UtxoAccumulator::new(context.utxo_accumulator_model.clone()),
            rng.gen(),
            [rng.gen::<_, u128>() / 2, rng.gen::<_, u128>() / 2],
            &mut rng,
        )
        .1,
    )
}

/// Verifies a to_private [`TransferPost`] given the [`Context`].
#[wasm_bindgen]
pub fn verify_to_private(context: &Context, transferpost: &TransferPost) {
    transferpost
        .0
        .assert_valid_proof(&context.verifying_context.to_private);
}

/// Verifies a private transfer [`TransferPost`] given the [`Context`].
#[wasm_bindgen]
pub fn verify_private_transfer(context: &Context, transferpost: &TransferPost) {
    transferpost
        .0
        .assert_valid_proof(&context.verifying_context.private_transfer);
}

/// Verifies a to_public [`TransferPost`] given the [`Context`].
#[wasm_bindgen]
pub fn verify_to_public(context: &Context, transferpost: &TransferPost) {
    transferpost
        .0
        .assert_valid_proof(&context.verifying_context.to_public);
}
