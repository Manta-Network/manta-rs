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

use manta_crypto::rand::OsRng;
use manta_pay::{
    config::{self, MultiProvingContext, MultiVerifyingContext, Parameters, UtxoAccumulatorModel},
    parameters,
    //test::payment,
};
use wasm_bindgen::prelude::wasm_bindgen;

/// Context Type
#[derive(Clone, Debug)]
#[wasm_bindgen]
pub struct Context {
    /// Proving Contexts
    proving_context: MultiProvingContext,

    /// Verifying Contexts
    verifying_context: MultiVerifyingContext,

    /// Parameters
    parameters: Parameters,

    /// UTXO Accumulator Model
    utxo_accumulator_model: UtxoAccumulatorModel,
}

#[wasm_bindgen]
impl Context {
    /// Constructs a new [`Context`] which can be used for proving and verifying [`TransferPost`].
    #[inline]
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
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// [`TransferPost`] Wrapper Type
#[wasm_bindgen]
pub struct TransferPost(config::TransferPost);

/// Defines the `prove` and `verify` WASM benchmarks for `$name`.
macro_rules! define_prove_verify {
    ($name:ident, $doc:expr, $prove:ident, $verify:ident $(,)?) => {
        #[doc = "Generates a valid proof for `"]
        #[doc = $doc]
        #[doc = "` in the given `context`."]
        #[inline]
        #[wasm_bindgen]
        pub fn $prove(context: &Context) -> TransferPost {
            TransferPost(payment::$name::prove(
                &context.proving_context.$name,
                &context.parameters,
                &context.utxo_accumulator_model,
                &mut OsRng,
            ))
        }

        #[doc = "Verifies that `post` is a valid proof for the `"]
        #[doc = $doc]
        #[doc = "` transaction in the given `context`."]
        #[inline]
        #[wasm_bindgen]
        pub fn $verify(context: &Context, post: &TransferPost) {
            post.0.assert_valid_proof(&context.verifying_context.$name);
        }
    };
}

define_prove_verify!(to_private, "ToPrivate", prove_to_private, verify_to_private);
define_prove_verify!(
    private_transfer,
    "PrivateTransfer",
    prove_private_transfer,
    verify_private_transfer,
);
define_prove_verify!(to_public, "ToPublic", prove_to_public, verify_to_public);
