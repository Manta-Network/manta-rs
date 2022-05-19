use crate::payment::{self, assert_valid_proof};
use manta_crypto::rand::{OsRng, Rand};
use manta_pay::{
    config::{
        MultiProvingContext, MultiVerifyingContext, Parameters, TransferPost, UtxoAccumulatorModel,
    },
    parameters::{generate_parameters, SEED},
};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Context {
    proving_context: MultiProvingContext,
    verifying_context: MultiVerifyingContext,
    parameters: Parameters,
    utxo_accumulator_model: UtxoAccumulatorModel,
}

#[wasm_bindgen]
impl Context {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
            generate_parameters(SEED).unwrap();
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

#[wasm_bindgen]
pub struct Proof(TransferPost);

#[wasm_bindgen]
pub fn prove_mint(context: &Context) -> Proof {
    let mut rng = OsRng;
    Proof(payment::prove_mint(
        &context.proving_context.mint,
        &context.parameters,
        &context.utxo_accumulator_model,
        rng.gen(),
        &mut rng,
    ))
}

#[wasm_bindgen]
pub fn prove_private_transfer(context: &Context) -> Proof {
    let mut rng = OsRng;
    Proof(payment::prove_private_transfer(
        &context.proving_context,
        &context.parameters,
        &context.utxo_accumulator_model,
        &mut rng,
    ))
}

#[wasm_bindgen]
pub fn prove_reclaim(context: &Context) -> Proof {
    let mut rng = OsRng;
    Proof(payment::prove_reclaim(
        &context.proving_context,
        &context.parameters,
        &context.utxo_accumulator_model,
        &mut rng,
    ))
}

#[wasm_bindgen]
pub fn verify_mint(context: &Context, proof: &Proof) {
    assert_valid_proof(&context.verifying_context.mint, &proof.0);
}

#[wasm_bindgen]
pub fn verify_private_transfer(context: &Context, proof: &Proof) {
    assert_valid_proof(&context.verifying_context.private_transfer, &proof.0);
}

#[wasm_bindgen]
pub fn verify_reclaim(context: &Context, proof: &Proof) {
    assert_valid_proof(&context.verifying_context.reclaim, &proof.0);
}
