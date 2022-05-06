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

//! Generate Parameters
//! This is a workaround for load_parameters(...) function.
//!     load_parameters(...) requires openssl, which has some compatible issues
//!     with wasm.
//! Adapted from manta-pay/src/bin/generate_parameters.rs

use anyhow::{Ok, Result};
use manta_crypto::{
    constraint::ProofSystem as _,
    rand::{Rand, SeedableRng},
};
use manta_pay::config::{
    FullParameters, Mint, MultiProvingContext, MultiVerifyingContext, Parameters, PrivateTransfer,
    ProofSystem, Reclaim, UtxoAccumulatorModel,
};
use rand_chacha::ChaCha20Rng;

/// Parameter Generation Seed
///
/// This is a nothing-up-my-sleve parameter generation number. Its just the numbers from `0` to `31`
/// as `u8` bytes.
///
/// # Warning
///
/// Right now, this seed is also used to generate to the proving and verifying keys for the ZKP
/// circuits. This is not safe, and a real system must use a Multi-Party-Computation to arrive at
/// the ZKP parameters.
pub const SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// Generates the parameters using the [`SEED`] and saves them to the filesystem.
/// Note: Only for benchmark purpose.
#[inline]
pub fn get_parameters() -> Result<(
    MultiProvingContext,
    MultiVerifyingContext,
    Parameters,
    UtxoAccumulatorModel,
)> {
    let mut rng = ChaCha20Rng::from_seed(SEED);

    let parameters = rng.gen();
    let utxo_accumulator_model: UtxoAccumulatorModel = rng.gen();

    let Parameters {
        note_encryption_scheme: _,
        utxo_commitment: _,
        void_number_commitment: _,
    } = &parameters;

    let full_parameters = FullParameters::new(&parameters, &utxo_accumulator_model);

    let cs = Mint::unknown_constraints(full_parameters);
    let (mint_proving_context, mint_verifying_context) =
        ProofSystem::generate_context(&(), cs, &mut rng).unwrap();

    let cs = PrivateTransfer::unknown_constraints(full_parameters);
    let (private_transfer_proving_context, private_transfer_verifying_context) =
        ProofSystem::generate_context(&(), cs, &mut rng).unwrap();

    let cs = Reclaim::unknown_constraints(full_parameters);
    let (reclaim_proving_context, reclaim_verifying_context) =
        ProofSystem::generate_context(&(), cs, &mut rng).unwrap();

    let proving_context = MultiProvingContext {
        mint: mint_proving_context,
        private_transfer: private_transfer_proving_context,
        reclaim: reclaim_proving_context,
    };

    let verifying_context = MultiVerifyingContext {
        mint: mint_verifying_context,
        private_transfer: private_transfer_verifying_context,
        reclaim: reclaim_verifying_context,
    };

    Ok((
        proving_context,
        verifying_context,
        parameters,
        utxo_accumulator_model,
    ))
}
