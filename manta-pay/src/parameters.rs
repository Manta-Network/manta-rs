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

//! Generate Parameters and Proving/Verifying Contexts

use crate::config::{
    Config, FullParameters, Mint, MultiProvingContext, MultiVerifyingContext, Parameters,
    PrivateTransfer, Reclaim, UtxoAccumulatorModel,
};
use manta_accounting::transfer::ProofSystemError;
use manta_crypto::rand::{Rand, SeedableRng};
use rand_chacha::ChaCha20Rng; // TODO: Should we use ChaCha20Rng here?

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

/// Generates the protocol parameters using `seed`.
#[inline]
pub fn generate_parameters(
    seed: [u8; 32],
) -> Result<
    (
        MultiProvingContext,
        MultiVerifyingContext,
        Parameters,
        UtxoAccumulatorModel,
    ),
    ProofSystemError<Config>,
> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let parameters = rng.gen();
    let utxo_accumulator_model: UtxoAccumulatorModel = rng.gen();
    let full_parameters = FullParameters::new(&parameters, &utxo_accumulator_model);
    let (mint_proving_context, mint_verifying_context) =
        Mint::generate_context(&(), full_parameters, &mut rng)?;
    let (private_transfer_proving_context, private_transfer_verifying_context) =
        PrivateTransfer::generate_context(&(), full_parameters, &mut rng)?;
    let (reclaim_proving_context, reclaim_verifying_context) =
        Reclaim::generate_context(&(), full_parameters, &mut rng)?;
    Ok((
        MultiProvingContext {
            mint: mint_proving_context,
            private_transfer: private_transfer_proving_context,
            reclaim: reclaim_proving_context,
        },
        MultiVerifyingContext {
            mint: mint_verifying_context,
            private_transfer: private_transfer_verifying_context,
            reclaim: reclaim_verifying_context,
        },
        parameters,
        utxo_accumulator_model,
    ))
}
