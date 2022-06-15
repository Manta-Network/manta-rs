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

//! Manta Pay UTXO Binary Compatibility
//! Checks if the current circuit implementation is compatible with precomputed parameters.

use crate::{
    config::{
        MultiProvingContext, MultiVerifyingContext, NoteEncryptionScheme, Parameters,
        ProvingContext, UtxoAccumulatorModel, UtxoCommitmentScheme, VerifyingContext,
        VoidNumberCommitmentScheme,
    },
    sample_payment::{assert_valid_proof, prove_mint, prove_private_transfer, prove_reclaim},
};
use anyhow::Result;
use ark_std::rand::thread_rng;
use manta_crypto::rand::Rand;
use manta_util::codec::{Decode, IoReader};
use std::{fs::File, path::Path};

/// Loads parameters from the `manta-parameters`, using `directory` as a temporary directory to store files.
#[inline]
fn load_parameters(
    directory: &Path,
) -> Result<(
    MultiProvingContext,
    MultiVerifyingContext,
    Parameters,
    UtxoAccumulatorModel,
)> {
    println!("Loading parameters...");
    let mint_path = directory.join("mint.dat");
    manta_parameters::pay::testnet::proving::Mint::download(&mint_path)?;
    let private_transfer_path = directory.join("private-transfer.dat");
    manta_parameters::pay::testnet::proving::PrivateTransfer::download(&private_transfer_path)?;
    let reclaim_path = directory.join("reclaim.dat");
    manta_parameters::pay::testnet::proving::Reclaim::download(&reclaim_path)?;
    println!("mint_path: {:?}", mint_path);
    let proving_context = MultiProvingContext {
        mint: ProvingContext::decode(IoReader(File::open(mint_path)?))
            .expect("Unable to decode MINT proving context."),
        private_transfer: ProvingContext::decode(IoReader(File::open(private_transfer_path)?))
            .expect("Unable to decode PRIVATE_TRANSFER proving context."),
        reclaim: ProvingContext::decode(IoReader(File::open(reclaim_path)?))
            .expect("Unable to decode RECLAIM proving context."),
    };
    let verifying_context = MultiVerifyingContext {
        mint: VerifyingContext::decode(
            manta_parameters::pay::testnet::verifying::Mint::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode MINT verifying context."),
        private_transfer: VerifyingContext::decode(
            manta_parameters::pay::testnet::verifying::PrivateTransfer::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode PRIVATE_TRANSFER verifying context."),
        reclaim: VerifyingContext::decode(
            manta_parameters::pay::testnet::verifying::Reclaim::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode RECLAIM verifying context."),
    };
    let parameters = Parameters {
        note_encryption_scheme: NoteEncryptionScheme::decode(
            manta_parameters::pay::testnet::parameters::NoteEncryptionScheme::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode NOTE_ENCRYPTION_SCHEME parameters."),
        utxo_commitment: UtxoCommitmentScheme::decode(
            manta_parameters::pay::testnet::parameters::UtxoCommitmentScheme::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode UTXO_COMMITMENT_SCHEME parameters."),
        void_number_commitment: VoidNumberCommitmentScheme::decode(
            manta_parameters::pay::testnet::parameters::VoidNumberCommitmentScheme::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode VOID_NUMBER_COMMITMENT_SCHEME parameters."),
    };
    println!("Loading parameters Done.");
    Ok((
        proving_context,
        verifying_context,
        parameters,
        UtxoAccumulatorModel::decode(
            manta_parameters::pay::testnet::parameters::UtxoAccumulatorModel::get()
                .expect("Checksum did not match."),
        )
        .expect("Unable to decode UTXO_ACCUMULATOR_MODEL."),
    ))
}

/// Test validity on sampled transactions.
#[test]
fn compatibility() {
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    let mut rng = thread_rng();
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("Failed to load parameters");
    assert_valid_proof(
        &verifying_context.mint,
        &prove_mint(
            &proving_context.mint,
            &parameters,
            &utxo_accumulator_model,
            rng.gen(),
            &mut rng,
        ),
    );
    assert_valid_proof(
        &verifying_context.private_transfer,
        &prove_private_transfer(
            &proving_context,
            &parameters,
            &utxo_accumulator_model,
            &mut rng,
        ),
    );
    assert_valid_proof(
        &verifying_context.reclaim,
        &prove_reclaim(
            &proving_context,
            &parameters,
            &utxo_accumulator_model,
            &mut rng,
        ),
    );
}
