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
    FullParameters, Mint, MultiProvingContext, MultiVerifyingContext, NoteEncryptionScheme,
    Parameters, PrivateTransfer, ProofSystemError, Reclaim, UtxoAccumulatorModel,
    UtxoCommitmentScheme, VerifyingContext, VoidNumberCommitmentScheme,
};
use manta_crypto::rand::{ChaCha20Rng, Rand, SeedableRng};
use manta_util::codec::Decode;

#[cfg(feature = "std")]
use {
    crate::config::ProvingContext,
    manta_util::codec::IoReader,
    std::{fs::File, path::Path},
};

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

/// Generates the protocol parameters starting from `seed`.
#[inline]
pub fn generate_from_seed(
    seed: [u8; 32],
) -> Result<
    (
        MultiProvingContext,
        MultiVerifyingContext,
        Parameters,
        UtxoAccumulatorModel,
    ),
    ProofSystemError,
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

/// Generates the protocol parameters starting from [`SEED`].
#[inline]
pub fn generate() -> Result<
    (
        MultiProvingContext,
        MultiVerifyingContext,
        Parameters,
        UtxoAccumulatorModel,
    ),
    ProofSystemError,
> {
    generate_from_seed(SEED)
}

/// Loads parameters from [`manta-parameters`], using `directory` as a temporary directory to store files.
#[cfg(feature = "download")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "download")))]
#[inline]
pub fn load_parameters(
    directory: &Path,
) -> Result<
    (
        MultiProvingContext,
        MultiVerifyingContext,
        Parameters,
        UtxoAccumulatorModel,
    ),
    ProofSystemError,
> {
    Ok((
        load_proving_context(directory),
        MultiVerifyingContext {
            mint: load_mint_verifying_context(),
            private_transfer: load_private_transfer_verifying_context(),
            reclaim: load_reclaim_verifying_context(),
        },
        load_transfer_parameters(),
        load_utxo_accumulator_model(),
    ))
}

/// Loads the [`MultiProvingContext`] from [`manta_parameters`], using `directory` as a
/// temporary directory to store files.
#[cfg(feature = "download")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "download")))]
#[inline]
pub fn load_proving_context(directory: &Path) -> MultiProvingContext {
    let mint_path = directory.join("mint.dat");
    manta_parameters::pay::testnet::proving::Mint::download(&mint_path)
        .expect("Unable to download MINT proving context.");
    let private_transfer_path = directory.join("private-transfer.dat");
    manta_parameters::pay::testnet::proving::PrivateTransfer::download(&private_transfer_path)
        .expect("Unable to download PRIVATE_TRANSFER proving context.");
    let reclaim_path = directory.join("reclaim.dat");
    manta_parameters::pay::testnet::proving::Reclaim::download(&reclaim_path)
        .expect("Unable to download RECLAIM proving context.");
    decode_proving_context(&mint_path, &private_transfer_path, &reclaim_path)
}

/// Loads the [`MultiProvingContext`] from [`manta_parameters`], using `directory` as
/// a temporary directory to store files.
///
/// This function skips downloading the proving contexts if they have been
/// downloaded before and their checksum matches the expected one. See
/// [`manta_parameters::verify_file`] for more on checksum verification.
#[cfg(feature = "download")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "download")))]
#[inline]
pub fn try_load_proving_context(directory: &Path) -> MultiProvingContext {
    let mint_path = directory.join("mint.dat");
    manta_parameters::pay::testnet::proving::Mint::download_if_invalid(&mint_path)
        .expect("Unable to download MINT proving context.");
    let private_transfer_path = directory.join("private-transfer.dat");
    manta_parameters::pay::testnet::proving::PrivateTransfer::download_if_invalid(
        &private_transfer_path,
    )
    .expect("Unable to download PRIVATE_TRANSFER proving context.");
    let reclaim_path = directory.join("reclaim.dat");
    manta_parameters::pay::testnet::proving::Reclaim::download_if_invalid(&reclaim_path)
        .expect("Unable to download RECLAIM proving context.");
    decode_proving_context(&mint_path, &private_transfer_path, &reclaim_path)
}

/// Decodes [`MultiProvingContext`] by loading from `mint_path`, `private_transfer_path`, and `reclaim_path`.
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
#[inline]
pub fn decode_proving_context(
    mint_path: &Path,
    private_transfer_path: &Path,
    reclaim_path: &Path,
) -> MultiProvingContext {
    MultiProvingContext {
        mint: ProvingContext::decode(IoReader(
            File::open(mint_path).expect("Unable to open MINT proving context file."),
        ))
        .expect("Unable to decode MINT proving context."),
        private_transfer: ProvingContext::decode(IoReader(
            File::open(private_transfer_path)
                .expect("Unable to open PRIVATE_TRANSFER proving context file."),
        ))
        .expect("Unable to decode PRIVATE_TRANSFER proving context."),
        reclaim: ProvingContext::decode(IoReader(
            File::open(reclaim_path).expect("Unable to open RECLAIM proving context file."),
        ))
        .expect("Unable to decode RECLAIM proving context."),
    }
}

/// Loads the `Mint` verifying contexts from [`manta_parameters`].
#[inline]
pub fn load_mint_verifying_context() -> VerifyingContext {
    VerifyingContext::decode(
        manta_parameters::pay::testnet::verifying::Mint::get().expect("Checksum did not match."),
    )
    .expect("Unable to decode MINT verifying context.")
}

/// Loads the `PrivateTransfer` verifying context from [`manta_parameters`].
#[inline]
pub fn load_private_transfer_verifying_context() -> VerifyingContext {
    VerifyingContext::decode(
        manta_parameters::pay::testnet::verifying::PrivateTransfer::get()
            .expect("Checksum did not match."),
    )
    .expect("Unable to decode PRIVATE_TRANSFER verifying context.")
}

/// Loads the `Reclaim` verifying context from [`manta_parameters`].
#[inline]
pub fn load_reclaim_verifying_context() -> VerifyingContext {
    VerifyingContext::decode(
        manta_parameters::pay::testnet::verifying::Reclaim::get().expect("Checksum did not match."),
    )
    .expect("Unable to decode RECLAIM verifying context.")
}

/// Loads the transfer [`Parameters`] from [`manta_parameters`].
#[inline]
pub fn load_transfer_parameters() -> Parameters {
    Parameters {
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
    }
}

/// Loads the [`UtxoAccumulatorModel`] from [`manta_parameters`].
#[inline]
pub fn load_utxo_accumulator_model() -> UtxoAccumulatorModel {
    UtxoAccumulatorModel::decode(
        manta_parameters::pay::testnet::parameters::UtxoAccumulatorModel::get()
            .expect("Checksum did not match."),
    )
    .expect("Unable to decode UTXO_ACCUMULATOR_MODEL.")
}
