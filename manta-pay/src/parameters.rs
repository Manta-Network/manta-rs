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
    utxo::v2::protocol::BaseParameters, FullParametersRef, MultiProvingContext,
    MultiVerifyingContext, Parameters, PrivateTransfer, ProofSystemError, ToPrivate, ToPublic,
    UtxoAccumulatorModel, VerifyingContext,
};
use core::fmt::Debug;
use manta_crypto::rand::{ChaCha20Rng, Rand, SeedableRng};
use manta_parameters::Get;
use manta_util::codec::Decode;

#[cfg(feature = "download")]
use manta_parameters::Download;

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
    let full_parameters = FullParametersRef::new(&parameters, &utxo_accumulator_model);
    let (to_private_proving_context, to_private_verifying_context) =
        ToPrivate::generate_context(&(), full_parameters, &mut rng)?;
    let (private_transfer_proving_context, private_transfer_verifying_context) =
        PrivateTransfer::generate_context(&(), full_parameters, &mut rng)?;
    let (to_public_proving_context, to_public_verifying_context) =
        ToPublic::generate_context(&(), full_parameters, &mut rng)?;
    Ok((
        MultiProvingContext {
            to_private: to_private_proving_context,
            private_transfer: private_transfer_proving_context,
            to_public: to_public_proving_context,
        },
        MultiVerifyingContext {
            to_private: to_private_verifying_context,
            private_transfer: private_transfer_verifying_context,
            to_public: to_public_verifying_context,
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
            to_private: load_to_private_verifying_context(),
            private_transfer: load_private_transfer_verifying_context(),
            to_public: load_to_public_verifying_context(),
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
    let to_private_path = directory.join("to-private.dat");
    manta_parameters::pay::testnet::proving::ToPrivate::download(&to_private_path)
        .expect("Unable to download ToPrivate proving context.");
    let private_transfer_path = directory.join("private-transfer.dat");
    manta_parameters::pay::testnet::proving::PrivateTransfer::download(&private_transfer_path)
        .expect("Unable to download PrivateTransfer proving context.");
    let to_public_path = directory.join("to-public.dat");
    manta_parameters::pay::testnet::proving::ToPublic::download(&to_public_path)
        .expect("Unable to download ToPublic proving context.");
    decode_proving_context(&to_private_path, &private_transfer_path, &to_public_path)
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
    let to_private_path = directory.join("to-private.dat");
    manta_parameters::pay::testnet::proving::ToPrivate::download_if_invalid(&to_private_path)
        .expect("Unable to download ToPrivate proving context.");
    let private_transfer_path = directory.join("private-transfer.dat");
    manta_parameters::pay::testnet::proving::PrivateTransfer::download_if_invalid(
        &private_transfer_path,
    )
    .expect("Unable to download PrivateTransfer proving context.");
    let to_public_path = directory.join("to-public.dat");
    manta_parameters::pay::testnet::proving::ToPublic::download_if_invalid(&to_public_path)
        .expect("Unable to download ToPublic proving context.");
    decode_proving_context(&to_private_path, &private_transfer_path, &to_public_path)
}

/// Decodes [`MultiProvingContext`] by loading from `to_private_path`, `private_transfer_path`, and
/// `to_public_path`.
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
#[inline]
pub fn decode_proving_context(
    to_private_path: &Path,
    private_transfer_path: &Path,
    to_public_path: &Path,
) -> MultiProvingContext {
    MultiProvingContext {
        to_private: ProvingContext::decode(IoReader(
            File::open(to_private_path).expect("Unable to open ToPrivate proving context file."),
        ))
        .expect("Unable to decode ToPrivate proving context."),
        private_transfer: ProvingContext::decode(IoReader(
            File::open(private_transfer_path)
                .expect("Unable to open PrivateTransfer proving context file."),
        ))
        .expect("Unable to decode PrivateTransfer proving context."),
        to_public: ProvingContext::decode(IoReader(
            File::open(to_public_path).expect("Unable to open ToPublic proving context file."),
        ))
        .expect("Unable to decode ToPublic proving context."),
    }
}

/// Loads the `ToPrivate` verifying contexts from [`manta_parameters`].
#[inline]
pub fn load_to_private_verifying_context() -> VerifyingContext {
    VerifyingContext::decode(
        manta_parameters::pay::testnet::verifying::ToPrivate::get()
            .expect("Checksum did not match."),
    )
    .expect("Unable to decode To-Private verifying context.")
}

/// Loads the `PrivateTransfer` verifying context from [`manta_parameters`].
#[inline]
pub fn load_private_transfer_verifying_context() -> VerifyingContext {
    VerifyingContext::decode(
        manta_parameters::pay::testnet::verifying::PrivateTransfer::get()
            .expect("Checksum did not match."),
    )
    .expect("Unable to decode PrivateTransfer verifying context.")
}

/// Loads the `ToPublic` verifying context from [`manta_parameters`].
#[inline]
pub fn load_to_public_verifying_context() -> VerifyingContext {
    VerifyingContext::decode(
        manta_parameters::pay::testnet::verifying::ToPublic::get()
            .expect("Checksum did not match."),
    )
    .expect("Unable to decode ToPublic verifying context.")
}

/// Load a [`Get`] object into an object of type `T`.
#[inline]
pub fn load_get_object<G, T>() -> T
where
    G: Get,
    T: Decode,
    T::Error: Debug,
{
    Decode::decode(G::get().expect("Mismatch of checksum.")).expect("Unable to decode object.")
}

/// Loads the transfer [`Parameters`] from [`manta_parameters`].
#[inline]
pub fn load_transfer_parameters() -> Parameters {
    use manta_parameters::pay::testnet::parameters::*;
    Parameters {
        base: BaseParameters {
            group_generator: load_get_object::<GroupGenerator, _>(),
            utxo_commitment_scheme: load_get_object::<UtxoCommitmentScheme, _>(),
            incoming_base_encryption_scheme: load_get_object::<IncomingBaseEncryptionScheme, _>(),
            viewing_key_derivation_function: load_get_object::<ViewingKeyDerivationFunction, _>(),
            utxo_accumulator_item_hash: load_get_object::<UtxoAccumulatorItemHash, _>(),
            nullifier_commitment_scheme: load_get_object::<NullifierCommitmentScheme, _>(),
            outgoing_base_encryption_scheme: load_get_object::<OutgoingBaseEncryptionScheme, _>(),
        },
        address_partition_function: load_get_object::<AddressPartitionFunction, _>(),
        schnorr_hash_function: load_get_object::<SchnorrHashFunction, _>(),
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
