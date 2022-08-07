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

//! Manta-Pay Configuration

use crate::crypto::{
    constraint::arkworks::{field_element_as_bytes, groth16, Boolean, Fp, FpVar, R1CS},
    ecc,
    encryption::aes::{self, FixedNonceAesGcm},
    key::Blake2sKdf,
};
use alloc::vec::Vec;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2sVar,
};
use bls12_381::Bls12_381;
use bls12_381_ed::constraints::EdwardsVar as Bls12_381_EdwardsVar;
use manta_accounting::{asset::Asset, transfer};
use manta_crypto::{
    accumulator,
    algebra::DiffieHellman,
    arkworks::{
        ff::ToConstraintField,
        serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError},
    },
    eclair::{
        self,
        alloc::{
            mode::{Public, Secret},
            Allocate, Allocator, Constant, Variable,
        },
        ops::Add,
    },
    encryption,
    hash::ArrayHashFunction,
    key::{
        self,
        kdf::{AsBytes, KeyDerivationFunction},
    },
    merkle_tree,
};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    into_array_unchecked, Array, SizeLimit,
};

#[cfg(feature = "bs58")]
use alloc::string::String;

#[cfg(any(feature = "test", test))]
use manta_crypto::rand::{Rand, RngCore, Sample};

#[doc(inline)]
pub use ark_bls12_381 as bls12_381;

#[doc(inline)]
pub use ark_ed_on_bls12_381 as bls12_381_ed;

pub(crate) use bls12_381_ed::EdwardsProjective as Bls12_381_Edwards;

pub mod poseidon;
pub mod utxo;

/// Pairing Curve Type
pub type PairingCurve = Bls12_381;

/// Embedded Scalar Field Type
pub type EmbeddedScalarField = bls12_381_ed::Fr;

/// Embedded Scalar Type
pub type EmbeddedScalar = ecc::arkworks::Scalar<Bls12_381_Edwards>;

/// Embedded Scalar Variable Type
pub type EmbeddedScalarVar = ecc::arkworks::ScalarVar<Bls12_381_Edwards, Bls12_381_EdwardsVar>;

/// Embedded Group Type
pub type Group = ecc::arkworks::Group<Bls12_381_Edwards>;

/// Embedded Group Variable Type
pub type GroupVar = ecc::arkworks::GroupVar<Bls12_381_Edwards, Bls12_381_EdwardsVar>;

/// Constraint Field
pub type ConstraintField = bls12_381::Fr;

/// Constraint Field Variable
pub type ConstraintFieldVar = FpVar<ConstraintField>;

/// Constraint Compiler
pub type Compiler = R1CS<ConstraintField>;

/// Proof System Proof
pub type Proof = groth16::Proof<PairingCurve>;

/// Proof System
pub type ProofSystem = groth16::Groth16<PairingCurve>;

/// Proof System Error
pub type ProofSystemError = groth16::Error;

///
pub struct Config;

impl transfer::Configuration for Config {
    type Compiler = Compiler;
    type AssetId = utxo::v1::AssetId;
    type AssetValue = utxo::v1::AssetValue;
    type AssociatedData = utxo::v1::AssociatedData;
    type Utxo = utxo::v1::Utxo;
    type Nullifier = utxo::v1::Nullifier;
    type Identifier = utxo::v1::Identifier;
    type MintSecret = utxo::v1::MintSecret;
    type SpendSecret = utxo::v1::SpendSecret;
    type UtxoAccumulatorWitness = utxo::v1::UtxoAccumulatorWitness;
    type UtxoAccumulatorOutput = utxo::v1::UtxoAccumulatorOutput;
    type Parameters = utxo::v1::Parameters;
    type AuthorizationContextVar = utxo::v1::AuthorizationContextVar;
    type AuthorizationProofVar = utxo::v1::AuthorizationProofVar;
    type AssetIdVar = utxo::v1::AssetIdVar;
    type AssetValueVar = utxo::v1::AssetValueVar;
    type UtxoVar = utxo::v1::UtxoVar;
    type NoteVar = utxo::v1::NoteVar;
    type NullifierVar = utxo::v1::NullifierVar;
    type UtxoAccumulatorWitnessVar = utxo::v1::UtxoAccumulatorWitnessVar;
    type UtxoAccumulatorOutputVar = utxo::v1::UtxoAccumulatorOutputVar;
    type UtxoAccumulatorModelVar = utxo::v1::UtxoAccumulatorModelVar;
    type MintSecretVar = utxo::v1::MintSecretVar;
    type SpendSecretVar = utxo::v1::SpendSecretVar;
    type ParametersVar = utxo::v1::ParametersVar;
    type ProofSystem = ProofSystem;
}

/* FIXME[remove]:
/// Transfer Parameters
pub type Parameters = transfer::Parameters<Config>;

/// Full Transfer Parameters
pub type FullParameters<'p> = transfer::FullParameters<'p, Config>;

/// Note Type
pub type Note = transfer::Note<Config>;

/// Encrypted Note Type
pub type EncryptedNote = transfer::EncryptedNote<Config>;

/// Sender Type
pub type Sender = transfer::Sender<Config>;

/// Sender Post Type
pub type SenderPost = transfer::SenderPost<Config>;

/// Receiver Type
pub type Receiver = transfer::Receiver<Config>;

/// Receiver Post Type
pub type ReceiverPost = transfer::ReceiverPost<Config>;

/// Transfer Post Type
pub type TransferPost = transfer::TransferPost<Config>;

/// Mint Transfer Type
pub type Mint = transfer::canonical::Mint<Config>;

/// Private Transfer Type
pub type PrivateTransfer = transfer::canonical::PrivateTransfer<Config>;

/// Reclaim Transfer Type
pub type Reclaim = transfer::canonical::Reclaim<Config>;

/// Proving Context Type
pub type ProvingContext = transfer::ProvingContext<Config>;

/// Verifying Context Type
pub type VerifyingContext = transfer::VerifyingContext<Config>;

/// Multi-Proving Context Type
pub type MultiProvingContext = transfer::canonical::MultiProvingContext<Config>;

/// Multi-Verifying Context Type
pub type MultiVerifyingContext = transfer::canonical::MultiVerifyingContext<Config>;

/// Transaction Type
pub type Transaction = transfer::canonical::Transaction<Config>;

/// Spending Key Type
pub type SpendingKey = transfer::SpendingKey<Config>;

/// Receiving Key Type
pub type ReceivingKey = transfer::ReceivingKey<Config>;

/// Converts a [`ReceivingKey`] into a base58-encoded string.
#[cfg(feature = "bs58")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bs58")))]
#[inline]
pub fn receiving_key_to_base58(receiving_key: &ReceivingKey) -> String {
    let mut bytes = Vec::new();
    receiving_key
        .spend
        .encode(&mut bytes)
        .expect("Encoding is not allowed to fail.");
    receiving_key
        .view
        .encode(&mut bytes)
        .expect("Encoding is not allowed to fail.");
    bs58::encode(bytes).into_string()
}

/// Converts a base58-encoded string into a [`ReceivingKey`].
#[cfg(feature = "bs58")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bs58")))]
#[inline]
pub fn receiving_key_from_base58(string: &str) -> Option<ReceivingKey> {
    let bytes = bs58::decode(string.as_bytes()).into_vec().ok()?;
    let (spend, view) = bytes.split_at(bytes.len() / 2);
    Some(ReceivingKey {
        spend: spend.to_owned().try_into().ok()?,
        view: view.to_owned().try_into().ok()?,
    })
}
*/

*/
