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

use manta_accounting::transfer;
use openzl_plugin_arkworks::{
    algebra::{self, ScalarVar},
    bn254::{self, Bn254},
    constraint::{FpVar, R1CS},
    ed_on_bn254::{
        self, constraints::EdwardsVar as Bn254_EdwardsVar, EdwardsProjective as Bn254_Edwards,
    },
    groth16,
};

#[cfg(feature = "bs58")]
use {alloc::string::String, openzl_util::codec::Encode};

pub mod poseidon;
pub mod utxo;
pub mod utxo_utilities;

/// Pairing Curve Type
pub type PairingCurve = Bn254;

/// Embedded Scalar Field Type
pub type EmbeddedScalarField = ed_on_bn254::Fr;

/// Embedded Scalar Type
pub type EmbeddedScalar = algebra::Scalar<GroupCurve>;

/// Embedded Scalar Variable Type
pub type EmbeddedScalarVar = ScalarVar<GroupCurve, GroupCurveVar>;

/// Embedded Group Curve Type
pub type GroupCurve = Bn254_Edwards;

/// Embedded Group Curve Type
pub type GroupCurveAffine = ed_on_bn254::EdwardsAffine;

/// Embedded Group Curve Variable Type
pub type GroupCurveVar = Bn254_EdwardsVar;

/// Embedded Group Type
pub type Group = algebra::Group<GroupCurve>;

/// Embedded Group Variable Type
pub type GroupVar = algebra::GroupVar<GroupCurve, GroupCurveVar>;

/// Constraint Field
pub type ConstraintField = bn254::Fr;

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

/// Transfer Configuration
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Config;

impl transfer::Configuration for Config {
    type Compiler = Compiler;
    type AssetId = utxo::AssetId;
    type AssetValue = utxo::AssetValue;
    type AssociatedData = utxo::AssociatedData;
    type Utxo = utxo::Utxo;
    type Nullifier = utxo::Nullifier;
    type Identifier = utxo::Identifier;
    type Address = utxo::Address;
    type Note = utxo::Note;
    type MintSecret = utxo::MintSecret;
    type SpendSecret = utxo::SpendSecret;
    type UtxoAccumulatorWitness = utxo::UtxoAccumulatorWitness;
    type UtxoAccumulatorOutput = utxo::UtxoAccumulatorOutput;
    type UtxoAccumulatorItemHash = utxo::UtxoAccumulatorItemHash;
    type Parameters = utxo::Parameters;
    type AuthorizationContextVar = utxo::AuthorizationContextVar;
    type AuthorizationProofVar = utxo::AuthorizationProofVar;
    type AssetIdVar = utxo::AssetIdVar;
    type AssetValueVar = utxo::AssetValueVar;
    type UtxoVar = utxo::UtxoVar;
    type NoteVar = utxo::NoteVar;
    type NullifierVar = utxo::NullifierVar;
    type UtxoAccumulatorWitnessVar = utxo::UtxoAccumulatorWitnessVar;
    type UtxoAccumulatorOutputVar = utxo::UtxoAccumulatorOutputVar;
    type UtxoAccumulatorModelVar = utxo::UtxoAccumulatorModelVar;
    type MintSecretVar = utxo::MintSecretVar;
    type SpendSecretVar = utxo::SpendSecretVar;
    type ParametersVar = utxo::ParametersVar;
    type ProofSystem = ProofSystem;
}

/// Transfer Parameters
pub type Parameters = transfer::Parameters<Config>;

/// UTXO Accumulator Output Type
pub type UtxoAccumulatorOutput = transfer::UtxoAccumulatorOutput<Config>;

/// UTXO Accumulator Model Type
pub type UtxoAccumulatorModel = transfer::UtxoAccumulatorModel<Config>;

/// Full Transfer Parameters
pub type FullParametersRef<'p> = transfer::FullParametersRef<'p, Config>;

/// Authorization Context Type
pub type AuthorizationContext = transfer::AuthorizationContext<Config>;

/// Authorization Type
pub type Authorization = transfer::Authorization<Config>;

/// Asset Id Type
pub type AssetId = transfer::AssetId<Config>;

/// Asset Value Type
pub type AssetValue = transfer::AssetValue<Config>;

/// Asset Type
pub type Asset = transfer::Asset<Config>;

/// Unspent Transaction Output Type
pub type Utxo = transfer::Utxo<Config>;

/// Note Type
pub type Note = transfer::Note<Config>;

/// Nullifier Type
pub type Nullifier = transfer::Nullifier<Config>;

/// Sender Type
pub type Sender = transfer::Sender<Config>;

/// Sender Post Type
pub type SenderPost = transfer::SenderPost<Config>;

/// Receiver Type
pub type Receiver = transfer::Receiver<Config>;

/// Receiver Post Type
pub type ReceiverPost = transfer::ReceiverPost<Config>;

/// Transfer Post Body Type
pub type TransferPostBody = transfer::TransferPostBody<Config>;

/// Transfer Post Type
pub type TransferPost = transfer::TransferPost<Config>;

/// To-Private Transfer Type
pub type ToPrivate = transfer::canonical::ToPrivate<Config>;

/// Private Transfer Type
pub type PrivateTransfer = transfer::canonical::PrivateTransfer<Config>;

/// To-Public Transfer Type
pub type ToPublic = transfer::canonical::ToPublic<Config>;

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

/// Address Type
pub type Address = transfer::Address<Config>;

/// Converts an [`Address`] into a base58-encoded string.
#[cfg(feature = "bs58")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bs58")))]
#[inline]
pub fn address_to_base58(address: &Address) -> String {
    let mut bytes = Vec::new();
    address
        .receiving_key
        .encode(&mut bytes)
        .expect("Encoding is not allowed to fail.");
    bs58::encode(bytes).into_string()
}

/// Converts a base58-encoded string into an [`Address`].
#[cfg(feature = "bs58")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bs58")))]
#[inline]
pub fn address_from_base58(string: &str) -> Option<Address> {
    Some(Address::new(
        bs58::decode(string.as_bytes())
            .into_vec()
            .ok()?
            .try_into()
            .ok()?,
    ))
}
