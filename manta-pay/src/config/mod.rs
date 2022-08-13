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
    constraint::arkworks::{groth16, FpVar, R1CS},
    ecc,
};
use bls12_381::Bls12_381;
use bls12_381_ed::constraints::EdwardsVar as Bls12_381_EdwardsVar;
use manta_accounting::transfer;

#[cfg(feature = "bs58")]
use {alloc::string::String, manta_util::codec::Encode};

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
pub type EmbeddedScalar = ecc::arkworks::Scalar<GroupCurve>;

/// Embedded Scalar Variable Type
pub type EmbeddedScalarVar = ecc::arkworks::ScalarVar<GroupCurve, GroupCurveVar>;

/// Embedded Group Curve Type
pub type GroupCurve = Bls12_381_Edwards;

/// Embedded Group Curve Type
pub type GroupCurveAffine = bls12_381_ed::EdwardsAffine;

/// Embedded Group Curve Variable Type
pub type GroupCurveVar = Bls12_381_EdwardsVar;

/// Embedded Group Type
pub type Group = ecc::arkworks::Group<GroupCurve>;

/// Embedded Group Variable Type
pub type GroupVar = ecc::arkworks::GroupVar<GroupCurve, GroupCurveVar>;

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

/// Transfer Configuration
pub struct Config;

impl transfer::Configuration for Config {
    type Compiler = Compiler;
    type AssetId = utxo::v1::AssetId;
    type AssetValue = utxo::v1::AssetValue;
    type AssociatedData = utxo::v1::AssociatedData;
    type Utxo = utxo::v1::Utxo;
    type Nullifier = utxo::v1::Nullifier;
    type Identifier = utxo::v1::Identifier;
    type Address = utxo::v1::Address;
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

/// Transfer Parameters
pub type Parameters = transfer::Parameters<Config>;

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
