// Copyright 2019-2021 Manta Network.
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

//! Accounting Implementations

// TODO: Make this generic over the backend we use. Automatically compute which features are
//       enabled when using whichever backend.

use crate::crypto::{
    commitment::{pedersen, poseidon},
    encryption::AesGcm,
    key::{Blake2sKdf, EllipticCurveDiffieHellman},
};
use manta_accounting::{asset::Asset, transfer};
use manta_crypto::{
    commitment::CommitmentScheme, encryption, key::KeyAgreementScheme, merkle_tree,
};

pub use ark_bls12_381 as bls12_381;
pub use ark_ed_on_bls12_381 as bls12_381_ed;
pub use bls12_381::Bls12_381;
pub use bls12_381_ed::EdwardsProjective as Bls12_381_Edwards;

pub mod key;
// TODO: pub mod ledger;
// TODO: pub mod transfer;

/// Configuration Structure
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Config;

impl poseidon::Specification for Config {
    const FULL_ROUNDS: usize = 10;
    const PARTIAL_ROUNDS: usize = 10;
    const SBOX_EXPONENT: u64 = 5;
    type Field = bls12_381::Fr;
}

impl transfer::Configuration for Config {
    type SecretKey = <Self::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;
    type SecretKeyVar = ();
    type PublicKey = <Self::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;
    type PublicKeyVar = ();
    type KeyAgreementScheme = EllipticCurveDiffieHellman<Bls12_381>;

    type EphemeralKeyTrapdoor = <Self::EphemeralKeyCommitmentScheme as CommitmentScheme>::Trapdoor;
    type EphemeralKeyTrapdoorVar = ();
    type EphemeralKeyParametersVar = ();
    type EphemeralKeyCommitmentScheme =
        poseidon::Commitment<Self, (), 2> + poseidon::Commitment<Self, Self::Compiler, 2>;

    type TrapdoorDerivationFunction = ();

    type UtxoCommitmentParametersVar = ();
    type Utxo = <Self::UtxoCommitmentScheme as CommitmentScheme>::Output;
    type UtxoCommitmentScheme = pedersen::Commitment<pedersen::arkworks::Group<Bls12_381>, 2>;

    type VoidNumberCommitmentParametersVar = ();
    type VoidNumber = <Self::VoidNumberCommitmentScheme as CommitmentScheme>::Output;
    type VoidNumberCommitmentScheme = pedersen::Commitment<pedersen::arkworks::Group<Bls12_381>, 1>;

    type UtxoSetParametersVar = ();
    type UtxoSetWitnessVar = ();
    type UtxoSetOutputVar = ();
    type UtxoSetVerifier = merkle_tree::Verifier;

    type AssetIdVar = ();
    type AssetValueVar = ();

    type Compiler = ArkworksR1CS;
    type ProofSystem = Groth16;

    type NoteEncryptionScheme = encryption::Hybrid<
        Self::KeyAgreementScheme,
        AesGcm<Asset, { Asset::SIZE }>,
        Blake2sKdf<<Self::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret>,
    >;
}

/* TODO:
/// Pedersen Window Parameters
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PedersenCommitmentWindowParameters;

impl PedersenWindow for PedersenCommitmentWindowParameters {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

/// Pedersen Commitment Projective Curve
pub type PedersenCommitmentProjectiveCurve = EdwardsProjective;

/// Pedersen Commitment Projective Curve
pub type PedersenCommitmentProjectiveCurveVar = EdwardsVar;

/// Pedersen Commitment Scheme
pub type PedersenCommitment = pedersen::constraint::PedersenCommitmentWrapper<
    PedersenCommitmentWindowParameters,
    PedersenCommitmentProjectiveCurve,
    PedersenCommitmentProjectiveCurveVar,
>;

/// Pedersen Commitment Scheme Variable
pub type PedersenCommitmentVar = pedersen::constraint::PedersenCommitmentVar<
    PedersenCommitmentWindowParameters,
    PedersenCommitmentProjectiveCurve,
    PedersenCommitmentProjectiveCurveVar,
>;

/// Arkworks Pedersen Commitment Scheme
type ArkPedersenCommitment =
    CRH<PedersenCommitmentProjectiveCurve, PedersenCommitmentWindowParameters>;

/// Constraint Field
pub type ConstraintField = Fq;

/// Constraint System
pub type ConstraintSystem = ArkConstraintSystem<ConstraintField>;

/// Proof System
pub type ProofSystem = Groth16<Bls12_381>;

impl ArkMerkleTreeConfiguration for Configuration {
    type Leaf = Utxo;
    type LeafHash = ArkPedersenCommitment;
    type InnerHash = ArkPedersenCommitment;
    type Height = u8;

    const HEIGHT: Self::Height = 20;
}

impl merkle_tree::HashConfiguration for Configuration {
    type LeafHash =
        <ArkMerkleTreeConfigConverter<Configuration> as merkle_tree::HashConfiguration>::LeafHash;
    type InnerHash =
        <ArkMerkleTreeConfigConverter<Configuration> as merkle_tree::HashConfiguration>::InnerHash;
}

impl merkle_tree::Configuration for Configuration {
    type Height =
        <ArkMerkleTreeConfigConverter<Configuration> as merkle_tree::Configuration>::Height;

    const HEIGHT: Self::Height =
        <ArkMerkleTreeConfigConverter<Configuration> as merkle_tree::Configuration>::HEIGHT;
}

impl merkle_tree_constraint::Configuration for Configuration {
    type ConstraintField = ConstraintField;
    type LeafHashVar = CRHGadget<
        PedersenCommitmentProjectiveCurve,
        PedersenCommitmentProjectiveCurveVar,
        PedersenCommitmentWindowParameters,
    >;
    type InnerHashVar = CRHGadget<
        PedersenCommitmentProjectiveCurve,
        PedersenCommitmentProjectiveCurveVar,
        PedersenCommitmentWindowParameters,
    >;
}

impl identity::Configuration for Configuration {
    type Asset = Asset;
    type KeyAgreementScheme = EllipticCurveDiffieHellman<PedersenCommitmentProjectiveCurve>;
    type CommitmentScheme = PedersenCommitment;
}

/*
/// Transfer Constraint Configuration Structure
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransferConstraintConfiguration;

impl identity::Configuration for TransferConstraintConfiguration {
    type Asset = AssetVar;
    type KeyAgreementScheme = ();
    type CommitmentScheme = ();
}

impl transfer::ConstraintConfiguration<ConstraintSystem> for TransferConstraintConfiguration {}

impl transfer::Configuration for Configuration {
    type EncryptionScheme = ();
    type UtxoSetVerifier = ();
    type ConstraintSystem = ConstraintSystem;
    type ConstraintConfiguration = TransferConstraintConfiguration;
    type ProofSystem = ProofSystem;
}
*/
*/
