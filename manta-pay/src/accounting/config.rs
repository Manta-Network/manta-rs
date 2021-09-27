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

//! Identity and Transfer Configurations

// TODO: Make this generic over the backend we use. Automatically compute which features are
//       enabled when using whichever backend.

use crate::{
    accounting::ledger::{UtxoSet, UtxoSetVar},
    crypto::{
        commitment::pedersen::{self, PedersenWindow},
        constraint::arkworks::{
            proof_systems::groth16::Groth16, ArkConstraintSystem, AssetBalanceVar, AssetIdVar,
        },
        ies::IES,
        merkle_tree::{
            constraint as merkle_tree_constraint, ConfigConverter as ArkMerkleTreeConfigConverter,
            Configuration as ArkMerkleTreeConfiguration,
        },
        prf::blake2s::{constraint::Blake2sVar, Blake2s},
    },
};
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::crh::pedersen::{constraints::CRHGadget, CRH};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective, Fq};
use manta_accounting::{identity, transfer};
use manta_crypto::{commitment::CommitmentScheme, merkle_tree, PseudorandomFunctionFamily};
use manta_util::rand::SeedIntoRng;
use rand_chacha::ChaCha20Rng;

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

/// Configuration Structure
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Configuration;

impl ArkMerkleTreeConfiguration for Configuration {
    type Leaf = [u8];
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
    type SecretKey = <Blake2s as PseudorandomFunctionFamily>::Seed;
    type PseudorandomFunctionFamily = Blake2s;
    type CommitmentScheme = PedersenCommitment;
    type Rng = SeedIntoRng<Self::SecretKey, ChaCha20Rng>;
}

impl identity::constraint::Configuration for Configuration {
    type ConstraintSystem = ConstraintSystem;
    type SecretKeyVar = <Blake2sVar<ConstraintField> as PseudorandomFunctionFamily>::Seed;
    type PseudorandomFunctionFamilyInputVar =
        <Blake2sVar<ConstraintField> as PseudorandomFunctionFamily>::Input;
    type PseudorandomFunctionFamilyOutputVar =
        <Blake2sVar<ConstraintField> as PseudorandomFunctionFamily>::Output;
    type PseudorandomFunctionFamilyVar = Blake2sVar<ConstraintField>;
    type CommitmentSchemeRandomnessVar = <PedersenCommitmentVar as CommitmentScheme>::Randomness;
    type CommitmentSchemeOutputVar = <PedersenCommitmentVar as CommitmentScheme>::Output;
    type CommitmentSchemeVar = PedersenCommitmentVar;
}

impl transfer::Configuration for Configuration {
    type ConstraintSystem = ConstraintSystem;
    type ProofSystem = ProofSystem;
    type AssetIdVar = AssetIdVar<ConstraintField>;
    type AssetBalanceVar = AssetBalanceVar<ConstraintField>;
    type IntegratedEncryptionScheme = IES;
    type UtxoSet = UtxoSet;
    type UtxoSetVar = UtxoSetVar;
}
