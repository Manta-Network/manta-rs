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

use crate::{
    accounting::ledger::{UtxoSet, UtxoSetVar},
    crypto::{
        commitment::pedersen::{self, PedersenWindow},
        constraint::{proof_systems::Groth16, ArkConstraintSystem, AssetBalanceVar, AssetIdVar},
        ies::IES,
        prf::blake2s::{constraint::Blake2sVar, Blake2s},
        rand::ChaCha20RngBlake2sSeedable,
    },
};
use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective, Fq};
use manta_accounting::{
    identity::{IdentityConfiguration, IdentityConstraintSystemConfiguration},
    transfer::TransferConfiguration,
};
use manta_crypto::{commitment::CommitmentScheme, PseudorandomFunctionFamily};

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

/// Constraint Field
pub type ConstraintField = Fq;

/// Constraint System
pub type ConstraintSystem = ArkConstraintSystem<ConstraintField>;

/// Proof System
pub type ProofSystem = Groth16<Bls12_381>;

/// Manta Pay Configuration
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Configuration;

impl IdentityConfiguration for Configuration {
    type SecretKey = <Blake2s as PseudorandomFunctionFamily>::Seed;
    type PseudorandomFunctionFamily = Blake2s;
    type CommitmentScheme = PedersenCommitment;
    type Rng = ChaCha20RngBlake2sSeedable;
}

impl IdentityConstraintSystemConfiguration for Configuration {
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

impl TransferConfiguration for Configuration {
    type ConstraintSystem = ConstraintSystem;
    type ProofSystem = ProofSystem;
    type AssetIdVar = AssetIdVar<ConstraintField>;
    type AssetBalanceVar = AssetBalanceVar<ConstraintField>;
    type IntegratedEncryptionScheme = IES;
    type UtxoSet = UtxoSet;
    type UtxoSetVar = UtxoSetVar;
}
