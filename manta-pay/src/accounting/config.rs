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
    accounting::ledger::UtxoSet,
    crypto::{
        commitment::pedersen::{self, PedersenWindow},
        constraint::ArkProofSystem,
        ies::IES,
        prf::blake2s::{constraint::Blake2sVar, Blake2s},
        rand::ChaCha20RngBlake2sSeedable,
    },
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective, Fq};
use manta_accounting::{
    identity::IdentityProofSystemConfiguration, transfer::TransferConfiguration,
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

/// Proof System
pub type ProofSystem = ArkProofSystem<Fq>;

/// Manta Pay Configuration
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Configuration;

impl IdentityProofSystemConfiguration for Configuration {
    type BooleanSystem = ProofSystem;
    type PseudorandomFunctionFamilySeed = <Blake2s as PseudorandomFunctionFamily>::Seed;
    type PseudorandomFunctionFamilyInput = <Blake2s as PseudorandomFunctionFamily>::Input;
    type PseudorandomFunctionFamilyOutput = <Blake2s as PseudorandomFunctionFamily>::Output;
    type PseudorandomFunctionFamily = Blake2s;
    type PseudorandomFunctionFamilyVar = Blake2sVar<Fq>;
    type CommitmentSchemeRandomness = <PedersenCommitment as CommitmentScheme>::Randomness;
    type CommitmentSchemeOutput = <PedersenCommitment as CommitmentScheme>::Output;
    type CommitmentScheme = PedersenCommitment;
    type CommitmentSchemeVar = PedersenCommitmentVar;
    type Rng = ChaCha20RngBlake2sSeedable;
}

/* TODO:
impl TransferConfiguration for Configuration {
    type ProofSystem = ArkProofSystem<Fq>;
    type IntegratedEncryptionScheme = IES;
    type UtxoPublicInput = ();
    type UtxoSecretWitness = ();
    type UtxoSet = UtxoSet;
}
*/
