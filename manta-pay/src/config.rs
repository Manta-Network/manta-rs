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

//! Manta-Pay Configuration

use crate::crypto::{
    commitment::{pedersen, poseidon},
    constraint::arkworks::{FpVar, Groth16, R1CS},
    encryption::AesGcm,
    key::{elliptic_curve_diffie_hellman, Blake2sKdf},
};
use ark_ec::ProjectiveCurve;
use bls12_381::Bls12_381;
use bls12_381_ed::{
    constraints::EdwardsVar as Bls12_381_EdwardsVar, EdwardsProjective as Bls12_381_Edwards,
};
use manta_accounting::{
    asset::{Asset, AssetId, AssetValue},
    transfer::{self, Utxo, VoidNumber},
};
use manta_crypto::{
    accumulator,
    commitment::CommitmentScheme,
    constraint, encryption,
    key::{self, KeyDerivationFunction},
    merkle_tree,
};

#[doc(inline)]
pub use ark_bls12_381 as bls12_381;
#[doc(inline)]
pub use ark_ed_on_bls12_381 as bls12_381_ed;

///
pub type Curve = Bls12_381;

///
pub type EmbeddedCurve = Bls12_381_Edwards;

///
pub type EmbeddedCurveVar = Bls12_381_EdwardsVar;

/// Constraint Field
pub type ConstraintField = bls12_381::Fr;

/// Constraint Field Variable
pub type ConstraintFieldVar = FpVar<ConstraintField>;

/// Constraint Compiler
pub type Compiler = R1CS<ConstraintField>;

/// Proof System
pub type ProofSystem = Groth16<Curve>;

///
pub type KeyAgreementSpec =
    elliptic_curve_diffie_hellman::arkworks::Specification<EmbeddedCurve, EmbeddedCurveVar>;

///
pub struct PoseidonSpec<const ARITY: usize>;

impl poseidon::arkworks::Specification for PoseidonSpec<2> {
    type Field = ConstraintField;
    const FULL_ROUNDS: usize = 10;
    const PARTIAL_ROUNDS: usize = 10;
    const SBOX_EXPONENT: u64 = 5;
}

///
pub type PedersenSpec = pedersen::arkworks::Specification<EmbeddedCurve, EmbeddedCurveVar>;

///
pub type KeyAgreementScheme = elliptic_curve_diffie_hellman::KeyAgreement<KeyAgreementSpec>;

///
pub type KeyAgreementSchemeVar =
    elliptic_curve_diffie_hellman::KeyAgreement<KeyAgreementSpec, Compiler>;

///
pub struct EphemeralKeyCommitmentScheme(pub poseidon::Commitment<PoseidonSpec<2>, (), 2>);

impl CommitmentScheme for EphemeralKeyCommitmentScheme {
    type Trapdoor = poseidon::Trapdoor<PoseidonSpec<2>, (), 2>;

    type Input = Asset;

    type Output = poseidon::Output<PoseidonSpec<2>, (), 2>;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut (),
    ) -> Self::Output {
        self.0.commit(
            trapdoor,
            &[input.id.0.into(), input.value.0.into()],
            compiler,
        )
    }
}

///
pub struct EphemeralKeyCommitmentSchemeVar(pub poseidon::Commitment<PoseidonSpec<2>, Compiler, 2>);

impl CommitmentScheme<Compiler> for EphemeralKeyCommitmentSchemeVar {
    type Trapdoor = poseidon::Trapdoor<PoseidonSpec<2>, Compiler, 2>;

    type Input = Asset<FpVar<ConstraintField>, FpVar<ConstraintField>>;

    type Output = poseidon::Output<PoseidonSpec<2>, Compiler, 2>;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut Compiler,
    ) -> Self::Output {
        self.0
            .commit(trapdoor, &[input.id.clone(), input.value.clone()], compiler)
    }
}

///
pub struct TrapdoorDerivationFunction(pub poseidon::Commitment<PoseidonSpec<2>, (), 2>);

impl KeyDerivationFunction for TrapdoorDerivationFunction {
    type Key = EmbeddedCurve;

    type Output = ConstraintField;

    #[inline]
    fn derive(&self, secret: Self::Key, compiler: &mut ()) -> Self::Output {
        // FIXME: We need to truncate the field element to get it to fit into an embedded scalar.
        let affine = <Self::Key as ProjectiveCurve>::Affine::from(secret);
        self.0
            .commit(&Default::default(), &[affine.x, affine.y], compiler)
    }
}

///
pub struct TrapdoorDerivationFunctionVar(pub poseidon::Commitment<PoseidonSpec<2>, Compiler, 2>);

impl KeyDerivationFunction<Compiler> for TrapdoorDerivationFunctionVar {
    type Key = EmbeddedCurveVar;

    type Output = FpVar<ConstraintField>;

    #[inline]
    fn derive(&self, secret: Self::Key, compiler: &mut Compiler) -> Self::Output {
        // FIXME: We need to truncate the field element to get it to fit into an embedded scalar.
        /* TODO:
        self.0
            .commit(&Default::default(), &[secret.x, secret.y], compiler)
        */
        todo!()
    }
}

///
pub struct UtxoCommitmentScheme(pub pedersen::Commitment<PedersenSpec, (), 2>);

impl CommitmentScheme for UtxoCommitmentScheme {
    type Trapdoor = pedersen::Trapdoor<PedersenSpec, (), 2>;
    type Input = Asset;
    type Output = pedersen::Output<PedersenSpec, (), 2>;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut (),
    ) -> Self::Output {
        self.0.commit(
            trapdoor,
            &[input.id.0.into(), input.value.0.into()],
            compiler,
        )
    }
}

///
pub struct UtxoCommitmentSchemeVar(pub pedersen::Commitment<PedersenSpec, Compiler, 2>);

impl CommitmentScheme<Compiler> for UtxoCommitmentSchemeVar {
    type Trapdoor = pedersen::Trapdoor<PedersenSpec, Compiler, 2>;
    type Input = Asset<FpVar<ConstraintField>, FpVar<ConstraintField>>;
    type Output = pedersen::Output<PedersenSpec, Compiler, 2>;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut Compiler,
    ) -> Self::Output {
        self.0
            .commit(trapdoor, &[input.id.clone(), input.value.clone()], compiler)
    }
}

///
pub struct VoidNumberCommitmentScheme(pub pedersen::Commitment<PedersenSpec, (), 1>);

impl CommitmentScheme for VoidNumberCommitmentScheme {
    type Trapdoor = pedersen::Trapdoor<PedersenSpec, (), 1>;
    type Input = <KeyAgreementScheme as key::KeyAgreementScheme>::SecretKey;
    type Output = pedersen::Output<PedersenSpec, (), 1>;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut (),
    ) -> Self::Output {
        self.0
            .commit(trapdoor, core::array::from_ref(input), compiler)
    }
}

///
pub struct VoidNumberCommitmentSchemeVar(pub pedersen::Commitment<PedersenSpec, Compiler, 1>);

impl CommitmentScheme<Compiler> for VoidNumberCommitmentSchemeVar {
    type Trapdoor = pedersen::Trapdoor<PedersenSpec, Compiler, 1>;
    type Input = <KeyAgreementSchemeVar as key::KeyAgreementScheme<Compiler>>::SecretKey;
    type Output = pedersen::Output<PedersenSpec, Compiler, 1>;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut Compiler,
    ) -> Self::Output {
        self.0
            .commit(trapdoor, core::array::from_ref(input), compiler)
    }
}

/// Configuration Structure
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Config;

/*
impl transfer::Configuration for Config {
    /* TODO:
    type SecretKey = <Self::KeyAgreementScheme as key::KeyAgreementScheme>::SecretKey;
    type PublicKey = <Self::KeyAgreementScheme as key::KeyAgreementScheme>::PublicKey;
    type KeyAgreementScheme = KeyAgreementScheme;
    type SecretKeyVar =
        <Self::KeyAgreementSchemeVar as key::KeyAgreementScheme<Self::Compiler>>::SecretKey;
    type PublicKeyVar =
        <Self::KeyAgreementSchemeVar as key::KeyAgreementScheme<Self::Compiler>>::PublicKey;
    type KeyAgreementSchemeVar = KeyAgreementSchemeVar;
    */

    /*
    type EphemeralKeyTrapdoor = <Self::EphemeralKeyCommitmentScheme as CommitmentScheme>::Trapdoor;
    type EphemeralKeyCommitmentScheme = EphemeralKeyCommitmentScheme;
    type EphemeralKeyTrapdoorVar =
        <Self::EphemeralKeyCommitmentSchemeVar as CommitmentScheme<Self::Compiler>>::Trapdoor;
    type EphemeralKeyCommitmentSchemeVar = EphemeralKeyCommitmentSchemeVar;
    */

    type TrapdoorDerivationFunction = TrapdoorDerivationFunction;
    type TrapdoorDerivationFunctionVar = TrapdoorDerivationFunctionVar;

    type Utxo = <Self::UtxoCommitmentScheme as CommitmentScheme>::Output;
    type UtxoCommitmentScheme = UtxoCommitmentScheme;
    type UtxoVar = <Self::UtxoCommitmentSchemeVar as CommitmentScheme<Self::Compiler>>::Output;
    type UtxoCommitmentSchemeVar = UtxoCommitmentSchemeVar;

    type VoidNumber = <Self::VoidNumberCommitmentScheme as CommitmentScheme>::Output;
    type VoidNumberCommitmentScheme = VoidNumberCommitmentScheme;
    type VoidNumberVar =
        <Self::VoidNumberCommitmentSchemeVar as CommitmentScheme<Self::Compiler>>::Output;
    type VoidNumberCommitmentSchemeVar = VoidNumberCommitmentSchemeVar;

    /* TODO:
    type UtxoSetModel = merkle_tree::Parameters<()>;
    type UtxoSetWitnessVar = <Self::UtxoSetModelVar as accumulator::Model<Self::Compiler>>::Witness;
    type UtxoSetOutputVar = <Self::UtxoSetModelVar as accumulator::Model<Self::Compiler>>::Output;
    type UtxoSetModelVar = ();
    */

    type AssetIdVar = ConstraintFieldVar;
    type AssetValueVar = ConstraintFieldVar;

    type Compiler = Compiler;
    type ProofSystem = ProofSystem;

    /* TODO:
    type NoteEncryptionKeyDerivationFunction =
        Blake2sKdf<<Self::KeyAgreementScheme as key::KeyAgreementScheme>::SharedSecret>;

    type NoteEncryptionScheme = encryption::Hybrid<
        Self::KeyAgreementScheme,
        AesGcm<Asset, { Asset::SIZE }>,
        Self::NoteEncryptionKeyDerivationFunction,
    >;
    */
}
*/

impl constraint::Input<AssetId> for ProofSystem {
    #[inline]
    fn extend(input: &mut Self::Input, next: &AssetId) {
        input.push(next.0.into());
    }
}

impl constraint::Input<AssetValue> for ProofSystem {
    #[inline]
    fn extend(input: &mut Self::Input, next: &AssetValue) {
        input.push(next.0.into());
    }
}

impl constraint::Input<EmbeddedCurve> for ProofSystem {
    #[inline]
    fn extend(input: &mut Self::Input, next: &EmbeddedCurve) {
        // TODO: next.extend_input(input);
        todo!()
    }
}

/* TODO:
impl constraint::Input<Root> for ProofSystem
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &Root) {
        root_extend_input(next, input);
    }
}
*/

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
