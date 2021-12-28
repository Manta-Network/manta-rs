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
    key::{Blake2sKdf, EllipticCurveDiffieHellman},
};
use manta_accounting::{asset::Asset, transfer};
use manta_crypto::{
    accumulator,
    commitment::CommitmentScheme,
    encryption,
    key::{KeyAgreementScheme, KeyDerivationFunction},
    merkle_tree,
};

#[doc(inline)]
pub use ark_bls12_381 as bls12_381;
#[doc(inline)]
pub use ark_ed_on_bls12_381 as bls12_381_ed;

/// BLS12-381 Pairing Engine
pub use bls12_381::Bls12_381;

///
pub use bls12_381_ed::EdwardsProjective as Bls12_381_Edwards;

///
pub use bls12_381_ed::constraints::EdwardsVar as Bls12_381_EdwardsVar;

/// Constraint Field
pub type ConstraintField = bls12_381::Fr;

///
pub type KeyAgreement = EllipticCurveDiffieHellman<Bls12_381_Edwards, Bls12_381_EdwardsVar>;

/// Constraint Compiler
pub type Compiler = R1CS<ConstraintField>;

/// Proof System
pub type ProofSystem = Groth16<Bls12_381>;

///
pub struct PoseidonSpec<const ARITY: usize>;

impl poseidon::arkworks::Specification for PoseidonSpec<2> {
    type Field = ConstraintField;
    const FULL_ROUNDS: usize = 10;
    const PARTIAL_ROUNDS: usize = 10;
    const SBOX_EXPONENT: u64 = 5;
}

///
pub type PedersenSpec = pedersen::arkworks::Specification<Bls12_381_Edwards>;

///
pub struct EphemeralKeyCommitmentScheme;

impl CommitmentScheme for EphemeralKeyCommitmentScheme {
    type Parameters = poseidon::Parameters<PoseidonSpec<2>, (), 2>;

    type Trapdoor = poseidon::Trapdoor<PoseidonSpec<2>, (), 2>;

    type Input = Asset;

    type Output = poseidon::Output<PoseidonSpec<2>, (), 2>;

    #[inline]
    fn commit(
        compiler: &mut (),
        parameters: &Self::Parameters,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
    ) -> Self::Output {
        poseidon::Commitment::<PoseidonSpec<2>, (), 2>::commit(
            compiler,
            parameters,
            trapdoor,
            &[input.id.0.into(), input.value.0.into()],
        )
    }
}

/*
impl CommitmentScheme<Compiler> for EphemeralKeyCommitmentScheme {
    type Parameters = poseidon::Parameters<Self, Compiler, 2>;

    type Trapdoor = poseidon::Trapdoor<Self, Compiler, 2>;

    type Input = Asset<FpVar<Compiler>, FpVar<Compiler>>;

    type Output = poseidon::Output<Self, Compiler, 2>;

    #[inline]
    fn commit(
        compiler: &mut Compiler,
        parameters: &Self::Parameters,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
    ) -> Self::Output {
        poseidon::Commitment::<Self, Compiler, 2>::commit(
            compiler,
            parameters,
            trapdoor,
            &[input.id.0.into(), input.value.0.into()],
        )
    }
}
*/

///
pub struct TrapdoorDerivationFunction;

impl KeyDerivationFunction for TrapdoorDerivationFunction {
    type Key = ();

    type Output = ();

    #[inline]
    fn derive(compiler: &mut (), secret: Self::Key) -> Self::Output {
        /* TODO:
        poseidon::Commitment::<PoseidonSpec<2>, (), 2>::commit(
            compiler,
            parameters,
            Default::default(),
            &[secret.x.into(), secret.y.into()],
        )
        */
        todo!()
    }
}

impl KeyDerivationFunction<Compiler> for TrapdoorDerivationFunction {
    type Key = ();

    type Output = ();

    #[inline]
    fn derive(compiler: &mut Compiler, secret: Self::Key) -> Self::Output {
        todo!()
    }
}

///
pub struct UtxoCommitmentScheme;

impl CommitmentScheme for UtxoCommitmentScheme {
    type Parameters = pedersen::Parameters<PedersenSpec, (), 2>;
    type Trapdoor = pedersen::Trapdoor<PedersenSpec, (), 2>;
    type Input = Asset;
    type Output = pedersen::Output<PedersenSpec, (), 2>;

    #[inline]
    fn commit(
        compiler: &mut (),
        parameters: &Self::Parameters,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
    ) -> Self::Output {
        pedersen::Commitment::<PedersenSpec, (), 2>::commit(
            compiler,
            parameters,
            trapdoor,
            &[input.id.0.into(), input.value.0.into()],
        )
    }
}

/*
impl CommitmentScheme<Compiler> for UtxoCommitmentScheme {}
*/

///
pub struct VoidNumberCommitmentScheme;

impl CommitmentScheme for VoidNumberCommitmentScheme {
    type Parameters = pedersen::Parameters<PedersenSpec, (), 1>;
    type Trapdoor = pedersen::Trapdoor<PedersenSpec, (), 2>;
    type Input = <KeyAgreement as KeyAgreementScheme>::SecretKey;
    type Output = pedersen::Output<PedersenSpec, (), 1>;

    #[inline]
    fn commit(
        compiler: &mut (),
        parameters: &Self::Parameters,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
    ) -> Self::Output {
        pedersen::Commitment::<PedersenSpec, (), 1>::commit(
            compiler,
            parameters,
            trapdoor,
            core::array::from_ref(input),
        )
    }
}

/*
impl CommitmentScheme<Compiler> for VoidNumberCommitmentScheme {}
*/

///
pub struct UtxoSetVerifier;

/*
impl accumulator::Verifier for UtxoSetVerifier {}

impl accumulator::Verifier<Compiler> for UtxoSetVerifier {}
*/

/// Configuration Structure
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Config;

/*
impl transfer::Configuration for Config {
    type SecretKey = <Self::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;
    type SecretKeyVar = <Self::KeyAgreementScheme as KeyAgreementScheme<Self::Compiler>>::SecretKey;
    type PublicKey = <Self::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;
    type PublicKeyVar = <Self::KeyAgreementScheme as KeyAgreementScheme<Self::Compiler>>::PublicKey;
    type KeyAgreementScheme = KeyAgreement;

    type EphemeralKeyTrapdoor = <Self::EphemeralKeyCommitmentScheme as CommitmentScheme>::Trapdoor;
    type EphemeralKeyTrapdoorVar =
        <Self::EphemeralKeyCommitmentScheme as CommitmentScheme<Self::Compiler>>::Trapdoor;
    type EphemeralKeyParametersVar =
        <Self::EphemeralKeyCommitmentScheme as CommitmentScheme<Self::Compiler>>::Parameters;
    type EphemeralKeyCommitmentScheme = EphemeralKeyCommitmentScheme;

    type TrapdoorDerivationFunction = TrapdoorDerivationFunction;

    type UtxoCommitmentParametersVar =
        <Self::UtxoCommitmentScheme as CommitmentScheme<Self::Compiler>>::Parameters;
    type Utxo = <Self::UtxoCommitmentScheme as CommitmentScheme>::Output;
    type UtxoCommitmentScheme = UtxoCommitmentScheme;

    type VoidNumberCommitmentParametersVar =
        <Self::VoidNumberCommitmentScheme as CommitmentScheme<Self::Compiler>>::Parameters;
    type VoidNumber = <Self::VoidNumberCommitmentScheme as CommitmentScheme>::Output;
    type VoidNumberCommitmentScheme = VoidNumberCommitmentScheme;

    type UtxoSetParametersVar =
        <Self::UtxoSetVerifier as accumulator::Verifier<Self::Compiler>>::Parameters;
    type UtxoSetWitnessVar =
        <Self::UtxoSetVerifier as accumulator::Verifier<Self::Compiler>>::Witness;
    type UtxoSetOutputVar =
        <Self::UtxoSetVerifier as accumulator::Verifier<Self::Compiler>>::Output;
    type UtxoSetVerifier = UtxoSetVerifier;

    type AssetIdVar = FpVar<ConstraintField>;
    type AssetValueVar = FpVar<ConstraintField>;

    type Compiler = Compiler;
    type ProofSystem = ProofSystem;

    type NoteEncryptionScheme = encryption::Hybrid<
        Self::KeyAgreementScheme,
        AesGcm<Asset, { Asset::SIZE }>,
        Blake2sKdf<<Self::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret>,
    >;
}
*/

/* TODO:
impl<E> Input<AssetId> for Groth16<E>
where
    E: PairingEngine,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &AssetId) {
        input.push(next.0.into());
        input.append(&mut next.into_bytes().to_field_elements().unwrap());
    }
}

impl<E> Input<AssetValue> for Groth16<E>
where
    E: PairingEngine,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &AssetValue) {
        input.push(next.0.into());
        input.append(&mut next.into_bytes().to_field_elements().unwrap());
    }
}

impl<E> Input<VoidNumber> for Groth16<E>
where
    E: PairingEngine,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &VoidNumber) {
        next.extend_input(input);
    }
}

impl<E> Input<Root> for Groth16<E>
where
    E: PairingEngine<Fr = ark_ff::Fp256<ark_bls12_381::FrParameters>>,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &Root) {
        root_extend_input(next, input);
    }
}

impl<E> Input<Utxo> for Groth16<E>
where
    E: PairingEngine,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &Utxo) {
        next.extend_input(input);
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
