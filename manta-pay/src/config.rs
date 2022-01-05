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
    constraint::arkworks::{FpVar, Groth16, R1CS},
    ecc,
    encryption::AesGcm,
    hash::poseidon,
    key::Blake2sKdf,
};
use ark_ec::ProjectiveCurve;
use ark_ff::{BigInteger, PrimeField};
use bls12_381::Bls12_381;
use bls12_381_ed::{
    constraints::EdwardsVar as Bls12_381_EdwardsVar, EdwardsProjective as Bls12_381_Edwards,
};
use core::marker::PhantomData;
use manta_accounting::{
    asset::{Asset, AssetId, AssetValue},
    transfer,
};
use manta_crypto::{
    accumulator,
    commitment::CommitmentScheme,
    constraint::{self, Allocation, Constant, Secret, Variable, VariableSource},
    ecc::DiffieHellman,
    encryption,
    hash::{BinaryHashFunction, HashFunction},
    key::{self, KeyDerivationFunction},
    merkle_tree,
};

#[doc(inline)]
pub use ark_bls12_381 as bls12_381;
#[doc(inline)]
pub use ark_ed_on_bls12_381 as bls12_381_ed;

///
pub type PairingCurve = Bls12_381;

///
pub type Group = ecc::arkworks::Group<Bls12_381_Edwards>;

///
pub type GroupVar = ecc::arkworks::GroupVar<Bls12_381_Edwards, Bls12_381_EdwardsVar>;

/// Constraint Field
pub type ConstraintField = bls12_381::Fr;

/// Constraint Field Variable
pub type ConstraintFieldVar = FpVar<ConstraintField>;

/// Constraint Compiler
pub type Compiler = R1CS<ConstraintField>;

/// Proof System
pub type ProofSystem = Groth16<PairingCurve>;

///
pub struct PoseidonSpec<const ARITY: usize>;

impl poseidon::arkworks::Specification for PoseidonSpec<2> {
    type Field = ConstraintField;
    const FULL_ROUNDS: usize = 10;
    const PARTIAL_ROUNDS: usize = 10;
    const SBOX_EXPONENT: u64 = 5;
}

impl poseidon::arkworks::Specification for PoseidonSpec<4> {
    type Field = ConstraintField;
    const FULL_ROUNDS: usize = 10;
    const PARTIAL_ROUNDS: usize = 10;
    const SBOX_EXPONENT: u64 = 5;
}

///
pub type KeyAgreementScheme = DiffieHellman<Group>;

///
pub type KeyAgreementSchemeVar = DiffieHellman<GroupVar, Compiler>;

///
pub type Utxo = poseidon::Output<PoseidonSpec<4>, 4>;

///
pub struct UtxoCommitmentScheme(pub poseidon::Hash<PoseidonSpec<4>, 4>);

impl CommitmentScheme for UtxoCommitmentScheme {
    type Trapdoor = Group;
    type Input = Asset;
    type Output = Utxo;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut (),
    ) -> Self::Output {
        // NOTE: The group is in projective form, so we need to convert it first.
        let trapdoor = trapdoor.0.into_affine();
        self.0.hash(
            &[
                trapdoor.x,
                trapdoor.y,
                input.id.0.into(),
                input.value.0.into(),
            ],
            compiler,
        )
    }
}

///
pub type UtxoVar = poseidon::Output<PoseidonSpec<4>, 4, Compiler>;

///
pub struct UtxoCommitmentSchemeVar(pub poseidon::Hash<PoseidonSpec<4>, 4, Compiler>);

impl CommitmentScheme<Compiler> for UtxoCommitmentSchemeVar {
    type Trapdoor = GroupVar;
    type Input = Asset<AssetIdVar, AssetValueVar>;
    type Output = UtxoVar;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut Compiler,
    ) -> Self::Output {
        // NOTE: The group is already in affine form, so we can extract `x` and `y`.
        self.0.hash(
            &[
                trapdoor.0.x.clone(),
                trapdoor.0.y.clone(),
                input.id.0.clone(),
                input.value.0.clone(),
            ],
            compiler,
        )
    }
}

impl Variable<Compiler> for UtxoCommitmentSchemeVar {
    type Type = UtxoCommitmentScheme;

    type Mode = Constant;

    #[inline]
    fn new(cs: &mut Compiler, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self(this.0.as_known(cs, mode)),
            _ => unreachable!("Constants cannot be unknown."),
        }
    }
}

///
pub type VoidNumber = poseidon::Output<PoseidonSpec<2>, 2>;

///
pub struct VoidNumberHashFunction(pub poseidon::Hash<PoseidonSpec<2>, 2>);

impl BinaryHashFunction for VoidNumberHashFunction {
    type Left = Utxo;
    type Right = <KeyAgreementScheme as key::KeyAgreementScheme>::SecretKey;
    type Output = VoidNumber;

    #[inline]
    fn hash(&self, left: &Self::Left, right: &Self::Right, compiler: &mut ()) -> Self::Output {
        self.0.hash(
            &[
                *left,
                // FIXME: This is the lift from inner scalar to outer scalar and only exists in some
                // cases! We need a better abstraction for this.
                ConstraintField::from_le_bytes_mod_order(&right.into_repr().to_bytes_le()),
            ],
            compiler,
        )
    }
}

///
pub struct VoidNumberHashFunctionVar(pub poseidon::Hash<PoseidonSpec<2>, 2, Compiler>);

impl BinaryHashFunction<Compiler> for VoidNumberHashFunctionVar {
    type Left = <UtxoCommitmentSchemeVar as CommitmentScheme<Compiler>>::Output;
    type Right = <KeyAgreementSchemeVar as key::KeyAgreementScheme<Compiler>>::SecretKey;
    type Output = poseidon::Output<PoseidonSpec<2>, 2, Compiler>;

    #[inline]
    fn hash(
        &self,
        left: &Self::Left,
        right: &Self::Right,
        compiler: &mut Compiler,
    ) -> Self::Output {
        self.0.hash(&[left.clone(), right.clone()], compiler)
    }
}

impl Variable<Compiler> for VoidNumberHashFunctionVar {
    type Type = VoidNumberHashFunction;

    type Mode = Constant;

    #[inline]
    fn new(cs: &mut Compiler, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self(this.0.as_known(cs, mode)),
            _ => unreachable!("Constants cannot be unknown."),
        }
    }
}

///
pub struct AssetIdVar(ConstraintFieldVar);

impl Variable<Compiler> for AssetIdVar {
    type Type = AssetId;
    type Mode = Secret;

    #[inline]
    fn new(cs: &mut Compiler, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        Self(match allocation {
            Allocation::Known(this, mode) => {
                ConstraintFieldVar::new(cs, Allocation::Known(&this.0.into(), mode.into()))
            }
            Allocation::Unknown(mode) => {
                ConstraintFieldVar::new(cs, Allocation::Unknown(mode.into()))
            }
        })
    }
}

///
pub struct AssetValueVar(ConstraintFieldVar);

impl Variable<Compiler> for AssetValueVar {
    type Type = AssetValue;
    type Mode = Secret;

    #[inline]
    fn new(cs: &mut Compiler, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        Self(match allocation {
            Allocation::Known(this, mode) => {
                ConstraintFieldVar::new(cs, Allocation::Known(&this.0.into(), mode.into()))
            }
            Allocation::Unknown(mode) => {
                ConstraintFieldVar::new(cs, Allocation::Unknown(mode.into()))
            }
        })
    }
}

///
pub type LeafHash = merkle_tree::IdentityLeafHash<Utxo>;

///
pub type LeafHashVar = merkle_tree::IdentityLeafHash<UtxoVar, Compiler>;

///
pub struct InnerHash;

impl merkle_tree::InnerHash for InnerHash {
    type LeafDigest = Utxo;
    type Parameters = poseidon::Hash<PoseidonSpec<2>, 2>;
    type Output = poseidon::Output<PoseidonSpec<2>, 2>;

    #[inline]
    fn join_in(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut (),
    ) -> Self::Output {
        parameters.hash(&[*lhs, *rhs], compiler)
    }

    #[inline]
    fn join_leaves_in(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        compiler: &mut (),
    ) -> Self::Output {
        parameters.hash(&[*lhs, *rhs], compiler)
    }
}

/*
///
pub struct InnerHashVar;

impl merkle_tree::InnerHash<Compiler> for InnerHash {
    type LeafDigest = UtxoVar;
    type Parameters = poseidon::Hash<PoseidonSpec<2>, 2, Compiler>;
    type Output = poseidon::Output<PoseidonSpec<2>, 2, Compiler>;

    #[inline]
    fn join_in(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut COM,
    ) -> Self::Output {
        parameters.hash(&[*lhs, *rhs], compiler)
    }

    #[inline]
    fn join_leaves_in(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        compiler: &mut COM,
    ) -> Self::Output {
        parameters.hash(&[*lhs, *rhs], compiler)
    }
}
*/

/// Configuration Structure
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Config;

/*
impl transfer::Configuration for Config {
    type SecretKey = <Self::KeyAgreementScheme as key::KeyAgreementScheme>::SecretKey;
    type PublicKey = <Self::KeyAgreementScheme as key::KeyAgreementScheme>::PublicKey;
    type KeyAgreementScheme = KeyAgreementScheme;
    type SecretKeyVar =
        <Self::KeyAgreementSchemeVar as key::KeyAgreementScheme<Self::Compiler>>::SecretKey;
    type PublicKeyVar =
        <Self::KeyAgreementSchemeVar as key::KeyAgreementScheme<Self::Compiler>>::PublicKey;
    type KeyAgreementSchemeVar = KeyAgreementSchemeVar;

    type Utxo = <Self::UtxoCommitmentScheme as CommitmentScheme>::Output;
    type UtxoCommitmentScheme = UtxoCommitmentScheme;
    type UtxoVar = <Self::UtxoCommitmentSchemeVar as CommitmentScheme<Self::Compiler>>::Output;
    type UtxoCommitmentSchemeVar = UtxoCommitmentSchemeVar;

    type VoidNumber = <Self::VoidNumberHashFunction as BinaryHashFunction>::Output;
    type VoidNumberHashFunction = VoidNumberHashFunction;
    type VoidNumberVar =
        <Self::VoidNumberHashFunctionVar as BinaryHashFunction<Self::Compiler>>::Output;
    type VoidNumberHashFunctionVar = VoidNumberHashFunctionVar;

    /* TODO:
    type UtxoSetModel = merkle_tree::Parameters<()>;
    type UtxoSetWitnessVar = <Self::UtxoSetModelVar as accumulator::Model<Self::Compiler>>::Witness;
    type UtxoSetOutputVar = <Self::UtxoSetModelVar as accumulator::Model<Self::Compiler>>::Output;
    type UtxoSetModelVar = ();
    */

    type AssetIdVar = AssetIdVar;
    type AssetValueVar = AssetValueVar;

    type Compiler = Compiler;
    type ProofSystem = ProofSystem;

    type NoteEncryptionScheme = encryption::Hybrid<
        Self::KeyAgreementScheme,
        encryption::ConstantSizeSymmetricKeyEncryption<
            { Asset::SIZE },
            AesGcm<{ Asset::SIZE }>,
            Asset,
        >,
        key::kdf::FromByteVector<
            <Self::KeyAgreementScheme as key::KeyAgreementScheme>::SharedSecret,
            Blake2sKdf,
        >,
    >;
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

impl constraint::Input<Group> for ProofSystem {
    #[inline]
    fn extend(input: &mut Self::Input, next: &Group) {
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
