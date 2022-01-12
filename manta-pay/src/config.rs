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

use crate::{
    crypto::{
        constraint::arkworks::{Boolean, Fp, FpVar, Groth16, R1CS},
        ecc::{self, arkworks::ProjectiveCurve},
        encryption::aes::{self, AesGcm},
        hash::poseidon,
        key::Blake2sKdf,
    },
    key::TestnetKeySecret,
};
use ark_ff::{PrimeField, ToConstraintField};
use ark_serialize::CanonicalSerialize;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2sVar,
};
use bls12_381::Bls12_381;
use bls12_381_ed::constraints::EdwardsVar as Bls12_381_EdwardsVar;
use manta_accounting::{
    asset::{Asset, AssetId, AssetValue},
    key::HierarchicalKeyDerivationScheme,
    transfer,
};
use manta_crypto::{
    accumulator,
    commitment::CommitmentScheme,
    constraint::{
        Add, Allocator, Constant, Equal, ProofSystemInput, Public, Secret, ValueSource, Variable,
    },
    ecc::DiffieHellman,
    encryption,
    hash::{BinaryHashFunction, HashFunction},
    key,
    key::KeyDerivationFunction,
    merkle_tree,
};

#[cfg(test)]
use manta_crypto::rand::{CryptoRng, Rand, RngCore, Sample, Standard};

#[doc(inline)]
pub use ark_bls12_381 as bls12_381;
#[doc(inline)]
pub use ark_ed_on_bls12_381 as bls12_381_ed;

pub(crate) use bls12_381_ed::EdwardsProjective as Bls12_381_Edwards;

/// Pairing Curve Type
pub type PairingCurve = Bls12_381;

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

/// Proof System
pub type ProofSystem = Groth16<PairingCurve>;

/// Poseidon Specification
pub struct PoseidonSpec<const ARITY: usize>;

/// Poseidon-2 Hash Parameters
pub type Poseidon2 = poseidon::Hash<PoseidonSpec<2>, 2>;

/// Poseidon-2 Hash Parameters Variable
pub type Poseidon2Var = poseidon::Hash<PoseidonSpec<2>, 2, Compiler>;

impl poseidon::arkworks::Specification for PoseidonSpec<2> {
    type Field = ConstraintField;
    const FULL_ROUNDS: usize = 10;
    const PARTIAL_ROUNDS: usize = 10;
    const SBOX_EXPONENT: u64 = 5;
}

/// Poseidon-4 Hash Parameters
pub type Poseidon4 = poseidon::Hash<PoseidonSpec<4>, 4>;

/// Poseidon-4 Hash Parameters Variable
pub type Poseidon4Var = poseidon::Hash<PoseidonSpec<4>, 4, Compiler>;

impl poseidon::arkworks::Specification for PoseidonSpec<4> {
    type Field = ConstraintField;
    const FULL_ROUNDS: usize = 10;
    const PARTIAL_ROUNDS: usize = 10;
    const SBOX_EXPONENT: u64 = 5;
}

/// Key Agreement Scheme Type
pub type KeyAgreementScheme = DiffieHellman<Group>;

/// Secret Key Type
pub type SecretKey = <KeyAgreementScheme as key::KeyAgreementScheme>::SecretKey;

/// Public Key Type
pub type PublicKey = <KeyAgreementScheme as key::KeyAgreementScheme>::PublicKey;

/// Key Agreement Scheme Variable Type
pub type KeyAgreementSchemeVar = DiffieHellman<GroupVar, Compiler>;

/// Unspent Transaction Output Type
pub type Utxo = Fp<ConstraintField>;

/// UTXO Commitment Scheme
#[derive(Clone)]
pub struct UtxoCommitmentScheme(pub Poseidon4);

impl CommitmentScheme for UtxoCommitmentScheme {
    type Trapdoor = Group;
    type Input = Asset;
    type Output = Utxo;

    #[inline]
    fn commit_in(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        _: &mut (),
    ) -> Self::Output {
        // NOTE: The group is in projective form, so we need to convert it first.
        let trapdoor = trapdoor.0.into_affine();
        self.0.hash([
            &Fp(trapdoor.x),
            &Fp(trapdoor.y),
            &Fp(input.id.0.into()),
            &Fp(input.value.0.into()),
        ])
    }
}

#[cfg(test)] // NOTE: This is only safe in a test.
impl Sample for UtxoCommitmentScheme {
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

/// Unspent Transaction Output Variable Type
pub type UtxoVar = ConstraintFieldVar;

/// UTXO Commitment Scheme Variable
pub struct UtxoCommitmentSchemeVar(pub Poseidon4Var);

impl CommitmentScheme<Compiler> for UtxoCommitmentSchemeVar {
    type Trapdoor = GroupVar;
    type Input = Asset<AssetIdVar, AssetValueVar>;
    type Output = UtxoVar;

    #[inline]
    fn commit_in(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut Compiler,
    ) -> Self::Output {
        // NOTE: The group is already in affine form, so we can extract `x` and `y`.
        self.0.hash_in(
            [&trapdoor.0.x, &trapdoor.0.y, &input.id.0, &input.value.0],
            compiler,
        )
    }
}

impl Constant<Compiler> for UtxoCommitmentSchemeVar {
    type Type = UtxoCommitmentScheme;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

/// Void Number Type
pub type VoidNumber = Fp<ConstraintField>;

/// Void Number Hash Function
#[derive(Clone)]
pub struct VoidNumberHashFunction(pub Poseidon2);

impl BinaryHashFunction for VoidNumberHashFunction {
    type Left = Utxo;
    type Right = <KeyAgreementScheme as key::KeyAgreementScheme>::SecretKey;
    type Output = VoidNumber;

    #[inline]
    fn hash_in(&self, left: &Self::Left, right: &Self::Right, _: &mut ()) -> Self::Output {
        self.0.hash([
            left,
            // FIXME: This is the lift from inner scalar to outer scalar and only exists in some
            // cases! We need a better abstraction for this.
            &ecc::arkworks::lift_embedded_scalar::<Bls12_381_Edwards>(right),
        ])
    }
}

#[cfg(test)] // NOTE: This is only safe in a test.
impl Sample for VoidNumberHashFunction {
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

/// Void Number Variable Type
pub type VoidNumberVar = ConstraintFieldVar;

/// Void Number Hash Function Variable
pub struct VoidNumberHashFunctionVar(pub Poseidon2Var);

impl BinaryHashFunction<Compiler> for VoidNumberHashFunctionVar {
    type Left = <UtxoCommitmentSchemeVar as CommitmentScheme<Compiler>>::Output;
    type Right = <KeyAgreementSchemeVar as key::KeyAgreementScheme<Compiler>>::SecretKey;
    type Output = ConstraintFieldVar;

    #[inline]
    fn hash_in(
        &self,
        left: &Self::Left,
        right: &Self::Right,
        compiler: &mut Compiler,
    ) -> Self::Output {
        self.0.hash_in([left, &right.0], compiler)
    }
}

impl Constant<Compiler> for VoidNumberHashFunctionVar {
    type Type = VoidNumberHashFunction;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

/// Asset ID Variable
pub struct AssetIdVar(ConstraintFieldVar);

impl Equal<Compiler> for AssetIdVar {
    #[inline]
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut Compiler) -> Boolean<ConstraintField> {
        ConstraintFieldVar::eq(&lhs.0, &rhs.0, compiler)
    }
}

impl Variable<Public, Compiler> for AssetIdVar {
    type Type = AssetId;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(Fp(ConstraintField::from(this.0)).as_known::<Public, _>(compiler))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler) -> Self {
        Self(compiler.allocate_unknown::<Public, _>())
    }
}

impl Variable<Secret, Compiler> for AssetIdVar {
    type Type = AssetId;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(Fp(ConstraintField::from(this.0)).as_known::<Secret, _>(compiler))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler) -> Self {
        Self(compiler.allocate_unknown::<Secret, _>())
    }
}

/// Asset Value Variable
pub struct AssetValueVar(ConstraintFieldVar);

impl Add<Compiler> for AssetValueVar {
    #[inline]
    fn add(lhs: Self, rhs: Self, compiler: &mut Compiler) -> Self {
        Self(ConstraintFieldVar::add(lhs.0, rhs.0, compiler))
    }
}

impl Equal<Compiler> for AssetValueVar {
    #[inline]
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut Compiler) -> Boolean<ConstraintField> {
        ConstraintFieldVar::eq(&lhs.0, &rhs.0, compiler)
    }
}

impl Variable<Public, Compiler> for AssetValueVar {
    type Type = AssetValue;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(Fp(ConstraintField::from(this.0)).as_known::<Public, _>(compiler))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler) -> Self {
        Self(compiler.allocate_unknown::<Public, _>())
    }
}

impl Variable<Secret, Compiler> for AssetValueVar {
    type Type = AssetValue;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(Fp(ConstraintField::from(this.0)).as_known::<Secret, _>(compiler))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler) -> Self {
        Self(compiler.allocate_unknown::<Secret, _>())
    }
}

/// Leaf Hash Configuration Type
pub type LeafHash = merkle_tree::IdentityLeafHash<Utxo>;

/// Leaf Hash Variable Configuration Type
pub type LeafHashVar = merkle_tree::IdentityLeafHash<UtxoVar, Compiler>;

/// Inner Hash Configuration
#[derive(Clone)]
pub struct InnerHash;

impl merkle_tree::InnerHash for InnerHash {
    type LeafDigest = Utxo;
    type Parameters = Poseidon2;
    type Output = Fp<ConstraintField>;

    #[inline]
    fn join_in(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        _: &mut (),
    ) -> Self::Output {
        parameters.hash([lhs, rhs])
    }

    #[inline]
    fn join_leaves_in(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        _: &mut (),
    ) -> Self::Output {
        parameters.hash([lhs, rhs])
    }
}

/// Inner Hash Variable Configuration
pub struct InnerHashVar;

impl merkle_tree::InnerHash<Compiler> for InnerHashVar {
    type LeafDigest = UtxoVar;
    type Parameters = Poseidon2Var;
    type Output = ConstraintFieldVar;

    #[inline]
    fn join_in(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut Compiler,
    ) -> Self::Output {
        parameters.hash_in([lhs, rhs], compiler)
    }

    #[inline]
    fn join_leaves_in(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        compiler: &mut Compiler,
    ) -> Self::Output {
        parameters.hash_in([lhs, rhs], compiler)
    }
}

/// Merkle Tree Configuration
#[derive(Clone)]
pub struct MerkleTreeConfiguration;

impl merkle_tree::HashConfiguration for MerkleTreeConfiguration {
    type LeafHash = LeafHash;
    type InnerHash = InnerHash;
}

impl merkle_tree::Configuration for MerkleTreeConfiguration {
    const HEIGHT: usize = 20;
}

#[cfg(test)]
impl merkle_tree::test::HashParameterSampling for MerkleTreeConfiguration {
    type LeafHashParameterDistribution = Standard;
    type InnerHashParameterDistribution = Standard;

    #[inline]
    fn sample_leaf_hash_parameters<R>(
        distribution: Self::LeafHashParameterDistribution,
        rng: &mut R,
    ) -> merkle_tree::LeafHashParameters<Self>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = (distribution, rng);
    }

    #[inline]
    fn sample_inner_hash_parameters<R>(
        distribution: Self::InnerHashParameterDistribution,
        rng: &mut R,
    ) -> merkle_tree::InnerHashParameters<Self>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        rng.sample(distribution)
    }
}

/// Merkle Tree Variable Configuration
pub struct MerkleTreeConfigurationVar;

impl merkle_tree::HashConfiguration<Compiler> for MerkleTreeConfigurationVar {
    type LeafHash = LeafHashVar;
    type InnerHash = InnerHashVar;
}

impl merkle_tree::Configuration<Compiler> for MerkleTreeConfigurationVar {
    const HEIGHT: usize = <MerkleTreeConfiguration as merkle_tree::Configuration>::HEIGHT;
}

impl Constant<Compiler> for MerkleTreeConfigurationVar {
    type Type = MerkleTreeConfiguration;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
        let _ = (this, compiler);
        Self
    }
}

impl ProofSystemInput<AssetId> for ProofSystem {
    #[inline]
    fn extend(input: &mut Self::Input, next: &AssetId) {
        input.push(next.0.into());
    }
}

impl ProofSystemInput<AssetValue> for ProofSystem {
    #[inline]
    fn extend(input: &mut Self::Input, next: &AssetValue) {
        input.push(next.0.into());
    }
}

impl ProofSystemInput<Fp<ConstraintField>> for ProofSystem {
    #[inline]
    fn extend(input: &mut Self::Input, next: &Fp<ConstraintField>) {
        input.push(next.0);
    }
}

impl ProofSystemInput<Group> for ProofSystem {
    #[inline]
    fn extend(input: &mut Self::Input, next: &Group) {
        // FIXME: Make sure we can type check the coordinate system here.
        input.append(&mut next.0.into_affine().to_field_elements().unwrap());
    }
}

/// Note Encryption Scheme
pub type NoteEncryptionScheme = encryption::Hybrid<
    KeyAgreementScheme,
    encryption::symmetric::Map<
        AesGcm<{ Asset::SIZE }, { aes::ciphertext_size(Asset::SIZE) }>,
        Asset,
    >,
    key::kdf::FromByteVector<
        <KeyAgreementScheme as key::KeyAgreementScheme>::SharedSecret,
        Blake2sKdf,
    >,
>;

/// Base Configuration
pub struct Config;

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

    type UtxoSetModel = merkle_tree::Parameters<MerkleTreeConfiguration>;
    type UtxoSetWitnessVar = <Self::UtxoSetModelVar as accumulator::Model<Self::Compiler>>::Witness;
    type UtxoSetOutputVar = <Self::UtxoSetModelVar as accumulator::Model<Self::Compiler>>::Output;
    type UtxoSetModelVar = merkle_tree::Parameters<MerkleTreeConfigurationVar, Compiler>;

    type AssetIdVar = AssetIdVar;
    type AssetValueVar = AssetValueVar;

    type Compiler = Compiler;
    type ProofSystem = ProofSystem;

    type NoteEncryptionScheme = NoteEncryptionScheme;
}

/// Transfer Parameters
pub type Parameters = transfer::Parameters<Config>;

/// Full Transfer Parameters
pub type FullParameters<'p> = transfer::FullParameters<'p, Config>;

/// Encrypted Note Type
pub type EncryptedNote = transfer::EncryptedNote<Config>;

/// Mint Transfer Type
pub type Mint = transfer::canonical::Mint<Config>;

/// Private Transfer Type
pub type PrivateTransfer = transfer::canonical::PrivateTransfer<Config>;

/// Reclaim Transfer Type
pub type Reclaim = transfer::canonical::Reclaim<Config>;

/// Transfer Post Type
pub type TransferPost = transfer::TransferPost<Config>;

/// Proving Context Type
pub type ProvingContext = transfer::ProvingContext<Config>;

/// Verifying Context Type
pub type VerifyingContext = transfer::VerifyingContext<Config>;

/// Multi-Proving Context Type
pub type MultiProvingContext = transfer::canonical::MultiProvingContext<Config>;

/// Multi-Verifying Context Type
pub type MultiVerifyingContext = transfer::canonical::MultiVerifyingContext<Config>;

/// Hierarchical Key Derivation Function
pub struct HierarchicalKeyDerivationFunction;

impl KeyDerivationFunction for HierarchicalKeyDerivationFunction {
    type Key = <TestnetKeySecret as HierarchicalKeyDerivationScheme>::SecretKey;
    type Output = SecretKey;

    #[inline]
    fn derive(secret_key: &Self::Key) -> Self::Output {
        // FIXME: Check that this conversion is logical/safe.
        let bytes: [u8; 32] = secret_key
            .private_key()
            .to_bytes()
            .try_into()
            .expect("The private key has 32 bytes.");
        Fp(<Bls12_381_Edwards as ProjectiveCurve>::ScalarField::from_le_bytes_mod_order(&bytes))
    }
}

impl merkle_tree::forest::Configuration for MerkleTreeConfiguration {
    type Index = u8;

    #[inline]
    fn tree_index(leaf: &merkle_tree::Leaf<Self>) -> Self::Index {
        let mut hasher = Blake2sVar::new(1).unwrap();
        let mut buffer = Vec::new();
        leaf.0
            .serialize_unchecked(&mut buffer)
            .expect("Serializing is not allowed to fail.");
        hasher.update(&buffer);
        let mut result = [0];
        hasher
            .finalize_variable(&mut result)
            .expect("Hashing is not allowed to fail.");
        result[0]
    }
}
