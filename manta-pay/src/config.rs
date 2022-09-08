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
    constraint::arkworks::{field_element_as_bytes, groth16, Boolean, Fp, FpVar, R1CS},
    ecc,
    encryption::aes::{self, FixedNonceAesGcm},
    key::Blake2sKdf,
    poseidon::compat as poseidon,
};
use alloc::vec::Vec;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2sVar,
};
use manta_accounting::{
    asset::{Asset, AssetId, AssetValue},
    transfer,
};
use manta_crypto::{
    accumulator,
    algebra::DiffieHellman,
    arkworks::{
        bls12_381::{self, Bls12_381},
        ed_on_bls12_381::{self, constraints::EdwardsVar as Bls12_381_EdwardsVar},
        ff::ToConstraintField,
        serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError},
    },
    constraint::Input,
    eclair::{
        self,
        alloc::{
            mode::{Public, Secret},
            Allocate, Allocator, Constant, Variable,
        },
        ops::Add,
    },
    encryption,
    hash::ArrayHashFunction,
    key::{self, kdf::KeyDerivationFunction},
    merkle_tree,
};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    into_array_unchecked, Array, AsBytes, SizeLimit,
};

#[cfg(feature = "bs58")]
use alloc::string::String;

#[cfg(any(feature = "test", test))]
use manta_crypto::rand::{Rand, RngCore, Sample};

pub(crate) use ed_on_bls12_381::EdwardsProjective as Bls12_381_Edwards;

/// Pairing Curve Type
pub type PairingCurve = Bls12_381;

/// Embedded Scalar Field Type
pub type EmbeddedScalarField = ed_on_bls12_381::Fr;

/// Embedded Scalar Type
pub type EmbeddedScalar = ecc::arkworks::Scalar<Bls12_381_Edwards>;

/// Embedded Scalar Variable Type
pub type EmbeddedScalarVar = ecc::arkworks::ScalarVar<Bls12_381_Edwards, Bls12_381_EdwardsVar>;

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

/// Proof System Proof
pub type Proof = groth16::Proof<PairingCurve>;

/// Proof System
pub type ProofSystem = groth16::Groth16<PairingCurve>;

/// Proof System Error
pub type ProofSystemError = groth16::Error;

/// Poseidon Specification
pub struct PoseidonSpec<const ARITY: usize>;

impl<COM, const ARITY: usize> Constant<COM> for PoseidonSpec<ARITY> {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

/// Poseidon-2 Hash Parameters
pub type Poseidon2 = poseidon::Hasher<PoseidonSpec<2>, 2>;

/// Poseidon-2 Hash Parameters Variable
pub type Poseidon2Var = poseidon::Hasher<PoseidonSpec<2>, 2, Compiler>;

impl poseidon::arkworks::Specification for PoseidonSpec<2> {
    type Field = ConstraintField;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 57;
    const SBOX_EXPONENT: u64 = 5;
}

/// Poseidon-4 Hash Parameters
pub type Poseidon4 = poseidon::Hasher<PoseidonSpec<4>, 4>;

/// Poseidon-4 Hash Parameters Variable
pub type Poseidon4Var = poseidon::Hasher<PoseidonSpec<4>, 4, Compiler>;

impl poseidon::arkworks::Specification for PoseidonSpec<4> {
    type Field = ConstraintField;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 60;
    const SBOX_EXPONENT: u64 = 5;
}

/// Key Agreement Scheme Type
pub type KeyAgreementScheme = DiffieHellman<EmbeddedScalar, Group>;

/// Secret Key Type
pub type SecretKey = <KeyAgreementScheme as key::agreement::Types>::SecretKey;

/// Public Key Type
pub type PublicKey = <KeyAgreementScheme as key::agreement::Types>::PublicKey;

/// Shared Secret Type
pub type SharedSecret = <KeyAgreementScheme as key::agreement::Types>::SharedSecret;

/// Key Agreement Scheme Variable Type
pub type KeyAgreementSchemeVar = DiffieHellman<EmbeddedScalarVar, GroupVar>;

/// Secret Key Variable Type
pub type SecretKeyVar = <KeyAgreementSchemeVar as key::agreement::Types>::SecretKey;

/// Public Key Variable Type
pub type PublicKeyVar = <KeyAgreementSchemeVar as key::agreement::Types>::PublicKey;

/// Unspent Transaction Output Type
pub type Utxo = Fp<ConstraintField>;

/// UTXO Commitment Scheme
#[derive(Clone, Debug)]
pub struct UtxoCommitmentScheme(pub Poseidon4);

impl transfer::UtxoCommitmentScheme for UtxoCommitmentScheme {
    type EphemeralSecretKey = EmbeddedScalar;
    type PublicSpendKey = Group;
    type Asset = Asset;
    type Utxo = Utxo;

    #[inline]
    fn commit(
        &self,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        public_spend_key: &Self::PublicSpendKey,
        asset: &Self::Asset,
        compiler: &mut (),
    ) -> Self::Utxo {
        self.0.hash(
            [
                // FIXME: This is the lift from inner scalar to outer scalar and only exists in some
                // cases! We need a better abstraction for this.
                &ecc::arkworks::lift_embedded_scalar::<Bls12_381_Edwards>(ephemeral_secret_key),
                &Fp(public_spend_key.0.x), // NOTE: Group is in affine form, so we can extract `x`.
                &Fp(asset.id.0.into()),
                &Fp(asset.value.0.into()),
            ],
            compiler,
        )
    }
}

impl Decode for UtxoCommitmentScheme {
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self(Poseidon4::decode(reader)?))
    }
}

impl Encode for UtxoCommitmentScheme {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.0.encode(writer)
    }
}

#[cfg(any(feature = "test", test))] // NOTE: This is only safe in a test.
impl Sample for UtxoCommitmentScheme {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

/// Unspent Transaction Output Variable Type
pub type UtxoVar = ConstraintFieldVar;

/// UTXO Commitment Scheme Variable
pub struct UtxoCommitmentSchemeVar(pub Poseidon4Var);

impl transfer::UtxoCommitmentScheme<Compiler> for UtxoCommitmentSchemeVar {
    type EphemeralSecretKey = EmbeddedScalarVar;
    type PublicSpendKey = GroupVar;
    type Asset = Asset<AssetIdVar, AssetValueVar>;
    type Utxo = UtxoVar;

    #[inline]
    fn commit(
        &self,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        public_spend_key: &Self::PublicSpendKey,
        asset: &Self::Asset,
        compiler: &mut Compiler,
    ) -> Self::Utxo {
        self.0.hash(
            [
                &ephemeral_secret_key.0,
                &public_spend_key.0.x, // NOTE: Group is in affine form, so we can extract `x`.
                &asset.id.0,
                &asset.value.0,
            ],
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

/// Void Number Commitment Scheme
#[derive(Clone, Debug)]
pub struct VoidNumberCommitmentScheme(pub Poseidon2);

impl transfer::VoidNumberCommitmentScheme for VoidNumberCommitmentScheme {
    type SecretSpendKey = SecretKey;
    type Utxo = Utxo;
    type VoidNumber = VoidNumber;

    #[inline]
    fn commit(
        &self,
        secret_spend_key: &Self::SecretSpendKey,
        utxo: &Self::Utxo,
        compiler: &mut (),
    ) -> Self::VoidNumber {
        self.0.hash(
            [
                // FIXME: This is the lift from inner scalar to outer scalar and only exists in some
                // cases! We need a better abstraction for this.
                &ecc::arkworks::lift_embedded_scalar::<Bls12_381_Edwards>(secret_spend_key),
                utxo,
            ],
            compiler,
        )
    }
}

impl Decode for VoidNumberCommitmentScheme {
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self(Poseidon2::decode(reader)?))
    }
}

impl Encode for VoidNumberCommitmentScheme {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.0.encode(writer)
    }
}

#[cfg(any(feature = "test", test))] // NOTE: This is only safe in a test.
impl Sample for VoidNumberCommitmentScheme {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

/// Void Number Variable Type
pub type VoidNumberVar = ConstraintFieldVar;

/// Void Number Commitment Scheme Variable
pub struct VoidNumberCommitmentSchemeVar(pub Poseidon2Var);

impl transfer::VoidNumberCommitmentScheme<Compiler> for VoidNumberCommitmentSchemeVar {
    type SecretSpendKey = SecretKeyVar;
    type Utxo = <UtxoCommitmentSchemeVar as transfer::UtxoCommitmentScheme<Compiler>>::Utxo;
    type VoidNumber = ConstraintFieldVar;

    #[inline]
    fn commit(
        &self,
        secret_spend_key: &Self::SecretSpendKey,
        utxo: &Self::Utxo,
        compiler: &mut Compiler,
    ) -> Self::VoidNumber {
        self.0.hash([&secret_spend_key.0, utxo], compiler)
    }
}

impl Constant<Compiler> for VoidNumberCommitmentSchemeVar {
    type Type = VoidNumberCommitmentScheme;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

/// Asset ID Variable
pub struct AssetIdVar(ConstraintFieldVar);

impl eclair::cmp::PartialEq<Self, Compiler> for AssetIdVar {
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut Compiler) -> Boolean<ConstraintField> {
        ConstraintFieldVar::eq(&self.0, &rhs.0, compiler)
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

impl Add<Self, Compiler> for AssetValueVar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self, compiler: &mut Compiler) -> Self::Output {
        Self(ConstraintFieldVar::add(self.0, rhs.0, compiler))
    }
}

impl eclair::cmp::PartialEq<Self, Compiler> for AssetValueVar {
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut Compiler) -> Boolean<ConstraintField> {
        ConstraintFieldVar::eq(&self.0, &rhs.0, compiler)
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
pub struct InnerHash;

impl merkle_tree::InnerHash for InnerHash {
    type LeafDigest = Utxo;
    type Parameters = Poseidon2;
    type Output = Fp<ConstraintField>;

    #[inline]
    fn join(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut (),
    ) -> Self::Output {
        parameters.hash([lhs, rhs], compiler)
    }

    #[inline]
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        compiler: &mut (),
    ) -> Self::Output {
        parameters.hash([lhs, rhs], compiler)
    }
}

/// Inner Hash Variable Configuration
pub struct InnerHashVar;

impl merkle_tree::InnerHash<Compiler> for InnerHashVar {
    type LeafDigest = UtxoVar;
    type Parameters = Poseidon2Var;
    type Output = ConstraintFieldVar;

    #[inline]
    fn join(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut Compiler,
    ) -> Self::Output {
        parameters.hash([lhs, rhs], compiler)
    }

    #[inline]
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        compiler: &mut Compiler,
    ) -> Self::Output {
        parameters.hash([lhs, rhs], compiler)
    }
}

/// UTXO Accumulator Model
pub type UtxoAccumulatorModel = merkle_tree::Parameters<MerkleTreeConfiguration>;

/// UTXO Accumulator Output
pub type UtxoAccumulatorOutput = merkle_tree::Root<MerkleTreeConfiguration>;

/// Merkle Tree Configuration
pub struct MerkleTreeConfiguration;

impl merkle_tree::HashConfiguration for MerkleTreeConfiguration {
    type LeafHash = LeafHash;
    type InnerHash = InnerHash;
}

impl merkle_tree::Configuration for MerkleTreeConfiguration {
    const HEIGHT: usize = 20;
}

impl MerkleTreeConfiguration {
    /// Width of the Merkle Forest
    pub const FOREST_WIDTH: usize = 256;
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

/* NOTE: Configuration for testing single-tree forest.
impl MerkleTreeConfiguration {
    /// Width of the Merkle Forest
    pub const FOREST_WIDTH: usize = 1;
}
impl merkle_tree::forest::Configuration for MerkleTreeConfiguration {
    type Index = merkle_tree::forest::SingleTreeIndex;
    #[inline]
    fn tree_index(leaf: &merkle_tree::Leaf<Self>) -> Self::Index {
        let _ = leaf;
        Default::default()
    }
}
*/

#[cfg(any(feature = "test", test))]
impl merkle_tree::test::HashParameterSampling for MerkleTreeConfiguration {
    type LeafHashParameterDistribution = ();
    type InnerHashParameterDistribution = ();

    #[inline]
    fn sample_leaf_hash_parameters<R>(
        distribution: Self::LeafHashParameterDistribution,
        rng: &mut R,
    ) -> merkle_tree::LeafHashParameters<Self>
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
    }

    #[inline]
    fn sample_inner_hash_parameters<R>(
        distribution: Self::InnerHashParameterDistribution,
        rng: &mut R,
    ) -> merkle_tree::InnerHashParameters<Self>
    where
        R: RngCore + ?Sized,
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

impl Input<ProofSystem> for AssetId {
    #[inline]
    fn extend(&self, input: &mut Vec<ConstraintField>) {
        input.push(self.0.into());
    }
}

impl Input<ProofSystem> for AssetValue {
    #[inline]
    fn extend(&self, input: &mut Vec<ConstraintField>) {
        input.push(self.0.into());
    }
}

impl Input<ProofSystem> for Group {
    #[inline]
    fn extend(&self, input: &mut Vec<ConstraintField>) {
        input.append(&mut self.0.to_field_elements().unwrap());
    }
}

/// Note Plaintext Mapping
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NotePlaintextMapping;

impl encryption::PlaintextType for NotePlaintextMapping {
    type Plaintext = Note;
}

impl encryption::convert::plaintext::Forward for NotePlaintextMapping {
    type TargetPlaintext = Array<u8, { Note::SIZE }>;

    #[inline]
    fn as_target(source: &Self::Plaintext, _: &mut ()) -> Self::TargetPlaintext {
        let mut bytes = Vec::new();
        bytes.append(&mut field_element_as_bytes(&source.ephemeral_secret_key.0));
        bytes
            .write(&mut source.asset.into_bytes().as_slice())
            .expect("This can never fail.");
        Array::from_unchecked(bytes)
    }
}

impl encryption::DecryptedPlaintextType for NotePlaintextMapping {
    type DecryptedPlaintext = Option<Note>;
}

impl encryption::convert::plaintext::Reverse for NotePlaintextMapping {
    type TargetDecryptedPlaintext = Option<Array<u8, { Note::SIZE }>>;

    #[inline]
    fn into_source(target: Self::TargetDecryptedPlaintext, _: &mut ()) -> Self::DecryptedPlaintext {
        // TODO: Use a deserialization method to do this.
        let target = target?;
        let mut slice = target.as_ref();
        Some(Note {
            ephemeral_secret_key: Fp(EmbeddedScalarField::deserialize(&mut slice).ok()?),
            asset: Asset::from_bytes(into_array_unchecked(slice)),
        })
    }
}

/// Note Encryption KDF
pub struct NoteEncryptionKDF;

impl encryption::EncryptionKeyType for NoteEncryptionKDF {
    type EncryptionKey = Group;
}

impl encryption::DecryptionKeyType for NoteEncryptionKDF {
    type DecryptionKey = Group;
}

impl encryption::convert::key::Encryption for NoteEncryptionKDF {
    type TargetEncryptionKey = [u8; 32];

    #[inline]
    fn as_target(source: &Self::EncryptionKey, compiler: &mut ()) -> Self::TargetEncryptionKey {
        Blake2sKdf.derive(&source.as_bytes(), compiler)
    }
}
impl encryption::convert::key::Decryption for NoteEncryptionKDF {
    type TargetDecryptionKey = [u8; 32];

    #[inline]
    fn as_target(source: &Self::DecryptionKey, compiler: &mut ()) -> Self::TargetDecryptionKey {
        Blake2sKdf.derive(&source.as_bytes(), compiler)
    }
}

/// Note Symmetric Encryption Scheme
pub type NoteSymmetricEncryptionScheme = encryption::convert::key::Converter<
    encryption::convert::plaintext::Converter<
        FixedNonceAesGcm<{ Note::SIZE }, { aes::ciphertext_size(Note::SIZE) }>,
        NotePlaintextMapping,
    >,
    NoteEncryptionKDF,
>;

/// Note Encryption Scheme
pub type NoteEncryptionScheme =
    encryption::hybrid::Hybrid<KeyAgreementScheme, NoteSymmetricEncryptionScheme>;

/// Base Configuration
pub struct Config;

impl transfer::Configuration for Config {
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type KeyAgreementScheme = KeyAgreementScheme;
    type SecretKeyVar = SecretKeyVar;
    type PublicKeyVar = PublicKeyVar;
    type KeyAgreementSchemeVar = KeyAgreementSchemeVar;
    type Utxo = <Self::UtxoCommitmentScheme as transfer::UtxoCommitmentScheme>::Utxo;
    type UtxoCommitmentScheme = UtxoCommitmentScheme;
    type UtxoVar =
        <Self::UtxoCommitmentSchemeVar as transfer::UtxoCommitmentScheme<Self::Compiler>>::Utxo;
    type UtxoCommitmentSchemeVar = UtxoCommitmentSchemeVar;
    type VoidNumber =
        <Self::VoidNumberCommitmentScheme as transfer::VoidNumberCommitmentScheme>::VoidNumber;
    type VoidNumberCommitmentScheme = VoidNumberCommitmentScheme;
    type VoidNumberVar =
        <Self::VoidNumberCommitmentSchemeVar as transfer::VoidNumberCommitmentScheme<
            Self::Compiler,
        >>::VoidNumber;
    type VoidNumberCommitmentSchemeVar = VoidNumberCommitmentSchemeVar;
    type UtxoAccumulatorModel = UtxoAccumulatorModel;
    type UtxoAccumulatorWitnessVar = <Self::UtxoAccumulatorModelVar as accumulator::Types>::Witness;
    type UtxoAccumulatorOutputVar = <Self::UtxoAccumulatorModelVar as accumulator::Types>::Output;
    type UtxoAccumulatorModelVar = merkle_tree::Parameters<MerkleTreeConfigurationVar, Compiler>;
    type AssetIdVar = AssetIdVar;
    type AssetValueVar = AssetValueVar;
    type Compiler = Compiler;
    type ProofSystem = ProofSystem;
    type NoteEncryptionScheme = NoteSymmetricEncryptionScheme;
}

/// Transfer Parameters
pub type Parameters = transfer::Parameters<Config>;

/// Full Transfer Parameters
pub type FullParameters<'p> = transfer::FullParameters<'p, Config>;

/// Note Type
pub type Note = transfer::Note<Config>;

/// Encrypted Note Type
pub type EncryptedNote = transfer::EncryptedNote<Config>;

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

/// Mint Transfer Type
pub type Mint = transfer::canonical::Mint<Config>;

/// Private Transfer Type
pub type PrivateTransfer = transfer::canonical::PrivateTransfer<Config>;

/// Reclaim Transfer Type
pub type Reclaim = transfer::canonical::Reclaim<Config>;

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

/// Receiving Key Type
pub type ReceivingKey = transfer::ReceivingKey<Config>;

/// Converts a [`ReceivingKey`] into a base58-encoded string.
#[cfg(feature = "bs58")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bs58")))]
#[inline]
pub fn receiving_key_to_base58(receiving_key: &ReceivingKey) -> String {
    let mut bytes = Vec::new();
    receiving_key
        .spend
        .encode(&mut bytes)
        .expect("Encoding is not allowed to fail.");
    receiving_key
        .view
        .encode(&mut bytes)
        .expect("Encoding is not allowed to fail.");
    bs58::encode(bytes).into_string()
}

/// Converts a base58-encoded string into a [`ReceivingKey`].
#[cfg(feature = "bs58")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bs58")))]
#[inline]
pub fn receiving_key_from_base58(string: &str) -> Option<ReceivingKey> {
    let bytes = bs58::decode(string.as_bytes()).into_vec().ok()?;
    let (spend, view) = bytes.split_at(bytes.len() / 2);
    Some(ReceivingKey {
        spend: spend.to_owned().try_into().ok()?,
        view: view.to_owned().try_into().ok()?,
    })
}
