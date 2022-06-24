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
    hash::poseidon::compat as poseidon,
    key::Blake2sKdf,
};
use alloc::vec::Vec;
use ark_ff::ToConstraintField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2sVar,
};
use bls12_381::Bls12_381;
use bls12_381_ed::constraints::EdwardsVar as Bls12_381_EdwardsVar;
use manta_accounting::{
    asset::{Asset, AssetId, AssetValue},
    transfer,
};
use manta_crypto::{
    accumulator,
    constraint::{
        self, Add, Allocate, Allocator, Constant, ProofSystemInput, Public, Secret, Variable,
    },
    ecc::DiffieHellman,
    encryption,
    hash::ArrayHashFunction,
    key, merkle_tree,
};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    into_array_unchecked, Array, SizeLimit,
};

#[cfg(feature = "bs58")]
use alloc::string::String;

#[cfg(any(feature = "test", test))]
use manta_crypto::rand::{Rand, RngCore, Sample};

#[doc(inline)]
pub use ark_bls12_381 as bls12_381;
#[doc(inline)]
pub use ark_ed_on_bls12_381 as bls12_381_ed;

pub(crate) use bls12_381_ed::EdwardsProjective as Bls12_381_Edwards;

/// Pairing Curve Type
pub type PairingCurve = Bls12_381;

/// Embedded Scalar Field Type
pub type EmbeddedScalarField = bls12_381_ed::Fr;

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
pub type KeyAgreementScheme = DiffieHellman<Group>;

/// Secret Key Type
pub type SecretKey = <KeyAgreementScheme as key::KeyAgreementScheme>::SecretKey;

/// Public Key Type
pub type PublicKey = <KeyAgreementScheme as key::KeyAgreementScheme>::PublicKey;

/// Key Agreement Scheme Variable Type
pub type KeyAgreementSchemeVar = DiffieHellman<GroupVar>;

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
        _: &mut (),
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
            &mut (),
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
    type SecretSpendKey = <KeyAgreementScheme as key::KeyAgreementScheme>::SecretKey;
    type Utxo = Utxo;
    type VoidNumber = VoidNumber;

    #[inline]
    fn commit(
        &self,
        secret_spend_key: &Self::SecretSpendKey,
        utxo: &Self::Utxo,
        _: &mut (),
    ) -> Self::VoidNumber {
        self.0.hash(
            [
                // FIXME: This is the lift from inner scalar to outer scalar and only exists in some
                // cases! We need a better abstraction for this.
                &ecc::arkworks::lift_embedded_scalar::<Bls12_381_Edwards>(secret_spend_key),
                utxo,
            ],
            &mut (),
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
    type SecretSpendKey = <KeyAgreementSchemeVar as key::KeyAgreementScheme<Compiler>>::SecretKey;
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

impl constraint::PartialEq<Self, Compiler> for AssetIdVar {
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

impl constraint::PartialEq<Self, Compiler> for AssetValueVar {
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
        input.append(&mut next.0.to_field_elements().unwrap());
    }
}

/// Note Plaintext Mapping
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NotePlaintextMapping;

impl encryption::symmetric::PlaintextMapping<Array<u8, { Note::SIZE }>> for NotePlaintextMapping {
    type Plaintext = Note;

    #[inline]
    fn into_base(plaintext: Self::Plaintext) -> Array<u8, { Note::SIZE }> {
        // TODO: Use a serialization method to do this.
        let mut bytes = Vec::new();
        bytes.append(&mut field_element_as_bytes(
            &plaintext.ephemeral_secret_key.0,
        ));
        bytes
            .write(&mut plaintext.asset.into_bytes().as_slice())
            .expect("This can never fail.");
        Array::from_unchecked(bytes)
    }

    #[inline]
    fn from_base(plaintext: Array<u8, { Note::SIZE }>) -> Option<Self::Plaintext> {
        // TODO: Use a deserialization method to do this.
        let mut slice = plaintext.as_ref();
        Some(Note {
            ephemeral_secret_key: Fp(EmbeddedScalarField::deserialize(&mut slice).ok()?),
            asset: Asset::from_bytes(into_array_unchecked(slice)),
        })
    }
}

/// Note Symmetric Encryption Scheme
pub type NoteSymmetricEncryptionScheme = encryption::symmetric::Map<
    FixedNonceAesGcm<{ Note::SIZE }, { aes::ciphertext_size(Note::SIZE) }>,
    NotePlaintextMapping,
>;

/// Note Encryption Scheme
pub type NoteEncryptionScheme = encryption::hybrid::Hybrid<
    KeyAgreementScheme,
    key::kdf::FromByteVector<
        <KeyAgreementScheme as key::KeyAgreementScheme>::SharedSecret,
        Blake2sKdf,
    >,
    NoteSymmetricEncryptionScheme,
>;

/// Asset Ciphertext
pub type Ciphertext =
    <NoteEncryptionScheme as encryption::symmetric::SymmetricKeyEncryptionScheme>::Ciphertext;

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
    type UtxoAccumulatorWitnessVar =
        <Self::UtxoAccumulatorModelVar as accumulator::Model<Self::Compiler>>::Witness;
    type UtxoAccumulatorOutputVar =
        <Self::UtxoAccumulatorModelVar as accumulator::Model<Self::Compiler>>::Output;
    type UtxoAccumulatorModelVar = merkle_tree::Parameters<MerkleTreeConfigurationVar, Compiler>;
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
