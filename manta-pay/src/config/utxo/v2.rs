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

//! Manta-Pay UTXO Model Version 2 Configuration

use crate::{
    config::{
        poseidon::{
            Spec2 as Poseidon2, Spec3 as Poseidon3, Spec4 as Poseidon4, Spec5 as Poseidon5,
        },
        Compiler, ConstraintField, EmbeddedScalar, EmbeddedScalarField, EmbeddedScalarVar, Group,
        GroupCurve, GroupVar,
    },
    crypto::{
        constraint::arkworks::{codec::SerializationError, rem_mod_prime, Boolean, Fp, FpVar},
        encryption::aes,
        poseidon::{self, encryption::BlockArray, hash::Hasher, ParameterFieldType},
    },
    util::utxo_utilities,
};
use alloc::{vec, vec::Vec};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2s256, Blake2sVar, Digest,
};
use core::{fmt::Debug, marker::PhantomData};
use manta_accounting::{
    asset::{self, Asset},
    wallet::ledger,
};
use manta_crypto::{
    accumulator::ItemHashFunction,
    algebra::HasGenerator,
    arkworks::{
        algebra::{affine_point_as_bytes, ScalarVar},
        ff::{try_into_u128, PrimeField, ToConstraintField},
        r1cs_std::R1CSVar,
        serialize::CanonicalSerialize,
    },
    eclair::{
        alloc::{Allocate, Constant},
        num::U128,
    },
    encryption::{self, EmptyHeader},
    hash,
    hash::ArrayHashFunction,
    merkle_tree::{self, partial::Partial},
    rand::{Rand, RngCore, Sample},
    signature::schnorr,
};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    Array,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub use manta_accounting::transfer::{
    self,
    utxo::{self, v2 as protocol},
};

/// Asset Id Type
pub type AssetId = Fp<ConstraintField>;

/// Asset Id Variable Type
pub type AssetIdVar = FpVar<ConstraintField>;

/// Asset Value Type
pub type AssetValue = u128;

/// Asset Value Variable Type
pub type AssetValueVar = U128<FpVar<ConstraintField>>;

/// Authorization Context Type
pub type AuthorizationContext = utxo::auth::AuthorizationContext<Parameters>;

/// Authorization Context Variable Type
pub type AuthorizationContextVar = utxo::auth::AuthorizationContext<ParametersVar>;

/// Authorization Proof Type
pub type AuthorizationProof = utxo::auth::AuthorizationProof<Parameters>;

/// Authorization Proof Variable Type
pub type AuthorizationProofVar = utxo::auth::AuthorizationProof<ParametersVar>;

/// Authorization Signature Type
pub type AuthorizationSignature = utxo::auth::AuthorizationSignature<Parameters>;

/// Proof Authorization Key Type
pub type ProofAuthorizationKey = Group;

///
pub type ProofAuthorizationKeyVar = GroupVar;

///
pub type ViewingKey = EmbeddedScalar;

///
pub type ViewingKeyVar = EmbeddedScalarVar;

///
pub type ReceivingKey = Group;

///
pub type ReceivingKeyVar = GroupVar;

///
pub type UtxoAccumulatorItem = Fp<ConstraintField>;

///
pub type UtxoAccumulatorItemVar = FpVar<ConstraintField>;

///
pub type UtxoAccumulatorWitness = utxo::UtxoAccumulatorWitness<Parameters>;

///
pub type UtxoAccumulatorWitnessVar = utxo::UtxoAccumulatorWitness<ParametersVar, Compiler>;

///
pub type UtxoAccumulatorOutput = utxo::UtxoAccumulatorOutput<Parameters>;

///
pub type UtxoAccumulatorOutputVar = utxo::UtxoAccumulatorOutput<ParametersVar, Compiler>;

///
pub type SignatureScheme = protocol::SignatureScheme<Config>;

///
pub type Parameters = protocol::Parameters<Config>;

///
pub type ParametersVar = protocol::BaseParameters<Config<Compiler>, Compiler>;

///
pub type AssociatedData = utxo::AssociatedData<Parameters>;

///
pub type Utxo = utxo::Utxo<Parameters>;

///
pub type UtxoVar = utxo::Utxo<ParametersVar>;

///
pub type Note = utxo::Note<Parameters>;

///
pub type NoteVar = utxo::Note<ParametersVar>;

///
pub type IncomingNote = protocol::IncomingNote<Config>;

///
pub type FullIncomingNote = protocol::FullIncomingNote<Config>;

///
pub type OutgoingNote = protocol::OutgoingNote<Config>;

///
pub type Nullifier = utxo::Nullifier<Parameters>;

///
pub type NullifierVar = utxo::Nullifier<ParametersVar>;

///
pub type Identifier = utxo::Identifier<Parameters>;

///
pub type Address = utxo::Address<Parameters>;

///
pub type MintSecret = protocol::MintSecret<Config>;

///
pub type MintSecretVar = protocol::MintSecret<Config<Compiler>, Compiler>;

///
pub type SpendSecret = protocol::SpendSecret<Config>;

///
pub type SpendSecretVar = protocol::SpendSecret<Config<Compiler>, Compiler>;

/// Embedded Group Generator
#[derive(Clone, Debug)]
pub struct GroupGenerator(Group);

impl HasGenerator<Group> for GroupGenerator {
    type Generator = Group;

    #[inline]
    fn generator(&self) -> &Group {
        &self.0
    }
}

impl Encode for GroupGenerator {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.0.encode(writer)
    }
}

impl Decode for GroupGenerator {
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self(Decode::decode(reader)?))
    }
}

impl Sample for GroupGenerator {
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(rng.gen())
    }
}

///
pub struct GroupGeneratorVar(GroupVar);

impl HasGenerator<GroupVar, Compiler> for GroupGeneratorVar {
    type Generator = GroupVar;

    #[inline]
    fn generator(&self) -> &GroupVar {
        &self.0
    }
}

impl Constant<Compiler> for GroupGeneratorVar {
    type Type = GroupGenerator;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

///
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtxoCommitmentSchemeDomainTag;

impl poseidon::hash::DomainTag<Poseidon5> for UtxoCommitmentSchemeDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon5 as ParameterFieldType>::ParameterField {
        Fp(0u8.into()) // FIXME: Use a real domain tag
    }
}

impl<COM> Constant<COM> for UtxoCommitmentSchemeDomainTag {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

///
type UtxoCommitmentSchemeType<COM = ()> = Hasher<Poseidon5, UtxoCommitmentSchemeDomainTag, 5, COM>;

///
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "UtxoCommitmentSchemeType<COM>: Clone"),
    Debug(bound = "UtxoCommitmentSchemeType<COM>: Debug"),
)]
pub struct UtxoCommitmentScheme<COM = ()>(UtxoCommitmentSchemeType<COM>)
where
    Poseidon5: poseidon::Specification<COM>;

impl Encode for UtxoCommitmentScheme {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.0.encode(writer)
    }
}

impl Decode for UtxoCommitmentScheme {
    type Error = <Fp<ConstraintField> as Decode>::Error;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self(Decode::decode(reader)?))
    }
}

impl Sample for UtxoCommitmentScheme {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

impl Constant<Compiler> for UtxoCommitmentScheme<Compiler> {
    type Type = UtxoCommitmentScheme;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

impl protocol::UtxoCommitmentScheme for UtxoCommitmentScheme {
    type AssetId = AssetId;
    type AssetValue = AssetValue;
    type ReceivingKey = ReceivingKey;
    type Randomness = Fp<ConstraintField>;
    type Commitment = Fp<ConstraintField>;

    #[inline]
    fn commit(
        &self,
        randomness: &Self::Randomness,
        asset_id: &Self::AssetId,
        asset_value: &Self::AssetValue,
        receiving_key: &Self::ReceivingKey,
        compiler: &mut (),
    ) -> Self::Commitment {
        self.0.hash(
            [
                randomness,
                asset_id,
                &Fp((*asset_value).into()),
                &Fp(receiving_key.0.x),
                &Fp(receiving_key.0.y),
            ],
            compiler,
        )
    }
}

impl protocol::UtxoCommitmentScheme<Compiler> for UtxoCommitmentScheme<Compiler> {
    type AssetId = AssetIdVar;
    type AssetValue = AssetValueVar;
    type ReceivingKey = ReceivingKeyVar;
    type Randomness = FpVar<ConstraintField>;
    type Commitment = FpVar<ConstraintField>;

    #[inline]
    fn commit(
        &self,
        randomness: &Self::Randomness,
        asset_id: &Self::AssetId,
        asset_value: &Self::AssetValue,
        receiving_key: &Self::ReceivingKey,
        compiler: &mut Compiler,
    ) -> Self::Commitment {
        /*
        print_measurement(
            "UTXO COMMITMENT SCHEME",
            |compiler| {
        */
        self.0.hash(
            [
                randomness,
                asset_id,
                asset_value.as_ref(),
                &receiving_key.0.x,
                &receiving_key.0.y,
            ],
            compiler,
        )
        /*
            },
            compiler,
        )
        */
    }
}

///
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ViewingKeyDerivationFunctionDomainTag;

impl poseidon::hash::DomainTag<Poseidon2> for ViewingKeyDerivationFunctionDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon2 as ParameterFieldType>::ParameterField {
        Fp(0u8.into()) // FIXME: Use a real domain tag
    }
}

impl<COM> Constant<COM> for ViewingKeyDerivationFunctionDomainTag {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

///
type ViewingKeyDerivationFunctionType<COM = ()> =
    Hasher<Poseidon2, ViewingKeyDerivationFunctionDomainTag, 2, COM>;

///
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "ViewingKeyDerivationFunctionType<COM>: Clone"),
    Debug(bound = "ViewingKeyDerivationFunctionType<COM>: Debug")
)]
pub struct ViewingKeyDerivationFunction<COM = ()>(ViewingKeyDerivationFunctionType<COM>)
where
    Poseidon2: poseidon::Specification<COM>;

impl Encode for ViewingKeyDerivationFunction {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.0.encode(writer)
    }
}

impl Decode for ViewingKeyDerivationFunction {
    type Error = <Fp<ConstraintField> as Decode>::Error;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self(Decode::decode(reader)?))
    }
}

impl Sample for ViewingKeyDerivationFunction {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

impl Constant<Compiler> for ViewingKeyDerivationFunction<Compiler> {
    type Type = ViewingKeyDerivationFunction;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

impl protocol::ViewingKeyDerivationFunction for ViewingKeyDerivationFunction {
    type ProofAuthorizationKey = ProofAuthorizationKey;
    type ViewingKey = ViewingKey;

    #[inline]
    fn viewing_key(
        &self,
        proof_authorization_key: &Self::ProofAuthorizationKey,
        compiler: &mut (),
    ) -> Self::ViewingKey {
        Fp(rem_mod_prime::<ConstraintField, EmbeddedScalarField>(
            self.0
                .hash(
                    [
                        &Fp(proof_authorization_key.0.x),
                        &Fp(proof_authorization_key.0.y),
                    ],
                    compiler,
                )
                .0,
        ))
    }
}

impl protocol::ViewingKeyDerivationFunction<Compiler> for ViewingKeyDerivationFunction<Compiler> {
    type ProofAuthorizationKey = ProofAuthorizationKeyVar;
    type ViewingKey = ViewingKeyVar;

    #[inline]
    fn viewing_key(
        &self,
        proof_authorization_key: &Self::ProofAuthorizationKey,
        compiler: &mut Compiler,
    ) -> Self::ViewingKey {
        /*
        print_measurement(
            "VIEWING KEY DERIVATION FUNCTION",
            |compiler| {
        */
        ScalarVar::new(self.0.hash(
            [&proof_authorization_key.0.x, &proof_authorization_key.0.y],
            compiler,
        ))
        /*
            },
            compiler,
        )
        */
    }
}

///
#[derive(derivative::Derivative)]
#[derivative(Default)]
pub struct IncomingEncryptionSchemeConverter<COM = ()>(PhantomData<COM>);

impl encryption::HeaderType for IncomingEncryptionSchemeConverter {
    type Header = encryption::EmptyHeader;
}

impl encryption::HeaderType for IncomingEncryptionSchemeConverter<Compiler> {
    type Header = encryption::EmptyHeader<Compiler>;
}

impl encryption::convert::header::Header for IncomingEncryptionSchemeConverter {
    type TargetHeader = encryption::Header<IncomingPoseidonEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::Header, _: &mut ()) -> Self::TargetHeader {
        let _ = source;
        vec![]
    }
}

impl encryption::convert::header::Header<Compiler> for IncomingEncryptionSchemeConverter<Compiler> {
    type TargetHeader = encryption::Header<IncomingPoseidonEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::Header, _: &mut Compiler) -> Self::TargetHeader {
        let _ = source;
        vec![]
    }
}

impl encryption::EncryptionKeyType for IncomingEncryptionSchemeConverter {
    type EncryptionKey = Group;
}

impl encryption::EncryptionKeyType for IncomingEncryptionSchemeConverter<Compiler> {
    type EncryptionKey = GroupVar;
}

impl encryption::convert::key::Encryption for IncomingEncryptionSchemeConverter {
    type TargetEncryptionKey = encryption::EncryptionKey<IncomingPoseidonEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::EncryptionKey, _: &mut ()) -> Self::TargetEncryptionKey {
        vec![Fp(source.0.x), Fp(source.0.y)]
    }
}

impl encryption::convert::key::Encryption<Compiler>
    for IncomingEncryptionSchemeConverter<Compiler>
{
    type TargetEncryptionKey =
        encryption::EncryptionKey<IncomingPoseidonEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::EncryptionKey, _: &mut Compiler) -> Self::TargetEncryptionKey {
        vec![source.0.x.clone(), source.0.y.clone()]
    }
}

impl encryption::DecryptionKeyType for IncomingEncryptionSchemeConverter {
    type DecryptionKey = Group;
}

impl encryption::DecryptionKeyType for IncomingEncryptionSchemeConverter<Compiler> {
    type DecryptionKey = GroupVar;
}

impl encryption::convert::key::Decryption for IncomingEncryptionSchemeConverter {
    type TargetDecryptionKey = encryption::DecryptionKey<IncomingPoseidonEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::DecryptionKey, _: &mut ()) -> Self::TargetDecryptionKey {
        vec![Fp(source.0.x), Fp(source.0.y)]
    }
}

impl encryption::convert::key::Decryption<Compiler>
    for IncomingEncryptionSchemeConverter<Compiler>
{
    type TargetDecryptionKey =
        encryption::DecryptionKey<IncomingPoseidonEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::DecryptionKey, _: &mut Compiler) -> Self::TargetDecryptionKey {
        vec![source.0.x.clone(), source.0.y.clone()]
    }
}

impl encryption::PlaintextType for IncomingEncryptionSchemeConverter {
    type Plaintext = protocol::IncomingPlaintext<Config>;
}

impl encryption::PlaintextType for IncomingEncryptionSchemeConverter<Compiler> {
    type Plaintext = protocol::IncomingPlaintext<Config<Compiler>, Compiler>;
}

impl encryption::convert::plaintext::Forward for IncomingEncryptionSchemeConverter {
    type TargetPlaintext = encryption::Plaintext<IncomingPoseidonEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::Plaintext, _: &mut ()) -> Self::TargetPlaintext {
        BlockArray(
            [poseidon::encryption::PlaintextBlock(
                vec![
                    source.utxo_commitment_randomness,
                    source.asset.id,
                    Fp(source.asset.value.into()),
                ]
                .into(),
            )]
            .into(),
        )
    }
}

impl encryption::convert::plaintext::Forward<Compiler>
    for IncomingEncryptionSchemeConverter<Compiler>
{
    type TargetPlaintext = encryption::Plaintext<IncomingPoseidonEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::Plaintext, _: &mut Compiler) -> Self::TargetPlaintext {
        BlockArray(
            [poseidon::encryption::PlaintextBlock(
                vec![
                    source.utxo_commitment_randomness.clone(),
                    source.asset.id.clone(),
                    source.asset.value.as_ref().clone(),
                ]
                .into(),
            )]
            .into(),
        )
    }
}

impl encryption::DecryptedPlaintextType for IncomingEncryptionSchemeConverter {
    type DecryptedPlaintext = Option<<Self as encryption::PlaintextType>::Plaintext>;
}

impl encryption::convert::plaintext::Reverse for IncomingEncryptionSchemeConverter {
    type TargetDecryptedPlaintext =
        encryption::DecryptedPlaintext<IncomingPoseidonEncryptionScheme>;

    #[inline]
    fn into_source(target: Self::TargetDecryptedPlaintext, _: &mut ()) -> Self::DecryptedPlaintext {
        if target.0 && target.1.len() == 1 {
            let block = &target.1[0].0;
            if block.len() == 3 {
                Some(protocol::IncomingPlaintext::new(
                    Fp(block[0].0),
                    Asset::new(Fp(block[1].0), try_into_u128(block[2].0)?),
                ))
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl<COM> Constant<COM> for IncomingEncryptionSchemeConverter<COM> {
    type Type = IncomingEncryptionSchemeConverter;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self::default()
    }
}

///
pub type IncomingPoseidonEncryptionScheme<COM = ()> =
    poseidon::encryption::FixedDuplexer<1, Poseidon3, COM>;

///
pub type IncomingBaseEncryptionScheme<COM = ()> = encryption::convert::key::Converter<
    encryption::convert::header::Converter<
        encryption::convert::plaintext::Converter<
            IncomingPoseidonEncryptionScheme<COM>,
            IncomingEncryptionSchemeConverter<COM>,
        >,
        IncomingEncryptionSchemeConverter<COM>,
    >,
    IncomingEncryptionSchemeConverter<COM>,
>;

///
pub const AES_PLAINTEXT_SIZE: usize = 80;

///
pub const AES_CIPHERTEXT_SIZE: usize = AES_PLAINTEXT_SIZE + 16;

///
pub type AES = aes::FixedNonceAesGcm<AES_PLAINTEXT_SIZE, AES_CIPHERTEXT_SIZE>;

///
#[derive(derivative::Derivative)]
#[derivative(Clone, Default)]
pub struct IncomingAESEncryptionScheme<COM = ()>(PhantomData<COM>);

impl<COM> encryption::HeaderType for IncomingAESEncryptionScheme<COM> {
    type Header = <AES as encryption::HeaderType>::Header;
}

impl<COM> encryption::EncryptionKeyType for IncomingAESEncryptionScheme<COM> {
    type EncryptionKey = <AES as encryption::EncryptionKeyType>::EncryptionKey;
}

impl<COM> encryption::DecryptionKeyType for IncomingAESEncryptionScheme<COM> {
    type DecryptionKey = <AES as encryption::DecryptionKeyType>::DecryptionKey;
}

impl<COM> encryption::PlaintextType for IncomingAESEncryptionScheme<COM> {
    type Plaintext = <AES as encryption::PlaintextType>::Plaintext;
}

impl<COM> encryption::DecryptedPlaintextType for IncomingAESEncryptionScheme<COM> {
    type DecryptedPlaintext = <AES as encryption::DecryptedPlaintextType>::DecryptedPlaintext;
}

impl<COM> encryption::CiphertextType for IncomingAESEncryptionScheme<COM> {
    type Ciphertext = <AES as encryption::CiphertextType>::Ciphertext;
}

impl<COM> encryption::RandomnessType for IncomingAESEncryptionScheme<COM> {
    type Randomness = <AES as encryption::RandomnessType>::Randomness;
}

impl<COM> encryption::Encrypt for IncomingAESEncryptionScheme<COM> {
    fn encrypt(
        &self,
        encryption_key: &Self::EncryptionKey,
        randomness: &Self::Randomness,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut (),
    ) -> Self::Ciphertext {
        let aes = AES::default();
        aes.encrypt(encryption_key, randomness, header, plaintext, compiler)
    }
}

impl<COM> encryption::Decrypt for IncomingAESEncryptionScheme<COM> {
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut (),
    ) -> Self::DecryptedPlaintext {
        let aes = AES::default();
        aes.decrypt(decryption_key, header, ciphertext, compiler)
    }
}

///
#[derive(derivative::Derivative)]
#[derivative(Clone, Default)]
pub struct IncomingAESConverter<COM = ()>(PhantomData<COM>);

impl<COM> encryption::HeaderType for IncomingAESConverter<COM> {
    type Header = encryption::EmptyHeader<COM>;
}

impl<COM> encryption::convert::header::Header<COM> for IncomingAESConverter<COM> {
    type TargetHeader = encryption::Header<IncomingAESEncryptionScheme<COM>>;

    #[inline]
    fn as_target(source: &Self::Header, _: &mut COM) -> Self::TargetHeader {
        let _ = source;
    }
}

impl encryption::EncryptionKeyType for IncomingAESConverter {
    type EncryptionKey = Group;
}

impl encryption::EncryptionKeyType for IncomingAESConverter<Compiler> {
    type EncryptionKey = GroupVar;
}

impl encryption::convert::key::Encryption for IncomingAESConverter {
    type TargetEncryptionKey = encryption::EncryptionKey<IncomingAESEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::EncryptionKey, _: &mut ()) -> Self::TargetEncryptionKey {
        let key = source.to_vec();
        assert_eq!(
            key.len(),
            32,
            "Wrong key length: {}. Expected 32 bytes.",
            key.len()
        );
        key.try_into()
            .expect("Getting a [u8; 32] array from a vector of length 32 should not fail.")
    }
}

impl encryption::convert::key::Encryption<Compiler> for IncomingAESConverter<Compiler> {
    type TargetEncryptionKey = encryption::EncryptionKey<IncomingAESEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::EncryptionKey, _: &mut Compiler) -> Self::TargetEncryptionKey {
        let key = Fp(*source
            .0
            .value()
            .expect("Getting the group element from GroupVar is not allowed to fail.")
            .to_field_elements()
            .expect("Getting the field elements from a group element is not allowed to fail.")
            .get(0)
            .expect("Vector of group elements in not empty"))
        .to_vec();
        // Note: we only keep the `x` coordinate, so we still need 1 bit (the sign of the `y` coordinate)
        // to reconstruct source from the key.
        assert_eq!(
            key.len(),
            32,
            "Wrong key length: {}. Expected 32 bytes.",
            key.len()
        );
        key.try_into()
            .expect("Getting a [u8; 32] array from a vector of length 32 should not fail.")
    }
}

impl encryption::DecryptionKeyType for IncomingAESConverter {
    type DecryptionKey = Group;
}

impl encryption::DecryptionKeyType for IncomingAESConverter<Compiler> {
    type DecryptionKey = GroupVar;
}

impl encryption::convert::key::Decryption for IncomingAESConverter {
    type TargetDecryptionKey = encryption::DecryptionKey<IncomingAESEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::DecryptionKey, _: &mut ()) -> Self::TargetDecryptionKey {
        let key = source.to_vec();
        assert_eq!(
            key.len(),
            32,
            "Wrong key length: {}. Expected 32 bytes.",
            key.len()
        );
        key.try_into()
            .expect("Getting a [u8; 32] array from a vector of length 32 should not fail.")
    }
}

impl encryption::convert::key::Decryption<Compiler> for IncomingAESConverter<Compiler> {
    type TargetDecryptionKey = encryption::DecryptionKey<IncomingAESEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::DecryptionKey, _: &mut Compiler) -> Self::TargetDecryptionKey {
        let key = Fp(*source
            .0
            .value()
            .expect("Getting the group element from GroupVar is not allowed to fail.")
            .to_field_elements()
            .expect("Getting the field elements from a group element is not allowed to fail.")
            .get(0)
            .expect("Vector of group elements in not empty"))
        .to_vec();
        // Note: we only keep the `x` coordinate, so we still need 1 bit (the sign of the `y` coordinate)
        // to reconstruct source from the key.
        assert_eq!(
            key.len(),
            32,
            "Wrong key length: {}. Expected 32 bytes.",
            key.len()
        );
        key.try_into()
            .expect("Getting a [u8; 32] array from a vector of length 32 should not fail.")
    }
}

impl encryption::PlaintextType for IncomingAESConverter {
    type Plaintext = protocol::IncomingPlaintext<Config>;
}

impl encryption::PlaintextType for IncomingAESConverter<Compiler> {
    type Plaintext = protocol::IncomingPlaintext<Config<Compiler>, Compiler>;
}

impl encryption::convert::plaintext::Forward for IncomingAESConverter {
    type TargetPlaintext = encryption::Plaintext<IncomingAESEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::Plaintext, _: &mut ()) -> Self::TargetPlaintext {
        let mut target_plaintext = Vec::<u8>::with_capacity(AES_PLAINTEXT_SIZE);
        target_plaintext.extend(source.utxo_commitment_randomness.to_vec());
        target_plaintext.extend(source.asset.id.to_vec());
        target_plaintext.extend(source.asset.value.to_le_bytes().to_vec());
        assert_eq!(
            target_plaintext.len(),
            AES_PLAINTEXT_SIZE,
            "Wrong plaintext length: {}. Expected {} bytes",
            target_plaintext.len(),
            AES_PLAINTEXT_SIZE
        );
        Array::from_unchecked::<Vec<u8>>(target_plaintext)
    }
}

impl encryption::convert::plaintext::Forward<Compiler> for IncomingAESConverter<Compiler> {
    type TargetPlaintext = encryption::Plaintext<IncomingAESEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::Plaintext, _: &mut Compiler) -> Self::TargetPlaintext {
        let mut target_plaintext = Vec::<u8>::with_capacity(AES_PLAINTEXT_SIZE);
        target_plaintext.extend(
            utxo_utilities::bytes_from_gadget(&source.utxo_commitment_randomness)
                .expect("Converting FpVar into bytes is not allowed to fail."),
        );
        target_plaintext.extend(
            utxo_utilities::bytes_from_gadget(&source.asset.id)
                .expect("Converting FpVar into bytes is not allowed to fail."),
        );
        target_plaintext.extend(utxo_utilities::from_little_endian(
            utxo_utilities::bytes_from_unsigned(&source.asset.value)
                .expect("Converting U128 into bytes is not allowed to fail."),
            16,
        ));
        assert_eq!(
            target_plaintext.len(),
            AES_PLAINTEXT_SIZE,
            "Wrong plaintext length: {}. Expected {} bytes",
            target_plaintext.len(),
            AES_PLAINTEXT_SIZE
        );
        Array::from_unchecked::<Vec<u8>>(target_plaintext)
    }
}

impl encryption::DecryptedPlaintextType for IncomingAESConverter {
    type DecryptedPlaintext = Option<<Self as encryption::PlaintextType>::Plaintext>;
}

impl encryption::convert::plaintext::Reverse for IncomingAESConverter {
    type TargetDecryptedPlaintext = encryption::DecryptedPlaintext<IncomingAESEncryptionScheme>;

    #[inline]
    fn into_source(target: Self::TargetDecryptedPlaintext, _: &mut ()) -> Self::DecryptedPlaintext {
        let bytes_vector = target?.0;
        let utxo_randomness_bytes = bytes_vector[0..32].to_vec();
        let asset_id_bytes = bytes_vector[32..64].to_vec();
        let asset_value_bytes =
            manta_util::Array::<u8, 16>::from_vec(bytes_vector[64..80].to_vec()).0;
        let utxo_randomness = Fp::<ConstraintField>::from_vec(utxo_randomness_bytes)
            .expect("Error while converting the bytes into a field element.");
        let asset_id = Fp::<ConstraintField>::from_vec(asset_id_bytes)
            .expect("Error while converting the bytes into a field element.");
        let asset_value = u128::from_le_bytes(asset_value_bytes);
        let source_plaintext = protocol::IncomingPlaintext::<Config>::new(
            utxo_randomness,
            asset::Asset {
                id: asset_id,
                value: asset_value,
            },
        );
        Some(source_plaintext)
    }
}

impl<COM> Constant<COM> for IncomingAESConverter<COM> {
    type Type = IncomingAESConverter;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self::default()
    }
}

///
pub type IncomingBaseAES<COM = ()> = encryption::convert::key::Converter<
    encryption::convert::header::Converter<
        encryption::convert::plaintext::Converter<
            IncomingAESEncryptionScheme<COM>,
            IncomingAESConverter<COM>,
        >,
        IncomingAESConverter<COM>,
    >,
    IncomingAESConverter<COM>,
>;

///
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtxoAccumulatorItemHashDomainTag;

impl poseidon::hash::DomainTag<Poseidon4> for UtxoAccumulatorItemHashDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon4 as ParameterFieldType>::ParameterField {
        Fp(0u8.into()) // FIXME: Use a real domain tag
    }
}

impl<COM> Constant<COM> for UtxoAccumulatorItemHashDomainTag {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

///
type UtxoAccumulatorItemHashType<COM = ()> =
    Hasher<Poseidon4, UtxoAccumulatorItemHashDomainTag, 4, COM>;

///
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "UtxoAccumulatorItemHashType<COM>: Clone"),
    Debug(bound = "UtxoAccumulatorItemHashType<COM>: Debug")
)]
pub struct UtxoAccumulatorItemHash<COM = ()>(UtxoAccumulatorItemHashType<COM>)
where
    Poseidon4: poseidon::Specification<COM>;

impl Encode for UtxoAccumulatorItemHash {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.0.encode(writer)
    }
}

impl Decode for UtxoAccumulatorItemHash {
    type Error = <Fp<ConstraintField> as Decode>::Error;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self(Decode::decode(reader)?))
    }
}

impl Sample for UtxoAccumulatorItemHash {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

impl Constant<Compiler> for UtxoAccumulatorItemHash<Compiler> {
    type Type = UtxoAccumulatorItemHash;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

impl ItemHashFunction<Utxo> for UtxoAccumulatorItemHash {
    type Item = UtxoAccumulatorItem;

    #[inline]
    fn item_hash(&self, value: &Utxo, compiler: &mut ()) -> Self::Item {
        self.0.hash(
            [
                &Fp(value.is_transparent.into()),
                &value.public_asset.id,
                &value.public_asset.value.into(),
                &value.commitment,
            ],
            compiler,
        )
    }
}

impl ItemHashFunction<UtxoVar, Compiler> for UtxoAccumulatorItemHash<Compiler> {
    type Item = UtxoAccumulatorItemVar;

    #[inline]
    fn item_hash(&self, value: &UtxoVar, compiler: &mut Compiler) -> Self::Item {
        self.0.hash(
            [
                &value.is_transparent.into(),
                &value.public_asset.id,
                value.public_asset.value.as_ref(),
                &value.commitment,
            ],
            compiler,
        )
    }
}

/// Leaf Hash Configuration Type
pub type LeafHash = merkle_tree::IdentityLeafHash<UtxoAccumulatorItem>;

/// Leaf Hash Variable Configuration Type
pub type LeafHashVar = merkle_tree::IdentityLeafHash<UtxoAccumulatorItemVar, Compiler>;

///
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InnerHashDomainTag;

impl poseidon::hash::DomainTag<Poseidon2> for InnerHashDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon2 as ParameterFieldType>::ParameterField {
        Fp(0u8.into()) // FIXME: Use a real domain tag
    }
}

impl<COM> Constant<COM> for InnerHashDomainTag {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

/// Inner Hash Configuration
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct InnerHash<COM = ()>(PhantomData<COM>);

impl merkle_tree::InnerHash for InnerHash {
    type LeafDigest = UtxoAccumulatorItem;
    type Parameters = Hasher<Poseidon2, InnerHashDomainTag, 2>;
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

impl merkle_tree::InnerHash<Compiler> for InnerHash<Compiler> {
    type LeafDigest = UtxoAccumulatorItemVar;
    type Parameters = Hasher<Poseidon2, InnerHashDomainTag, 2, Compiler>;
    type Output = FpVar<ConstraintField>;

    #[inline]
    fn join(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut Compiler,
    ) -> Self::Output {
        /*
        print_measurement(
            "INNER HASH",
            |compiler| {
        */
        parameters.hash([lhs, rhs], compiler)
        /*
            },
            compiler,
        )
        */
    }

    #[inline]
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        compiler: &mut Compiler,
    ) -> Self::Output {
        /*
        print_measurement(
            "INNER HASH",
            |compiler| {
        */
        parameters.hash([lhs, rhs], compiler)
        /*
            },
            compiler,
        )
        */
    }
}

/// Merkle Tree Configuration
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MerkleTreeConfiguration;

impl MerkleTreeConfiguration {
    /// Width of the Merkle Forest
    pub const FOREST_WIDTH: usize = 256;
}

impl merkle_tree::HashConfiguration for MerkleTreeConfiguration {
    type LeafHash = LeafHash;
    type InnerHash = InnerHash;
}

impl merkle_tree::HashConfiguration<Compiler> for MerkleTreeConfiguration {
    type LeafHash = LeafHashVar;
    type InnerHash = InnerHash<Compiler>;
}

impl merkle_tree::Configuration for MerkleTreeConfiguration {
    const HEIGHT: usize = 20;
}

impl merkle_tree::Configuration<Compiler> for MerkleTreeConfiguration {
    const HEIGHT: usize = 20;
}

impl<COM> Constant<COM> for MerkleTreeConfiguration {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

/// UTXO Accumulator Model
pub type UtxoAccumulatorModel = merkle_tree::Parameters<MerkleTreeConfiguration>;

/// UTXO Accumulator Model Variable
pub type UtxoAccumulatorModelVar = merkle_tree::Parameters<MerkleTreeConfiguration, Compiler>;

impl merkle_tree::forest::Configuration for MerkleTreeConfiguration {
    type Index = u8;

    #[inline]
    fn tree_index(leaf: &merkle_tree::Leaf<Self>) -> Self::Index {
        let mut hasher = Blake2sVar::new(1).unwrap();
        hasher.update(b"manta-v1.0.0/merkle-tree-shard-function");
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

#[cfg(any(feature = "parameters", test))]
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

///
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NullifierCommitmentSchemeDomainTag;

impl poseidon::hash::DomainTag<Poseidon3> for NullifierCommitmentSchemeDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon3 as ParameterFieldType>::ParameterField {
        Fp(0u8.into()) // FIXME: Use a real domain tag
    }
}

impl<COM> Constant<COM> for NullifierCommitmentSchemeDomainTag {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

///
type NullifierCommitmentSchemeType<COM = ()> =
    Hasher<Poseidon3, NullifierCommitmentSchemeDomainTag, 3, COM>;

///
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "NullifierCommitmentSchemeType<COM>: Clone"),
    Debug(bound = "NullifierCommitmentSchemeType<COM>: Debug")
)]
pub struct NullifierCommitmentScheme<COM = ()>(NullifierCommitmentSchemeType<COM>)
where
    Poseidon3: poseidon::Specification<COM>;

impl Encode for NullifierCommitmentScheme {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.0.encode(writer)
    }
}

impl Decode for NullifierCommitmentScheme {
    type Error = <Fp<ConstraintField> as Decode>::Error;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self(Decode::decode(reader)?))
    }
}

impl Sample for NullifierCommitmentScheme {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

impl Constant<Compiler> for NullifierCommitmentScheme<Compiler> {
    type Type = NullifierCommitmentScheme;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

impl protocol::NullifierCommitmentScheme for NullifierCommitmentScheme {
    type ProofAuthorizationKey = ProofAuthorizationKey;
    type UtxoAccumulatorItem = Fp<ConstraintField>;
    type Commitment = Fp<ConstraintField>;

    #[inline]
    fn commit(
        &self,
        proof_authorization_key: &Self::ProofAuthorizationKey,
        item: &Self::UtxoAccumulatorItem,
        compiler: &mut (),
    ) -> Self::Commitment {
        self.0.hash(
            [
                &Fp(proof_authorization_key.0.x),
                &Fp(proof_authorization_key.0.y),
                item,
            ],
            compiler,
        )
    }
}

impl protocol::NullifierCommitmentScheme<Compiler> for NullifierCommitmentScheme<Compiler> {
    type ProofAuthorizationKey = ProofAuthorizationKeyVar;
    type UtxoAccumulatorItem = FpVar<ConstraintField>;
    type Commitment = FpVar<ConstraintField>;

    #[inline]
    fn commit(
        &self,
        proof_authorization_key: &Self::ProofAuthorizationKey,
        item: &Self::UtxoAccumulatorItem,
        compiler: &mut Compiler,
    ) -> Self::Commitment {
        /*
        print_measurement(
            "NULLIFIER COMMITMENT SCHEME",
            |compiler| {
        */
        self.0.hash(
            [
                &proof_authorization_key.0.x,
                &proof_authorization_key.0.y,
                item,
            ],
            compiler,
        )
        /*
            },
            compiler,
        )
        */
    }
}

///
#[derive(derivative::Derivative)]
#[derivative(Default)]
pub struct OutgoingEncryptionSchemeConverter<COM = ()>(PhantomData<COM>);

impl encryption::HeaderType for OutgoingEncryptionSchemeConverter {
    type Header = encryption::EmptyHeader;
}

impl encryption::HeaderType for OutgoingEncryptionSchemeConverter<Compiler> {
    type Header = encryption::EmptyHeader<Compiler>;
}

impl encryption::convert::header::Header for OutgoingEncryptionSchemeConverter {
    type TargetHeader = encryption::Header<OutgoingPoseidonEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::Header, _: &mut ()) -> Self::TargetHeader {
        let _ = source;
        vec![]
    }
}

impl encryption::convert::header::Header<Compiler> for OutgoingEncryptionSchemeConverter<Compiler> {
    type TargetHeader = encryption::Header<OutgoingPoseidonEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::Header, _: &mut Compiler) -> Self::TargetHeader {
        let _ = source;
        vec![]
    }
}

impl encryption::EncryptionKeyType for OutgoingEncryptionSchemeConverter {
    type EncryptionKey = Group;
}

impl encryption::EncryptionKeyType for OutgoingEncryptionSchemeConverter<Compiler> {
    type EncryptionKey = GroupVar;
}

impl encryption::convert::key::Encryption for OutgoingEncryptionSchemeConverter {
    type TargetEncryptionKey = encryption::EncryptionKey<OutgoingPoseidonEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::EncryptionKey, _: &mut ()) -> Self::TargetEncryptionKey {
        vec![Fp(source.0.x), Fp(source.0.y)]
    }
}

impl encryption::convert::key::Encryption<Compiler>
    for OutgoingEncryptionSchemeConverter<Compiler>
{
    type TargetEncryptionKey =
        encryption::EncryptionKey<OutgoingPoseidonEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::EncryptionKey, _: &mut Compiler) -> Self::TargetEncryptionKey {
        vec![source.0.x.clone(), source.0.y.clone()]
    }
}

impl encryption::DecryptionKeyType for OutgoingEncryptionSchemeConverter {
    type DecryptionKey = Group;
}

impl encryption::DecryptionKeyType for OutgoingEncryptionSchemeConverter<Compiler> {
    type DecryptionKey = GroupVar;
}

impl encryption::convert::key::Decryption for OutgoingEncryptionSchemeConverter {
    type TargetDecryptionKey = encryption::DecryptionKey<OutgoingPoseidonEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::DecryptionKey, _: &mut ()) -> Self::TargetDecryptionKey {
        vec![Fp(source.0.x), Fp(source.0.y)]
    }
}

impl encryption::convert::key::Decryption<Compiler>
    for OutgoingEncryptionSchemeConverter<Compiler>
{
    type TargetDecryptionKey =
        encryption::DecryptionKey<OutgoingPoseidonEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::DecryptionKey, _: &mut Compiler) -> Self::TargetDecryptionKey {
        vec![source.0.x.clone(), source.0.y.clone()]
    }
}

impl encryption::PlaintextType for OutgoingEncryptionSchemeConverter {
    type Plaintext = Asset<AssetId, AssetValue>;
}

impl encryption::PlaintextType for OutgoingEncryptionSchemeConverter<Compiler> {
    type Plaintext = Asset<AssetIdVar, AssetValueVar>;
}

impl encryption::convert::plaintext::Forward for OutgoingEncryptionSchemeConverter {
    type TargetPlaintext = encryption::Plaintext<OutgoingPoseidonEncryptionScheme>;

    #[inline]
    fn as_target(source: &Self::Plaintext, _: &mut ()) -> Self::TargetPlaintext {
        BlockArray(
            [poseidon::encryption::PlaintextBlock(
                vec![source.id, Fp(source.value.into())].into(),
            )]
            .into(),
        )
    }
}

impl encryption::convert::plaintext::Forward<Compiler>
    for OutgoingEncryptionSchemeConverter<Compiler>
{
    type TargetPlaintext = encryption::Plaintext<OutgoingPoseidonEncryptionScheme<Compiler>>;

    #[inline]
    fn as_target(source: &Self::Plaintext, _: &mut Compiler) -> Self::TargetPlaintext {
        BlockArray(
            [poseidon::encryption::PlaintextBlock(
                vec![source.id.clone(), source.value.as_ref().clone()].into(),
            )]
            .into(),
        )
    }
}

impl encryption::DecryptedPlaintextType for OutgoingEncryptionSchemeConverter {
    type DecryptedPlaintext = Option<<Self as encryption::PlaintextType>::Plaintext>;
}

impl encryption::convert::plaintext::Reverse for OutgoingEncryptionSchemeConverter {
    type TargetDecryptedPlaintext =
        encryption::DecryptedPlaintext<OutgoingPoseidonEncryptionScheme>;

    #[inline]
    fn into_source(target: Self::TargetDecryptedPlaintext, _: &mut ()) -> Self::DecryptedPlaintext {
        if target.0 && target.1.len() == 1 {
            let block = &target.1[0].0;
            if block.len() == 2 {
                Some(Asset::new(block[0], try_into_u128(block[1].0)?))
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl<COM> Constant<COM> for OutgoingEncryptionSchemeConverter<COM> {
    type Type = OutgoingEncryptionSchemeConverter;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self::default()
    }
}

///
pub type OutgoingPoseidonEncryptionScheme<COM = ()> =
    poseidon::encryption::FixedDuplexer<1, Poseidon2, COM>;

///
pub type OutgoingBaseEncryptionScheme<COM = ()> = encryption::convert::key::Converter<
    encryption::convert::header::Converter<
        encryption::convert::plaintext::Converter<
            OutgoingPoseidonEncryptionScheme<COM>,
            OutgoingEncryptionSchemeConverter<COM>,
        >,
        OutgoingEncryptionSchemeConverter<COM>,
    >,
    OutgoingEncryptionSchemeConverter<COM>,
>;

/// Address Partition Function
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AddressPartitionFunction;

impl protocol::AddressPartitionFunction for AddressPartitionFunction {
    type Address = Address;
    type Partition = u8;

    #[inline]
    fn partition(&self, address: &Self::Address) -> Self::Partition {
        let mut hasher = Blake2sVar::new(1).unwrap();
        hasher.update(b"manta-v1.0.0/address-partition-function");
        let mut buffer = Vec::new();
        address
            .receiving_key
            .0
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

impl Encode for AddressPartitionFunction {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        let _ = writer;
        Ok(())
    }
}

impl Decode for AddressPartitionFunction {
    type Error = ();

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        let _ = reader;
        Ok(Self)
    }
}

impl Sample for AddressPartitionFunction {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
        Self
    }
}

/// Schnorr Hash Function
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchnorrHashFunction;

impl hash::security::PreimageResistance for SchnorrHashFunction {}

impl schnorr::HashFunction for SchnorrHashFunction {
    type Scalar = EmbeddedScalar;
    type Group = Group;
    type Message = Vec<u8>;

    #[inline]
    fn hash(
        &self,
        verifying_key: &Group,
        nonce_point: &Group,
        message: &Self::Message,
        _: &mut (),
    ) -> EmbeddedScalar {
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, b"domain tag"); // FIXME: Use specific domain tag
        Digest::update(
            &mut hasher,
            affine_point_as_bytes::<GroupCurve>(&verifying_key.0),
        );
        Digest::update(
            &mut hasher,
            affine_point_as_bytes::<GroupCurve>(&nonce_point.0),
        );
        Digest::update(&mut hasher, message);
        let bytes: [u8; 32] = hasher.finalize().into();
        Fp(EmbeddedScalarField::from_le_bytes_mod_order(&bytes))
    }
}

impl Encode for SchnorrHashFunction {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        let _ = writer;
        Ok(())
    }
}

impl Decode for SchnorrHashFunction {
    type Error = ();

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        let _ = reader;
        Ok(Self)
    }
}

impl Sample for SchnorrHashFunction {
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
        Self
    }
}

///
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Config<COM = ()>(PhantomData<COM>);

impl<COM> Constant<COM> for Config<COM> {
    type Type = Config;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self::default()
    }
}

impl protocol::BaseConfiguration for Config {
    type Bool = bool;
    type AssetId = AssetId;
    type AssetValue = AssetValue;
    type Scalar = EmbeddedScalar;
    type Group = Group;
    type GroupGenerator = GroupGenerator;
    type UtxoCommitmentScheme = UtxoCommitmentScheme;
    type ViewingKeyDerivationFunction = ViewingKeyDerivationFunction;
    type IncomingHeader = EmptyHeader;
    type IncomingCiphertext =
        <Self::IncomingBaseEncryptionScheme as encryption::CiphertextType>::Ciphertext;
    type IncomingBaseEncryptionScheme = IncomingBaseEncryptionScheme;
    type LightIncomingHeader = EmptyHeader;
    type LightIncomingBaseEncryptionScheme = IncomingBaseAES;
    type LightIncomingCiphertext =
        <Self::LightIncomingBaseEncryptionScheme as encryption::CiphertextType>::Ciphertext;
    type UtxoAccumulatorItemHash = UtxoAccumulatorItemHash;
    type UtxoAccumulatorModel = UtxoAccumulatorModel;
    type NullifierCommitmentScheme = NullifierCommitmentScheme;
    type OutgoingHeader = EmptyHeader;
    type OutgoingCiphertext =
        <Self::OutgoingBaseEncryptionScheme as encryption::CiphertextType>::Ciphertext;
    type OutgoingBaseEncryptionScheme = OutgoingBaseEncryptionScheme;
}

impl protocol::BaseConfiguration<Compiler> for Config<Compiler> {
    type Bool = Boolean<ConstraintField>;
    type AssetId = AssetIdVar;
    type AssetValue = AssetValueVar;
    type Scalar = EmbeddedScalarVar;
    type Group = GroupVar;
    type GroupGenerator = GroupGeneratorVar;
    type UtxoCommitmentScheme = UtxoCommitmentScheme<Compiler>;
    type ViewingKeyDerivationFunction = ViewingKeyDerivationFunction<Compiler>;
    type IncomingHeader = EmptyHeader<Compiler>;
    type IncomingCiphertext =
        <Self::IncomingBaseEncryptionScheme as encryption::CiphertextType>::Ciphertext;
    type IncomingBaseEncryptionScheme = IncomingBaseEncryptionScheme<Compiler>;
    type LightIncomingHeader = EmptyHeader<Compiler>;
    type LightIncomingCiphertext =
        <Self::LightIncomingBaseEncryptionScheme as encryption::CiphertextType>::Ciphertext;
    type LightIncomingBaseEncryptionScheme =
        encryption::UnsafeNoEncrypt<IncomingBaseAES<Compiler>, Compiler>;
    type UtxoAccumulatorItemHash = UtxoAccumulatorItemHash<Compiler>;
    type UtxoAccumulatorModel = UtxoAccumulatorModelVar;
    type NullifierCommitmentScheme = NullifierCommitmentScheme<Compiler>;
    type OutgoingHeader = EmptyHeader<Compiler>;
    type OutgoingCiphertext =
        <Self::OutgoingBaseEncryptionScheme as encryption::CiphertextType>::Ciphertext;
    type OutgoingBaseEncryptionScheme = OutgoingBaseEncryptionScheme<Compiler>;
}

impl protocol::Configuration for Config {
    type AddressPartitionFunction = AddressPartitionFunction;
    type SchnorrHashFunction = SchnorrHashFunction;
}

/// Checkpoint
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Checkpoint {
    /// Receiver Index
    pub receiver_index: Array<usize, { MerkleTreeConfiguration::FOREST_WIDTH }>,

    /// Sender Index
    pub sender_index: usize,
}

impl Checkpoint {
    /// Builds a new [`Checkpoint`] from `receiver_index` and `sender_index`.
    #[inline]
    pub fn new(
        receiver_index: Array<usize, { MerkleTreeConfiguration::FOREST_WIDTH }>,
        sender_index: usize,
    ) -> Self {
        Self {
            receiver_index,
            sender_index,
        }
    }
}

impl Default for Checkpoint {
    #[inline]
    fn default() -> Self {
        Self::new([0; MerkleTreeConfiguration::FOREST_WIDTH].into(), 0)
    }
}

impl From<RawCheckpoint> for Checkpoint {
    #[inline]
    fn from(checkpoint: RawCheckpoint) -> Self {
        Self::new(
            checkpoint.receiver_index.map(|i| i as usize).into(),
            checkpoint.sender_index as usize,
        )
    }
}

impl ledger::Checkpoint for Checkpoint {}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_codec::Decode for Checkpoint {
    #[inline]
    fn decode<I>(input: &mut I) -> Result<Self, scale_codec::Error>
    where
        I: scale_codec::Input,
    {
        RawCheckpoint::decode(input).map(Into::into)
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_codec::Encode for Checkpoint {
    #[inline]
    fn using_encoded<R, Encoder>(&self, f: Encoder) -> R
    where
        Encoder: FnOnce(&[u8]) -> R,
    {
        RawCheckpoint::from(*self).using_encoded(f)
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_codec::EncodeLike for Checkpoint {}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_codec::MaxEncodedLen for Checkpoint {
    #[inline]
    fn max_encoded_len() -> usize {
        RawCheckpoint::max_encoded_len()
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_info::TypeInfo for Checkpoint {
    type Identity = RawCheckpoint;

    #[inline]
    fn type_info() -> scale_info::Type {
        Self::Identity::type_info()
    }
}

/// Raw Checkpoint for Encoding and Decoding
#[cfg_attr(
    feature = "scale",
    derive(
        scale_codec::Decode,
        scale_codec::Encode,
        scale_codec::MaxEncodedLen,
        scale_info::TypeInfo
    )
)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RawCheckpoint {
    /// Receiver Index
    pub receiver_index: [u64; MerkleTreeConfiguration::FOREST_WIDTH],

    /// Sender Index
    pub sender_index: u64,
}

impl RawCheckpoint {
    /// Builds a new [`RawCheckpoint`] from `receiver_index` and `sender_index`.
    #[inline]
    pub fn new(
        receiver_index: [u64; MerkleTreeConfiguration::FOREST_WIDTH],
        sender_index: u64,
    ) -> Self {
        Self {
            receiver_index,
            sender_index,
        }
    }
}

impl Default for RawCheckpoint {
    #[inline]
    fn default() -> Self {
        Self::new([0; MerkleTreeConfiguration::FOREST_WIDTH], 0)
    }
}

impl From<Checkpoint> for RawCheckpoint {
    #[inline]
    fn from(checkpoint: Checkpoint) -> Self {
        Self::new(
            (*checkpoint.receiver_index).map(|i| i as u64),
            checkpoint.sender_index as u64,
        )
    }
}

/// Test
#[cfg(test)]
pub mod test {
    use crate::{
        config::{
            utxo::v2::{
                Config, IncomingAESConverter, IncomingBaseAES, AES_CIPHERTEXT_SIZE,
                AES_PLAINTEXT_SIZE,
            },
            Compiler, ConstraintField, Group, GroupVar,
        },
        crypto::constraint::arkworks::Fp,
    };
    use manta_accounting::{asset, transfer::utxo::v2 as protocol};
    use manta_crypto::{
        arkworks::constraint::FpVar,
        eclair::{
            alloc::{mode::Secret, Allocate},
            num::U128,
        },
        encryption::{
            convert::{
                key::Encryption,
                plaintext::{Forward, Reverse},
            },
            Decrypt, EmptyHeader, Encrypt,
        },
        rand::{OsRng, Sample},
    };

    /// Checks that the length of the fixed-nonce AES plaintext is 80. Checks that converting back returns
    /// what we started with.
    #[test]
    fn check_plaintext_conversion() {
        let mut rng = OsRng;
        let utxo_commitment_randomness = Fp::<ConstraintField>::gen(&mut rng);
        let asset_id = Fp::<ConstraintField>::gen(&mut rng);
        let asset_value = u128::gen(&mut rng);
        let source_plaintext = protocol::IncomingPlaintext::<Config>::new(
            utxo_commitment_randomness,
            asset::Asset {
                id: asset_id,
                value: asset_value,
            },
        );
        let final_array = <IncomingAESConverter as Forward>::as_target(&source_plaintext, &mut ());
        assert_eq!(
            AES_PLAINTEXT_SIZE,
            final_array.len(),
            "Length doesn't match, should be {} but is {}",
            AES_PLAINTEXT_SIZE,
            final_array.len()
        );
        let new_source = IncomingAESConverter::into_source(Some(final_array), &mut ())
            .expect("Converting back returns None.");
        let new_randomness = new_source.utxo_commitment_randomness;
        let (new_asset_id, new_asset_value) = (new_source.asset.id, new_source.asset.value);
        assert_eq!(
            new_randomness, utxo_commitment_randomness,
            "Randomness is not the same"
        );
        assert_eq!(new_asset_id, asset_id, "Asset ID is not the same.");
        assert_eq!(new_asset_value, asset_value, "Asset value is not the same.");
    }

    /// Same but w.r.t. compiler
    #[test]
    fn check_plaintext_conversion_r1cs() {
        let mut cs = Compiler::for_proofs();
        let mut rng = OsRng;
        let base_utxo = Fp::<ConstraintField>::gen(&mut rng);
        let utxo_commitment_randomness =
            base_utxo.as_known::<Secret, FpVar<ConstraintField>>(&mut cs);
        let base_asset_id = Fp::<ConstraintField>::gen(&mut rng);
        let asset_id = base_asset_id.as_known::<Secret, FpVar<ConstraintField>>(&mut cs);
        let base_asset_value = u128::gen(&mut rng);
        let asset_value =
            base_asset_value.as_known::<Secret, U128<FpVar<ConstraintField>>>(&mut cs);
        let source_plaintext = protocol::IncomingPlaintext::<Config<Compiler>, Compiler>::new(
            utxo_commitment_randomness,
            asset::Asset {
                id: asset_id,
                value: asset_value,
            },
        );
        let final_array = <IncomingAESConverter<Compiler> as Forward<Compiler>>::as_target(
            &source_plaintext,
            &mut cs,
        );
        assert_eq!(
            AES_PLAINTEXT_SIZE,
            final_array.len(),
            "Length doesn't match, should be {} but is {}",
            AES_PLAINTEXT_SIZE,
            final_array.len()
        );
    }

    /// Checks the encryption key conversion is properly executed.
    #[test]
    fn check_encryption_key_conversion() {
        let mut rng = OsRng;
        let group_element = Group::gen(&mut rng);
        <IncomingAESConverter as Encryption>::as_target(&group_element, &mut ());
    }

    /// Checks the encryption key conversion is properly executed for Compiler.
    #[test]
    fn check_encryption_key_conversion_r1cs() {
        let mut cs = Compiler::for_proofs();
        let mut rng = OsRng;
        let base_group = Group::gen(&mut rng);
        let group = base_group.as_known::<Secret, GroupVar>(&mut cs);
        <IncomingAESConverter<Compiler> as Encryption<Compiler>>::as_target(&group, &mut cs);
    }

    /// Checks encryption is properly executed, i.e. that the ciphertext size is consistent with all the parameters, and that
    /// decryption is the inverse of encryption.
    #[test]
    fn check_encryption() {
        let mut rng = OsRng;
        let encryption_key = Group::gen(&mut rng);
        let header = EmptyHeader::default();
        let base_aes = IncomingBaseAES::default();
        let randomness = ();
        let utxo_commitment_randomness = Fp::<ConstraintField>::gen(&mut rng);
        let asset_id = Fp::<ConstraintField>::gen(&mut rng);
        let asset_value = u128::gen(&mut rng);
        let plaintext = protocol::IncomingPlaintext::<Config>::new(
            utxo_commitment_randomness,
            asset::Asset {
                id: asset_id,
                value: asset_value,
            },
        );
        let ciphertext =
            base_aes.encrypt(&encryption_key, &randomness, &header, &plaintext, &mut ());
        assert_eq!(
            AES_CIPHERTEXT_SIZE,
            ciphertext.len(),
            "Ciphertext length doesn't match, should be {} but is {}",
            AES_CIPHERTEXT_SIZE,
            ciphertext.len()
        );
        let decrypted_ciphertext = base_aes
            .decrypt(&encryption_key, &header, &ciphertext, &mut ())
            .expect("Decryption returned None.");
        let new_randomness = decrypted_ciphertext.utxo_commitment_randomness;
        let (new_asset_id, new_asset_value) = (
            decrypted_ciphertext.asset.id,
            decrypted_ciphertext.asset.value,
        );
        assert_eq!(
            new_randomness, utxo_commitment_randomness,
            "Randomness is not the same"
        );
        assert_eq!(new_asset_id, asset_id, "Asset ID is not the same.");
        assert_eq!(new_asset_value, asset_value, "Asset value is not the same.");
    }
}
