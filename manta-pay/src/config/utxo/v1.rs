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

//! Manta-Pay UTXO Model Version 1 Configuration

use crate::{
    config::{
        poseidon::{
            Spec2 as Poseidon2, Spec3 as Poseidon3, Spec4 as Poseidon4, Spec5 as Poseidon5,
        },
        Compiler, ConstraintField, EmbeddedScalar, EmbeddedScalarVar, Group, GroupVar,
    },
    crypto::{
        constraint::arkworks::{Boolean, Fp, FpVar, R1CS},
        poseidon::{self, hash::Hasher, ParameterFieldType},
    },
};
use ark_ff::PrimeField;
use core::marker::PhantomData;
use manta_crypto::{
    eclair::{num::U128, Has},
    hash::ArrayHashFunction,
    merkle_tree,
};

pub use manta_accounting::transfer::utxo::v1 as protocol;

///
pub type AssetId = Fp<ConstraintField>;

///
pub type AssetIdVar = FpVar<ConstraintField>;

///
pub type AssetValue = u128;

///
pub type AssetValueVar = U128<FpVar<ConstraintField>>;

///
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
pub struct UtxoCommitmentSchemeDomainTag;

impl poseidon::hash::DomainTag<Poseidon5> for UtxoCommitmentSchemeDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon5 as ParameterFieldType>::ParameterField {
        todo!()
    }
}

///
pub struct UtxoCommitmentScheme<COM = ()>(Hasher<Poseidon5, UtxoCommitmentSchemeDomainTag, 5, COM>)
where
    Poseidon5: poseidon::Specification<COM>;

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
    }
}

///
pub struct ViewingKeyDerivationFunctionDomainTag;

impl poseidon::hash::DomainTag<Poseidon2> for ViewingKeyDerivationFunctionDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon2 as ParameterFieldType>::ParameterField {
        todo!()
    }
}

///
pub struct ViewingKeyDerivationFunction<COM = ()>(
    Hasher<Poseidon2, ViewingKeyDerivationFunctionDomainTag, 2, COM>,
)
where
    Poseidon2: poseidon::Specification<COM>;

impl protocol::ViewingKeyDerivationFunction for ViewingKeyDerivationFunction {
    type ProofAuthorizationKey = ProofAuthorizationKey;
    type ViewingKey = ViewingKey;

    #[inline]
    fn viewing_key(
        &self,
        proof_authorization_key: &Self::ProofAuthorizationKey,
        compiler: &mut (),
    ) -> Self::ViewingKey {
        /* TODO:
        self.0.hash(
            [
                &Fp(proof_authorization_key.0.x),
                &Fp(proof_authorization_key.0.y),
            ],
            compiler,
        )
        */
        todo!()
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
        todo!()
    }
}

///
pub type IncomingBaseEncryptionScheme<COM = ()> = poseidon::encryption::Encryption<Poseidon5, COM>;

///
pub struct UtxoAccumulatorItemHashDomainTag;

impl poseidon::hash::DomainTag<Poseidon4> for UtxoAccumulatorItemHashDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon3 as ParameterFieldType>::ParameterField {
        todo!()
    }
}

///
pub struct UtxoAccumulatorItemHash<COM = ()>(
    Hasher<Poseidon4, UtxoAccumulatorItemHashDomainTag, 4, COM>,
)
where
    Poseidon4: poseidon::Specification<COM>;

impl protocol::UtxoAccumulatorItemHash for UtxoAccumulatorItemHash {
    type Bool = bool;
    type AssetId = AssetId;
    type AssetValue = AssetValue;
    type Commitment = Fp<ConstraintField>;
    type Item = UtxoAccumulatorItem;

    #[inline]
    fn hash(
        &self,
        is_transparent: &Self::Bool,
        public_asset_id: &Self::AssetId,
        public_asset_value: &Self::AssetValue,
        commitment: &Self::Commitment,
        compiler: &mut (),
    ) -> Self::Item {
        self.0.hash(
            [
                &Fp((*is_transparent).into()),
                public_asset_id,
                &Fp((*public_asset_value).into()),
                commitment,
            ],
            compiler,
        )
    }
}

impl protocol::UtxoAccumulatorItemHash<Compiler> for UtxoAccumulatorItemHash<Compiler> {
    type Bool = Boolean<ConstraintField>;
    type AssetId = AssetIdVar;
    type AssetValue = AssetValueVar;
    type Commitment = FpVar<ConstraintField>;
    type Item = UtxoAccumulatorItemVar;

    #[inline]
    fn hash(
        &self,
        is_transparent: &Self::Bool,
        public_asset_id: &Self::AssetId,
        public_asset_value: &Self::AssetValue,
        commitment: &Self::Commitment,
        compiler: &mut Compiler,
    ) -> Self::Item {
        self.0.hash(
            [
                &(is_transparent.clone()).into(),
                public_asset_id,
                public_asset_value.as_ref(),
                commitment,
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
pub struct InnerHashDomainTag;

impl poseidon::hash::DomainTag<Poseidon2> for InnerHashDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon2 as ParameterFieldType>::ParameterField {
        todo!()
    }
}

/// Inner Hash Configuration
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

/// Merkle Tree Configuration
pub struct MerkleTreeConfiguration;

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

/// UTXO Accumulator Model
pub type UtxoAccumulatorModel = merkle_tree::Parameters<MerkleTreeConfiguration>;

/// UTXO Accumulator Model Variable
pub type UtxoAccumulatorModelVar = merkle_tree::Parameters<MerkleTreeConfiguration, Compiler>;

///
pub struct NullifierCommitmentSchemeDomainTag;

impl poseidon::hash::DomainTag<Poseidon3> for NullifierCommitmentSchemeDomainTag {
    #[inline]
    fn domain_tag() -> <Poseidon3 as ParameterFieldType>::ParameterField {
        todo!()
    }
}

///
pub struct NullifierCommitmentScheme<COM = ()>(
    Hasher<Poseidon3, NullifierCommitmentSchemeDomainTag, 3, COM>,
)
where
    Poseidon3: poseidon::Specification<COM>;

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
        self.0.hash(
            [
                &proof_authorization_key.0.x,
                &proof_authorization_key.0.y,
                item,
            ],
            compiler,
        )
    }
}

///
pub type OutgoingBaseEncryptionScheme<COM = ()> = poseidon::encryption::Encryption<Poseidon2, COM>;

///
pub struct Config<COM = ()>(PhantomData<COM>);

/* TODO:
impl protocol::Configuration for Config {
    type Bool = bool;
    type AssetId = AssetId;
    type AssetValue = AssetValue;
    type Scalar = EmbeddedScalar;
    type Group = Group;
    type UtxoCommitmentScheme = UtxoCommitmentScheme;
    type ViewingKeyDerivationFunction = ViewingKeyDerivationFunction;
    type IncomingCiphertext = ();
    type IncomingBaseEncryptionScheme = IncomingBaseEncryptionScheme;
    type UtxoAccumulatorItemHash = UtxoAccumulatorItemHash;
    type UtxoAccumulatorModel = ();
    type NullifierCommitmentScheme = NullifierCommitmentScheme;
    type OutgoingCiphertext = ();
    type OutgoingBaseEncryptionScheme = OutgoingBaseEncryptionScheme;
}
*/

/* TODO:
impl<F> protocol::Configuration<Compiler> for Config<Compiler>
where
    F: PrimeField,
{
    type Bool = Boolean<F>;
    type AssetId = AssetIdVar;
    type AssetValue = AssetValueVar;
    type Scalar = EmbeddedScalarVar;
    type Group = GroupVar;
    type UtxoCommitmentScheme = UtxoCommitmentScheme<Compiler>;
    type ViewingKeyDerivationFunction = ViewingKeyDerivationFunction<Compiler>;
    type IncomingCiphertext = ();
    type IncomingBaseEncryptionScheme = IncomingBaseEncryptionScheme<Compiler>;
    type UtxoAccumulatorItemHash = UtxoAccumulatorItemHash<Compiler>;
    type UtxoAccumulatorModel = ();
    type OutgoingCiphertext = ();
    type OutgoingBaseEncryptionScheme = OutgoingBaseEncryptionScheme<Compiler>;
}
*/
