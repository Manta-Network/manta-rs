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
    config::{ConstraintField, EmbeddedScalar, Group},
    crypto::constraint::arkworks::{Boolean, Fp, R1CS},
};
use ark_ff::PrimeField;
use core::marker::PhantomData;
use manta_crypto::eclair::Has;

pub use manta_accounting::transfer::utxo::v1 as protocol;

///
pub type AssetId = Fp<ConstraintField>;

///
pub type AssetValue = u128;

///
pub type ProofAuthorizationKey = Group;

///
pub type ViewingKey = EmbeddedScalar;

///
pub type ReceivingKey = Group;

///
pub struct UtxoCommitmentScheme<COM = ()>(PhantomData<COM>);

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
        todo!()
    }
}

///
pub struct ViewingKeyDerivationFunction<COM = ()>(PhantomData<COM>);

impl protocol::ViewingKeyDerivationFunction for ViewingKeyDerivationFunction {
    type ProofAuthorizationKey = ProofAuthorizationKey;
    type ViewingKey = ViewingKey;

    #[inline]
    fn viewing_key(
        &self,
        proof_authorization_key: &Self::ProofAuthorizationKey,
        _: &mut (),
    ) -> Self::ViewingKey {
        todo!()
    }
}

///
#[derive(Clone)]
pub struct IncomingBaseEncryptionScheme<COM = ()>(PhantomData<COM>);

///
pub struct UtxoAccumulatorItemHash<COM = ()>(PhantomData<COM>);

impl protocol::UtxoAccumulatorItemHash for UtxoAccumulatorItemHash {
    type Bool = bool;
    type AssetId = AssetId;
    type AssetValue = AssetValue;
    type Commitment = Fp<ConstraintField>;
    type Item = Fp<ConstraintField>;

    #[inline]
    fn hash(
        &self,
        is_transparent: &Self::Bool,
        public_asset_id: &Self::AssetId,
        public_asset_value: &Self::AssetValue,
        commitment: &Self::Commitment,
        compiler: &mut (),
    ) -> Self::Item {
        todo!()
    }
}

///
pub struct NullifierCommitmentScheme<COM = ()>(PhantomData<COM>);

impl protocol::NullifierCommitmentScheme for NullifierCommitmentScheme {
    type ProofAuthorizationKey = ProofAuthorizationKey;
    type UtxoAccumulatorItem = ();
    type Commitment = Fp<ConstraintField>;

    #[inline]
    fn commit(
        &self,
        proof_authorization_key: &Self::ProofAuthorizationKey,
        item: &Self::UtxoAccumulatorItem,
        _: &mut (),
    ) -> Self::Commitment {
        todo!()
    }
}

///
#[derive(Clone)]
pub struct OutgoingBaseEncryptionScheme<COM = ()>(PhantomData<COM>);

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
impl<F> protocol::Configuration<R1CS<F>> for Config<R1CS<F>>
where
    F: PrimeField,
{
    type Bool = Boolean<F>;
    type AssetId = ();
    type AssetValue = ();
    type Scalar = ();
    type Group = ();
    type UtxoCommitmentScheme = ();
    type ViewingKeyDerivationFunction = ();
    type IncomingCiphertext = ();
    type IncomingBaseEncryptionScheme = ();
    type UtxoAccumulatorItemHash = ();
    type UtxoAccumulatorModel = ();
    type OutgoingCiphertext = ();
    type OutgoingBaseEncryptionScheme = ();
}
*/
