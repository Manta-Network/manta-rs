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

//! Transfer Protocol

use crate::{
    asset::{Asset, AssetId, AssetValue, AssetVar},
    identity2::{self, Utxo},
};
use manta_crypto::{
    accumulator::Verifier,
    constraint::{
        reflection::{HasVariable, Var},
        Constant, ConstraintSystem, ProofSystem, PublicOrSecret, Variable,
    },
    encryption::HybridPublicKeyEncryptionScheme,
};

/// Transfer Configuration
pub trait Configuration: identity2::Configuration<Asset = Asset> {
    /// Encryption Scheme
    type EncryptionScheme: HybridPublicKeyEncryptionScheme<
        Plaintext = Self::Asset,
        KeyAgreementScheme = Self::KeyAgreementScheme,
    >;

    /// UTXO Set Verifier
    type UtxoSetVerifier: Verifier<Item = Utxo<Self>, Verification = bool>;
}

/*
/// Transfer Configuration
pub trait Configuration {
    /// Encryption Scheme Type
    type EncryptionScheme: HybridPublicKeyEncryptionScheme;

    /// Constraint System Type
    type ConstraintSystem: ConstraintSystem
        + HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetValue, Mode = PublicOrSecret>;

    /// Proof System Type
    type ProofSystem: ProofSystem<ConstraintSystem = Self::ConstraintSystem, Verification = bool>;

    /// UTXO Set Verifier
    type UtxoSetVerifier: Verifier<Item = Utxo<Self::Config>, Verification = bool>;

    /// UTXO Set Verifier
    type UtxoSetVerifierVar: Verifier<
            Item = Utxo<Self::ConfigVar>,
            Verification = <Self::ConstraintSystem as ConstraintSystem>::Bool,
        > + Variable<Self::ConstraintSystem, Mode = Constant, Type = Self::UtxoSetVerifier>;

    /// Identity Configuration Type
    type Config: identity2::Configuration<Asset = Asset, KeyScheme = Self::EncryptionScheme>;

    /// Identity Variable Configuration Type
    type ConfigVar: identity2::Configuration<Asset = AssetVar<Self::ConstraintSystem>>;
}

impl<C> identity2::Configuration for C
where
    C: Configuration,
{
    type Asset = <C::Config as identity2::Configuration>::Asset;
    type KeyScheme = <C::Config as identity2::Configuration>::KeyScheme;
    type CommitmentScheme = <C::Config as identity2::Configuration>::CommitmentScheme;
}

///
pub type Sender<C> =
    identity2::Sender<<C as Configuration>::Config, <C as Configuration>::UtxoSetVerifier>;

///
pub type SenderVar<C> =
    identity2::Sender<<C as Configuration>::ConfigVar, <C as Configuration>::UtxoSetVerifierVar>;

///
pub type SenderPost<C> =
    identity2::SenderPost<<C as Configuration>::Config, <C as Configuration>::UtxoSetVerifier>;

///
pub type Receiver<C> = identity2::Receiver<<C as Configuration>::Config>;

///
pub type ReceiverVar<C> = identity2::Receiver<<C as Configuration>::ConfigVar>;

///
pub type ReceiverPost<C> = identity2::ReceiverPost<<C as Configuration>::Config>;
*/
