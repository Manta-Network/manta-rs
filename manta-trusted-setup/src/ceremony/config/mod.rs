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

//! Ceremony Configurations

use crate::{
    ceremony::{
        queue::{HasIdentifier, Priority},
        server::{HasContributed, HasNonce},
        signature,
        signature::SignatureScheme,
    },
    mpc,
};

pub mod g16_bls12_381;

/// Trustred Setup Ceremony Config
pub trait CeremonyConfig {
    /// Setup
    type Setup: mpc::Verify + mpc::Contribute;

    /// Signature Scheme
    type SignatureScheme: SignatureScheme;

    /// Participant
    type Participant: Priority
        + HasIdentifier
        + signature::HasPublicKey<Self::SignatureScheme>
        + HasContributed
        + HasNonce<Self::SignatureScheme>;
}

/// State
pub type State<C> = <<C as CeremonyConfig>::Setup as mpc::Types>::State;

/// Challenge
pub type Challenge<C> = <<C as CeremonyConfig>::Setup as mpc::Types>::Challenge;

/// Hasher
pub type Hasher<C> = <<C as CeremonyConfig>::Setup as mpc::Contribute>::Hasher;

/// Proof
pub type Proof<C> = <<C as CeremonyConfig>::Setup as mpc::Types>::Proof;

/// Nonce
pub type Nonce<C> = <<C as CeremonyConfig>::SignatureScheme as SignatureScheme>::Nonce;

/// Public Key
pub type PublicKey<C> = <<C as CeremonyConfig>::SignatureScheme as SignatureScheme>::PublicKey;

/// Signature
pub type Signature<C> = <<C as CeremonyConfig>::SignatureScheme as SignatureScheme>::Signature;

/// Private Key
pub type PrivateKey<C> = <<C as CeremonyConfig>::SignatureScheme as SignatureScheme>::PrivateKey;

/// Participant Identifier
pub type ParticipantIdentifier<C> =
    <<C as CeremonyConfig>::Participant as HasIdentifier>::Identifier;
