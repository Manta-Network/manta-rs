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
        registry::HasContributed,
        signature::{self, SignatureScheme},
        state::ServerSize,
    },
    mpc,
};
use g16_bls12_381::Groth16BLS12381;

pub mod config;
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
        + signature::HasNonce<Self::SignatureScheme>;
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

/// Checks `states` has the same size as `size`.
pub fn check_state_size(states: &[State<Groth16BLS12381>; 3], size: &ServerSize) -> bool {
    (states[0].vk.gamma_abc_g1.len() == size.mint.gamma_abc_g1)
        || (states[0].a_query.len() == size.mint.a_b_g1_b_g2_query)
        || (states[0].b_g1_query.len() == size.mint.a_b_g1_b_g2_query)
        || (states[0].b_g2_query.len() == size.mint.a_b_g1_b_g2_query)
        || (states[0].h_query.len() == size.mint.h_query)
        || (states[0].l_query.len() == size.mint.l_query)
        || (states[1].vk.gamma_abc_g1.len() == size.private_transfer.gamma_abc_g1)
        || (states[1].a_query.len() == size.private_transfer.a_b_g1_b_g2_query)
        || (states[1].b_g1_query.len() == size.private_transfer.a_b_g1_b_g2_query)
        || (states[1].b_g2_query.len() == size.private_transfer.a_b_g1_b_g2_query)
        || (states[1].h_query.len() == size.private_transfer.h_query)
        || (states[1].l_query.len() == size.private_transfer.l_query)
        || (states[2].vk.gamma_abc_g1.len() == size.reclaim.gamma_abc_g1)
        || (states[2].a_query.len() == size.reclaim.a_b_g1_b_g2_query)
        || (states[2].b_g1_query.len() == size.reclaim.a_b_g1_b_g2_query)
        || (states[2].b_g2_query.len() == size.reclaim.a_b_g1_b_g2_query)
        || (states[2].h_query.len() == size.reclaim.h_query)
        || (states[2].l_query.len() == size.reclaim.l_query)
}
