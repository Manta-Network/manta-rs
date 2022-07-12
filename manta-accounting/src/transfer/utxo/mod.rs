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

//! UTXO Protocols
//!
//! The current protocol is referred to by [`protocol`] and older protocols are marked by their
//! version number. The [`VERSION`] number can be queried for the current protocol and can be used
//! to select the protocol version. The transfer protocol is built up from a given [`Mint`] and
//! [`Spend`] implementation.

use manta_crypto::accumulator::{self, ItemHashFunction, MembershipProof};

pub mod v1;

#[doc(inline)]
pub use v1 as protocol;

/// Current UTXO Protocol Version
pub const VERSION: u8 = protocol::VERSION;

/// UTXO Protocol Types
pub trait Types {
    /// Asset Type
    type Asset;

    /// Unspent Transaction Output Type
    type Utxo;
}

/// UTXO Minting
pub trait Mint<COM = ()>: Types {
    /// Base Authority Type
    type Authority;

    /// Mint Secret Type
    type Secret;

    /// UTXO Note Type
    type Note;

    /// Returns the asset inside of `utxo` asserting that `secret`, `utxo`, and `note` are
    /// well-formed.
    fn well_formed_asset(
        &self,
        authority: &Self::Authority,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        note: &Self::Note,
        compiler: &mut COM,
    ) -> Self::Asset;
}

/// UTXO Spending
pub trait Spend<COM = ()>: Types + ItemHashFunction<Self::Utxo, COM> {
    /// UTXO Accumulator Model Type
    type UtxoAccumulatorModel: accumulator::Model<COM, Item = Self::Item>;

    /// Base Authority Type
    type Authority;

    /// Spend Secret Type
    type Secret;

    /// Nullifier Type
    type Nullifier;

    /// Returns the asset and its nullifier inside of `utxo` asserting that `secret` and `utxo` are
    /// well-formed and that `utxo_membership_proof` is a valid proof.
    fn well_formed_asset(
        &self,
        utxo_accumulator_model: &Self::UtxoAccumulatorModel,
        authority: &Self::Authority,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        utxo_membership_proof: &UtxoMembershipProof<Self, COM>,
        compiler: &mut COM,
    ) -> (Self::Asset, Self::Nullifier);

    ///
    #[inline]
    fn well_formed_nullifier(
        &self,
        utxo_accumulator_model: &Self::UtxoAccumulatorModel,
        authority: &Self::Authority,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        utxo_membership_proof: &UtxoMembershipProof<Self, COM>,
        compiler: &mut COM,
    ) -> Self::Nullifier {
        self.well_formed_asset(
            utxo_accumulator_model,
            authority,
            secret,
            utxo,
            utxo_membership_proof,
            compiler,
        )
        .1
    }
}

/// UTXO Membership Proof Type
pub type UtxoMembershipProof<S, COM = ()> =
    MembershipProof<<S as Spend<COM>>::UtxoAccumulatorModel, COM>;

/// UTXO Accumulator Output Type
pub type UtxoAccumulatorOutput<S, COM = ()> =
    <<S as Spend<COM>>::UtxoAccumulatorModel as accumulator::Types>::Output;

/// UTXO Accumulator Item Type
pub type UtxoAccumulatorItem<S, COM = ()> =
    <<S as Spend<COM>>::UtxoAccumulatorModel as accumulator::Types>::Item;
