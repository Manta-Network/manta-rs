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

pub mod v1;

#[doc(inline)]
pub use v1 as protocol;

/// Current UTXO Protocol Version
pub const VERSION: u8 = protocol::VERSION;

/// UTXO Protocol Types
pub trait Types {
    /// Asset Type
    type Asset;

    /// UTXO Type
    type Utxo;
}

/// UTXO Minting
pub trait Mint<S, COM = ()>: Types {
    /// Base Authority
    type Authority;

    /// UTXO Note Type
    type Note;

    /// Returns the asset inside of `utxo` asserting that `secret`, `utxo`, and `note` are
    /// well-formed.
    fn well_formed_asset(
        &self,
        authority: &Self::Authority,
        secret: &S,
        utxo: &Self::Utxo,
        note: &Self::Note,
        compiler: &mut COM,
    ) -> Self::Asset;
}

/// UTXO Spending
pub trait Spend<S, COM = ()>: Types {
    /// Base Authority
    type Authority;

    /// Nullifier Type
    type Nullifier;

    /// Returns the asset and its nullifier inside of `utxo` asserting that `secret` and `utxo` are
    /// well-formed.
    fn well_formed_asset(
        &self,
        authority: &Self::Authority,
        secret: &S,
        utxo: &Self::Utxo,
        compiler: &mut COM,
    ) -> (Self::Asset, Self::Nullifier);
}
