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

use manta_crypto::constraint::{AssertEq, PartialEq};

pub mod v1;

#[doc(inline)]
pub use v1 as protocol;

/// Current UTXO Protocol Version
pub const VERSION: u8 = protocol::VERSION;

/// Version
pub trait VersionType {
    /// Version Type
    type Version;
}

/// UTXO Minting
pub trait Mint<COM = ()> {
    /// Minting Secret Type
    type MintSecret;

    /// Asset Type
    type Asset;

    /// Utxo Type
    type Utxo;

    /// Returns the asset inside of `utxo` asserting that `mint_secret` and `utxo` are well-formed.
    fn asset(
        &self,
        mint_secret: &Self::MintSecret,
        utxo: &Self::Utxo,
        compiler: &mut COM,
    ) -> Self::Asset;
}

/// UTXO Spending
pub trait Spend<COM = ()>: Mint<COM> {
    /// Spending Secret Type
    type SpendSecret;

    /// Void Number Type
    type VoidNumber;

    /// Returns the [`VoidNumber`](Self::VoidNumber) for `utxo` asserting that `mint_secret` and
    /// `spend_secret` are well-formed.
    fn void_number(
        &self,
        mint_secret: &Self::MintSecret,
        spend_secret: &Self::SpendSecret,
        utxo: &Self::Utxo,
        compiler: &mut COM,
    ) -> Self::VoidNumber;

    /// Returns the asset inside of `utxo` asserting that it is spendable by calling [`asset`] and
    /// [`void_number`] and checking that the computed [`VoidNumber`] is equal to `void_number`.
    ///
    /// [`asset`]: Mint::asset
    /// [`void_number`]: Self::void_number
    /// [`VoidNumber`]: Self::VoidNumber
    #[inline]
    fn spendable_asset(
        &self,
        mint_secret: &Self::MintSecret,
        spend_secret: &Self::SpendSecret,
        utxo: &Self::Utxo,
        void_number: &Self::VoidNumber,
        compiler: &mut COM,
    ) -> Self::Asset
    where
        COM: AssertEq,
        Self::VoidNumber: PartialEq<Self::VoidNumber, COM>,
    {
        let asset = self.asset(mint_secret, utxo, compiler);
        let computed_void_number = self.void_number(mint_secret, spend_secret, utxo, compiler);
        compiler.assert_eq(void_number, &computed_void_number);
        asset
    }
}
