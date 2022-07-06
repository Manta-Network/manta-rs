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
//! to select the protocol version.

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

/// UTXO Generation
pub trait Generate<COM = ()> {
    /// Asset Type
    type Asset;

    /// Secret Type
    type Secret;

    /// Utxo Type
    type Utxo;

    /// Returns the asset inside the UTXO, asserting that the `secret` and `utxo` are well-formed.
    fn asset(&self, secret: &Self::Secret, utxo: &Self::Utxo, compiler: &mut COM) -> Self::Asset;
}

/// UTXO Spending
pub trait Spend<COM = ()>: Generate<COM> {
    /// UTXO Membership Proof
    type MembershipProof;

    /// Void Number Type
    type VoidNumber;

    /// Asserts that `membership_proof` constitutes a proof that `utxo` is contained in the
    /// appropriate accumulator.
    fn assert_membership(
        &self,
        utxo: &Self::Utxo,
        membership_proof: &Self::MembershipProof,
        compiler: &mut COM,
    );

    /// Computes the void number associated to `utxo`.
    fn void_number(&self, utxo: &Self::Utxo, compiler: &mut COM) -> Self::VoidNumber;

    /// Returns the asset inside the UTXo, asserting that the `secret` and `utxo` are well-formed
    /// and that the asset is spendable according to `membership_proof` and `void_number`.
    #[inline]
    fn spendable_asset(
        &self,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        membership_proof: &Self::MembershipProof,
        void_number: &Self::VoidNumber,
        compiler: &mut COM,
    ) -> Self::Asset
    where
        COM: AssertEq,
        Self::VoidNumber: PartialEq<Self::VoidNumber, COM>,
    {
        let asset = self.asset(secret, utxo, compiler);
        self.assert_membership(utxo, membership_proof, compiler);
        let expected_void_number = self.void_number(utxo, compiler);
        compiler.assert_eq(&expected_void_number, void_number);
        asset
    }
}
