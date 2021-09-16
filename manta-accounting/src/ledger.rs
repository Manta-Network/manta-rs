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

//! Ledger Abstraction

use crate::identity::{ReceiverPostError, SenderPostError};
use manta_crypto::{
    constraint::ProofSystem,
    set::{Set, VerifiedSet},
};

/// Ledger Trait
pub trait Ledger {
    /// Void Number Type
    type VoidNumber;

    /// Unspent Transaction Output Type
    type Utxo;

    /// UTXO Set Type
    type UtxoSet: VerifiedSet<Item = Self::Utxo>;

    /// Encrypted Asset Type
    type EncryptedAsset;

    /// Proof System
    type ProofSystem: ProofSystem;

    /// Returns a shared reference to the [`UtxoSet`](Self::UtxoSet).
    fn utxos(&self) -> &Self::UtxoSet;

    /// Returns `true` if the `void_number` corresponding to some asset
    /// __is not stored__ on `self`.
    fn is_unspent(&self, void_number: &Self::VoidNumber) -> bool;

    /// Returns `true` if the `utxo` corresponding to some asset
    /// __is stored__ on `self`.
    #[inline]
    fn is_registered(&self, utxo: &Self::Utxo) -> bool {
        self.utxos().contains(utxo)
    }

    /// Returns `true` if an asset's `utxo` __is stored__ on the `ledger` and that
    /// its `void_number` __is not stored__ on `self`.
    #[inline]
    fn is_spendable(&self, utxo: &Self::Utxo, void_number: &Self::VoidNumber) -> bool {
        self.is_registered(utxo) && self.is_unspent(void_number)
    }

    /// Checks if the `public_input` corresponding to a UTXO containment proof represents the current
    /// state of the [`UtxoSet`](Self::UtxoSet), returning it back if not.
    #[inline]
    fn check_utxo_containment_proof_public_input(
        &self,
        public_input: <Self::UtxoSet as VerifiedSet>::Public,
    ) -> Result<(), <Self::UtxoSet as VerifiedSet>::Public> {
        if self.utxos().check_public_input(&public_input) {
            Ok(())
        } else {
            Err(public_input)
        }
    }

    /// Tries to post the `void_number` to `self` returning it back if the
    /// `void_number` was already stored on `self`.
    fn try_post_void_number(
        &mut self,
        void_number: Self::VoidNumber,
    ) -> Result<(), Self::VoidNumber>;

    /// Tries to post the `utxo` to `self` returning it back if the
    /// `utxo` was already stored on `self`.
    fn try_post_utxo(&mut self, utxo: Self::Utxo) -> Result<(), Self::Utxo>;

    /// Tries to post the `encrypted_asset` to `self` returning it back
    /// if the `encrypted_asset` was already stored on `self`.
    fn try_post_encrypted_asset(
        &mut self,
        encrypted_asset: Self::EncryptedAsset,
    ) -> Result<(), Self::EncryptedAsset>;

    /// Checks that the given `proof` is valid.
    fn check_proof(
        &self,
        proof: <Self::ProofSystem as ProofSystem>::Proof,
    ) -> Result<(), ProofPostError<Self>>;
}

/// Proof Post Error
pub enum ProofPostError<L>
where
    L: Ledger + ?Sized,
{
    /// Proof was invalid
    InvalidProof(
        /// Proof
        <L::ProofSystem as ProofSystem>::Proof,
        /// Proof Verification Error
        Option<<L::ProofSystem as ProofSystem>::Error>,
    ),
}

/// Ledger Post Error
pub enum PostError<L>
where
    L: Ledger + ?Sized,
{
    /// Sender Post Error
    Sender(SenderPostError<L>),

    /// Receiver Post Error
    Receiver(ReceiverPostError<L>),

    /// Proof Post Error
    Proof(ProofPostError<L>),
}

impl<L> From<SenderPostError<L>> for PostError<L>
where
    L: Ledger + ?Sized,
{
    #[inline]
    fn from(err: SenderPostError<L>) -> Self {
        Self::Sender(err)
    }
}

impl<L> From<ReceiverPostError<L>> for PostError<L>
where
    L: Ledger + ?Sized,
{
    #[inline]
    fn from(err: ReceiverPostError<L>) -> Self {
        Self::Receiver(err)
    }
}

impl<L> From<ProofPostError<L>> for PostError<L>
where
    L: Ledger + ?Sized,
{
    #[inline]
    fn from(err: ProofPostError<L>) -> Self {
        Self::Proof(err)
    }
}
