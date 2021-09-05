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

use manta_crypto::{Set, VerifiedSet};

pub(crate) mod prelude {
    #[doc(inline)]
    pub use crate::ledger::Ledger;
}

/// Ledger Error
pub enum Error<L>
where
    L: Ledger + ?Sized,
{
    /// Asset has already been spent
    AssetSpent(
        /// Void Number
        L::VoidNumber,
    ),
    /// Asset has already been registered
    AssetRegistered(
        /// Unspent Transaction Output
        L::Utxo,
    ),
    /// Encrypted Asset has already been stored
    EncryptedAssetStored(
        /// Encrypted [`Asset`](crate::asset::Asset)
        L::EncryptedAsset,
    ),
    /// Utxo [`ContainmentProof`](manta_crypto::set::ContainmentProof) has an invalid public input
    InvalidUtxoState(
        /// UTXO Containment Proof Public Input
        <L::UtxoSet as VerifiedSet>::Public,
    ),
}

/// Post Trait
pub trait Post<L>
where
    L: Ledger + ?Sized,
{
    /// Posts an update to the ledger or returns an error if the update could not be
    /// completed successfully.
    fn post(self, ledger: &mut L) -> Result<(), Error<L>>;
}

/// Into Post Trait
pub trait IntoPost<L>
where
    L: Ledger + ?Sized,
{
    /// Post Data
    type IntoPost: Post<L>;

    /// Converts from `self` into its ledger [`Post`] data.
    fn into_post(self) -> Self::IntoPost;
}

/// Ledger Trait
pub trait Ledger {
    /// Void Number Type
    type VoidNumber;

    /// Void Number Set Type
    type VoidNumberSet: Set<Item = Self::VoidNumber>;

    /// Unspent Transaction Output Type
    type Utxo;

    /// UTXO Set Type
    type UtxoSet: VerifiedSet<Item = Self::Utxo>;

    /// Encrypted Asset Type
    type EncryptedAsset;

    /// Encrypted Asset Set Type
    type EncryptedAssetSet: Set<Item = Self::EncryptedAsset>;

    /// Returns a shared reference to the [`VoidNumberSet`](Self::VoidNumberSet).
    fn void_numbers(&self) -> &Self::VoidNumberSet;

    /// Returns a mutable reference to the [`VoidNumberSet`](Self::VoidNumberSet).
    fn void_numbers_mut(&mut self) -> &mut Self::VoidNumberSet;

    /// Returns a shared reference to the [`UtxoSet`](Self::UtxoSet).
    fn utxos(&self) -> &Self::UtxoSet;

    /// Returns a mutable reference to the [`UtxoSet`](Self::UtxoSet).
    fn utxos_mut(&mut self) -> &mut Self::UtxoSet;

    /// Returns a shared reference to the [`EncryptedAssetSet`](Self::EncryptedAssetSet).
    fn encrypted_assets(&self) -> &Self::EncryptedAssetSet;

    /// Returns a mutable reference to the [`EncryptedAssetSet`](Self::EncryptedAssetSet).
    fn encrypted_assets_mut(&mut self) -> &mut Self::EncryptedAssetSet;
}

/// Returns `true` if the `void_number` corresponding to some asset
/// __is not stored__ on the `ledger`.
#[inline]
pub fn is_unspent<L>(ledger: &L, void_number: &L::VoidNumber) -> bool
where
    L: Ledger + ?Sized,
{
    !ledger.void_numbers().contains(void_number)
}

/// Returns `true` if an asset's `utxo` __is stored__ on the `ledger` and that
/// its `void_number` __is not stored__ on the `ledger`.
#[inline]
pub fn is_spendable<L>(ledger: &L, void_number: &L::VoidNumber, utxo: &L::Utxo) -> bool
where
    L: Ledger + ?Sized,
{
    is_unspent(ledger, void_number) && ledger.utxos().contains(utxo)
}

/// Tries to post the `void_number` to the `ledger` returning [`Error::AssetSpent`] if the
/// `void_number` was already stored on the `ledger`.
#[inline]
pub fn try_post_void_number<L>(ledger: &mut L, void_number: L::VoidNumber) -> Result<(), Error<L>>
where
    L: Ledger + ?Sized,
{
    ledger
        .void_numbers_mut()
        .try_insert(void_number)
        .map_err(Error::AssetSpent)
}

/// Tries to post the `utxo` to the `ledger` returning [`Error::AssetRegistered`] if the
/// `utxo` was already stored on the `ledger`.
#[inline]
pub fn try_post_utxo<L>(ledger: &mut L, utxo: L::Utxo) -> Result<(), Error<L>>
where
    L: Ledger + ?Sized,
{
    ledger
        .utxos_mut()
        .try_insert(utxo)
        .map_err(Error::AssetRegistered)
}

/// Tries to post the `encrypted_asset` to the `ledger` returning [`Error::EncryptedAssetStored`]
/// if the `encrypted_asset` was already stored on the `ledger`.
#[inline]
pub fn try_post_encrypted_asset<L>(
    ledger: &mut L,
    encrypted_asset: L::EncryptedAsset,
) -> Result<(), Error<L>>
where
    L: Ledger + ?Sized,
{
    ledger
        .encrypted_assets_mut()
        .try_insert(encrypted_asset)
        .map_err(Error::EncryptedAssetStored)
}

/// Checks if the `public_input` corresponding to a UTXO containment proof represents the current
/// state of the [`UtxoSet`](Ledger::UtxoSet), returning [`Error::InvalidUtxoState`] if not.
#[inline]
pub fn check_utxo_containment_proof_public_input<L>(
    ledger: &mut L,
    public_input: <L::UtxoSet as VerifiedSet>::Public,
) -> Result<(), Error<L>>
where
    L: Ledger + ?Sized,
{
    if ledger.utxos().check_public_input(&public_input) {
        Ok(())
    } else {
        Err(Error::InvalidUtxoState(public_input))
    }
}
