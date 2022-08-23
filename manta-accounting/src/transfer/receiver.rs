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

//! Transfer Receiver

use crate::{
    asset::Asset,
    transfer::{
        AssetVar, Configuration, EncryptedNote, FullParametersVar, Note, Parameters, ProofInput,
        PublicKey, PublicKeyVar, SecretKey, SecretKeyVar, Utxo, UtxoVar,
    },
};
use core::{fmt::Debug, hash::Hash, iter};
use manta_crypto::{
    constraint::HasInput,
    eclair::{
        alloc::{
            mode::{Derived, Public},
            Allocate, Allocator, Variable,
        },
        bool::AssertEq,
    },
    encryption::{hybrid, Encrypt},
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Receiver
pub struct Receiver<C>
where
    C: Configuration,
{
    /// Public Spend Key
    public_spend_key: PublicKey<C>,

    /// Ephemeral Secret Spend Key
    ephemeral_secret_key: SecretKey<C>,

    /// Asset
    asset: Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Encrypted Note
    encrypted_note: EncryptedNote<C>,
}

impl<C> Receiver<C>
where
    C: Configuration,
{
    /// Build a new [`Receiver`] from `ephemeral_secret_key`, to send `asset` to the owners of
    /// `public_spend_key` and `public_view_key`.
    #[inline]
    pub fn new(
        parameters: &Parameters<C>,
        public_spend_key: PublicKey<C>,
        public_view_key: PublicKey<C>,
        ephemeral_secret_key: SecretKey<C>,
        asset: Asset,
    ) -> Self {
        let randomness = hybrid::Randomness::from_key(ephemeral_secret_key);
        Self {
            utxo: parameters.utxo(&randomness.ephemeral_secret_key, &public_spend_key, &asset),
            encrypted_note: parameters.note_encryption_scheme.encrypt_into(
                &public_view_key,
                &randomness,
                (),
                &Note::new(randomness.ephemeral_secret_key.clone(), asset),
                &mut (),
            ),
            ephemeral_secret_key: randomness.ephemeral_secret_key,
            public_spend_key,
            asset,
        }
    }

    /// Returns the ephemeral public key associated to `self`.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &PublicKey<C> {
        self.encrypted_note.ephemeral_public_key()
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> ReceiverPost<C> {
        ReceiverPost {
            utxo: self.utxo,
            encrypted_note: self.encrypted_note,
        }
    }

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        C::ProofSystem::extend(input, &self.utxo);
    }
}

/// Receiver Variable
pub struct ReceiverVar<C>
where
    C: Configuration,
{
    /// Ephemeral Secret Spend Key
    ephemeral_secret_key: SecretKeyVar<C>,

    /// Public Spend Key
    public_spend_key: PublicKeyVar<C>,

    /// Asset
    asset: AssetVar<C>,

    /// Unspent Transaction Output
    utxo: UtxoVar<C>,
}

impl<C> ReceiverVar<C>
where
    C: Configuration,
{
    /// Returns the asset for `self`, checking if `self` is well-formed.
    #[inline]
    pub fn get_well_formed_asset(
        self,
        parameters: &FullParametersVar<C>,
        compiler: &mut C::Compiler,
    ) -> AssetVar<C> {
        let utxo = parameters.utxo(
            &self.ephemeral_secret_key,
            &self.public_spend_key,
            &self.asset,
            compiler,
        );
        compiler.assert_eq(&self.utxo, &utxo);
        self.asset
    }
}

impl<C> Variable<Derived, C::Compiler> for ReceiverVar<C>
where
    C: Configuration,
{
    type Type = Receiver<C>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
        Self {
            ephemeral_secret_key: this.ephemeral_secret_key.as_known(compiler),
            public_spend_key: this.public_spend_key.as_known(compiler),
            asset: this.asset.as_known(compiler),
            utxo: this.utxo.as_known::<Public, _>(compiler),
        }
    }

    #[inline]
    fn new_unknown(compiler: &mut C::Compiler) -> Self {
        Self {
            ephemeral_secret_key: compiler.allocate_unknown(),
            public_spend_key: compiler.allocate_unknown(),
            asset: compiler.allocate_unknown(),
            utxo: compiler.allocate_unknown::<Public, _>(),
        }
    }
}

/// Receiver Ledger
///
/// This is the validation trait for ensuring that a particular instance of [`Receiver`] is valid
/// according to the ledger state. These methods are the minimum required for a ledger which accepts
/// the [`Receiver`] abstraction.
pub trait ReceiverLedger<C>
where
    C: Configuration,
{
    /// Valid [`Utxo`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`Utxo`] which can only be constructed by this
    /// implementation of [`ReceiverLedger`]. This is to prevent that [`register`](Self::register)
    /// is called before [`is_not_registered`](Self::is_not_registered).
    type ValidUtxo: AsRef<Utxo<C>>;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`ReceiverLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks if the ledger already contains the `utxo` in its set of UTXOs.
    ///
    /// Existence of such a UTXO could indicate a possible double-spend.
    fn is_not_registered(&self, utxo: Utxo<C>) -> Option<Self::ValidUtxo>;

    /// Posts the `utxo` and `encrypted_note` to the ledger, registering the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `utxo` is not already stored on the
    /// ledger. See [`is_not_registered`](Self::is_not_registered) for more.
    ///
    /// # Implementation Note
    ///
    /// This method, by default, calls the [`register_all`] method on an iterator of length one
    /// containing `(utxo, encrypted_note)`. Either [`register`] or [`register_all`] can be
    /// implemented depending on which is more efficient.
    ///
    /// [`register`]: Self::register
    /// [`register_all`]: Self::register_all
    #[inline]
    fn register(
        &mut self,
        utxo: Self::ValidUtxo,
        encrypted_note: EncryptedNote<C>,
        super_key: &Self::SuperPostingKey,
    ) {
        self.register_all(iter::once((utxo, encrypted_note)), super_key)
    }

    /// Posts all of the [`Utxo`] and [`EncryptedNote`] to the ledger, registering the assets.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that all the [`Utxo`] and [`EncryptedNote`] are
    /// not already stored on the ledger. See [`is_not_registered`](Self::is_not_registered) for
    /// more.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for multiple calls to [`register`] and by default just
    /// iterates over `iter` calling [`register`] on each item returned. Either [`register`] or
    /// [`register_all`] can be implemented depending on which is more efficient.
    ///
    /// [`register`]: Self::register
    /// [`register_all`]: Self::register_all
    #[inline]
    fn register_all<I>(&mut self, iter: I, super_key: &Self::SuperPostingKey)
    where
        I: IntoIterator<Item = (Self::ValidUtxo, EncryptedNote<C>)>,
    {
        for (utxo, encrypted_note) in iter {
            self.register(utxo, encrypted_note, super_key)
        }
    }
}

/// Receiver Post Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReceiverPostError {
    /// Asset Registered Error
    ///
    /// The asset has already been registered with the ledger.
    AssetRegistered,
}

/// Receiver Post
///
/// This `struct` represents the public data required to verify that a particular instance of a
/// [`Receiver`] should be valid according to the [`ReceiverLedger`]. The rest of the information
/// required to verify a [`Transfer`] is stored in the [`TransferPost`] which includes the [`Proof`]
/// of validity.
///
/// [`Transfer`]: crate::transfer::Transfer
/// [`TransferPost`]: crate::transfer::TransferPost
/// [`Proof`]: crate::transfer::Proof
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Utxo<C>: Deserialize<'de>, EncryptedNote<C>: Deserialize<'de>",
            serialize = "Utxo<C>: Serialize, EncryptedNote<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Utxo<C>: Clone, EncryptedNote<C>: Clone"),
    Copy(bound = "Utxo<C>: Copy, EncryptedNote<C>: Copy"),
    Debug(bound = "Utxo<C>: Debug, EncryptedNote<C>: Debug"),
    Eq(bound = "Utxo<C>: Eq, EncryptedNote<C>: Eq"),
    Hash(bound = "Utxo<C>: Hash, EncryptedNote<C>: Hash"),
    PartialEq(bound = "Utxo<C>: PartialEq, EncryptedNote<C>: PartialEq")
)]
pub struct ReceiverPost<C>
where
    C: Configuration,
{
    /// Unspent Transaction Output
    pub utxo: Utxo<C>,

    /// Encrypted Note
    pub encrypted_note: EncryptedNote<C>,
}

impl<C> ReceiverPost<C>
where
    C: Configuration,
{
    /// Returns the ephemeral public key associated to `self`.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &PublicKey<C> {
        self.encrypted_note.ephemeral_public_key()
    }

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        C::ProofSystem::extend(input, &self.utxo);
    }

    /// Validates `self` on the receiver `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<ReceiverPostingKey<C, L>, ReceiverPostError>
    where
        L: ReceiverLedger<C>,
    {
        Ok(ReceiverPostingKey {
            utxo: ledger
                .is_not_registered(self.utxo)
                .ok_or(ReceiverPostError::AssetRegistered)?,
            encrypted_note: self.encrypted_note,
        })
    }
}

/// Receiver Posting Key
pub struct ReceiverPostingKey<C, L>
where
    C: Configuration,
    L: ReceiverLedger<C> + ?Sized,
{
    /// UTXO Posting Key
    utxo: L::ValidUtxo,

    /// Encrypted Note
    encrypted_note: EncryptedNote<C>,
}

impl<C, L> ReceiverPostingKey<C, L>
where
    C: Configuration,
    L: ReceiverLedger<C> + ?Sized,
{
    /// Returns the ephemeral public key associated to `self`.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &PublicKey<C> {
        self.encrypted_note.ephemeral_public_key()
    }

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        C::ProofSystem::extend(input, self.utxo.as_ref());
    }

    /// Posts `self` to the receiver `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.register(self.utxo, self.encrypted_note, super_key);
    }

    /// Posts all the of the [`ReceiverPostingKey`] in `iter` to the receiver `ledger`.
    #[inline]
    pub fn post_all<I>(iter: I, super_key: &L::SuperPostingKey, ledger: &mut L)
    where
        I: IntoIterator<Item = Self>,
    {
        ledger.register_all(
            iter.into_iter().map(move |k| (k.utxo, k.encrypted_note)),
            super_key,
        )
    }
}
