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

use crate::transfer::utxo::{DeriveMint, Identifier, Mint, Note, QueryIdentifier};
use core::{fmt::Debug, hash::Hash, iter};
use eclair::alloc::{
    mode::{Derived, Public, Secret},
    Allocate, Allocator, Constant, Var, Variable,
};
use openzl_crypto::{
    accumulator::{Accumulator, ItemHashFunction},
    constraint::{HasInput, Input},
};
use openzl_util::{
    codec::{Encode, Write},
    rand::RngCore,
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Receiver
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "M::Secret: Deserialize<'de>, M::Utxo: Deserialize<'de>, M::Note: Deserialize<'de>",
            serialize = "M::Secret: Serialize, M::Utxo: Serialize, M::Note: Serialize",
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "M::Secret: Clone, M::Utxo: Clone, M::Note: Clone"),
    Copy(bound = "M::Secret: Copy, M::Utxo: Copy, M::Note: Copy"),
    Debug(bound = "M::Secret: Debug, M::Utxo: Debug, M::Note: Debug"),
    Default(bound = "M::Secret: Default, M::Utxo: Default, M::Note: Default"),
    Eq(bound = "M::Secret: Eq, M::Utxo: Eq, M::Note: Eq"),
    Hash(bound = "M::Secret: Hash, M::Utxo: Hash, M::Note: Hash"),
    PartialEq(bound = "M::Secret: PartialEq, M::Utxo: PartialEq, M::Note: PartialEq")
)]
pub struct Receiver<M, COM = ()>
where
    M: Mint<COM>,
{
    /// Minting Secret
    secret: M::Secret,

    /// Unspent Transaction Output
    utxo: M::Utxo,

    /// Note
    note: M::Note,
}

impl<M, COM> Receiver<M, COM>
where
    M: Mint<COM>,
{
    /// Builds a new [`Receiver`] from `secret`, `utxo`, and `note`.
    #[inline]
    pub fn new(secret: M::Secret, utxo: M::Utxo, note: M::Note) -> Self {
        Self { secret, utxo, note }
    }

    /// Returns the asset underlying `self`, asserting that `self` is well-formed.
    #[inline]
    pub fn well_formed_asset(&self, parameters: &M, compiler: &mut COM) -> M::Asset {
        parameters.well_formed_asset(&self.secret, &self.utxo, &self.note, compiler)
    }
}

impl<M> Receiver<M>
where
    M: Mint,
{
    /// Samples a new [`Receiver`] that will control `asset` at the given `address`.
    #[inline]
    pub fn sample<R>(
        parameters: &M,
        address: M::Address,
        asset: M::Asset,
        associated_data: M::AssociatedData,
        rng: &mut R,
    ) -> Self
    where
        M: DeriveMint,
        R: RngCore + ?Sized,
    {
        let (secret, utxo, note) = parameters.derive_mint(address, asset, associated_data, rng);
        Self::new(secret, utxo, note)
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_accumulator` with the intention
    /// of returning a proof later.
    ///
    /// [`Utxo`]: crate::transfer::utxo::UtxoType::Utxo
    #[inline]
    pub fn insert_utxo<A>(&self, parameters: &M, utxo_accumulator: &mut A) -> bool
    where
        M: ItemHashFunction<M::Utxo>,
        A: Accumulator<Item = M::Item>,
    {
        utxo_accumulator.insert(&parameters.item_hash(&self.utxo, &mut ()))
    }

    /// Returns the identifier for `self`.
    #[inline]
    pub fn identifier(&self) -> Identifier<M::Secret>
    where
        M::Secret: QueryIdentifier<Utxo = M::Utxo>,
    {
        self.secret.query_identifier(&self.utxo)
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> ReceiverPost<M> {
        ReceiverPost::new(self.utxo, self.note)
    }
}

impl<M, P> Input<P> for Receiver<M>
where
    M: Mint,
    P: HasInput<M::Utxo> + HasInput<M::Note> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.utxo);
        P::extend(input, &self.note);
    }
}

impl<M, COM> Variable<Derived, COM> for Receiver<M, COM>
where
    M: Mint<COM> + Constant<COM>,
    M::Secret: Variable<Secret, COM>,
    M::Utxo: Variable<Public, COM>,
    M::Note: Variable<Public, COM>,
    M::Type: Mint<Secret = Var<M::Secret, Secret, COM>, Utxo = Var<M::Utxo, Public, COM>>,
    Note<M::Type>: AsRef<Var<M::Note, Public, COM>>,
{
    type Type = Receiver<M::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.secret.as_known(compiler),
            this.utxo.as_known(compiler),
            this.note.as_ref().as_known(compiler),
        )
    }
}

/// Receiver Ledger
///
/// This is the validation trait for ensuring that a particular instance of [`Receiver`] is valid
/// according to the ledger state. These methods are the minimum required for a ledger which accepts
/// the [`Receiver`] abstraction.
pub trait ReceiverLedger<M>
where
    M: Mint,
{
    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`ReceiverLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Valid [`Utxo`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`Utxo`] which can only be constructed by this
    /// implementation of [`ReceiverLedger`]. This is to prevent that [`register`](Self::register)
    /// is called before [`is_not_registered`](Self::is_not_registered).
    ///
    /// [`Utxo`]: crate::transfer::utxo::UtxoType::Utxo
    type ValidUtxo: AsRef<M::Utxo>;

    /// Checks if the ledger already contains the `utxo` in its set of UTXOs.
    ///
    /// Existence of such a UTXO could indicate a possible double-spend.
    fn is_not_registered(&self, utxo: M::Utxo) -> Option<Self::ValidUtxo>;

    /// Posts the `utxo` and `note` to the ledger, registering the asset.
    ///
    /// # Crypto Safety
    ///
    /// This method can only be called once we check that `utxo` is not already stored on the
    /// ledger. See [`is_not_registered`](Self::is_not_registered) for more.
    ///
    /// # Implementation Note
    ///
    /// This method, by default, calls the [`register_all`] method on an iterator of length one
    /// containing `(utxo, note)`. Either [`register`] or [`register_all`] can be implemented
    /// depending on which is more efficient.
    ///
    /// [`register`]: Self::register
    /// [`register_all`]: Self::register_all
    #[inline]
    fn register(
        &mut self,
        super_key: &Self::SuperPostingKey,
        utxo: Self::ValidUtxo,
        note: M::Note,
    ) {
        self.register_all(super_key, iter::once((utxo, note)))
    }

    /// Posts all of the [`Utxo`] and [`Note`] to the ledger, registering the assets.
    ///
    /// # Crypto Safety
    ///
    /// This method can only be called once we check that all the [`Utxo`] and [`Note`] are not
    /// already stored on the ledger. See [`is_not_registered`](Self::is_not_registered) for more.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for multiple calls to [`register`] and by default just
    /// iterates over `iter` calling [`register`] on each item returned. Either [`register`] or
    /// [`register_all`] can be implemented depending on which is more efficient.
    ///
    /// [`Utxo`]: crate::transfer::utxo::UtxoType::Utxo
    /// [`Note`]: crate::transfer::utxo::NoteType::Note
    /// [`register`]: Self::register
    /// [`register_all`]: Self::register_all
    #[inline]
    fn register_all<I>(&mut self, super_key: &Self::SuperPostingKey, iter: I)
    where
        I: IntoIterator<Item = (Self::ValidUtxo, M::Note)>,
    {
        for (utxo, note) in iter {
            self.register(super_key, utxo, note)
        }
    }
}

/// Receiver Post Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ReceiverPostError {
    /// Asset Registered Error
    ///
    /// The asset has already been registered with the ledger.
    #[default]
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
            deserialize = "M::Utxo: Deserialize<'de>, M::Note: Deserialize<'de>",
            serialize = "M::Utxo: Serialize, M::Note: Serialize",
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "M::Utxo: Clone, M::Note: Clone"),
    Copy(bound = "M::Utxo: Copy, M::Note: Copy"),
    Debug(bound = "M::Utxo: Debug, M::Note: Debug"),
    Eq(bound = "M::Utxo: Eq, M::Note: Eq"),
    Hash(bound = "M::Utxo: Hash, M::Note: Hash"),
    PartialEq(bound = "M::Utxo: PartialEq, M::Note: PartialEq")
)]
pub struct ReceiverPost<M>
where
    M: Mint,
{
    /// Unspent Transaction Output
    pub utxo: M::Utxo,

    /// Note
    pub note: M::Note,
}

impl<M> ReceiverPost<M>
where
    M: Mint,
{
    /// Builds a new [`ReceiverPost`] from `utxo` and `note`.
    #[inline]
    pub fn new(utxo: M::Utxo, note: M::Note) -> Self {
        Self { utxo, note }
    }

    /// Validates `self` on the receiver `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<ReceiverPostingKey<M, L>, ReceiverPostError>
    where
        L: ReceiverLedger<M>,
    {
        Ok(ReceiverPostingKey {
            utxo: ledger
                .is_not_registered(self.utxo)
                .ok_or(ReceiverPostError::AssetRegistered)?,
            note: self.note,
        })
    }
}

impl<M> Encode for ReceiverPost<M>
where
    M: Mint,
    M::Utxo: Encode,
    M::Note: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.utxo.encode(&mut writer)?;
        self.note.encode(&mut writer)?;
        Ok(())
    }
}

impl<M, P> Input<P> for ReceiverPost<M>
where
    M: Mint,
    P: HasInput<M::Utxo> + HasInput<M::Note> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.utxo);
        P::extend(input, &self.note);
    }
}

/// Receiver Posting Key
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "L::ValidUtxo: Deserialize<'de>, M::Note: Deserialize<'de>",
            serialize = "L::ValidUtxo: Serialize, M::Note: Serialize",
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "L::ValidUtxo: Clone, M::Note: Clone"),
    Copy(bound = "L::ValidUtxo: Copy, M::Note: Copy"),
    Debug(bound = "L::ValidUtxo: Debug, M::Note: Debug"),
    Default(bound = "L::ValidUtxo: Default, M::Note: Default"),
    Eq(bound = "L::ValidUtxo: Eq, M::Note: Eq"),
    Hash(bound = "L::ValidUtxo: Hash, M::Note: Hash"),
    PartialEq(bound = "L::ValidUtxo: PartialEq, M::Note: PartialEq")
)]
pub struct ReceiverPostingKey<M, L>
where
    M: Mint,
    L: ReceiverLedger<M> + ?Sized,
{
    /// Valid UTXO Posting Key
    utxo: L::ValidUtxo,

    /// Note
    note: M::Note,
}

impl<M, L> ReceiverPostingKey<M, L>
where
    M: Mint,
    L: ReceiverLedger<M> + ?Sized,
{
    /// Posts `self` to the receiver `ledger`.
    #[inline]
    pub fn post(self, ledger: &mut L, super_key: &L::SuperPostingKey) {
        ledger.register(super_key, self.utxo, self.note);
    }

    /// Posts all the of the [`ReceiverPostingKey`]s in `iter` to the receiver `ledger`.
    #[inline]
    pub fn post_all<I>(iter: I, ledger: &mut L, super_key: &L::SuperPostingKey)
    where
        I: IntoIterator<Item = Self>,
    {
        ledger.register_all(super_key, iter.into_iter().map(move |k| (k.utxo, k.note)))
    }
}

impl<M, L, P> Input<P> for ReceiverPostingKey<M, L>
where
    M: Mint,
    L: ReceiverLedger<M> + ?Sized,
    P: HasInput<M::Utxo> + HasInput<M::Note> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, self.utxo.as_ref());
        P::extend(input, &self.note);
    }
}
