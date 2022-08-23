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

//! Transfer Sender

use crate::{
    asset::{Asset, AssetValue},
    transfer::{
        AssetVar, Configuration, FullParametersVar, Parameters, ProofInput, SecretKey,
        SecretKeyVar, Utxo, UtxoAccumulatorOutput, UtxoMembershipProof, UtxoMembershipProofVar,
        VoidNumber, VoidNumberVar,
    },
};
use core::{fmt::Debug, hash::Hash, iter};
use manta_crypto::{
    accumulator::Accumulator,
    constraint::HasInput,
    eclair::{
        alloc::{mode::Derived, Allocate, Allocator, Variable},
        bool::AssertEq,
    },
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Pre-Sender
pub struct PreSender<C>
where
    C: Configuration,
{
    /// Secret Spend Key
    secret_spend_key: SecretKey<C>,

    /// Ephemeral Secret Key
    ephemeral_secret_key: SecretKey<C>,

    /// Asset
    asset: Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C> PreSender<C>
where
    C: Configuration,
{
    /// Builds a new [`PreSender`] from `ephemeral_secret_key` to claim `asset` with
    /// `secret_spend_key`.
    #[inline]
    pub fn new(
        parameters: &Parameters<C>,
        secret_spend_key: SecretKey<C>,
        ephemeral_secret_key: SecretKey<C>,
        asset: Asset,
    ) -> Self {
        let utxo = parameters.utxo(
            &ephemeral_secret_key,
            &parameters.derive(&secret_spend_key),
            &asset,
        );
        Self {
            void_number: parameters.void_number(&secret_spend_key, &utxo),
            secret_spend_key,
            ephemeral_secret_key,
            asset,
            utxo,
        }
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_accumulator` with the intention
    /// of returning a proof later by a call to [`get_proof`](Self::get_proof).
    #[inline]
    pub fn insert_utxo<A>(&self, utxo_accumulator: &mut A) -> bool
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        utxo_accumulator.insert(&self.utxo)
    }

    /// Requests the membership proof of the [`Utxo`] corresponding to `self` from
    /// `utxo_accumulator` to prepare the conversion from `self` into a [`Sender`].
    #[inline]
    pub fn get_proof<A>(&self, utxo_accumulator: &A) -> Option<SenderProof<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        Some(SenderProof {
            utxo_membership_proof: utxo_accumulator.prove(&self.utxo)?,
        })
    }

    /// Converts `self` into a [`Sender`] by attaching `proof` to it.
    #[inline]
    pub fn upgrade(self, proof: SenderProof<C>) -> Sender<C> {
        Sender {
            secret_spend_key: self.secret_spend_key,
            ephemeral_secret_key: self.ephemeral_secret_key,
            asset: self.asset,
            utxo: self.utxo,
            utxo_membership_proof: proof.utxo_membership_proof,
            void_number: self.void_number,
        }
    }

    /// Tries to convert `self` into a [`Sender`] by getting a proof from `utxo_accumulator`.
    #[inline]
    pub fn try_upgrade<A>(self, utxo_accumulator: &A) -> Option<Sender<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        Some(self.get_proof(utxo_accumulator)?.upgrade(self))
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_accumulator` and upgrades to a
    /// full [`Sender`] if the insertion succeeded.
    #[inline]
    pub fn insert_and_upgrade<A>(self, utxo_accumulator: &mut A) -> Option<Sender<C>>
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        if self.insert_utxo(utxo_accumulator) {
            self.try_upgrade(utxo_accumulator)
        } else {
            None
        }
    }
}

/// Sender Proof
///
/// This `struct` is created by the [`get_proof`](PreSender::get_proof) method on [`PreSender`].
/// See its documentation for more.
pub struct SenderProof<C>
where
    C: Configuration,
{
    /// UTXO Membership Proof
    utxo_membership_proof: UtxoMembershipProof<C>,
}

impl<C> SenderProof<C>
where
    C: Configuration,
{
    /// Upgrades the `pre_sender` to a [`Sender`] by attaching `self` to it.
    #[inline]
    pub fn upgrade(self, pre_sender: PreSender<C>) -> Sender<C> {
        pre_sender.upgrade(self)
    }
}

/// Sender
pub struct Sender<C>
where
    C: Configuration,
{
    /// Secret Spend Key
    secret_spend_key: SecretKey<C>,

    /// Ephemeral Secret Key
    ephemeral_secret_key: SecretKey<C>,

    /// Asset
    asset: Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// UTXO Membership Proof
    utxo_membership_proof: UtxoMembershipProof<C>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C> Sender<C>
where
    C: Configuration,
{
    /// Returns the asset value sent by `self` in the transaction.
    #[inline]
    pub fn asset_value(&self) -> AssetValue {
        self.asset.value
    }

    /// Reverts `self` back into a [`PreSender`].
    ///
    /// This method should be called if the [`Utxo`] membership proof attached to `self` was deemed
    /// invalid or had expired.
    #[inline]
    pub fn downgrade(self) -> PreSender<C> {
        PreSender {
            secret_spend_key: self.secret_spend_key,
            ephemeral_secret_key: self.ephemeral_secret_key,
            asset: self.asset,
            utxo: self.utxo,
            void_number: self.void_number,
        }
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> SenderPost<C> {
        SenderPost {
            utxo_accumulator_output: self.utxo_membership_proof.into_output(),
            void_number: self.void_number,
        }
    }

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        C::ProofSystem::extend(input, self.utxo_membership_proof.output());
        C::ProofSystem::extend(input, &self.void_number);
    }
}

/// Sender Variable
pub struct SenderVar<C>
where
    C: Configuration,
{
    /// Secret Spend Key
    secret_spend_key: SecretKeyVar<C>,

    /// Ephemeral Secret Key
    ephemeral_secret_key: SecretKeyVar<C>,

    /// Asset
    asset: AssetVar<C>,

    /// UTXO Membership Proof
    utxo_membership_proof: UtxoMembershipProofVar<C>,

    /// Void Number
    void_number: VoidNumberVar<C>,
}

impl<C> SenderVar<C>
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
        let public_spend_key = parameters.derive(&self.secret_spend_key, compiler);
        let utxo = parameters.utxo(
            &self.ephemeral_secret_key,
            &public_spend_key,
            &self.asset,
            compiler,
        );
        self.utxo_membership_proof.assert_valid(
            &parameters.utxo_accumulator_model,
            &utxo,
            compiler,
        );
        let void_number = parameters.void_number(&self.secret_spend_key, &utxo, compiler);
        compiler.assert_eq(&self.void_number, &void_number);
        self.asset
    }
}

impl<C> Variable<Derived, C::Compiler> for SenderVar<C>
where
    C: Configuration,
{
    type Type = Sender<C>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
        Self {
            secret_spend_key: this.secret_spend_key.as_known(compiler),
            ephemeral_secret_key: this.ephemeral_secret_key.as_known(compiler),
            asset: this.asset.as_known(compiler),
            utxo_membership_proof: this.utxo_membership_proof.as_known(compiler),
            void_number: this.void_number.as_known(compiler),
        }
    }

    #[inline]
    fn new_unknown(compiler: &mut C::Compiler) -> Self {
        Self {
            secret_spend_key: compiler.allocate_unknown(),
            ephemeral_secret_key: compiler.allocate_unknown(),
            asset: compiler.allocate_unknown(),
            utxo_membership_proof: compiler.allocate_unknown(),
            void_number: compiler.allocate_unknown(),
        }
    }
}

/// Sender Ledger
///
/// This is the validation trait for ensuring that a particular instance of [`Sender`] is valid
/// according to the ledger state. These methods are the minimum required for a ledger which accepts
/// the [`Sender`] abstraction.
pub trait SenderLedger<C>
where
    C: Configuration,
{
    /// Valid [`VoidNumber`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`VoidNumber`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`has_matching_utxo_accumulator_output`](Self::has_matching_utxo_accumulator_output).
    type ValidVoidNumber: AsRef<VoidNumber<C>>;

    /// Valid UTXO Accumulator Output Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`S::Output`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`has_matching_utxo_accumulator_output`](Self::has_matching_utxo_accumulator_output).
    ///
    /// [`S::Output`]: manta_crypto::accumulator::Types::Output
    type ValidUtxoAccumulatorOutput: AsRef<UtxoAccumulatorOutput<C>>;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`SenderLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks if the ledger already contains the `void_number` in its set of void numbers.
    ///
    /// Existence of such a void number could indicate a possible double-spend.
    fn is_unspent(&self, void_number: VoidNumber<C>) -> Option<Self::ValidVoidNumber>;

    /// Checks if `output` matches the current accumulated value of the UTXO accumulator that is
    /// stored on the ledger.
    ///
    /// Failure to match the ledger state means that the sender was constructed under an invalid or
    /// older state of the ledger.
    fn has_matching_utxo_accumulator_output(
        &self,
        output: UtxoAccumulatorOutput<C>,
    ) -> Option<Self::ValidUtxoAccumulatorOutput>;

    /// Posts the `void_number` to the ledger, spending the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `void_number` is not already stored on
    /// the ledger. See [`is_unspent`](Self::is_unspent) for more.
    ///
    /// # Implementation Note
    ///
    /// This method, by defualt, calls the [`spend_all`] method on an iterator of length one
    /// containing `(utxo, encrypted_note)`. Either [`spend`] or [`spend_all`] can be implemented
    /// depending on which is more efficient.
    ///
    /// [`spend`]: Self::spend
    /// [`spend_all`]: Self::spend_all
    #[inline]
    fn spend(
        &mut self,
        utxo_accumulator_output: Self::ValidUtxoAccumulatorOutput,
        void_number: Self::ValidVoidNumber,
        super_key: &Self::SuperPostingKey,
    ) {
        self.spend_all(
            iter::once((utxo_accumulator_output, void_number)),
            super_key,
        )
    }

    /// Posts all of the [`VoidNumber`] to the ledger, spending the assets.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that all the [`VoidNumber`] are not already
    /// stored on the ledger. See [`is_unspent`](Self::is_unspent) for more.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for multiple calls to [`spend`] and by default just
    /// iterates over `iter` calling [`spend`] on each item returned. Either [`spend`] or
    /// [`spend_all`] can be implemented depending on which is more efficient.
    ///
    /// [`spend`]: Self::spend
    /// [`spend_all`]: Self::spend_all
    #[inline]
    fn spend_all<I>(&mut self, iter: I, super_key: &Self::SuperPostingKey)
    where
        I: IntoIterator<Item = (Self::ValidUtxoAccumulatorOutput, Self::ValidVoidNumber)>,
    {
        for (utxo_accumulator_output, void_number) in iter {
            self.spend(utxo_accumulator_output, void_number, super_key)
        }
    }
}

/// Sender Post Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SenderPostError {
    /// Asset Spent Error
    ///
    /// The asset has already been spent.
    AssetSpent,

    /// Invalid UTXO Accumulator Output Error
    ///
    /// The sender was not constructed under the current state of the UTXO accumulator.
    InvalidUtxoAccumulatorOutput,
}

/// Sender Post
///
/// This `struct` represents the public data required to verify that a particular instance of a
/// [`Sender`] should be valid according to the [`SenderLedger`]. The rest of the information
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
            deserialize = "UtxoAccumulatorOutput<C>: Deserialize<'de>, VoidNumber<C>: Deserialize<'de>",
            serialize = "UtxoAccumulatorOutput<C>: Serialize, VoidNumber<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "UtxoAccumulatorOutput<C>: Clone, VoidNumber<C>: Clone"),
    Copy(bound = "UtxoAccumulatorOutput<C>: Copy, VoidNumber<C>: Copy"),
    Debug(bound = "UtxoAccumulatorOutput<C>: Debug, VoidNumber<C>: Debug"),
    Eq(bound = "UtxoAccumulatorOutput<C>: Eq, VoidNumber<C>: Eq"),
    Hash(bound = "UtxoAccumulatorOutput<C>: Hash, VoidNumber<C>: Hash"),
    PartialEq(bound = "UtxoAccumulatorOutput<C>: PartialEq, VoidNumber<C>: PartialEq")
)]
pub struct SenderPost<C>
where
    C: Configuration,
{
    /// UTXO Accumulator Output
    pub utxo_accumulator_output: UtxoAccumulatorOutput<C>,

    /// Void Number
    pub void_number: VoidNumber<C>,
}

impl<C> SenderPost<C>
where
    C: Configuration,
{
    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        C::ProofSystem::extend(input, &self.utxo_accumulator_output);
        C::ProofSystem::extend(input, &self.void_number);
    }

    /// Validates `self` on the sender `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<SenderPostingKey<C, L>, SenderPostError>
    where
        L: SenderLedger<C>,
    {
        Ok(SenderPostingKey {
            utxo_accumulator_output: ledger
                .has_matching_utxo_accumulator_output(self.utxo_accumulator_output)
                .ok_or(SenderPostError::InvalidUtxoAccumulatorOutput)?,
            void_number: ledger
                .is_unspent(self.void_number)
                .ok_or(SenderPostError::AssetSpent)?,
        })
    }
}

/// Sender Posting Key
pub struct SenderPostingKey<C, L>
where
    C: Configuration,
    L: SenderLedger<C> + ?Sized,
{
    /// UTXO Accumulator Output Posting Key
    utxo_accumulator_output: L::ValidUtxoAccumulatorOutput,

    /// Void Number Posting Key
    void_number: L::ValidVoidNumber,
}

impl<C, L> SenderPostingKey<C, L>
where
    C: Configuration,
    L: SenderLedger<C> + ?Sized,
{
    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        C::ProofSystem::extend(input, self.utxo_accumulator_output.as_ref());
        C::ProofSystem::extend(input, self.void_number.as_ref());
    }

    /// Posts `self` to the sender `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.spend(self.utxo_accumulator_output, self.void_number, super_key);
    }

    /// Posts all of the [`SenderPostingKey`] in `iter` to the sender `ledger`.
    #[inline]
    pub fn post_all<I>(iter: I, super_key: &L::SuperPostingKey, ledger: &mut L)
    where
        I: IntoIterator<Item = Self>,
    {
        ledger.spend_all(
            iter.into_iter()
                .map(move |k| (k.utxo_accumulator_output, k.void_number)),
            super_key,
        )
    }
}
