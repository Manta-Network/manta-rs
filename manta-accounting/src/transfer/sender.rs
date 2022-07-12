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

use crate::transfer::utxo::{
    Spend, UtxoAccumulatorItem, UtxoAccumulatorOutput, UtxoMembershipProof,
};
use core::{fmt::Debug, hash::Hash, iter};
use manta_crypto::{
    accumulator::{self, Accumulator},
    constraint::{
        self, Allocate, Allocator, Assert, AssertEq, Const, Constant, Derived, ProofSystemInput,
        Public, Secret, Var, Variable,
    },
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Pre-Sender
pub struct PreSender<S>
where
    S: Spend,
{
    /// Spending Secret
    secret: S::Secret,

    /// Unspent Transaction Output
    utxo: S::Utxo,

    /// Nullifier
    nullifier: S::Nullifier,
}

impl<S> PreSender<S>
where
    S: Spend,
{
    /// Builds a new [`PreSender`] from `secret`, `utxo`, and `nullifier`.
    #[inline]
    pub fn new(secret: S::Secret, utxo: S::Utxo, nullifier: S::Nullifier) -> Self {
        Self {
            secret,
            utxo,
            nullifier,
        }
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_accumulator` with the intention
    /// of returning a proof later by a call to [`get_proof`](Self::get_proof).
    #[inline]
    pub fn insert_utxo<A>(&self, parameters: &S, utxo_accumulator: &mut A) -> bool
    where
        A: Accumulator<Item = UtxoAccumulatorItem<S>, Model = S::UtxoAccumulatorModel>,
    {
        utxo_accumulator.insert(&parameters.item_hash(&self.utxo, &mut ()))
    }

    /// Requests the membership proof of the [`Utxo`] corresponding to `self` from
    /// `utxo_accumulator` to prepare the conversion from `self` into a [`Sender`].
    #[inline]
    pub fn get_proof<A>(&self, parameters: &S, utxo_accumulator: &A) -> Option<SenderProof<S>>
    where
        A: Accumulator<Item = UtxoAccumulatorItem<S>, Model = S::UtxoAccumulatorModel>,
    {
        Some(SenderProof {
            utxo_membership_proof: utxo_accumulator
                .prove(&parameters.item_hash(&self.utxo, &mut ()))?,
        })
    }

    /// Converts `self` into a [`Sender`] by attaching `proof` to it.
    #[inline]
    pub fn upgrade(self, proof: SenderProof<S>) -> Sender<S> {
        Sender {
            secret: self.secret,
            utxo: self.utxo,
            utxo_membership_proof: proof.utxo_membership_proof,
            nullifier: self.nullifier,
        }
    }

    /// Tries to convert `self` into a [`Sender`] by getting a proof from `utxo_accumulator`.
    #[inline]
    pub fn try_upgrade<A>(self, parameters: &S, utxo_accumulator: &A) -> Option<Sender<S>>
    where
        A: Accumulator<Item = UtxoAccumulatorItem<S>, Model = S::UtxoAccumulatorModel>,
    {
        Some(self.get_proof(parameters, utxo_accumulator)?.upgrade(self))
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_accumulator` and upgrades to a
    /// full [`Sender`] if the insertion succeeded.
    #[inline]
    pub fn insert_and_upgrade<A>(
        self,
        parameters: &S,
        utxo_accumulator: &mut A,
    ) -> Option<Sender<S>>
    where
        A: Accumulator<Item = UtxoAccumulatorItem<S>, Model = S::UtxoAccumulatorModel>,
    {
        if self.insert_utxo(parameters, utxo_accumulator) {
            self.try_upgrade(parameters, utxo_accumulator)
        } else {
            None
        }
    }

    /// Returns `true` whenever `self.utxo` and `rhs.utxo` can be inserted in any order into the
    /// `utxo_accumulator`.
    #[inline]
    pub fn is_independent_from<A>(&self, rhs: &Self, parameters: &S, utxo_accumulator: &A) -> bool
    where
        A: Accumulator<Item = UtxoAccumulatorItem<S>, Model = S::UtxoAccumulatorModel>,
    {
        utxo_accumulator.are_independent(
            &parameters.item_hash(&self.utxo, &mut ()),
            &parameters.item_hash(&rhs.utxo, &mut ()),
        )
    }
}

/// Sender Proof
///
/// This `struct` is created by the [`get_proof`](PreSender::get_proof) method on [`PreSender`].
/// See its documentation for more.
pub struct SenderProof<S>
where
    S: Spend,
{
    /// UTXO Membership Proof
    utxo_membership_proof: UtxoMembershipProof<S>,
}

impl<S> SenderProof<S>
where
    S: Spend,
{
    /// Upgrades the `pre_sender` to a [`Sender`] by attaching `self` to it.
    #[inline]
    pub fn upgrade(self, pre_sender: PreSender<S>) -> Sender<S> {
        pre_sender.upgrade(self)
    }
}

/// Sender
pub struct Sender<S, COM = ()>
where
    S: Spend<COM>,
{
    /// Spending Secret
    secret: S::Secret,

    /// Unspent Transaction Output
    utxo: S::Utxo,

    /// UTXO Membership Proof
    utxo_membership_proof: UtxoMembershipProof<S, COM>,

    /// Nullifier
    nullifier: S::Nullifier,
}

impl<S, COM> Sender<S, COM>
where
    S: Spend<COM>,
{
    /// Builds a new [`Sender`] from `secret`, `utxo`, and `nullifier`.
    #[inline]
    pub fn new(
        secret: S::Secret,
        utxo: S::Utxo,
        utxo_membership_proof: UtxoMembershipProof<S, COM>,
        nullifier: S::Nullifier,
    ) -> Self {
        Self {
            secret,
            utxo,
            utxo_membership_proof,
            nullifier,
        }
    }

    /// Returns the asset underlying `self`, asserting that `self` is well-formed.
    #[inline]
    pub fn well_formed_asset(
        &self,
        parameters: &S,
        utxo_accumulator_model: &S::UtxoAccumulatorModel,
        authority: &S::Authority,
        compiler: &mut COM,
    ) -> S::Asset
    where
        COM: Assert,
        S::Nullifier: constraint::PartialEq<S::Nullifier, COM>,
    {
        let (asset, nullifier) = parameters.well_formed_asset(
            utxo_accumulator_model,
            authority,
            &self.secret,
            &self.utxo,
            &self.utxo_membership_proof,
            compiler,
        );
        compiler.assert_eq(&self.nullifier, &nullifier);
        asset
    }
}

impl<S> Sender<S>
where
    S: Spend,
{
    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input<P>(&self, input: &mut P::Input)
    where
        P: ProofSystemInput<UtxoAccumulatorOutput<S>> + ProofSystemInput<S::Nullifier>,
    {
        P::extend(input, self.utxo_membership_proof.output());
        P::extend(input, &self.nullifier);
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> SenderPost<S> {
        SenderPost::new(self.utxo_membership_proof.into_output(), self.nullifier)
    }
}

impl<S, COM> Variable<Derived, COM> for Sender<S, COM>
where
    S: Spend<COM> + Constant<COM>,
    S::UtxoAccumulatorModel: Constant<COM>,
    Const<S::UtxoAccumulatorModel, COM>: accumulator::Model,
    S::Secret: Variable<Secret, COM>,
    S::Utxo: Variable<Secret, COM>,
    UtxoMembershipProof<S, COM>:
        Variable<Derived<(Secret, Public)>, COM, Type = UtxoMembershipProof<S::Type>>,
    S::Nullifier: Variable<Public, COM>,
    S::Type: Spend<
        UtxoAccumulatorModel = Const<S::UtxoAccumulatorModel, COM>,
        Secret = Var<S::Secret, Secret, COM>,
        Utxo = Var<S::Utxo, Secret, COM>,
        Nullifier = Var<S::Nullifier, Public, COM>,
    >,
{
    type Type = Sender<S::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(
            compiler.allocate_unknown(),
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
            this.utxo_membership_proof.as_known(compiler),
            this.nullifier.as_known(compiler),
        )
    }
}

/// Sender Ledger
///
/// This is the validation trait for ensuring that a particular instance of [`Sender`] is valid
/// according to the ledger state. These methods are the minimum required for a ledger which accepts
/// the [`Sender`] abstraction.
pub trait SenderLedger<S>
where
    S: Spend,
{
    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`SenderLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Valid UTXO Accumulator Output Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`UtxoAccumulatorOutput<S>`] that can only be
    /// constructed by this implementation of [`SenderLedger`]. This is to prevent that [`spend`] is
    /// called before [`is_unspent`] and [`has_matching_utxo_accumulator_output`].
    ///
    /// [`UtxoAccumulatorOutput<S>`]: UtxoAccumulatorOutput
    /// [`spend`]: Self::spend
    /// [`is_unspent`]: Self::is_unspent
    /// [`has_matching_utxo_accumulator_output`]: Self::has_matching_utxo_accumulator_output
    type ValidUtxoAccumulatorOutput: AsRef<UtxoAccumulatorOutput<S>>;

    /// Valid [`Nullifier`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`Nullifier`] that can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`] is called before
    /// [`is_unspent`] and [`has_matching_utxo_accumulator_output`].
    ///
    /// [`spend`]: Self::spend
    /// [`is_unspent`]: Self::is_unspent
    /// [`has_matching_utxo_accumulator_output`]: Self::has_matching_utxo_accumulator_output
    type ValidNullifier: AsRef<S::Nullifier>;

    /// Checks if the ledger already contains the `nullifier` in its set of nullifiers.
    ///
    /// Existence of such a nullifier could indicate a possible double-spend and so the ledger does
    /// not accept duplicates.
    fn is_unspent(&self, nullifier: S::Nullifier) -> Option<Self::ValidNullifier>;

    /// Checks if `output` matches the current accumulated value of the UTXO accumulator that is
    /// stored on the ledger.
    ///
    /// Failure to match the ledger state means that the sender was constructed under an invalid or
    /// older state of the ledger.
    fn has_matching_utxo_accumulator_output(
        &self,
        output: UtxoAccumulatorOutput<S>,
    ) -> Option<Self::ValidUtxoAccumulatorOutput>;

    /// Posts the `nullifier` to the ledger, spending the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `nullifier` is not already stored on
    /// the ledger. See [`is_unspent`](Self::is_unspent) for more.
    ///
    /// # Implementation Note
    ///
    /// This method, by defualt, calls the [`spend_all`] method on an iterator of length one
    /// containing `(utxo_accumulator_output, nullifier)`. Either [`spend`] or [`spend_all`] can be
    /// implemented depending on which is more efficient.
    ///
    /// [`spend`]: Self::spend
    /// [`spend_all`]: Self::spend_all
    #[inline]
    fn spend(
        &mut self,
        super_key: &Self::SuperPostingKey,
        utxo_accumulator_output: Self::ValidUtxoAccumulatorOutput,
        nullifier: Self::ValidNullifier,
    ) {
        self.spend_all(super_key, iter::once((utxo_accumulator_output, nullifier)))
    }

    /// Posts all of the [`Nullifier`]s to the ledger, spending the assets.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that all the [`Nullifier`]s are not already
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
    fn spend_all<I>(&mut self, super_key: &Self::SuperPostingKey, iter: I)
    where
        I: IntoIterator<Item = (Self::ValidUtxoAccumulatorOutput, Self::ValidNullifier)>,
    {
        for (utxo_accumulator_output, nullifier) in iter {
            self.spend(super_key, utxo_accumulator_output, nullifier)
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
    /// Invalid UTXO Accumulator Output Error
    ///
    /// The sender was not constructed under the current state of the UTXO accumulator.
    InvalidUtxoAccumulatorOutput,

    /// Asset Spent Error
    ///
    /// The asset has already been spent.
    AssetSpent,
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
            deserialize = "UtxoAccumulatorOutput<S>: Deserialize<'de>, S::Nullifier: Deserialize<'de>",
            serialize = "UtxoAccumulatorOutput<S>: Serialize, S::Nullifier: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "UtxoAccumulatorOutput<S>: Clone, S::Nullifier: Clone"),
    Copy(bound = "UtxoAccumulatorOutput<S>: Copy, S::Nullifier: Copy"),
    Debug(bound = "UtxoAccumulatorOutput<S>: Debug, S::Nullifier: Debug"),
    Eq(bound = "UtxoAccumulatorOutput<S>: Eq, S::Nullifier: Eq"),
    Hash(bound = "UtxoAccumulatorOutput<S>: Hash, S::Nullifier: Hash"),
    PartialEq(bound = "UtxoAccumulatorOutput<S>: PartialEq, S::Nullifier: PartialEq")
)]
pub struct SenderPost<S>
where
    S: Spend,
{
    /// UTXO Accumulator Output
    pub utxo_accumulator_output: UtxoAccumulatorOutput<S>,

    /// Nullifier
    pub nullifier: S::Nullifier,
}

impl<S> SenderPost<S>
where
    S: Spend,
{
    /// Builds a new [`SenderPost`] from `utxo_accumulator_output` and `nullifier`.
    #[inline]
    pub fn new(utxo_accumulator_output: UtxoAccumulatorOutput<S>, nullifier: S::Nullifier) -> Self {
        Self {
            utxo_accumulator_output,
            nullifier,
        }
    }

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input<P>(&self, input: &mut P::Input)
    where
        P: ProofSystemInput<UtxoAccumulatorOutput<S>> + ProofSystemInput<S::Nullifier>,
    {
        P::extend(input, &self.utxo_accumulator_output);
        P::extend(input, &self.nullifier);
    }

    /// Validates `self` on the sender `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<SenderPostingKey<S, L>, SenderPostError>
    where
        L: SenderLedger<S>,
    {
        Ok(SenderPostingKey {
            utxo_accumulator_output: ledger
                .has_matching_utxo_accumulator_output(self.utxo_accumulator_output)
                .ok_or(SenderPostError::InvalidUtxoAccumulatorOutput)?,
            nullifier: ledger
                .is_unspent(self.nullifier)
                .ok_or(SenderPostError::AssetSpent)?,
        })
    }
}

/// Sender Posting Key
pub struct SenderPostingKey<S, L>
where
    S: Spend,
    L: SenderLedger<S> + ?Sized,
{
    /// UTXO Accumulator Output Posting Key
    utxo_accumulator_output: L::ValidUtxoAccumulatorOutput,

    /// Nullifier Posting Key
    nullifier: L::ValidNullifier,
}

impl<S, L> SenderPostingKey<S, L>
where
    S: Spend,
    L: SenderLedger<S> + ?Sized,
{
    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input<P>(&self, input: &mut P::Input)
    where
        P: ProofSystemInput<UtxoAccumulatorOutput<S>> + ProofSystemInput<S::Nullifier>,
    {
        P::extend(input, self.utxo_accumulator_output.as_ref());
        P::extend(input, self.nullifier.as_ref());
    }

    /// Posts `self` to the sender `ledger`.
    #[inline]
    pub fn post(self, ledger: &mut L, super_key: &L::SuperPostingKey) {
        ledger.spend(super_key, self.utxo_accumulator_output, self.nullifier);
    }

    /// Posts all of the [`SenderPostingKey`] in `iter` to the sender `ledger`.
    #[inline]
    pub fn post_all<I>(iter: I, ledger: &mut L, super_key: &L::SuperPostingKey)
    where
        I: IntoIterator<Item = Self>,
    {
        ledger.spend_all(
            super_key,
            iter.into_iter()
                .map(move |k| (k.utxo_accumulator_output, k.nullifier)),
        )
    }
}

/*
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
    constraint::{Allocate, Allocator, AssertEq, Derived, ProofSystemInput, Variable},
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
    nullifier: S::Nullifier,
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
            nullifier: parameters.nullifier(&secret_spend_key, &utxo),
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
            nullifier: self.nullifier,
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

    /// Returns `true` whenever `self.utxo` and `rhs.utxo` can be inserted in any order into the
    /// `utxo_accumulator`.
    #[inline]
    pub fn is_independent_from<A>(&self, rhs: &Self, utxo_accumulator: &A) -> bool
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        utxo_accumulator.are_independent(&self.utxo, &rhs.utxo)
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
    nullifier: S::Nullifier,
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

    /// Returns `true` whenever `self.utxo` and `rhs.utxo` can be inserted in any order into the
    /// `utxo_accumulator`.
    #[inline]
    pub fn is_independent_from<A>(&self, rhs: &Self, utxo_accumulator: &A) -> bool
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        utxo_accumulator.are_independent(&self.utxo, &rhs.utxo)
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
            nullifier: self.nullifier,
        }
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> SenderPost<C> {
        SenderPost {
            utxo_accumulator_output: self.utxo_membership_proof.into_output(),
            nullifier: self.nullifier,
        }
    }

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input(&self, input: &mut ProofInput<C>) {
        C::ProofSystem::extend(input, self.utxo_membership_proof.output());
        C::ProofSystem::extend(input, &self.nullifier);
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
    nullifier: VoidNumberVar<C>,
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
        let nullifier = parameters.nullifier(&self.secret_spend_key, &utxo, compiler);
        compiler.assert_eq(&self.nullifier, &nullifier);
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
            nullifier: this.nullifier.as_known(compiler),
        }
    }

    #[inline]
    fn new_unknown(compiler: &mut C::Compiler) -> Self {
        Self {
            secret_spend_key: compiler.allocate_unknown(),
            ephemeral_secret_key: compiler.allocate_unknown(),
            asset: compiler.allocate_unknown(),
            utxo_membership_proof: compiler.allocate_unknown(),
            nullifier: compiler.allocate_unknown(),
        }
    }
}

*/
