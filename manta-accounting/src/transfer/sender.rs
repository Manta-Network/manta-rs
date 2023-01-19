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
    DeriveSpend, QueryAsset, Spend, UtxoAccumulatorItem, UtxoAccumulatorOutput, UtxoMembershipProof,
};
use core::{fmt::Debug, hash::Hash, iter};
use manta_crypto::{
    accumulator::{self, Accumulator, ItemHashFunction},
    constraint::{HasInput, Input},
    eclair::alloc::{
        mode::{Derived, Public, Secret},
        Allocate, Allocator, Const, Constant, Var, Variable,
    },
    rand::RngCore,
};
use manta_util::codec::{Encode, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Pre-Sender
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                S::Secret: Deserialize<'de>,
                S::Utxo: Deserialize<'de>,
                S::Nullifier: Deserialize<'de>",
            serialize = r"
                S::Secret: Serialize,
                S::Utxo: Serialize,
                S::Nullifier: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Secret: Clone, S::Utxo: Clone, S::Nullifier: Clone"),
    Copy(bound = "S::Secret: Copy, S::Utxo: Copy, S::Nullifier: Copy"),
    Debug(bound = "S::Secret: Debug, S::Utxo: Debug, S::Nullifier: Debug"),
    Default(bound = "S::Secret: Default, S::Utxo: Default, S::Nullifier: Default"),
    Eq(bound = "S::Secret: Eq, S::Utxo: Eq, S::Nullifier: Eq"),
    Hash(bound = "S::Secret: Hash, S::Utxo: Hash, S::Nullifier: Hash"),
    PartialEq(bound = "S::Secret: PartialEq, S::Utxo: PartialEq, S::Nullifier: PartialEq")
)]
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

    /// Samples a new [`PreSender`] that will control `asset` at the given `identifier`.
    #[inline]
    pub fn sample<R>(
        parameters: &S,
        authorization_context: &mut S::AuthorizationContext,
        identifier: S::Identifier,
        asset: S::Asset,
        rng: &mut R,
    ) -> Self
    where
        S: DeriveSpend,
        R: RngCore + ?Sized,
    {
        let (secret, utxo, nullifier) =
            parameters.derive_spend(authorization_context, identifier, asset, rng);
        Self::new(secret, utxo, nullifier)
    }

    /// Samples a new [`PreSender`], returning also its [`Utxo`].
    #[inline]
    pub fn sample_with_utxo<R>(
        parameters: &S,
        authorization_context: &mut S::AuthorizationContext,
        identifier: S::Identifier,
        asset: S::Asset,
        rng: &mut R,
    ) -> (Self, S::Utxo)
    where
        S: DeriveSpend,
        R: RngCore + ?Sized,
        S::Utxo: Clone,
    {
        let (secret, utxo, nullifier) =
            parameters.derive_spend(authorization_context, identifier, asset, rng);
        (Self::new(secret, utxo.clone(), nullifier), utxo)
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_accumulator` with the intention
    /// of returning a proof later by a call to [`get_proof`](Self::get_proof).
    ///
    /// [`Utxo`]: crate::transfer::utxo::UtxoType::Utxo
    #[inline]
    pub fn insert_utxo<A>(&self, parameters: &S, utxo_accumulator: &mut A) -> bool
    where
        A: Accumulator<Item = UtxoAccumulatorItem<S>, Model = S::UtxoAccumulatorModel>,
    {
        utxo_accumulator.insert(
            &parameters
                .utxo_accumulator_item_hash()
                .item_hash(&self.utxo, &mut ()),
        )
    }

    /// Requests the membership proof of the [`Utxo`] corresponding to `self` from
    /// `utxo_accumulator` to prepare the conversion from `self` into a [`Sender`].
    ///
    /// [`Utxo`]: crate::transfer::utxo::UtxoType::Utxo
    #[inline]
    pub fn get_proof<A>(&self, parameters: &S, utxo_accumulator: &A) -> Option<SenderProof<S>>
    where
        A: Accumulator<Item = UtxoAccumulatorItem<S>, Model = S::UtxoAccumulatorModel>,
    {
        Some(SenderProof {
            utxo_membership_proof: utxo_accumulator.prove(
                &parameters
                    .utxo_accumulator_item_hash()
                    .item_hash(&self.utxo, &mut ()),
            )?,
        })
    }

    /// Converts `self` into a [`Sender`] by attaching `proof` to it.
    #[inline]
    pub fn upgrade(self, proof: SenderProof<S>) -> Sender<S> {
        Self::upgrade_unchecked(self, proof.utxo_membership_proof)
    }

    /// Converts `self` into a [`Sender`] by attaching `proof` to it without necessarily checking
    /// that it comes from an accumulator or represents a valid proof.
    #[inline]
    pub fn upgrade_unchecked(self, proof: UtxoMembershipProof<S>) -> Sender<S> {
        Sender {
            secret: self.secret,
            utxo: self.utxo,
            utxo_membership_proof: proof,
            nullifier: self.nullifier,
        }
    }

    /// Converts `self` into a [`Sender`] by attaching a default [`UtxoMembershipProof`] to it which
    /// in general should not be a valid proof.
    #[inline]
    pub fn assign_default_proof_unchecked(self) -> Sender<S>
    where
        UtxoMembershipProof<S>: Default,
    {
        self.upgrade_unchecked(Default::default())
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
    ///
    /// [`Utxo`]: crate::transfer::utxo::UtxoType::Utxo
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
}

/// Sender Proof
///
/// This `struct` is created by the [`get_proof`](PreSender::get_proof) method on [`PreSender`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"UtxoMembershipProof<S>: Deserialize<'de>",
            serialize = r"UtxoMembershipProof<S>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "UtxoMembershipProof<S>: Clone"),
    Copy(bound = "UtxoMembershipProof<S>: Copy"),
    Debug(bound = "UtxoMembershipProof<S>: Debug"),
    Default(bound = "UtxoMembershipProof<S>: Default"),
    Eq(bound = "UtxoMembershipProof<S>: Eq"),
    Hash(bound = "UtxoMembershipProof<S>: Hash"),
    PartialEq(bound = "UtxoMembershipProof<S>: PartialEq")
)]
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
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                S::Secret: Deserialize<'de>,
                S::Utxo: Deserialize<'de>,
                UtxoMembershipProof<S, COM>: Deserialize<'de>,
                S::Nullifier: Deserialize<'de>",
            serialize = r"
                S::Secret: Serialize,
                S::Utxo: Serialize,
                UtxoMembershipProof<S, COM>: Serialize,
                S::Nullifier: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = r"
            S::Secret: Clone,
            S::Utxo: Clone,
            UtxoMembershipProof<S, COM>: Clone,
            S::Nullifier: Clone"),
    Copy(bound = r"
            S::Secret: Copy,
            S::Utxo: Copy,
            UtxoMembershipProof<S, COM>: Copy,
            S::Nullifier: Copy"),
    Debug(bound = r"
            S::Secret: Debug,
            S::Utxo: Debug,
            UtxoMembershipProof<S, COM>: Debug,
            S::Nullifier: Debug"),
    Default(bound = r"
            S::Secret: Default,
            S::Utxo: Default,
            UtxoMembershipProof<S, COM>: Default,
            S::Nullifier: Default"),
    Eq(bound = r"
        S::Secret: Eq,
        S::Utxo: Eq,
        UtxoMembershipProof<S, COM>: Eq,
        S::Nullifier: Eq"),
    Hash(bound = r"
            S::Secret: Hash,
            S::Utxo: Hash,
            UtxoMembershipProof<S, COM>: Hash,
            S::Nullifier: Hash"),
    PartialEq(bound = r"
            S::Secret: PartialEq,
            S::Utxo: PartialEq,
            UtxoMembershipProof<S, COM>: PartialEq,
            S::Nullifier: PartialEq")
)]
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
        authorization_context: &mut S::AuthorizationContext,
        compiler: &mut COM,
    ) -> S::Asset {
        let (asset, nullifier) = parameters.well_formed_asset(
            utxo_accumulator_model,
            authorization_context,
            &self.secret,
            &self.utxo,
            &self.utxo_membership_proof,
            compiler,
        );
        parameters.assert_equal_nullifiers(&self.nullifier, &nullifier, compiler);
        asset
    }
}

impl<S> Sender<S>
where
    S: Spend,
{
    /// Returns the underlying asset for `self`.
    #[inline]
    pub fn asset(&self) -> S::Asset
    where
        S::Secret: QueryAsset<Asset = S::Asset, Utxo = S::Utxo>,
    {
        self.secret.query_asset(&self.utxo)
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> SenderPost<S> {
        SenderPost::new(self.utxo_membership_proof.into_output(), self.nullifier)
    }
}

impl<S, P> Input<P> for Sender<S>
where
    S: Spend,
    P: HasInput<UtxoAccumulatorOutput<S>> + HasInput<S::Nullifier> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, self.utxo_membership_proof.output());
        P::extend(input, &self.nullifier);
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
    /// [`Nullifier`]: crate::transfer::utxo::NullifierType::Nullifier
    /// [`spend`]: Self::spend
    /// [`is_unspent`]: Self::is_unspent
    /// [`has_matching_utxo_accumulator_output`]: Self::has_matching_utxo_accumulator_output
    type ValidNullifier: AsRef<S::Nullifier>;

    /// Error Type
    ///
    /// This error describes situations in which ledger invariants have been broken but the system
    /// must be able to handle them gracefully instead of crashing.
    type Error: Into<SenderPostError<Self::Error>>;

    /// Checks if the ledger already contains the `nullifier` in its set of nullifiers.
    ///
    /// Existence of such a nullifier could indicate a possible double-spend and so the ledger does
    /// not accept duplicates.
    fn is_unspent(&self, nullifier: S::Nullifier) -> Result<Self::ValidNullifier, Self::Error>;

    /// Checks if `output` matches the current accumulated value of the UTXO accumulator that is
    /// stored on the ledger.
    ///
    /// Failure to match the ledger state means that the sender was constructed under an invalid or
    /// older state of the ledger.
    fn has_matching_utxo_accumulator_output(
        &self,
        output: UtxoAccumulatorOutput<S>,
    ) -> Result<Self::ValidUtxoAccumulatorOutput, Self::Error>;

    /// Posts the `nullifier` to the ledger, spending the asset.
    ///
    /// # Crypto Safety
    ///
    /// This method can only be called once we check that `nullifier` is not already stored on
    /// the ledger. See [`is_unspent`](Self::is_unspent) for more.
    ///
    /// # Implementation Note
    ///
    /// This method, by default, calls the [`spend_all`] method on an iterator of length one
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
    ) -> Result<(), Self::Error> {
        self.spend_all(super_key, iter::once((utxo_accumulator_output, nullifier)))
    }

    /// Posts all of the [`Nullifier`]s to the ledger, spending the assets.
    ///
    /// # Crypto Safety
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
    /// [`Nullifier`]: crate::transfer::utxo::NullifierType::Nullifier
    /// [`spend`]: Self::spend
    /// [`spend_all`]: Self::spend_all
    #[inline]
    fn spend_all<I>(
        &mut self,
        super_key: &Self::SuperPostingKey,
        iter: I,
    ) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = (Self::ValidUtxoAccumulatorOutput, Self::ValidNullifier)>,
    {
        for (utxo_accumulator_output, nullifier) in iter {
            self.spend(super_key, utxo_accumulator_output, nullifier)?;
        }
        Ok(())
    }
}

/// Sender Post Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Error: Deserialize<'de>",
            serialize = "Error: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Error: Clone"),
    Copy(bound = "Error: Copy"),
    Debug(bound = "Error: Debug"),
    Eq(bound = "Error: Eq"),
    Hash(bound = "Error: Hash"),
    PartialEq(bound = "Error: PartialEq")
)]
pub enum SenderPostError<Error> {
    /// Invalid UTXO Accumulator Output Error
    ///
    /// The sender was not constructed under the current state of the UTXO accumulator.
    InvalidUtxoAccumulatorOutput,

    /// Asset Spent Error
    ///
    /// The asset has already been spent.
    AssetSpent,

    /// Unexpected Error
    UnexpectedError(Error),
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
            deserialize = r"
                UtxoAccumulatorOutput<S>: Deserialize<'de>,
                S::Nullifier: Deserialize<'de>",
            serialize = r"
                UtxoAccumulatorOutput<S>: Serialize,
                S::Nullifier: Serialize",
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

    /// Validates `self` on the sender `ledger`.
    #[inline]
    pub fn validate<L>(
        self,
        ledger: &L,
    ) -> Result<SenderPostingKey<S, L>, SenderPostError<L::Error>>
    where
        L: SenderLedger<S>,
    {
        Ok(SenderPostingKey {
            utxo_accumulator_output: ledger
                .has_matching_utxo_accumulator_output(self.utxo_accumulator_output)
                .map_err(|x| x.into())?,
            nullifier: ledger.is_unspent(self.nullifier).map_err(|x| x.into())?,
        })
    }
}

impl<S> Encode for SenderPost<S>
where
    S: Spend,
    UtxoAccumulatorOutput<S>: Encode,
    S::Nullifier: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.utxo_accumulator_output.encode(&mut writer)?;
        self.nullifier.encode(&mut writer)?;
        Ok(())
    }
}

impl<S, P> Input<P> for SenderPost<S>
where
    S: Spend,
    P: HasInput<UtxoAccumulatorOutput<S>> + HasInput<S::Nullifier> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.utxo_accumulator_output);
        P::extend(input, &self.nullifier);
    }
}

/// Sender Posting Key
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                L::ValidUtxoAccumulatorOutput: Deserialize<'de>,
                L::ValidNullifier: Deserialize<'de>",
            serialize = r"
                L::ValidUtxoAccumulatorOutput: Serialize,
                L::ValidNullifier: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "L::ValidUtxoAccumulatorOutput: Clone, L::ValidNullifier: Clone"),
    Copy(bound = "L::ValidUtxoAccumulatorOutput: Copy, L::ValidNullifier: Copy"),
    Debug(bound = "L::ValidUtxoAccumulatorOutput: Debug, L::ValidNullifier: Debug"),
    Default(bound = "L::ValidUtxoAccumulatorOutput: Default, L::ValidNullifier: Default"),
    Eq(bound = "L::ValidUtxoAccumulatorOutput: Eq, L::ValidNullifier: Eq"),
    Hash(bound = "L::ValidUtxoAccumulatorOutput: Hash, L::ValidNullifier: Hash"),
    PartialEq(bound = "L::ValidUtxoAccumulatorOutput: PartialEq, L::ValidNullifier: PartialEq")
)]
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
    /// Posts `self` to the sender `ledger`.
    #[inline]
    pub fn post(self, ledger: &mut L, super_key: &L::SuperPostingKey) -> Result<(), L::Error> {
        ledger.spend(super_key, self.utxo_accumulator_output, self.nullifier)
    }

    /// Posts all of the [`SenderPostingKey`] in `iter` to the sender `ledger`.
    #[inline]
    pub fn post_all<I>(
        iter: I,
        ledger: &mut L,
        super_key: &L::SuperPostingKey,
    ) -> Result<(), L::Error>
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

impl<S, L, P> Input<P> for SenderPostingKey<S, L>
where
    S: Spend,
    L: SenderLedger<S> + ?Sized,
    P: HasInput<UtxoAccumulatorOutput<S>> + HasInput<S::Nullifier> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, self.utxo_accumulator_output.as_ref());
        P::extend(input, self.nullifier.as_ref());
    }
}
