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

//! Transfer Protocol
//!
//! This module defines a protocol for the zero-knowledge transfer of private assets. We define the
//! following structures:
//!
//! - Global Configuration: [`Configuration`]
//! - Sender Abstraction: [`Sender`], [`SenderPost`], [`SenderLedger`](
//! - Receiver Abstraction: [`Receiver`], [`ReceiverPost`], [`ReceiverLedger`]
//! - Transfer Abstraction: [`Transfer`], [`TransferPost`], [`TransferLedger`]
//! - Canonical Transactions: [`canonical`]
//! - Batched Transactions: [`batch`]
//!
//! See the [`crate::wallet`] module for more on how this transfer protocol is used in a wallet
//! protocol for the keeping of accounts for private assets.

use crate::{
    asset,
    transfer::{
        receiver::{ReceiverLedger, ReceiverPostError},
        sender::{SenderLedger, SenderPostError},
        utxo::{
            auth::{self, Generate},
            DefaultAddress, Mint, Spend,
        },
    },
};
use core::{fmt::Debug, hash::Hash, iter::Sum, ops::AddAssign};
use manta_crypto::{
    accumulator,
    constraint::{
        self, Add, Allocate, Allocator, Assert, AssertEq, Constant, Derived, ProofSystem,
        ProofSystemInput, Public, Secret, Variable,
    },
    rand::{CryptoRng, Rand, RngCore, Sample},
    signature::{self, Verify},
};
use manta_util::vec::{all_unequal, Vec};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod batch;
pub mod canonical;
pub mod receiver;
pub mod sender;
pub mod utxo;

#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test;

#[doc(inline)]
pub use canonical::Shape;

/// Returns `true` if the [`Transfer`] with this shape would have public participants.
#[inline]
pub const fn has_public_participants(sources: usize, sinks: usize) -> bool {
    (sources + sinks) > 0
}

/// Returns `true` if the [`Transfer`] with this shape would have secret participants.
#[inline]
pub const fn has_secret_participants(senders: usize, receivers: usize) -> bool {
    (senders + receivers) > 0
}

/// Returns `true` if the [`Transfer`] with this shape would require an authorization.
#[inline]
pub const fn requires_authorization(senders: usize) -> bool {
    senders > 0
}

/// Configuration
pub trait Configuration {
    /// Compiler Type
    type Compiler: Assert;

    /// Asset Id Type
    type AssetId: Clone;

    /// Asset Value Type
    type AssetValue: AddAssign + Clone + Default + PartialOrd + Sum;

    /// Unspent Transaction Output Type
    type Utxo: PartialEq;

    /// Nullifier Type
    type Nullifier: PartialEq;

    /// Spending Key
    type SpendingKey;

    /// Authorization Signature Randomness
    type AuthorizationSignatureRandomness: Sample;

    /// Mint Secret Type
    type MintSecret: utxo::MintSecret<Asset = Asset<Self>>
        + utxo::QueryIdentifier<Identifier = Identifier<Self>, Utxo = Self::Utxo>;

    /// Spend Secret Type
    type SpendSecret: utxo::SpendSecret<Asset = Asset<Self>>;

    /// Parameters Type
    type Parameters: auth::Generate
        + auth::Verify
        + auth::Randomize<Self::SpendingKey>
        + signature::Sign<
            SigningKey = Self::SpendingKey,
            Randomness = Self::AuthorizationSignatureRandomness,
            Message = TransferPostBody<Self>,
        > + signature::Verify<VerifyingKey = AuthorizationKey<Self>, Verification = bool>
        + utxo::AssetType<Asset = Asset<Self>>
        + utxo::UtxoType<Utxo = Self::Utxo>
        + utxo::DefaultAddress<Self::SpendingKey, Address = Address<Self>>
        + Mint<Secret = Self::MintSecret>
        + Spend<Secret = Self::SpendSecret, Nullifier = Self::Nullifier>;

    /// Authorization Key Type  Variable
    type AuthorizationKeyVar: Variable<Secret, Self::Compiler, Type = AuthorizationKey<Self>>
        + Variable<Public, Self::Compiler, Type = AuthorizationKey<Self>>
        + constraint::PartialEq<Self::AuthorizationKeyVar, Self::Compiler>;

    /// Authorization Randomness Type Variable
    type AuthorizationRandomnessVar: Variable<
        Secret,
        Self::Compiler,
        Type = AuthorizationRandomness<Self>,
    >;

    /// Asset Id Variable Type
    type AssetIdVar: Variable<Secret, Self::Compiler, Type = Self::AssetId>
        + Variable<Public, Self::Compiler, Type = Self::AssetId>
        + constraint::PartialEq<Self::AssetIdVar, Self::Compiler>;

    /// Asset Value Variable Type
    type AssetValueVar: Variable<Secret, Self::Compiler, Type = Self::AssetValue>
        + Variable<Public, Self::Compiler, Type = Self::AssetValue>
        + Add<Self::AssetValueVar, Self::Compiler, Output = Self::AssetValueVar>
        + constraint::PartialEq<Self::AssetValueVar, Self::Compiler>;

    /// Unspent Transaction Output Variable Type
    type UtxoVar: Variable<Secret, Self::Compiler, Type = Self::Utxo>
        + Variable<Public, Self::Compiler, Type = Self::Utxo>;

    /// Note Variable Type
    type NoteVar: Variable<Public, Self::Compiler, Type = utxo::Note<Self::Parameters>>;

    /// Nullifier Variable Type
    type NullifierVar: Variable<Public, Self::Compiler, Type = Self::Nullifier>;

    /// UTXO Accumulator Witness Variable Type
    type UtxoAccumulatorWitnessVar: Variable<
        Secret,
        Self::Compiler,
        Type = UtxoAccumulatorWitness<Self>,
    >;

    /// UTXO Accumulator Output Variable Type
    type UtxoAccumulatorOutputVar: Variable<
        Public,
        Self::Compiler,
        Type = UtxoAccumulatorOutput<Self>,
    >;

    /// UTXO Accumulator Model Variable Type
    type UtxoAccumulatorModelVar: Constant<Self::Compiler, Type = UtxoAccumulatorModel<Self>>
        + accumulator::Model<
            Self::Compiler,
            Witness = Self::UtxoAccumulatorWitnessVar,
            Output = Self::UtxoAccumulatorOutputVar,
        >;

    /// Mint Secret Variable Type
    type MintSecretVar: Variable<Secret, Self::Compiler, Type = <Self::Parameters as Mint>::Secret>;

    /// Spend Secret Variable Type
    type SpendSecretVar: Variable<
        Secret,
        Self::Compiler,
        Type = <Self::Parameters as Spend>::Secret,
    >;

    /// Parameters Variable Type
    type ParametersVar: Constant<Self::Compiler, Type = Self::Parameters>
        + auth::Randomize<
            Self::AuthorizationKeyVar,
            Self::Compiler,
            Randomness = Self::AuthorizationRandomnessVar,
        > + utxo::AssetType<Asset = AssetVar<Self>>
        + utxo::UtxoType<Utxo = Self::UtxoVar>
        + Mint<Self::Compiler, Secret = Self::MintSecretVar, Note = Self::NoteVar>
        + Spend<
            Self::Compiler,
            AuthorizationKey = Self::AuthorizationKeyVar,
            UtxoAccumulatorModel = Self::UtxoAccumulatorModelVar,
            Secret = Self::SpendSecretVar,
            Nullifier = Self::NullifierVar,
        >;

    /// Proof System Type
    type ProofSystem: ProofSystem<Compiler = Self::Compiler>
        + ProofSystemInput<AuthorizationKey<Self>>
        + ProofSystemInput<Self::AssetId>
        + ProofSystemInput<Self::AssetValue>
        + ProofSystemInput<UtxoAccumulatorOutput<Self>>
        + ProofSystemInput<Utxo<Self>>
        + ProofSystemInput<Note<Self>>
        + ProofSystemInput<Nullifier<Self>>;
}

/// Compiler Type
pub type Compiler<C> = <C as Configuration>::Compiler;

/// Proof System Type
type ProofSystemType<C> = <C as Configuration>::ProofSystem;

/// Proof System Error Type
pub type ProofSystemError<C> = <ProofSystemType<C> as ProofSystem>::Error;

/// Proof System Public Parameters Type
pub type ProofSystemPublicParameters<C> = <ProofSystemType<C> as ProofSystem>::PublicParameters;

/// Proving Context Type
pub type ProvingContext<C> = <ProofSystemType<C> as ProofSystem>::ProvingContext;

/// Verifying Context Type
pub type VerifyingContext<C> = <ProofSystemType<C> as ProofSystem>::VerifyingContext;

/// Proof System Input Type
pub type ProofInput<C> = <ProofSystemType<C> as ProofSystem>::Input;

/// Validity Proof Type
pub type Proof<C> = <ProofSystemType<C> as ProofSystem>::Proof;

/// Parameters Type
pub type Parameters<C> = <C as Configuration>::Parameters;

/// Parameters Variable Type
pub type ParametersVar<C> = <C as Configuration>::ParametersVar;

/// Full Parameters Type
pub type FullParameters<'p, C> = utxo::FullParameters<'p, Parameters<C>>;

/// Full Parameters Variable Type
pub type FullParametersVar<'p, C> = utxo::FullParameters<'p, ParametersVar<C>, Compiler<C>>;

/// Full Parameters Reference Type
pub type FullParametersRef<'p, C> = utxo::FullParametersRef<'p, Parameters<C>>;

/// Full Parameters Reference Variable Type
pub type FullParametersRefVar<'p, C> = utxo::FullParametersRef<'p, ParametersVar<C>, Compiler<C>>;

/// UTXO Accumulator Model Type
pub type UtxoAccumulatorModel<C> = utxo::UtxoAccumulatorModel<Parameters<C>>;

/// UTXO Accumulator Model Variable Type
pub type UtxoAccumulatorModelVar<C> = utxo::UtxoAccumulatorModel<ParametersVar<C>, Compiler<C>>;

/// UTXO Accumulator Item Type
pub type UtxoAccumulatorItem<C> = utxo::UtxoAccumulatorItem<Parameters<C>>;

/// UTXO Accumulator Witness Type
pub type UtxoAccumulatorWitness<C> = utxo::UtxoAccumulatorWitness<Parameters<C>>;

/// UTXO Accumulator Output Type
pub type UtxoAccumulatorOutput<C> = utxo::UtxoAccumulatorOutput<Parameters<C>>;

/// Address Type
pub type Address<C> = utxo::Address<<C as Configuration>::MintSecret>;

/// Asset Type
pub type Asset<C> = asset::Asset<<C as Configuration>::AssetId, <C as Configuration>::AssetValue>;

/// Asset Variable Type
pub type AssetVar<C> =
    asset::Asset<<C as Configuration>::AssetIdVar, <C as Configuration>::AssetValueVar>;

/// Authorization Key Type
pub type AuthorizationKey<C> = auth::AuthorizationKey<Parameters<C>>;

/// Authorization Key Type Variable
pub type AuthorizationKeyVar<C> = auth::AuthorizationKey<ParametersVar<C>>;

/// Authorization Randomness Type
pub type AuthorizationRandomness<C> = auth::Randomness<Parameters<C>>;

/// Authorization Randomness Type Variable
pub type AuthorizationRandomnessVar<C> = auth::Randomness<ParametersVar<C>>;

/// Authorization Type
pub type Authorization<C> = auth::Authorization<Parameters<C>>;

/// Authorization Variable Type
pub type AuthorizationVar<C> = auth::Authorization<ParametersVar<C>>;

/// Authorization Proof Type
pub type AuthorizationProof<C> = auth::AuthorizationProof<Parameters<C>>;

/// Authorization Proof Variable Type
pub type AuthorizationProofVar<C> = auth::AuthorizationProof<ParametersVar<C>>;

/// Authorization Signature Type
pub type AuthorizationSignature<C> = signature::Signature<Parameters<C>>;

/// Unspent Transaction Output Type
pub type Utxo<C> = utxo::Utxo<Parameters<C>>;

/// Incoming Note Type
pub type Note<C> = utxo::Note<Parameters<C>>;

/// Nullifier Type
pub type Nullifier<C> = utxo::Nullifier<Parameters<C>>;

/// Identifier Type
pub type Identifier<C> = utxo::Identifier<<C as Configuration>::SpendSecret>;

/// Pre-Sender Type
pub type PreSender<C> = sender::PreSender<Parameters<C>>;

/// Sender Type
pub type Sender<C> = sender::Sender<Parameters<C>>;

/// Sender Variable Type
pub type SenderVar<C> = sender::Sender<ParametersVar<C>, Compiler<C>>;

/// Sender Post Type
pub type SenderPost<C> = sender::SenderPost<Parameters<C>>;

/// Receiver Type
pub type Receiver<C> = receiver::Receiver<Parameters<C>>;

/// Receiver Variable Type
pub type ReceiverVar<C> = receiver::Receiver<ParametersVar<C>, Compiler<C>>;

/// Receiver Post Type
pub type ReceiverPost<C> = receiver::ReceiverPost<Parameters<C>>;

/// Generates an internal pair for `asset` against `spending_key`.
#[inline]
pub fn internal_pair<C, R>(
    parameters: &Parameters<C>,
    spending_key: &C::SpendingKey,
    asset: Asset<C>,
    rng: &mut R,
) -> (Receiver<C>, PreSender<C>)
where
    C: Configuration,
    R: CryptoRng + RngCore + ?Sized,
{
    let receiver = Receiver::<C>::sample(
        parameters,
        parameters.default_address(spending_key),
        asset.clone(),
        rng,
    );
    let mut authorization = parameters.generate(spending_key, rng);
    let pre_sender = PreSender::<C>::sample(
        parameters,
        &mut authorization.authorization_key,
        receiver.identifier(),
        asset,
        rng,
    );
    (receiver, pre_sender)
}

/// Generates an internal pair for a zero-asset with the given `asset_id` against `spending_key`.
#[inline]
pub fn internal_zero_pair<C, R>(
    parameters: &Parameters<C>,
    spending_key: &C::SpendingKey,
    asset_id: C::AssetId,
    rng: &mut R,
) -> (Receiver<C>, PreSender<C>)
where
    C: Configuration,
    R: CryptoRng + RngCore + ?Sized,
{
    internal_pair::<C, R>(parameters, spending_key, Asset::<C>::zero(asset_id), rng)
}

/// Transfer
pub struct Transfer<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    C: Configuration,
{
    /// Authorization Proof
    authorization_proof: Option<AuthorizationProof<C>>,

    /// Asset Id
    asset_id: Option<C::AssetId>,

    /// Sources
    sources: [C::AssetValue; SOURCES],

    /// Senders
    senders: [Sender<C>; SENDERS],

    /// Receivers
    receivers: [Receiver<C>; RECEIVERS],

    /// Sinks
    sinks: [C::AssetValue; SINKS],
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Builds a new [`Transfer`] from its component parts.
    #[inline]
    pub fn new(
        authorization_proof: impl Into<Option<AuthorizationProof<C>>>,
        asset_id: impl Into<Option<C::AssetId>>,
        sources: [C::AssetValue; SOURCES],
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
        sinks: [C::AssetValue; SINKS],
    ) -> Self {
        let authorization_proof = authorization_proof.into();
        let asset_id = asset_id.into();
        Self::check_shape(authorization_proof.is_some(), asset_id.is_some());
        Self::new_unchecked(
            authorization_proof,
            asset_id,
            sources,
            senders,
            receivers,
            sinks,
        )
    }

    /// Checks that the [`Transfer`] has a valid shape.
    #[inline]
    pub fn check_shape(has_authorization_proof: bool, has_visible_asset_id: bool) {
        Self::has_nonempty_input_shape();
        Self::has_nonempty_output_shape();
        Self::has_authorization_proof_when_required(has_authorization_proof);
        Self::has_visible_asset_id_when_required(has_visible_asset_id);
    }

    /// Checks that the input side of the transfer is not empty.
    #[inline]
    pub fn has_nonempty_input_shape() {
        assert_ne!(
            SOURCES + SENDERS,
            0,
            "Not enough participants on the input side."
        );
    }

    /// Checks that the output side of the transfer is not empty.
    #[inline]
    pub fn has_nonempty_output_shape() {
        assert_ne!(
            RECEIVERS + SINKS,
            0,
            "Not enough participants on the output side."
        );
    }

    /// Checks that the given `authorization_proof` for [`Transfer`] building is present exactly
    /// when required.
    #[inline]
    pub fn has_authorization_proof_when_required(has_authorization_proof: bool) {
        if requires_authorization(SENDERS) {
            assert!(
                has_authorization_proof,
                "Missing authorization proof when required."
            );
        } else {
            assert!(
                !has_authorization_proof,
                "Given authorization proof when not required."
            );
        }
    }

    /// Checks that the given `asset_id` for [`Transfer`] building is visible exactly when required.
    #[inline]
    pub fn has_visible_asset_id_when_required(has_visible_asset_id: bool) {
        if has_public_participants(SOURCES, SINKS) {
            assert!(
                has_visible_asset_id,
                "Missing public asset id when required."
            );
        } else {
            assert!(
                !has_visible_asset_id,
                "Given public asset id when not required."
            );
        }
    }

    /// Builds a new [`Transfer`] without checking the number of participants on the input and
    /// output sides.
    #[inline]
    fn new_unchecked(
        authorization_proof: Option<AuthorizationProof<C>>,
        asset_id: Option<C::AssetId>,
        sources: [C::AssetValue; SOURCES],
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
        sinks: [C::AssetValue; SINKS],
    ) -> Self {
        Self {
            authorization_proof,
            asset_id,
            sources,
            senders,
            receivers,
            sinks,
        }
    }

    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        let mut input = Default::default();
        if let Some(authorization_proof) = &self.authorization_proof {
            authorization_proof.extend_input::<C::ProofSystem>(&mut input);
        }
        if let Some(asset_id) = &self.asset_id {
            C::ProofSystem::extend(&mut input, asset_id);
        }
        self.sources
            .iter()
            .for_each(|source| C::ProofSystem::extend(&mut input, source));
        self.senders
            .iter()
            .for_each(|sender| sender.extend_input::<C::ProofSystem>(&mut input));
        self.receivers
            .iter()
            .for_each(|receiver| receiver.extend_input::<C::ProofSystem>(&mut input));
        self.sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(&mut input, sink));
        input
    }

    /// Builds a constraint system which asserts constraints against unknown variables.
    #[inline]
    pub fn unknown_constraints(parameters: FullParametersRef<C>) -> C::Compiler {
        let mut compiler = C::ProofSystem::context_compiler();
        TransferVar::<C, SOURCES, SENDERS, RECEIVERS, SINKS>::new_unknown(&mut compiler)
            .build_validity_constraints(&parameters.as_constant(&mut compiler), &mut compiler);
        compiler
    }

    /// Builds a constraint system which asserts constraints against known variables.
    #[inline]
    pub fn known_constraints(&self, parameters: FullParametersRef<C>) -> C::Compiler {
        let mut compiler = C::ProofSystem::proof_compiler();
        let transfer: TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS> =
            self.as_known(&mut compiler);
        transfer.build_validity_constraints(&parameters.as_constant(&mut compiler), &mut compiler);
        compiler
    }

    /// Generates a proving and verifying context for this transfer shape.
    #[inline]
    pub fn generate_context<R>(
        public_parameters: &ProofSystemPublicParameters<C>,
        parameters: FullParametersRef<C>,
        rng: &mut R,
    ) -> Result<(ProvingContext<C>, VerifyingContext<C>), ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        C::ProofSystem::compile(
            public_parameters,
            Self::unknown_constraints(parameters),
            rng,
        )
    }

    /// Converts `self` into its [`TransferPostBody`] by building the [`Transfer`] validity proof.
    #[inline]
    pub fn into_post_body<R>(
        self,
        parameters: FullParametersRef<C>,
        proving_context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPostBody<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Ok(TransferPostBody::build(
            C::ProofSystem::prove(proving_context, self.known_constraints(parameters), rng)?,
            self.authorization_proof
                .map(AuthorizationProof::<C>::into_post),
            self.asset_id,
            self.sources,
            self.senders,
            self.receivers,
            self.sinks,
        ))
    }

    ///
    #[inline]
    pub fn into_post<R>(
        mut self,
        parameters: FullParametersRef<C>,
        proving_context: &ProvingContext<C>,
        spending_key: Option<&C::SpendingKey>,
        rng: &mut R,
    ) -> Result<Option<TransferPost<C>>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        match (
            requires_authorization(SENDERS),
            self.authorization_proof.take(),
            spending_key,
        ) {
            (true, Some(authorization_proof), Some(spending_key)) => match auth::sign(
                parameters.base,
                spending_key,
                authorization_proof,
                &rng.gen(),
                |randomized_authorization_key| match C::ProofSystem::prove(
                    proving_context,
                    self.known_constraints(parameters),
                    rng,
                ) {
                    Ok(proof) => Ok(TransferPostBody::build(
                        proof,
                        Some(randomized_authorization_key),
                        self.asset_id,
                        self.sources,
                        self.senders,
                        self.receivers,
                        self.sinks,
                    )),
                    Err(err) => Err(err),
                },
            ) {
                Some(Ok((signature, body))) => {
                    Ok(Some(TransferPost::new_unchecked(Some(signature), body)))
                }
                Some(Err(err)) => Err(err),
                _ => Ok(None),
            },
            (false, None, None) => Ok(Some(TransferPost::new_unchecked(
                None,
                self.into_post_body(parameters, proving_context, rng)?,
            ))),
            _ => todo!(),
        }
    }
}

/// Transfer Variable
struct TransferVar<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    C: Configuration,
{
    /// Authorization Proof
    authorization_proof: Option<AuthorizationProofVar<C>>,

    /// Asset Id
    asset_id: Option<C::AssetIdVar>,

    /// Sources
    sources: Vec<C::AssetValueVar>,

    /// Senders
    senders: Vec<SenderVar<C>>,

    /// Receivers
    receivers: Vec<ReceiverVar<C>>,

    /// Sinks
    sinks: Vec<C::AssetValueVar>,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Builds constraints for the [`Transfer`] validity proof.
    #[inline]
    fn build_validity_constraints(
        self,
        parameters: &FullParametersVar<C>,
        compiler: &mut C::Compiler,
    ) {
        let mut secret_asset_ids = Vec::with_capacity(SENDERS + RECEIVERS);
        let input_sum = Self::input_sum(
            parameters,
            &mut secret_asset_ids,
            self.authorization_proof,
            self.senders,
            self.sources,
            compiler,
        );
        let output_sum = Self::output_sum(
            parameters,
            &mut secret_asset_ids,
            self.receivers,
            self.sinks,
            compiler,
        );
        compiler.assert_eq(&input_sum, &output_sum);
        match self.asset_id {
            Some(asset_id) => compiler.assert_all_eq_to_base(&asset_id, secret_asset_ids.iter()),
            _ => compiler.assert_all_eq(secret_asset_ids.iter()),
        }
    }

    /// Computes the sum over all the input assets, asserting that they are all well-formed.
    #[inline]
    fn input_sum(
        parameters: &FullParametersVar<C>,
        secret_asset_ids: &mut Vec<C::AssetIdVar>,
        authorization_proof: Option<AuthorizationProofVar<C>>,
        senders: Vec<SenderVar<C>>,
        sources: Vec<C::AssetValueVar>,
        compiler: &mut C::Compiler,
    ) -> C::AssetValueVar {
        if let Some(mut authorization_proof) = authorization_proof {
            authorization_proof.assert_valid(&parameters.base, compiler);
            Self::value_sum(
                senders
                    .into_iter()
                    .map(|s| {
                        let asset = s.well_formed_asset(
                            &parameters.base,
                            &parameters.utxo_accumulator_model,
                            &mut authorization_proof.authorization.authorization_key,
                            compiler,
                        );
                        secret_asset_ids.push(asset.id);
                        asset.value
                    })
                    .chain(sources)
                    .collect::<Vec<_>>(),
                compiler,
            )
        } else {
            Self::value_sum(sources, compiler)
        }
    }

    /// Computes the sum over all the output assets, asserting that they are all well-formed.
    #[inline]
    fn output_sum(
        parameters: &FullParametersVar<C>,
        secret_asset_ids: &mut Vec<C::AssetIdVar>,
        receivers: Vec<ReceiverVar<C>>,
        sinks: Vec<C::AssetValueVar>,
        compiler: &mut C::Compiler,
    ) -> C::AssetValueVar {
        Self::value_sum(
            receivers
                .into_iter()
                .map(|r| {
                    let asset = r.well_formed_asset(&parameters.base, compiler);
                    secret_asset_ids.push(asset.id);
                    asset.value
                })
                .chain(sinks)
                .collect::<Vec<_>>(),
            compiler,
        )
    }

    /// Computes the sum of the asset values over `iter`.
    #[inline]
    fn value_sum<I>(iter: I, compiler: &mut C::Compiler) -> C::AssetValueVar
    where
        I: IntoIterator<Item = C::AssetValueVar>,
    {
        // TODO: Add a `Sum` trait for `compiler` and just do a sum here.
        iter.into_iter()
            .reduce(move |l, r| Add::add(l, r, compiler))
            .unwrap()
    }
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Variable<Derived, C::Compiler> for TransferVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    type Type = Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>;

    #[inline]
    fn new_unknown(compiler: &mut C::Compiler) -> Self {
        Self {
            authorization_proof: requires_authorization(SENDERS)
                .then(|| compiler.allocate_unknown()),
            asset_id: has_public_participants(SOURCES, SINKS)
                .then(|| compiler.allocate_unknown::<Public, _>()),
            sources: (0..SOURCES)
                .into_iter()
                .map(|_| compiler.allocate_unknown::<Public, _>())
                .collect(),
            senders: (0..SENDERS)
                .into_iter()
                .map(|_| compiler.allocate_unknown())
                .collect(),
            receivers: (0..RECEIVERS)
                .into_iter()
                .map(|_| compiler.allocate_unknown())
                .collect(),
            sinks: (0..SINKS)
                .into_iter()
                .map(|_| compiler.allocate_unknown::<Public, _>())
                .collect(),
        }
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
        Self {
            authorization_proof: this
                .authorization_proof
                .as_ref()
                .map(|proof| proof.as_known(compiler)),
            asset_id: this
                .asset_id
                .as_ref()
                .map(|id| id.as_known::<Public, _>(compiler)),
            sources: this
                .sources
                .iter()
                .map(|source| source.as_known::<Public, _>(compiler))
                .collect(),
            senders: this
                .senders
                .iter()
                .map(|sender| sender.as_known(compiler))
                .collect(),
            receivers: this
                .receivers
                .iter()
                .map(|receiver| receiver.as_known(compiler))
                .collect(),
            sinks: this
                .sinks
                .iter()
                .map(|sink| sink.as_known::<Public, _>(compiler))
                .collect(),
        }
    }
}

/// Transfer Ledger
///
/// This is the validation trait for ensuring that a particular instance of [`Transfer`] is valid
/// according to the ledger state. These methods are the minimum required for a ledger which accepts
/// the [`Transfer`] abstraction. This `trait` inherits from [`SenderLedger`] and [`ReceiverLedger`]
/// which validate the [`Sender`] and [`Receiver`] parts of any [`Transfer`]. See their
/// documentation for more.
pub trait TransferLedger<C>:
    SenderLedger<
        Parameters<C>,
        SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>),
    > + ReceiverLedger<
        Parameters<C>,
        SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>),
    >
where
    C: Configuration + ?Sized,
{
    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`TransferLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Account Identifier
    type AccountId;

    /// Ledger Event
    type Event;

    /// State Update Error
    ///
    /// This error type is used if the ledger can fail when updating the public state. The
    /// [`update_public_balances`](Self::update_public_balances) method uses this error type to
    /// track this condition.
    type UpdateError;

    /// Valid [`AssetValue`](Configuration::AssetValue) for [`TransferPost`] Source
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation of
    /// [`TransferLedger`].
    type ValidSourceAccount: AsRef<C::AssetValue>;

    /// Valid [`AssetValue`](Configuration::AssetValue) for [`TransferPost`] Sink
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation of
    /// [`TransferLedger`].
    type ValidSinkAccount: AsRef<C::AssetValue>;

    /// Valid [`Proof`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation
    /// of [`TransferLedger`]. This is to prevent that [`SenderPostingKey::post`] and
    /// [`ReceiverPostingKey::post`] are called before [`SenderPost::validate`],
    /// [`ReceiverPost::validate`], [`check_source_accounts`](Self::check_source_accounts),
    /// [`check_sink_accounts`](Self::check_sink_accounts) and [`is_valid`](Self::is_valid).
    type ValidProof: Copy;

    /// Checks that the balances associated to the source accounts are sufficient to withdraw the
    /// amount given in `sources`.
    fn check_source_accounts<I>(
        &self,
        asset_id: &C::AssetId,
        sources: I,
    ) -> Result<Vec<Self::ValidSourceAccount>, InvalidSourceAccount<C, Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, C::AssetValue)>;

    /// Checks that the sink accounts exist and balance can be increased by the specified amounts.
    fn check_sink_accounts<I>(
        &self,
        asset_id: &C::AssetId,
        sinks: I,
    ) -> Result<Vec<Self::ValidSinkAccount>, InvalidSinkAccount<C, Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, C::AssetValue)>;

    /// Checks that the transfer `proof` is valid.
    fn is_valid(
        &self,
        posting_key: TransferPostingKeyRef<C, Self>,
    ) -> Option<(Self::ValidProof, Self::Event)>;

    /// Updates the public balances in the ledger, finishing the transaction.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `proof` is a valid proof and that
    /// `senders` and `receivers` are valid participants in the transaction. See
    /// [`is_valid`](Self::is_valid) for more.
    fn update_public_balances(
        &mut self,
        super_key: &TransferLedgerSuperPostingKey<C, Self>,
        asset_id: C::AssetId,
        sources: Vec<SourcePostingKey<C, Self>>,
        sinks: Vec<SinkPostingKey<C, Self>>,
        proof: Self::ValidProof,
    ) -> Result<(), Self::UpdateError>;
}

/// Transfer Source Posting Key Type
pub type SourcePostingKey<C, L> = <L as TransferLedger<C>>::ValidSourceAccount;

/// Transfer Sink Posting Key Type
pub type SinkPostingKey<C, L> = <L as TransferLedger<C>>::ValidSinkAccount;

/// Transfer Sender Posting Key Type
pub type SenderPostingKey<C, L> = sender::SenderPostingKey<Parameters<C>, L>;

/// Transfer Receiver Posting Key Type
pub type ReceiverPostingKey<C, L> = receiver::ReceiverPostingKey<Parameters<C>, L>;

/// Transfer Ledger Super Posting Key Type
pub type TransferLedgerSuperPostingKey<C, L> = <L as TransferLedger<C>>::SuperPostingKey;

/// Invalid Authorization Signature Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidAuthorizationSignature {
    /// Invalid Authorization Signature Shape
    InvalidShape,

    /// Missing Signature
    MissingSignature,

    /// Missing Authorization
    MissingAuthorization,

    /// Bad Signature
    BadSignature,
}

/// Invalid Source Accounts
///
/// This `struct` is the error state of the [`TransferLedger::check_source_accounts`] method. See
/// its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "AccountId: Clone, C::AssetId: Clone, C::AssetValue: Clone"),
    Copy(bound = "AccountId: Copy, C::AssetId: Copy, C::AssetValue: Copy"),
    Debug(bound = "AccountId: Debug, C::AssetId: Debug, C::AssetValue: Debug"),
    Eq(bound = "AccountId: Eq, C::AssetId: Eq, C::AssetValue: Eq"),
    Hash(bound = "AccountId: Hash, C::AssetId: Hash, C::AssetValue: Hash"),
    PartialEq(bound = "AccountId: PartialEq, C::AssetId: PartialEq, C::AssetValue: PartialEq")
)]
pub struct InvalidSourceAccount<C, AccountId>
where
    C: Configuration + ?Sized,
{
    /// Account Id
    pub account_id: AccountId,

    /// Asset Id
    pub asset_id: C::AssetId,

    /// Amount Attempting to Withdraw
    pub withdraw: C::AssetValue,
}

/// Invalid Sink Accounts
///
/// This `struct` is the error state of the [`TransferLedger::check_sink_accounts`] method. See its
/// documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "AccountId: Clone, C::AssetId: Clone, C::AssetValue: Clone"),
    Copy(bound = "AccountId: Copy, C::AssetId: Copy, C::AssetValue: Copy"),
    Debug(bound = "AccountId: Debug, C::AssetId: Debug, C::AssetValue: Debug"),
    Eq(bound = "AccountId: Eq, C::AssetId: Eq, C::AssetValue: Eq"),
    Hash(bound = "AccountId: Hash, C::AssetId: Hash, C::AssetValue: Hash"),
    PartialEq(bound = "AccountId: PartialEq, C::AssetId: PartialEq, C::AssetValue: PartialEq")
)]
pub struct InvalidSinkAccount<C, AccountId>
where
    C: Configuration + ?Sized,
{
    /// Account Id
    pub account_id: AccountId,

    /// Asset Id
    pub asset_id: C::AssetId,

    /// Amount Attempting to Deposit
    pub deposit: C::AssetValue,
}

/// Transfer Post Error
///
/// This `enum` is the error state of the [`TransferPost::validate`] method. See its documentation
/// for more.
/* TODO:
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "AccountId: Clone, UpdateError: Clone, C::AssetId: Clone, C::AssetValue: Clone"),
    Copy(bound = "AccountId: Copy, UpdateError: Copy, C::AssetId: Copy, C::AssetValue: Copy"),
    Debug(bound = "AccountId: Debug, UpdateError: Debug, C::AssetId: Debug, C::AssetValue: Debug"),
    Eq(bound = "AccountId: Eq, UpdateError: Eq, C::AssetId: Eq, C::AssetValue: Eq"),
    Hash(bound = "AccountId: Hash, UpdateError: Hash, C::AssetId: Hash, C::AssetValue: Hash"),
    PartialEq(
        bound = "AccountId: PartialEq, UpdateError: PartialEq, C::AssetId: PartialEq, C::AssetValue: PartialEq"
    )
)]
*/
pub enum TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    /// Invalid Transfer Post Shape
    InvalidShape,

    /// Invalid Authorization Signature
    ///
    /// The authorization signature for the [`TransferPost`] was not valid.
    InvalidAuthorizationSignature(InvalidAuthorizationSignature),

    /// Invalid Source Accounts
    InvalidSourceAccount(InvalidSourceAccount<C, AccountId>),

    /// Invalid Sink Accounts
    InvalidSinkAccount(InvalidSinkAccount<C, AccountId>),

    /// Sender Post Error
    Sender(SenderPostError),

    /// Receiver Post Error
    Receiver(ReceiverPostError),

    /// Duplicate Spend Error
    DuplicateSpend,

    /// Duplicate Mint Error
    DuplicateMint,

    /// Invalid Transfer Proof Error
    ///
    /// Validity of the transfer could not be proved by the ledger.
    InvalidProof,

    /// Update Error
    ///
    /// An error occured while updating the ledger state.
    UpdateError(UpdateError),
}

impl<C, AccountId, UpdateError> From<InvalidAuthorizationSignature>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: InvalidAuthorizationSignature) -> Self {
        Self::InvalidAuthorizationSignature(err)
    }
}

impl<C, AccountId, UpdateError> From<InvalidSourceAccount<C, AccountId>>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: InvalidSourceAccount<C, AccountId>) -> Self {
        Self::InvalidSourceAccount(err)
    }
}

impl<C, AccountId, UpdateError> From<InvalidSinkAccount<C, AccountId>>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: InvalidSinkAccount<C, AccountId>) -> Self {
        Self::InvalidSinkAccount(err)
    }
}

impl<C, AccountId, UpdateError> From<sender::SenderPostError>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: sender::SenderPostError) -> Self {
        Self::Sender(err)
    }
}

impl<C, AccountId, UpdateError> From<receiver::ReceiverPostError>
    for TransferPostError<C, AccountId, UpdateError>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(err: receiver::ReceiverPostError) -> Self {
        Self::Receiver(err)
    }
}

/// Transfer Post Body
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                AuthorizationKey<C>: Deserialize<'de>,
                C::AssetId: Deserialize<'de>,
                C::AssetValue: Deserialize<'de>,
                SenderPost<C>: Deserialize<'de>,
                ReceiverPost<C>: Deserialize<'de>,
                Proof<C>: Deserialize<'de>,
            ",
            serialize = r"
                AuthorizationKey<C>: Serialize,
                C::AssetId: Serialize,
                C::AssetValue: Serialize,
                SenderPost<C>: Serialize,
                ReceiverPost<C>: Serialize,
                Proof<C>: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = r"
        AuthorizationKey<C>: Clone,
        C::AssetId: Clone,
        C::AssetValue: Clone,
        SenderPost<C>: Clone,
        ReceiverPost<C>: Clone,
        Proof<C>: Clone
    "),
    Debug(bound = r"
        AuthorizationKey<C>: Debug,
        C::AssetId: Debug,
        C::AssetValue: Debug,
        SenderPost<C>: Debug,
        ReceiverPost<C>: Debug,
        Proof<C>: Debug
    "),
    Eq(bound = r"
        AuthorizationKey<C>: Eq,
        C::AssetId: Eq,
        C::AssetValue: Eq,
        SenderPost<C>: Eq,
        ReceiverPost<C>: Eq,
        Proof<C>: Eq
    "),
    Hash(bound = r"
        AuthorizationKey<C>: Hash,
        C::AssetId: Hash,
        C::AssetValue: Hash,
        SenderPost<C>: Hash,
        ReceiverPost<C>: Hash,
        Proof<C>: Hash
    "),
    PartialEq(bound = r"
        AuthorizationKey<C>: PartialEq,
        C::AssetId: PartialEq,
        C::AssetValue: PartialEq,
        SenderPost<C>: PartialEq,
        ReceiverPost<C>: PartialEq,
        Proof<C>: PartialEq
    ")
)]
pub struct TransferPostBody<C>
where
    C: Configuration + ?Sized,
{
    /// Randomized Authorization Key
    pub randomized_authorization_key: Option<AuthorizationKey<C>>,

    /// Asset Id
    pub asset_id: Option<C::AssetId>,

    /// Sources
    pub sources: Vec<C::AssetValue>,

    /// Sender Posts
    pub sender_posts: Vec<SenderPost<C>>,

    /// Receiver Posts
    pub receiver_posts: Vec<ReceiverPost<C>>,

    /// Sinks
    pub sinks: Vec<C::AssetValue>,

    /// Validity Proof
    pub validity_proof: Proof<C>,
}

impl<C> TransferPostBody<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`TransferPostBody`].
    #[inline]
    fn build<
        const SOURCES: usize,
        const SENDERS: usize,
        const RECEIVERS: usize,
        const SINKS: usize,
    >(
        validity_proof: Proof<C>,
        randomized_authorization_key: Option<AuthorizationKey<C>>,
        asset_id: Option<C::AssetId>,
        sources: [C::AssetValue; SOURCES],
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
        sinks: [C::AssetValue; SINKS],
    ) -> Self {
        Self {
            randomized_authorization_key,
            asset_id,
            sources: sources.into(),
            sender_posts: senders.into_iter().map(Sender::<C>::into_post).collect(),
            receiver_posts: receivers
                .into_iter()
                .map(Receiver::<C>::into_post)
                .collect(),
            sinks: sinks.into(),
            validity_proof,
        }
    }

    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        let mut input = Default::default();
        if let Some(randomized_authorization_key) = &self.randomized_authorization_key {
            C::ProofSystem::extend(&mut input, randomized_authorization_key);
        }
        if let Some(asset_id) = &self.asset_id {
            C::ProofSystem::extend(&mut input, asset_id);
        }
        self.sources
            .iter()
            .for_each(|source| C::ProofSystem::extend(&mut input, source));
        self.sender_posts
            .iter()
            .for_each(|post| post.extend_input::<C::ProofSystem>(&mut input));
        self.receiver_posts
            .iter()
            .for_each(|post| post.extend_input::<C::ProofSystem>(&mut input));
        self.sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(&mut input, sink));
        input
    }

    /// Verifies the validity proof of `self` according to the `verifying_context`.
    #[inline]
    pub fn has_valid_proof(
        &self,
        verifying_context: &VerifyingContext<C>,
    ) -> Result<bool, ProofSystemError<C>> {
        C::ProofSystem::verify(
            verifying_context,
            &self.generate_proof_input(),
            &self.validity_proof,
        )
    }

    /// Asserts that `self` has a valid proof. See [`has_valid_proof`](Self::has_valid_proof) for
    /// more.
    #[inline]
    pub fn assert_valid_proof(&self, verifying_context: &VerifyingContext<C>)
    where
        Self: Debug,
        ProofSystemError<C>: Debug,
    {
        assert!(
            self.has_valid_proof(verifying_context)
                .expect("Unable to verify proof."),
            "Invalid TransferPostBody: {:?}.",
            self,
        );
    }
}

/// Transfer Post
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                AuthorizationSignature<C>: Deserialize<'de>,
                TransferPostBody<C>: Deserialize<'de>,
            ",
            serialize = r"
                AuthorizationSignature<C>: Serialize,
                TransferPostBody<C>: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "AuthorizationSignature<C>: Clone, TransferPostBody<C>: Clone"),
    Debug(bound = "AuthorizationSignature<C>: Debug, TransferPostBody<C>: Debug"),
    Eq(bound = "AuthorizationSignature<C>: Eq, TransferPostBody<C>: Eq"),
    Hash(bound = "AuthorizationSignature<C>: Hash, TransferPostBody<C>: Hash"),
    PartialEq(bound = "AuthorizationSignature<C>: PartialEq, TransferPostBody<C>: PartialEq")
)]
pub struct TransferPost<C>
where
    C: Configuration + ?Sized,
{
    /// Authorization Signature
    pub authorization_signature: Option<AuthorizationSignature<C>>,

    /// Transfer Post Body
    pub body: TransferPostBody<C>,
}

impl<C> TransferPost<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`TransferPost`] without checking the consistency conditions between the `body`
    /// and the `authorization_signature`.
    #[inline]
    fn new_unchecked(
        authorization_signature: Option<AuthorizationSignature<C>>,
        body: TransferPostBody<C>,
    ) -> Self {
        Self {
            authorization_signature,
            body,
        }
    }

    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        self.body.generate_proof_input()
    }

    /// Verifies the validity proof of `self` according to the `verifying_context`.
    #[inline]
    pub fn has_valid_proof(
        &self,
        verifying_context: &VerifyingContext<C>,
    ) -> Result<bool, ProofSystemError<C>> {
        self.body.has_valid_proof(verifying_context)
    }

    /// Asserts that `self` has a valid proof. See [`has_valid_proof`](Self::has_valid_proof) for
    /// more.
    #[inline]
    pub fn assert_valid_proof(&self, verifying_context: &VerifyingContext<C>)
    where
        Self: Debug,
        ProofSystemError<C>: Debug,
    {
        assert!(
            self.has_valid_proof(verifying_context)
                .expect("Unable to verify proof."),
            "Invalid TransferPost: {:?}.",
            self,
        );
    }

    /// Verifies that the authorization signature for `self` is valid under the `parameters`.
    #[inline]
    pub fn has_valid_authorization_signature(
        &self,
        parameters: &C::Parameters,
    ) -> Result<(), InvalidAuthorizationSignature> {
        match (
            &self.authorization_signature,
            &self.body.randomized_authorization_key,
            requires_authorization(self.body.sender_posts.len()),
        ) {
            (Some(authorization_signature), Some(randomized_authorization_key), true) => {
                if parameters.verify(
                    randomized_authorization_key,
                    &self.body,
                    authorization_signature,
                    &mut (),
                ) {
                    Ok(())
                } else {
                    Err(InvalidAuthorizationSignature::BadSignature)
                }
            }
            (Some(_), None, true) => Err(InvalidAuthorizationSignature::MissingAuthorization),
            (None, Some(_), true) => Err(InvalidAuthorizationSignature::MissingSignature),
            (None, None, false) => Ok(()),
            _ => Err(InvalidAuthorizationSignature::InvalidShape),
        }
    }

    /// Checks that the public participant data is well-formed and runs `ledger` validation on
    /// source and sink accounts.
    #[allow(clippy::type_complexity)] // FIXME: Use a better abstraction for this.
    #[inline]
    fn check_public_participants<L>(
        asset_id: &Option<C::AssetId>,
        source_accounts: Vec<L::AccountId>,
        source_values: Vec<C::AssetValue>,
        sink_accounts: Vec<L::AccountId>,
        sink_values: Vec<C::AssetValue>,
        ledger: &L,
    ) -> Result<
        (Vec<L::ValidSourceAccount>, Vec<L::ValidSinkAccount>),
        TransferPostError<C, L::AccountId, L::UpdateError>,
    >
    where
        L: TransferLedger<C>,
    {
        let sources = source_values.len();
        let sinks = sink_values.len();
        if has_public_participants(sources, sinks) != asset_id.is_some() {
            return Err(TransferPostError::InvalidShape);
        }
        if source_accounts.len() != sources {
            return Err(TransferPostError::InvalidShape);
        }
        if sink_accounts.len() != sinks {
            return Err(TransferPostError::InvalidShape);
        }
        let sources = if sources > 0 {
            ledger.check_source_accounts(
                asset_id.as_ref().unwrap(),
                source_accounts.into_iter().zip(source_values),
            )?
        } else {
            Vec::new()
        };
        let sinks = if sinks > 0 {
            ledger.check_sink_accounts(
                asset_id.as_ref().unwrap(),
                sink_accounts.into_iter().zip(sink_values),
            )?
        } else {
            Vec::new()
        };
        Ok((sources, sinks))
    }

    /// Validates `self` on the transfer `ledger`.
    #[allow(clippy::type_complexity)] // FIXME: Use a better abstraction for this.
    #[inline]
    pub fn validate<L>(
        self,
        parameters: &C::Parameters,
        ledger: &L,
        source_accounts: Vec<L::AccountId>,
        sink_accounts: Vec<L::AccountId>,
    ) -> Result<TransferPostingKey<C, L>, TransferPostError<C, L::AccountId, L::UpdateError>>
    where
        L: TransferLedger<C>,
    {
        self.has_valid_authorization_signature(parameters)?;
        let (source_posting_keys, sink_posting_keys) = Self::check_public_participants(
            &self.body.asset_id,
            source_accounts,
            self.body.sources,
            sink_accounts,
            self.body.sinks,
            ledger,
        )?;
        if !all_unequal(&self.body.sender_posts, |p, q| p.nullifier == q.nullifier) {
            return Err(TransferPostError::DuplicateSpend);
        }
        if !all_unequal(&self.body.receiver_posts, |p, q| p.utxo == q.utxo) {
            return Err(TransferPostError::DuplicateMint);
        }
        let sender_posting_keys = self
            .body
            .sender_posts
            .into_iter()
            .map(move |s| s.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        let receiver_posting_keys = self
            .body
            .receiver_posts
            .into_iter()
            .map(move |r| r.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        let (validity_proof, event) = match ledger.is_valid(TransferPostingKeyRef {
            randomized_authorization_key: &self.body.randomized_authorization_key,
            asset_id: &self.body.asset_id,
            sources: &source_posting_keys,
            senders: &sender_posting_keys,
            receivers: &receiver_posting_keys,
            sinks: &sink_posting_keys,
            proof: self.body.validity_proof,
        }) {
            Some((validity_proof, event)) => (validity_proof, event),
            _ => return Err(TransferPostError::InvalidProof),
        };
        Ok(TransferPostingKey {
            asset_id: self.body.asset_id,
            source_posting_keys,
            sender_posting_keys,
            receiver_posting_keys,
            sink_posting_keys,
            validity_proof,
            event,
        })
    }

    /// Validates `self` on the transfer `ledger` and then posts the updated state to the `ledger`
    /// if validation succeeded.
    #[inline]
    pub fn post<L>(
        self,
        parameters: &C::Parameters,
        ledger: &mut L,
        super_key: &TransferLedgerSuperPostingKey<C, L>,
        source_accounts: Vec<L::AccountId>,
        sink_accounts: Vec<L::AccountId>,
    ) -> Result<L::Event, TransferPostError<C, L::AccountId, L::UpdateError>>
    where
        L: TransferLedger<C>,
    {
        self.validate(parameters, ledger, source_accounts, sink_accounts)?
            .post(ledger, super_key)
            .map_err(TransferPostError::UpdateError)
    }
}

/// Transfer Posting Key
pub struct TransferPostingKey<C, L>
where
    C: Configuration + ?Sized,
    L: TransferLedger<C>,
{
    /// Asset Id
    asset_id: Option<C::AssetId>,

    /// Source Posting Keys
    source_posting_keys: Vec<SourcePostingKey<C, L>>,

    /// Sender Posting Keys
    sender_posting_keys: Vec<SenderPostingKey<C, L>>,

    /// Receiver Posting Keys
    receiver_posting_keys: Vec<ReceiverPostingKey<C, L>>,

    /// Sink Posting Keys
    sink_posting_keys: Vec<SinkPostingKey<C, L>>,

    /// Validity Proof Posting Key
    validity_proof: L::ValidProof,

    /// Ledger Event
    event: L::Event,
}

impl<C, L> TransferPostingKey<C, L>
where
    C: Configuration + ?Sized,
    L: TransferLedger<C>,
{
    /// Posts `self` to the transfer `ledger`.
    ///
    /// # Safety
    ///
    /// This method assumes that posting `self` to `ledger` is atomic and cannot fail. See
    /// [`SenderLedger::spend`] and [`ReceiverLedger::register`] for more information on the
    /// contract for this method.
    #[inline]
    pub fn post(
        self,
        ledger: &mut L,
        super_key: &TransferLedgerSuperPostingKey<C, L>,
    ) -> Result<L::Event, L::UpdateError> {
        let proof = self.validity_proof;
        SenderPostingKey::<C, _>::post_all(self.sender_posting_keys, ledger, &(proof, *super_key));
        ReceiverPostingKey::<C, _>::post_all(
            self.receiver_posting_keys,
            ledger,
            &(proof, *super_key),
        );
        if let Some(asset_id) = self.asset_id {
            ledger.update_public_balances(
                super_key,
                asset_id,
                self.source_posting_keys,
                self.sink_posting_keys,
                proof,
            )?;
        }
        Ok(self.event)
    }
}

/// Transfer Posting Key Reference
pub struct TransferPostingKeyRef<'k, C, L>
where
    C: Configuration + ?Sized,
    L: TransferLedger<C> + ?Sized,
{
    /// Randomized Authorization Key
    pub randomized_authorization_key: &'k Option<AuthorizationKey<C>>,

    /// Asset Id
    pub asset_id: &'k Option<C::AssetId>,

    /// Sources
    pub sources: &'k [SourcePostingKey<C, L>],

    /// Senders
    pub senders: &'k [SenderPostingKey<C, L>],

    /// Receivers
    pub receivers: &'k [ReceiverPostingKey<C, L>],

    /// Sinks
    pub sinks: &'k [SinkPostingKey<C, L>],

    /// Proof
    pub proof: Proof<C>,
}

impl<'k, C, L> TransferPostingKeyRef<'k, C, L>
where
    C: Configuration + ?Sized,
    L: TransferLedger<C> + ?Sized,
{
    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        let mut input = Default::default();
        if let Some(randomized_authorization_key) = &self.randomized_authorization_key {
            C::ProofSystem::extend(&mut input, randomized_authorization_key);
        }
        if let Some(asset_id) = &self.asset_id {
            C::ProofSystem::extend(&mut input, asset_id);
        }
        self.sources
            .iter()
            .for_each(|source| C::ProofSystem::extend(&mut input, source.as_ref()));
        self.senders
            .iter()
            .for_each(|post| post.extend_input::<C::ProofSystem>(&mut input));
        self.receivers
            .iter()
            .for_each(|post| post.extend_input::<C::ProofSystem>(&mut input));
        self.sinks
            .iter()
            .for_each(|sink| C::ProofSystem::extend(&mut input, sink.as_ref()));
        input
    }
}
