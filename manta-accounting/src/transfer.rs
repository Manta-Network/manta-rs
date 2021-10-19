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

//! Transfer Protocols

// FIXME: Make sure that either (a) no empty transfer can be built, or (b) empty transfers work
//        properly i.e. do nothing.
// FIXME: Remove `UtxoSet` dependence from `transfer`, really we only need `UtxoSetVerifier`.
// TODO:  See if we can get rid of the `Copy` restriction on `ValidProof` and `SuperPostingKey`.
// TODO:  See if we can get rid of `PublicTransfer` and `SecretTransfer` and just use `Transfer`.

use crate::{
    asset::{Asset, AssetBalance, AssetBalances, AssetId},
    identity::{
        self, constraint::UtxoVar, ReceiverLedger, ReceiverPostError, SenderLedger,
        SenderPostError, Utxo, VoidNumber,
    },
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, ops::AddAssign};
use manta_crypto::{
    constraint::{
        self,
        reflection::{HasAllocation, HasVariable},
        Allocation, Constant, ConstraintSystem as _, Derived, Equal, Input as ProofSystemInput,
        ProofSystem, Public, PublicOrSecret, Secret, Variable, VariableSource,
    },
    ies::{EncryptedMessage, IntegratedEncryptionScheme},
    rand::{CryptoRng, RngCore},
    set::{constraint::VerifierVariable, VerifiedSet},
};
use manta_util::{create_seal, from_variant_impl, seal};

/// Returns `true` if the transfer with this shape would have no public participants.
#[inline]
const fn has_no_public_participants(
    sources: usize,
    senders: usize,
    receivers: usize,
    sinks: usize,
) -> bool {
    let _ = (senders, receivers);
    sources == 0 && sinks == 0
}

/// [`Transfer`] Configuration
pub trait Configuration:
    identity::constraint::Configuration<ConstraintSystem = ConstraintSystem<Self>>
{
    /// Constraint System
    type ConstraintSystem: constraint::ConstraintSystem
        + HasVariable<AssetId, Variable = Self::AssetIdVar, Mode = PublicOrSecret>
        + HasVariable<AssetBalance, Variable = Self::AssetBalanceVar, Mode = PublicOrSecret>
        + HasVariable<<Self::UtxoSet as VerifiedSet>::Public, Mode = Public>
        + HasVariable<<Self::UtxoSet as VerifiedSet>::Secret, Mode = Secret>;

    /// Proof System
    type ProofSystem: ProofSystem<ConstraintSystem = ConstraintSystem<Self>, Verification = bool>
        + ProofSystemInput<AssetId>
        + ProofSystemInput<AssetBalance>
        + ProofSystemInput<VoidNumber<Self>>
        + ProofSystemInput<<Self::UtxoSet as VerifiedSet>::Public>
        + ProofSystemInput<Utxo<Self>>;

    /// Asset Id Variable
    type AssetIdVar: Variable<ConstraintSystem<Self>, Mode = PublicOrSecret, Type = AssetId>
        + Equal<ConstraintSystem<Self>>;

    /// Asset Balance Variable
    type AssetBalanceVar: Variable<ConstraintSystem<Self>, Mode = PublicOrSecret, Type = AssetBalance>
        + Equal<ConstraintSystem<Self>>
        + AddAssign;

    /// Integrated Encryption Scheme for [`Asset`]
    type IntegratedEncryptionScheme: IntegratedEncryptionScheme<Plaintext = Asset>;

    /// Verified Set for [`Utxo`]
    type UtxoSet: VerifiedSet<Item = Utxo<Self>>;

    /// Verified Set Verifier Variable for [`Utxo`]
    type UtxoSetVerifierVar: VerifierVariable<
        ConstraintSystem<Self>,
        ItemVar = UtxoVar<Self>,
        Type = <Self::UtxoSet as VerifiedSet>::Verifier,
        Mode = Constant,
    >;
}

/// Transfer Shielded Identity Type
pub type ShieldedIdentity<C> =
    identity::ShieldedIdentity<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Internal Identity Type
pub type InternalIdentity<C> =
    identity::InternalIdentity<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Spend Type
pub type Spend<C> = identity::Spend<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Sender Type
pub type Sender<C> = identity::Sender<C, <C as Configuration>::UtxoSet>;

/// Transfer Sender Post Type
pub type SenderPost<C> = identity::SenderPost<C, <C as Configuration>::UtxoSet>;

/// Transfer Sender Posting Key Type
pub type SenderPostingKey<C, L> = identity::SenderPostingKey<C, <C as Configuration>::UtxoSet, L>;

/// Transfer Receiver Type
pub type Receiver<C> = identity::Receiver<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Receiver Post Type
pub type ReceiverPost<C> =
    identity::ReceiverPost<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Receiver Posting Key Type
pub type ReceiverPostingKey<C, L> =
    identity::ReceiverPostingKey<C, <C as Configuration>::IntegratedEncryptionScheme, L>;

/// Transfer Encrypted Asset Type
pub type EncryptedAsset<C> = EncryptedMessage<<C as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Integrated Encryption Scheme Error Type
pub type IntegratedEncryptionSchemeError<C> =
    <<C as Configuration>::IntegratedEncryptionScheme as IntegratedEncryptionScheme>::Error;

/// Transfer Constraint System Type
pub type ConstraintSystem<C> = <C as Configuration>::ConstraintSystem;

/// Transfer Sender Variable Type
pub type SenderVar<C> = identity::constraint::SenderVar<C, <C as Configuration>::UtxoSet>;

/// Transfer Receiver Type
pub type ReceiverVar<C> =
    identity::constraint::ReceiverVar<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Transfer UTXO Set Verifier Type
pub type UtxoSetVerifier<C> = <<C as Configuration>::UtxoSet as VerifiedSet>::Verifier;

/// Transfer Proving Context Type
pub type ProvingContext<C> = <<C as Configuration>::ProofSystem as ProofSystem>::ProvingContext;

/// Transfer Verifying Context Type
pub type VerifyingContext<C> = <<C as Configuration>::ProofSystem as ProofSystem>::VerifyingContext;

/// Transfer Proof Type
pub type Proof<C> = <<C as Configuration>::ProofSystem as ProofSystem>::Proof;

/// Transfer Proof System Input Type
pub type ProofInput<C> = <<C as Configuration>::ProofSystem as ProofSystem>::Input;

/// Transfer Proof System Error Type
pub type ProofSystemError<C> = <<C as Configuration>::ProofSystem as ProofSystem>::Error;

/// Transfer Source Posting Key Type
pub type SourcePostingKey<C, L> = <L as TransferLedger<C>>::ValidSourceBalance;

/// Transfer Ledger Super Posting Key Type
pub type TransferLedgerSuperPostingKey<C, L> = <L as TransferLedger<C>>::SuperPostingKey;

/// Transfer Ledger
///
/// # Safety
///
/// The [`TransferLedger`] interface describes the conditions for a valid ledger update but only for
/// the state that is described by a [`TransferPost`]. Independently of this trait, any ledger
/// implementation still needs to check that source and sink accounts are associated to a real
/// public address. However, checking public balances is done in the
/// [`check_source_balances`](Self::check_source_balances) method.
pub trait TransferLedger<C>:
    SenderLedger<
        C,
        C::UtxoSet,
        SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>),
    > + ReceiverLedger<
        C,
        C::IntegratedEncryptionScheme,
        SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>),
    >
where
    C: Configuration,
{
    /// Valid [`AssetBalance`] for [`TransferPost`] source
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation of
    /// [`TransferLedger`].
    type ValidSourceBalance;

    /// Valid [`Proof`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation
    /// of [`TransferLedger`]. This is to prevent that [`SenderPostingKey::post`] and
    /// [`ReceiverPostingKey::post`] are called before [`SenderPost::validate`],
    /// [`ReceiverPost::validate`], [`check_source_balances`](Self::check_source_balances), and
    /// [`is_valid`](Self::is_valid).
    type ValidProof: Copy;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`TransferLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks that the balances associated to the source accounts are sufficient to withdraw the
    /// amount given in `sources`.
    fn check_source_balances(
        &self,
        sources: Vec<AssetBalance>,
    ) -> Result<Vec<Self::ValidSourceBalance>, InsufficientPublicBalance>;

    /// Checks that the transfer `proof` is valid.
    fn is_valid(
        &self,
        asset_id: Option<AssetId>,
        sources: &[Self::ValidSourceBalance],
        senders: &[SenderPostingKey<C, Self>],
        receivers: &[ReceiverPostingKey<C, Self>],
        sinks: &[AssetBalance],
        proof: Proof<C>,
    ) -> Option<Self::ValidProof>;

    /// Updates the public balances in the ledger, finishing the transaction.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `proof` is a valid proof and that
    /// `senders` and `receivers` are valid participants in the transaction. See
    /// [`is_valid`](Self::is_valid) for more.
    fn update_public_balances(
        &mut self,
        asset_id: AssetId,
        sources: Vec<Self::ValidSourceBalance>,
        sinks: Vec<AssetBalance>,
        proof: Self::ValidProof,
        super_key: &TransferLedgerSuperPostingKey<C, Self>,
    );
}

/// Dynamic Transfer Shape
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct DynamicShape {
    /// Number of Sources
    pub sources: usize,

    /// Number of Senders
    pub senders: usize,

    /// Number of Receivers
    pub receivers: usize,

    /// Number of Sinks
    pub sinks: usize,
}

impl DynamicShape {
    /// Builds a new [`DynamicShape`] from `sources`, `senders`, `receivers`, and `sinks`.
    #[inline]
    pub const fn new(sources: usize, senders: usize, receivers: usize, sinks: usize) -> Self {
        Self {
            sources,
            senders,
            receivers,
            sinks,
        }
    }

    /// Builds a new [`DynamicShape`] using the static [`Shape`] given by `S`.
    #[inline]
    pub fn from_static<S>() -> Self
    where
        S: Shape,
    {
        Self::new(S::SOURCES, S::SENDERS, S::RECEIVERS, S::SINKS)
    }

    /// Checks if `self` matches the static [`Shape`] given by `S`.
    #[inline]
    pub fn matches<S>(&self) -> bool
    where
        S: Shape,
    {
        S::SOURCES == self.sources
            && S::SENDERS == self.senders
            && S::RECEIVERS == self.receivers
            && S::SINKS == self.sinks
    }
}

impl<S> From<S> for DynamicShape
where
    S: Shape,
{
    #[inline]
    fn from(shape: S) -> Self {
        let _ = shape;
        Self::from_static::<S>()
    }
}

/// Public Transfer Protocol
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublicTransfer<const SOURCES: usize, const SINKS: usize> {
    /// Asset Id
    pub asset_id: Option<AssetId>,

    /// Public Asset Sources
    pub sources: AssetBalances<SOURCES>,

    /// Public Asset Sinks
    pub sinks: AssetBalances<SINKS>,
}

impl<const SOURCES: usize, const SINKS: usize> PublicTransfer<SOURCES, SINKS> {
    /// Builds a new [`PublicTransfer`].
    #[inline]
    pub const fn new(
        asset_id: AssetId,
        sources: AssetBalances<SOURCES>,
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self::new_unchecked(
            if has_no_public_participants(SOURCES, 0, 0, SINKS) {
                None
            } else {
                Some(asset_id)
            },
            sources,
            sinks,
        )
    }

    /// Builds a new [`PublicTransfer`] without checking if the asset id should be `None`.
    #[inline]
    const fn new_unchecked(
        asset_id: Option<AssetId>,
        sources: AssetBalances<SOURCES>,
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self {
            asset_id,
            sources,
            sinks,
        }
    }

    /// Returns the shape of this public transfer.
    #[inline]
    pub fn shape(&self) -> DynamicShape {
        DynamicShape::new(SOURCES, 0, 0, SINKS)
    }

    /// Returns the sum of the asset values of the sources in this transfer.
    #[inline]
    pub fn source_sum(&self) -> AssetBalance {
        self.sources.iter().sum()
    }

    /// Returns the sum of the asset values of the sinks in this transfer.
    #[inline]
    pub fn sink_sum(&self) -> AssetBalance {
        self.sinks.iter().sum()
    }

    /// Validates the transaction by checking that the [`source_sum`](Self::source_sum)
    /// equals the [`sink_sum`](Self::sink_sum).
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.source_sum() == self.sink_sum()
    }
}

#[allow(clippy::derivable_impls)] // NOTE: We only want default on the `<0, 0>` setting.
impl Default for PublicTransfer<0, 0> {
    #[inline]
    fn default() -> Self {
        Self::new_unchecked(None, [], [])
    }
}

/// Secret Transfer Protocol
pub struct SecretTransfer<C, const SENDERS: usize, const RECEIVERS: usize>
where
    C: Configuration,
{
    /// Senders
    pub senders: [Sender<C>; SENDERS],

    /// Receivers
    pub receivers: [Receiver<C>; RECEIVERS],
}

impl<C, const SENDERS: usize, const RECEIVERS: usize> SecretTransfer<C, SENDERS, RECEIVERS>
where
    C: Configuration,
{
    /// Maximum Number of Senders
    pub const MAXIMUM_SENDER_COUNT: usize = 16;

    /// Maximum Number of Receivers
    pub const MAXIMUM_RECEIVER_COUNT: usize = 16;

    /// Builds a new [`SecretTransfer`].
    #[inline]
    pub fn new(senders: [Sender<C>; SENDERS], receivers: [Receiver<C>; RECEIVERS]) -> Self {
        Self::check_shape();
        Self::new_unchecked(senders, receivers)
    }

    /// Checks that the [`SecretTransfer`] has a valid shape.
    #[inline]
    fn check_shape() {
        Self::check_sender_shape();
        Self::check_receiver_shape();
        Self::check_size_overflow();
    }

    /// Checks that the sender side is not empty.
    #[inline]
    fn check_sender_shape() {
        assert_ne!(SENDERS, 0, "Not enough senders.");
    }

    /// Checks that the receiver side is not empty.
    #[inline]
    fn check_receiver_shape() {
        assert_ne!(RECEIVERS, 0, "Not enough receivers.");
    }

    /// Checks that the number of senders and/or receivers does not exceed the allocation limit.
    #[inline]
    fn check_size_overflow() {
        match (
            SENDERS > Self::MAXIMUM_SENDER_COUNT,
            RECEIVERS > Self::MAXIMUM_RECEIVER_COUNT,
        ) {
            (true, true) => panic!("Allocated too many senders and receivers."),
            (true, _) => panic!("Allocated too many senders."),
            (_, true) => panic!("Allocated too many receivers."),
            _ => {}
        }
    }

    /// Builds a new [`SecretTransfer`] without checking the number of senders and receivers.
    #[inline]
    fn new_unchecked(senders: [Sender<C>; SENDERS], receivers: [Receiver<C>; RECEIVERS]) -> Self {
        Self { senders, receivers }
    }

    /// Returns the shape of this secret transfer.
    #[inline]
    pub fn shape(&self) -> DynamicShape {
        DynamicShape::new(0, SENDERS, RECEIVERS, 0)
    }

    /// Returns an iterator over all the asset ids in this transfer.
    #[inline]
    fn asset_id_iter(&self) -> impl '_ + Iterator<Item = AssetId> {
        self.senders
            .iter()
            .map(Sender::asset_id)
            .chain(self.receivers.iter().map(Receiver::asset_id))
    }

    /// Checks that the asset ids of all the senders and receivers matches.
    #[inline]
    pub fn has_unique_asset_id(&self) -> bool {
        let mut asset_id = None;
        self.asset_id_iter()
            .all(move |i| asset_id.replace(i) == Some(i))
    }

    /// Returns the sum of the asset values of the senders in this transfer.
    #[inline]
    pub fn sender_sum(&self) -> AssetBalance {
        self.senders.iter().map(Sender::asset_value).sum()
    }

    /// Returns the sum of the asset values of the receivers in this transfer.
    #[inline]
    pub fn receiver_sum(&self) -> AssetBalance {
        self.receivers.iter().map(Receiver::asset_value).sum()
    }

    /// Checks that the [`sender_sum`](Self::sender_sum) equals the
    /// [`receiver_sum`](Self::receiver_sum).
    #[inline]
    pub fn is_balanced(&self) -> bool {
        self.sender_sum() == self.receiver_sum()
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post<R>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &UtxoSetVerifier<C>,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Transfer::from(self).into_post(commitment_scheme, utxo_set_verifier, context, rng)
    }
}

impl<C, const SENDERS: usize, const RECEIVERS: usize> From<SecretTransfer<C, SENDERS, RECEIVERS>>
    for Transfer<C, 0, SENDERS, RECEIVERS, 0>
where
    C: Configuration,
{
    #[inline]
    fn from(transfer: SecretTransfer<C, SENDERS, RECEIVERS>) -> Self {
        Self {
            public: Default::default(),
            secret: transfer,
        }
    }
}

/// Transfer Protocol
pub struct Transfer<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    C: Configuration,
{
    /// Public Part of the Transfer
    public: PublicTransfer<SOURCES, SINKS>,

    /// Secret Part of the Transfer
    secret: SecretTransfer<C, SENDERS, RECEIVERS>,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Builds a new universal [`Transfer`] from public and secret information.
    #[inline]
    pub fn new(
        asset_id: AssetId,
        sources: AssetBalances<SOURCES>,
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self::check_shape();
        Self::new_unchecked(asset_id, sources, senders, receivers, sinks)
    }

    /// Checks that the [`Transfer`] has a valid shape.
    #[inline]
    fn check_shape() {
        Self::check_input_shape();
        Self::check_output_shape();
        SecretTransfer::<C, SENDERS, RECEIVERS>::check_size_overflow();
    }

    /// Checks that the input side is not empty.
    #[inline]
    fn check_input_shape() {
        assert_ne!(
            SOURCES + SENDERS,
            0,
            "Not enough participants on the input side."
        );
    }

    /// Checks that the output side is not empty.
    #[inline]
    fn check_output_shape() {
        assert_ne!(
            RECEIVERS + SINKS,
            0,
            "Not enough participants on the output side."
        );
    }

    /// Builds a new [`Transfer`] without checking the number of participants on the input and
    /// output sides.
    #[inline]
    fn new_unchecked(
        asset_id: AssetId,
        sources: AssetBalances<SOURCES>,
        senders: [Sender<C>; SENDERS],
        receivers: [Receiver<C>; RECEIVERS],
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self {
            public: PublicTransfer::new(asset_id, sources, sinks),
            secret: SecretTransfer::new_unchecked(senders, receivers),
        }
    }

    /// Returns the shape of this transfer.
    #[inline]
    pub fn shape(&self) -> DynamicShape {
        DynamicShape::new(SOURCES, SENDERS, RECEIVERS, SINKS)
    }

    /// Checks that there is one unique asset id for all participants in this transfer.
    #[inline]
    pub fn has_unique_asset_id(&self) -> bool {
        if let Some(asset_id) = self.public.asset_id {
            self.secret.asset_id_iter().all(move |i| asset_id == i)
        } else {
            self.secret.has_unique_asset_id()
        }
    }

    /// Returns the sum of the asset values of the sources in this transfer.
    #[inline]
    pub fn source_sum(&self) -> AssetBalance {
        self.public.source_sum()
    }

    /// Returns the sum of the asset values of the senders in this transfer.
    #[inline]
    pub fn sender_sum(&self) -> AssetBalance {
        self.secret.sender_sum()
    }

    /// Returns the sum of the asset values of the receivers in this transfer.
    #[inline]
    pub fn receiver_sum(&self) -> AssetBalance {
        self.secret.receiver_sum()
    }

    /// Returns the sum of the asset values of the sinks in this transfer.
    #[inline]
    pub fn sink_sum(&self) -> AssetBalance {
        self.public.sink_sum()
    }

    /// Returns the sum of the asset values of the sources and senders in this transfer.
    #[inline]
    pub fn input_sum(&self) -> AssetBalance {
        self.source_sum() + self.sender_sum()
    }

    /// Returns the sum of the asset values of the receivers and sinks in this transfer.
    #[inline]
    pub fn output_sum(&self) -> AssetBalance {
        self.receiver_sum() + self.sink_sum()
    }

    /// Checks that the transaction is balanced.
    #[inline]
    pub fn is_balanced(&self) -> bool {
        self.input_sum() == self.output_sum()
    }

    /// Generates the unknown variables for the validity proof.
    #[inline]
    fn unknown_variables(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &UtxoSetVerifier<C>,
        cs: &mut ConstraintSystem<C>,
    ) -> (
        Option<C::AssetIdVar>,
        TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        C::CommitmentSchemeVar,
        C::UtxoSetVerifierVar,
    ) {
        let base_asset_id = if has_no_public_participants(SOURCES, SENDERS, RECEIVERS, SINKS) {
            None
        } else {
            Some(C::AssetIdVar::new_unknown(cs, Public))
        };
        (
            base_asset_id,
            TransferParticipantsVar::new_unknown(cs, Derived),
            commitment_scheme.as_known(cs, Public),
            utxo_set_verifier.as_known(cs, Public),
        )
    }

    /// Generates the known variables for the validity proof.
    #[inline]
    fn known_variables(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &UtxoSetVerifier<C>,
        cs: &mut ConstraintSystem<C>,
    ) -> (
        Option<C::AssetIdVar>,
        TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        C::CommitmentSchemeVar,
        C::UtxoSetVerifierVar,
    ) {
        (
            self.public.asset_id.map(|id| id.as_known(cs, Public)),
            TransferParticipantsVar::new_known(cs, self, Derived),
            commitment_scheme.as_known(cs, Public),
            utxo_set_verifier.as_known(cs, Public),
        )
    }

    /// Builds constraints for transfer validity proof.
    #[inline]
    fn build_constraints(
        base_asset_id: Option<C::AssetIdVar>,
        participants: TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        commitment_scheme: C::CommitmentSchemeVar,
        utxo_set_verifier: C::UtxoSetVerifierVar,
        cs: &mut ConstraintSystem<C>,
    ) {
        let mut input_sum = C::AssetBalanceVar::from_default(cs, Secret);
        let mut output_sum = C::AssetBalanceVar::from_default(cs, Secret);
        let mut secret_asset_ids = Vec::new();

        for source in participants.sources {
            input_sum += source;
        }

        for sender in participants.senders {
            let asset = sender.get_well_formed_asset(cs, &commitment_scheme, &utxo_set_verifier);
            input_sum += asset.value;
            secret_asset_ids.push(asset.id);
        }

        for receiver in participants.receivers {
            let asset = receiver.get_well_formed_asset(cs, &commitment_scheme);
            output_sum += asset.value;
            secret_asset_ids.push(asset.id);
        }

        for sink in participants.sinks {
            output_sum += sink;
        }

        cs.assert_eq(&input_sum, &output_sum);

        match base_asset_id {
            Some(asset_id) => cs.assert_all_eq_to_base(&asset_id, secret_asset_ids.iter()),
            _ => cs.assert_all_eq(secret_asset_ids.iter()),
        }
    }

    /// Generates the constraint system for an unknown transfer.
    #[inline]
    pub fn unknown_constraints(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &UtxoSetVerifier<C>,
    ) -> ConstraintSystem<C> {
        let mut cs = C::ProofSystem::for_unknown();
        let (base_asset_id, participants, commitment_scheme, utxo_set_verifier) =
            Self::unknown_variables(commitment_scheme, utxo_set_verifier, &mut cs);
        Self::build_constraints(
            base_asset_id,
            participants,
            commitment_scheme,
            utxo_set_verifier,
            &mut cs,
        );
        cs
    }

    /// Generates the constraint system for a known transfer.
    #[inline]
    pub fn known_constraints(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &UtxoSetVerifier<C>,
    ) -> ConstraintSystem<C> {
        let mut cs = C::ProofSystem::for_known();
        let (base_asset_id, participants, commitment_scheme, utxo_set_verifier) =
            self.known_variables(commitment_scheme, utxo_set_verifier, &mut cs);
        Self::build_constraints(
            base_asset_id,
            participants,
            commitment_scheme,
            utxo_set_verifier,
            &mut cs,
        );
        cs
    }

    /// Generates a proving and verifying context for this transfer shape.
    #[inline]
    pub fn generate_context<R>(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &UtxoSetVerifier<C>,
        rng: &mut R,
    ) -> Result<(ProvingContext<C>, VerifyingContext<C>), ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::unknown_constraints(commitment_scheme, utxo_set_verifier)
            .generate_context::<C::ProofSystem, _>(rng)
    }

    /// Generates a validity proof for this transfer.
    #[inline]
    pub fn is_valid<R>(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &UtxoSetVerifier<C>,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<Proof<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        self.known_constraints(commitment_scheme, utxo_set_verifier)
            .prove::<C::ProofSystem, _>(context, rng)
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post<R>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &UtxoSetVerifier<C>,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Ok(TransferPost {
            validity_proof: self.is_valid(commitment_scheme, utxo_set_verifier, context, rng)?,
            asset_id: self.public.asset_id,
            sources: self.public.sources.into(),
            sender_posts: IntoIterator::into_iter(self.secret.senders)
                .map(Sender::into_post)
                .collect(),
            receiver_posts: IntoIterator::into_iter(self.secret.receivers)
                .map(Receiver::into_post)
                .collect(),
            sinks: self.public.sinks.into(),
        })
    }
}

/// Transfer Participants Variable
struct TransferParticipantsVar<
    C,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    C: Configuration,
{
    /// Source Variables
    sources: Vec<C::AssetBalanceVar>,

    /// Sender Variables
    senders: Vec<SenderVar<C>>,

    /// Receiver Variables
    receivers: Vec<ReceiverVar<C>>,

    /// Sink Variables
    sinks: Vec<C::AssetBalanceVar>,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Variable<ConstraintSystem<C>> for TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    type Type = Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut ConstraintSystem<C>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self {
                sources: this
                    .public
                    .sources
                    .iter()
                    .map(|source| source.as_known(cs, Public))
                    .collect(),
                senders: this
                    .secret
                    .senders
                    .iter()
                    .map(|sender| sender.known(cs, mode))
                    .collect(),
                receivers: this
                    .secret
                    .receivers
                    .iter()
                    .map(|receiver| receiver.known(cs, mode))
                    .collect(),
                sinks: this
                    .public
                    .sinks
                    .iter()
                    .map(|sink| sink.as_known(cs, Public))
                    .collect(),
            },
            Allocation::Unknown(mode) => Self {
                sources: (0..SOURCES)
                    .into_iter()
                    .map(|_| C::AssetBalanceVar::new_unknown(cs, Public))
                    .collect(),
                senders: (0..SENDERS)
                    .into_iter()
                    .map(|_| SenderVar::new_unknown(cs, mode))
                    .collect(),
                receivers: (0..RECEIVERS)
                    .into_iter()
                    .map(|_| ReceiverVar::new_unknown(cs, mode))
                    .collect(),
                sinks: (0..SINKS)
                    .into_iter()
                    .map(|_| C::AssetBalanceVar::new_unknown(cs, Public))
                    .collect(),
            },
        }
    }
}

/// Insufficient Public Balance Error
///
/// This `enum` is the error state of the [`TransferLedger::check_source_balances`] method. See its
/// documentation for more.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InsufficientPublicBalance {
    /// Index of the Public Address
    pub index: usize,

    /// Current Balance
    pub balance: AssetBalance,

    /// Amount Attempting to Withdraw
    pub withdraw: AssetBalance,
}

/// Transfer Post Error
///
/// This `enum` is the error state of the [`TransferPost::validate`] method. See its documentation
/// for more.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransferPostError {
    /// Insufficient Public Balance
    InsufficientPublicBalance(InsufficientPublicBalance),

    /// Sender Post Error
    Sender(SenderPostError),

    /// Receiver Post Error
    Receiver(ReceiverPostError),

    /// Invalid Transfer Proof Error
    ///
    /// Validity of the transfer could not be proved by the ledger.
    InvalidProof,
}

from_variant_impl!(TransferPostError, Sender, SenderPostError);
from_variant_impl!(TransferPostError, Receiver, ReceiverPostError);

/// Transfer Post
pub struct TransferPost<C>
where
    C: Configuration,
{
    /// Asset Id
    asset_id: Option<AssetId>,

    /// Sources
    sources: Vec<AssetBalance>,

    /// Sender Posts
    sender_posts: Vec<SenderPost<C>>,

    /// Receiver Posts
    receiver_posts: Vec<ReceiverPost<C>>,

    /// Sinks
    sinks: Vec<AssetBalance>,

    /// Validity Proof
    validity_proof: Proof<C>,
}

impl<C> TransferPost<C>
where
    C: Configuration,
{
    /// Returns the shape of the transfer which generated this post.
    #[inline]
    pub fn shape(&self) -> DynamicShape {
        DynamicShape::new(
            self.sources.len(),
            self.sender_posts.len(),
            self.receiver_posts.len(),
            self.sinks.len(),
        )
    }

    /// Generates the public input for the [`Transfer`] validation proof.
    #[inline]
    pub fn generate_proof_input(&self) -> ProofInput<C> {
        // TODO: See comments in `crate::identity::constraint` about automatically deriving this
        //       method from possibly `TransferParticipantsVar`?
        let mut input = Default::default();
        if let Some(asset_id) = self.asset_id {
            C::ProofSystem::extend(&mut input, &asset_id);
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

    /// Validates `self` on the transfer `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<TransferPostingKey<C, L>, TransferPostError>
    where
        L: TransferLedger<C>,
    {
        let source_posting_keys = ledger
            .check_source_balances(self.sources)
            .map_err(TransferPostError::InsufficientPublicBalance)?;
        let sender_posting_keys = self
            .sender_posts
            .into_iter()
            .map(move |s| s.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        let receiver_posting_keys = self
            .receiver_posts
            .into_iter()
            .map(move |r| r.validate(ledger))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TransferPostingKey {
            validity_proof: match ledger.is_valid(
                self.asset_id,
                &source_posting_keys,
                &sender_posting_keys,
                &receiver_posting_keys,
                &self.sinks,
                self.validity_proof,
            ) {
                Some(key) => key,
                _ => return Err(TransferPostError::InvalidProof),
            },
            asset_id: self.asset_id,
            source_posting_keys,
            sender_posting_keys,
            receiver_posting_keys,
            sinks: self.sinks,
        })
    }
}

/// Transfer Posting Key
pub struct TransferPostingKey<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    /// Asset Id
    asset_id: Option<AssetId>,

    /// Source Posting Keys
    source_posting_keys: Vec<SourcePostingKey<C, L>>,

    /// Sender Posting Keys
    sender_posting_keys: Vec<SenderPostingKey<C, L>>,

    /// Receiver Posting Keys
    receiver_posting_keys: Vec<ReceiverPostingKey<C, L>>,

    /// Sinks
    sinks: Vec<AssetBalance>,

    /// Validity Proof Posting Key
    validity_proof: L::ValidProof,
}

impl<C, L> TransferPostingKey<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    /// Returns the shape of the transfer which generated this posting key.
    #[inline]
    pub fn shape(&self) -> DynamicShape {
        DynamicShape::new(
            self.source_posting_keys.len(),
            self.sender_posting_keys.len(),
            self.receiver_posting_keys.len(),
            self.sinks.len(),
        )
    }

    /// Posts `self` to the transfer `ledger`.
    ///
    /// # Safety
    ///
    /// This method assumes that posting `self` to `ledger` is atomic and cannot fail. See
    /// [`SenderLedger::spend`] and [`ReceiverLedger::register`] for more information on the
    /// contract for this method.
    #[inline]
    pub fn post(self, super_key: &TransferLedgerSuperPostingKey<C, L>, ledger: &mut L) {
        let proof = self.validity_proof;
        for key in self.sender_posting_keys {
            key.post(&(proof, *super_key), ledger);
        }
        for key in self.receiver_posting_keys {
            key.post(&(proof, *super_key), ledger);
        }
        if let Some(asset_id) = self.asset_id {
            ledger.update_public_balances(
                asset_id,
                self.source_posting_keys,
                self.sinks,
                proof,
                super_key,
            );
        }
    }
}

create_seal! {}

/// Transfer Shapes
///
/// This trait identifies a transfer shape, i.e. the number and type of participants on the input
/// and output sides of the transaction. This trait is sealed and can only be used with the
/// [existing canonical implementations](canonical).
pub trait Shape: sealed::Sealed {
    /// Number of Sources
    const SOURCES: usize;

    /// Number of Senders
    const SENDERS: usize;

    /// Number of Receivers
    const RECEIVERS: usize;

    /// Number of Sinks
    const SINKS: usize;
}

/// Canonical Transaction Types
pub mod canonical {
    use super::*;
    use crate::identity::{Identity, PreSender};

    /// Implements [`Shape`] for a given shape type.
    macro_rules! impl_shape {
        ($shape:tt, $sources:expr, $senders:expr, $receivers:expr, $sinks:expr) => {
            seal!($shape);
            impl Shape for $shape {
                const SOURCES: usize = $sources;
                const SENDERS: usize = $senders;
                const RECEIVERS: usize = $receivers;
                const SINKS: usize = $sinks;
            }
        };
    }

    /// Builds a new alias using the given shape type.
    macro_rules! alias_type {
        ($type:tt, $t:ident, $shape:tt) => {
            $type<
                $t,
                { $shape::SOURCES },
                { $shape::SENDERS },
                { $shape::RECEIVERS },
                { $shape::SINKS },
            >
        }
    }

    /// Builds a new [`Transfer`] alias using the given shape type.
    macro_rules! transfer_alias {
        ($t:ident, $shape:tt) => {
            alias_type!(Transfer, $t, $shape)
        };
    }

    /// Mint Transaction Shape
    ///
    /// ```text
    /// <1, 0, 1, 0>
    /// ```
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct MintShape;

    impl_shape!(MintShape, 1, 0, 1, 0);

    /// Mint Transaction
    pub type Mint<C> = transfer_alias!(C, MintShape);

    impl<C> Mint<C>
    where
        C: Configuration,
    {
        /// Builds a [`Mint`] from `asset` and `receiver`.
        #[inline]
        pub fn build(asset: Asset, receiver: Receiver<C>) -> Self {
            Self::new(
                asset.id,
                [asset.value],
                Default::default(),
                [receiver],
                Default::default(),
            )
        }

        /// Builds a [`Mint`] from an `identity` and an `asset`.
        #[inline]
        pub fn from_identity<R>(
            identity: Identity<C>,
            commitment_scheme: &C::CommitmentScheme,
            asset: Asset,
            rng: &mut R,
        ) -> Result<Mint<C>, IntegratedEncryptionSchemeError<C>>
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            Ok(Mint::build(
                asset,
                identity.into_receiver(commitment_scheme, asset, rng)?,
            ))
        }

        /// Builds a [`Mint`] from an `identity` for an [`Asset`] with the given `asset_id` but
        /// zero value.
        ///
        /// This is particularly useful when constructing transactions accumulated from [`Transfer`]
        /// objects and a zero slot on the input side needs to be filled.
        #[inline]
        pub fn zero<R>(
            identity: Identity<C>,
            commitment_scheme: &C::CommitmentScheme,
            asset_id: AssetId,
            rng: &mut R,
        ) -> Result<(Mint<C>, PreSender<C>), IntegratedEncryptionSchemeError<C>>
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            let asset = Asset::zero(asset_id);
            let internal = identity.into_internal(commitment_scheme, asset, rng)?;
            Ok((Mint::build(asset, internal.receiver), internal.pre_sender))
        }
    }

    /// Private Transfer Transaction Shape
    ///
    /// ```text
    /// <0, 2, 2, 0>
    /// ```
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct PrivateTransferShape;

    impl_shape!(PrivateTransferShape, 0, 2, 2, 0);

    /// Private Transfer Transaction
    pub type PrivateTransfer<C> = transfer_alias!(C, PrivateTransferShape);

    impl<C> PrivateTransfer<C>
    where
        C: Configuration,
    {
        /// Builds a [`PrivateTransfer`] from `senders` and `receivers`.
        #[inline]
        pub fn build(
            senders: [Sender<C>; PrivateTransferShape::SENDERS],
            receivers: [Receiver<C>; PrivateTransferShape::RECEIVERS],
        ) -> Self {
            Self::new(
                Default::default(),
                Default::default(),
                senders,
                receivers,
                Default::default(),
            )
        }
    }

    /// Reclaim Transaction Shape
    ///
    /// ```text
    /// <0, 2, 1, 1>
    /// ```
    ///
    /// The [`ReclaimShape`] is defined in terms of the [`PrivateTransferShape`]. It is defined to
    /// have the same number of senders and one secret receiver turned into a public sink.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct ReclaimShape;

    impl_shape!(
        ReclaimShape,
        0,
        PrivateTransferShape::SENDERS,
        PrivateTransferShape::RECEIVERS - 1,
        1
    );

    /// Reclaim Transaction
    pub type Reclaim<C> = transfer_alias!(C, ReclaimShape);

    impl<C> Reclaim<C>
    where
        C: Configuration,
    {
        /// Builds a [`Reclaim`] from `senders`, `receivers`, and `reclaim`.
        #[inline]
        pub fn build(
            senders: [Sender<C>; ReclaimShape::SENDERS],
            receivers: [Receiver<C>; ReclaimShape::RECEIVERS],
            reclaim: Asset,
        ) -> Self {
            Self::new(
                reclaim.id,
                Default::default(),
                senders,
                receivers,
                [reclaim.value],
            )
        }
    }

    /// Canonical Transaction Type
    pub enum Transaction<C>
    where
        C: Configuration,
    {
        /// Mint Private Asset
        Mint(Asset),

        /// Private Transfer Asset to Receiver
        PrivateTransfer(Asset, ShieldedIdentity<C>),

        /// Reclaim Private Asset
        Reclaim(Asset),
    }

    impl<C> Transaction<C>
    where
        C: Configuration,
    {
        /// Checks that `self` can be executed for a given `balance` state, returning the
        /// transaction kind if successful, and returning the asset back if the balance was
        /// insufficient.
        #[inline]
        pub fn check<F>(&self, balance: F) -> Result<TransactionKind, Asset>
        where
            F: FnOnce(Asset) -> bool,
        {
            match self {
                Self::Mint(asset) => Ok(TransactionKind::Deposit(*asset)),
                Self::PrivateTransfer(asset, _) | Self::Reclaim(asset) => {
                    if balance(*asset) {
                        Ok(TransactionKind::Withdraw(*asset))
                    } else {
                        Err(*asset)
                    }
                }
            }
        }
    }

    /// Transaction Kind
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub enum TransactionKind {
        /// Deposit Transaction
        ///
        /// A transaction of this kind will result in a deposit of `asset`.
        Deposit(Asset),

        /// Withdraw Transaction
        ///
        /// A transaction of this kind will result in a withdraw of `asset`.
        Withdraw(Asset),
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use crate::{asset::AssetBalanceType, identity::Identity};
    use manta_crypto::rand::{Rand, Sample, Standard, TrySample};
    use manta_util::{array_map, fallible_array_map, into_array_unchecked};

    /// Test Sampling Distributions
    pub mod distribution {
        use super::*;

        /// [`PublicTransfer`](super::PublicTransfer) Sampling Distribution
        pub type PublicTransfer = Standard;

        /// Fixed Asset [`PublicTransfer`](super::PublicTransfer) Sampling Distribution
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
        pub struct FixedPublicTransfer(pub Asset);

        /// [`SecretTransfer`](super::SecretTransfer) Sampling Distribution
        pub type SecretTransfer<'c, C> = Transfer<'c, C>;

        /// Fixed Asset [`SecretTransfer`](super::SecretTransfer) Sampling Distribution
        pub struct FixedSecretTransfer<'c, C>
        where
            C: Configuration,
        {
            /// Asset
            pub asset: Asset,

            /// Base Distribution
            pub base: SecretTransfer<'c, C>,
        }

        impl<'c, C> FixedSecretTransfer<'c, C>
        where
            C: Configuration,
            C::SecretKey: Sample,
        {
            /// Tries to sample a [`super::SecretTransfer`] using custom sender and receiver asset
            /// totals.
            ///
            /// # Safety
            ///
            /// This method does not check the input/output size constraints found in the
            /// [`super::SecretTransfer::check_shape`] method.
            #[inline]
            pub(super) fn try_sample_custom_totals<
                R,
                const SENDERS: usize,
                const RECEIVERS: usize,
            >(
                asset_id: AssetId,
                sender_total: AssetBalance,
                receiver_total: AssetBalance,
                commitment_scheme: &C::CommitmentScheme,
                utxo_set: &mut C::UtxoSet,
                rng: &mut R,
            ) -> Result<
                super::SecretTransfer<C, SENDERS, RECEIVERS>,
                IntegratedEncryptionSchemeError<C>,
            >
            where
                R: CryptoRng + RngCore + ?Sized,
            {
                FixedSecretTransfer::<C>::try_sample_custom_distribution(
                    asset_id,
                    sample_asset_balances::<_, SENDERS>(sender_total, rng),
                    sample_asset_balances::<_, RECEIVERS>(receiver_total, rng),
                    commitment_scheme,
                    utxo_set,
                    rng,
                )
            }

            /// Tries to sample a [`super::SecretTransfer`] with custom sender and receiver asset
            /// value distributions.
            ///
            /// # Safety
            ///
            /// This method does not check the input/output size constraints found in the
            /// [`super::SecretTransfer::check_shape`] method.
            #[inline]
            pub(super) fn try_sample_custom_distribution<
                R,
                const SENDERS: usize,
                const RECEIVERS: usize,
            >(
                asset_id: AssetId,
                senders: AssetBalances<SENDERS>,
                receivers: AssetBalances<RECEIVERS>,
                commitment_scheme: &C::CommitmentScheme,
                utxo_set: &mut C::UtxoSet,
                rng: &mut R,
            ) -> Result<
                super::SecretTransfer<C, SENDERS, RECEIVERS>,
                IntegratedEncryptionSchemeError<C>,
            >
            where
                R: CryptoRng + RngCore + ?Sized,
            {
                Ok(super::SecretTransfer::new_unchecked(
                    array_map(senders, |v| {
                        let pre_sender =
                            Identity::gen(rng).into_pre_sender(commitment_scheme, asset_id.with(v));
                        pre_sender.insert_utxo(utxo_set);
                        pre_sender.try_upgrade(utxo_set).unwrap()
                    }),
                    fallible_array_map(receivers, |v| {
                        Identity::gen(rng).into_receiver(commitment_scheme, asset_id.with(v), rng)
                    })?,
                ))
            }

            /// Tries to sample a [`super::SecretTransfer`].
            #[inline]
            pub(super) fn try_sample<R, const SENDERS: usize, const RECEIVERS: usize>(
                self,
                rng: &mut R,
            ) -> Result<
                super::SecretTransfer<C, SENDERS, RECEIVERS>,
                IntegratedEncryptionSchemeError<C>,
            >
            where
                R: CryptoRng + RngCore + ?Sized,
            {
                super::SecretTransfer::<C, SENDERS, RECEIVERS>::check_shape();
                Self::try_sample_custom_totals(
                    self.asset.id,
                    self.asset.value,
                    self.asset.value,
                    self.base.commitment_scheme,
                    self.base.utxo_set,
                    rng,
                )
            }
        }

        /// [`Transfer`](super::Transfer) Sampling Distribution
        pub struct Transfer<'c, C>
        where
            C: Configuration,
        {
            /// Commitment Scheme
            pub commitment_scheme: &'c C::CommitmentScheme,

            /// UTXO Set
            pub utxo_set: &'c mut C::UtxoSet,
        }

        /// Fixed Asset [`Transfer`](super::Transfer) Sampling Distribution
        pub struct FixedTransfer<'c, C>
        where
            C: Configuration,
        {
            /// Asset
            pub asset: Asset,

            /// Base Distribution
            pub base: Transfer<'c, C>,
        }
    }

    /// Samples a distribution over `count`-many values summing to `total`.
    ///
    /// # Warning
    ///
    /// This is a naive algorithm and should only be used for testing purposes.
    #[inline]
    pub fn value_distribution<R>(
        count: usize,
        total: AssetBalance,
        rng: &mut R,
    ) -> Vec<AssetBalance>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        if count == 0 {
            return Default::default();
        }
        let mut result = Vec::with_capacity(count + 1);
        result.push(AssetBalance(0));
        for _ in 1..count {
            result.push(AssetBalance(AssetBalanceType::gen(rng) % total.0));
        }
        result.push(total);
        result.sort_unstable();
        for i in 0..count {
            result[i] = result[i + 1] - result[i];
        }
        result.pop().unwrap();
        result
    }

    /// Samples asset balances from `rng`.
    ///
    /// # Warning
    ///
    /// This is a naive algorithm and should only be used for testing purposes.
    #[inline]
    pub fn sample_asset_balances<R, const N: usize>(
        total: AssetBalance,
        rng: &mut R,
    ) -> AssetBalances<N>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        into_array_unchecked(value_distribution(N, total, rng))
    }

    impl<const SOURCES: usize, const SINKS: usize> Sample<distribution::PublicTransfer>
        for PublicTransfer<SOURCES, SINKS>
    {
        #[inline]
        fn sample<R>(distribution: distribution::PublicTransfer, rng: &mut R) -> Self
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            let _ = distribution;
            Self::sample(distribution::FixedPublicTransfer(rng.gen()), rng)
        }
    }

    impl<const SOURCES: usize, const SINKS: usize> Sample<distribution::FixedPublicTransfer>
        for PublicTransfer<SOURCES, SINKS>
    {
        #[inline]
        fn sample<R>(distribution: distribution::FixedPublicTransfer, rng: &mut R) -> Self
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            Self::new(
                distribution.0.id,
                sample_asset_balances(distribution.0.value, rng),
                sample_asset_balances(distribution.0.value, rng),
            )
        }
    }

    impl<C, const SENDERS: usize, const RECEIVERS: usize>
        TrySample<distribution::SecretTransfer<'_, C>> for SecretTransfer<C, SENDERS, RECEIVERS>
    where
        C: Configuration,
        C::SecretKey: Sample,
    {
        type Error = IntegratedEncryptionSchemeError<C>;

        #[inline]
        fn try_sample<R>(
            distribution: distribution::SecretTransfer<C>,
            rng: &mut R,
        ) -> Result<Self, Self::Error>
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            Self::try_sample(
                distribution::FixedSecretTransfer {
                    asset: rng.gen(),
                    base: distribution,
                },
                rng,
            )
        }
    }

    impl<C, const SENDERS: usize, const RECEIVERS: usize>
        TrySample<distribution::FixedSecretTransfer<'_, C>>
        for SecretTransfer<C, SENDERS, RECEIVERS>
    where
        C: Configuration,
        C::SecretKey: Sample,
    {
        type Error = IntegratedEncryptionSchemeError<C>;

        #[inline]
        fn try_sample<R>(
            distribution: distribution::FixedSecretTransfer<C>,
            rng: &mut R,
        ) -> Result<Self, Self::Error>
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            distribution.try_sample(rng)
        }
    }

    impl<
            C,
            const SOURCES: usize,
            const SENDERS: usize,
            const RECEIVERS: usize,
            const SINKS: usize,
        > TrySample<distribution::Transfer<'_, C>>
        for Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
    where
        C: Configuration,
        C::SecretKey: Sample,
    {
        type Error = IntegratedEncryptionSchemeError<C>;

        #[inline]
        fn try_sample<R>(
            distribution: distribution::Transfer<C>,
            rng: &mut R,
        ) -> Result<Self, Self::Error>
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            Self::try_sample(
                distribution::FixedTransfer {
                    asset: rng.gen(),
                    base: distribution,
                },
                rng,
            )
        }
    }

    impl<
            C,
            const SOURCES: usize,
            const SENDERS: usize,
            const RECEIVERS: usize,
            const SINKS: usize,
        > TrySample<distribution::FixedTransfer<'_, C>>
        for Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
    where
        C: Configuration,
        C::SecretKey: Sample,
    {
        type Error = IntegratedEncryptionSchemeError<C>;

        #[inline]
        fn try_sample<R>(
            distribution: distribution::FixedTransfer<C>,
            rng: &mut R,
        ) -> Result<Self, Self::Error>
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            Self::check_shape();

            let asset = distribution.asset;
            let mut input = value_distribution(SOURCES + SENDERS, asset.value, rng);
            let mut output = value_distribution(RECEIVERS + SINKS, asset.value, rng);
            let secret_input = input.split_off(SOURCES);
            let public_output = output.split_off(RECEIVERS);

            Ok(Self {
                public: PublicTransfer::new(
                    asset.id,
                    into_array_unchecked(input),
                    into_array_unchecked(public_output),
                ),
                secret: distribution::FixedSecretTransfer::try_sample_custom_distribution(
                    asset.id,
                    into_array_unchecked(secret_input),
                    into_array_unchecked(output),
                    distribution.base.commitment_scheme,
                    distribution.base.utxo_set,
                    rng,
                )?,
            })
        }
    }

    impl<
            C,
            const SOURCES: usize,
            const SENDERS: usize,
            const RECEIVERS: usize,
            const SINKS: usize,
        > Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
    where
        C: Configuration,
    {
        /// Samples constraint system for unknown transfer from `rng`.
        #[inline]
        pub fn sample_unknown_constraints<CD, VD, R>(rng: &mut R) -> ConstraintSystem<C>
        where
            CD: Default,
            VD: Default,
            C::CommitmentScheme: Sample<CD>,
            UtxoSetVerifier<C>: Sample<VD>,
            R: CryptoRng + RngCore + ?Sized,
        {
            Self::unknown_constraints(&rng.gen(), &rng.gen())
        }

        /// Samples proving and verifying contexts from `rng`.
        #[inline]
        pub fn sample_context<CD, VD, R>(
            rng: &mut R,
        ) -> Result<(ProvingContext<C>, VerifyingContext<C>), ProofSystemError<C>>
        where
            CD: Default,
            VD: Default,
            C::CommitmentScheme: Sample<CD>,
            UtxoSetVerifier<C>: Sample<VD>,
            R: CryptoRng + RngCore + ?Sized,
        {
            Self::generate_context(&rng.gen(), &rng.gen(), rng)
        }

        /// Samples a [`Transfer`] and checks whether its internal proof is valid relative to the
        /// given `commitment_scheme` and `utxo_set`.
        #[inline]
        pub fn sample_and_check_proof<R>(
            commitment_scheme: &C::CommitmentScheme,
            utxo_set: &mut C::UtxoSet,
            rng: &mut R,
        ) -> Result<bool, ProofSystemError<C>>
        where
            C::SecretKey: Sample,
            R: CryptoRng + RngCore + ?Sized,
        {
            let transfer = Self::try_sample(
                distribution::Transfer {
                    commitment_scheme,
                    utxo_set,
                },
                rng,
            )
            .ok()
            .expect("This test is not checking whether sampling works properly.");

            let (proving_key, verifying_key) =
                Self::generate_context(commitment_scheme, utxo_set.verifier(), rng)?;

            has_valid_proof(
                &transfer.into_post(commitment_scheme, utxo_set.verifier(), &proving_key, rng)?,
                &verifying_key,
            )
        }
    }

    /// Checks if `post` has a valid internal proof, verifying with the given `context`.
    #[inline]
    pub fn has_valid_proof<C>(
        post: &TransferPost<C>,
        context: &VerifyingContext<C>,
    ) -> Result<bool, ProofSystemError<C>>
    where
        C: Configuration,
    {
        C::ProofSystem::verify(&post.generate_proof_input(), &post.validity_proof, context)
    }

    /// Asserts that `post` has a valid internal proof, verifying with the given `context`.
    #[inline]
    pub fn assert_valid_proof<C>(post: &TransferPost<C>, context: &VerifyingContext<C>)
    where
        C: Configuration,
    {
        assert!(matches!(has_valid_proof(post, context), Ok(true)));
    }
}
