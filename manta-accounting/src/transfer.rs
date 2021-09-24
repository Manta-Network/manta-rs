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
// TODO:  See if we can get rid of the `Copy` restriction on `ValidProof` and `SuperPostingKey`.
// TODO:  Add `generate_context`/`generate_proof` logic to `SecretTransfer`.
// TODO:  Have a compile-time way to check if proof generation is used for a certain shape,
//        so that the `generate_context`/`generate_proof` functions can only exist on the right
//        shape implementations, instead of failing at runtime with `None`.

use crate::{
    asset::{sample_asset_balances, Asset, AssetBalance, AssetBalances, AssetId},
    identity::{self, constraint::UtxoVar, ReceiverLedger, SenderLedger, Utxo},
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, ops::AddAssign};
use manta_crypto::{
    constraint::{
        self,
        reflection::{HasAllocation, HasVariable},
        Allocation, Constant, ConstraintSystem as _, Derived, Equal, ProofSystem, Public,
        PublicOrSecret, Secret, Variable, VariableSource,
    },
    ies::{EncryptedMessage, IntegratedEncryptionScheme},
    set::{constraint::VerifiedSetVariable, VerifiedSet},
};
use manta_util::{mixed_chain, Either};
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

/// Returns `true` if the transfer with this shape would have no public side.
#[inline]
const fn has_no_public_side(
    sources: usize,
    senders: usize,
    receivers: usize,
    sinks: usize,
) -> bool {
    let _ = (senders, receivers);
    sources == 0 && sinks == 0
}

/// Returns `true` if the transfer with this shape requires a proof.
#[inline]
const fn requires_proof(sources: usize, senders: usize, receivers: usize, sinks: usize) -> bool {
    let _ = (sources, receivers, sinks);
    senders > 0
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
    type ProofSystem: ProofSystem<ConstraintSystem = ConstraintSystem<Self>>;

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
    type UtxoSet: VerifiedSet<Item = Utxo<Self>>
        + HasAllocation<ConstraintSystem<Self>, Variable = Self::UtxoSetVar, Mode = Constant>;

    /// Verified Set Variable for [`Utxo`]
    type UtxoSetVar: VerifiedSetVariable<
        ConstraintSystem<Self>,
        ItemVar = UtxoVar<Self>,
        Type = Self::UtxoSet,
        Mode = Constant,
    >;
}

/// Transfer Shielded Identity Type
pub type ShieldedIdentity<C> =
    identity::ShieldedIdentity<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Spend Type
pub type Spend<C> = identity::Spend<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Sender Type
pub type Sender<C> = identity::Sender<C, <C as Configuration>::UtxoSet>;

/// Sender Post Type
pub type SenderPost<C> = identity::SenderPost<C, <C as Configuration>::UtxoSet>;

/// Sender Post Error Type
pub type SenderPostError<C, L> = identity::SenderPostError<C, <C as Configuration>::UtxoSet, L>;

/// Sender Posting Key Type
pub type SenderPostingKey<C, L> = identity::SenderPostingKey<C, <C as Configuration>::UtxoSet, L>;

/// Transfer Receiver Type
pub type Receiver<C> = identity::Receiver<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Receiver Post Type
pub type ReceiverPost<C> =
    identity::ReceiverPost<C, <C as Configuration>::IntegratedEncryptionScheme>;

/// Receiver Post Error Type
pub type ReceiverPostError<C, L> =
    identity::ReceiverPostError<C, <C as Configuration>::IntegratedEncryptionScheme, L>;

/// Receiver Posting Key Type
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

/// Transfer Proving Context Type
pub type ProvingContext<C> = <<C as Configuration>::ProofSystem as ProofSystem>::ProvingContext;

/// Transfer Verifying Context Type
pub type VerifyingContext<C> = <<C as Configuration>::ProofSystem as ProofSystem>::VerifyingContext;

/// Transfer Proof Type
pub type Proof<C> = <<C as Configuration>::ProofSystem as ProofSystem>::Proof;

/// Transfer Proof System Error Type
pub type ProofSystemError<C> = <<C as Configuration>::ProofSystem as ProofSystem>::Error;

/// Transfer Ledger Super Posting Key Type
pub type TransferLedgerSuperPostingKey<C, L> = <L as TransferLedger<C>>::SuperPostingKey;

/// Transfer Ledger Error Type
pub type TransferLedgerError<C, L> = <L as TransferLedger<C>>::Error;

/// Transfer Ledger
pub trait TransferLedger<C>:
    SenderLedger<
        C,
        C::UtxoSet,
        SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>),
        Error = TransferLedgerError<C, Self>,
    > + ReceiverLedger<
        C,
        C::IntegratedEncryptionScheme,
        SuperPostingKey = (Self::ValidProof, TransferLedgerSuperPostingKey<C, Self>),
        Error = TransferLedgerError<C, Self>,
    >
where
    C: Configuration,
{
    /// Valid [`Proof`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be restricted so that it can only be constructed by this implementation
    /// of [`TransferLedger`]. This is to prevent that [`SenderPostingKey::post`] and
    /// [`ReceiverPostingKey::post`] are called before [`is_valid`](Self::is_valid),
    /// [`SenderPost::validate`], and [`ReceiverPost::validate`].
    type ValidProof: Copy;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`TransferLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Ledger Error
    type Error;

    /// Checks that the transfer `proof` is valid.
    ///
    /// # Implementation Note
    ///
    /// This should always succeed on inputs that demonstrate that they do not require a
    /// proof, by revealing their transaction shape.
    fn is_valid(
        &self,
        proof: ShapedProof<C>,
    ) -> Result<Option<Self::ValidProof>, TransferLedgerError<C, Self>>;
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

    /// Returns `true` whenever a transfer of the given shape `self` requires a validity proof.
    #[inline]
    pub const fn requires_proof(&self) -> bool {
        requires_proof(self.sources, self.senders, self.receivers, self.sinks)
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
        Self {
            sources: S::SOURCES,
            senders: S::SENDERS,
            receivers: S::RECEIVERS,
            sinks: S::SINKS,
        }
    }
}

/// Transfer Shape with Possible Validity [`Proof`]
pub enum ShapedProof<C>
where
    C: Configuration,
{
    /// Shape with a Validity Proof
    WithProof(ShapedProofEntry<C>),

    /// Shape with no Proof
    NoProof(DynamicShape),
}

impl<C> ShapedProof<C>
where
    C: Configuration,
{
    /// Builds a new [`ShapedProof`] for the given `shape` and `proof`.
    #[inline]
    fn new_proof(shape: DynamicShape, proof: Proof<C>) -> Self {
        Self::WithProof(ShapedProofEntry::new(shape, proof))
    }

    /// Returns the shape of the transfer which generated `self`.
    #[inline]
    pub fn shape(&self) -> &DynamicShape {
        match self {
            Self::WithProof(ShapedProofEntry { shape, .. }) => shape,
            Self::NoProof(shape) => shape,
        }
    }

    /// Returns the validity proof for the transfer which generated `self`.
    #[inline]
    pub fn proof(&self) -> Option<&Proof<C>> {
        match self {
            Self::WithProof(ShapedProofEntry { proof, .. }) => Some(proof),
            _ => None,
        }
    }
}

impl<C> From<DynamicShape> for ShapedProof<C>
where
    C: Configuration,
{
    #[inline]
    fn from(shape: DynamicShape) -> Self {
        Self::NoProof(shape)
    }
}

/// Entry for [`ShapedProof`] with a [`Proof`]
pub struct ShapedProofEntry<C>
where
    C: Configuration,
{
    /// Transfer Shape
    shape: DynamicShape,

    /// Validity Proof
    proof: Proof<C>,
}

impl<C> ShapedProofEntry<C>
where
    C: Configuration,
{
    /// Builds a new [`ShapedProofEntry`] for the given `shape` and `proof`.
    #[inline]
    fn new(shape: DynamicShape, proof: Proof<C>) -> Self {
        Self { shape, proof }
    }

    /// Returns the validity `proof` along with its `shape`.
    #[inline]
    pub fn open(self) -> (DynamicShape, Proof<C>) {
        (self.shape, self.proof)
    }
}

impl<C> From<ShapedProofEntry<C>> for (DynamicShape, Proof<C>)
where
    C: Configuration,
{
    #[inline]
    fn from(entry: ShapedProofEntry<C>) -> Self {
        entry.open()
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
            if has_no_public_side(SOURCES, 0, 0, SINKS) {
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

impl<const SOURCES: usize, const SINKS: usize> Distribution<PublicTransfer<SOURCES, SINKS>>
    for Standard
{
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> PublicTransfer<SOURCES, SINKS> {
        PublicTransfer::new(
            self.sample(rng),
            sample_asset_balances(rng),
            sample_asset_balances(rng),
        )
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
    pub const MAXIMUM_SENDER_COUNT: usize = 32;

    /// Maximum Number of Receivers
    pub const MAXIMUM_RECEIVER_COUNT: usize = 32;

    /// Builds a new [`SecretTransfer`].
    #[inline]
    pub fn new(senders: [Sender<C>; SENDERS], receivers: [Receiver<C>; RECEIVERS]) -> Self {
        Self::check_sender_side();
        Self::check_receiver_side();
        Self::check_size_overflow();
        Self::new_unchecked(senders, receivers)
    }

    /// Checks that the sender side is not empty.
    #[inline]
    fn check_sender_side() {
        if SENDERS == 0 {
            panic!("Not enough senders.")
        }
    }

    /// Checks that the receiver side is not empty.
    #[inline]
    fn check_receiver_side() {
        if RECEIVERS == 0 {
            panic!("Not enough receivers.")
        }
    }

    /// Checks that the number of senders and/or receivers does not exceed the allocation limit.
    #[inline]
    fn check_size_overflow() {
        // FIXME: Should we have arrays of senders and receivers or use vectors?
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
        utxo_set: &C::UtxoSet,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Transfer::from(self).into_post(commitment_scheme, utxo_set, context, rng)
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
        Self::check_sender_side();
        Self::check_receiver_side();
        SecretTransfer::<C, SENDERS, RECEIVERS>::check_size_overflow();
        Self::new_unchecked(asset_id, sources, senders, receivers, sinks)
    }

    /// Checks that the sender side is not empty.
    #[inline]
    fn check_sender_side() {
        if SOURCES + SENDERS == 0 {
            panic!("Not enough participants on the sender side.");
        }
    }

    /// Checks that the receiver side is not empty.
    #[inline]
    fn check_receiver_side() {
        if RECEIVERS + SINKS == 0 {
            panic!("Not enough participants on the receiver side.");
        }
    }

    /// Builds a new [`Transfer`] without checking the number of participants on the sender and
    /// receiver side.
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

    /// Checks that the transaction is balanced.
    #[inline]
    pub fn is_balanced(&self) -> bool {
        self.source_sum() + self.sender_sum() == self.receiver_sum() + self.sink_sum()
    }

    /// Generates the unknown variables for the validity proof.
    #[inline]
    fn unknown_variables(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set: &C::UtxoSet,
        cs: &mut ConstraintSystem<C>,
    ) -> (
        Option<C::AssetIdVar>,
        TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        C::CommitmentSchemeVar,
        C::UtxoSetVar,
    ) {
        let base_asset_id = if has_no_public_side(SOURCES, SENDERS, RECEIVERS, SINKS) {
            None
        } else {
            Some(C::AssetIdVar::new_unknown(cs, Public))
        };
        (
            base_asset_id,
            TransferParticipantsVar::new_unknown(cs, Derived),
            commitment_scheme.as_known(cs, Public),
            utxo_set.as_known(cs, Public),
        )
    }

    /// Generates the known variables for the validity proof.
    #[inline]
    fn known_variables(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set: &C::UtxoSet,
        cs: &mut ConstraintSystem<C>,
    ) -> (
        Option<C::AssetIdVar>,
        TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        C::CommitmentSchemeVar,
        C::UtxoSetVar,
    ) {
        (
            self.public.asset_id.map(|id| id.as_known(cs, Public)),
            TransferParticipantsVar::new_known(cs, self, Derived),
            commitment_scheme.as_known(cs, Public),
            utxo_set.as_known(cs, Public),
        )
    }

    /// Builds constraints for transfer validity proof/verifier.
    #[inline]
    fn build_constraints(
        base_asset_id: Option<C::AssetIdVar>,
        participants: TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        commitment_scheme: C::CommitmentSchemeVar,
        utxo_set: C::UtxoSetVar,
        cs: &mut ConstraintSystem<C>,
    ) {
        let mut sender_sum = C::AssetBalanceVar::from_default(cs, Secret);
        let mut receiver_sum = C::AssetBalanceVar::from_default(cs, Secret);

        participants
            .sources
            .into_iter()
            .for_each(|source| sender_sum += source);

        participants
            .sinks
            .into_iter()
            .for_each(|sink| receiver_sum += sink);

        #[allow(clippy::needless_collect)] // NOTE: `cs` is being mutated, we need to collect.
        let secret_asset_ids = mixed_chain(
            participants.senders.into_iter(),
            participants.receivers.into_iter(),
            |c| match c {
                Either::Left(sender) => {
                    let asset = sender.get_well_formed_asset(cs, &commitment_scheme, &utxo_set);
                    sender_sum += asset.value;
                    asset.id
                }
                Either::Right(receiver) => {
                    let asset = receiver.get_well_formed_asset(cs, &commitment_scheme);
                    receiver_sum += asset.value;
                    asset.id
                }
            },
        )
        .collect::<Vec<_>>();

        match base_asset_id {
            Some(asset_id) => cs.assert_all_eq_to_base(&asset_id, secret_asset_ids.iter()),
            _ => cs.assert_all_eq(secret_asset_ids.iter()),
        }

        cs.assert_eq(&sender_sum, &receiver_sum);
    }

    /// Generates a verifier for this transfer shape.
    ///
    /// Returns `None` if proof generation does not apply for this kind of transfer.
    #[allow(clippy::type_complexity)] // FIXME: We will have to refactor this at some point.
    #[inline]
    pub fn generate_context<R>(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set: &C::UtxoSet,
        rng: &mut R,
    ) -> Option<Result<(ProvingContext<C>, VerifyingContext<C>), ProofSystemError<C>>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        if !requires_proof(SOURCES, SENDERS, RECEIVERS, SINKS) {
            return None;
        }
        let mut cs = C::ProofSystem::for_unknown();
        let (base_asset_id, participants, commitment_scheme, utxo_set) =
            Self::unknown_variables(commitment_scheme, utxo_set, &mut cs);
        Self::build_constraints(
            base_asset_id,
            participants,
            commitment_scheme,
            utxo_set,
            &mut cs,
        );
        Some(C::ProofSystem::generate_context(cs, rng))
    }

    /// Generates a validity proof for this transfer.
    ///
    /// Returns `Ok(ShapedProof::NoProof(_))` if proof generation does not apply for this kind
    /// of transfer.
    #[inline]
    pub fn generate_proof<R>(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set: &C::UtxoSet,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<ShapedProof<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let shape = DynamicShape::new(SOURCES, SENDERS, RECEIVERS, SINKS);
        if !shape.requires_proof() {
            return Ok(shape.into());
        }
        let mut cs = C::ProofSystem::for_known();
        let (base_asset_id, participants, commitment_scheme, utxo_set) =
            self.known_variables(commitment_scheme, utxo_set, &mut cs);
        Self::build_constraints(
            base_asset_id,
            participants,
            commitment_scheme,
            utxo_set,
            &mut cs,
        );
        Ok(ShapedProof::new_proof(
            shape,
            C::ProofSystem::generate_proof(cs, context, rng)?,
        ))
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post<R>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set: &C::UtxoSet,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Ok(TransferPost {
            validity_proof: self.generate_proof(commitment_scheme, utxo_set, context, rng)?,
            sender_posts: IntoIterator::into_iter(self.secret.senders)
                .map(Sender::into_post)
                .collect(),
            receiver_posts: IntoIterator::into_iter(self.secret.receivers)
                .map(Receiver::into_post)
                .collect(),
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

/// Transfer Post Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "TransferLedgerError<C, L>: Clone"),
    Copy(bound = "TransferLedgerError<C, L>: Copy"),
    Debug(bound = "TransferLedgerError<C, L>: Debug"),
    Eq(bound = "TransferLedgerError<C, L>: Eq"),
    Hash(bound = "TransferLedgerError<C, L>: Hash"),
    PartialEq(bound = "TransferLedgerError<C, L>: PartialEq")
)]
pub enum TransferPostError<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    /// Sender Post Error
    Sender(SenderPostError<C, L>),

    /// Receiver Post Error
    Receiver(ReceiverPostError<C, L>),

    /// Invalid Transfer Proof Error
    ///
    /// Validity of the transfer could not be proved by the ledger.
    InvalidProof,

    /// Ledger Error
    LedgerError(TransferLedgerError<C, L>),
}

impl<C, L> From<SenderPostError<C, L>> for TransferPostError<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    #[inline]
    fn from(err: SenderPostError<C, L>) -> Self {
        Self::Sender(err)
    }
}

impl<C, L> From<ReceiverPostError<C, L>> for TransferPostError<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    #[inline]
    fn from(err: ReceiverPostError<C, L>) -> Self {
        Self::Receiver(err)
    }
}

/// Transfer Post
pub struct TransferPost<C>
where
    C: Configuration,
{
    /// Sender Posts
    pub sender_posts: Vec<SenderPost<C>>,

    /// Receiver Posts
    pub receiver_posts: Vec<ReceiverPost<C>>,

    /// Validity Proof
    ///
    /// This value is only inhabited by a proof when the transfer shape requires one.
    validity_proof: ShapedProof<C>,
}

impl<C> TransferPost<C>
where
    C: Configuration,
{
    /// Returns the shape of the transfer which generated this post.
    #[inline]
    pub fn shape(&self) -> &DynamicShape {
        self.validity_proof.shape()
    }

    /// Validates `self` on the transfer `ledger`.
    #[inline]
    pub fn validate<L>(
        self,
        ledger: &L,
    ) -> Result<TransferPostingKey<C, L>, TransferPostError<C, L>>
    where
        L: TransferLedger<C>,
    {
        Ok(TransferPostingKey {
            sender_posting_keys: self
                .sender_posts
                .into_iter()
                .map(move |s| s.validate(ledger))
                .collect::<Result<_, _>>()?,
            receiver_posting_keys: self
                .receiver_posts
                .into_iter()
                .map(move |r| r.validate(ledger))
                .collect::<Result<_, _>>()?,
            validity_proof: match ledger
                .is_valid(self.validity_proof)
                .map_err(TransferPostError::LedgerError)?
            {
                Some(key) => key,
                _ => return Err(TransferPostError::InvalidProof),
            },
        })
    }
}

/// Transfer Posting Key
pub struct TransferPostingKey<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    /// Sender Posting Keys
    sender_posting_keys: Vec<SenderPostingKey<C, L>>,

    /// Receiver Posting Keys
    receiver_posting_keys: Vec<ReceiverPostingKey<C, L>>,

    /// Validity Proof Posting Key
    validity_proof: L::ValidProof,
}

impl<C, L> TransferPostingKey<C, L>
where
    C: Configuration,
    L: TransferLedger<C>,
{
    /// Posts `self` to the transfer `ledger`.
    #[inline]
    pub fn post(
        self,
        super_key: &TransferLedgerSuperPostingKey<C, L>,
        ledger: &mut L,
    ) -> Result<(), TransferLedgerError<C, L>> {
        for key in self.sender_posting_keys {
            key.post(&(self.validity_proof, *super_key), ledger)?;
        }
        for key in self.receiver_posting_keys {
            key.post(&(self.validity_proof, *super_key), ledger)?;
        }
        Ok(())
    }
}

/// Sealed Trait Module
mod sealed {
    /// Sealed Trait
    pub trait Sealed {}
}

/// Transfer Shapes
///
/// This trait identifies a transfer shape, i.e. the number and type of participants on the sender
/// and receiver side of the transaction. This trait is sealed and can only be used with the
/// existing implementations.
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
    use crate::identity::{AssetParameters, Identity, InternalReceiver, OpenSpend};

    /// Implements [`Shape`] for a given shape type.
    macro_rules! impl_shape {
        ($shape:tt, $sources:expr, $senders:expr, $receivers:expr, $sinks:expr) => {
            impl sealed::Sealed for $shape {}
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

        /// Builds a [`Mint`]-[`OpenSpend`] pair from an `identity` and an `asset`.
        #[inline]
        pub fn from_identity<R>(
            identity: Identity<C>,
            commitment_scheme: &C::CommitmentScheme,
            asset: Asset,
            rng: &mut R,
        ) -> Result<(Mint<C>, OpenSpend<C>), IntegratedEncryptionSchemeError<C>>
        where
            R: CryptoRng + RngCore + ?Sized,
            Standard: Distribution<AssetParameters<C>>,
        {
            let InternalReceiver {
                receiver,
                open_spend,
            } = identity.into_internal_receiver(commitment_scheme, asset, rng)?;
            Ok((Mint::build(asset, receiver), open_spend))
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
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct ReclaimShape;

    impl_shape!(ReclaimShape, 0, 2, 1, 1);

    /// Reclaim Transaction
    pub type Reclaim<C> = transfer_alias!(C, ReclaimShape);

    impl<C> Reclaim<C>
    where
        C: Configuration,
    {
        /// Builds a [`Reclaim`] from `senders`, `receiver`, and `reclaim`.
        #[inline]
        pub fn build(
            senders: [Sender<C>; ReclaimShape::SENDERS],
            receiver: Receiver<C>,
            reclaim: Asset,
        ) -> Self {
            Self::new(
                reclaim.id,
                Default::default(),
                senders,
                [receiver],
                [reclaim.value],
            )
        }
    }
}

/* TODO:
/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use canonical::Mint;
    use rand::Rng;

    ///
    #[inline]
    pub fn sample_sender<C, R>(commitment_scheme: &C::CommitmentScheme, rng: &mut R)
    where
        C: Configuration,
        R: CryptoRng + RngCore + ?Sized,
    {
        // TODO: let _ = Mint::from_identity(rng.gen(), commitment_scheme, rng.gen(), rng);
        let _ = (commitment_scheme, rng);
        todo!()
    }
}
*/
