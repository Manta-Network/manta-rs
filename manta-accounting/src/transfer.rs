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

use crate::{
    asset::{sample_asset_balances, Asset, AssetBalance, AssetBalances, AssetId},
    identity::{self, constraint::UtxoVar, Utxo, VoidNumber},
    ledger::{Ledger, PostError},
};
use alloc::vec::Vec;
use core::{
    convert::{TryFrom, TryInto},
    ops::AddAssign,
};
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
use manta_util::{array_map, mixed_chain, Either};
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

/// Returns `true` if the transfer with this shape would have no public side.
#[inline]
const fn has_no_public_side<
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
>() -> bool {
    SOURCES == 0 && SINKS == 0
}

/// Public Transfer Protocol
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicTransfer<const SOURCES: usize, const SINKS: usize> {
    /// Asset Id
    pub asset_id: Option<AssetId>,

    /// Public Asset Sources
    pub sources: AssetBalances<SOURCES>,

    /// Public Asset Sinks
    pub sinks: AssetBalances<SINKS>,
}

#[allow(clippy::derivable_impls)] // NOTE: We only want default on the `<0, 0>` setting.
impl Default for PublicTransfer<0, 0> {
    #[inline]
    fn default() -> Self {
        Self::new_unchecked(None, [], [])
    }
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
            if has_no_public_side::<SOURCES, 0, 0, SINKS>() {
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
pub type ShieldedIdentity<T> =
    identity::ShieldedIdentity<T, <T as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Spend Type
pub type Spend<T> = identity::Spend<T, <T as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Sender Type
pub type Sender<T> = identity::Sender<T, <T as Configuration>::UtxoSet>;

/// Transfer Receiver Type
pub type Receiver<T> = identity::Receiver<T, <T as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Integrated Encryption Scheme Error
pub type IntegratedEncryptionSchemeError<T> =
    <<T as Configuration>::IntegratedEncryptionScheme as IntegratedEncryptionScheme>::Error;

/// Transfer Constraint System Type
pub type ConstraintSystem<T> = <T as Configuration>::ConstraintSystem;

/// Transfer Sender Variable Type
pub type SenderVar<T> = identity::constraint::SenderVar<T, <T as Configuration>::UtxoSet>;

/// Transfer Receiver Type
pub type ReceiverVar<T> =
    identity::constraint::ReceiverVar<T, <T as Configuration>::IntegratedEncryptionScheme>;

/// Transfer Proving Context Type
pub type ProvingContext<T> = <<T as Configuration>::ProofSystem as ProofSystem>::ProvingContext;

/// Transfer Verifying Context Type
pub type VerifyingContext<T> = <<T as Configuration>::ProofSystem as ProofSystem>::VerifyingContext;

/// Transfer Proof Type
pub type Proof<T> = <<T as Configuration>::ProofSystem as ProofSystem>::Proof;

/// Transfer Proof System Error Type
pub type ProofSystemError<T> = <<T as Configuration>::ProofSystem as ProofSystem>::Error;

/// Secret Transfer Protocol
pub struct SecretTransfer<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: Configuration,
{
    /// Senders
    pub senders: [Sender<T>; SENDERS],

    /// Receivers
    pub receivers: [Receiver<T>; RECEIVERS],
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransfer<T, SENDERS, RECEIVERS>
where
    T: Configuration,
{
    /// Maximum Number of Senders
    pub const MAXIMUM_SENDER_COUNT: usize = 32;

    /// Maximum Number of Receivers
    pub const MAXIMUM_RECEIVER_COUNT: usize = 32;

    /// Builds a new [`SecretTransfer`].
    #[inline]
    pub fn new(senders: [Sender<T>; SENDERS], receivers: [Receiver<T>; RECEIVERS]) -> Self {
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
    fn new_unchecked(senders: [Sender<T>; SENDERS], receivers: [Receiver<T>; RECEIVERS]) -> Self {
        Self { senders, receivers }
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
        commitment_scheme: &T::CommitmentScheme,
        utxo_set: &T::UtxoSet,
        context: &ProvingContext<T>,
        rng: &mut R,
    ) -> Result<SecretTransferPost<T, SENDERS, RECEIVERS>, ProofSystemError<T>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        match Transfer::from(self)
            .into_post(commitment_scheme, utxo_set, context, rng)?
            .try_into()
        {
            Ok(post) => Ok(post),
            _ => unreachable!("We convert there and back so we know that the proof exists."),
        }
    }
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> From<SecretTransfer<T, SENDERS, RECEIVERS>>
    for Transfer<T, 0, SENDERS, RECEIVERS, 0>
where
    T: Configuration,
{
    #[inline]
    fn from(transfer: SecretTransfer<T, SENDERS, RECEIVERS>) -> Self {
        Self {
            public: Default::default(),
            secret: transfer,
        }
    }
}

/// Sender Post Type
pub type SenderPost<T> = identity::SenderPost<T, <T as Configuration>::UtxoSet>;

/// Receiver Post Type
pub type ReceiverPost<T> =
    identity::ReceiverPost<T, <T as Configuration>::IntegratedEncryptionScheme>;

/// Secret Transfer Post
pub struct SecretTransferPost<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: Configuration,
{
    /// Sender Posts
    pub sender_posts: [SenderPost<T>; SENDERS],

    /// Receiver Posts
    pub receiver_posts: [ReceiverPost<T>; RECEIVERS],

    /// Validity Proof
    pub validity_proof: Proof<T>,
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransferPost<T, SENDERS, RECEIVERS>
where
    T: Configuration,
{
    /// Posts the [`SecretTransferPost`] to the `ledger`.
    #[inline]
    pub fn post<L>(self, ledger: &mut L) -> Result<(), PostError<L>>
    where
        L: Ledger<
                VoidNumber = VoidNumber<T>,
                Utxo = Utxo<T>,
                UtxoSet = T::UtxoSet,
                EncryptedAsset = EncryptedMessage<T::IntegratedEncryptionScheme>,
                ProofSystem = T::ProofSystem,
            > + ?Sized,
    {
        TransferPost::from(self).post(ledger)
    }
}

impl<T, const SENDERS: usize, const RECEIVERS: usize>
    From<SecretTransferPost<T, SENDERS, RECEIVERS>> for TransferPost<T, 0, SENDERS, RECEIVERS, 0>
where
    T: Configuration,
{
    #[inline]
    fn from(post: SecretTransferPost<T, SENDERS, RECEIVERS>) -> Self {
        Self {
            sender_posts: post.sender_posts,
            receiver_posts: post.receiver_posts,
            validity_proof: Some(post.validity_proof),
        }
    }
}

impl<T, const SENDERS: usize, const RECEIVERS: usize>
    TryFrom<TransferPost<T, 0, SENDERS, RECEIVERS, 0>> for SecretTransferPost<T, SENDERS, RECEIVERS>
where
    T: Configuration,
{
    type Error = ();

    #[inline]
    fn try_from(post: TransferPost<T, 0, SENDERS, RECEIVERS, 0>) -> Result<Self, Self::Error> {
        Ok(Self {
            sender_posts: post.sender_posts,
            receiver_posts: post.receiver_posts,
            validity_proof: post.validity_proof.ok_or(())?,
        })
    }
}

/// Transfer Protocol
pub struct Transfer<
    T,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    T: Configuration,
{
    /// Public Part of the Transfer
    public: PublicTransfer<SOURCES, SINKS>,

    /// Secret Part of the Transfer
    secret: SecretTransfer<T, SENDERS, RECEIVERS>,
}

impl<T, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<T, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    T: Configuration,
{
    /// Builds a new universal [`Transfer`] from public and secret information.
    #[inline]
    pub fn new(
        asset_id: AssetId,
        sources: AssetBalances<SOURCES>,
        senders: [Sender<T>; SENDERS],
        receivers: [Receiver<T>; RECEIVERS],
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self::check_sender_side();
        Self::check_receiver_side();
        SecretTransfer::<T, SENDERS, RECEIVERS>::check_size_overflow();
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
        senders: [Sender<T>; SENDERS],
        receivers: [Receiver<T>; RECEIVERS],
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self {
            public: PublicTransfer::new(asset_id, sources, sinks),
            secret: SecretTransfer::new_unchecked(senders, receivers),
        }
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
        commitment_scheme: &T::CommitmentScheme,
        utxo_set: &T::UtxoSet,
        cs: &mut ConstraintSystem<T>,
    ) -> (
        Option<T::AssetIdVar>,
        TransferParticipantsVar<T, SOURCES, SENDERS, RECEIVERS, SINKS>,
        T::CommitmentSchemeVar,
        T::UtxoSetVar,
    ) {
        let base_asset_id = if has_no_public_side::<SOURCES, SENDERS, RECEIVERS, SINKS>() {
            None
        } else {
            Some(())
        };
        (
            base_asset_id.map(|_| T::AssetIdVar::new_unknown(cs, Public)),
            TransferParticipantsVar::new_unknown(cs, Derived),
            commitment_scheme.as_known(cs, Public),
            utxo_set.as_known(cs, Public),
        )
    }

    /// Generates the known variables for the validity proof.
    #[inline]
    fn known_variables(
        &self,
        commitment_scheme: &T::CommitmentScheme,
        utxo_set: &T::UtxoSet,
        cs: &mut ConstraintSystem<T>,
    ) -> (
        Option<T::AssetIdVar>,
        TransferParticipantsVar<T, SOURCES, SENDERS, RECEIVERS, SINKS>,
        T::CommitmentSchemeVar,
        T::UtxoSetVar,
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
        base_asset_id: Option<T::AssetIdVar>,
        participants: TransferParticipantsVar<T, SOURCES, SENDERS, RECEIVERS, SINKS>,
        commitment_scheme: T::CommitmentSchemeVar,
        utxo_set: T::UtxoSetVar,
        cs: &mut ConstraintSystem<T>,
    ) {
        let mut sender_sum = T::AssetBalanceVar::from_default(cs, Secret);
        let mut receiver_sum = T::AssetBalanceVar::from_default(cs, Secret);

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
        commitment_scheme: &T::CommitmentScheme,
        utxo_set: &T::UtxoSet,
        rng: &mut R,
    ) -> Option<Result<(ProvingContext<T>, VerifyingContext<T>), ProofSystemError<T>>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        if SENDERS == 0 {
            return None;
        }
        let mut cs = T::ProofSystem::for_unknown();
        let (base_asset_id, participants, commitment_scheme, utxo_set) =
            Self::unknown_variables(commitment_scheme, utxo_set, &mut cs);
        Self::build_constraints(
            base_asset_id,
            participants,
            commitment_scheme,
            utxo_set,
            &mut cs,
        );
        Some(T::ProofSystem::generate_context(cs, rng))
    }

    /// Generates a validity proof for this transfer.
    ///
    /// Returns `None` if proof generation does not apply for this kind of transfer.
    #[inline]
    pub fn generate_proof<R>(
        &self,
        commitment_scheme: &T::CommitmentScheme,
        utxo_set: &T::UtxoSet,
        context: &ProvingContext<T>,
        rng: &mut R,
    ) -> Option<Result<Proof<T>, ProofSystemError<T>>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        if SENDERS == 0 {
            return None;
        }
        let mut cs = T::ProofSystem::for_known();
        let (base_asset_id, participants, commitment_scheme, utxo_set) =
            self.known_variables(commitment_scheme, utxo_set, &mut cs);
        Self::build_constraints(
            base_asset_id,
            participants,
            commitment_scheme,
            utxo_set,
            &mut cs,
        );
        Some(T::ProofSystem::generate_proof(cs, context, rng))
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post<R>(
        self,
        commitment_scheme: &T::CommitmentScheme,
        utxo_set: &T::UtxoSet,
        context: &ProvingContext<T>,
        rng: &mut R,
    ) -> Result<TransferPost<T, SOURCES, SENDERS, RECEIVERS, SINKS>, ProofSystemError<T>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Ok(TransferPost {
            validity_proof: match self.generate_proof(commitment_scheme, utxo_set, context, rng) {
                Some(result) => Some(result?),
                _ => None,
            },
            sender_posts: array_map(self.secret.senders, Sender::into_post),
            receiver_posts: array_map(self.secret.receivers, Receiver::into_post),
        })
    }
}

/// Transfer Participants Variable
struct TransferParticipantsVar<
    T,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    T: Configuration,
{
    /// Source Variables
    sources: Vec<T::AssetBalanceVar>,

    /// Sender Variables
    senders: Vec<SenderVar<T>>,

    /// Receiver Variables
    receivers: Vec<ReceiverVar<T>>,

    /// Sink Variables
    sinks: Vec<T::AssetBalanceVar>,
}

impl<T, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Variable<ConstraintSystem<T>> for TransferParticipantsVar<T, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    T: Configuration,
{
    type Type = Transfer<T, SOURCES, SENDERS, RECEIVERS, SINKS>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut ConstraintSystem<T>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
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
                    .map(|_| T::AssetBalanceVar::new_unknown(cs, Public))
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
                    .map(|_| T::AssetBalanceVar::new_unknown(cs, Public))
                    .collect(),
            },
        }
    }
}

/// Transfer Post
pub struct TransferPost<
    T,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    T: Configuration,
{
    /// Sender Posts
    pub sender_posts: [SenderPost<T>; SENDERS],

    /// Receiver Posts
    pub receiver_posts: [ReceiverPost<T>; RECEIVERS],

    /// Validity Proof
    pub validity_proof: Option<Proof<T>>,
}

impl<T, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    TransferPost<T, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    T: Configuration,
{
    /// Posts the [`TransferPost`] to the `ledger`.
    #[inline]
    pub fn post<L>(self, ledger: &mut L) -> Result<(), PostError<L>>
    where
        L: Ledger<
                VoidNumber = VoidNumber<T>,
                Utxo = Utxo<T>,
                EncryptedAsset = EncryptedMessage<T::IntegratedEncryptionScheme>,
                UtxoSet = T::UtxoSet,
                ProofSystem = T::ProofSystem,
            > + ?Sized,
    {
        for sender_post in IntoIterator::into_iter(self.sender_posts) {
            sender_post.post(ledger)?;
        }
        for receiver_post in IntoIterator::into_iter(self.receiver_posts) {
            receiver_post.post(ledger)?;
        }
        if let Some(proof) = self.validity_proof {
            ledger.check_proof(proof)?;
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
    use crate::identity::{AssetParameters, Identity, OpenSpend};

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

    /// Builds a new [`TransferPost`] alias using the given shape type.
    macro_rules! transfer_post_alias {
        ($t:ident, $shape:tt) => {
            alias_type!(TransferPost, $t, $shape)
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
    pub type Mint<T> = transfer_alias!(T, MintShape);

    /// Mint Transaction Ledger Post
    pub type MintPost<T> = transfer_post_alias!(T, MintShape);

    impl<T> Mint<T>
    where
        T: Configuration,
    {
        /// Builds a [`Mint`] from `asset` and `receiver`.
        #[inline]
        pub fn build(asset: Asset, receiver: Receiver<T>) -> Self {
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
            identity: Identity<T>,
            commitment_scheme: &T::CommitmentScheme,
            asset: Asset,
            rng: &mut R,
        ) -> Result<(Mint<T>, OpenSpend<T>), IntegratedEncryptionSchemeError<T>>
        where
            R: CryptoRng + RngCore + ?Sized,
            Standard: Distribution<AssetParameters<T>>,
        {
            let (shielded_identity, spend) = identity.into_receiver(commitment_scheme);
            Ok((
                Mint::build(
                    asset,
                    shielded_identity.into_receiver(commitment_scheme, asset, rng)?,
                ),
                spend.open(asset),
            ))
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
    pub type PrivateTransfer<T> = transfer_alias!(T, PrivateTransferShape);

    /// Private Transfer Transaction Post
    pub type PrivateTransferPost<T> = transfer_post_alias!(T, PrivateTransferShape);

    impl<T> PrivateTransfer<T>
    where
        T: Configuration,
    {
        /// Builds a [`PrivateTransfer`] from `senders` and `receivers`.
        #[inline]
        pub fn build(
            senders: [Sender<T>; PrivateTransferShape::SENDERS],
            receivers: [Receiver<T>; PrivateTransferShape::RECEIVERS],
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
    pub type Reclaim<T> = transfer_alias!(T, ReclaimShape);

    /// Reclaim Transaction Post
    pub type ReclaimPost<T> = transfer_post_alias!(T, ReclaimShape);

    impl<T> Reclaim<T>
    where
        T: Configuration,
    {
        /// Builds a [`Reclaim`] from `senders`, `receiver`, and `reclaim`.
        #[inline]
        pub fn build(
            senders: [Sender<T>; ReclaimShape::SENDERS],
            receiver: Receiver<T>,
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
    pub fn sample_sender<T, R>(commitment_scheme: &T::CommitmentScheme, rng: &mut R)
    where
        T: Configuration,
        R: CryptoRng + RngCore + ?Sized,
    {
        // TODO: let _ = Mint::from_identity(rng.gen(), commitment_scheme, rng.gen(), rng);
        let _ = (commitment_scheme, rng);
        todo!()
    }
}
*/
