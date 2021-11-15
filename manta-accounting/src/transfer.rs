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

//! Transfer Protocol

use crate::{
    asset::{Asset, AssetId, AssetValue},
    identity::{self, CommitmentSchemeOutput, PreReceiver, Utxo},
};
use alloc::vec::Vec;
use core::ops::Add;
use manta_crypto::{
    accumulator::Verifier,
    commitment::CommitmentScheme,
    constraint::{
        reflection::{HasEqual, HasVariable, Var},
        Allocation, Constant, ConstraintSystem, Derived, Equal, ProofSystem, Public,
        PublicOrSecret, Variable, VariableSource,
    },
    encryption::{EncryptedMessage, HybridPublicKeyEncryptionScheme},
    key::KeyAgreementScheme,
    rand::{CryptoRng, RngCore},
};
use manta_util::create_seal;

/// Returns `true` if the transfer with this shape would have no public participants.
#[inline]
pub const fn has_no_public_participants(
    sources: usize,
    senders: usize,
    receivers: usize,
    sinks: usize,
) -> bool {
    let _ = (senders, receivers);
    sources == 0 && sinks == 0
}

/// Transfer Configuration
pub trait Configuration: identity::Configuration<Asset = Asset> {
    /// Encryption Scheme Type
    type EncryptionScheme: HybridPublicKeyEncryptionScheme<
        Plaintext = Self::Asset,
        KeyAgreementScheme = Self::KeyAgreementScheme,
    >;

    /// UTXO Set Verifier Type
    type UtxoSetVerifier: Verifier<Item = Utxo<Self>, Verification = bool>;

    /// Constraint System Type
    type ConstraintSystem: ConstraintSystem
        + HasVariable<
            Self::KeyAgreementScheme,
            Variable = KeyAgreementSchemeVar<Self>,
            Mode = Constant,
        > + HasVariable<Self::CommitmentScheme, Variable = CommitmentSchemeVar<Self>, Mode = Constant>
        + HasVariable<Self::UtxoSetVerifier, Variable = UtxoSetVerifierVar<Self>, Mode = Constant>
        + HasVariable<AssetId, Variable = AssetIdVar<Self>, Mode = PublicOrSecret>
        + HasVariable<AssetValue, Variable = AssetValueVar<Self>, Mode = PublicOrSecret>
        + HasVariable<
            CommitmentSchemeOutput<Self>,
            Variable = CommitmentSchemeOutput<Self::ConstraintConfiguration>,
            Mode = PublicOrSecret,
        > + HasEqual<CommitmentSchemeOutput<Self::ConstraintConfiguration>>;

    /// Constraint System Configuration
    type ConstraintConfiguration: ConstraintConfiguration<Self::ConstraintSystem>;

    /// Proof System Type
    type ProofSystem: ProofSystem<ConstraintSystem = Self::ConstraintSystem, Verification = bool>;
}

/// Transfer Constraint System Configuration
pub trait ConstraintConfiguration<CS>:
    identity::Configuration<Asset = Asset<Self::AssetId, Self::AssetValue>>
where
    CS: ConstraintSystem,
{
    /// Asset Id Variable Type
    type AssetId: Variable<CS, Type = AssetId, Mode = PublicOrSecret> + Equal<CS>;

    /// Asset Value Variable Type
    type AssetValue: Variable<CS, Type = AssetValue, Mode = PublicOrSecret>
        + Equal<CS>
        + Add<Output = Self::AssetValue>;

    /// UTXO Set Verifier Variable Type
    type UtxoSetVerifier: Verifier<Item = Utxo<Self>, Verification = CS::Bool>;
}

/// Spending Key Type
pub type SpendingKey<C> = identity::SpendingKey<<C as identity::Configuration>::KeyAgreementScheme>;

/// Receiving Key Type
pub type ReceivingKey<C> =
    identity::ReceivingKey<<C as identity::Configuration>::KeyAgreementScheme>;

/// Encrypted Note Type
pub type EncryptedNote<C> = EncryptedMessage<<C as Configuration>::EncryptionScheme>;

/// Constraint System Type
type ConstraintSystemType<C> = <C as Configuration>::ConstraintSystem;

/// Constraint Configuration Type
type ConstraintConfigurationType<C> = <C as Configuration>::ConstraintConfiguration;

/// Pre-Sender Type
pub type PreSender<C> = identity::PreSender<C>;

/// Sender Type
pub type Sender<C> = identity::Sender<C, <C as Configuration>::UtxoSetVerifier>;

/// Sender Variable Type
type SenderVar<C> = identity::Sender<
    ConstraintConfigurationType<C>,
    <ConstraintConfigurationType<C> as ConstraintConfiguration<ConstraintSystemType<C>>>::UtxoSetVerifier,
>;

/// Sender Post Type
pub type SenderPost<C> = identity::SenderPost<C, <C as Configuration>::UtxoSetVerifier>;

/// Receiver Type
pub type Receiver<C> = identity::Receiver<C>;

/// Receiver Variable Type
type ReceiverVar<C> = identity::Receiver<<C as Configuration>::ConstraintConfiguration>;

/// Full Receiver Type
pub type FullReceiver<C> = identity::FullReceiver<C>;

/// Receiver Post Type
pub type ReceiverPost<C> = identity::ReceiverPost<C, <C as Configuration>::EncryptionScheme>;

/// Asset Id Variable Type
pub type AssetIdVar<C> =
    <ConstraintConfigurationType<C> as ConstraintConfiguration<ConstraintSystemType<C>>>::AssetId;

/// Asset Value Variable Type
pub type AssetValueVar<C> = <ConstraintConfigurationType<C> as ConstraintConfiguration<
    ConstraintSystemType<C>,
>>::AssetValue;

/// Key Agreement Scheme Variable Type
pub type KeyAgreementSchemeVar<C> =
    <ConstraintConfigurationType<C> as identity::Configuration>::KeyAgreementScheme;

/// Commitment Scheme Variable Type
pub type CommitmentSchemeVar<C> =
    <ConstraintConfigurationType<C> as identity::Configuration>::CommitmentScheme;

/// UTXO Set Verifier Variable Type
pub type UtxoSetVerifierVar<C> = <ConstraintConfigurationType<C> as ConstraintConfiguration<
    ConstraintSystemType<C>,
>>::UtxoSetVerifier;

/// Transfer Proof System Type
type ProofSystemType<C> = <C as Configuration>::ProofSystem;

/// Transfer Proof System Error Type
pub type ProofSystemError<C> = <ProofSystemType<C> as ProofSystem>::Error;

/// Transfer Proving Context Type
pub type ProvingContext<C> = <ProofSystemType<C> as ProofSystem>::ProvingContext;

/// Transfer Verifying Context Type
pub type VerifyingContext<C> = <ProofSystemType<C> as ProofSystem>::VerifyingContext;

/// Transfer Validity Proof Type
pub type Proof<C> = <ProofSystemType<C> as ProofSystem>::Proof;

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
    /// Asset Id
    asset_id: Option<AssetId>,

    /// Sources
    sources: [AssetValue; SOURCES],

    /// Senders
    senders: [PreSender<C>; SENDERS],

    /// Receivers
    receivers: [PreReceiver<C>; RECEIVERS],

    /// Sinks
    sinks: [AssetValue; SINKS],
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Builds a new [`Transfer`].
    #[inline]
    fn new(
        asset_id: Option<AssetId>,
        sources: [AssetValue; SOURCES],
        senders: [PreSender<C>; SENDERS],
        receivers: [PreReceiver<C>; RECEIVERS],
        sinks: [AssetValue; SINKS],
    ) -> Self {
        Self::check_shape(asset_id.is_some());
        Self::new_unchecked(asset_id, sources, senders, receivers, sinks)
    }

    /// Checks that the [`Transfer`] has a valid shape.
    #[inline]
    fn check_shape(has_visible_asset_id: bool) {
        Self::has_nonempty_input_shape();
        Self::has_nonempty_output_shape();
        Self::has_visible_asset_id_when_required(has_visible_asset_id);
    }

    /// Checks that the input side of the transfer is not empty.
    #[inline]
    fn has_nonempty_input_shape() {
        assert_ne!(
            SOURCES + SENDERS,
            0,
            "Not enough participants on the input side."
        );
    }

    /// Checks that the output side of the transfer is not empty.
    #[inline]
    fn has_nonempty_output_shape() {
        assert_ne!(
            RECEIVERS + SINKS,
            0,
            "Not enough participants on the output side."
        );
    }

    /// Checks that the given `asset_id` for [`Transfer`] building is visible exactly when required.
    #[inline]
    fn has_visible_asset_id_when_required(has_visible_asset_id: bool) {
        if SOURCES > 0 || SINKS > 0 {
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
        asset_id: Option<AssetId>,
        sources: [AssetValue; SOURCES],
        senders: [PreSender<C>; SENDERS],
        receivers: [PreReceiver<C>; RECEIVERS],
        sinks: [AssetValue; SINKS],
    ) -> Self {
        Self {
            asset_id,
            sources,
            senders,
            receivers,
            sinks,
        }
    }

    /// Generates the unknown variables for the transfer validity proof.
    #[inline]
    fn unknown_variables(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        cs: &mut C::ConstraintSystem,
    ) -> (
        Option<AssetIdVar<C>>,
        TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        CommitmentSchemeVar<C>,
        UtxoSetVerifierVar<C>,
    ) {
        let base_asset_id = if has_no_public_participants(SOURCES, SENDERS, RECEIVERS, SINKS) {
            None
        } else {
            Some(AssetIdVar::<C>::new_unknown(cs, Public))
        };
        /* TODO:
        (
            base_asset_id,
            TransferParticipantsVar::new_unknown(cs, Derived),
            commitment_scheme.as_known(cs, Public),
            utxo_set_verifier.as_known(cs, Public),
        )
        */
        todo!()
    }

    /// Generates the known variables for the transfer validity proof.
    #[inline]
    fn known_variables(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        cs: &mut C::ConstraintSystem,
    ) -> (
        Option<AssetIdVar<C>>,
        TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        CommitmentSchemeVar<C>,
        UtxoSetVerifierVar<C>,
    ) {
        /* TODO:
        (
            self.public.asset_id.map(|id| id.as_known(cs, Public)),
            TransferParticipantsVar::new_known(cs, self, Derived),
            commitment_scheme.as_known(cs, Public),
            utxo_set_verifier.as_known(cs, Public),
        )
        */
        todo!()
    }

    /// Builds constraints for the transfer validity proof.
    #[inline]
    fn build_constraints(
        base_asset_id: Option<AssetIdVar<C>>,
        participants: TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        commitment_scheme: CommitmentSchemeVar<C>,
        utxo_set_verifier: UtxoSetVerifierVar<C>,
        cs: &mut C::ConstraintSystem,
    ) {
        // FIXME: Add fair randomness constraint.

        let mut secret_asset_ids = Vec::with_capacity(SENDERS + RECEIVERS);

        let input_sum = participants
            .senders
            .into_iter()
            .map(|s| {
                let asset = s.get_well_formed_asset(&commitment_scheme, &utxo_set_verifier, cs);
                secret_asset_ids.push(asset.id);
                asset.value
            })
            .chain(participants.sources)
            .reduce(Add::add)
            .unwrap();

        let output_sum = participants
            .receivers
            .into_iter()
            .map(|r| {
                let asset = r.get_well_formed_asset(&commitment_scheme, cs);
                secret_asset_ids.push(asset.id);
                asset.value
            })
            .chain(participants.sinks)
            .reduce(Add::add)
            .unwrap();

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
        utxo_set_verifier: &C::UtxoSetVerifier,
    ) -> C::ConstraintSystem {
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
        utxo_set_verifier: &C::UtxoSetVerifier,
    ) -> C::ConstraintSystem {
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
        utxo_set_verifier: &C::UtxoSetVerifier,
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
        utxo_set_verifier: &C::UtxoSetVerifier,
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
        utxo_set_verifier: &C::UtxoSetVerifier,
        context: &ProvingContext<C>,
        rng: &mut R,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        /* TODO:
        Ok(TransferPost {
            validity_proof: self.is_valid(commitment_scheme, utxo_set_verifier, context, rng)?,
            asset_id: self.asset_id,
            sources: self.sources.into(),
            sender_posts: IntoIterator::into_iter(self.senders)
                .map(Sender::into_post)
                .collect(),
            receiver_posts: IntoIterator::into_iter(self.receivers)
                .map(FullReceiver::into_post)
                .collect(),
            sinks: self.sinks.into(),
        })
        */
        todo!()
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
    sources: Vec<AssetValueVar<C>>,

    /// Sender Variables
    senders: Vec<SenderVar<C>>,

    /// Receiver Variables
    receivers: Vec<ReceiverVar<C>>,

    /// Sink Variables
    sinks: Vec<AssetValueVar<C>>,
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Variable<C::ConstraintSystem> for TransferParticipantsVar<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    type Type = Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut C::ConstraintSystem, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self {
                sources: this
                    .sources
                    .iter()
                    .map(|source| source.as_known(cs, Public))
                    .collect(),
                senders: this
                    .senders
                    .iter()
                    .map(|sender| {
                        //
                        todo!()
                    })
                    .collect(),
                receivers: this
                    .receivers
                    .iter()
                    .map(|receiver| {
                        //
                        todo!()
                    })
                    .collect(),
                sinks: this
                    .sinks
                    .iter()
                    .map(|sink| sink.as_known(cs, Public))
                    .collect(),
            },
            Allocation::Unknown(mode) => Self {
                sources: (0..SOURCES)
                    .into_iter()
                    .map(|_| AssetValueVar::<C>::new_unknown(cs, Public))
                    .collect(),
                senders: (0..SENDERS)
                    .into_iter()
                    .map(|_| {
                        //
                        todo!()
                    })
                    .collect(),
                receivers: (0..RECEIVERS)
                    .into_iter()
                    .map(|_| {
                        //
                        todo!()
                    })
                    .collect(),
                sinks: (0..SINKS)
                    .into_iter()
                    .map(|_| AssetValueVar::<C>::new_unknown(cs, Public))
                    .collect(),
            },
        }
    }
}

/// Transfer Post
pub struct TransferPost<C>
where
    C: Configuration,
{
    /// Asset Id
    pub asset_id: Option<AssetId>,

    /// Sources
    pub sources: Vec<AssetValue>,

    /// Sender Posts
    pub sender_posts: Vec<SenderPost<C>>,

    /// Receiver Posts
    pub receiver_posts: Vec<ReceiverPost<C>>,

    /// Sinks
    pub sinks: Vec<AssetValue>,

    /// Validity Proof
    pub validity_proof: Proof<C>,
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
    use manta_util::seal;

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
        pub fn build(asset: Asset, receiver: PreReceiver<C>) -> Self {
            Self::new(
                Some(asset.id),
                [asset.value],
                Default::default(),
                [receiver],
                Default::default(),
            )
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
            senders: [PreSender<C>; PrivateTransferShape::SENDERS],
            receivers: [PreReceiver<C>; PrivateTransferShape::RECEIVERS],
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
            senders: [PreSender<C>; ReclaimShape::SENDERS],
            receivers: [PreReceiver<C>; ReclaimShape::RECEIVERS],
            reclaim: Asset,
        ) -> Self {
            Self::new(
                Some(reclaim.id),
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
        PrivateTransfer(Asset, ReceivingKey<C>),

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
