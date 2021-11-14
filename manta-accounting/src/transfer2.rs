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
    asset::{Asset, AssetId, AssetValue, AssetVar},
    identity2::{self, CommitmentSchemeOutput, PublicKey, Utxo},
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
    encryption::HybridPublicKeyEncryptionScheme,
    key::KeyAgreementScheme,
    rand::{CryptoRng, RngCore},
};

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
pub trait Configuration: identity2::Configuration<Asset = Asset> {
    /// Encryption Scheme Type
    type EncryptionScheme: HybridPublicKeyEncryptionScheme<
        Plaintext = Self::Asset,
        KeyAgreementScheme = Self::KeyAgreementScheme,
    >;

    /// UTXO Set Verifier Type
    type UtxoSetVerifier: Verifier<Item = Utxo<Self>, Verification = bool>;
}

/// Transfer Proof System Configuration
pub trait ProofSystemConfiguration<C>:
    identity2::Configuration<Asset = AssetVar<Self::ConstraintSystem>>
where
    C: Configuration,
{
    /// Constraint System Type
    type ConstraintSystem: ConstraintSystem
        + HasVariable<
            C::KeyAgreementScheme,
            Variable = <Self as identity2::Configuration>::KeyAgreementScheme,
            Mode = Constant,
        > + HasVariable<
            C::CommitmentScheme,
            Variable = <Self as identity2::Configuration>::CommitmentScheme,
            Mode = Constant,
        > + HasVariable<AssetId, Variable = Self::AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetValue, Variable = Self::AssetValue, Mode = PublicOrSecret>
        + HasVariable<
            CommitmentSchemeOutput<C>,
            Variable = CommitmentSchemeOutput<Self>,
            Mode = PublicOrSecret,
        > + HasEqual<CommitmentSchemeOutput<Self>>;

    /// Proof System Type
    type ProofSystem: ProofSystem<ConstraintSystem = Self::ConstraintSystem, Verification = bool>;

    /// Asset Id Variable Type
    type AssetId: Variable<Self::ConstraintSystem, Type = AssetId, Mode = PublicOrSecret>
        + Equal<Self::ConstraintSystem>;

    /// Asset Value Variable Type
    type AssetValue: Variable<Self::ConstraintSystem, Type = AssetValue, Mode = PublicOrSecret>
        + Equal<Self::ConstraintSystem>
        + Add<Output = Self::AssetValue>;

    /// UTXO Set Verifier Variable Type
    type UtxoSetVerifier: Verifier<
            Item = Utxo<Self>,
            Verification = <Self::ConstraintSystem as ConstraintSystem>::Bool,
        > + Variable<Self::ConstraintSystem, Type = C::UtxoSetVerifier, Mode = Constant>;
}

/// Pre-Sender Type
pub type PreSender<C> = identity2::PreSender<C>;

/// Sender Type
pub type Sender<C> = identity2::Sender<C, <C as Configuration>::UtxoSetVerifier>;

/// Sender Post Type
pub type SenderPost<C> = identity2::SenderPost<C, <C as Configuration>::UtxoSetVerifier>;

/// Receiver Type
pub type Receiver<C> = identity2::Receiver<C>;

/// Full Receiver Type
pub type FullReceiver<C> = identity2::FullReceiver<C>;

/// Receiver Post Type
pub type ReceiverPost<C> = identity2::ReceiverPost<C, <C as Configuration>::EncryptionScheme>;

/// Transfer Proof System Type
type ProofSystemType<C, P> = <P as ProofSystemConfiguration<C>>::ProofSystem;

/// Transfer Proof System Error Type
pub type ProofSystemError<C, P> = <ProofSystemType<C, P> as ProofSystem>::Error;

/// Transfer Proving Context Type
pub type ProvingContext<C, P> = <ProofSystemType<C, P> as ProofSystem>::ProvingContext;

/// Transfer Verifying Context Type
pub type VerifyingContext<C, P> = <ProofSystemType<C, P> as ProofSystem>::VerifyingContext;

/// Transfer Validity Proof Type
pub type Proof<C, P> = <ProofSystemType<C, P> as ProofSystem>::Proof;

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
    senders: [Sender<C>; SENDERS],

    /// Receivers
    receivers: [FullReceiver<C>; RECEIVERS],

    /// Sinks
    sinks: [AssetValue; SINKS],
}

impl<C, const SOURCES: usize, const SENDERS: usize, const RECEIVERS: usize, const SINKS: usize>
    Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
{
    /// Builds a new [`Transfer`] from public and secret information.
    #[inline]
    fn new(
        asset_id: Option<AssetId>,
        sources: [AssetValue; SOURCES],
        senders: [Sender<C>; SENDERS],
        receivers: [FullReceiver<C>; RECEIVERS],
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
        senders: [Sender<C>; SENDERS],
        receivers: [FullReceiver<C>; RECEIVERS],
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
    fn unknown_variables<P>(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        cs: &mut P::ConstraintSystem,
    ) -> (
        Option<P::AssetId>,
        TransferParticipantsVar<C, P, SOURCES, SENDERS, RECEIVERS, SINKS>,
        P::CommitmentScheme,
        P::UtxoSetVerifier,
    )
    where
        P: ProofSystemConfiguration<C>,
    {
        let base_asset_id = if has_no_public_participants(SOURCES, SENDERS, RECEIVERS, SINKS) {
            None
        } else {
            Some(P::AssetId::new_unknown(cs, Public))
        };
        /*
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
    fn known_variables<P>(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        cs: &mut P::ConstraintSystem,
    ) -> (
        Option<P::AssetId>,
        TransferParticipantsVar<C, P, SOURCES, SENDERS, RECEIVERS, SINKS>,
        P::CommitmentScheme,
        P::UtxoSetVerifier,
    )
    where
        P: ProofSystemConfiguration<C>,
    {
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
    fn build_constraints<P>(
        base_asset_id: Option<P::AssetId>,
        participants: TransferParticipantsVar<C, P, SOURCES, SENDERS, RECEIVERS, SINKS>,
        commitment_scheme: P::CommitmentScheme,
        utxo_set_verifier: P::UtxoSetVerifier,
        cs: &mut P::ConstraintSystem,
    ) where
        P: ProofSystemConfiguration<C>,
    {
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
    pub fn unknown_constraints<P>(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
    ) -> P::ConstraintSystem
    where
        P: ProofSystemConfiguration<C>,
    {
        let mut cs = P::ProofSystem::for_unknown();
        let (base_asset_id, participants, commitment_scheme, utxo_set_verifier) =
            Self::unknown_variables::<P>(commitment_scheme, utxo_set_verifier, &mut cs);
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
    pub fn known_constraints<P>(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
    ) -> P::ConstraintSystem
    where
        P: ProofSystemConfiguration<C>,
    {
        let mut cs = P::ProofSystem::for_known();
        let (base_asset_id, participants, commitment_scheme, utxo_set_verifier) =
            self.known_variables::<P>(commitment_scheme, utxo_set_verifier, &mut cs);
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
    pub fn generate_context<P, R>(
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        rng: &mut R,
    ) -> Result<(ProvingContext<C, P>, VerifyingContext<C, P>), ProofSystemError<C, P>>
    where
        P: ProofSystemConfiguration<C>,
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::unknown_constraints::<P>(commitment_scheme, utxo_set_verifier)
            .generate_context::<P::ProofSystem, _>(rng)
    }

    /// Generates a validity proof for this transfer.
    #[inline]
    pub fn is_valid<P, R>(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        context: &ProvingContext<C, P>,
        rng: &mut R,
    ) -> Result<Proof<C, P>, ProofSystemError<C, P>>
    where
        P: ProofSystemConfiguration<C>,
        R: CryptoRng + RngCore + ?Sized,
    {
        self.known_constraints::<P>(commitment_scheme, utxo_set_verifier)
            .prove::<P::ProofSystem, _>(context, rng)
    }

    /// Converts `self` into its ledger post.
    #[inline]
    pub fn into_post<P, R>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set_verifier: &C::UtxoSetVerifier,
        context: &ProvingContext<C, P>,
        rng: &mut R,
    ) -> Result<TransferPost<C, P>, ProofSystemError<C, P>>
    where
        P: ProofSystemConfiguration<C>,
        R: CryptoRng + RngCore + ?Sized,
    {
        Ok(TransferPost {
            validity_proof: self.is_valid::<P, _>(
                commitment_scheme,
                utxo_set_verifier,
                context,
                rng,
            )?,
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
    }
}

/// Transfer Participants Variable
struct TransferParticipantsVar<
    C,
    P,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    C: Configuration,
    P: ProofSystemConfiguration<C>,
{
    /// Source Variables
    sources: Vec<P::AssetValue>,

    /// Sender Variables
    senders: Vec<identity2::Sender<P, P::UtxoSetVerifier>>,

    /// Receiver Variables
    receivers: Vec<identity2::Receiver<P>>,

    /// Sink Variables
    sinks: Vec<P::AssetValue>,
}

impl<
        C,
        P,
        const SOURCES: usize,
        const SENDERS: usize,
        const RECEIVERS: usize,
        const SINKS: usize,
    > Variable<P::ConstraintSystem>
    for TransferParticipantsVar<C, P, SOURCES, SENDERS, RECEIVERS, SINKS>
where
    C: Configuration,
    P: ProofSystemConfiguration<C>,
{
    type Type = Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>;

    type Mode = Derived;

    #[inline]
    fn new(cs: &mut P::ConstraintSystem, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
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
                    .map(|_| P::AssetValue::new_unknown(cs, Public))
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
                    .map(|_| P::AssetValue::new_unknown(cs, Public))
                    .collect(),
            },
        }
    }
}

/// Transfer Post
pub struct TransferPost<C, P>
where
    C: Configuration,
    P: ProofSystemConfiguration<C>,
{
    /// Asset Id
    asset_id: Option<AssetId>,

    /// Sources
    sources: Vec<AssetValue>,

    /// Sender Posts
    sender_posts: Vec<SenderPost<C>>,

    /// Receiver Posts
    receiver_posts: Vec<ReceiverPost<C>>,

    /// Sinks
    sinks: Vec<AssetValue>,

    /// Validity Proof
    validity_proof: Proof<C, P>,
}
