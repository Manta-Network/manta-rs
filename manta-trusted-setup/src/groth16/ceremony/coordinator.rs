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

//! Coordinator

use crate::{
    ceremony::{
        participant::{Participant, Priority},
        registry::{self, Registry},
        signature::{Nonce, SignedMessage},
        util::{deserialize_from_file, serialize_into_file},
    },
    groth16::{
        ceremony::{
            server::filename_format, Ceremony, CeremonyError, Circuits, Configuration, Metadata,
            Queue, Round, UnexpectedError,
        },
        kzg,
        kzg::Accumulator,
        mpc,
        mpc::{verify_transform, Proof, ProvingKeyHasher, State},
        ppot::serialization::{read_subaccumulator, Compressed},
    },
    mpc::ChallengeType,
};
use core::{fmt::Debug, mem};
use manta_crypto::arkworks::{
    bn254::{G1Affine, G2Affine},
    pairing::Pairing,
    relations::r1cs::ConstraintSynthesizer,
};
use manta_util::{time::lock::Timed, Array, BoxArray};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

#[cfg(feature = "csv")]
use crate::ceremony::registry::csv::Record;

/// Queue and Participant Lock
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = "C::Identifier: Debug"),
    Default(bound = ""),
    Eq(bound = ""),
    PartialEq(bound = "")
)]
pub struct LockQueue<C, const LEVEL_COUNT: usize>
where
    C: Ceremony,
{
    /// Participant Queue
    queue: Queue<C, LEVEL_COUNT>,

    /// Participant Lock
    participant_lock: Timed<Option<C::Identifier>>,
}

impl<C, const LEVEL_COUNT: usize> LockQueue<C, LEVEL_COUNT>
where
    C: Ceremony,
{
    /// Returns a mutable reference to `queue`.
    #[inline]
    pub fn queue_mut(&mut self) -> &mut Queue<C, LEVEL_COUNT> {
        &mut self.queue
    }

    /// Retuns the participant lock.
    #[inline]
    pub fn participant_lock(&mut self) -> &Timed<Option<C::Identifier>> {
        &mut self.participant_lock
    }

    /// Checks if the lock is expired or if nobody is in it.
    #[inline]
    pub fn has_expired(&self, metadata: &Metadata) -> bool {
        self.participant_lock
            .has_expired(metadata.contribution_time_limit)
            || self.participant_lock.get().is_none()
    }

    /// Checks if the lock is expired. If so, it updates it.
    #[inline]
    pub fn update_lock<R>(
        &mut self,
        metadata: &Metadata,
        registry: &mut R,
    ) -> (bool, Option<C::Identifier>)
    where
        R: Registry<C::Identifier, C::Participant>,
    {
        if self.has_expired(metadata) {
            (true, self.update_expired_lock(registry))
        } else {
            (false, None)
        }
    }

    /// Checks whether 'participant' has the lock. Returns an Error if not.
    #[inline]
    pub fn has_lock<R>(
        &mut self,
        participant: &C::Identifier,
        metadata: &Metadata,
        registry: &mut R,
    ) -> (bool, Result<(), CeremonyError<C>>)
    where
        R: Registry<C::Identifier, C::Participant>,
    {
        let (has_been_updated, identifier) = self.update_lock(metadata, registry);
        if let Some(p) = identifier {
            if p == *participant {
                return (has_been_updated, Err(CeremonyError::Timeout));
            }
        };
        match self.participant_lock.get() {
            Some(p) => {
                if p == participant {
                    (has_been_updated, Ok(()))
                } else {
                    (has_been_updated, Err(CeremonyError::NotYourTurn))
                }
            }
            _ => (has_been_updated, Err(CeremonyError::NotYourTurn)),
        }
    }

    /// Updates the expired lock by reducing the priority of its participant and setting its
    /// contained value to the new front of the queue. The previous participant in the lock is
    /// returned.
    #[inline]
    pub fn update_expired_lock<R>(&mut self, registry: &mut R) -> Option<C::Identifier>
    where
        R: Registry<C::Identifier, C::Participant>,
    {
        self.participant_lock.mutate(|p| {
            if let Some(identifier) = p {
                if let Some(participant) = registry.get_mut(identifier) {
                    participant.reduce_priority();
                }
            }
            mem::replace(p, self.queue.pop_front())
        })
    }
}

/// State, Challenge and Latest Proof
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            serialize = r"
                C::Challenge: Serialize,
                C::Participant: Serialize,
            ",
            deserialize = r"
                C::Challenge: Deserialize<'de>,
                C::Participant: Deserialize<'de>,
            "
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(Clone)]
pub struct StateChallengeProof<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// State
    state: BoxArray<State<C>, CIRCUIT_COUNT>,

    /// Challenge
    challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,

    /// Latest Proof
    latest_proof: Option<BoxArray<Proof<C>, CIRCUIT_COUNT>>,

    /// Round
    round: u64,
}

impl<C, const CIRCUIT_COUNT: usize> StateChallengeProof<C, CIRCUIT_COUNT>
where
    C: Ceremony,
{
    /// Builds a new [`StateChallengeProof`] from `state`, `challenge`, `latest_proof` and `round`
    #[inline]
    pub fn new_unchecked(
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,
        latest_proof: Option<BoxArray<Proof<C>, CIRCUIT_COUNT>>,
        round: u64,
    ) -> Self {
        assert!(
            metadata.ceremony_size.matches(state.as_slice()),
            "Mismatch of metadata `{metadata:?}` and state.",
        );
        Self {
            state,
            challenge,
            latest_proof,
            round,
        }
    }

    /// Builds a new [`StateChallengeProof`] from `state` and `challenge`.
    #[inline]
    pub fn new(
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,
    ) -> Self {
        Self::new_unchecked(state, challenge, None, 0)
    }

    /// Returns the current round number.
    #[inline]
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Increments the round number.
    #[inline]
    pub fn increment_round(&mut self) {
        self.round += 1;
    }

    /// Returns the current round state.
    #[inline]
    pub fn round_state(&self) -> Round<C>
    where
        C::Challenge: Clone,
    {
        Round::new(self.state.to_vec().into(), self.challenge.to_vec().into())
    }

    /// Returns the challenge.
    #[inline]
    pub fn challenge(&self) -> &BoxArray<C::Challenge, CIRCUIT_COUNT> {
        &self.challenge
    }

    /// Returns the state.
    #[inline]
    pub fn state(&self) -> &BoxArray<State<C>, CIRCUIT_COUNT> {
        &self.state
    }

    /// Returns the latest proof.
    #[inline]
    pub fn latest_proof(&self) -> &Option<BoxArray<Proof<C>, CIRCUIT_COUNT>> {
        &self.latest_proof
    }

    /// Updates the MPC state and challenge using client's contribution. If the contribution is
    /// valid, the participant will be removed from the waiting queue, and cannot participate in
    /// this ceremony again. Then it saves State, Challenge, Proof and round number into data files.
    ///
    /// # Registration
    ///
    /// This method requires that `participant` is already registered. This method assumes the state
    /// was deserialized without checks and performs these checks here.
    #[inline]
    pub fn update(
        &mut self,
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        proof: BoxArray<Proof<C>, CIRCUIT_COUNT>,
        recovery_directory: PathBuf,
    ) -> Result<(u64, BoxArray<C::Challenge, CIRCUIT_COUNT>), CeremonyError<C>>
    where
        C::Challenge: Clone + Serialize,
    {
        for (i, (state, proof)) in state.into_iter().zip(proof.clone().into_iter()).enumerate() {
            C::check_state(&state).map_err(|_| CeremonyError::BadRequest)?;
            let next_challenge = C::challenge(&self.challenge[i], &self.state[i], &state, &proof);
            self.state[i] = verify_transform(&self.challenge[i], &self.state[i], state, proof)
                .map_err(|_| CeremonyError::BadRequest)?
                .1;
            self.challenge[i] = next_challenge;
        }
        self.latest_proof = Some(proof);
        self.increment_round();
        let round = self.round;
        self.save(recovery_directory, round);
        Ok((round, self.challenge.clone()))
    }

    /// Saves State, Challenge and Proof
    #[inline]
    fn save(&self, recovery_directory: PathBuf, round: u64)
    where
        C::Challenge: Serialize,
    {
        assert_eq!(round, self.round());
        let names: Vec<String> = deserialize_from_file(recovery_directory.join(r"circuit_names"))
            .expect("Cannot open circuit name file.");

        for ((state, challenge), name) in self
            .state()
            .iter()
            .zip(self.challenge().iter())
            .zip(names.iter())
        {
            serialize_into_file(
                OpenOptions::new().write(true).truncate(true).create(true),
                &filename_format(
                    &recovery_directory,
                    name.clone(),
                    "state".to_string(),
                    round,
                ),
                state,
            )
            .expect("Writing state to disk should succeed.");

            serialize_into_file(
                OpenOptions::new().write(true).truncate(true).create(true),
                &filename_format(
                    &recovery_directory,
                    name.clone(),
                    "challenge".to_string(),
                    round,
                ),
                &challenge,
            )
            .expect("Writing challenge to disk should succeed.");
        }

        if round > 0 {
            for (proof, name) in self
                .latest_proof()
                .as_ref()
                .unwrap()
                .iter()
                .zip(names.iter())
            {
                serialize_into_file(
                    OpenOptions::new().write(true).truncate(true).create(true),
                    &filename_format(
                        &recovery_directory,
                        name.clone(),
                        "proof".to_string(),
                        round,
                    ),
                    proof,
                )
                .expect("Writing proof to disk should succeed.");
            }
        }

        serialize_into_file(
            OpenOptions::new().write(true).truncate(true).create(true),
            &recovery_directory.join(r"round_number"),
            &round,
        )
        .expect("Must serialize round number to file");
    }
}

/// Preprocesses a request by checking the nonce and verifying the signature.
#[inline]
pub fn preprocess_request<C, R, T>(
    registry: &mut R,
    request: &SignedMessage<C, C::Identifier, T>,
) -> Result<C::Priority, CeremonyError<C>>
where
    T: Serialize,
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    let participant = registry
        .get_mut(request.identifier())
        .ok_or(CeremonyError::NotRegistered)?;
    if participant.has_contributed() {
        return Err(CeremonyError::AlreadyContributed);
    }
    let participant_nonce = participant.nonce();
    if !participant_nonce.is_valid() {
        return Err(CeremonyError::Unexpected(UnexpectedError::AllNoncesUsed));
    }
    request
        .verify(participant_nonce.clone(), participant.verifying_key())
        .map_err(|_| CeremonyError::InvalidSignature {
            expected_nonce: participant_nonce.clone(),
        })?;
    participant.increment_nonce();
    Ok(participant.priority())
}

/// Returns a shared reference to the participant data for `id` from the registry.
#[inline]
pub fn participant<'a, C, R>(registry: &'a R, id: &'a C::Identifier) -> Option<&'a C::Participant>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    registry.get(id)
}

/// Returns a mutable reference to the participant data for `id` from the registry.
#[inline]
pub fn participant_mut<'a, C, R>(
    registry: &'a mut R,
    id: &'a C::Identifier,
) -> Option<&'a mut C::Participant>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    registry.get_mut(id)
}

/// Given Phase 1 accumulator and circuit description,
/// compute initial `State`, `Challenge`.
pub fn initialize<C, S>(
    powers: &Accumulator<C>,
    cs: S,
) -> (<C as ChallengeType>::Challenge, State<C>)
where
    C: Ceremony + kzg::Configuration + kzg::Size + mpc::ProvingKeyHasher<C>,
    <C as ProvingKeyHasher<C>>::Output: Into<<C as ChallengeType>::Challenge>, // TODO Is this weird?
    S: ConstraintSynthesizer<C::Scalar>,
{
    let state =
        mpc::initialize(powers, cs).expect("Should form proving key from circuit description");
    let challenge = <C as ProvingKeyHasher<C>>::hash(&state.0);
    (challenge.into(), state)
}

/// Prepare by initalizing each circuit's prover key, challenge hash and saving
/// to file. Creates a `_registry_0` file containing an empty registry.
/// TODO: Generalize ProvingKeyHasher Output type and curves.
pub fn prepare<C, R, T>(phase_one_param_path: PathBuf, target_path: PathBuf)
where
    C: Ceremony
        + Configuration
        + kzg::Configuration
        + kzg::Size
        + mpc::ProvingKeyHasher<C>
        + Circuits<<C as Pairing>::Scalar>,
    C: mpc::ProvingKeyHasher<C, Output = [u8; 64]>,
    C: ChallengeType<Challenge = Array<u8, 64>>,
    C: Pairing<G1 = G1Affine, G2 = G2Affine>, // TODO: Generalize or make part of a config
    R: Default + Registry<C::Identifier, C::Participant> + Serialize,
    R: registry::Configuration<
        Identifier = C::Identifier,
        Participant = C::Participant,
        Registry = R,
    >,
    R: Debug,
    T: Record<C::Identifier, C::Participant>,
    T::Error: Debug,
    C::Identifier: Debug + Copy,
{
    use memmap::MmapOptions;

    let file = OpenOptions::new()
        .read(true)
        .open(phase_one_param_path)
        .expect("Unable to open phase 1 parameter file in this directory");
    let reader = unsafe {
        MmapOptions::new()
            .map(&file)
            .expect("unable to create memory map for input")
    };
    let powers = read_subaccumulator(&reader, Compressed::No)
        .expect("Cannot read Phase 1 accumulator from file");

    let round_number = 0u64;
    let mut names = Vec::new();
    for (circuit, name) in C::circuits().into_iter() {
        println!("Creating proving key for {name}");
        names.push(name.clone());
        let (challenge, state): (<C as ChallengeType>::Challenge, State<C>) =
            initialize(&powers, circuit);

        serialize_into_file(
            OpenOptions::new().write(true).truncate(true).create(true), // TODO: Change to create_new for production. `prepare` should only be called once
            &filename_format(
                &target_path,
                name.clone(),
                "state".to_string(),
                round_number,
            ),
            &state,
        )
        .expect("Writing state to disk should succeed.");

        serialize_into_file(
            OpenOptions::new().write(true).truncate(true).create(true),
            &filename_format(&target_path, name, "challenge".to_string(), round_number),
            &challenge,
        )
        .expect("Writing challenge to disk should succeed.");
    }

    serialize_into_file(
        OpenOptions::new().write(true).truncate(true).create(true),
        &target_path.join(r"circuit_names"),
        &names,
    )
    .expect("Writing circuit names to disk should succeed.");

    serialize_into_file(
        OpenOptions::new().write(true).truncate(true).create(true),
        &target_path.join(r"round_number"),
        &round_number,
    )
    .expect("Must serialize round number to file");

    let registry = R::default();
    serialize_into_file(
        OpenOptions::new().write(true).truncate(true).create(true),
        &filename_format(
            &target_path,
            "".to_string(),
            "registry".to_string(),
            round_number,
        ),
        &registry,
    )
    .expect("Writing registry to disk should succeed.");
}

/// Saves registry
#[inline]
pub fn save_registry<R, C>(registry: &R, recovery_directory: &Path, round: u64)
where
    R: Registry<C::Identifier, C::Participant> + Serialize,
    C: Ceremony,
{
    serialize_into_file(
        OpenOptions::new().write(true).create(true),
        &filename_format(
            recovery_directory,
            "".to_string(),
            "registry".to_string(),
            round,
        ),
        registry,
    )
    .expect("Writing registry to disk should succeed.")
}
