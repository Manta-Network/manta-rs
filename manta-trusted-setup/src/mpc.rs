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

//! Secure Multi-Party Computation Primitives

use alloc::vec::{self, Vec};
use core::{
    fmt::Debug,
    hash::Hash,
    ops::{Deref, DerefMut},
    slice,
};
use manta_util::assert_all_eq_len;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// State
pub trait StateType {
    /// State Type
    type State;
}

impl<T> StateType for &T
where
    T: StateType,
{
    type State = T::State;
}

/// State Type
pub type State<T> = <T as StateType>::State;

/// Challenge
pub trait ChallengeType {
    /// Challenge Type
    type Challenge;
}

impl<T> ChallengeType for &T
where
    T: ChallengeType,
{
    type Challenge = T::Challenge;
}

/// Challenge Type
pub type Challenge<T> = <T as ChallengeType>::Challenge;

/// Proof
pub trait ProofType {
    /// Proof Type
    type Proof;
}

impl<T> ProofType for &T
where
    T: ProofType,
{
    type Proof = T::Proof;
}

/// Proof Type
pub type Proof<T> = <T as ProofType>::Proof;

/// Contribution
pub trait ContributionType {
    /// Contribution Type
    type Contribution;
}

impl<T> ContributionType for &T
where
    T: ContributionType,
{
    type Contribution = T::Contribution;
}

/// Contribution Type
pub type Contribution<T> = <T as ContributionType>::Contribution;

/// Secure Multi-Party Computation Types
pub trait Types: ChallengeType + ContributionType + ProofType + StateType {}

impl<T> Types for T where T: ChallengeType + ContributionType + ProofType + StateType {}

/// Contribution
pub trait Contribute: ChallengeType + ContributionType + ProofType + StateType {
    /// Computes the next state from `state`, `challenge`, and `contribution`.
    fn contribute(
        &self,
        state: &mut Self::State,
        challenge: &Self::Challenge,
        contribution: &Self::Contribution,
    ) -> Self::Proof;
}

/// Verification
pub trait Verify: ChallengeType + ProofType + StateType {
    /// Verification Error Type
    type Error;

    /// Computes the challenge associated to `challenge`, `last`, `next`, and `proof` for the next
    /// player.
    fn challenge(
        &self,
        challenge: &Self::Challenge,
        last: &Self::State,
        next: &Self::State,
        proof: &Self::Proof,
    ) -> Self::Challenge;

    /// Verifies the transformation from `last` to `next` using the `challenge` and `proof` as
    /// evidence for the correct update of the state. This method returns the `next` state and
    /// the next response.
    fn verify_transform(
        &self,
        challenge: &Self::Challenge,
        last: Self::State,
        next: Self::State,
        proof: Self::Proof,
    ) -> Result<Self::State, Self::Error>;

    /// Verifies all contributions in `iter` chaining from an initial `state` and `challenge`
    /// returning the newest [`State`](StateType::State) and [`Challenge`](ChallengeType::Challenge)
    /// if all the contributions in the chain had valid transitions.
    #[inline]
    fn verify_transform_all<E, I>(
        &self,
        mut challenge: Self::Challenge,
        mut state: Self::State,
        iter: I,
    ) -> Result<(Self::Challenge, Self::State), Self::Error>
    where
        E: Into<Self::Error>,
        I: IntoIterator<Item = Result<(Self::State, Self::Proof), E>>,
    {
        for item in iter {
            let (next, next_proof) = item.map_err(Into::into)?;
            let next_challenge = self.challenge(&challenge, &state, &next, &next_proof);
            state = self.verify_transform(&challenge, state, next, next_proof)?;
            challenge = next_challenge;
        }
        Ok((challenge, state))
    }
}

/// Secure Multi-Party Contribution Transcript
pub struct Transcript<T>
where
    T: ChallengeType + StateType + ProofType,
{
    /// Initial Challenge
    pub initial_challenge: T::Challenge,

    /// Initial State
    pub initial_state: T::State,

    /// Rounds
    pub rounds: Vec<(T::State, T::Proof)>,
}

impl<T> Transcript<T>
where
    T: ChallengeType + StateType + ProofType,
{
    /// Verifies the transcript `self` against `parameters` returning the final challenge and state.
    #[inline]
    pub fn verify(self, parameters: &T) -> Result<(T::Challenge, T::State), T::Error>
    where
        T: Verify,
    {
        parameters.verify_transform_all::<T::Error, _>(
            self.initial_challenge,
            self.initial_state,
            self.rounds.into_iter().map(Ok),
        )
    }
}

/// Secure Multi-Party Computation Round
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "T::State: Deserialize<'de>, T::Challenge: Deserialize<'de>",
            serialize = "T::State: Serialize, T::Challenge: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T::State: Clone, T::Challenge: Clone"),
    Copy(bound = "T::State: Copy, T::Challenge: Copy"),
    Debug(bound = "T::State: Debug, T::Challenge: Debug"),
    Default(bound = "T::State: Default, T::Challenge: Default"),
    Eq(bound = "T::State: Eq, T::Challenge: Eq"),
    Hash(bound = "T::State: Hash, T::Challenge: Hash"),
    PartialEq(bound = "T::State: PartialEq, T::Challenge: PartialEq")
)]
pub struct Round<T>
where
    T: ChallengeType + StateType,
{
    /// State
    pub state: T::State,

    /// Challenge
    pub challenge: T::Challenge,
}

impl<T> Round<T>
where
    T: ChallengeType + StateType,
{
    /// Builds a new [`Round`] from `state` and `challenge`.
    #[inline]
    pub fn new(state: T::State, challenge: T::Challenge) -> Self {
        Self { state, challenge }
    }

    /// Computes the contribution proof using [`Contribute::contribute`] over `parameters`.
    #[inline]
    pub fn contribute(&mut self, parameters: &T, contribution: &T::Contribution) -> T::Proof
    where
        T: Contribute,
    {
        parameters.contribute(&mut self.state, &self.challenge, contribution)
    }

    /// Computes the round challenge using [`Verify::challenge`] over `parameters`.
    #[inline]
    pub fn challenge(&self, parameters: &T, next: &T::State, proof: &T::Proof) -> T::Challenge
    where
        T: Verify,
    {
        parameters.challenge(&self.challenge, &self.state, next, proof)
    }

    /// Verifies that the transformation from `self` to `next` is valid, returning the next state
    /// using [`Verify::verify_transform`] over `parameters`.
    #[inline]
    pub fn verify_transform(
        self,
        parameters: &T,
        next: T::State,
        proof: T::Proof,
    ) -> Result<T::State, T::Error>
    where
        T: Verify,
    {
        parameters.verify_transform(&self.challenge, self.state, next, proof)
    }
}

/// Parallel MPC Wrapper
///
/// Multiple secure multi-party computation protocols with the same round structure can be run in
/// parallel, i.e. both the contribution and verification of each protocol can be run in parallel.
/// This increases the latency of any particular instance of the protocol but reduces the overhead
/// of running multiple protocols.
///
/// This type [`Parallel`] can be used for any component of the protocol, including types defined by
/// [`Types`] instances or the [`Contribute`] or [`Verify`] instances.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Parallel<T>(Vec<T>);

impl<T> Deref for Parallel<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T> DerefMut for Parallel<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

impl<T> From<Vec<T>> for Parallel<T> {
    #[inline]
    fn from(vec: Vec<T>) -> Self {
        Self(vec)
    }
}

impl<T> From<Parallel<T>> for Vec<T> {
    #[inline]
    fn from(parallel: Parallel<T>) -> Self {
        parallel.0
    }
}

impl<T> FromIterator<T> for Parallel<T> {
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self(iter.into_iter().collect())
    }
}

impl<T> IntoIterator for Parallel<T> {
    type Item = T;
    type IntoIter = vec::IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'p, T> IntoIterator for &'p Parallel<T> {
    type Item = &'p T;
    type IntoIter = slice::Iter<'p, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'p, T> IntoIterator for &'p mut Parallel<T> {
    type Item = &'p mut T;
    type IntoIter = slice::IterMut<'p, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<T> ChallengeType for Parallel<T>
where
    T: ChallengeType,
{
    type Challenge = Parallel<T::Challenge>;
}

impl<T> ContributionType for Parallel<T>
where
    T: ContributionType,
{
    type Contribution = Parallel<T::Contribution>;
}

impl<T> ProofType for Parallel<T>
where
    T: ProofType,
{
    type Proof = Parallel<T::Proof>;
}

impl<T> StateType for Parallel<T>
where
    T: StateType,
{
    type State = Parallel<T::State>;
}

impl<C> Contribute for Parallel<C>
where
    C: Contribute,
{
    #[inline]
    fn contribute(
        &self,
        state: &mut Self::State,
        challenge: &Self::Challenge,
        contribution: &Self::Contribution,
    ) -> Self::Proof {
        assert_all_eq_len!(
            [self, state, challenge, contribution],
            "Length mismatch in parallel `Contribute::contribute`."
        );
        self.0
            .iter()
            .zip(state)
            .zip(challenge)
            .zip(contribution)
            .map(|(((this, state), challenge), contribution)| {
                this.contribute(state, challenge, contribution)
            })
            .collect()
    }
}

impl<V> Verify for Parallel<V>
where
    V: Verify,
{
    type Error = V::Error;

    #[inline]
    fn challenge(
        &self,
        challenge: &Self::Challenge,
        last: &Self::State,
        next: &Self::State,
        proof: &Self::Proof,
    ) -> Self::Challenge {
        assert_all_eq_len!(
            [self, challenge, last, next, proof],
            "Length mismatch in parallel `Verify::challlenge`."
        );
        self.0
            .iter()
            .zip(challenge)
            .zip(last)
            .zip(next)
            .zip(proof)
            .map(|((((this, challenge), last), next), proof)| {
                this.challenge(challenge, last, next, proof)
            })
            .collect()
    }

    #[inline]
    fn verify_transform(
        &self,
        challenge: &Self::Challenge,
        last: Self::State,
        next: Self::State,
        proof: Self::Proof,
    ) -> Result<Self::State, Self::Error> {
        assert_all_eq_len!(
            [self, challenge, last, next, proof],
            "Length mismatch in parallel `Verify::verify_transform`."
        );
        self.0
            .iter()
            .zip(challenge)
            .zip(last)
            .zip(next)
            .zip(proof)
            .map(|((((this, challenge), last), next), proof)| {
                this.verify_transform(challenge, last, next, proof)
            })
            .collect()
    }
}

/// Parallel Round Alias
pub type ParallelRound<T> = Round<Parallel<T>>;

impl<T> ParallelRound<T>
where
    T: ChallengeType + StateType,
{
    /// Returns `self` if it has the correct shape expected for a [`Round`] over a [`Parallel`]
    /// ceremony, i.e. that `self.state` has the same length as `self.challenge`.
    #[inline]
    pub fn with_valid_shape(self) -> Option<Self> {
        (self.state.len() == self.challenge.len()).then_some(self)
    }
}
