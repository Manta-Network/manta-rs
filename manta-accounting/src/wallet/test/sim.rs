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

//! Actor Simulation Framework

use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, hash::Hash};
use futures::stream::{self, select_all::SelectAll, Stream, StreamExt};
use manta_crypto::rand::{CryptoRng, RngCore};
use manta_util::future::LocalBoxFuture;

/// Abstract Simulation
pub trait Simulation {
    /// Actor Type
    type Actor;

    /// Event Type
    type Event;

    /// Runs the given `actor` returning a future event.
    ///
    /// This method should return `None` when the actor is done being simulated for this round of
    /// the simulation.
    fn step<'s, R>(
        &'s self,
        actor: &'s mut Self::Actor,
        rng: &'s mut R,
    ) -> LocalBoxFuture<'s, Option<Self::Event>>
    where
        R: CryptoRng + RngCore + ?Sized;
}

impl<S> Simulation for &S
where
    S: Simulation,
{
    type Actor = S::Actor;
    type Event = S::Event;

    #[inline]
    fn step<'s, R>(
        &'s self,
        actor: &'s mut Self::Actor,
        rng: &'s mut R,
    ) -> LocalBoxFuture<'s, Option<Self::Event>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        (*self).step(actor, rng)
    }
}

/// Simulation Event
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Event: Clone"),
    Copy(bound = "S::Event: Copy"),
    Debug(bound = "S::Event: Debug"),
    Default(bound = "S::Event: Default"),
    Eq(bound = "S::Event: Eq"),
    Hash(bound = "S::Event: Hash"),
    PartialEq(bound = "S::Event: PartialEq")
)]
pub struct Event<S>
where
    S: Simulation,
{
    /// Actor Index
    pub actor: usize,

    /// Step Index of the Actor
    pub step: usize,

    /// Step Event
    pub event: S::Event,
}

impl<S> Event<S>
where
    S: Simulation,
{
    /// Builds a new [`Event`] from `actor`, `step`, and `event`.
    #[inline]
    pub fn new(actor: usize, step: usize, event: S::Event) -> Self {
        Self { actor, step, event }
    }
}

/// Simulator
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S: Clone, S::Actor: Clone"),
    Debug(bound = "S: Debug, S::Actor: Debug"),
    Default(bound = "S: Default"),
    Eq(bound = "S: Eq, S::Actor: Eq"),
    Hash(bound = "S: Hash, S::Actor: Hash"),
    PartialEq(bound = "S: PartialEq, S::Actor: PartialEq")
)]
pub struct Simulator<S>
where
    S: Simulation,
{
    /// Simulation
    pub simulation: S,

    /// Actors
    pub actors: Vec<S::Actor>,
}

impl<S> Simulator<S>
where
    S: Simulation,
{
    /// Builds a new [`Simulator`] from `simulation` and `actors`.
    #[inline]
    pub fn new(simulation: S, actors: Vec<S::Actor>) -> Self {
        Self { simulation, actors }
    }

    /// Builds a stream of future events for a particular `actor`.
    #[inline]
    fn build_actor_stream<'s, R>(
        simulation: &'s S,
        index: usize,
        actor: &'s mut S::Actor,
        rng: R,
    ) -> impl 's + Stream<Item = Event<S>>
    where
        R: 's + CryptoRng + RngCore,
    {
        stream::unfold((actor, rng), move |mut state| {
            Box::pin(async move {
                simulation
                    .step(state.0, &mut state.1)
                    .await
                    .map(move |event| (event, state))
            })
        })
        .enumerate()
        .map(move |(step, event)| Event::new(index, step, event))
    }

    /// Runs the simulator using `rng`, returning a stream of future events.
    #[inline]
    pub fn run<'s, R, F>(&'s mut self, mut rng: F) -> impl 's + Stream<Item = Event<S>>
    where
        R: 's + CryptoRng + RngCore,
        F: FnMut() -> R,
    {
        let mut streams = SelectAll::new();
        for (i, actor) in self.actors.iter_mut().enumerate() {
            streams.push(Self::build_actor_stream(&self.simulation, i, actor, rng()));
        }
        streams
    }
}

impl<S> AsRef<S> for Simulator<S>
where
    S: Simulation,
{
    #[inline]
    fn as_ref(&self) -> &S {
        &self.simulation
    }
}

/// Action Simulation
pub trait ActionSimulation {
    /// Actor Type
    type Actor;

    /// Action Type
    type Action;

    /// Event Type
    type Event;

    /// Samples an action for the `actor` to take using `rng`.
    ///
    /// This method should return `None` when the actor is done being simulated for this round of
    /// the simulation.
    fn sample<'s, R>(
        &'s self,
        actor: &'s mut Self::Actor,
        rng: &'s mut R,
    ) -> LocalBoxFuture<'s, Option<Self::Action>>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Executes the given `action` on `actor` returning a future event.
    fn act<'s>(
        &'s self,
        actor: &'s mut Self::Actor,
        action: Self::Action,
    ) -> LocalBoxFuture<'s, Self::Event>;
}

/// Action Simulation Wrapper
///
/// This `struct` wraps an implementation of [`ActionSimulation`] and implements [`Simulation`] for
/// use in some [`Simulator`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActionSim<S>(pub S)
where
    S: ActionSimulation;

impl<S> AsRef<S> for ActionSim<S>
where
    S: ActionSimulation,
{
    #[inline]
    fn as_ref(&self) -> &S {
        &self.0
    }
}

impl<S> Simulation for ActionSim<S>
where
    S: ActionSimulation,
{
    type Actor = S::Actor;
    type Event = S::Event;

    #[inline]
    fn step<'s, R>(
        &'s self,
        actor: &'s mut Self::Actor,
        rng: &'s mut R,
    ) -> LocalBoxFuture<'s, Option<Self::Event>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Box::pin(async {
            match self.0.sample(actor, rng).await {
                Some(action) => Some(self.0.act(actor, action).await),
                _ => None,
            }
        })
    }
}
