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

//! Testing and Simulation Framework

use crate::{
    asset::Asset,
    transfer::{canonical::Transaction, Configuration, PublicKey, ReceivingKey},
    wallet::{self, ledger, signer, Wallet},
};
use alloc::rc::Rc;
use async_std::sync::RwLock;
use core::{hash::Hash, marker::PhantomData};
use manta_crypto::rand::{CryptoRng, RngCore};
use manta_util::future::LocalBoxFuture;
use std::collections::HashSet;

/// Actor Simulation
pub mod sim {
    use alloc::vec::Vec;
    use core::{fmt::Debug, hash::Hash};
    use futures::stream::{self, select_all::SelectAll, Stream};
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
        /// This method should return `None` when the actor is done being simulated for this round
        /// of the simulation.
        fn step<'s, R>(
            &'s self,
            actor: &'s mut Self::Actor,
            rng: &'s mut R,
        ) -> LocalBoxFuture<'s, Option<Self::Event>>
        where
            R: CryptoRng + RngCore + ?Sized;
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
            simulator: &'s S,
            actor: &'s mut S::Actor,
            mut rng: R,
        ) -> impl 's + Stream<Item = S::Event>
        where
            R: 's + CryptoRng + RngCore,
        {
            stream::poll_fn(move |ctx| simulator.step(actor, &mut rng).as_mut().poll(ctx))
        }

        /// Runs the simulator using `rng`, returning a stream of future events.
        #[inline]
        pub async fn run<'s, R, F>(&'s mut self, mut rng: F) -> impl 's + Stream<Item = S::Event>
        where
            F: FnMut() -> R,
            R: 's + CryptoRng + RngCore,
        {
            let mut streams = SelectAll::new();
            for actor in &mut self.actors {
                streams.push(Self::build_actor_stream(&self.simulation, actor, rng()));
            }
            streams
        }
    }
}

/// Simulation Action Space
pub enum Action<C>
where
    C: Configuration,
{
    /// Public Deposit Action
    PublicDeposit(Asset),

    /// Public Withdraw Action
    PublicWithdraw(Asset),

    /// Post Transaction
    Post(Transaction<C>),

    /// Generate Public Key
    GeneratePublicKey,
}

/// Public Key Database
pub type PublicKeyDatabase<C> = HashSet<ReceivingKey<C>>;

/// Shared Public Key Database
pub type SharedPublicKeyDatabase<C> = Rc<RwLock<PublicKeyDatabase<C>>>;

///
pub struct Simulation<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
{
    ///
    public_keys: SharedPublicKeyDatabase<C>,

    ///
    __: PhantomData<(L, S)>,
}

impl<C, L, S> sim::Simulation for Simulation<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
    PublicKey<C>: Eq + Hash,
{
    type Actor = Wallet<C, L, S>;
    type Event = Result<(), wallet::Error<C, L, S>>;

    #[inline]
    fn step<'s, R>(
        &'s self,
        actor: &'s mut Self::Actor,
        rng: &'s mut R,
    ) -> LocalBoxFuture<'s, Option<Self::Event>>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = rng;
        Box::pin(async move {
            // TODO:
            Some(match actor.receiving_key().await {
                Ok(key) => {
                    self.public_keys.write().await.insert(key);
                    Ok(())
                }
                Err(err) => Err(wallet::Error::SignerError(err)),
            })
        })
    }
}
