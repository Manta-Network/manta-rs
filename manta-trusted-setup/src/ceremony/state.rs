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

//! Internal States

use crate::ceremony::config::{CeremonyConfig, Challenge, Proof, State};
use core::fmt::Debug;
use manta_crypto::arkworks::serialize::{
    CanonicalDeserialize, CanonicalSerialize, SerializationError,
};
use manta_util::serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// MPC States
pub struct MPCState<C, const N: usize>
where
    C: CeremonyConfig,
{
    /// State
    pub state: [State<C>; N],

    /// Challenge
    pub challenge: [Challenge<C>; N],
}

impl<C, const N: usize> CanonicalSerialize for MPCState<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalSerialize,
    Challenge<C>: CanonicalSerialize,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: ark_std::io::Write,
    {
        for item in &self.state {
            item.serialize(&mut writer)
                .expect("Serializing states should succeed.");
        }
        for item in &self.challenge {
            item.serialize(&mut writer)
                .expect("Serializing challenges should succeed.");
        }
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.state.serialized_size() + self.challenge.serialized_size()
    }
}

impl<C, const N: usize> CanonicalDeserialize for MPCState<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalDeserialize + Debug,
    Challenge<C>: CanonicalDeserialize + Debug,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: ark_std::io::Read,
    {
        let mut state = Vec::with_capacity(N);
        for _ in 0..N {
            state.push(
                CanonicalDeserialize::deserialize(&mut reader)
                    .expect("Deserialize state should succeed."),
            );
        }
        let mut challenge = Vec::with_capacity(N);
        for _ in 0..N {
            challenge.push(
                CanonicalDeserialize::deserialize(&mut reader)
                    .expect("Deserialize challenge should succeed."),
            );
        }
        Ok(Self {
            state: state
                .try_into()
                .expect("MPC State should contain N elements."),
            challenge: challenge
                .try_into()
                .expect("MPC State should contain N elements."),
        })
    }
}

/// Contribute States
pub struct ContributeState<C, const N: usize>
where
    C: CeremonyConfig,
{
    /// State
    pub state: [State<C>; N],

    /// Proof
    pub proof: [Proof<C>; N],
}

impl<C, const N: usize> CanonicalSerialize for ContributeState<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalSerialize,
    Proof<C>: CanonicalSerialize,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: ark_std::io::Write,
    {
        for item in &self.state {
            item.serialize(&mut writer)
                .expect("Serializing states should succeed.");
        }
        for item in &self.proof {
            item.serialize(&mut writer)
                .expect("Serializing proofs should succeed.");
        }
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.state.serialized_size() + self.proof.serialized_size()
    }
}

impl<C, const N: usize> CanonicalDeserialize for ContributeState<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalDeserialize + Debug,
    Proof<C>: CanonicalDeserialize + Debug,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: ark_std::io::Read,
    {
        let mut state = Vec::with_capacity(N);
        for _ in 0..N {
            state.push(
                CanonicalDeserialize::deserialize(&mut reader)
                    .expect("Deserialize should succeed."),
            );
        }
        let mut proof = Vec::with_capacity(N);
        for _ in 0..N {
            proof.push(
                CanonicalDeserialize::deserialize(&mut reader)
                    .expect("Deserialize should succeed."),
            );
        }
        Ok(Self {
            state: state
                .try_into()
                .expect("Contribute State should contain N elements."),
            proof: proof
                .try_into()
                .expect("Contribute State should contain N elements."),
        })
    }
}

/// Priority
#[derive(Debug, Clone, Copy)]
pub enum UserPriority {
    /// High Priority
    High,

    /// Normal Priority
    Normal,
}

impl CanonicalSerialize for UserPriority {
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: std::io::Write,
    {
        let priority: bool = match self {
            UserPriority::High => true,
            UserPriority::Normal => false,
        };
        CanonicalSerialize::serialize(&priority, &mut writer)
            .expect("Serializing usize should succeed.");
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        core::mem::size_of::<bool>()
    }
}

impl CanonicalDeserialize for UserPriority {
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: std::io::Read,
    {
        Ok(
            match CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserializing bool should succeed.")
            {
                true => UserPriority::High,
                false => UserPriority::Normal,
            },
        )
    }
}

/// Response for State Sizes
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize, Serialize, Deserialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct ServerSize {
    /// Mint State Size
    pub mint: StateSize,

    /// Private Transfer State Size
    pub private_transfer: StateSize,

    /// Reclaim State Size
    pub reclaim: StateSize,
}

/// State Size
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize, Serialize, Deserialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct StateSize {
    /// Size of gamma_abc_g1 in verifying key
    pub gamma_abc_g1: usize,

    /// Size of a_query, b_g1_query, and b_g2_query which are equal
    pub a_b_g1_b_g2_query: usize,

    /// Size of h_query
    pub h_query: usize,

    /// Size of l_query
    pub l_query: usize,
}
