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
use serde::{Deserialize, Serialize};
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

/// Array of u8 with fixed size `N`
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct U8Array<const N: usize>(#[serde(with = "serde_arrays")] pub [u8; N]);

impl<const N: usize> CanonicalSerialize for U8Array<N> {
    #[inline]
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        for num in self.0 {
            CanonicalSerialize::serialize(&num, &mut writer)
                .expect("Serializing u8 should succeed.");
        }
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.0[0].serialized_size() * self.0.len()
    }
}

impl<const N: usize> CanonicalDeserialize for U8Array<N> {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut res = Vec::with_capacity(N);
        for _ in 0..N {
            res.push(
                CanonicalDeserialize::deserialize(&mut reader)
                    .expect("Deserializing u8 should succeed."),
            );
        }
        Ok(Self(
            res.try_into()
                .expect(&format!("Should converting into [u8; {}].", N)),
        ))
    }
}

impl<const N: usize> From<U8Array<N>> for [u8; N] {
    fn from(f: U8Array<N>) -> Self {
        f.0
    }
}

impl<const N: usize> From<[u8; N]> for U8Array<N> {
    fn from(f: [u8; N]) -> Self {
        U8Array(f)
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

    fn serialized_size(&self) -> usize {
        core::mem::size_of::<bool>()
    }
}

impl CanonicalDeserialize for UserPriority {
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
