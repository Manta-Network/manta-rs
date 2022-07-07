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

//! Poseidon Encryption Implementation

use crate::crypto::poseidon::{Permutation, Specification, State};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, hash::Hash};
use manta_crypto::permutation::{
    duplex::{self, Setup, Types, Verify},
    sponge::{Read, Write},
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Encryption Duplexer
pub type Duplexer<S, COM> = duplex::Duplexer<Permutation<S, COM>, Encryption<S, COM>, COM>;

/// Block Element
pub trait BlockElement<COM = ()> {
    /// Adds `self` to `rhs`.
    fn add(&self, rhs: &Self, compiler: &mut COM) -> Self;

    /// Subtracts `rhs` from `self`.
    fn sub(&self, rhs: &Self, compiler: &mut COM) -> Self;
}

/// Setup Block
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "S::Field: Deserialize<'de>",
            serialize = "S::Field: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Field: Clone"),
    Debug(bound = "S::Field: Debug"),
    Eq(bound = "S::Field: Eq"),
    Hash(bound = "S::Field: Hash"),
    PartialEq(bound = "S::Field: PartialEq")
)]
pub struct SetupBlock<S, COM = ()>(Box<[S::Field]>)
where
    S: Specification<COM>;

impl<S, COM> Write<Permutation<S, COM>, COM> for SetupBlock<S, COM>
where
    S: Specification<COM>,
    S::Field: BlockElement<COM>,
{
    type Output = ();

    #[inline]
    fn write(&self, state: &mut State<S, COM>, compiler: &mut COM) -> Self::Output {
        for (i, elem) in state.iter_mut().skip(1).enumerate() {
            *elem = elem.add(&self.0[i], compiler);
        }
    }
}

/// Plaintext Block
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "S::Field: Deserialize<'de>",
            serialize = "S::Field: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Field: Clone"),
    Debug(bound = "S::Field: Debug"),
    Eq(bound = "S::Field: Eq"),
    Hash(bound = "S::Field: Hash"),
    PartialEq(bound = "S::Field: PartialEq")
)]
pub struct PlaintextBlock<S, COM = ()>(Box<[S::Field]>)
where
    S: Specification<COM>;

impl<S, COM> Write<Permutation<S, COM>, COM> for PlaintextBlock<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone + BlockElement<COM>,
{
    type Output = CiphertextBlock<S, COM>;

    #[inline]
    fn write(&self, state: &mut State<S, COM>, compiler: &mut COM) -> Self::Output {
        for (i, elem) in state.iter_mut().skip(1).enumerate() {
            *elem = elem.add(&self.0[i], compiler);
        }
        CiphertextBlock(state.iter().skip(1).cloned().collect())
    }
}

/// Ciphertext Block
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "S::Field: Deserialize<'de>",
            serialize = "S::Field: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Field: Clone"),
    Debug(bound = "S::Field: Debug"),
    Eq(bound = "S::Field: Eq"),
    Hash(bound = "S::Field: Hash"),
    PartialEq(bound = "S::Field: PartialEq")
)]
pub struct CiphertextBlock<S, COM = ()>(Box<[S::Field]>)
where
    S: Specification<COM>;

impl<S, COM> Write<Permutation<S, COM>, COM> for CiphertextBlock<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone + BlockElement<COM>,
{
    type Output = PlaintextBlock<S, COM>;

    #[inline]
    fn write(&self, state: &mut State<S, COM>, compiler: &mut COM) -> Self::Output {
        for (i, elem) in state.iter_mut().skip(1).enumerate() {
            *elem = self.0[i].sub(elem, compiler);
        }
        PlaintextBlock(state.iter().skip(1).cloned().collect())
    }
}

/// Authentication Tag
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "S::Field: Deserialize<'de>",
            serialize = "S::Field: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Field: Clone"),
    Debug(bound = "S::Field: Debug"),
    Eq(bound = "S::Field: Eq"),
    Hash(bound = "S::Field: Hash"),
    PartialEq(bound = "S::Field: PartialEq")
)]
pub struct Tag<S, COM = ()>(S::Field)
where
    S: Specification<COM>;

impl<S, COM> Read<Permutation<S, COM>, COM> for Tag<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone,
{
    #[inline]
    fn read(state: &State<S, COM>, compiler: &mut COM) -> Self {
        let _ = compiler;
        Self(state.0[1].clone())
    }
}

/// Encryption Configuration
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "S::Field: Deserialize<'de>",
            serialize = "S::Field: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Field: Clone"),
    Debug(bound = "S::Field: Debug"),
    Eq(bound = "S::Field: Eq"),
    Hash(bound = "S::Field: Hash"),
    PartialEq(bound = "S::Field: PartialEq")
)]
pub struct Encryption<S, COM = ()>
where
    S: Specification<COM>,
{
    /// Initial State
    pub initial_state: State<S, COM>,
}

impl<S, COM> Types<Permutation<S, COM>, COM> for Encryption<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone + BlockElement<COM>,
{
    type Key = Vec<S::Field>;
    type Header = Vec<S::Field>;
    type SetupBlock = SetupBlock<S, COM>;
    type PlaintextBlock = PlaintextBlock<S, COM>;
    type CiphertextBlock = CiphertextBlock<S, COM>;
    type Tag = Tag<S, COM>;
}

impl<S, COM> Setup<Permutation<S, COM>, COM> for Encryption<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone + Default + BlockElement<COM>,
{
    #[inline]
    fn initialize(&self, compiler: &mut COM) -> State<S, COM> {
        let _ = compiler;
        self.initial_state.clone()
    }

    #[inline]
    fn setup(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        compiler: &mut COM,
    ) -> Vec<Self::SetupBlock> {
        let _ = compiler;
        let mut blocks = self.padding(
            key.as_slice(),
            S::WIDTH,
            key.len() / (S::WIDTH - 1),
            compiler,
        );
        blocks.extend(self.padding(
            header.as_slice(),
            S::WIDTH,
            header.len() / (S::WIDTH - 1),
            compiler,
        ));
        blocks
            .into_iter()
            .map(|b| SetupBlock(b.into_boxed_slice()))
            .collect()
    }
}

impl<S> Verify<Permutation<S>> for Encryption<S>
where
    S: Specification,
    S::Field: Clone + PartialEq + BlockElement,
{
    type Verification = bool;

    #[inline]
    fn verify(
        &self,
        encryption_tag: &Self::Tag,
        decryption_tag: &Self::Tag,
        _: &mut (),
    ) -> Self::Verification {
        encryption_tag == decryption_tag
    }
}
