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

//! Poseidon Permutation Implementation

use crate::crypto::poseidon::{Permutation, Specification, State};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, hash::Hash, iter, marker::PhantomData, mem, slice};
use manta_crypto::{
    permutation::{
        duplex::{Setup, Types, Verify},
        sponge::{Read, Write},
        PseudorandomPermutation,
    },
    rand::{Rand, RngCore, Sample},
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

///
pub struct SetupBlock<S, COM = ()>(PhantomData<(S, COM)>);

impl<S, COM> Write<Permutation<S, COM>, COM> for SetupBlock<S, COM>
where
    S: Specification<COM>,
{
    type Output = ();

    #[inline]
    fn write(&self, state: &mut State<S, COM>, compiler: &mut COM) -> Self::Output {
        todo!()
    }
}

///
pub struct PlaintextBlock<S, COM = ()>(PhantomData<(S, COM)>);

impl<S, COM> Write<Permutation<S, COM>, COM> for PlaintextBlock<S, COM>
where
    S: Specification<COM>,
{
    type Output = CiphertextBlock<S, COM>;

    #[inline]
    fn write(&self, state: &mut State<S, COM>, compiler: &mut COM) -> Self::Output {
        todo!()
    }
}

///
pub struct CiphertextBlock<S, COM = ()>(PhantomData<(S, COM)>);

impl<S, COM> Write<Permutation<S, COM>, COM> for CiphertextBlock<S, COM>
where
    S: Specification<COM>,
{
    type Output = PlaintextBlock<S, COM>;

    #[inline]
    fn write(&self, state: &mut State<S, COM>, compiler: &mut COM) -> Self::Output {
        todo!()
    }
}

/// Tag
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
        Self(state.0[0].clone())
    }
}

///
pub struct Encryption<S, COM = ()>
where
    S: Specification<COM>,
{
    ///
    pub initial_state: State<S, COM>,
}

impl<S, COM> Types<Permutation<S, COM>, COM> for Encryption<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone,
{
    type Key = ();
    type Header = ();
    type SetupBlock = SetupBlock<S, COM>;
    type PlaintextBlock = PlaintextBlock<S, COM>;
    type CiphertextBlock = CiphertextBlock<S, COM>;
    type Tag = Tag<S, COM>;
}

impl<S, COM> Setup<Permutation<S, COM>, COM> for Encryption<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone,
{
    #[inline]
    fn initialize(&self, compiler: &mut COM) -> State<S, COM> {
        self.initial_state.clone()
    }

    #[inline]
    fn setup(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        compiler: &mut COM,
    ) -> Vec<Self::SetupBlock> {
        todo!()
    }
}

impl<S> Verify<Permutation<S>> for Encryption<S>
where
    S: Specification,
    S::Field: Clone + PartialEq,
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
