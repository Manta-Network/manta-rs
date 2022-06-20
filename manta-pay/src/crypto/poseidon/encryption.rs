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
use core::{fmt::Debug, hash::Hash, iter, mem, slice};
use manta_crypto::{
    constraint::{Bool, Has},
    permutation::{duplex, PseudorandomPermutation},
    rand::{Rand, RngCore, Sample},
};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    vec::VecExt,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/* TODO:

///
pub struct Encryption<S, COM = ()>
where
    S: Specification<COM>,
{
    ///
    pub initial_state: State<S, COM>,
}

impl<S, COM> duplex::Configuration<Permutation<S, COM>, COM> for Encryption<S, COM>
where
    S: Specification<COM>,
    COM: Has<bool>,
{
    type Key = ();
    type Header = ();
    type SetupBlock = ();
    type PlaintextBlock = ();
    type CiphertextBlock = ();
    type Tag = ();
    type Verification = Bool<COM>;

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

    #[inline]
    fn verify(
        &self,
        encryption_tag: &Self::Tag,
        decryption_tag: &Self::Tag,
        compiler: &mut COM,
    ) -> Self::Verification {
        todo!()
    }
}

*/
