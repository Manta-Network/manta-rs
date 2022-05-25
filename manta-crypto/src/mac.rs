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

//! Commitment Schemes

use crate::{constraint::Native, hash::BinaryHashFunction, key::KeyDerivationFunction};
use core::marker::PhantomData;

/// Message Authentication Code
pub trait MessageAuthenticationCode<COM = ()> {
    /// Key Type
    type Key: ?Sized;

    /// Message Type
    type Message: ?Sized;

    /// Digest Type
    type Digest;

    /// Computes the message authentication code against `key` and `message` with `compiler`.
    fn hash_with(
        &self,
        key: &Self::Key,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Digest;

    /// Computes the message authentication code against `key` and `message`.
    #[inline]
    fn hash(&self, key: &Self::Key, message: &Self::Message) -> Self::Digest
    where
        COM: Native,
    {
        self.hash_with(key, message, &mut COM::compiler())
    }
}

/// Hash-Based MAC
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HashBased<IK, IH, OK, OH, COM = ()>
where
    IK: KeyDerivationFunction<COM>,
    IK::Key: Sized,
    IH: BinaryHashFunction<COM, Left = IK::Output>,
    OK: KeyDerivationFunction<COM, Key = IK::Key>,
    OH: BinaryHashFunction<COM, Left = OK::Output, Right = IH::Output>,
{
    /// Inner Key Derivation Function
    pub inner_kdf: IK,

    /// Inner Hash Function
    pub inner_hash: IH,

    /// Outer Key Derivation Function
    pub outer_kdf: OK,

    /// Outer Hash Function
    pub outer_hash: OH,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}

impl<IK, IH, OK, OH, COM> HashBased<IK, IH, OK, OH, COM>
where
    IK: KeyDerivationFunction<COM>,
    IK::Key: Sized,
    IH: BinaryHashFunction<COM, Left = IK::Output>,
    OK: KeyDerivationFunction<COM, Key = IK::Key>,
    OH: BinaryHashFunction<COM, Left = OK::Output, Right = IH::Output>,
{
    /// Builds a new [`HashBased`] message authentication code scheme from `inner_kdf`,
    /// `inner_hash`, `outer_kdf`, `outer_hash`.
    #[inline]
    pub fn new(inner_kdf: IK, inner_hash: IH, outer_kdf: OK, outer_hash: OH) -> Self {
        Self {
            inner_kdf,
            inner_hash,
            outer_kdf,
            outer_hash,
            __: PhantomData,
        }
    }
}

impl<IK, IH, OK, OH, COM> MessageAuthenticationCode<COM> for HashBased<IK, IH, OK, OH, COM>
where
    IK: KeyDerivationFunction<COM>,
    IK::Key: Sized,
    IH: BinaryHashFunction<COM, Left = IK::Output>,
    OK: KeyDerivationFunction<COM, Key = IK::Key>,
    OH: BinaryHashFunction<COM, Left = OK::Output, Right = IH::Output>,
{
    type Key = IK::Key;
    type Message = IH::Right;
    type Digest = OH::Output;

    #[inline]
    fn hash_with(
        &self,
        key: &Self::Key,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Digest {
        self.outer_hash.hash_with(
            &self.outer_kdf.derive_with(key, compiler),
            &self.inner_hash.hash_with(
                &self.inner_kdf.derive_with(key, compiler),
                message,
                compiler,
            ),
            compiler,
        )
    }
}
