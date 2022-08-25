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

//! Hash Functions

/// Hash Function
pub trait HashFunction<COM = ()> {
    /// Input Type
    type Input: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `input`.
    fn hash(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output;
}

impl<H, COM> HashFunction<COM> for &H
where
    H: HashFunction<COM>,
{
    type Input = H::Input;
    type Output = H::Output;

    #[inline]
    fn hash(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output {
        (*self).hash(input, compiler)
    }
}

/// Binary Hash Function
pub trait BinaryHashFunction<COM = ()> {
    /// Left Input Type
    type Left: ?Sized;

    /// Right Input Type
    type Right: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `lhs` and `rhs`.
    fn hash(&self, lhs: &Self::Left, rhs: &Self::Right, compiler: &mut COM) -> Self::Output;
}

/// Array Hash Function
pub trait ArrayHashFunction<const ARITY: usize, COM = ()> {
    /// Input Type
    type Input: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `input`.
    fn hash(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output;
}

/// Array Hashing Utilities
pub mod array {
    use super::*;
    use core::marker::PhantomData;

    #[cfg(feature = "serde")]
    use manta_util::serde::{Deserialize, Serialize};

    /// Converts `hasher` from an [`ArrayHashFunction`] into a [`HashFunction`].
    #[inline]
    pub fn as_unary<H, COM>(hasher: H) -> AsUnary<H, COM>
    where
        H: ArrayHashFunction<1, COM>,
    {
        AsUnary::new(hasher)
    }

    /// Unary Hash Function Converter
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde", deny_unknown_fields)
    )]
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct AsUnary<H, COM = ()>
    where
        H: ArrayHashFunction<1, COM>,
    {
        /// Array Hasher
        hasher: H,

        /// Type Parameter Marker
        __: PhantomData<COM>,
    }

    impl<H, COM> AsUnary<H, COM>
    where
        H: ArrayHashFunction<1, COM>,
    {
        /// Builds a new [`HashFunction`] implementation out of an [`ArrayHashFunction`]
        /// implementation `hasher`.
        #[inline]
        pub fn new(hasher: H) -> Self {
            Self {
                hasher,
                __: PhantomData,
            }
        }
    }

    impl<H, COM> HashFunction<COM> for AsUnary<H, COM>
    where
        H: ArrayHashFunction<1, COM>,
    {
        type Input = H::Input;
        type Output = H::Output;

        #[inline]
        fn hash(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output {
            self.hasher.hash([input], compiler)
        }
    }
}

/// Security Assumptions
///
/// The following outlines some standard security assumptions for hash functions. These security
/// properties can be attached to general types that don't exactly conform to the hash function
/// `trait`s to describe the same cryptographic assumptions or guarantees given by the type.
pub mod security {
    /// Preimage Resistance
    ///
    /// For a hash function `H` and an output `y`, it should be infeasible to find a preimage `x`
    /// such that the following function returns `true`:
    ///
    /// ```text
    /// fn is_preimage(x: H::Input, y: H::Output) -> bool {
    ///     H(x) == y
    /// }
    /// ```
    pub trait PreimageResistance {}

    /// Second Preimage Resistance
    ///
    /// For a hash function `H` and an input `x_1`, it should be infeasible to find a another input
    /// `x_2` such that the following function returns `true`:
    ///
    /// ```text
    /// fn is_collision(x_1: H::Input, x_2: H::Input) -> bool {
    ///     (x_1 != x_2) && (H(x_1) == H(x_2))
    /// }
    /// ```
    pub trait SecondPreimageResistance {}

    /// Collision Resistance
    ///
    /// For a hash function `H` it should be infeasible to find two inputs `x_1` and `x_2` such that
    /// the following function returns `true`:
    ///
    /// ```text
    /// fn is_collision(x_1: H::Input, x_2: H::Input) -> bool {
    ///     (x_1 != x_2) && (H(x_1) == H(x_2))
    /// }
    /// ```
    ///
    /// # Strength
    ///
    /// Note this is a stronger assumption than [`SecondPreimageResistance`] since we are not
    /// requiring that the attacker find a second preimage of a given input `x_1`, they only need to
    /// find any collision for any input to break this assumption.
    pub trait CollisionResistance: SecondPreimageResistance {}
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::{
        security::{PreimageResistance, SecondPreimageResistance},
        *,
    };
    use crate::eclair::{
        bool::{AssertEq, Bool},
        cmp::PartialEq,
        ops::{BitOr, Not},
    };

    /// Preimage resistance test. Asserts that `y` is not the image of `x` under `hash`.
    #[inline]
    pub fn is_not_preimage<H, F, COM>(
        hash: H,
        x: &H::Input,
        y: &H::Output,
        assert_different: F,
        compiler: &mut COM,
    ) where
        H: HashFunction<COM> + PreimageResistance,
        F: FnOnce(&H::Output, &H::Output, &mut COM),
    {
        let image = &hash.hash(x, compiler);
        assert_different(image, y, compiler)
    }

    /// Second preimage/Collision resistance test. Asserts that different `x_1` and `x_2` don't have the same image under `hash`.
    #[inline]
    pub fn is_not_collision<H, F, COM>(hash: H, x_1: &H::Input, x_2: &H::Input, compiler: &mut COM)
    where
        H: HashFunction<COM> + SecondPreimageResistance,
        H::Input: PartialEq<H::Input, COM>,
        H::Output: PartialEq<H::Output, COM>,
        COM: AssertEq,
        Bool<COM>: BitOr<Bool<COM>, COM, Output = Bool<COM>> + Not<COM, Output = Bool<COM>>,
    {
        let bool_1 = x_1.eq(x_2, compiler);
        let y_1 = &hash.hash(x_1, compiler);
        let y_2 = &hash.hash(x_2, compiler);
        let bool_2 = y_1.ne(y_2, compiler);
        let bool = bool_1.bitor(bool_2, compiler);
        compiler.assert(&bool)
    }
}
