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

//! Structures over Booleans
//!
//! For many of the standard Rust operations we need access to some simulation of the primitive
//! types. In this module, we define the access interfaces needed to simulate the [`bool`] type with
//! [`Bool`].

use crate::eclair::Has;

/// Boolean Type Inside of the Compiler
pub type Bool<COM = ()> = <COM as Has<bool>>::Type;

/// Conditional Selection
pub trait ConditionalSelect<COM>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Selects the result of `true_value` when `bit == true` and the result of `false_value` when
    /// `bit == false`.
    fn select_from<T, F>(
        bit: &Bool<COM>,
        true_value: T,
        false_value: F,
        compiler: &mut COM,
    ) -> Self
    where
        T: FnOnce() -> Self,
        F: FnOnce() -> Self;

    /// Selects `true_value` when `bit == true` and `false_value` when `bit == false`.
    #[inline]
    fn select(bit: &Bool<COM>, true_value: Self, false_value: Self, compiler: &mut COM) -> Self {
        Self::select_from(bit, || true_value, || false_value, compiler)
    }
}

/* FIXME: We cannot implement this yet.
impl<V> ConditionalSelect for V {
    #[inline]
    fn select_from<T, F>(bit: &bool, true_value: T, false_value: F, _: &mut ()) -> Self
    where
        T: FnOnce() -> Self,
        F: FnOnce() -> Self,
    {
        if *bit {
            true_value()
        } else {
            false_value()
        }
    }
}
*/

/// Conditional Swap
pub trait ConditionalSwap<COM>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Swaps `lhs` and `rhs` whenever `bit == true` and keeps them in the same order when `bit ==
    /// false`.
    fn swap(bit: &Bool<COM>, lhs: &Self, rhs: &Self, compiler: &mut COM) -> (Self, Self);
}

/* FIXME: We cannot implement this yet.
impl<V> ConditionalSwap for V {
    #[inline]
    fn swap(bit: &bool, lhs: Self, rhs: Self, _: &mut ()) -> (Self, Self) {
        if *bit {
            (rhs, lhs)
        } else {
            (lhs, rhs)
        }
    }
}
*/
