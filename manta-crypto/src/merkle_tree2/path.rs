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

//! Merkle Tree Paths

use crate::{
    constraint::{Allocator, Constant, Variable},
    merkle_tree2::{GlobalSelector, Hash, SelectorIter},
};
use manta_util::BoxArray;

/// Merkle Tree Path
pub struct Path<H, const HEIGHT: usize, S, COM = ()>
where
    H: Hash<COM>,
    S: GlobalSelector<H, HEIGHT, COM>,
    for<'s> &'s S: SelectorIter<'s, H, COM>,
{
    /// Selector Iterator
    selector: S,

    /// Inner Path
    path: BoxArray<H::Output, HEIGHT>,
}

impl<H, const HEIGHT: usize, S, COM> Path<H, HEIGHT, S, COM>
where
    H: Hash<COM>,
    S: GlobalSelector<H, HEIGHT, COM>,
    for<'s> &'s S: SelectorIter<'s, H, COM>,
{
    /// Computes the root from `self` on the given `base` using `hash`.
    #[inline]
    pub fn root(&self, hash: &H, base: H::Output, compiler: &mut COM) -> H::Output {
        self.path
            .iter()
            .zip(&self.selector)
            .fold(base, |acc, (d, s)| hash.join_with(s, &acc, d, compiler))
    }
}

impl<M, H, const HEIGHT: usize, S, COM> Variable<M, COM> for Path<H, HEIGHT, S, COM>
where
    H: Hash<COM> + Constant<COM>,
    H::Type: Hash,
    S: GlobalSelector<H, HEIGHT, COM> + Variable<M, COM>,
    S::Type: GlobalSelector<H::Type, HEIGHT>,
    for<'s> &'s S: SelectorIter<'s, H, COM>,
    for<'s> &'s S::Type: SelectorIter<'s, H::Type>,
    H::Output: Variable<M, COM, Type = <H::Type as Hash>::Output>,
{
    type Type = Path<H::Type, HEIGHT, S::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self {
            selector: compiler.allocate_unknown(),
            path: (0..HEIGHT).map(|_| compiler.allocate_unknown()).collect(),
        }
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self {
            selector: compiler.allocate_known(&this.selector),
            path: this
                .path
                .iter()
                .map(|d| compiler.allocate_known(d))
                .collect(),
        }
    }
}
