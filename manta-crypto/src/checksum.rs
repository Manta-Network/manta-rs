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

//! Checksums

// TODO: move this out of this crate, this is for `pallet-manta-pay` when we check local parameters
// against stored ones. maybe this can go in `manta-pay`?

/// Checksum Equality
pub trait ChecksumEq<SumAlg, Rhs: ?Sized = Self> {
    /// Returns `true` if `self` and `other` have the same checksum.
    #[must_use]
    fn checksum_eq(&self, other: &Rhs) -> bool;

    /// Returns `true` if `self` and `other` have different checksums.
    #[inline]
    #[must_use]
    fn checksum_ne(&self, other: &Rhs) -> bool {
        !self.checksum_eq(other)
    }
}
