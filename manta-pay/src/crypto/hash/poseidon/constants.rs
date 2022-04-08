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

use core::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use crate::crypto::hash::poseidon::matrix::{Matrix, MdsMatrices, SparseMatrix};

/// TODO doc
pub trait ParamField:
    Clone
    + Copy
    + PartialEq
    + Eq
    + Debug
    + Add<Output=Self>
    + for<'a> AddAssign<&'a Self>
    + Mul<Output=Self>
    + for<'a> MulAssign<&'a Self>
    + Sub<Output=Self>
    + for<'a> SubAssign<&'a Self>
    + From<u64>
{
    /// TODO doc
    fn zero() -> Self;
    /// TODO doc
    fn one() -> Self;
    /// TODO doc
    fn inverse(&self) -> Option<Self>;
}

#[derive(Clone, Debug, PartialEq, Default)]
/// TODO doc
pub struct PoseidonConstants<F: ParamField> {
    /// TODO doc
    pub mds_matrices: MdsMatrices<F>,
    /// TODO doc
    pub round_constants: Vec<F>,
    /// TODO doc
    pub compressed_round_constants: Vec<F>,
    /// TODO doc
    pub pre_sparse_matrix: Matrix<F>,
    /// TODO doc
    pub sparse_matrixes: Vec<SparseMatrix<F>>,
    /// TODO doc
    pub domain_tag: F,
    /// TODO doc
    pub full_rounds: usize,
    /// TODO doc
    pub half_full_rounds: usize,
    /// TODO doc
    pub partial_rounds: usize,
}
