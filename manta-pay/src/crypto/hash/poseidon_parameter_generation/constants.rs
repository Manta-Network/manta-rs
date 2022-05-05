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

//! Generate constants for optimized poseidon hash

use super::round_numbers::calc_round_numbers;
use super::round_constants::generate_round_constants;
use super::preprocessing::compress_round_constants;
use super::matrix::Matrix;
use super::mds::{factor_to_sparse_matrixes, MdsMatrices, SparseMatrix};
use crate::crypto::hash::poseidon::Specification;
use core::fmt::Debug;
use alloc::vec::Vec;

// TODO: shall we put constant generation code to compile time?

#[derive(Clone)]
/// Poseidon Constants struct for optimized poseidon
pub struct PoseidonConstants<S, COM>
where 
S: Specification<COM> + Clone,
S::ParameterField: Clone,
{
    /// mds matrix data
    pub mds_matrices: MdsMatrices<S, COM>,
    /// a vector of round constants
    pub round_constants: Vec<S::ParameterField>,
    /// The compressed round constants used in optimized poseidon hash.
    pub compressed_round_constants: Vec<S::ParameterField>,
    /// pre sparse matrix used in optimized poseidon hash
    pub pre_sparse_matrix: Matrix<S, COM>,
    /// Sparse matrix used in optimized poseidon hash
    pub sparse_matrixes: Vec<SparseMatrix<S, COM>>,
    /// domain tag for domain separation
    pub domain_tag: S::ParameterField,
    /// number of full rounds. Note: full_rounds % 2 == 0
    pub full_rounds: usize,
    /// number of half full rounds. In particular, half_full_rounds = full_rounds/2
    pub half_full_rounds: usize,
    /// number of partial rounds
    pub partial_rounds: usize,
}

impl<S, COM> PoseidonConstants<S, COM> 
where 
S: Specification<COM> + Clone,
S::ParameterField: Clone + Debug + Copy + Eq,
{
    /// Generate the default poseidon hash parameters 
    pub fn default<const WIDTH: usize>() -> Self{
        let arity = WIDTH - 1;

        let (num_full_rounds, num_partial_rounds) = calc_round_numbers(WIDTH, true);

        debug_assert_eq!(num_full_rounds % 2, 0);
        let num_half_full_rounds = num_full_rounds / 2;
        let (round_constants, _) = generate_round_constants::<S, COM>(
            S::MODULUS_BITS as u64,
            WIDTH.try_into().expect("WIDTH is too large"),
            num_full_rounds
                .try_into()
                .expect("num_full_rounds is too large"),
            num_partial_rounds
                .try_into()
                .expect("num_partial_rounds is too large"),
        );
        let domain_tag = S::from_u64_to_param(((1 << arity) - 1) as u64);

        let mds_matrices = MdsMatrices::<S, COM>::new(WIDTH);

        let compressed_round_constants = compress_round_constants(
            WIDTH,
            num_full_rounds,
            num_partial_rounds,
            &round_constants,
            &mds_matrices,
        );

        let (pre_sparse_matrix, sparse_matrixes) =
            factor_to_sparse_matrixes(mds_matrices.m.clone(), num_partial_rounds);

        assert!(
            WIDTH * (num_full_rounds + num_partial_rounds) <= round_constants.len(),
            "Not enough round constants"
        );

        PoseidonConstants {
            mds_matrices,
            round_constants,
            domain_tag,
            full_rounds: num_full_rounds,
            half_full_rounds: num_half_full_rounds,
            partial_rounds: num_partial_rounds,
            compressed_round_constants,
            pre_sparse_matrix,
            sparse_matrixes,
        }
    }
}