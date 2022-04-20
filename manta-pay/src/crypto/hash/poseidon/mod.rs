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

//! Poseidon Hash Function

use core::fmt::Debug;
use crate::crypto::hash::poseidon::constants::{ParamField, PoseidonConstants};
use crate::crypto::hash::poseidon::matrix::{Matrix, SparseMatrix};

/// TODO doc
pub mod constants;
/// TODO doc
pub mod matrix;
#[cfg(feature = "arkworks")]
/// TODO doc
pub mod arkworks;

/// Specification for a Poseidon hash function.
/// `WIDTH` = full rounds + partial rounds + 1
pub trait Specification<const WIDTH: usize, COM = ()>{
    /// TODO doc
    type Field: Debug + Clone;
    /// TODO doc
    type ParameterField: ParamField;

    // TODO: for now FULL_ROUNDS and PARTIAL_ROUNDS are computed at runtime.


    /// TODO doc
    fn output_hash(
        c: &mut COM,
        constants_offset: &mut usize,
        current_round: &mut usize,
        elements: &mut [Self::Field; WIDTH],
        constants: &PoseidonConstants<Self::ParameterField>,
    ) -> Self::Field {
        Self::add_round_constants(c, elements, constants, constants_offset);

        for _ in 0..constants.half_full_rounds {
            Self::full_round(
                c,
                constants,
                current_round,
                constants_offset,
                false,
                elements,
            )
        }

        for _ in 0..constants.partial_rounds {
            Self::partial_round(c, constants, current_round, constants_offset, elements);
        }

        // All but last full round
        for _ in 1..constants.half_full_rounds {
            Self::full_round(
                c,
                constants,
                current_round,
                constants_offset,
                false,
                elements,
            );
        }
        Self::full_round(
            c,
            constants,
            current_round,
            constants_offset,
            true,
            elements,
        );

        assert_eq!(
            *constants_offset,
            constants.compressed_round_constants.len(),
            "Constants consumed ({}) must equal preprocessed constants provided ({}).",
            constants_offset,
            constants.compressed_round_constants.len()
        );

        elements[1].clone()
    }

    /// TODO doc
    fn full_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        current_round: &mut usize,
        const_offset: &mut usize,
        last_round: bool,
        state: &mut [Self::Field; WIDTH],
    ) {
        let to_take = WIDTH;
        let post_round_keys = constants
            .compressed_round_constants
            .iter()
            .skip(*const_offset)
            .take(to_take);

        if !last_round {
            let needed = *const_offset + to_take;
            assert!(
                needed <= constants.compressed_round_constants.len(),
                "Not enough preprocessed round constants ({}), need {}.",
                constants.compressed_round_constants.len(),
                needed
            );
        }

        state.iter_mut().zip(post_round_keys).for_each(|(l, post)| {
            // Be explicit that no round key is added after last round of S-boxes.
            let post_key = if last_round {
                panic!(
                    "Trying to skip last full round, but there is a key here! ({:?})",
                    post
                );
            } else {
                Some(post.clone())
            };
            *l = Self::quintic_s_box(c, l.clone(), None, post_key);
        });

        if last_round {
            state
                .iter_mut()
                .for_each(|l| *l = Self::quintic_s_box(c, l.clone(), None, None))
        } else {
            *const_offset += to_take;
        }
        Self::round_product_mds(c, constants, current_round, state);
    }

    /// TODO doc
    fn partial_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        current_round: &mut usize,
        const_offset: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        let post_round_key = constants.compressed_round_constants[*const_offset].clone();

        state[0] = Self::quintic_s_box(c, state[0].clone(), None, Some(post_round_key));
        *const_offset += 1;

        Self::round_product_mds(c, constants, current_round, state);
    }

    /// TODO doc
    fn add_round_constants(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        constants: &PoseidonConstants<Self::ParameterField>,
        const_offset: &mut usize,
    ) {
        for (element, round_constant) in state.iter_mut().zip(
            constants
                .compressed_round_constants
                .iter()
                .skip(*const_offset),
        ) {
            *element = Self::add_parameter(c, element, round_constant);
        }
        *const_offset += WIDTH;
    }

    /// TODO doc
    fn round_product_mds(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        current_round: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        let full_half = constants.half_full_rounds;
        let sparse_offset = full_half - 1;
        if *current_round == sparse_offset {
            Self::product_mds_with_matrix(c, state, &constants.pre_sparse_matrix)
        } else {
            if (*current_round > sparse_offset)
                && (*current_round < full_half + constants.partial_rounds)
            {
                let index = *current_round - sparse_offset - 1;
                let sparse_matrix = &constants.sparse_matrixes[index];

                Self::product_mds_with_sparse_matrix(c, state, sparse_matrix)
            } else {
                Self::product_mds(c, constants, state)
            }
        };

        *current_round += 1;
    }

    /// TODO doc
    fn product_mds(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        state: &mut [Self::Field; WIDTH],
    ) {
        Self::product_mds_with_matrix(c, state, &constants.mds_matrices.m)
    }

    /// TODO doc
    fn linear_combination(
        c: &mut COM,
        state: &[Self::Field; WIDTH],
        coeff: impl IntoIterator<Item = Self::ParameterField>,
    ) -> Self::Field {
        state.iter().zip(coeff).fold(Self::zero(c), |acc, (x, y)| {
            let tmp = Self::mul_parameter(c, x, &y);
            Self::add(c, &tmp, &acc)
        })
    }

    /// compute state @ Mat where `state` is a row vector
    fn product_mds_with_matrix(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        matrix: &Matrix<Self::ParameterField>,
    ) {
        let mut result = Self::zeros::<WIDTH>(c);
        for (col_index, val) in result.iter_mut().enumerate() {

            *val = Self::linear_combination(c, state, matrix.column(col_index).cloned());
        }

        *state = result;
    }

    /// TODO doc
    fn product_mds_with_sparse_matrix(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        matrix: &SparseMatrix<Self::ParameterField>,
    ) {
        let mut result = Self::zeros::<WIDTH>(c);

        result[0] = Self::linear_combination(c, state, matrix.w_hat.iter().cloned());

        for (j, val) in result.iter_mut().enumerate().skip(1) {
            // for each j, result[j] = state[j] + state[0] * v_rest[j-1]

            // Except for first row/column, diagonals are one.
            *val = Self::add(c, val, &state[j]);
            //
            // First row is dense.
            let tmp = Self::mul_parameter(c, &state[0], &matrix.v_rest[j - 1]);
            *val = Self::add(c, val, &tmp);
        }
        *state = result;
    }

    /// return (x + pre_add)^5 + post_add
    fn quintic_s_box(
        c: &mut COM,
        x: Self::Field,
        pre_add: Option<Self::ParameterField>,
        post_add: Option<Self::ParameterField>,
    ) -> Self::Field {
        let mut tmp = match pre_add {
            Some(a) => Self::add_parameter(c, &x, &a),
            None => x.clone(),
        };
        tmp = Self::power_of_5(c, &tmp);
        match post_add {
            Some(a) => Self::add_parameter(c, &tmp, &a),
            None => tmp,
        }
    }

    /// TODO doc
    fn power_of_5(c: &mut COM, x: &Self::Field) -> Self::Field {
        let mut tmp = Self::mul(c, x, x); // x^2
        tmp = Self::mul(c, &tmp, &tmp); // x^4
        Self::mul(c, &tmp, x) // x^5
    }

    /// TODO doc
    fn alloc(c: &mut COM, v: Self::ParameterField) -> Self::Field;
    /// TODO doc
    fn zeros<const W: usize>(c: &mut COM) -> [Self::Field; W];
    /// TODO doc
    fn zero(c: &mut COM) -> Self::Field {
        Self::zeros::<1>(c)[0].clone()
    }
    /// TODO doc
    fn add(c: &mut COM, x: &Self::Field, y: &Self::Field) -> Self::Field;
    /// TODO doc
    fn add_parameter(c: &mut COM, a: &Self::Field, b: &Self::ParameterField) -> Self::Field;
    /// TODO doc
    fn mul(c: &mut COM, x: &Self::Field, y: &Self::Field) -> Self::Field;
    /// TODO doc
    fn mul_parameter(c: &mut COM, x: &Self::Field, y: &Self::ParameterField) -> Self::Field;

}

/// Poseidon State Vector
type State<S, COM, const WIDTH: usize> = [<S as Specification<WIDTH, COM>>::Field; WIDTH];

/// TODO doc
pub struct Hasher<S, COM, const WIDTH: usize> where S: Specification<WIDTH, COM>{
    state: State<S, COM, WIDTH>,
    constant: PoseidonConstants<S::ParameterField>
}