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

//! Basic Linear Algebra Implementation

use crate::crypto::hash::poseidon::Specification;
use alloc::{vec, vec::Vec};
use core::fmt::Debug;
use core::ops::{Index, IndexMut};

#[derive(Eq, PartialEq, Debug, Default)]
/// a struct for matrix data
pub struct Matrix<S, COM>(pub Vec<Vec<S::ParameterField>>)
where
    S: Specification<COM>;

impl<S, COM> From<Vec<Vec<S::ParameterField>>> for Matrix<S, COM>
where
    S: Specification<COM>,
{
    fn from(v: Vec<Vec<S::ParameterField>>) -> Self {
        Matrix(v)
    }
}

impl<S, COM> Matrix<S, COM>
where
    S: Specification<COM>,
    S::ParameterField: Copy,
{
    /// Return the number of rows
    pub fn num_rows(&self) -> usize {
        self.0.len()
    }

    /// Return the number of columns
    pub fn num_columns(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            let column_length = self.0[0].len();
            for row in &self.0 {
                if row.len() != column_length {
                    panic!("not a matrix");
                }
            }
            column_length
        }
    }

    /// Iterator over rows
    pub fn iter_rows(&self) -> impl Iterator<Item = &Vec<S::ParameterField>> {
        self.0.iter()
    }

    /// Iterator over a specific column
    pub fn column(&self, column: usize) -> impl Iterator<Item = &'_ S::ParameterField> {
        self.0.iter().map(move |row| &row[column])
    }

    /// Check if the matrix is square
    pub fn is_square(&self) -> bool {
        self.num_rows() == self.num_columns()
    }

    /// Return transpose of the matrix
    pub fn transpose(&self) -> Matrix<S, COM> {
        let size = self.num_rows();
        let mut new = Vec::with_capacity(size);
        for j in 0..size {
            let mut row = Vec::with_capacity(size);
            for i in 0..size {
                row.push(self.0[i][j])
            }
            new.push(row);
        }
        Matrix(new)
    }

    /// return row major representation of the matrix
    pub fn to_row_major(&self) -> Vec<S::ParameterField> {
        let size = self.num_rows() * self.num_columns();
        let mut res = Vec::with_capacity(size);

        for i in 0..self.num_rows() {
            for j in 0..self.num_columns() {
                res.push(self.0[i][j]);
            }
        }
        res
    }
}

impl<S, COM> Index<usize> for Matrix<S, COM>
where
    S: Specification<COM>,
{
    type Output = Vec<S::ParameterField>;

    /// return an unmutable reference to the `index`^{th} row in the matrix
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<S, COM> IndexMut<usize> for Matrix<S, COM>
where
    S: Specification<COM>,
{
    /// return a mutable reference to the `index`^{th} row in the matrix
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<S, COM> FromIterator<Vec<S::ParameterField>> for Matrix<S, COM>
where
    S: Specification<COM>,
{
    /// from iterator rows
    fn from_iter<T: IntoIterator<Item = Vec<S::ParameterField>>>(iter: T) -> Self {
        let rows = iter.into_iter().collect::<Vec<_>>();
        Self(rows)
    }
}

impl<S, COM> Clone for Matrix<S, COM>
where
    S: Specification<COM>,
    S::ParameterField: Clone,
{
    fn clone(&self) -> Self {
        self.0.clone().into()
    }
}

impl<S, COM> Matrix<S, COM>
where
    S: Specification<COM> + Clone,
    S::ParameterField: Copy,
{
    /// return an identity matrix of size `n*n`
    pub fn identity(n: usize) -> Matrix<S, COM> {
        let mut m = Matrix(vec![vec![S::param_zero(); n]; n]);
        for i in 0..n {
            m.0[i][i] = S::param_one();
        }
        m
    }

    /// Check if the matrix is an identity matrix
    pub fn is_identity(&self) -> bool {
        if !self.is_square() {
            return false;
        }
        for i in 0..self.num_rows() {
            for j in 0..self.num_columns() {
                if !S::param_eq(&self.0[i][j], &kronecker_delta::<S, COM>(i, j)) {
                    return false;
                }
            }
        }
        true
    }

    /// check if `self` is square and `self[1..][1..]` is identity
    pub fn is_sparse(&self) -> bool {
        self.is_square() && self.minor(0, 0).is_identity()
    }

    /// elementwisely multiply with `scalar`
    pub fn mul_by_scalar(&self, scalar: S::ParameterField) -> Self {
        let res = self
            .0
            .iter()
            .map(|row| {
                row.iter()
                    .map(|val| S::param_mul(&scalar, val))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Matrix(res)
    }

    /// return `self @ vec`, treating `vec` as a column vector.
    pub fn mul_col_vec(&self, v: &[S::ParameterField]) -> Vec<S::ParameterField> {
        assert!(
            self.is_square(),
            "Only square matrix can be applied to vector."
        );
        assert_eq!(
            self.num_rows(),
            v.len(),
            "Matrix can only be applied to vector of same size."
        );

        let mut result = vec![S::param_zero(); v.len()];

        for (result, row) in result.iter_mut().zip(self.0.iter()) {
            for (mat_val, vec_val) in row.iter().zip(v) {
                let tmp = S::param_mul(mat_val, vec_val);
                S::param_add_assign(result, &tmp);
            }
        }
        result
    }

    /// return `self @ vec`, treating `vec` as a column vector.
    pub fn left_apply(&self, v: &[S::ParameterField]) -> Vec<S::ParameterField> {
        self.mul_col_vec(v)
    }

    /// return `vec @ self`, treating `vec` as a row vector.
    pub fn mul_row_vec_at_left(&self, v: &[S::ParameterField]) -> Vec<S::ParameterField> {
        assert!(
            self.is_square(),
            "Only square matrix can be applied to vector."
        );
        assert_eq!(
            self.num_rows(),
            v.len(),
            "Matrix can only be applied to vector of same size."
        );

        let mut result = vec![S::param_zero(); v.len()];
        for (j, val) in result.iter_mut().enumerate() {
            for (i, row) in self.0.iter().enumerate() {
                let tmp = S::param_mul(&v[i], &row[j]);
                S::param_add_assign(val, &tmp);
            }
        }
        result
    }

    /// return `vec @ self`, treat `vec` as a row vector.
    pub fn right_apply(&self, v: &[S::ParameterField]) -> Vec<S::ParameterField> {
        self.mul_row_vec_at_left(v)
    }

    /// return `self @ other`
    pub fn matmul(&self, other: &Self) -> Option<Self> {
        if self.num_rows() != other.num_columns() {
            return None;
        };

        let other_t = other.transpose();

        let res = self
            .0
            .iter()
            .map(|input_row| {
                other_t
                    .iter_rows()
                    .map(|transposed_column| inner_product::<S, COM>(input_row, transposed_column))
                    .collect()
            })
            .collect();
        Some(Matrix(res))
    }

    /// return the inversion of a matrix
    pub fn invert(&self) -> Option<Self> {
        let mut shadow = Self::identity(self.num_columns());
        let ut = self.upper_triangular(&mut shadow);

        ut.and_then(|x| x.reduce_to_identity(&mut shadow))
            .and(Some(shadow))
    }

    /// check if the matrix is invertible
    pub fn is_invertible(&self) -> bool {
        self.is_square() && self.invert().is_some()
    }

    /// Generate the minor matrix
    pub fn minor(&self, i: usize, j: usize) -> Self {
        assert!(self.is_square());
        let size = self.num_rows();
        assert!(size > 0);
        let new: Vec<Vec<S::ParameterField>> = self
            .0
            .iter()
            .enumerate()
            .filter_map(|(ii, row)| {
                if ii == i {
                    None
                } else {
                    let mut new_row = row.clone();
                    new_row.remove(j);
                    Some(new_row)
                }
            })
            .collect();
        let res = Matrix(new);
        assert!(res.is_square());
        res
    }

    /// Assumes matrix is partially reduced to upper triangular. `column` is the
    /// column to eliminate from all rows. Returns `None` if either:
    ///   - no non-zero pivot can be found for `column`
    ///   - `column` is not the first
    pub fn eliminate(&self, column: usize, shadow: &mut Self) -> Option<Self> {
        let zero = S::param_zero();
        let pivot_index = (0..self.num_rows()).find(|&i| {
            (!S::param_eq(&self[i][column], &zero))
                && (0..column).all(|j| S::param_eq(&self[i][j], &zero))
        })?;

        let pivot = &self[pivot_index];
        let pivot_val = pivot[column];

        // This should never fail since we have a non-zero `pivot_val` if we got here.
        let inv_pivot = S::inverse(&pivot_val)?;
        let mut result = Vec::with_capacity(self.num_rows());
        result.push(pivot.clone());

        for (i, row) in self.iter_rows().enumerate() {
            if i == pivot_index {
                continue;
            };

            let val = row[column];
            if S::param_eq(&val, &zero) {
                result.push(row.to_vec());
            } else {
                let factor = S::param_mul(&val, &inv_pivot);
                let scaled_pivot = scalar_vec_mul::<S, COM>(factor, pivot);
                let eliminated = vec_sub::<S, COM>(row, &scaled_pivot);
                result.push(eliminated);

                let shadow_pivot = &shadow[pivot_index];
                let scaled_shadow_pivot = scalar_vec_mul::<S, COM>(factor, shadow_pivot);
                let shadow_row = &shadow[i];
                shadow[i] = vec_sub::<S, COM>(shadow_row, &scaled_shadow_pivot);
            }
        }

        let pivot_row = shadow.0.remove(pivot_index);
        shadow.0.insert(0, pivot_row);

        Some(result.into())
    }

    /// generate the upper triangular matrix
    pub fn upper_triangular(&self, shadow: &mut Self) -> Option<Self> {
        assert!(self.is_square());
        let mut result = Vec::with_capacity(self.num_rows());
        let mut shadow_result = Vec::with_capacity(self.num_rows());

        let mut curr = (*self).clone();
        let mut column = 0;
        while curr.num_rows() > 1 {
            let initial_rows = curr.num_rows();

            curr = curr.eliminate(column, shadow)?;
            result.push(curr[0].clone());
            shadow_result.push(shadow[0].clone());
            column += 1;

            curr = Matrix::<S, COM>(curr.0[1..].to_vec());
            *shadow = Matrix(shadow.0[1..].to_vec());
            assert_eq!(curr.num_rows(), initial_rows - 1);
        }
        result.push(curr[0].clone());
        shadow_result.push(shadow[0].clone());

        *shadow = Matrix(shadow_result);

        Some(Matrix(result))
    }

    /// `matrix` must be upper triangular.
    pub fn reduce_to_identity(&self, shadow: &mut Self) -> Option<Self> {
        let size = self.num_rows();
        let mut result: Vec<Vec<S::ParameterField>> = Vec::new();
        let mut shadow_result: Vec<Vec<S::ParameterField>> = Vec::new();

        for i in 0..size {
            let idx = size - i - 1;
            let row = &self.0[idx];
            let shadow_row = &shadow[idx];

            let val = row[idx];
            let inv = S::inverse(&val)?;

            let mut normalized = scalar_vec_mul::<S, COM>(inv, row);
            let mut shadow_normalized = scalar_vec_mul::<S, COM>(inv, shadow_row);

            for j in 0..i {
                let idx = size - j - 1;
                let val = normalized[idx];
                let subtracted = scalar_vec_mul::<S, COM>(val, &result[j]);
                let result_subtracted = scalar_vec_mul::<S, COM>(val, &shadow_result[j]);

                normalized = vec_sub::<S, COM>(&normalized, &subtracted);
                shadow_normalized = vec_sub::<S, COM>(&shadow_normalized, &result_subtracted);
            }

            result.push(normalized);
            shadow_result.push(shadow_normalized);
        }

        result.reverse();
        shadow_result.reverse();

        *shadow = Matrix(shadow_result);
        Some(Matrix(result))
    }
}

/// inner product of two vectors
pub fn inner_product<S, COM>(a: &[S::ParameterField], b: &[S::ParameterField]) -> S::ParameterField
where
    S: Specification<COM>,
{
    a.iter().zip(b).fold(S::param_zero(), |mut acc, (v1, v2)| {
        let tmp = S::param_mul(v1, v2);
        S::param_add_assign(&mut acc, &tmp);
        acc
    })
}

/// elementwise addition of two vectors
pub fn vec_add<S, COM>(a: &[S::ParameterField], b: &[S::ParameterField]) -> Vec<S::ParameterField>
where
    S: Specification<COM>,
{
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| S::param_add(a, b))
        .collect::<Vec<_>>()
}

/// elementwise subtraction (i.e., out[i] = a[i] - b[i])
pub fn vec_sub<S, COM>(a: &[S::ParameterField], b: &[S::ParameterField]) -> Vec<S::ParameterField>
where
    S: Specification<COM>,
{
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| S::param_sub(a, b))
        .collect::<Vec<_>>()
}

/// elementwisely multiply a vector `v` with `scalar`
pub fn scalar_vec_mul<S, COM>(
    scalar: S::ParameterField,
    v: &[S::ParameterField],
) -> Vec<S::ParameterField>
where
    S: Specification<COM>,
{
    v.iter()
        .map(|val| S::param_mul(&scalar, val))
        .collect::<Vec<_>>()
}

/// returns kronecker delta
pub fn kronecker_delta<S, COM>(i: usize, j: usize) -> S::ParameterField
where
    S: Specification<COM>,
{
    if i == j {
        S::param_one()
    } else {
        S::param_zero()
    }
}

/// check whether `elem` equals zero
pub fn equal_zero<S, COM>(elem: &S::ParameterField) -> bool
where
    S: Specification<COM>,
{
    let zero = S::param_zero();
    S::param_eq(elem, &zero)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        constraint::arkworks::{Fp, R1CS},
        hash::poseidon,
    };
    use ark_bls12_381 as bls12_381;

    /// Compiler Type
    type Compiler<S> = R1CS<<S as poseidon::arkworks::Specification>::Field>;
    pub type ConstraintField = bls12_381::Fr;

    #[derive(Clone)]
    pub struct PoseidonSpec;
    // Only for test purpose
    impl poseidon::arkworks::Specification for PoseidonSpec {
        type Field = ConstraintField;
        const FULL_ROUNDS: usize = 8;
        const PARTIAL_ROUNDS: usize = 55;
        const SBOX_EXPONENT: u64 = 5;
    }

    #[test]
    fn test_minor() {
        let one = Fp(ConstraintField::from(1u64));
        let two = Fp(ConstraintField::from(2u64));
        let three = Fp(ConstraintField::from(3u64));
        let four = Fp(ConstraintField::from(4u64));
        let five = Fp(ConstraintField::from(5u64));
        let six = Fp(ConstraintField::from(6u64));
        let seven = Fp(ConstraintField::from(7u64));
        let eight = Fp(ConstraintField::from(8u64));
        let nine = Fp(ConstraintField::from(9u64));

        let m: Matrix<PoseidonSpec, Compiler<PoseidonSpec>> = vec![
            vec![one, two, three],
            vec![four, five, six],
            vec![seven, eight, nine],
        ]
        .into();

        let cases = [
            (
                0,
                0,
                Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
                    vec![five, six],
                    vec![eight, nine],
                ]),
            ),
            (
                0,
                1,
                Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
                    vec![four, six],
                    vec![seven, nine],
                ]),
            ),
            (
                0,
                2,
                Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
                    vec![four, five],
                    vec![seven, eight],
                ]),
            ),
            (
                1,
                0,
                Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
                    vec![two, three],
                    vec![eight, nine],
                ]),
            ),
            (
                1,
                1,
                Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
                    vec![one, three],
                    vec![seven, nine],
                ]),
            ),
            (
                1,
                2,
                Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
                    vec![one, two],
                    vec![seven, eight],
                ]),
            ),
            (
                2,
                0,
                Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
                    vec![two, three],
                    vec![five, six],
                ]),
            ),
            (
                2,
                1,
                Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
                    vec![one, three],
                    vec![four, six],
                ]),
            ),
            (
                2,
                2,
                Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
                    vec![one, two],
                    vec![four, five],
                ]),
            ),
        ];
        for (i, j, expected) in &cases {
            let result = m.minor(*i, *j);

            assert_eq!(expected.0, result.0);
        }
    }

    #[test]
    fn test_scalar_mul() {
        let zero = Fp(ConstraintField::from(0u64));
        let one = Fp(ConstraintField::from(1u64));
        let two = Fp(ConstraintField::from(2u64));
        let three = Fp(ConstraintField::from(3u64));
        let four = Fp(ConstraintField::from(4u64));
        let six = Fp(ConstraintField::from(6u64));

        let m =
            Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![vec![zero, one], vec![two, three]]);
        let res = m.mul_by_scalar(two);

        let expected =
            Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![vec![zero, two], vec![four, six]]);

        assert_eq!(expected.0, res.0);
    }

    #[test]
    fn test_vec_mul() {
        let one = Fp(ConstraintField::from(1u64));
        let two = Fp(ConstraintField::from(2u64));
        let three = Fp(ConstraintField::from(3u64));
        let four = Fp(ConstraintField::from(4u64));
        let five = Fp(ConstraintField::from(5u64));
        let six = Fp(ConstraintField::from(6u64));

        let a = vec![one, two, three];
        let b = vec![four, five, six];
        let res = inner_product::<PoseidonSpec, Compiler<PoseidonSpec>>(&a, &b);

        let expected = Fp(ConstraintField::from(32u64));

        assert_eq!(expected, res);
    }

    #[test]
    fn test_transpose() {
        let one = Fp(ConstraintField::from(1u64));
        let two = Fp(ConstraintField::from(2u64));
        let three = Fp(ConstraintField::from(3u64));
        let four = Fp(ConstraintField::from(4u64));
        let five = Fp(ConstraintField::from(5u64));
        let six = Fp(ConstraintField::from(6u64));
        let seven = Fp(ConstraintField::from(7u64));
        let eight = Fp(ConstraintField::from(8u64));
        let nine = Fp(ConstraintField::from(9u64));

        let m: Matrix<PoseidonSpec, Compiler<PoseidonSpec>> = vec![
            vec![one, two, three],
            vec![four, five, six],
            vec![seven, eight, nine],
        ]
        .into();

        let expected: Matrix<PoseidonSpec, Compiler<PoseidonSpec>> = vec![
            vec![one, four, seven],
            vec![two, five, eight],
            vec![three, six, nine],
        ]
        .into();

        let res = m.transpose();
        assert_eq!(expected.0, res.0);
    }

    #[test]
    fn test_upper_triangular() {
        let zero = Fp(ConstraintField::from(0u64));
        let two = Fp(ConstraintField::from(2u64));
        let three = Fp(ConstraintField::from(3u64));
        let four = Fp(ConstraintField::from(4u64));
        let five = Fp(ConstraintField::from(5u64));
        let six = Fp(ConstraintField::from(6u64));
        let seven = Fp(ConstraintField::from(7u64));
        let eight = Fp(ConstraintField::from(8u64));

        let m = Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
            vec![two, three, four],
            vec![four, five, six],
            vec![seven, eight, eight],
        ]);

        let mut shadow = Matrix::identity(m.num_columns());
        let res = m.upper_triangular(&mut shadow).unwrap();

        // Actually assert things.
        assert!(res[0][0] != zero);
        assert!(res[0][1] != zero);
        assert!(res[0][2] != zero);
        assert!(res[1][0] == zero);
        assert!(res[1][1] != zero);
        assert!(res[1][2] != zero);
        assert!(res[2][0] == zero);
        assert!(res[2][1] == zero);
        assert!(res[2][2] != zero);
    }

    #[test]
    fn test_inverse() {
        let zero = Fp(ConstraintField::from(0u64));
        let one = Fp(ConstraintField::from(1u64));
        let two = Fp(ConstraintField::from(2u64));
        let three = Fp(ConstraintField::from(3u64));
        let four = Fp(ConstraintField::from(4u64));
        let five = Fp(ConstraintField::from(5u64));
        let six = Fp(ConstraintField::from(6u64));
        let seven = Fp(ConstraintField::from(7u64));
        let eight = Fp(ConstraintField::from(8u64));
        let nine = Fp(ConstraintField::from(9u64));

        let m = Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
            vec![one, two, three],
            vec![four, three, six],
            vec![five, eight, seven],
        ]);

        let m1 = Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
            vec![one, two, three],
            vec![four, five, six],
            vec![seven, eight, nine],
        ]);

        assert!(!m1.is_invertible());
        assert!(m.is_invertible());

        let m_inv = m.invert().unwrap();

        let computed_identity = m.matmul(&m_inv).unwrap();
        assert!(computed_identity.is_identity());

        // S
        let some_vec = vec![six, five, four];

        // M^-1(S)
        let inverse_applied = m_inv.right_apply(&some_vec);

        // M(M^-1(S))
        let m_applied_after_inverse = m.right_apply(&inverse_applied);

        // S = M(M^-1(S))
        assert_eq!(
            some_vec, m_applied_after_inverse,
            "M(M^-1(V))) = V did not hold"
        );

        // panic!();
        // B
        let base_vec = vec![eight, two, five];

        // S + M(B)
        let add_after_apply =
            vec_add::<PoseidonSpec, Compiler<PoseidonSpec>>(&some_vec, &m.right_apply(&base_vec));

        // M(B + M^-1(S))
        let apply_after_add = m.right_apply(&vec_add::<PoseidonSpec, Compiler<PoseidonSpec>>(
            &base_vec,
            &inverse_applied,
        ));

        // S + M(B) = M(B + M^-1(S))
        assert_eq!(add_after_apply, apply_after_add, "breakin' the law");

        let m =
            Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![vec![zero, one], vec![one, zero]]);
        let m_inv = m.invert().unwrap();
        let computed_identity = m.matmul(&m_inv).unwrap();
        assert!(computed_identity.is_identity());
        let computed_identity = m_inv.matmul(&m).unwrap();
        assert!(computed_identity.is_identity());
    }

    #[test]
    fn test_eliminate() {
        let two = Fp(ConstraintField::from(2u64));
        let three = Fp(ConstraintField::from(3u64));
        let four = Fp(ConstraintField::from(4u64));
        let five = Fp(ConstraintField::from(5u64));
        let six = Fp(ConstraintField::from(6u64));
        let seven = Fp(ConstraintField::from(7u64));
        let eight = Fp(ConstraintField::from(8u64));
        let m = Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
            vec![two, three, four],
            vec![four, five, six],
            vec![seven, eight, eight],
        ]);

        for i in 0..m.num_rows() {
            let mut shadow = Matrix::identity(m.num_columns());
            let res = m.eliminate(i, &mut shadow);
            if i > 0 {
                assert!(res.is_none());
                continue;
            } else {
                assert!(res.is_some());
            }

            assert_eq!(
                1,
                res.unwrap()
                    .iter_rows()
                    .filter(|&row| !equal_zero::<PoseidonSpec, Compiler<PoseidonSpec>>(&row[i]))
                    .count()
            );
        }
    }

    #[test]
    fn test_reduce_to_identity() {
        let two = Fp(ConstraintField::from(2u64));
        let three = Fp(ConstraintField::from(3u64));
        let four = Fp(ConstraintField::from(4u64));
        let five = Fp(ConstraintField::from(5u64));
        let six = Fp(ConstraintField::from(6u64));
        let seven = Fp(ConstraintField::from(7u64));
        let eight = Fp(ConstraintField::from(8u64));

        let m = Matrix::<PoseidonSpec, Compiler<PoseidonSpec>>(vec![
            vec![two, three, four],
            vec![four, five, six],
            vec![seven, eight, eight],
        ]);

        let mut shadow = Matrix::identity(m.num_columns());
        let ut = m.upper_triangular(&mut shadow);

        let res = ut
            .and_then(|x: Matrix<PoseidonSpec, Compiler<PoseidonSpec>>| {
                x.reduce_to_identity(&mut shadow)
            })
            .unwrap();

        assert!(res.is_identity());

        let prod = m.matmul(&shadow).unwrap();

        assert!(prod.is_identity());
    }
}
