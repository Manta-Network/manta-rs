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

use crate::crypto::hash::ParamField;
use alloc::{vec, vec::Vec};
use core::{
    fmt::Debug,
    ops::{Index, IndexMut},
};

#[derive(Eq, PartialEq, Debug, Default)]
/// a struct for matrix data
pub struct Matrix<F>(pub Vec<Vec<F>>)
where
    F: ParamField;

impl<F> From<Vec<Vec<F>>> for Matrix<F>
where
    F: ParamField,
{
    fn from(v: Vec<Vec<F>>) -> Self {
        Matrix(v)
    }
}

impl<F> Matrix<F>
where
    F: ParamField,
{
    /// Returns the number of rows
    pub fn num_rows(&self) -> usize {
        self.0.len()
    }

    /// Returns the number of columns
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
    pub fn iter_rows(&self) -> impl Iterator<Item = &Vec<F>> {
        self.0.iter()
    }

    /// Iterator over a specific column
    pub fn column(&self, column: usize) -> impl Iterator<Item = &'_ F> {
        self.0.iter().map(move |row| &row[column])
    }

    /// Checks if the matrix is square
    pub fn is_square(&self) -> bool {
        self.num_rows() == self.num_columns()
    }

    /// Checks if the matrix is an identity matrix
    pub fn is_identity(&self) -> bool {
        if !self.is_square() {
            return false;
        }

        for i in 0..self.num_rows() {
            for j in 0..self.num_columns() {
                if !F::eq(&self.0[i][j], &kronecker_delta::<F>(i, j)) {
                    return false;
                }
            }
        }
        true
    }

    /// elementwisely multiplies with `scalar`
    pub fn mul_by_scalar(&self, scalar: F) -> Self {
        let res = self
            .0
            .iter()
            .map(|row| {
                row.iter()
                    .map(|val| F::mul(&scalar, val))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Matrix(res)
    }
}

impl<F> Matrix<F>
where
    F: ParamField + Copy,
{
    /// Returns the transpose of the matrix
    pub fn transpose(&self) -> Matrix<F> {
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

    /// Returns row major representation of the matrix
    pub fn to_row_major(&self) -> Vec<F> {
        let size = self.num_rows() * self.num_columns();
        let mut res = Vec::with_capacity(size);

        for i in 0..self.num_rows() {
            for j in 0..self.num_columns() {
                res.push(self.0[i][j]);
            }
        }
        res
    }

    /// Returns `self @ other`
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
                    .map(|transposed_column| inner_product::<F>(input_row, transposed_column))
                    .collect()
            })
            .collect();
        Some(Matrix(res))
    }

    /// `matrix` must be upper triangular.
    pub fn reduce_to_identity(&self, shadow: &mut Self) -> Option<Self> {
        let size = self.num_rows();
        let mut result: Vec<Vec<F>> = Vec::new();
        let mut shadow_result: Vec<Vec<F>> = Vec::new();

        for i in 0..size {
            let idx = size - i - 1;
            let row = &self.0[idx];
            let shadow_row = &shadow[idx];

            let val = row[idx];
            let inv = F::inverse(&val)?;

            let mut normalized = scalar_vec_mul::<F>(inv, row);
            let mut shadow_normalized = scalar_vec_mul::<F>(inv, shadow_row);

            for j in 0..i {
                let idx = size - j - 1;
                let val = normalized[idx];
                let subtracted = scalar_vec_mul::<F>(val, &result[j]);
                let result_subtracted = scalar_vec_mul::<F>(val, &shadow_result[j]);

                normalized = vec_sub::<F>(&normalized, &subtracted);
                shadow_normalized = vec_sub::<F>(&shadow_normalized, &result_subtracted);
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

impl<F> Matrix<F>
where
    F: ParamField + Clone,
{
    /// Returns an identity matrix of size `n*n`
    pub fn identity(n: usize) -> Matrix<F> {
        let mut m = Matrix(vec![vec![F::zero(); n]; n]);
        for i in 0..n {
            m.0[i][i] = F::one();
        }
        m
    }

    /// Returns `self @ vec`, treating `vec` as a column vector.
    pub fn mul_col_vec(&self, v: &[F]) -> Vec<F> {
        assert!(
            self.is_square(),
            "Only square matrix can be applied to vector."
        );
        assert_eq!(
            self.num_rows(),
            v.len(),
            "Matrix can only be applied to vector of same size."
        );

        let mut result = vec![F::zero(); v.len()];

        for (result, row) in result.iter_mut().zip(self.0.iter()) {
            for (mat_val, vec_val) in row.iter().zip(v) {
                let tmp = F::mul(mat_val, vec_val);
                F::add_assign(result, &tmp);
            }
        }
        result
    }

    /// Returns `self @ vec`, treating `vec` as a column vector.
    pub fn left_apply(&self, v: &[F]) -> Vec<F> {
        self.mul_col_vec(v)
    }

    /// Returns `vec @ self`, treating `vec` as a row vector.
    pub fn mul_row_vec_at_left(&self, v: &[F]) -> Vec<F> {
        assert!(
            self.is_square(),
            "Only square matrix can be applied to vector."
        );
        assert_eq!(
            self.num_rows(),
            v.len(),
            "Matrix can only be applied to vector of same size."
        );

        let mut result = vec![F::zero(); v.len()];
        for (j, val) in result.iter_mut().enumerate() {
            for (i, row) in self.0.iter().enumerate() {
                let tmp = F::mul(&v[i], &row[j]);
                F::add_assign(val, &tmp);
            }
        }
        result
    }

    /// Returns `vec @ self`, treat `vec` as a row vector.
    pub fn right_apply(&self, v: &[F]) -> Vec<F> {
        self.mul_row_vec_at_left(v)
    }

    /// Generates the minor matrix
    pub fn minor(&self, i: usize, j: usize) -> Self {
        assert!(self.is_square());
        let size = self.num_rows();
        assert!(size > 0);
        let new: Vec<Vec<F>> = self
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

    /// Checks if `self` is square and `self[1..][1..]` is identity
    pub fn is_sparse(&self) -> bool {
        self.is_square() && self.minor(0, 0).is_identity()
    }
}

impl<F> Matrix<F>
where
    F: ParamField + Clone + Copy,
{
    /// Assumes matrix is partially reduced to upper triangular. `column` is the
    /// column to eliminate from all rows. Returns `None` if either:
    ///   - no non-zero pivot can be found for `column`
    ///   - `column` is not the first
    pub fn eliminate(&self, column: usize, shadow: &mut Self) -> Option<Self> {
        let zero = F::zero();
        let pivot_index = (0..self.num_rows()).find(|&i| {
            (!F::eq(&self[i][column], &zero)) && (0..column).all(|j| F::eq(&self[i][j], &zero))
        })?;

        let pivot = &self[pivot_index];
        let pivot_val = pivot[column];

        // This should never fail since we have a non-zero `pivot_val` if we got here.
        let inv_pivot = F::inverse(&pivot_val)?;
        let mut result = Vec::with_capacity(self.num_rows());
        result.push(pivot.clone());

        for (i, row) in self.iter_rows().enumerate() {
            if i == pivot_index {
                continue;
            };

            let val = row[column];
            if F::eq(&val, &zero) {
                result.push(row.to_vec());
            } else {
                let factor = F::mul(&val, &inv_pivot);
                let scaled_pivot = scalar_vec_mul::<F>(factor, pivot);
                let eliminated = vec_sub::<F>(row, &scaled_pivot);
                result.push(eliminated);

                let shadow_pivot = &shadow[pivot_index];
                let scaled_shadow_pivot = scalar_vec_mul::<F>(factor, shadow_pivot);
                let shadow_row = &shadow[i];
                shadow[i] = vec_sub::<F>(shadow_row, &scaled_shadow_pivot);
            }
        }

        let pivot_row = shadow.0.remove(pivot_index);
        shadow.0.insert(0, pivot_row);

        Some(result.into())
    }

    /// Generates the upper triangular matrix
    pub fn upper_triangular(&self, shadow: &mut Self) -> Option<Self> {
        assert!(self.is_square());
        let mut result = Vec::with_capacity(self.num_rows());
        let mut shadow_result = Vec::with_capacity(self.num_rows());

        let mut curr = self.clone();
        let mut column = 0;
        while curr.num_rows() > 1 {
            let initial_rows = curr.num_rows();

            curr = curr.eliminate(column, shadow)?;
            result.push(curr[0].clone());
            shadow_result.push(shadow[0].clone());
            column += 1;

            curr = Matrix::<F>(curr.0[1..].to_vec());
            *shadow = Matrix(shadow.0[1..].to_vec());
            assert_eq!(curr.num_rows(), initial_rows - 1);
        }
        result.push(curr[0].clone());
        shadow_result.push(shadow[0].clone());

        *shadow = Matrix(shadow_result);

        Some(Matrix(result))
    }

    /// Returns the inversion of a matrix
    pub fn invert(&self) -> Option<Self> {
        let mut shadow = Self::identity(self.num_columns());
        let ut = self.upper_triangular(&mut shadow);

        ut.and_then(|x| x.reduce_to_identity(&mut shadow))
            .and(Some(shadow))
    }

    /// Checks if the matrix is invertible
    pub fn is_invertible(&self) -> bool {
        self.is_square() && self.invert().is_some()
    }
}

impl<F> Index<usize> for Matrix<F>
where
    F: ParamField,
{
    type Output = Vec<F>;

    /// Returns an unmutable reference to the `index`^{th} row in the matrix
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<F> IndexMut<usize> for Matrix<F>
where
    F: ParamField,
{
    /// Returns a mutable reference to the `index`^{th} row in the matrix
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F> FromIterator<Vec<F>> for Matrix<F>
where
    F: ParamField,
{
    /// from iterator rows
    fn from_iter<T: IntoIterator<Item = Vec<F>>>(iter: T) -> Self {
        let rows = iter.into_iter().collect::<Vec<_>>();
        Self(rows)
    }
}

impl<F> Clone for Matrix<F>
where
    F: ParamField + Clone,
{
    fn clone(&self) -> Self {
        self.0.clone().into()
    }
}

/// Inner product of two vectors
pub fn inner_product<F>(a: &[F], b: &[F]) -> F
where
    F: ParamField,
{
    a.iter().zip(b).fold(F::zero(), |mut acc, (v1, v2)| {
        let tmp = F::mul(v1, v2);
        F::add_assign(&mut acc, &tmp);
        acc
    })
}

/// Elementwise addition of two vectors
pub fn vec_add<F>(a: &[F], b: &[F]) -> Vec<F>
where
    F: ParamField,
{
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| F::add(a, b))
        .collect::<Vec<_>>()
}

/// Elementwise subtraction (i.e., out_i = a_i - b_i)
pub fn vec_sub<F>(a: &[F], b: &[F]) -> Vec<F>
where
    F: ParamField,
{
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| F::sub(a, b))
        .collect::<Vec<_>>()
}

/// Elementwisely multiplies a vector `v` with `scalar`
pub fn scalar_vec_mul<F>(scalar: F, v: &[F]) -> Vec<F>
where
    F: ParamField,
{
    v.iter().map(|val| F::mul(&scalar, val)).collect::<Vec<_>>()
}

/// Returns kronecker delta
pub fn kronecker_delta<F>(i: usize, j: usize) -> F
where
    F: ParamField,
{
    if i == j {
        F::one()
    } else {
        F::zero()
    }
}

/// Checks whether `elem` equals zero
pub fn equal_zero<F>(elem: &F) -> bool
where
    F: ParamField,
{
    let zero = F::zero();
    F::eq(elem, &zero)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::constraint::arkworks::Fp;
    use ark_bls12_381::Fr;

    #[test]
    fn test_minor() {
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let nine = Fp(Fr::from(9u64));

        let m: Matrix<Fp<Fr>> = vec![
            vec![one, two, three],
            vec![four, five, six],
            vec![seven, eight, nine],
        ]
        .into();

        let cases = [
            (
                0,
                0,
                Matrix::<Fp<Fr>>(vec![vec![five, six], vec![eight, nine]]),
            ),
            (
                0,
                1,
                Matrix::<Fp<Fr>>(vec![vec![four, six], vec![seven, nine]]),
            ),
            (
                0,
                2,
                Matrix::<Fp<Fr>>(vec![vec![four, five], vec![seven, eight]]),
            ),
            (
                1,
                0,
                Matrix::<Fp<Fr>>(vec![vec![two, three], vec![eight, nine]]),
            ),
            (
                1,
                1,
                Matrix::<Fp<Fr>>(vec![vec![one, three], vec![seven, nine]]),
            ),
            (
                1,
                2,
                Matrix::<Fp<Fr>>(vec![vec![one, two], vec![seven, eight]]),
            ),
            (
                2,
                0,
                Matrix::<Fp<Fr>>(vec![vec![two, three], vec![five, six]]),
            ),
            (
                2,
                1,
                Matrix::<Fp<Fr>>(vec![vec![one, three], vec![four, six]]),
            ),
            (
                2,
                2,
                Matrix::<Fp<Fr>>(vec![vec![one, two], vec![four, five]]),
            ),
        ];
        for (i, j, expected) in &cases {
            let result = m.minor(*i, *j);

            assert_eq!(expected.0, result.0);
        }
    }

    #[test]
    fn test_scalar_mul() {
        let zero = Fp(Fr::from(0u64));
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let six = Fp(Fr::from(6u64));

        let m = Matrix::<Fp<Fr>>(vec![vec![zero, one], vec![two, three]]);
        let res = m.mul_by_scalar(two);

        let expected = Matrix::<Fp<Fr>>(vec![vec![zero, two], vec![four, six]]);

        assert_eq!(expected.0, res.0);
    }

    #[test]
    fn test_vec_mul() {
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));

        let a = vec![one, two, three];
        let b = vec![four, five, six];
        let res = inner_product::<Fp<Fr>>(&a, &b);

        let expected = Fp(Fr::from(32u64));

        assert_eq!(expected, res);
    }

    #[test]
    fn test_transpose() {
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let nine = Fp(Fr::from(9u64));

        let m: Matrix<Fp<Fr>> = vec![
            vec![one, two, three],
            vec![four, five, six],
            vec![seven, eight, nine],
        ]
        .into();

        let expected: Matrix<Fp<Fr>> = vec![
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
        let zero = Fp(Fr::from(0u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));

        let m = Matrix::<Fp<Fr>>(vec![
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
        let zero = Fp(Fr::from(0u64));
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let nine = Fp(Fr::from(9u64));

        let m = Matrix::<Fp<Fr>>(vec![
            vec![one, two, three],
            vec![four, three, six],
            vec![five, eight, seven],
        ]);

        let m1 = Matrix::<Fp<Fr>>(vec![
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
        let add_after_apply = vec_add::<Fp<Fr>>(&some_vec, &m.right_apply(&base_vec));

        // M(B + M^-1(S))
        let apply_after_add = m.right_apply(&vec_add::<Fp<Fr>>(&base_vec, &inverse_applied));

        // S + M(B) = M(B + M^-1(S))
        assert_eq!(add_after_apply, apply_after_add, "breakin' the law");

        let m = Matrix::<Fp<Fr>>(vec![vec![zero, one], vec![one, zero]]);
        let m_inv = m.invert().unwrap();
        let computed_identity = m.matmul(&m_inv).unwrap();
        assert!(computed_identity.is_identity());
        let computed_identity = m_inv.matmul(&m).unwrap();
        assert!(computed_identity.is_identity());
    }

    #[test]
    fn test_eliminate() {
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let m = Matrix::<Fp<Fr>>(vec![
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
                    .filter(|&row| !equal_zero::<Fp<Fr>>(&row[i]))
                    .count()
            );
        }
    }

    #[test]
    fn test_reduce_to_identity() {
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));

        let m = Matrix::<Fp<Fr>>(vec![
            vec![two, three, four],
            vec![four, five, six],
            vec![seven, eight, eight],
        ]);

        let mut shadow = Matrix::identity(m.num_columns());
        let ut = m.upper_triangular(&mut shadow);

        let res = ut
            .and_then(|x: Matrix<Fp<Fr>>| x.reduce_to_identity(&mut shadow))
            .unwrap();

        assert!(res.is_identity());

        let prod = m.matmul(&shadow).unwrap();

        assert!(prod.is_identity());
    }
}
