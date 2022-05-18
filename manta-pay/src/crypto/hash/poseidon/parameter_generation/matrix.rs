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

use crate::crypto::hash::poseidon::Field;
use alloc::vec::Vec;
use core::{
    fmt::Debug,
    ops::{Deref, Index, IndexMut},
    slice,
};

/// Allocates a vector of length `n` and initializes with `f`.
pub fn vec_with<T, F>(n: usize, f: F) -> Vec<T>
where
    F: FnMut() -> T,
{
    let mut v = Vec::with_capacity(n);
    v.resize_with(n, f);
    v
}

/// Allocates a matrix of shape `(num_rows, num_columns)`.
pub fn allocate_matrix<T, F>(
    num_rows: usize,
    num_columns: usize,
    mut allocate_row: F,
) -> Vec<Vec<T>>
where
    F: FnMut(usize) -> Vec<T>,
{
    vec_with(num_rows, || allocate_row(num_columns))
}

/// TODO: Trait
pub trait MatrixOperations {
    // TODO: Move owned to this trait

    /// Scalar field
    type Scalar;

    /// Returns the transpose of the matrix.
    fn transpose(self) -> Self;

    /// Elementwisely multiplies with `scalar`.
    fn mul_by_scalar(&self, scalar: Self::Scalar) -> Self;

    /// Returns row major representation of the matrix.
    fn to_row_major(self) -> Vec<Self::Scalar>;

    /// Multiplies matrix `self` with matrix `other` on the right side.
    fn matmul(&self, other: &Self) -> Option<Self>
    where
        Self: Sized,
        Self::Scalar: Clone;

    /// Returns an identity matrix of size `n*n`.
    fn identity(n: usize) -> Self;

    /// Returns the inversion of a matrix
    fn invert(&self) -> Option<Self>
    where
        Self: Sized,
        Self::Scalar: Copy;
}

/// Row Major Matrix Representation
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Matrix<F>(Vec<Vec<F>>)
where
    F: Field;

impl<F> Matrix<F>
where
    F: Field,
{
    /// Constructs a [`Matrix`].
    /// If `v` is empty then returns `None`.
    pub fn new(v: Vec<Vec<F>>) -> Option<Self> {
        if v.is_empty() {
            return None;
        }
        let first_row_length = v[0].len();
        if first_row_length == 0 {
            return None;
        }
        for row in &v {
            if row.len() != first_row_length {
                return None;
            }
        }
        Some(Self(v))
    }

    /// Returns the number of rows.
    pub fn num_rows(&self) -> usize {
        self.0.len()
    }

    /// Returns the number of columns.
    pub fn num_columns(&self) -> usize {
        self.0[0].len()
    }

    /// Iterator over rows.
    pub fn iter_rows(&self) -> slice::Iter<Vec<F>> {
        self.0.iter()
    }

    /// Iterator over a specific column.
    pub fn column(&self, column: usize) -> impl Iterator<Item = &'_ F> {
        self.0.iter().map(move |row| &row[column])
    }

    /// Checks if the matrix is square.
    pub fn is_square(&self) -> bool {
        self.num_rows() == self.num_columns()
    }

    /// Checks if the matrix is an identity matrix.
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

    /// Checks if the matrix is symmetric.
    pub fn is_symmetric(&self) -> bool 
    {
        // assert!(matrix.0 == matrix.transpose().0);
        for i in 0..self.num_rows() {
            for j in 0..self.num_columns() {
                if !F::eq(&self.0[i][j], &self.0[j][i]) {
                    return false;
                }
            }
        }
        return true;
    }

    /// Returns `self @ vec`, treating `vec` as a column vector.
    pub fn mul_col_vec(&self, v: &[F]) -> Option<Vec<F>> {
        if self.num_rows() != v.len() {
            return None;
        }
        let mut result = Vec::with_capacity(v.len());
        for row in &self.0 {
            result.push(
                row.iter()
                    .zip(v)
                    .fold(F::zero(), |acc, (r, v)| F::add(&acc, &F::mul(r, v))),
            );
        }
        Some(result)
    }

    /// Returns `vec @ self`, treating `vec` as a row vector.
    pub fn mul_row_vec_at_left(&self, v: &[F]) -> Option<Vec<F>> {
        if self.num_rows() != v.len() {
            return None;
        }
        let mut result = Vec::with_capacity(v.len());
        for j in 0..v.len() {
            result.push(
                self.0
                    .iter()
                    .zip(v)
                    .fold(F::zero(), |acc, (row, v)| F::add(&acc, &F::mul(v, &row[j]))),
            );
        }
        Some(result)
    }
}

impl<F> From<SquareMatrix<F>> for Matrix<F>
where
    F: Field,
{
    fn from(matrix: SquareMatrix<F>) -> Self {
        matrix.0
    }
}

impl<F> MatrixOperations for Matrix<F>
where
    F: Field,
{
    type Scalar = F;

    fn transpose(self) -> Self {
        let mut transposed_matrix =
            allocate_matrix(self.num_columns(), self.num_rows(), Vec::with_capacity);
        for row in self.0 {
            for (j, elem) in row.into_iter().enumerate() {
                transposed_matrix[j].push(elem);
            }
        }
        Self(transposed_matrix)
    }

    fn mul_by_scalar(&self, scalar: F) -> Self {
        Self(
            self.0
                .iter()
                .map(|row| row.iter().map(|val| F::mul(&scalar, val)).collect())
                .collect(),
        )
    }

    fn to_row_major(self) -> Vec<F> {
        let size = self.num_rows() * self.num_columns();
        let mut row_major_repr = Vec::with_capacity(size);
        for mut row in self.0 {
            row_major_repr.append(&mut row);
        }
        row_major_repr
    }

    fn matmul(&self, other: &Self) -> Option<Self>
    where
        Self::Scalar: Clone,
    {
        if self.num_rows() != other.num_columns() {
            return None;
        };
        let other_t = other.clone().transpose();
        Some(Self(
            self.0
                .iter()
                .map(|input_row| {
                    other_t
                        .iter_rows()
                        .map(|transposed_column| inner_product::<F>(input_row, transposed_column))
                        .collect()
                })
                .collect(),
        ))
    }

    fn identity(n: usize) -> Self {
        let mut identity_matrix = allocate_matrix(n, n, |n| vec_with(n, F::zero));
        for i in 0..n {
            identity_matrix[i][i] = F::one();
        }
        Self(identity_matrix)
    }

    fn invert(&self) -> Option<Self> 
    where Self::Scalar: Copy,
    {
        let mut shadow = Self::identity(self.num_columns());
        self.upper_triangular(&mut shadow)
            .and_then(|x| x.reduce_to_identity(&mut shadow))
            .and(Some(shadow))
    }
}

impl<F> MatrixOperations for SquareMatrix<F>
where
    F: Field,
{
    type Scalar = F;

    fn transpose(self) -> Self {
        Self(self.0.transpose())
    }

    fn mul_by_scalar(&self, scalar: Self::Scalar) -> Self {
        Self(self.0.mul_by_scalar(scalar))
    }

    fn to_row_major(self) -> Vec<F> {
        self.0.to_row_major()
    }

    fn matmul(&self, other: &Self) -> Option<Self>
    where
        Self::Scalar: Clone,
    {
        self.0.matmul(&other.0).map(Self)
    }

    fn identity(n: usize) -> Self {
        Self(Matrix::identity(n))
    }

    fn invert(&self) -> Option<Self> 
    where Self::Scalar: Copy,
    {
        self.0.invert().map(Self)
    }
}

impl<F> PartialEq<SquareMatrix<F>> for Matrix<F>
where
    F: Field + PartialEq,
{
    fn eq(&self, other: &SquareMatrix<F>) -> bool {
        self.eq(&other.0)
    }
}

/// Row Major Matrix Representation with Square Shapes
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SquareMatrix<F>(Matrix<F>)
where
    F: Field;

impl<F> SquareMatrix<F>
where
    F: Field,
{
    /// Returns a new square matrix
    pub fn new(m: Matrix<F>) -> Option<Self> {
        m.is_square().then(|| Self(m))
    }

    /// Generates the minor matrix
    pub fn minor(&self, i: usize, j: usize) -> Option<Self>
    where
        F: Clone,
    {
        let size = self.num_rows();
        if size <= 1 {
            return None;
        }
        Some(Self(Matrix(
            self.0
                 .0
                .iter()
                .enumerate()
                .filter_map(|(ii, row)| {
                    if ii == i {
                        None
                    } else {
                        let mut row = row.clone();
                        row.remove(j);
                        Some(row)
                    }
                })
                .collect(),
        )))
    }
}

impl<F> AsRef<Matrix<F>> for SquareMatrix<F>
where
    F: Field,
{
    fn as_ref(&self) -> &Matrix<F> {
        &self.0
    }
}

impl<F> Deref for SquareMatrix<F>
where
    F: Field,
{
    type Target = Matrix<F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F> PartialEq<Matrix<F>> for SquareMatrix<F>
where
    F: Field + PartialEq,
{
    fn eq(&self, other: &Matrix<F>) -> bool {
        self.0.eq(other)
    }
}

impl<F> Matrix<F>
where
    F: Field + Copy,
{
    /// Assumes matrix is partially reduced to upper triangular. `column` is the
    /// column to eliminate from all rows. Returns `None` if either:
    ///   - no non-zero pivot can be found for `column`
    ///   - `column` is not the first
    fn eliminate(&self, column: usize, shadow: &mut Self) -> Option<Self> {
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
    fn upper_triangular(&self, shadow: &mut Self) -> Option<Self> {
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

    /// `matrix` must be upper triangular.
    fn reduce_to_identity(&self, shadow: &mut Self) -> Option<Self> {
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

    /// Checks if the matrix is invertible
    pub fn is_invertible(&self) -> bool {
        self.is_square() && self.invert().is_some()
    }
}

impl<F> From<Vec<Vec<F>>> for Matrix<F>
where
    F: Field,
{
    fn from(v: Vec<Vec<F>>) -> Self {
        Self(v)
    }
}

impl<F> Index<usize> for Matrix<F>
where
    F: Field,
{
    type Output = Vec<F>;

    /// Returns an unmutable reference to the `index`^{th} row in the matrix
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<F> IndexMut<usize> for Matrix<F>
where
    F: Field,
{
    /// Returns a mutable reference to the `index`^{th} row in the matrix
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

/// Inner product of two vectors
pub fn inner_product<F>(a: &[F], b: &[F]) -> F
where
    F: Field,
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
    F: Field,
{
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| F::add(a, b))
        .collect::<Vec<_>>()
}

/// Elementwise subtraction (i.e., out_i = a_i - b_i)
pub fn vec_sub<F>(a: &[F], b: &[F]) -> Vec<F>
where
    F: Field,
{
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| F::sub(a, b))
        .collect::<Vec<_>>()
}

/// Elementwisely multiplies a vector `v` with `scalar`
pub fn scalar_vec_mul<F>(scalar: F, v: &[F]) -> Vec<F>
where
    F: Field,
{
    v.iter().map(|val| F::mul(&scalar, val)).collect::<Vec<_>>()
}

/// Returns kronecker delta
pub fn kronecker_delta<F>(i: usize, j: usize) -> F
where
    F: Field,
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
    F: Field,
{
    let zero = F::zero();
    F::eq(elem, &zero)
}

#[cfg(test)]
mod test {
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
        let m = SquareMatrix::new(m).unwrap();
        for (i, j, expected) in &cases {
            let result = m.minor(*i, *j).unwrap();
            assert_eq!(expected, &result);
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
        let inverse_applied = m_inv.mul_row_vec_at_left(&some_vec).unwrap();

        // M(M^-1(S))
        let m_applied_after_inverse = m.mul_row_vec_at_left(&inverse_applied).unwrap();

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
            vec_add::<Fp<Fr>>(&some_vec, &m.mul_row_vec_at_left(&base_vec).unwrap());

        // M(B + M^-1(S))
        let apply_after_add = m
            .mul_row_vec_at_left(&vec_add::<Fp<Fr>>(&base_vec, &inverse_applied))
            .unwrap();

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
