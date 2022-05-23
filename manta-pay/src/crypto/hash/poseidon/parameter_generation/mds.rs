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

//! MDS Data Generation

use super::matrix::{MatrixOperations, SquareMatrix};
use crate::crypto::hash::poseidon::{parameter_generation::matrix::Matrix, Field, FieldGeneration};
use alloc::{vec, vec::Vec};
use core::fmt::Debug;
use manta_util::vec::VecExt;

/// MDS Matrix for both naive poseidon hash and optimized poseidon hash
/// For detailed descriptions, please refer to <https://hackmd.io/8MdoHwoKTPmQfZyIKEYWXQ>
/// Note: Naive and optimized poseidon hash does not change #constraints in Groth16.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdsMatrices<F>
where
    F: Field,
{
    /// MDS Matrix for naive poseidon hash
    pub m: SquareMatrix<F>,
    /// inversion of mds matrix. Used in optimzed poseidon hash.
    pub m_inv: SquareMatrix<F>,
    /// m_hat matrix. Used in optimized poseidon hash
    pub m_hat: SquareMatrix<F>,
    /// Inversion of m_hat matrix. Used in optimized poseidon hash.
    pub m_hat_inv: SquareMatrix<F>,
    /// m prime matrix. Used in optimized poseidon hash.
    pub m_prime: SquareMatrix<F>,
    /// m double prime matrix. Used in optimized poseidon hash.
    pub m_double_prime: SquareMatrix<F>,
}

impl<F> MdsMatrices<F>
where
    F: Field + Clone,
{
    fn make_v_w(m: &Matrix<F>) -> (Vec<F>, Vec<F>) {
        let v = m[0][1..].to_vec();
        let w = m
            .iter_rows()
            .skip(1)
            .map(|column| column[0].clone())
            .collect();
        (v, w)
    }
}

impl<F> MdsMatrices<F>
where
    F: Field + Clone,
{
    fn make_prime(m: &SquareMatrix<F>) -> SquareMatrix<F> {
        SquareMatrix::new(
            Matrix::new(
                m.iter_rows()
                    .enumerate()
                    .map(|(i, row)| match i {
                        0 => {
                            let mut new_row = Vec::allocate_with(row.len(), F::zero);
                            new_row[0] = F::one();
                            new_row
                        }
                        _ => {
                            let mut new_row = Vec::allocate_with(row.len(), F::zero);
                            new_row[1..].clone_from_slice(&row[1..]);
                            new_row
                        }
                    })
                    .collect(),
            )
            .unwrap(),
        )
        .unwrap()
    }
}

impl<F> MdsMatrices<F>
where
    F: Clone + Field + FieldGeneration + PartialEq,
{
    /// Derives MDS matrix of size `dim*dim` and relevant things
    pub fn new(dim: usize) -> Option<Self> {
        Self::generate_mds(dim).map(Self::derive_mds_matrices)
    }

    /// Generates the mds matrix `m` for naive poseidon hash.
    /// mds matrix is constructed to be symmetry so that row-major or col-major
    /// representation gives the same output
    pub fn generate_mds(t: usize) -> Option<SquareMatrix<F>>
    where
        F: FieldGeneration,
    {
        let ys: Vec<F> = (t as u64..2 * t as u64).map(F::from_u64).collect();
        let matrix = SquareMatrix::new(
            Matrix::new(
                (0..t as u64)
                    .map(|x| {
                        ys.iter()
                            .map(|y| F::add(&F::from_u64(x), y).inverse().unwrap())
                            .collect()
                    })
                    .collect(),
            )
            .unwrap(),
        )
        .unwrap();
        if matrix.is_invertible() && matrix.is_symmetric() {
            Some(matrix)
        } else {
            None
        }
    }

    fn make_double_prime(m: &Matrix<F>, m_hat_inv: &Matrix<F>) -> SquareMatrix<F> {
        let (v, w) = Self::make_v_w(m);
        let w_hat = m_hat_inv.mul_row_vec_at_left(&w).unwrap();
        SquareMatrix::new(
            Matrix::new(
                m.iter_rows()
                    .enumerate()
                    .map(|(i, row)| match i {
                        0 => {
                            let mut new_row = Vec::with_capacity(row.len());
                            new_row.push(row[0].clone());
                            new_row.extend(v.clone());
                            new_row
                        }
                        _ => {
                            let mut new_row = vec![F::zero(); row.len()];
                            new_row[0] = w_hat[i - 1].clone();
                            new_row[i] = F::one();
                            new_row
                        }
                    })
                    .collect(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// Derives the mds matrices for optimized poseidon hash. Start from mds matrix `m` in naive poseidon hash.
    pub fn derive_mds_matrices(m: SquareMatrix<F>) -> Self {
        let m_inv = m.invert().expect("Derived MDS matrix is not invertible");
        let m_hat = m.minor(0, 0).expect("Expect minor matrix");
        let m_hat_inv = m_hat.invert().expect("Derived MDS matrix is not correct");
        let m_prime = Self::make_prime(&m);
        let m_double_prime = Self::make_double_prime(&m, &m_hat_inv);
        MdsMatrices {
            m,
            m_inv,
            m_hat,
            m_hat_inv,
            m_prime,
            m_double_prime,
        }
    }
}

/// A `SparseMatrix` is specifically one of the form of M''.
/// This means its first row and column are each dense, and the interior matrix
/// (minor to the element in both the row and column) is the identity.
/// We will pluralize this compact structure `sparse_matrixes` to distinguish from `sparse_matrices` from which they are created.
#[derive(Debug, Clone)]
pub struct SparseMatrix<F>
where
    F: Field,
{
    /// `w_hat` is the first column of the M'' matrix. It will be directly multiplied (scalar product) with a row of state elements.
    pub w_hat: Vec<F>,
    /// `v_rest` contains all but the first (already included in `w_hat`).
    pub v_rest: Vec<F>,
}

impl<F> SparseMatrix<F>
where
    F: Field,
{
    /// Checks if `self` is square and `self[1..][1..]` is identity
    fn is_sparse(m: &SquareMatrix<F>) -> bool
    where
        F: Clone,
    {
        match m.minor(0, 0) {
            Some(minor_matrix) => minor_matrix.is_identity(),
            None => false,
        }
    }

    /// Generates sparse matrix from m_double_prime matrix
    pub fn new(m_double_prime: SquareMatrix<F>) -> Self
    where
        F: Clone,
    {
        assert!(Self::is_sparse(&m_double_prime));
        let m_double_prime = Matrix::from(m_double_prime);
        let w_hat = m_double_prime.iter_rows().map(|r| r[0].clone()).collect();
        let v_rest = m_double_prime[0][1..].to_vec();
        Self { w_hat, v_rest }
    }

    /// Size of the sparse matrix
    pub fn size(&self) -> usize {
        self.w_hat.len()
    }

    /// Generates dense-matrix representation from sparse matrix representation
    pub fn to_matrix(&self) -> Matrix<F>
    where
        F: Clone,
    {
        let mut m = Matrix::identity(self.size());
        for (j, elt) in self.w_hat.iter().enumerate() {
            m[j][0] = elt.clone();
        }
        for (i, elt) in self.v_rest.iter().enumerate() {
            m[0][i + 1] = elt.clone();
        }
        m
    }
}

/// Factorizes into sparse matrices.
pub fn factor_to_sparse_matrixes<F>(
    base_matrix: SquareMatrix<F>,
    n: usize,
) -> (SquareMatrix<F>, Vec<SparseMatrix<F>>)
where
    F: Clone + Field + FieldGeneration + PartialEq,
{
    let (pre_sparse, mut sparse_matrices) =
        (0..n).fold((base_matrix.clone(), Vec::new()), |(curr, mut acc), _| {
            let derived = MdsMatrices::derive_mds_matrices(curr);
            acc.push(derived.m_double_prime);
            let new = base_matrix.matmul(&derived.m_prime).unwrap();
            (new, acc)
        });
    sparse_matrices.reverse();
    let sparse_matrices = sparse_matrices.into_iter().map(SparseMatrix::new).collect();
    (pre_sparse, sparse_matrices)
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::field_new;
    use ark_std::{test_rng, UniformRand};

    use crate::crypto::{
        constraint::arkworks::Fp, hash::poseidon::parameter_generation::matrix::Matrix,
    };

    #[test]
    fn mds_matrices_creation_is_correct() {
        for i in 2..5 {
            mds_matrices_creation_aux(i);
        }
    }

    fn mds_matrices_creation_aux(width: usize) {
        let MdsMatrices {
            m,
            m_inv,
            m_hat,
            m_hat_inv: _,
            m_prime,
            m_double_prime,
        } = MdsMatrices::<Fp<Fr>>::new(width).unwrap();

        for i in 0..m_hat.num_rows() {
            for j in 0..m_hat.num_columns() {
                assert_eq!(m[i + 1][j + 1], m_hat[i][j], "MDS minor has wrong value.");
            }
        }

        // M^-1 x M = I
        assert!(m_inv.matmul(&m).unwrap().is_identity());

        // M' x M'' = M
        assert_eq!(m, m_prime.matmul(&m_double_prime).unwrap());
    }

    #[test]
    fn swapping_is_correct() {
        swapping_aux(3)
    }

    fn swapping_aux(width: usize) {
        let mut rng = test_rng();
        let mds = MdsMatrices::<Fp<Fr>>::new(width).unwrap();

        let base = (0..width)
            .map(|_| Fp(Fr::rand(&mut rng)))
            .collect::<Vec<_>>();
        let x = {
            let mut x = base.clone();
            x[0] = Fp(Fr::rand(&mut rng));
            x
        };
        let y = {
            let mut y = base;
            y[0] = Fp(Fr::rand(&mut rng));
            y
        };

        let qx = mds.m_prime.mul_row_vec_at_left(&x).unwrap();
        let qy = mds.m_prime.mul_row_vec_at_left(&y).unwrap();
        assert_eq!(qx[0], x[0]);
        assert_eq!(qy[0], y[0]);
        assert_eq!(qx[1..], qy[1..]);

        let mx = mds.m.mul_col_vec(&x).unwrap();
        let m1_m2_x = mds
            .m_prime
            .mul_col_vec(&mds.m_double_prime.mul_col_vec(&x).unwrap())
            .unwrap();
        assert_eq!(mx, m1_m2_x);

        let xm = mds.m.mul_row_vec_at_left(&x).unwrap();
        let x_m1_m2 = mds
            .m_double_prime
            .mul_row_vec_at_left(&mds.m_prime.mul_row_vec_at_left(&x).unwrap())
            .unwrap();
        assert_eq!(xm, x_m1_m2);
    }

    #[test]
    fn mds_matches_hardcoded_sage_output() {
        // value come out from sage script
        let width = 3;

        let expected_mds = Matrix::<Fp<Fr>>::new(vec![
            vec![
                Fp(field_new!(
                    Fr,
                    "34957250116750793652965160338790643891793701667018425215069105799959054123009"
                )),
                Fp(field_new!(
                    Fr,
                    "39326906381344642859585805381139474378267914375395728366952744024953935888385"
                )),
                Fp(field_new!(
                    Fr,
                    "31461525105075714287668644304911579502614331500316582693562195219963148710708"
                )),
            ],
            vec![
                Fp(field_new!(
                    Fr,
                    "39326906381344642859585805381139474378267914375395728366952744024953935888385"
                )),
                Fp(field_new!(
                    Fr,
                    "31461525105075714287668644304911579502614331500316582693562195219963148710708"
                )),
                Fp(field_new!(
                    Fr,
                    "43696562645938492066206450423488304864742127083773031518836382249948817653761"
                )),
            ],
            vec![
                Fp(field_new!(
                    Fr,
                    "31461525105075714287668644304911579502614331500316582693562195219963148710708"
                )),
                Fp(field_new!(
                    Fr,
                    "43696562645938492066206450423488304864742127083773031518836382249948817653761"
                )),
                Fp(field_new!(
                    Fr,
                    "14981678621464625851270783002338847382197300714436467949315331057125308909861"
                )),
            ],
        ])
        .unwrap();

        let mds = MdsMatrices::<Fp<Fr>>::generate_mds(width).unwrap();
        assert_eq!(mds, expected_mds);
    }

    #[test]
    fn mds_is_invertible() {
        for t in 3..10 {
            let mds = MdsMatrices::<Fp<Fr>>::generate_mds(t).unwrap();
            assert!(mds.is_invertible());
        }
    }

    #[test]
    fn mds_is_symmetric() {
        for t in 3..10 {
            let mds = MdsMatrices::<Fp<Fr>>::generate_mds(t).unwrap();
            assert_eq!(mds, mds.clone().transpose());
        }
    }
}
