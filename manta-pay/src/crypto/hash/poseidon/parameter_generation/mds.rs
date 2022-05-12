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

use crate::crypto::hash::{poseidon::parameter_generation::matrix::Matrix, ParamField};
use alloc::{vec, vec::Vec};
use core::fmt::Debug;

/// MDS Matrix for both naive poseidon hash and optimized poseidon hash
/// For detailed descriptions, please refer to <https://hackmd.io/8MdoHwoKTPmQfZyIKEYWXQ>
/// Note: Naive and optimized poseidon hash does not change #constraints in Groth16.
pub struct MdsMatrices<F>
where
    F: ParamField,
{
    /// MDS Matrix for naive poseidon hash
    pub m: Matrix<F>,
    /// inversion of mds matrix. Used in optimzed poseidon hash.
    pub m_inv: Matrix<F>,
    /// m_hat matrix. Used in optimized poseidon hash
    pub m_hat: Matrix<F>,
    /// Inversion of m_hat matrix. Used in optimized poseidon hash.
    pub m_hat_inv: Matrix<F>,
    /// m prime matrix. Used in optimized poseidon hash.
    pub m_prime: Matrix<F>,
    /// m double prime matrix. Used in optimized poseidon hash.
    pub m_double_prime: Matrix<F>,
}

impl<F> Clone for MdsMatrices<F>
where
    F: ParamField + Clone,
{
    fn clone(&self) -> Self {
        MdsMatrices {
            m: self.m.clone(),
            m_inv: self.m_inv.clone(),
            m_hat: self.m_hat.clone(),
            m_hat_inv: self.m_hat_inv.clone(),
            m_prime: self.m_prime.clone(),
            m_double_prime: self.m_double_prime.clone(),
        }
    }
}

impl<F> MdsMatrices<F>
where
    F: ParamField + Clone + Copy,
{
    fn make_v_w(m: &Matrix<F>) -> (Vec<F>, Vec<F>) {
        let v = m[0][1..].to_vec();
        let w = m.iter_rows().skip(1).map(|column| column[0]).collect();
        (v, w)
    }
}

impl<F> MdsMatrices<F>
where
    F: ParamField + Copy,
{
    fn make_prime(m: &Matrix<F>) -> Matrix<F> {
        m.iter_rows()
            .enumerate()
            .map(|(i, row)| match i {
                0 => {
                    let mut new_row = vec![F::zero(); row.len()];
                    new_row[0] = F::one();
                    new_row
                }
                _ => {
                    let mut new_row = vec![F::zero(); row.len()];
                    new_row[1..].copy_from_slice(&row[1..]);
                    new_row
                }
            })
            .collect()
    }
}

impl<F> MdsMatrices<F>
where
    F: ParamField + Copy + PartialEq + Debug,
{
    /// Derives MDS matrix of size `dim*dim` and relevant things
    pub fn new(dim: usize) -> Self {
        let m = Self::generate_mds(dim);
        Self::derive_mds_matrices(m)
    }

    /// Generates the mds matrix `m` for naive poseidon hash.
    pub fn generate_mds(t: usize) -> Matrix<F> {
        let xs: Vec<F> = (0..t as u64).map(F::from_u64_to_param).collect();
        let ys: Vec<F> = (t as u64..2 * t as u64).map(F::from_u64_to_param).collect();

        let matrix = xs
            .iter()
            .map(|xs_item| {
                ys.iter()
                    .map(|ys_item| {
                        // Generate the entry at (i,j)
                        let mut tmp = *xs_item;
                        F::add_assign(&mut tmp, ys_item);
                        F::inverse(&tmp).unwrap()
                    })
                    .collect()
            })
            .collect::<Matrix<F>>();

        assert!(matrix.is_invertible());
        assert_eq!(matrix.0, matrix.transpose().0);
        matrix
    }

    fn make_double_prime(m: &Matrix<F>, m_hat_inv: &Matrix<F>) -> Matrix<F> {
        let (v, w) = Self::make_v_w(m);
        let w_hat = m_hat_inv.right_apply(&w);

        m.iter_rows()
            .enumerate()
            .map(|(i, row)| match i {
                0 => {
                    let mut new_row = Vec::with_capacity(row.len());
                    new_row.push(row[0]);
                    new_row.extend(&v);
                    new_row
                }
                _ => {
                    let mut new_row = vec![F::zero(); row.len()];
                    new_row[0] = w_hat[i - 1];
                    new_row[i] = F::one();
                    new_row
                }
            })
            .collect()
    }

    /// Derives the mds matrices for optimized poseidon hash. Start from mds matrix `m` in naive poseidon hash.
    pub fn derive_mds_matrices(m: Matrix<F>) -> Self {
        let m_inv = m.invert().expect("Derived MDS matrix is not invertible");
        let m_hat = m.minor(0, 0);
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
    F: ParamField,
{
    /// `w_hat` is the first column of the M'' matrix. It will be directly multiplied (scalar product) with a row of state elements.
    pub w_hat: Vec<F>,
    /// `v_rest` contains all but the first (already included in `w_hat`).
    pub v_rest: Vec<F>,
}

impl<F> SparseMatrix<F>
where
    F: ParamField + Copy,
{
    /// Generates sparse matrix from m_double_prime matrix
    pub fn new(m_double_prime: &Matrix<F>) -> Self {
        assert!(m_double_prime.is_sparse());

        let w_hat = m_double_prime.iter_rows().map(|r| r[0]).collect();
        let v_rest = m_double_prime[0][1..].to_vec();
        Self { w_hat, v_rest }
    }

    /// Size of the sparse matrix
    pub fn size(&self) -> usize {
        self.w_hat.len()
    }

    /// Generates dense-matrix representation from sparse matrix representation
    pub fn to_matrix(&self) -> Matrix<F> {
        let mut m = Matrix::identity(self.size());
        for (j, elt) in self.w_hat.iter().enumerate() {
            m[j][0] = *elt;
        }
        for (i, elt) in self.v_rest.iter().enumerate() {
            m[0][i + 1] = *elt;
        }
        m
    }
}

/// Factorizes into sparse matrices.
pub fn factor_to_sparse_matrixes<F>(
    base_matrix: Matrix<F>,
    n: usize,
) -> (Matrix<F>, Vec<SparseMatrix<F>>)
where
    F: ParamField + Clone + Copy + Debug + PartialEq,
{
    let (pre_sparse, mut sparse_matrices) =
        (0..n).fold((base_matrix.clone(), Vec::new()), |(curr, mut acc), _| {
            let derived = MdsMatrices::derive_mds_matrices(curr);
            acc.push(derived.m_double_prime);
            let new = base_matrix.matmul(&derived.m_prime).unwrap();
            (new, acc)
        });
    sparse_matrices.reverse();
    let sparse_matrixes = sparse_matrices
        .iter()
        .map(|m| SparseMatrix::<F>::new(m))
        .collect::<Vec<_>>();

    (pre_sparse, sparse_matrixes)
}

#[cfg(test)]
mod tests {
    use super::MdsMatrices;
    use ark_bls12_381::Fr;
    use ark_ff::field_new;
    use ark_std::{test_rng, UniformRand};

    use crate::crypto::{
        constraint::arkworks::Fp, hash::poseidon::parameter_generation::matrix::Matrix,
    };

    #[test]
    fn test_mds_matrices_creation() {
        for i in 2..5 {
            test_mds_matrices_creation_aux(i);
        }
    }

    fn test_mds_matrices_creation_aux(width: usize) {
        let MdsMatrices {
            m,
            m_inv,
            m_hat,
            m_hat_inv: _,
            m_prime,
            m_double_prime,
        } = MdsMatrices::<Fp<Fr>>::new(width);

        for i in 0..m_hat.num_rows() {
            for j in 0..m_hat.num_columns() {
                assert_eq!(m[i + 1][j + 1], m_hat[i][j], "MDS minor has wrong value.");
            }
        }

        // M^-1 x M = I
        assert!(m_inv.matmul(&m).unwrap().is_identity());

        // M' x M'' = M
        assert_eq!(m.0, m_prime.matmul(&m_double_prime).unwrap().0);
    }

    #[test]
    fn test_swapping() {
        test_swapping_aux(3)
    }

    fn test_swapping_aux(width: usize) {
        let mut rng = test_rng();
        let mds = MdsMatrices::<Fp<Fr>>::new(width);

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

        let qx = mds.m_prime.right_apply(&x);
        let qy = mds.m_prime.right_apply(&y);
        assert_eq!(qx[0], x[0]);
        assert_eq!(qy[0], y[0]);
        assert_eq!(qx[1..], qy[1..]);

        let mx = mds.m.left_apply(&x);
        let m1_m2_x = mds.m_prime.left_apply(&mds.m_double_prime.left_apply(&x));
        assert_eq!(mx, m1_m2_x);

        let xm = mds.m.right_apply(&x);
        let x_m1_m2 = mds.m_double_prime.right_apply(&mds.m_prime.right_apply(&x));
        assert_eq!(xm, x_m1_m2);
    }

    #[test]
    fn test_mds_creation_hardcoded() {
        // value come out from sage script
        let width = 3;

        let expected_mds = Matrix::<Fp<Fr>>(vec![
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
        ]);

        let mds = MdsMatrices::<Fp<Fr>>::generate_mds(width);
        assert_eq!(mds.0, expected_mds.0);
    }
}
