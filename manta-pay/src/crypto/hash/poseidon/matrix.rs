
use core::fmt::Debug;
use std::ops::{Index, IndexMut};
use crate::crypto::hash::poseidon::constants::ParamField;

#[derive(Clone, Eq, PartialEq, Debug, Default)]
/// TODO doc
pub struct Matrix<F: ParamField>(pub Vec<Vec<F>>);

impl<F: ParamField> From<Vec<Vec<F>>> for Matrix<F> {
    fn from(v: Vec<Vec<F>>) -> Self {
        Matrix(v)
    }
}

impl<F: ParamField> Matrix<F> {
    /// TODO doc
    pub fn num_rows(&self) -> usize {
        self.0.len()
    }
    /// TODO doc
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
    /// TODO doc
    pub fn iter_rows<'a>(&'a self) -> impl Iterator<Item = &'a Vec<F>> {
        self.0.iter()
    }
    /// TODO doc
    pub fn column(&self, column: usize) -> impl Iterator<Item = &'_ F> {
        self.0.iter().map(move |row| &row[column])
    }
    /// TODO doc
    pub fn is_square(&self) -> bool {
        self.num_rows() == self.num_columns()
    }
    /// TODO doc
    pub fn transpose(&self) -> Matrix<F> {
        let size = self.num_rows();
        let mut new = Vec::with_capacity(size);
        for j in 0..size {
            let mut row = Vec::with_capacity(size);
            for i in 0..size {
                row.push(self.0[i][j].clone())
            }
            new.push(row);
        }
        Matrix(new)
    }
}

impl<F: ParamField> Index<usize> for Matrix<F> {
    type Output = Vec<F>;
    /// TODO doc
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<F: ParamField> IndexMut<usize> for Matrix<F> {
    /// TODO doc
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

// from iterator rows
impl<F: ParamField> FromIterator<Vec<F>> for Matrix<F> {
    /// TODO doc
    fn from_iter<T: IntoIterator<Item = Vec<F>>>(iter: T) -> Self {
        let rows = iter.into_iter().collect::<Vec<_>>();
        Self(rows)
    }
}


impl<F: ParamField> Matrix<F> {
    /// return an identity matrix of size `n*n`
    pub fn identity(n: usize) -> Matrix<F> {
        let mut m = Matrix(vec![vec![F::zero(); n]; n]);
        for i in 0..n {
            m.0[i][i] = F::one();
        }
        m
    }

    /// TODO doc
    pub fn is_identity(&self) -> bool {
        if !self.is_square() {
            return false;
        }
        for i in 0..self.num_rows() {
            for j in 0..self.num_columns() {
                if self.0[i][j] != kronecker_delta(i, j) {
                    return false;
                }
            }
        }
        true
    }

    /// TODO doc
    /// check if `self` is square and `self[1..][1..]` is identity
    pub fn is_sparse(&self) -> bool {
        self.is_square() && self.minor(0, 0).is_identity()
    }

    /// TODO doc
    pub fn mul_by_scalar(&self, scalar: F) -> Self {
        let res = self
            .0
            .iter()
            .map(|row| {
                row.iter()
                    .map(|val| {
                        let mut prod = scalar;
                        prod.mul_assign(val);
                        prod
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Matrix(res)
    }

    /// return `self @ vec`, treating `vec` as a column vector.
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
                let mut tmp = *mat_val;
                tmp.mul_assign(vec_val);
                result.add_assign(&tmp);
            }
        }
        result
    }

    /// return `vec @ self`, treat `vec` as a row vector.
    pub fn right_apply(&self, v: &[F]) -> Vec<F> {
        self.mul_row_vec_at_left(v)
    }

    /// return `self @ vec`, treating `vec` as a column vector.
    pub fn left_apply(&self, v: &[F]) -> Vec<F> {
        self.mul_col_vec(v)
    }

    /// return `vec @ self`, treating `vec` as a row vector.
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
                let mut tmp = row[j];
                tmp.mul_assign(&v[i]);
                val.add_assign(&tmp);
            }
        }
        result
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
                    .map(|transposed_column| inner_product(&input_row, &transposed_column))
                    .collect()
            })
            .collect();
        Some(Matrix(res))
    }

    /// TODO doc
    pub fn invert(&self) -> Option<Self> {
        let mut shadow = Self::identity(self.num_columns());
        let ut = self.upper_triangular(&mut shadow);

        ut.and_then(|x| x.reduce_to_identity(&mut shadow))
            .and(Some(shadow))
    }

    /// TODO doc
    fn is_invertible(&self) -> bool {
        self.is_square() && self.invert().is_some()
    }

    fn minor(&self, i: usize, j: usize) -> Self {
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

    /// Assumes matrix is partially reduced to upper triangular. `column` is the
    /// column to eliminate from all rows. Returns `None` if either:
    ///   - no non-zero pivot can be found for `column`
    ///   - `column` is not the first
    pub fn eliminate(&self, column: usize, shadow: &mut Self) -> Option<Self> {
        let zero = F::zero();
        let pivot_index = (0..self.num_rows())
            .find(|&i| self[i][column] != zero && (0..column).all(|j| self[i][j] == zero))?;

        let pivot = &self[pivot_index];
        let pivot_val = pivot[column];

        // This should never fail since we have a non-zero `pivot_val` if we got here.
        let inv_pivot = pivot_val.inverse()?;
        let mut result = Vec::with_capacity(self.num_rows());
        result.push(pivot.clone());

        for (i, row) in self.iter_rows().enumerate() {
            if i == pivot_index {
                continue;
            };

            let val = row[column];
            if val == zero {
                result.push(row.to_vec());
            } else {
                let factor = val * inv_pivot;
                let scaled_pivot = scalar_vec_mul(factor, &pivot[..]);
                let eliminated = vec_sub(row, &scaled_pivot);
                result.push(eliminated);

                let shadow_pivot = &shadow[pivot_index];
                let scaled_shadow_pivot = scalar_vec_mul(factor, shadow_pivot);
                let shadow_row = &shadow[i];
                shadow[i] = vec_sub(shadow_row, &scaled_shadow_pivot);
            }
        }

        let pivot_row = shadow.0.remove(pivot_index);
        shadow.0.insert(0, pivot_row);

        Some(result.into())
    }

    /// TODO doc
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

            curr = Matrix(curr.0[1..].to_vec());
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
        let mut result: Vec<Vec<F>> = Vec::new();
        let mut shadow_result: Vec<Vec<F>> = Vec::new();

        for i in 0..size {
            let idx = size - i - 1;
            let row = &self.0[idx];
            let shadow_row = &shadow[idx];

            let val = row[idx];
            let inv = val.inverse()?;

            let mut normalized = scalar_vec_mul(inv, &row);
            let mut shadow_normalized = scalar_vec_mul(inv, &shadow_row);

            for j in 0..i {
                let idx = size - j - 1;
                let val = normalized[idx];
                let subtracted = scalar_vec_mul(val, &result[j]);
                let result_subtracted = scalar_vec_mul(val, &shadow_result[j]);

                normalized = vec_sub(&normalized, &subtracted);
                shadow_normalized = vec_sub(&shadow_normalized, &result_subtracted);
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
/// TODO doc
pub fn inner_product<F: ParamField>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b).fold(F::zero(), |mut acc, (v1, v2)| {
        let mut tmp = *v1;
        tmp.mul_assign(v2);
        acc.add_assign(&tmp);
        acc
    })
}
/// TODO doc
pub fn vec_add<F: ParamField>(a: &[F], b: &[F]) -> Vec<F> {
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| {
            let mut res = *a;
            res.add_assign(b);
            res
        })
        .collect::<Vec<_>>()
}
/// TODO doc
pub fn vec_sub<F: ParamField>(a: &[F], b: &[F]) -> Vec<F> {
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| {
            let mut res = *a;
            res.sub_assign(b);
            res
        })
        .collect::<Vec<_>>()
}
/// TODO doc
fn scalar_vec_mul<F: ParamField>(scalar: F, v: &[F]) -> Vec<F> {
    v.iter()
        .map(|val| {
            let mut prod = scalar;
            prod.mul_assign(val);
            prod
        })
        .collect::<Vec<_>>()
}
/// TODO doc
pub fn kronecker_delta<F: ParamField>(i: usize, j: usize) -> F {
    if i == j {
        F::one()
    } else {
        F::zero()
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
/// TODO doc
pub struct MdsMatrices<F: ParamField> {
    /// TODO doc
    pub m: Matrix<F>,
    /// TODO doc
    pub m_inv: Matrix<F>,
    /// TODO doc
    pub m_hat: Matrix<F>,
    /// TODO doc
    pub m_hat_inv: Matrix<F>,
    /// TODO doc
    pub m_prime: Matrix<F>,
    /// TODO doc
    pub m_double_prime: Matrix<F>,
}

impl<F: ParamField> MdsMatrices<F> {
    /// Derive MDS matrix of size `dim*dim` and relevant things
    pub fn new(dim: usize) -> Self {
        let m = Self::generate_mds(dim);
        Self::derive_mds_matrices(m)
    }

    pub(crate) fn derive_mds_matrices(m: Matrix<F>) -> Self {
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

    fn generate_mds(t: usize) -> Matrix<F> {
        let xs: Vec<F> = (0..t as u64).map(F::from).collect();
        let ys: Vec<F> = (t as u64..2 * t as u64).map(F::from).collect();

        let matrix = xs
            .iter()
            .map(|xs_item| {
                ys.iter()
                    .map(|ys_item| {
                        // Generate the entry at (i,j)
                        let mut tmp = *xs_item;
                        tmp.add_assign(ys_item);
                        tmp.inverse().unwrap()
                    })
                    .collect()
            })
            .collect::<Matrix<F>>();

        assert!(matrix.is_invertible());
        assert_eq!(matrix, matrix.transpose());
        matrix
    }

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

    fn make_v_w(m: &Matrix<F>) -> (Vec<F>, Vec<F>) {
        let v = m[0][1..].to_vec();
        let w = m.iter_rows().skip(1).map(|column| column[0]).collect();
        (v, w)
    }
}

/// A `SparseMatrix` is specifically one of the form of M''.
/// This means its first row and column are each dense, and the interior matrix
/// (minor to the element in both the row and column) is the identity.
/// We will pluralize this compact structure `sparse_matrixes` to distinguish from `sparse_matrices` from which they are created.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SparseMatrix<F: ParamField> {
    /// `w_hat` is the first column of the M'' matrix. It will be directly multiplied (scalar product) with a row of state elements.
    pub w_hat: Vec<F>,
    /// `v_rest` contains all but the first (already included in `w_hat`).
    pub v_rest: Vec<F>,
}

impl<F: ParamField> SparseMatrix<F> {
    /// TODO doc
    pub fn new(m_double_prime: &Matrix<F>) -> Self {
        assert!(m_double_prime.is_sparse());

        let w_hat = m_double_prime.iter_rows().map(|r| r[0]).collect();
        let v_rest = m_double_prime[0][1..].to_vec();
        Self { w_hat, v_rest }
    }
    /// TODO doc
    pub fn size(&self) -> usize {
        self.w_hat.len()
    }
    /// TODO doc
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
/// TODO doc
pub fn factor_to_sparse_matrixes<F: ParamField>(
    base_matrix: Matrix<F>,
    n: usize,
) -> (Matrix<F>, Vec<SparseMatrix<F>>) {
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
mod tests{

    use ark_ff::{field_new};
    use crate::crypto::hash::poseidon::matrix::{Matrix, MdsMatrices};
    use ark_bls12_381::Fr;

    #[test]
    /// Test on arkworks bls12-381
    fn test_mds_creation_hardcoded() {
        // value come out from sage script
        let width = 3;

        let expected_mds = Matrix(vec![
            vec![
                field_new!(
                    Fr,
                    "34957250116750793652965160338790643891793701667018425215069105799959054123009"
                ),
                field_new!(
                    Fr,
                    "39326906381344642859585805381139474378267914375395728366952744024953935888385"
                ),
                field_new!(
                    Fr,
                    "31461525105075714287668644304911579502614331500316582693562195219963148710708"
                ),
            ],
            vec![
                field_new!(
                    Fr,
                    "39326906381344642859585805381139474378267914375395728366952744024953935888385"
                ),
                field_new!(
                    Fr,
                    "31461525105075714287668644304911579502614331500316582693562195219963148710708"
                ),
                field_new!(
                    Fr,
                    "43696562645938492066206450423488304864742127083773031518836382249948817653761"
                ),
            ],
            vec![
                field_new!(
                    Fr,
                    "31461525105075714287668644304911579502614331500316582693562195219963148710708"
                ),
                field_new!(
                    Fr,
                    "43696562645938492066206450423488304864742127083773031518836382249948817653761"
                ),
                field_new!(
                    Fr,
                    "14981678621464625851270783002338847382197300714436467949315331057125308909861"
                ),
            ],
        ]);

        let mds = MdsMatrices::<Fr>::generate_mds(width);
        assert_eq!(mds, expected_mds);
    }
}
