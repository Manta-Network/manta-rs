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

use crate::crypto::hash::poseidon::matrix::{factor_to_sparse_matrixes, Matrix, MdsMatrices, SparseMatrix};
use core::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use crate::crypto::hash::poseidon::constants::preprocess::compress_round_constants;
use crate::crypto::hash::poseidon::constants::round_constants::generate_round_constants;
use crate::crypto::hash::poseidon::constants::round_nums::calc_round_numbers;

// TODO: shall we put constant generation code to compile time?

/// TODO doc
pub trait ParamField:
    Clone
    + Copy
    + PartialEq
    + Eq
    + Debug
    + Add<Output = Self>
    + for<'a> AddAssign<&'a Self>
    + Mul<Output = Self>
    + for<'a> MulAssign<&'a Self>
    + Sub<Output = Self>
    + for<'a> SubAssign<&'a Self>
    + From<u64>
{
    /// Number of bits of modulus of the field.
    const MODULUS_BITS: usize;

    /// TODO doc
    fn zero() -> Self;
    /// TODO doc
    fn one() -> Self;
    /// TODO doc
    fn inverse(&self) -> Option<Self>;

    /// Convert from bits in little endian order. Return None if bits is out of range.
    fn try_from_bits_le(bits: &[bool]) -> Option<Self>;

    /// Convert from bytes in little endian order. If the number of bytes is out of range, the result will be modulo.   
    fn from_le_bytes_mod_order(bytes: &[u8]) -> Self;
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

impl<F: ParamField> PoseidonConstants<F> {
    pub(crate) fn default<const WIDTH: usize>() -> Self{
        let arity = WIDTH - 1;

        let (num_full_rounds, num_partial_rounds) = calc_round_numbers(WIDTH, true);

        debug_assert_eq!(num_full_rounds % 2, 0);
        let num_half_full_rounds = num_full_rounds / 2;
        let (round_constants, _) = generate_round_constants(
            F::MODULUS_BITS as u64,
            WIDTH.try_into().expect("WIDTH is too large"),
            num_full_rounds
                .try_into()
                .expect("num_full_rounds is too large"),
            num_partial_rounds
                .try_into()
                .expect("num_partial_rounds is too large"),
        );
        let domain_tag = F::from(((1 << arity) - 1) as u64);

        let mds_matrices = MdsMatrices::new(WIDTH);

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

pub(crate) mod lfsr {
    use crate::crypto::hash::poseidon::constants::ParamField;

    /// LFSR for randomness in Poseidon round constants.
    // adapted from: https://github.com/arkworks-rs/sponge/blob/51d6fc9aac1fa69f44a04839202b5de828584ed8/src/poseidon/grain_lfsr.rs
    pub(crate) struct GrainLFSR {
        state: [bool; 80],
        prime_num_bits: u64,
        head: usize,
    }

    fn append_bits<T: Into<u128>>(state: &mut [bool; 80], head: &mut usize, n: usize, from: T) {
        let val = from.into() as u128;
        for i in (0..n).rev() {
            state[*head] = (val >> i) & 1 != 0;
            *head += 1;
            *head %= 80;
        }
    }

    impl GrainLFSR {
        /// Create a new LFSR with given parameters: prime number bits, width of the state, number of full rounds, and number of partial rounds.
        pub(crate) fn new(prime_num_bits: u64, width: usize, r_f: usize, r_p: usize) -> Self {
            let mut init_sequence = [false; 80];
            let mut head = 0;
            // b0, b1 describes the field
            append_bits(&mut init_sequence, &mut head, 2, 1u8);
            // b2...=b5 describes s-box: we always use non-inverse s-box
            append_bits(&mut init_sequence, &mut head, 4, 0b00000u8);
            // b6...=b17 describes prime_num_bits
            append_bits(&mut init_sequence, &mut head, 12, prime_num_bits);
            // b18...=b29 describes width
            append_bits(&mut init_sequence, &mut head, 12, width as u16);
            // b30..=39 describes r_f (num_full_rounds)
            append_bits(&mut init_sequence, &mut head, 10, r_f as u16);
            // b40..=49 describes r_p (num_partial_rounds)
            append_bits(&mut init_sequence, &mut head, 10, r_p as u16);
            // b50..=79 describes the constant 1
            append_bits(
                &mut init_sequence,
                &mut head,
                30,
                0b111111111111111111111111111111u128,
            );
            let mut res = GrainLFSR {
                state: init_sequence,
                prime_num_bits,
                head,
            };
            res.init();
            res
        }

        fn update(&mut self) -> bool {
            let new_bit = self.bit(62)
                ^ self.bit(51)
                ^ self.bit(38)
                ^ self.bit(23)
                ^ self.bit(13)
                ^ self.bit(0);
            self.state[self.head] = new_bit;
            self.head += 1;
            self.head %= 80;
            new_bit
        }

        fn init(&mut self) {
            for _ in 0..160 {
                self.update();
            }
        }

        #[inline]
        fn bit(&self, index: usize) -> bool {
            self.state[(index + self.head) % 80]
        }

        /// TODO: doc
        pub fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
            let mut res = Vec::new();

            for _ in 0..num_bits {
                // Obtain the first bit
                let mut new_bit = self.update();

                // Loop until the first bit is true
                while new_bit == false {
                    // Discard the second bit
                    let _ = self.update();
                    // Obtain another first bit
                    new_bit = self.update();
                }

                // Obtain the second bit
                res.push(self.update());
            }

            res
        }

        /// TODO: doc
        pub fn get_field_elements_rejection_sampling<F: ParamField>(
            &mut self,
            num_elems: usize,
        ) -> Vec<F> {
            assert_eq!(F::MODULUS_BITS as u64, self.prime_num_bits);

            let mut res = Vec::new();
            for _ in 0..num_elems {
                // Perform rejection sampling
                loop {
                    // Obtain n bits and make it most-significant-bit first
                    let mut bits = self.get_bits(self.prime_num_bits as usize);
                    bits.reverse();

                    // Construct the number
                    if let Some(f) = F::try_from_bits_le(&bits) {
                        res.push(f);
                        break;
                    }
                }
            }

            res
        }

        /// TODO: doc
        pub fn get_field_elements_mod_p<F: ParamField>(&mut self, num_elems: usize) -> Vec<F> {
            assert_eq!(F::MODULUS_BITS as u64, self.prime_num_bits);

            let mut res = Vec::new();
            for _ in 0..num_elems {
                // Obtain n bits and make it most-significant-bit first
                let mut bits = self.get_bits(self.prime_num_bits as usize);
                bits.reverse();

                let bytes = bits
                    .chunks(8)
                    .map(|chunk| {
                        let mut result = 0u8;
                        for (i, bit) in chunk.iter().enumerate() {
                            result |= u8::from(*bit) << i
                        }
                        result
                    })
                    .collect::<Vec<u8>>();

                res.push(F::from_le_bytes_mod_order(&bytes));
            }

            res
        }
    }
}

pub(crate) mod round_constants{
    use crate::crypto::hash::poseidon::constants::lfsr::GrainLFSR;
    use crate::crypto::hash::poseidon::constants::ParamField;

    /// return round constants, and return the LFSR used to generate MDS matrix
    pub(crate) fn generate_round_constants<F: ParamField>(
        prime_num_bits: u64,
        width: usize,
        r_f: usize,
        r_p: usize,
    ) -> (Vec<F>, GrainLFSR) {
        let num_constants = (r_f + r_p) * width;
        let mut lfsr = GrainLFSR::new(prime_num_bits, width, r_f, r_p);
        (lfsr.get_field_elements_rejection_sampling(num_constants), lfsr)
    }

}

pub(crate) mod round_nums{

    // Adapted from https://github.com/filecoin-project/neptune/blob/master/src/round_numbers.rs

    // The number of bits of the Poseidon prime field modulus. Denoted `n` in the Poseidon paper
// (where `n = ceil(log2(p))`). Note that BLS12-381's scalar field modulus is 255 bits, however we
// use 256 bits for simplicity when operating on bytes as the single bit difference does not affect
// the round number security properties.
    const PRIME_BITLEN: usize = 256;

    // Security level (in bits), denoted `M` in the Poseidon paper.
    const M: usize = 128;

    /// The number of S-boxes (also called the "cost") given by equation (14) in the Poseidon paper:
    /// `cost = t * R_F + R_P`.
    fn n_sboxes(t: usize, rf: usize, rp: usize) -> usize {
        t * rf + rp
    }


    /// Returns the round numbers for a given arity `(R_F, R_P)`.
    pub fn round_numbers_base(arity: usize) -> (usize, usize) {
        let t = arity + 1;
        calc_round_numbers(t, true)
    }

    /// In case of newly-discovered attacks, we may need stronger security.
    /// This option exists so we can preemptively create circuits in order to switch
    /// to them quickly if needed.
    ///
    /// "A realistic alternative is to increase the number of partial rounds by 25%.
    /// Then it is unlikely that a new attack breaks through this number,
    /// but even if this happens then the complexity is almost surely above 2^64, and you will be safe."
    /// - D Khovratovich
    pub fn round_numbers_strengthened(arity: usize) -> (usize, usize) {
        let (full_round, partial_rounds) = round_numbers_base(arity);

        // Increase by 25%, rounding up.
        let strengthened_partial_rounds = f64::ceil(partial_rounds as f64 * 1.25) as usize;

        (full_round, strengthened_partial_rounds)
    }

    /// Returns the round numbers for a given width `t`. Here, the `security_margin` parameter does not
    /// indicate that we are calculating `R_F` and `R_P` for the "strengthened" round numbers, done in
    /// the function `round_numbers_strengthened()`.
    pub(crate) fn calc_round_numbers(t: usize, security_margin: bool) -> (usize, usize) {
        let mut rf = 0;
        let mut rp = 0;
        let mut n_sboxes_min = usize::MAX;

        for mut rf_test in (2..=1000).step_by(2) {
            for mut rp_test in 4..200 {
                if round_numbers_are_secure(t, rf_test, rp_test) {
                    if security_margin {
                        rf_test += 2;
                        rp_test = (1.075 * rp_test as f32).ceil() as usize;
                    }
                    let n_sboxes = n_sboxes(t, rf_test, rp_test);
                    if n_sboxes < n_sboxes_min || (n_sboxes == n_sboxes_min && rf_test < rf) {
                        rf = rf_test;
                        rp = rp_test;
                        n_sboxes_min = n_sboxes;
                    }
                }
            }
        }

        (rf, rp)
    }

    /// Returns `true` if the provided round numbers satisfy the security inequalities specified in the
    /// Poseidon paper.
    fn round_numbers_are_secure(t: usize, rf: usize, rp: usize) -> bool {
        let (rp, t, n, m) = (rp as f32, t as f32, PRIME_BITLEN as f32, M as f32);
        let rf_stat = if m <= (n - 3.0) * (t + 1.0) {
            6.0
        } else {
            10.0
        };
        let rf_interp = 0.43 * m + t.log2() - rp;
        let rf_grob_1 = 0.21 * n - rp;
        let rf_grob_2 = (0.14 * n - 1.0 - rp) / (t - 1.0);
        let rf_max = [rf_stat, rf_interp, rf_grob_1, rf_grob_2]
            .iter()
            .map(|rf| rf.ceil() as usize)
            .max()
            .unwrap();
        rf >= rf_max
    }

}

pub(crate) mod preprocess{
    use crate::crypto::hash::poseidon::constants::ParamField;
    use crate::crypto::hash::poseidon::matrix::{MdsMatrices, vec_add};

    // acknowledgement: adapted from FileCoin Project: https://github.com/filecoin-project/neptune/blob/master/src/preprocessing.rs
    /// Compress constants by pushing them back through linear layers and through the identity components of partial layers.
    /// As a result, constants need only be added after each S-box.
    pub(crate) fn compress_round_constants<F: ParamField>(
        width: usize,
        full_rounds: usize,
        partial_rounds: usize,
        round_constants: &Vec<F>,
        mds_matrices: &MdsMatrices<F>,
    ) -> Vec<F> {
        let inverse_matrix = &mds_matrices.m_inv;

        let mut res: Vec<F> = Vec::new();

        let round_keys = |r: usize| &round_constants[r*width..(r+1)*width];

        // This is half full-rounds.
        let half_full_rounds = full_rounds/2;

        // First round constants are unchanged.
        res.extend(round_keys(0));

        // Post S-box adds for the first set of full rounds should be 'inverted' from next round.
        // The final round is skipped when fully preprocessing because that value must be obtained from the result of preprocessing the partial rounds.
        let end = half_full_rounds - 1;
        for i in 0..end {
            let next_round = round_keys(i+1);
            let inverted = inverse_matrix.right_apply(next_round);
            res.extend(inverted);
        }

        // The plan:
        // - Work backwards from last row in this group
        // - Invert the row.
        // - Save first constant (corresponding to the one S-box performed).
        // - Add inverted result to previous row.
        // - Repeat until all partial round key rows have been consumed.
        // - Extend the preprocessed result by the final resultant row.
        // - Move the accumulated list of single round keys to the preprocesed result.
        // - (Last produced should be first applied, so either pop until empty, or reverse and extend, etc.)

        // 'partial_keys' will accumulated the single post-S-box constant for each partial-round, in reverse order.
        let mut partial_keys: Vec<F> = Vec::new();

        let final_round = half_full_rounds + partial_rounds;
        let final_round_key = round_keys(final_round).to_vec();

        // 'round_acc' holds the accumulated result of inverting and adding subsequent round constants (in reverse).
        let round_acc = (0..partial_rounds)
            .map(|i| round_keys(final_round - i - 1))
            .fold(final_round_key, |acc, previous_round_keys| {
                let mut inverted = inverse_matrix.right_apply(&acc);

                partial_keys.push(inverted[0]);
                inverted[0] = F::zero();

                vec_add(&previous_round_keys, &inverted)
            });

        res.extend(inverse_matrix.right_apply(&round_acc));

        while let Some(x) = partial_keys.pop() {
            res.push(x)
        }

        // Post S-box adds for the first set of full rounds should be 'inverted' from next round.
        for i in 1..(half_full_rounds) {
            let start = half_full_rounds + partial_rounds;
            let next_round = round_keys(i + start);
            let inverted = inverse_matrix.right_apply(next_round);
            res.extend(inverted);
        }

        res
    }

}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::field_new;
    use crate::crypto::hash::poseidon::constants::round_nums::calc_round_numbers;
    use super::lfsr::GrainLFSR;
    #[test]
    fn test_grain_lfsr_consistency() {
        // sage generate_parameters_grain_deterministic.sage 1 0 255 3 8 55 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

        let mut lfsr = GrainLFSR::new(255, 3, 8, 55);
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fr>(1)[0],
            field_new!(
                Fr,
                "41764196652518280402801918994067134807238124178723763855975902025540297174931"
            )
        );
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fr>(1)[0],
            field_new!(
                Fr,
                "12678502092746318913289523392430826887011664085277767208266352862540971998250"
            )
        );
    }

    #[test]
    fn test_round_numbers_against_known_values() {
        // Each case contains a `t` (where `t = arity + 1`) and the `R_P` expected for that `t`.
        let cases = [
            (2usize, 55usize),
            (3, 55),
            (4, 56),
            (5, 56),
            (6, 56),
            (7, 56),
            (8, 57),
            (9, 57),
            (10, 57),
            (11, 57),
            (12, 57),
            (13, 57),
            (14, 57),
            (15, 57),
            (16, 59),
            (17, 59),
            (25, 59),
            (37, 60),
            (65, 61),
        ];
        for (t, rp_expected) in cases.iter() {
            let (rf, rp) = calc_round_numbers(*t, true);
            assert_eq!(rf, 8);
            assert_eq!(rp, *rp_expected);
        }
    }
}
