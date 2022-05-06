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

//! Generate number of full & partial rounds
//! Adapted from https://github.com/filecoin-project/neptune/blob/master/src/round_numbers.rs

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
pub fn calc_round_numbers(t: usize, security_margin: bool) -> (usize, usize) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
