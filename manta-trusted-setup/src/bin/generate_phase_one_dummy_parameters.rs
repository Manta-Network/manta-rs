// // Copyright 2019-2022 Manta Network.
// // This file is part of manta-rs.
// //
// // manta-rs is free software: you can redistribute it and/or modify
// // it under the terms of the GNU General Public License as published by
// // the Free Software Foundation, either version 3 of the License, or
// // (at your option) any later version.
// //
// // manta-rs is distributed in the hope that it will be useful,
// // but WITHOUT ANY WARRANTY; without even the implied warranty of
// // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// // GNU General Public License for more details.
// //
// // You should have received a copy of the GNU General Public License
// // along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

// //! Generates Dummy Phase One Parameters

use manta_crypto::{
    arkworks::serialize::CanonicalSerialize,
    rand::{OsRng, Sample},
};
use manta_trusted_setup::groth16::kzg::{Accumulator, Contribution};
use std::{fs::File, io::Write};

type Config = manta_trusted_setup::groth16::config::Config;

// TODO: To be replaced with production circuit.
/// Conducts a dummy phase one trusted setup.
#[inline]
pub fn dummy_phase_one_trusted_setup() -> Accumulator<Config> {
    let mut rng = OsRng;
    let accumulator = Accumulator::default();
    let challenge = [0; 64];
    let contribution = Contribution::gen(&mut rng);
    let proof = contribution
        .proof(&challenge, &mut rng)
        .expect("The contribution proof should have been generated correctly.");
    let mut next_accumulator = accumulator.clone();
    next_accumulator.update(&contribution);
    Accumulator::verify_transform(accumulator, next_accumulator, challenge, proof)
        .expect("Accumulator should have been generated correctly.")
}

fn main() {
    let powers = dummy_phase_one_trusted_setup(); // TODO: To be replaced with disk file
    let path = "dummy_phase_one_parameter.data";
    let mut writer = Vec::new();
    CanonicalSerialize::serialize(&powers, &mut writer)
        .expect("Serialize accumulator should succceed.");
    let mut file = File::create(path).expect("Open file should succeed.");
    file.write_all(&writer)
        .expect("Write phase one parameters to disk should succeed.");
    file.flush().expect("Unable to flush file.");
}
