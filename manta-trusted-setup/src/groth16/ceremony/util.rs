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

//! Utilities

extern crate alloc;

use manta_crypto::arkworks::pairing::Pairing;
use manta_util::{
    serde::{de::DeserializeOwned, Serialize},
    BoxArray,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use crate::groth16::mpc::State;

use super::message::ServerSize;

/// Logs `data` to a disk file at `path`.
#[inline]
pub fn log_to_file<T, P>(path: &P, data: &T)
where
    T: Serialize,
    P: AsRef<Path>,
{
    let mut file = File::create(path).expect("Open file should succeed.");
    let encoded = bincode::serialize(data).expect("");
    file.write_all(&encoded)
        .expect("Writing phase one parameters to disk should succeed.");
    file.flush().expect("Flushing file should succeed.");
}

/// Loads `data` from a disk file at `path`.
#[inline]
pub fn load_from_file<T, P>(path: P) -> T
where
    P: AsRef<Path>,
    T: DeserializeOwned,
{
    let mut file = File::open(path).expect("Opening file should succeed.");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("Reading data should succeed.");
    bincode::deserialize(&buf[..]).unwrap()
}

// /// Prepares phase one parameter `powers` for phase two parameters of circuit `cs` with `name`.
// #[inline]
// pub fn prepare_parameters<C, D, S>(powers: Accumulator<C>, cs: S, name: &str)
// where
//     C: Pairing + Size + kzg::Configuration + mpc::ProvingKeyHasher<C> + mpc::Configuration,
//     S: ConstraintSynthesizer<C::Scalar>,
//     D: CeremonyConfig<Setup = Groth16Phase2<C>>,
//     <C as mpc::Configuration>::Challenge:
//         From<<C as mpc::ProvingKeyHasher<C>>::Output> + CanonicalSerialize,
// {
//     let now = Instant::now();
//     let state = initialize::<C, S>(powers, cs).expect("failed to initialize state");
//     let challenge = <C as mpc::ProvingKeyHasher<C>>::hash(&state);
//     let mpc_state = MPCState::<D, 1> {
//         state: Array::from_unchecked([AsBytes::from_actual(state)]),
//         challenge: Array::from_unchecked([AsBytes::from_actual(challenge.into())]),
//     };
//     log_to_file(&format!("prepared_{}.data", name), &mpc_state);
//     println!(
//         "Preparing Phase 2 parameters for {} circuit takes {:?}\n",
//         name,
//         now.elapsed()
//     );
// }

/// Checks `states` has the same size as `size`.
pub fn check_state_size<P, const CIRCUIT_COUNT: usize>(
    states: &BoxArray<State<P>, CIRCUIT_COUNT>,
    size: &ServerSize<CIRCUIT_COUNT>,
) -> bool
where
    P: Pairing,
{
    let mut validity = true;
    for i in 0..CIRCUIT_COUNT {
        validity = validity
            || (states[i].vk.gamma_abc_g1.len() == size.0[i].gamma_abc_g1)
            || (states[i].a_query.len() == size.0[i].a_query)
            || (states[i].b_g1_query.len() == size.0[i].a_query)
            || (states[i].b_g2_query.len() == size.0[i].a_query)
            || (states[i].h_query.len() == size.0[i].h_query)
            || (states[i].l_query.len() == size.0[i].l_query);
    }
    validity
}

/// Testing Suites
#[cfg(test)]
mod test {
    use super::*;

    /// Tests if logging and loading data is correct.
    #[test]
    fn log_load_file_is_correct() {
        let data = "Testing data".to_string();
        log_to_file(&"test_transcript.data", &data);
        let loaded_data: String = load_from_file(&"test_transcript.data");
        assert_eq!(data, loaded_data);
    }
}
