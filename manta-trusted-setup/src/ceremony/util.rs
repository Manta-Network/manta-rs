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

use crate::{
    ceremony::{
        config::CeremonyConfig,
        message::{MPCState, ServerSize},
    },
    groth16::{
        kzg::{self, Accumulator, Size},
        mpc::{self, initialize, Groth16Phase2, State},
    },
    util::AsBytes,
};
use manta_crypto::arkworks::{
    pairing::Pairing, relations::r1cs::ConstraintSynthesizer, serialize::CanonicalSerialize,
};
use manta_util::{
    serde::{de::DeserializeOwned, Serialize},
    Array,
};
use std::{fmt::Debug, fs::File, io::Write, path::Path, time::Instant};

/// Logs `data` to a disk file at `path`.
#[inline]
pub fn log_to_file<T, P>(path: &P, data: &T)
where
    T: Serialize,
    P: AsRef<Path>,
{
    let mut file = File::create(path).expect("Open file should succeed.");
    serde_json::to_writer(&mut file, &data)
        .expect("Writing phase one parameters to disk should succeed.");
    file.flush().expect("Flushing file should succeed.");
}

/// Loads `data` from a disk file at `path`.
#[inline]
pub fn load_from_file<T, P>(path: P) -> T
where
    P: AsRef<Path> + Debug,
    T: DeserializeOwned,
{
    let mut file = File::open(path).expect("Opening file should succeed.");
    serde_json::from_reader(&mut file).expect("Reading and deserializing data should succeed.")
}

/// Prepares phase one parameter `powers` for phase two parameters of circuit `cs` with `name`.
#[inline]
pub fn prepare_parameters<C, D, S>(powers: Accumulator<C>, cs: S, name: &str)
where
    C: Pairing + Size + kzg::Configuration + mpc::ProvingKeyHasher<C> + mpc::Configuration,
    S: ConstraintSynthesizer<C::Scalar>,
    D: CeremonyConfig<Setup = Groth16Phase2<C>>,
    <C as mpc::Configuration>::Challenge:
        From<<C as mpc::ProvingKeyHasher<C>>::Output> + CanonicalSerialize,
{
    let now = Instant::now();
    let state = initialize::<C, S>(powers, cs).expect("failed to initialize state");
    let challenge = <C as mpc::ProvingKeyHasher<C>>::hash(&state);
    let mpc_state = MPCState::<D, 1> {
        state: Array::from_unchecked([AsBytes::from_actual(state)]),
        challenge: Array::from_unchecked([AsBytes::from_actual(challenge.into())]),
    };
    log_to_file(&format!("prepared_{}.data", name), &mpc_state);
    println!(
        "Preparing Phase 2 parameters for {} circuit takes {:?}\n",
        name,
        now.elapsed()
    );
}

/// Checks `states` has the same size as `size`.
pub fn check_state_size<P, const CIRCUIT_COUNT: usize>(
    states: &Array<AsBytes<State<P>>, CIRCUIT_COUNT>,
    size: &ServerSize<CIRCUIT_COUNT>,
) -> bool
where
    P: Pairing,
{
    let mut validity = true;
    for i in 0..CIRCUIT_COUNT {
        let state = states[i].to_actual().expect("Deserialize should succeed.");
        validity = validity
            || (state.vk.gamma_abc_g1.len() == size.0[i].gamma_abc_g1)
            || (state.a_query.len() == size.0[i].a_b_g1_b_g2_query)
            || (state.b_g1_query.len() == size.0[i].a_b_g1_b_g2_query)
            || (state.b_g2_query.len() == size.0[i].a_b_g1_b_g2_query)
            || (state.h_query.len() == size.0[i].h_query)
            || (state.l_query.len() == size.0[i].l_query);
    }
    validity
}

/// Testing Suites
#[cfg(test)]
mod test {
    use super::*;

    /// Tests if log and loading data is correct.
    #[test]
    fn log_load_file_is_correct() {
        let data = "Testing data".to_string();
        log_to_file(&"data/test_transcript.data", &data);
        let loaded_data: String = load_from_file(&"data/test_transcript.data");
        assert_eq!(data, loaded_data);
    }
}
