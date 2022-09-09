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

use manta_util::serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

/// Logs `data` to a disk file at `path` assuming this file does not exist.
#[inline]
pub fn serialize_into_file<T, P>(
    path: &P,
    data: &T,
    option: &mut OpenOptions,
) -> bincode::Result<()>
where
    P: AsRef<Path>,
    T: Serialize,
{
    Ok(bincode::serialize_into(option.open(path)?, data)?)
}

/// Loads `data` from a disk file at `path`.
#[inline]
pub fn deserialize_from_file<T, P>(path: P) -> bincode::Result<T>
where
    P: AsRef<Path>,
    T: DeserializeOwned,
{
    Ok(bincode::deserialize_from(File::open(path)?)?)
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

/// Testing Suites
#[cfg(test)]
mod test {
    use super::*;

    /// Tests if logging and loading data is correct.
    #[test]
    fn log_load_file_is_correct() {
        let data = "Testing data".to_string();
        serialize_into_file(
            &"test_transcript.data",
            &data,
            OpenOptions::new().write(true).create_new(true),
        )
        .unwrap();
        let loaded_data: String = deserialize_from_file(&"test_transcript.data").unwrap();
        assert_eq!(data, loaded_data);
    }
}
