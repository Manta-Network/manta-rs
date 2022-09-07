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

//! Serde

use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use manta_util::{
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    Array,
};

/// Uses `serializer` to serialize `data` that implements `CanonicalSerialize`.
#[inline]
pub fn serialize_element<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: CanonicalSerialize,
    S: Serializer,
{
    let mut bytes = Vec::new();
    data.serialize(&mut bytes).unwrap();
    Serialize::serialize(&bytes, serializer)
}

/// Uses `deserializer` to deserialize into data with type `T` that implements `CanonicalDeserialize`.
#[inline]
pub fn deserialize_element<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: CanonicalDeserialize,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    Ok(CanonicalDeserialize::deserialize(bytes.as_slice()).expect("Deserialize should succeed."))
}

///
#[inline]
pub fn serialize_array<T, S, const N: usize>(
    data: &Array<T, N>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: CanonicalSerialize,
    S: Serializer,
{
    let mut bytes = Vec::new();
    for i in 0..N {
        data.0[i].serialize(&mut bytes).unwrap();
    }
    Serialize::serialize(&bytes, serializer)
}

///
#[inline]
pub fn deserialize_array<'de, D, T, const N: usize>(
    deserializer: D,
) -> Result<Array<T, N>, D::Error>
where
    D: Deserializer<'de>,
    T: CanonicalDeserialize,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let bytes = bytes.as_slice();
    let mut data = Vec::with_capacity(N);
    for _ in 0..N {
        data.push(
            CanonicalDeserialize::deserialize(bytes) // TODO: Issue here
                .expect("Deserialize should succeed."),
        )
    }
    Ok(Array::from_vec(data))
}

// /// Testing Suites
// TODO: Check if serde works correctly.
// #[cfg(test)]
// mod test {
//     use super::*;
//     use ark_bls12_381::Bls12_381;
//     use ark_groth16::{ProvingKey, VerifyingKey};
//     use manta_crypto::{
//         arkworks::ec::PairingEngine,
//         rand::{OsRng, Rand},
//     };

//     /// Samples a dummy verifying key `vk`.
//     fn sample_dummy_vk<R>(rng: &mut R) -> VerifyingKey<Bls12_381>
//     where
//         R: Rand,
//     {
//         VerifyingKey {
//             alpha_g1: rng.gen(),
//             beta_g2: rng.gen(),
//             gamma_g2: rng.gen(),
//             delta_g2: rng.gen(),
//             gamma_abc_g1: vec![rng.gen()],
//         }
//     }

//     #[test]
//     fn serde_element_is_correct() {
//         let mut rng = OsRng;
//         let dummy_vk = sample_dummy_vk(&mut rng);
//         let mut serialized_data = Vec::new();
//         serialize_element(&dummy_vk, &mut serialized_data);
//     }
// }
