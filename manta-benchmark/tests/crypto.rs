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

// Cryptography Benchmarking Suites

// use manta_crypto::hash::ArrayHashFunction;
// use manta_crypto::{
//     arkworks::{constraint::fp::Fp, ff::field_new},
//     rand::{OsRng, Sample},
// };
// use manta_pay::{
//     config::{poseidon::Spec2 as Poseidon2, utxo::InnerHashDomainTag, ConstraintField},
//     crypto::poseidon::hash::Hasher,
// };
// use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
// use web_sys::console;

// wasm_bindgen_test_configure!(run_in_browser);

// static REPEAT: usize = 3;

// #[wasm_bindgen_test]
// fn bench_poseidon_hash() {
//     let mut rng = OsRng;
//     let hasher = Hasher::<Poseidon2, InnerHashDomainTag, 2>::sample((), &mut rng);
//     let inputs = [
//         &Fp(field_new!(ConstraintField, "1")),
//         &Fp(field_new!(ConstraintField, "2")),
//     ];
//     hasher.hash(inputs, &mut ());

//     // let context = Context::new();
//     // let start_time = instant::Instant::now();
//     // for _ in 0..REPEAT {
//     //     f(&context);
//     // }
//     // let end_time = instant::Instant::now();
//     // console::log_1(
//     //     &format!(
//     //         "{:?} Performance: {:?}",
//     //         operation,
//     //         ((end_time - start_time) / REPEAT as u32)
//     //     )
//     //     .into(),
//     // );
// }
