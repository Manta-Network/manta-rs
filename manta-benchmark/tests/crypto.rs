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

//! Cryptography Benchmarking Suites

use manta_accounting::{asset, transfer::utxo::protocol};
use manta_crypto::{
    arkworks::{constraint::fp::Fp, ff::field_new},
    encryption::{Decrypt, EmptyHeader, Encrypt},
    hash::ArrayHashFunction,
    rand::{OsRng, Rand, Sample},
};
use manta_pay::{
    config::{
        poseidon::Spec2 as Poseidon2,
        utxo::{Config, IncomingBaseAES, InnerHashDomainTag},
        ConstraintField,
    },
    crypto::poseidon::hash::Hasher,
};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::console;

wasm_bindgen_test_configure!(run_in_browser);

static REPEAT: usize = 1000;

#[wasm_bindgen_test]
fn bench_poseidon_hash() {
    let mut rng = OsRng;
    let hasher = Hasher::<Poseidon2, InnerHashDomainTag, 2>::sample((), &mut rng);
    let inputs = [
        &Fp(field_new!(ConstraintField, "1")),
        &Fp(field_new!(ConstraintField, "2")),
    ];
    let start_time = instant::Instant::now();
    for _ in 0..REPEAT {
        hasher.hash(inputs, &mut ());
    }
    let end_time = instant::Instant::now();
    console::log_1(
        &format!(
            "Poseidon2 Performance: {:?}",
            ((end_time - start_time) / REPEAT as u32)
        )
        .into(),
    );
}

#[wasm_bindgen_test]
fn bench_aes_decryption() {
    let mut rng = OsRng;
    let base_aes = IncomingBaseAES::default();
    let header = EmptyHeader::default();
    let key = rng.gen();
    let plaintext = protocol::IncomingPlaintext::<Config>::new(
        rng.gen(),
        asset::Asset {
            id: rng.gen(),
            value: rng.gen(),
        },
    );
    let ciphertext = base_aes.encrypt(&key, &(), &header, &plaintext, &mut ());
    let start_time = instant::Instant::now();
    for _ in 0..REPEAT {
        base_aes.decrypt(&key, &header, &ciphertext, &mut ());
    }
    let end_time = instant::Instant::now();
    console::log_1(
        &format!(
            "AES decryption Performance: {:?}",
            ((end_time - start_time) / REPEAT as u32)
        )
        .into(),
    );
}
