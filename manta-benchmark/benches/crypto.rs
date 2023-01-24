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

//! Cryptography Benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
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

#[inline]
fn poseidon_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let hasher = black_box(Hasher::<Poseidon2, InnerHashDomainTag, 2>::sample(
        (),
        &mut rng,
    ));
    let inputs = black_box([
        Fp(field_new!(ConstraintField, "1")),
        Fp(field_new!(ConstraintField, "2")),
    ]);
    group.bench_function("Poseidon Hash", |b| {
        b.iter(|| {
            let _ = black_box(hasher.hash([&inputs[0], &inputs[1]], &mut ()));
        })
    });
}

#[inline]
fn aes_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let base_aes = black_box(IncomingBaseAES::default());
    let header = black_box(EmptyHeader::default());
    let key = black_box(rng.gen());
    let plaintext = black_box(protocol::IncomingPlaintext::<Config>::new(
        rng.gen(),
        asset::Asset {
            id: rng.gen(),
            value: rng.gen(),
        },
    ));
    let ciphertext = black_box(base_aes.encrypt(&key, &(), &header, &plaintext, &mut ()));
    group.bench_function("AES Decryption", |b| {
        b.iter(|| {
            let _ = black_box(base_aes.decrypt(&key, &header, &ciphertext, &mut ()));
        })
    });
}

criterion_group!(crypto, poseidon_hash, aes_decryption);
criterion_main!(crypto);
