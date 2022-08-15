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

//! To-Public Benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_crypto::rand::OsRng;
use manta_pay::{parameters, test::payment};

#[inline]
fn prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let (proving_context, _, parameters, utxo_accumulator_model) =
        parameters::generate().expect("");
    group.bench_function("to-public prove", |b| {
        b.iter(|| {
            payment::to_public::prove(
                &proving_context.to_public,
                &parameters,
                &utxo_accumulator_model,
                &mut OsRng,
            );
        })
    });
}

#[inline]
fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        parameters::generate().expect("");
    let post = black_box(payment::to_public::prove(
        &proving_context.to_public,
        &parameters,
        &utxo_accumulator_model,
        &mut OsRng,
    ));
    group.bench_function("to-public verify", |b| {
        b.iter(|| {
            post.assert_valid_proof(&verifying_context.to_public);
        })
    });
}

criterion_group!(to_public, prove, verify);
criterion_main!(to_public);
