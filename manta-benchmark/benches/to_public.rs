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

//! To Public Benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_crypto::rand::OsRng;
use manta_pay::{
    parameters,
    test::payment::{to_public::prove as prove_to_public, UtxoAccumulator},
};

fn prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let (proving_context, _, parameters, utxo_accumulator_model) = parameters::generate().unwrap();
    group.bench_function("to public prove", |b| {
        b.iter(|| {
            prove_to_public(
                &proving_context.to_public,
                &parameters,
                &mut UtxoAccumulator::new(utxo_accumulator_model.clone()),
                &mut rng,
            );
        })
    });
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        parameters::generate().unwrap();
    let transferpost = black_box(prove_to_public(
        &proving_context.to_public,
        &parameters,
        &mut UtxoAccumulator::new(utxo_accumulator_model.clone()),
        &mut rng,
    ));
    group.bench_function("to public verify", |b| {
        b.iter(|| {
            transferpost.assert_valid_proof(&verifying_context.to_public);
        })
    });
}

criterion_group!(to_public, prove, verify);
criterion_main!(to_public);
