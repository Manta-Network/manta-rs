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

//! To Private Benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_crypto::rand::{OsRng, Rand};
use manta_pay::{
    parameters,
    test::payment::{to_private::prove_full, UtxoAccumulator},
};

fn prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let (proving_context, _verifying_context, parameters, utxo_accumulator_model) =
        parameters::generate().unwrap();
    let mut rng = OsRng;
    group.bench_function("to_private prove", |b| {
        let asset_id = black_box(rng.gen());
        let asset_value = black_box(rng.gen());
        b.iter(|| {
            prove_full(
                &proving_context.to_private,
                &parameters,
                &mut UtxoAccumulator::new(utxo_accumulator_model.clone()),
                asset_id,
                asset_value,
                &mut rng,
            );
        })
    });
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        parameters::generate().unwrap();
    let mut rng = OsRng;
    let transferpost = black_box(prove_full(
        &proving_context.to_private,
        &parameters,
        &mut UtxoAccumulator::new(utxo_accumulator_model.clone()),
        rng.gen(),
        rng.gen(),
        &mut rng,
    ));
    group.bench_function("mint verify", |b| {
        b.iter(|| {
            transferpost.assert_valid_proof(&verifying_context.to_private);
        })
    });
}

criterion_group!(to_private, prove, verify);
criterion_main!(to_private);
