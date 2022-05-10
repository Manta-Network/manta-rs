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

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_benchmark::payment::{self, assert_valid_proof};
use manta_crypto::rand::OsRng;
use manta_pay::parameters::{generate_parameters, SEED};

fn prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");

    let mut rng = OsRng;
    let (proving_context, _, parameters, utxo_accumulator_model) =
        generate_parameters(SEED).unwrap();

    group.bench_function("reclaim prove", |b| {
        b.iter(|| {
            let _ = payment::prove_reclaim(
                &proving_context,
                &parameters,
                &utxo_accumulator_model,
                &mut rng,
            );
        })
    });
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");

    let mut rng = OsRng;
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        generate_parameters(SEED).unwrap();

    let post = payment::prove_reclaim(
        &proving_context,
        &parameters,
        &utxo_accumulator_model,
        &mut rng,
    );

    let post = black_box(post);

    group.bench_function("reclaim verify", |b| {
        b.iter(|| {
            assert_valid_proof(&verifying_context.reclaim, &post);
        })
    });
}

criterion_group!(reclaim, prove, verify);
criterion_main!(reclaim);
