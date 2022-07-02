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

use ark_bls12_381::{G1Affine, G1Projective};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_benchmark::ec;
use manta_crypto::rand::OsRng;

fn affine_affine_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let mut lhs = black_box(ec::sample_affine_point::<G1Affine, _>(&mut rng));
    let rhs = black_box(ec::sample_affine_point(&mut rng));
    group.bench_function("affine-affine addition", |b| {
        b.iter(|| {
            ec::affine_affine_add_assign(&mut lhs, &rhs);
        })
    });
}

fn projective_affine_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let mut lhs = black_box(ec::sample_projective_point::<G1Projective, _>(&mut rng));
    let rhs = black_box(ec::sample_affine_point(&mut rng));
    group.bench_function("projective-affine addition", |b| {
        b.iter(|| {
            ec::projective_affine_add_assign(&mut lhs, &rhs);
        })
    });
}

fn projective_projective_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let mut lhs = black_box(ec::sample_projective_point::<G1Projective, _>(&mut rng));
    let rhs = black_box(ec::sample_projective_point::<G1Projective, _>(&mut rng));
    group.bench_function("projective-projective addition", |b| {
        b.iter(|| {
            ec::projective_projective_add_assign(&mut lhs, rhs);
        })
    });
}

fn affine_scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let point = black_box(ec::sample_affine_point::<G1Affine, _>(&mut rng));
    let scalar = black_box(ec::sample_scalar::<G1Affine, _>(&mut rng));
    group.bench_function("affine-scalar multiplication", |b| {
        b.iter(|| {
            let _ = ec::affine_scalar_mul(&point, scalar);
        })
    });
}

fn projective_scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let mut point = black_box(ec::sample_projective_point::<G1Projective, _>(&mut rng));
    let scalar = black_box(ec::sample_scalar::<G1Affine, _>(&mut rng));
    group.bench_function("projective-scalar multiplication", |b| {
        b.iter(|| {
            ec::projective_scalar_mul_assign(&mut point, scalar);
        })
    });
}

fn projective_to_affine_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let point = black_box(ec::sample_projective_point::<G1Projective, _>(&mut rng));
    group.bench_function("projective to affine normalization", |b| {
        b.iter(|| {
            let _ = ec::projective_to_affine_normalization(&point);
        })
    });
}

fn batch_vector_projective_to_affine_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let point_vec = (0..(1 << 16))
        .map(|_| ec::sample_projective_point::<G1Projective, _>(&mut rng))
        .collect::<Vec<_>>();
    group.bench_function("batch vector of projective to affine normalization", |b| {
        b.iter(|| {
            let _ = ec::batch_vector_projective_to_affine_normalization(point_vec.as_slice());
        })
    });
}

fn naive_vector_projective_to_affine_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let point_vec = (0..(1 << 16))
        .map(|_| ec::sample_projective_point::<G1Projective, _>(&mut rng))
        .collect::<Vec<_>>();
    group.bench_function("naive vector of projective to affine normalization", |b| {
        b.iter(|| {
            let _ = ec::naive_vector_projective_to_affine_normalization(point_vec.as_slice());
        })
    });
}

criterion_group!(
    ec,
    affine_affine_addition,
    projective_affine_addition,
    projective_projective_addition,
    affine_scalar_multiplication,
    projective_scalar_multiplication,
    projective_to_affine_normalization,
    batch_vector_projective_to_affine_normalization,
    naive_vector_projective_to_affine_normalization,
);
criterion_main!(ec);
