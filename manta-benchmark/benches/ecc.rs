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

//! Elliptic Curve Cryptography Benchmarks

use core::iter::repeat_with;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_benchmark::ecc;
use manta_crypto::{
    arkworks::bls12_381::{G1Affine, G1Projective},
    rand::OsRng,
};

#[inline]
fn affine_affine_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let mut lhs = black_box(ecc::sample_affine_point::<G1Affine, _>(&mut rng));
    let rhs = black_box(ecc::sample_affine_point(&mut rng));
    group.bench_function("affine-affine addition", |b| {
        b.iter(|| {
            let _ = black_box(ecc::affine_affine_add_assign(&mut lhs, &rhs));
        })
    });
}

#[inline]
fn projective_affine_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let mut lhs = black_box(ecc::sample_projective_point::<G1Projective, _>(&mut rng));
    let rhs = black_box(ecc::sample_affine_point(&mut rng));
    group.bench_function("projective-affine addition", |b| {
        b.iter(|| {
            let _ = black_box(ecc::projective_affine_add_assign(&mut lhs, &rhs));
        })
    });
}

#[inline]
fn projective_projective_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let mut lhs = black_box(ecc::sample_projective_point::<G1Projective, _>(&mut rng));
    let rhs = black_box(ecc::sample_projective_point::<G1Projective, _>(&mut rng));
    group.bench_function("projective-projective addition", |b| {
        b.iter(|| {
            let _ = black_box(ecc::projective_projective_add_assign(&mut lhs, rhs));
        })
    });
}

#[inline]
fn affine_scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let point = black_box(ecc::sample_affine_point::<G1Affine, _>(&mut rng));
    let scalar = black_box(ecc::sample_scalar::<G1Affine, _>(&mut rng));
    group.bench_function("affine-scalar multiplication", |b| {
        b.iter(|| {
            let _ = black_box(ecc::affine_scalar_mul(&point, scalar));
        })
    });
}

#[inline]
fn projective_scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let mut point = black_box(ecc::sample_projective_point::<G1Projective, _>(&mut rng));
    let scalar = black_box(ecc::sample_scalar::<G1Affine, _>(&mut rng));
    group.bench_function("projective-scalar multiplication", |b| {
        b.iter(|| {
            let _ = black_box(ecc::projective_scalar_mul_assign(&mut point, scalar));
        })
    });
}

#[inline]
fn projective_to_affine_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let point = black_box(ecc::sample_projective_point::<G1Projective, _>(&mut rng));
    group.bench_function("projective to affine normalization", |b| {
        b.iter(|| {
            let _ = black_box(ecc::projective_to_affine_normalization(&point));
        })
    });
}

#[inline]
fn batch_vector_projective_to_affine_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let points = repeat_with(|| ecc::sample_projective_point::<G1Projective, _>(&mut rng))
        .take(1 << 16)
        .collect::<Vec<_>>();
    let points_slice = black_box(points.as_slice());
    group.bench_function("batch vector of projective to affine normalization", |b| {
        b.iter(|| {
            let _ = black_box(ecc::batch_vector_projective_to_affine_normalization(
                points_slice,
            ));
        })
    });
}

#[inline]
fn naive_vector_projective_to_affine_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let mut rng = OsRng;
    let points = repeat_with(|| ecc::sample_projective_point::<G1Projective, _>(&mut rng))
        .take(1 << 16)
        .collect::<Vec<_>>();
    let points_slice = black_box(points.as_slice());
    group.bench_function("naive vector of projective to affine normalization", |b| {
        b.iter(|| {
            let _ = black_box(ecc::naive_vector_projective_to_affine_normalization(
                points_slice,
            ));
        })
    });
}

criterion_group!(
    ecc,
    affine_affine_addition,
    projective_affine_addition,
    projective_projective_addition,
    affine_scalar_multiplication,
    projective_scalar_multiplication,
    projective_to_affine_normalization,
    batch_vector_projective_to_affine_normalization,
    naive_vector_projective_to_affine_normalization,
);
criterion_main!(ecc);
