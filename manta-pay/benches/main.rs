// Copyright 2019-2021 Manta Network.
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

//! Benchmarks

extern crate manta_pay;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_accounting::transfer::test;
use manta_crypto::{
    rand::{Rand, TrySample},
    set::VerifiedSet,
};
use manta_pay::accounting::{
    identity::UtxoSet,
    transfer::{Mint, PrivateTransfer, Reclaim},
};
use rand::thread_rng;

/// Runs the following benchmarks for a given transfer:
/// 1. Constraint generation
/// 2. TODO: Constraint satisfaction check
/// 3. TODO: ZKP Setup generating Proving Key and Verifying Key
/// 4. TODO: ZKP Prove with Proving Key
/// 5. TODO: ZKP Verify with Verifying Key
/// 6. TODO: ZKP Verify with Processed Verifying Key
macro_rules! transfer_benchmark {
    (
        $c:ident,
        $name:expr,
        $rng:ident,
        $transfer:ident,
        $commitment_scheme: ident,
        $utxo_set_verifier: ident
    ) => {
        let mut group = $c.benchmark_group($name);

        group.bench_function("generate-constraints", |b| {
            b.iter(|| {
                black_box($transfer.known_constraints(&$commitment_scheme, &$utxo_set_verifier));
            })
        });

        let _known_constraints =
            $transfer.known_constraints(&$commitment_scheme, &$utxo_set_verifier);

        /* TODO:
        group.bench_function("is-satisfied", |b| {
            b.iter(|| {
                black_box(constraints.is_satisfied().unwrap());
            })
        });
        */

        /* TODO:
        group.bench_function("zkp-setup", |b| {
            b.iter_batched(
                || $circuit.clone(),
                |c| {
                    black_box(Groth::generate_(c, &mut $rng).unwrap());
                },
                BatchSize::SmallInput,
            )
        });

        let (pk, vk) = Groth::circuit_specific_setup($circuit.clone(), &mut $rng).unwrap();

        group.bench_function("zkp-prove", |b| {
            b.iter_batched(
                || $circuit.clone(),
                |c| {
                    black_box(Groth::prove(&pk, c, &mut $rng).unwrap());
                },
                BatchSize::SmallInput,
            )
        });

        let proof = Groth::prove(&pk, $circuit.clone(), &mut $rng).unwrap();
        let input = $circuit.raw_input().unwrap();

        group.bench_function("zkp-verify", |b| {
            b.iter(|| {
                black_box(Groth::verify(&vk, &input, &proof).unwrap());
            })
        });

        let pvk = Groth::process_vk(&vk).unwrap();

        group.bench_function("zkp-verify-processed", |b| {
            b.iter(|| {
                black_box(Groth::verify_with_processed_vk(&pvk, &input, &proof).unwrap());
            })
        });
        */

        group.finish();
    };
}

/// Runs the circuit benchmark for the [`Mint`] transfer.
fn mint(c: &mut Criterion) {
    let mut rng = thread_rng();
    let commitment_scheme = rng.gen();
    let mut utxo_set = UtxoSet::new(rng.gen());
    let mint = Mint::try_sample(
        test::distribution::Transfer {
            commitment_scheme: &commitment_scheme,
            utxo_set: &mut utxo_set,
        },
        &mut rng,
    )
    .unwrap();
    let utxo_set_verifier = utxo_set.verifier();
    transfer_benchmark!(c, "Mint", rng, mint, commitment_scheme, utxo_set_verifier);
}

/// Runs the circuit benchmark for the [`PrivateTransfer`] transfer.
fn private_transfer(c: &mut Criterion) {
    let mut rng = thread_rng();
    let commitment_scheme = rng.gen();
    let mut utxo_set = UtxoSet::new(rng.gen());
    let private_transfer = PrivateTransfer::try_sample(
        test::distribution::Transfer {
            commitment_scheme: &commitment_scheme,
            utxo_set: &mut utxo_set,
        },
        &mut rng,
    )
    .unwrap();
    let utxo_set_verifier = utxo_set.verifier();
    transfer_benchmark!(
        c,
        "PrivateTransfer",
        rng,
        private_transfer,
        commitment_scheme,
        utxo_set_verifier
    );
}

/// Runs the circuit benchmark for the [`Reclaim`] transfer.
fn reclaim(c: &mut Criterion) {
    let mut rng = thread_rng();
    let commitment_scheme = rng.gen();
    let mut utxo_set = UtxoSet::new(rng.gen());
    let reclaim = Reclaim::try_sample(
        test::distribution::Transfer {
            commitment_scheme: &commitment_scheme,
            utxo_set: &mut utxo_set,
        },
        &mut rng,
    )
    .unwrap();
    let utxo_set_verifier = utxo_set.verifier();
    transfer_benchmark!(
        c,
        "Reclaim",
        rng,
        reclaim,
        commitment_scheme,
        utxo_set_verifier
    );
}

criterion_group!(circuits, mint, private_transfer, reclaim);
criterion_main!(circuits);
