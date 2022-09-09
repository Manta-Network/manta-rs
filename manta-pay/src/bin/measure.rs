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

//! Manta Pay Circuit Measurements

use manta_crypto::{
    constraint::measure::Instrument,
    eclair::alloc::{mode::Secret, Allocate, Allocator},
    hash::ArrayHashFunction,
    key::agreement::{Agree, Derive},
    rand::{ChaCha20Rng, Sample, SeedableRng},
};
use manta_pay::config::{
    Compiler, KeyAgreementScheme, KeyAgreementSchemeVar, Poseidon2, Poseidon2Var, Poseidon4,
    Poseidon4Var,
};

/// Runs some basic measurements of the circuit component sizes.
#[inline]
pub fn main() {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut compiler = Compiler::for_contexts();

    let mut instrument = Instrument::new(&mut compiler);

    let hasher = Poseidon2::gen(&mut rng).as_constant::<Poseidon2Var>(&mut instrument);
    let poseidon_lhs = instrument.base.allocate_unknown::<Secret, _>();
    let poseidon_rhs = instrument.base.allocate_unknown::<Secret, _>();

    let _ = instrument.measure("Poseidon ARITY-2", |compiler| {
        hasher.hash([&poseidon_lhs, &poseidon_rhs], compiler)
    });

    let hasher = Poseidon4::gen(&mut rng).as_constant::<Poseidon4Var>(&mut instrument);
    let poseidon_0 = instrument.base.allocate_unknown::<Secret, _>();
    let poseidon_1 = instrument.base.allocate_unknown::<Secret, _>();
    let poseidon_2 = instrument.base.allocate_unknown::<Secret, _>();
    let poseidon_3 = instrument.base.allocate_unknown::<Secret, _>();

    let _ = instrument.measure("Poseidon ARITY-4", |compiler| {
        hasher.hash(
            [&poseidon_0, &poseidon_1, &poseidon_2, &poseidon_3],
            compiler,
        )
    });

    let key_agreement =
        KeyAgreementScheme::gen(&mut rng).as_constant::<KeyAgreementSchemeVar>(&mut instrument);
    let secret_key_0 = instrument.base.allocate_unknown::<Secret, _>();
    let secret_key_1 = instrument.base.allocate_unknown::<Secret, _>();

    let public_key_0 = instrument.measure("DHKE `derive`", |compiler| {
        key_agreement.derive(&secret_key_0, compiler)
    });

    let _ = instrument.measure("DHKE `agree`", |compiler| {
        key_agreement.agree(&public_key_0, &secret_key_1, compiler)
    });

    println!("{:#?}", instrument.measurements);
}
