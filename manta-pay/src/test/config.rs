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

//! Manta Pay Configuration Testing

use crate::config::KeyAgreementScheme;
use manta_crypto::{
    key::test::key_agreement,
    rand::{Rand, Sample, SeedableRng},
};
use rand_chacha::ChaCha20Rng;

#[test]
fn key_agreement_property_is_satisfied() {
    let mut rng = ChaCha20Rng::from_entropy();
    key_agreement::<KeyAgreementScheme>(&KeyAgreementScheme::gen(&mut rng), &rng.gen(), &rng.gen());
}

#[test]
fn random_derivation_property_is_satified() {
    // TODO: Add a test here when we have concrete type following RandomizableKeyDerivationFunction trait.
    // random_derivation()
}
