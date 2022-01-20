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

//! Generate Parameters

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use manta_accounting::transfer::Parameters;
use manta_crypto::{
    accumulator::Accumulator,
    constraint::{measure::Measure, ProofSystem as _},
    rand::{Rand, SeedableRng},
};
use manta_pay::{
    config::{FullParameters, Mint, PrivateTransfer, ProofSystem, Reclaim, VerifyingContext},
    wallet::UtxoSet,
};
use rand_chacha::ChaCha20Rng;
use std::{fs::OpenOptions, io};

///
#[inline]
pub fn main() -> io::Result<()> {
    let mut rng = ChaCha20Rng::from_seed([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]);

    let parameters = rng.gen();
    let mut utxo_set = UtxoSet::new(rng.gen());

    /*
    let mut bytes = Vec::new();

    let Parameters {
        key_agreement,
        utxo_commitment,
        void_number_hash,
    } = &parameters;

    key_agreement.generator().0.serialize(&mut bytes).unwrap();
    utxo_commitment.0.serialize(&mut bytes).unwrap();
    void_number_hash.0.serialize(&mut bytes).unwrap();

    println!("Parameters: {:?}", bytes.as_slice());

    let mut bytes = Vec::new();
    utxo_set_parameters.serialize(&mut bytes).unwrap();
    println!("UTXO Set Parameters: {:?}", bytes.as_slice());
    */

    let cs = Mint::unknown_constraints(FullParameters::new(&parameters, utxo_set.model()));
    // println!("Mint: {:#?}", cs.measure());

    let mut mint_file = OpenOptions::new()
        .read(true)
        .create(true)
        .write(true)
        .open("mint")?;

    let (proving_context, verifying_context) =
        ProofSystem::generate_context(cs, &(), &mut rng).unwrap();

    verifying_context.serialize(&mut mint_file).unwrap();

    // let cs = PrivateTransfer::unknown_constraints(full_parameters);
    // println!("PrivateTransfer: {:#?}", cs.measure());
    // let _ = ProofSystem::generate_context(cs, &(), &mut rng).unwrap();

    // let cs = Reclaim::unknown_constraints(full_parameters);
    // println!("Reclaim: {:#?}", cs.measure());
    // let _ = ProofSystem::generate_context(cs, &(), &mut rng).unwrap();

    Ok(())
}
