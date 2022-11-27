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

//! Manta Pay Simulation

use ark_snark::SNARK;
use clap::{error::ErrorKind, CommandFactory, Parser};
use manta_accounting::transfer::{
    canonical::{
        // generate_context,
        MultiProvingContext,
        MultiVerifyingContext,
    },
    Configuration,
};
use manta_crypto::{
    arkworks::serialize::CanonicalDeserialize,
    constraint::ProofSystem,
    rand::{OsRng, Rand},
};
use manta_pay::{
    config::Config,
    crypto::constraint::arkworks::{groth16::VerifyingContext, Fp},
    simulation::Simulation,
};
use std::{fs::File, path::PathBuf};

// cargo run --release --package manta-pay --all-features --bin simulation <number_of_actors> <number_of_steps> <number_of_asset_ids> <initial_balance>
// cargo run --release --package manta-pay --all-features --bin simulation 5 100000000 3 1000 > simulation_output_1

/// Runs the Manta Pay simulation.
pub fn main() {
    let simulation = Simulation::parse();
    let mut rng = OsRng;
    let parameters = rng.gen();
    let utxo_accumulator_model = rng.gen();
    // let (proving_context, verifying_context) = generate_context(
    //     &(),
    //     FullParametersRef::new(&parameters, &utxo_accumulator_model),
    //     &mut rng,
    // )
    // .expect("Failed to generate contexts.");

    let to_private_path = PathBuf::from(
        "/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/to_private_pk",
    );
    let to_public_path = PathBuf::from(
        "/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/to_public_pk",
    );
    let private_transfer_path = PathBuf::from("/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/private_transfer_pk");

    let to_private: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
        CanonicalDeserialize::deserialize_unchecked(
            File::open(to_private_path).expect("Cannot open file"),
        )
        .expect("cannot load proving context");
    let to_public: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
        CanonicalDeserialize::deserialize_unchecked(
            File::open(to_public_path).expect("Cannot open file"),
        )
        .expect("cannot load proving context");
    let private_transfer: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
        CanonicalDeserialize::deserialize_unchecked(
            File::open(private_transfer_path).expect("Cannot open file"),
        )
        .expect("cannot load proving context");

    let to_private_verify = to_private.0.vk.clone();
    let to_public_verify = to_public.0.vk.clone();
    let private_transfer_verify = private_transfer.0.vk.clone();

    let proving_context = MultiProvingContext::<Config> {
        to_private,
        private_transfer,
        to_public,
    };
    let verifying_context = MultiVerifyingContext::<Config> {
        to_private: VerifyingContext(
            ark_groth16::Groth16::<_>::process_vk(&to_private_verify)
                .expect("unable to process vk"),
        ),
        private_transfer: VerifyingContext(
            ark_groth16::Groth16::<_>::process_vk(&private_transfer_verify)
                .expect("unable to process vk"),
        ),
        to_public: VerifyingContext(
            ark_groth16::Groth16::<_>::process_vk(&to_public_verify).expect("unable to process vk"),
        ),
    };
    match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(6)
        .build()
    {
        Ok(runtime) => runtime.block_on(async {
            simulation
                .run(
                    &parameters,
                    &utxo_accumulator_model,
                    &proving_context,
                    verifying_context,
                    &mut rng,
                )
                .await
        }),
        Err(err) => Simulation::command()
            .error(
                ErrorKind::Io,
                format_args!("Unable to start `tokio` runtime: {err}"),
            )
            .exit(),
    }
}

/// Do the new keys we used in the TS dry run work?
/// cargo test --release --package manta-pay --bin simulation --all-features -- test_new_prover_keys --exact --nocapture
#[test]
fn test_new_prover_keys() {
    use manta_pay::{
        parameters::load_parameters,
        signer::base::UtxoAccumulator,
        test::payment::{
            private_transfer::prove_full as prove_private_transfer,
            to_private::prove_full as prove_to_private, to_public::prove_full as prove_to_public,
        },
    };

    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    // let to_private_path = PathBuf::from(
    //     "/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/to_private_pk",
    // );
    // let to_public_path = PathBuf::from(
    //     "/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/to_public_pk",
    // );
    // let private_transfer_path = PathBuf::from("/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/private_transfer_pk");
    // let to_private_proving: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
    //     CanonicalDeserialize::deserialize_unchecked(File::open(to_private_path).expect("Cannot open file"))
    //         .expect("cannot load proving context");
    // let to_private_verifying = VerifyingContext(
    //     ark_groth16::Groth16::<_>::process_vk(&to_private_proving.0.vk)
    //         .expect("unable to process vk"),
    // );
    // let to_public_proving: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
    //     CanonicalDeserialize::deserialize_unchecked(
    //         File::open(to_public_path).expect("Cannot open file"),
    //     )
    //     .expect("cannot load proving context");

    // let to_private_path = PathBuf::from(
    //     "/Users/thomascnorton/Desktop/pk_server/to_private_pk",
    // );
    // let to_public_path = PathBuf::from(
    //     "/Users/thomascnorton/Desktop/pk_server/to_public_pk",
    // );
    // let private_transfer_path = PathBuf::from("/Users/thomascnorton/Desktop/pk_server/private_transfer_pk");

    // let to_private_proving: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
    //     CanonicalDeserialize::deserialize(File::open(to_private_path).expect("Cannot open file"))
    //         .expect("cannot load proving context");
    // let to_private_verifying = VerifyingContext(
    //     ark_groth16::Groth16::<_>::process_vk(&to_private_proving.0.vk)
    //         .expect("unable to process vk"),
    // );
    // let to_public_proving: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
    //     CanonicalDeserialize::deserialize(
    //         File::open(to_public_path).expect("Cannot open file"),
    //     )
    //     .expect("cannot load proving context");
    
    // let to_public_verifying = VerifyingContext(
    //     ark_groth16::Groth16::<_>::process_vk(&to_public_proving.0.vk)
    //         .expect("unable to process vk"),
    // );
    // let private_transfer_proving: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
    //     CanonicalDeserialize::deserialize(File::open(private_transfer_path).expect("Cannot open file"))
    //         .expect("cannot load proving context");
    // let private_transfer_verifying = VerifyingContext(
    //     ark_groth16::Groth16::<_>::process_vk(&private_transfer_proving.0.vk)
    //         .expect("unable to process vk"),
    // );

    let to_private_path = PathBuf::from(
        "/Users/thomascnorton/Desktop/server_data_test/to_private_pk",
    );
    let to_public_path = PathBuf::from(
        "/Users/thomascnorton/Desktop/server_data_test/to_public_pk",
    );
    let private_transfer_path = PathBuf::from("/Users/thomascnorton/Desktop/server_data_test/private_transfer_pk");

    let to_private_proving: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
        CanonicalDeserialize::deserialize_unchecked(File::open(to_private_path).expect("Cannot open file"))
            .expect("cannot load proving context");
    let to_private_verifying = VerifyingContext(
        ark_groth16::Groth16::<_>::process_vk(&to_private_proving.0.vk)
            .expect("unable to process vk"),
    );
    let to_public_proving: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
        CanonicalDeserialize::deserialize_unchecked(
            File::open(to_public_path).expect("Cannot open file"),
        )
        .expect("cannot load proving context");
    
    let to_public_verifying = VerifyingContext(
        ark_groth16::Groth16::<_>::process_vk(&to_public_proving.0.vk)
            .expect("unable to process vk"),
    );
    let private_transfer_proving: <<Config as Configuration>::ProofSystem as ProofSystem>::ProvingContext =
        CanonicalDeserialize::deserialize_unchecked(File::open(private_transfer_path).expect("Cannot open file"))
            .expect("cannot load proving context");
    let private_transfer_verifying = VerifyingContext(
        ark_groth16::Groth16::<_>::process_vk(&private_transfer_proving.0.vk)
            .expect("unable to process vk"),
    );

    let multi_proving_context = MultiProvingContext::<Config> {
        to_private: to_private_proving,
        private_transfer: private_transfer_proving,
        to_public: to_public_proving,
    };
    let multi_verifying_context = MultiVerifyingContext::<Config> {
        to_private: to_private_verifying,
        to_public: to_public_verifying,
        private_transfer: private_transfer_verifying,
    };

    let mut rng = OsRng;
    let (_, _, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("Failed to load parameters");

    for i in 0..300 {
        // To Private
        let _ = &prove_to_private(
            &multi_proving_context.to_private,
            &parameters,
            &mut UtxoAccumulator::new(utxo_accumulator_model.clone()),
            rng.gen(),
            rng.gen(),
            &mut rng,
        )
        .assert_valid_proof(&multi_verifying_context.to_private);

        println!("Passed to_private check");

        let mut asset_values: [manta_pay::config::AssetValue; 2] = rng.gen();
        asset_values[0] /= 2;
        asset_values[1] /= 2;
        // To Public
        let _ = &prove_to_public(
            &multi_proving_context.clone(),
            &parameters,
            &mut UtxoAccumulator::new(utxo_accumulator_model.clone()),
            // Fp::<manta_pay::config::ConstraintField>::from(1),
            rng.gen(),
            asset_values,
            &mut rng,
        )
        .1
        .assert_valid_proof(&multi_verifying_context.to_public);
        println!("Passed to_public check");

        let mut asset_values: [manta_pay::config::AssetValue; 2] = rng.gen();
        asset_values[0] /= 2;
        asset_values[1] /= 2;
        // Private Transfer
        let _ = &prove_private_transfer(
            &multi_proving_context,
            &parameters,
            &mut UtxoAccumulator::new(utxo_accumulator_model.clone()),
            // Fp::<manta_pay::config::ConstraintField>::from(1),
            rng.gen(),
            asset_values,
            &mut rng,
        )
        .1
        .assert_valid_proof(&multi_verifying_context.private_transfer);
        println!("Passed private_transfer check");

        println!("Finished iteration {i}");
    }
}
