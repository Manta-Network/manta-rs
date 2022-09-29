use manta_pay::{
    config::{FullParameters, Mint},
    parameters::{load_transfer_parameters, load_utxo_accumulator_model},
};
use manta_trusted_setup::groth16::{
    kzg,
    mpc::{initialize, State},
    ppot::{
        kzg::PerpetualPowersOfTauCeremony,
        serialization::{read_subaccumulator, Compressed, PpotSerializer},
    },
};
use memmap::MmapOptions;
use std::fs;

const NUM_POWERS: usize = 1 << 10;

type MantaPayPhase1 = PerpetualPowersOfTauCeremony<PpotSerializer, NUM_POWERS>;
type MantaAccumulator = kzg::Accumulator<MantaPayPhase1>;

/// Given Phase 1 parameters and circuit descriptions,
/// transform these into a Groth16 ProvingKey with no
/// contributions.
fn main() {
    let ppot_challenge_path =
        "/Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072.lfs".to_string();
    let reader = fs::OpenOptions::new()
        .read(true)
        .open(ppot_challenge_path)
        .expect("Unable to open challenge in this directory");
    let challenge_reader = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create memory map for input")
    };
    let accumulator: MantaAccumulator =
        read_subaccumulator(&challenge_reader, Compressed::No).unwrap();
    println!("Phase 1 accumulator read successfully");

    let transfer_parameters = load_transfer_parameters();
    let utxo_parameters = load_utxo_accumulator_model();

    println!("Preparing Mint circuit ProverKey");
    // TODO: The CS Mint::unknown... is over Bls12-381, not Bn254
    // let state = initialize(
    //     accumulator,
    //     Mint::unknown_constraints(FullParameters::new(&transfer_parameters, &utxo_parameters)),
    // )
    // .unwrap();

    // Placeholder until actual circuits are available
    // let state = dummy_prover_key();

    // let challenge
}
// cargo run --features="manta-trusted-setup/test memmap ppot std" --bin prepare_phase2

#[cfg(test)]
#[test]
fn test_prepare() {
    // use manta_trusted_setup::groth16::test::dummy_prover_key;

    let ppot_challenge_path =
        "/Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072.lfs".to_string();
    let reader = fs::OpenOptions::new()
        .read(true)
        .open(ppot_challenge_path)
        .expect("Unable to open challenge in this directory");
    let challenge_reader = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create memory map for input")
    };
    let accumulator: MantaAccumulator =
        read_subaccumulator(&challenge_reader, Compressed::No).unwrap();
    println!("Phase 1 accumulator read successfully");

    let state = dummy_prover_key();
}
// cargo test --package manta-trusted-setup --bin prepare_phase2 --features manta-trusted-setup/test --features memmap --features ppot --features std -- test_prepare
