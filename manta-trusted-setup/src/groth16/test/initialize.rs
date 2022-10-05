use crate::groth16::{kzg, mpc::ProvingKeyHasher};
use manta_crypto::arkworks::serialize::CanonicalSerialize;
use memmap::MmapOptions;
use std::fs;

#[cfg(feature = "ppot")]
use crate::groth16::ppot::{
    kzg::PerpetualPowersOfTauCeremony,
    serialization::{read_subaccumulator, Compressed, PpotSerializer},
};

const NUM_POWERS: usize = 1 << 10;

type MantaPayPhase1 = PerpetualPowersOfTauCeremony<PpotSerializer, NUM_POWERS>;
type MantaAccumulator = kzg::Accumulator<MantaPayPhase1>;

#[cfg(feature = "ppot")]
#[test]
fn test_prepare() {
    use std::{fs::File, io::Write};

    use crate::groth16::test::dummy_prover_key;

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
    let _accumulator: MantaAccumulator =
        read_subaccumulator(&challenge_reader, Compressed::No).unwrap();
    println!("Phase 1 accumulator read successfully");

    let state = dummy_prover_key();
    let challenge = <MantaPayPhase1 as ProvingKeyHasher<_>>::hash(&state);

    // Write to disk
    let mut file = File::create("dummy_state").expect("Open file should succeed");
    let mut buffer = Vec::<u8>::new();
    CanonicalSerialize::serialize(&state, &mut buffer)
        .expect("Writing state to disk should succeed");
    file.write_all(&buffer)
        .expect("Writing challenge to disk should succeed");
    file.flush().expect("Flushing file should succeed.");

    // Write to disk
    let mut file = File::create("dummy_challenge").expect("Open file should succeed");
    file.write_all(&challenge)
        .expect("Writing challenge to disk should succeed");
    file.flush().expect("Flushing file should succeed.");
}
// cargo test --package manta-trusted-setup --lib --features ppot -- groth16::test::random::test_prepare --exact --nocapture
