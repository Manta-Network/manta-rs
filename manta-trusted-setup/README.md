# Manta Pay Trusted Setup

From November 28, 2022 to December 29, 2022, Manta Network held a trusted setup ceremony to generate the Groth16 proving keys for the Manta Pay protocol circuits. With 4,382 individual contributions, this was the largest trusted setup thus far in web 3 history. 

The results of the ceremony are now available to the public for verification. We have provided the full ceremony history, including all contribution hashes, the state of the proving keys after each contribution, and the validity proofs that each contribution was made according to the multi-party computation (MPC) protocol. By verifying this chain of proofs, users can be certain that the Manta Pay proving keys are the result of a MPC and carry the 1-of-N security guarantee provided by the MPC protocol. For a layperson's explanation of this MPC, see [here](https://docs.manta.network/docs/concepts/TrustedSetup); for a technical description of the protocol, see [here](https://eprint.iacr.org/2017/1050).

We have provided tools to help users to verify the ceremony results. The remainder of this document explains how to use these tools.

# Trust Assumptions

"Ceremony verification" can mean many things depending on the level of trust a user has in the ceremony coordinators. The more a user trusts Manta Network, the less rigorously they may wish to verify the ceremony results. We will explain these varying levels of rigor in order from most to least trust. Note that more rigorous levels of verification require more resources and expertise.

## Total Trust: No Verification

If you have total trust in the Manta Network team then you can simply use the network without verifying the ceremony results. This is a bit like stepping on a bus without checking that the driver has a license and is what the vast majority of users will do.

## High Trust: Hash Checks Only

We have published a list of contribution hashes [here](https://github.com/Manta-Network/manta-rs/blob/feat/ts_verifier/manta-trusted-setup/contribution_hashes.txt). These hashes are commitments to each of the 4,382 ceremony contributions. If you trust that Manta has correctly computed these hashes from the ceremony transcript, then it is sufficient to check that the hashes in this list match the published claims from ceremony participants. For example, you or someone you trust may have announced their contribution via twitter:

![tweet](./docs/contribution_hash_announcement.png)

To check whether this contribution is included in the final proving key, you can check its contribution hash against the published list. Of course, this assumes that the list was computed correctly.

## Medium Trust: Contribution Proof Checks

Instead of trusting that Manta created the contribution hash list correctly, you can generate it yourself from the ceremony data, which is hosted [here](https://trusted-setup-data-backup.s3.us-east-1.amazonaws.com/index.html). The ceremony data contains all intermediate states and cryptographic proofs that each contribution obeyed the MPC protocol. This is a little under 140 Gb of data. Before demonstrating how to verify this data, let us explain carefully the trust assumptions:

This level of verification checks that each state of the MPC is built from the last according to the MPC protocol. However, it does *not* check that the genesis state of the MPC was computed correctly from a Phase 1 KZG trusted setup and the Manta Pay circuit description. That is, you are trusting that Manta generated the initial proving keys correctly from a secure set of KZG parameters. If you use the verification tool we provide, you are also trusting that it is written correctly; the [source code](https://github.com/Manta-Network/manta-rs/blob/feat/ts_verifier/manta-trusted-setup/src/bin/groth16_phase2_verifier.rs) is yours to examine, of course.

To perform this level of verification, clone this branch of the repository and download all the ceremony data to some directory. Use the following command to initiate the verification process:
```sh
cargo run --release --package manta-trusted-setup --all-features --bin groth16_phase2_verifier -- path_to_ceremony_data 0
```
The `path_to_ceremony_data` argument should be replaced by the path to the directory where you have downloaded the ceremony data. The `0` argument indicates that you wish to begin verification at round 0 of the ceremony. If for some reason you wish to verify the ceremony data during multiple sessions, this argument can be used to start the verification from round `n` of the ceremony.

This process will generate four new files in the directory containing ceremony data. These consist of three auxiliary files containing the challenge hashes for contributions to the three individual Manta Pay circuits as well as one file containing the overall contribution hashes. It is this last file (`contribution_hashes.txt`) that contains the hashes that were announced by participants, as in the above tweet.

If the process terminates without error then all contribution proofs were valid, *i.e.* the ceremony obeyed the MPC protocol and the proving keys are secure as long as at least 1 of the 4,382 participants contributed honestly. The hashes `contribution_hashes.txt` can be compared to those provided in the previous section.

Note that this process may take a long time (about 15 hrs on 32 Gb RAM AWS c6i.4xlarge instance).

## Low Trust: Initial State Check

In addition to checking the contribution proofs as above, a user may wish to check that the ceremony's genesis state was computed correctly. This requires computing the genesis state from Phase 1 KZG parameters and the circuit description. 

The Phase 1 used in this ceremony was Round 72 of the Perpetual Powers of Tau (PPoT) ceremony. These parameters may be downloaded [here](https://ppot.blob.core.windows.net/public/challenge_0072). Note that due to the large size of the PPoT ceremony this file is approximately 100 Gb.

The genesis state can then be computed using the following command:
```sh
cargo run --release --package manta-trusted-setup --all-features --bin groth16_phase2_prepare path_to_challenge_0072 path_to_directory
```
The `path_to_challenge_0072` is a path to the file containing the PPoT round 72 file; the `path_to_directory` is a path to an output directory where the genesis state will be placed. The process takes about 5 minutes (on an M1 Mac with 16 Gb RAM).

This generates the initial MPC state and challenge files. Move these to the directory containing all ceremony data to replace the genesis state and challenge with the one you just generated, then perform the check from the previous section.

This level of verification completely eliminates trust in the ceremony coordinator (Manta Network), but still requires that one trust in the security of the PPoT Phase 1 parameters used.

## No Trust: PPoT Check (the most hardcore)

To eliminate trust in the PPoT ceremony, one must also verify the contribution proofs for the first 72 rounds of PPoT. This is quite an endeavor, as that corresponds to about 7 Tb of data that must be downloaded and checked.

There is a shortcut, however: rather than checking the full parameter set for each round of PPoT, one can check only as many powers as are needed to form the Manta Pay proving keys. This is only $2^{19}$ powers, as opposed to the full $2^{28}$ generated by PPoT. This reduces the verification cost by a factor of about 500 by performing far fewer scalar multiplications. Note however that challenge hashes still must be computed using the full parameter sets, so there is no way to avoid downloading all 7 Tb of parameters.

Manta performed this cheaper verification using tools that can be found in [this repository](https://github.com/Manta-Network/ppot-verifier). We concluded that all the powers of tau needed to generate our proving keys were computed according to the phase 1 MPC protocol, and are thus secure as long as at least 1 of the 72 PPoT participants was honest.

For the full PPoT data see [here](https://github.com/weijiekoh/perpetualpowersoftau).

For another PPoT verification tool, see Kobi Gurkan's [repository](https://github.com/kobigurk/phase2-bn254/tree/powers_28).