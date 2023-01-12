# MantaPay Parameters

The parameters in this directory are the current parameters of the MantaPay protocol, namely the proving and verifying keys for Groth16 proofs and base parameters for crytographic hash functions and accumulators. 

Whenever these change the old parameters should be moved to their own directory within `manta-parameters/data/archive` and the new parameters should be placed here at `manta-parameters/data/pay`. The descriptions below should be updated to reflect the changes.

## Current Parameters

The current parameters are the result of the MantaPay trusted setup ceremony after 4,382 rounds of contribution. The list of contribution hashes can be found at `manta-parameters/data/pay/trusted-setup/contribution_hashes.txt`. These keys were computed relative to the base parameters for cryptographic hash functions and accumulators found in `manta-parameters/pay/parameters`, which were randomly sampled.

## Archived Parameters

### Testnet
The parameters in `manta-parameters/data/archive/testnet` are those used for the Dolphin testnet v3. The base parameters for cryptographic hash functions and accumulators were randomly sampled. The Groth16 proving and verifying keys were computed relative to these base parameters and one round of randomly sampled contribution. These proving and verifying keys are not secure for use in production.