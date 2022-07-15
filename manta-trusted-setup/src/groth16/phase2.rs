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

//! Groth16 Phase 2
use crate::{
    groth16::kzg::{Accumulator, Configuration, Pairing},
    util::{
        batch_into_projective, batch_mul_fixed_scalar, hash_to_group, into_array_unchecked,
        merge_pairs_affine, Digest, PairingEngineExt, Zero,
    },
};
use alloc::{vec, vec::Vec};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalSerialize, SerializationError, Write};
use ark_std::rand::{CryptoRng, Rng};
use core::marker::PhantomData;
use manta_crypto::{accumulator::ConstantCapacityAccumulator, rand::Sample};

/// TODO
pub type Contribution<E> = <E as PairingEngine>::Fr;

/// Groth16 Phase 2
pub struct Phase2<E, const N: usize> {
    __: PhantomData<E>,
}

/// TODO: may change the name
pub struct State<E>
where
    E: PairingEngine,
{
    /// TODO
    pub pk: ProvingKey<E>,
}

/// TODO: may change the name
pub struct ContributionAndHashes<E, const N: usize>
where
    E: PairingEngine,
{
    /// TODO
    pub hash: [u8; N],

    /// TODO
    pub contributions: Vec<Proof<E, N>>,
}

/// This struct carries the data from a contribution
/// that allows others to test it.  The hash returned
/// by MPCParameters::contribute is the Blake2b hash
/// of this object.
#[derive(Clone, PartialEq, Eq)]
pub struct Proof<E, const N: usize>
where
    E: PairingEngine,
{
    delta_after: E::G1Affine,
    s: E::G1Affine,
    s_delta: E::G1Affine,
    r_delta: E::G2Affine,
    transcript: [u8; N],
}

impl<E, const N: usize> CanonicalSerialize for Proof<E, N>
where
    E: PairingEngine,
{
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.delta_after.serialize(&mut writer)?;
        self.s.serialize(&mut writer)?;
        self.s_delta.serialize(&mut writer)?;
        self.r_delta.serialize(&mut writer)?;
        writer.write_all(&self.transcript)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.delta_after.serialized_size()
            + self.s.serialized_size()
            + self.s_delta.serialized_size()
            + self.r_delta.serialized_size()
            + N // TODO: There might be an error related to u8 vs usize.
    }
}

impl<E, const N: usize> Phase2<E, N>
where
    E: PairingEngine,
{
    /// TODO
    pub fn initialize<B, C, H>(
        cs: B,
        powers: Accumulator<C>,
    ) -> Result<(State<E>, ContributionAndHashes<E, N>), PhaseTwoError>
    where
        B: ConstraintSynthesizer<C::Scalar>,
        C: Configuration<Pairing = E, G1 = E::G1Affine, G2 = E::G2Affine, Scalar = E::Fr>,
        H: Digest<N>,
    {
        let constraints = ConstraintSystem::new_ref();
        cs.generate_constraints(constraints.clone())
            .map_err(PhaseTwoError::ConstraintSystemError)?;
        constraints.finalize();

        // Determine evaluation domain size from constraint system
        let num_constraints = constraints.num_constraints();
        let num_instance_variables = constraints.num_instance_variables();
        let domain = match Radix2EvaluationDomain::<C::Scalar>::new(
            num_constraints + num_instance_variables,
        ) {
            Some(domain) => domain,
            None => return Err(PhaseTwoError::TooManyConstraints),
        };

        // Get a, b, c matrices
        let constraint_matrices = match constraints.to_matrices() {
            Some(matrices) => matrices,
            None => return Err(PhaseTwoError::MissingCSMatrices),
        };

        // Grab the commitment `beta * g1` before it's consumed by IFFT
        // (Only necessary if you IFFT in place)
        let beta_g1 = powers.beta_tau_powers_g1[0];

        // Compute the tau^i Z(tau) commitments before powers of tau are IFFT'd.
        // Since Z(tau) = (tau^degree - 1) this is computed as
        // tau^(i + degree) - tau^i
        let degree = domain.size as usize; // safe because domain.size is at most 2^22
        let mut h_query = Vec::with_capacity(degree - 1);
        for i in 0..degree {
            let tmp = powers.tau_powers_g1[i + degree].into_projective();
            let tmp2 = powers.tau_powers_g1[i].into_projective();

            h_query.push((tmp - tmp2).into_affine()); // ? Does it really make snse to convert to affine right now?
        }

        // `Accumulator` holds commitments in monomial basis; use IFFT to transform
        // to Lagrange basis.
        // // INEFFICIENT: probably should ifft in place b/c these vectors are huge -- but should the Accumulator really be mutable ?
        // let tau_powers_g1_proj = powers.tau_powers_g1.iter().map(|p| p.into_projective()).collect::<Vec<_>>();
        // TODO: Those should be written to disk after phase 1 and read in from there
        let tau_lagrange_g1 = domain.ifft(&batch_into_projective(&powers.tau_powers_g1));
        let tau_lagrange_g2 = domain.ifft(&batch_into_projective(&powers.tau_powers_g2));
        let alpha_lagrange_g1 = domain.ifft(&batch_into_projective(&powers.alpha_tau_powers_g1));
        let beta_lagrange_g1 = domain.ifft(&batch_into_projective(&powers.beta_tau_powers_g1));

        // Compute the various circuit-specific polynomial commitments
        // Note that all curve points are projective here
        let num_witnesses =
            constraint_matrices.num_witness_variables + constraint_matrices.num_instance_variables;

        let mut a_g1 = vec![<C as Pairing>::G1::zero().into_projective(); num_witnesses];
        let mut b_g1 = vec![<C as Pairing>::G1::zero().into_projective(); num_witnesses];
        let mut b_g2 = vec![<C as Pairing>::G2::zero().into_projective(); num_witnesses];
        let mut ext = vec![<C as Pairing>::G1::zero().into_projective(); num_witnesses];

        // Adds public input constraints to ensure their consistency, as in "Libsnark reduction"
        // This is essentially adding the constraint pi * 0 = 0 for each public input.  I do not
        // understand why it is necessary.
        {
            let start = 0;
            let end = num_instance_variables;
            a_g1[start..end].copy_from_slice(
                &tau_lagrange_g1[(start + num_constraints)..(end + num_constraints)],
            );
            ext[start..end].copy_from_slice(
                &beta_lagrange_g1[(start + num_constraints)..(end + num_constraints)],
            );
        }

        specialize_to_phase_2(
            &tau_lagrange_g1,
            &tau_lagrange_g2,
            &alpha_lagrange_g1,
            &beta_lagrange_g1,
            &constraint_matrices.a,
            &constraint_matrices.b,
            &constraint_matrices.c,
            &mut a_g1,
            &mut b_g1,
            &mut b_g2,
            &mut ext,
        );

        // Projective -> Affine
        let a_query = ProjectiveCurve::batch_normalization_into_affine(&a_g1);
        let b_g1_query = ProjectiveCurve::batch_normalization_into_affine(&b_g1);
        let b_g2_query = ProjectiveCurve::batch_normalization_into_affine(&b_g2);
        let ext = ProjectiveCurve::batch_normalization_into_affine(&ext);
        // Split `ext` into public and private witness parts
        let public_cross_terms = Vec::from(&ext[..constraint_matrices.num_instance_variables]);
        let private_cross_terms = Vec::from(&ext[constraint_matrices.num_instance_variables..]);

        // Make the verifying key using default values for the `delta_g` curve points
        let vk = VerifyingKey::<C::Pairing> {
            alpha_g1: powers.alpha_tau_powers_g1[0],
            beta_g2: powers.beta_g2,
            gamma_g2: C::g2_prime_subgroup_generator(), // This will not be modified by contributions. See Bowe, Gabizon '19
            delta_g2: C::g2_prime_subgroup_generator(),
            gamma_abc_g1: public_cross_terms, // `gamma` = 1 actually BG'19
        };

        // Make the proving key
        let pk = ProvingKey::<C::Pairing> {
            vk,
            beta_g1,
            delta_g1: C::g1_prime_subgroup_generator(),
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query: private_cross_terms,
        };

        // Hash the proving key, store this as `cs_hash`
        let mut hasher = H::new();
        pk.serialize(&mut hasher)
            .expect("Hasher is not allowed to fail");
        let hash = hasher.finalize();

        Ok((
            State { pk },
            ContributionAndHashes {
                contributions: Vec::new(),
                hash,
            },
        ))
    }

    /// Sample `delta` from `rng` and generate a range proof for it.
    pub fn keypair<D, R, H>(
        state: &State<E>,
        previous_contributions: &ContributionAndHashes<E, N>,
        rng: &mut R,
    ) -> (Proof<E, N>, Contribution<E>)
    where
        D: Default,
        R: Rng + CryptoRng,
        E: PairingEngine,
        E::Fr: Sample<D>,
        E::G1Affine: Sample<D>,
        E::G2Affine: Sample<D>,
        H: Digest<N>,
    {
        // Sample random delta
        let delta = E::Fr::gen(rng);

        // Compute delta s-pair in G1
        let s = E::G1Affine::gen(rng); // Is projective mul. faster ?
        let s_delta = s.mul(delta).into_affine();

        let h = {
            let mut hasher = H::new();
            hasher.update(&previous_contributions.hash[..]);
            for pubkey in previous_contributions.contributions.clone() {
                // ? better solution than clone ?
                pubkey
                    .serialize(&mut hasher)
                    .expect("Blake2b Hasher never returns an error");
            }
            s.serialize_uncompressed(&mut hasher)
                .expect("Blake2b Hasher never returns an error");
            s_delta
                .serialize_uncompressed(&mut hasher)
                .expect("Blake2b Hasher never returns an error");
            hasher.finalize()
        };

        // Compute delta s-pair in G2
        let r: E::G2Affine = hash_to_group(h); // could fix distribution D here for phase two, or can leave
        let r_delta = r.mul(delta).into_affine();

        (
            Proof {
                delta_after: state.pk.delta_g1.mul(delta).into_affine(),
                s,
                s_delta,
                r_delta,
                transcript: h,
            },
            delta,
        )
    }

    /// Contribute randomness to the parameters.  The `PublicKey`
    /// of this contribution is then added to a hash chain
    /// to allow a user to later confirm that their
    /// contribution has been included in the final parameters.
    pub fn contribute<D, R, H>(
        state: &mut State<E>,
        previous_contributions: &mut ContributionAndHashes<E, N>,
        rng: &mut R,
    ) -> [u8; N]
    where
        D: Default,
        E::Fr: Sample<D>,
        E::G1Affine: Sample<D>,
        E::G2Affine: Sample<D>,
        R: Rng + CryptoRng,
        H: Digest<N>,
    {
        // Generate a keypair
        let (proof, contribution) = Self::keypair::<D, R, H>(state, previous_contributions, rng);
        // Invert delta and multiply the `l` and `h` parameters
        let delta_inv = contribution.inverse().expect("nonzero");
        batch_mul_fixed_scalar(&mut state.pk.l_query, delta_inv);
        batch_mul_fixed_scalar(&mut state.pk.h_query, delta_inv);
        // Multiply the `delta_g1` and `delta_g2` elements by the private key delta
        state.pk.delta_g1 = state.pk.delta_g1.mul(contribution).into_affine();
        state.pk.vk.delta_g2 = state.pk.vk.delta_g2.mul(contribution).into_affine();
        // Ensure the private key is no longer used
        drop(contribution);
        previous_contributions.contributions.push(proof);
        let mut hasher = H::new();
        hasher.update(&previous_contributions.hash[..]);
        for pubkey in previous_contributions.contributions.clone() {
            pubkey
                .serialize(&mut hasher)
                .expect("Blake2b Hasher never returns an error");
        }
        into_array_unchecked(hasher.finalize())
    }

    /// Verify the validity of all contributions made so far to these parameters.
    /// This method checks that only the parameters affected by Phase2 have changed
    /// and that they were all modified consistently (i.e. pass the same-ratio check).
    /// Output is a list of hashes of public keys that participants may use to confirm
    /// that their contribution is included.
    pub fn verify<B, C, D, H>(
        state: &State<E>,
        contribution_and_hashes: &ContributionAndHashes<E, N>,
        cs: B,
        powers: Accumulator<C>,
    ) -> Result<Vec<[u8; N]>, PhaseTwoError>
    where
        B: ConstraintSynthesizer<C::Scalar>,
        C: Configuration<Pairing = E, G1 = E::G1Affine, G2 = E::G2Affine, Scalar = E::Fr>,
        E::G2Affine: Sample<D>,
        D: Default,
        H: Clone + Digest<N>,
        <E as PairingEngine>::G1Prepared: From<<E as PairingEngine>::G1Projective>
    {
        // Build default MPCParameters from phase 1 accumulator
        let (initial_state, initial_contribution_and_hashes) = Self::initialize::<B, C, H>(cs, powers)?;

        Self::check_phase_2_invariants(
            state,
            &initial_state,
            contribution_and_hashes,
            &initial_contribution_and_hashes,
        )?;

        let mut cumulative_hasher = H::new();
        cumulative_hasher.update(&contribution_and_hashes.hash[..]);
        let mut current_delta = C::g1_prime_subgroup_generator();
        // Record the hash of each contribution's signature here
        let mut result = Vec::<[u8; N]>::with_capacity(contribution_and_hashes.contributions.len());
        for pubkey in &contribution_and_hashes.contributions {
            // Check the validity of this contribution
            // First we need the same G2 challenge point used in `pubkey`
            let h: [u8; N] = {
                let mut hasher = cumulative_hasher.clone();
                pubkey
                    .s
                    .serialize_uncompressed(&mut hasher)
                    .expect("Blake2b Hasher never returns an error");
                pubkey
                    .s_delta
                    .serialize_uncompressed(&mut hasher)
                    .expect("Blake2b Hasher never returns an error");
                hasher.finalize().into()
            };

            // This check is superfluous: if the transcripts weren't equal then
            // hash_to_group would produce different challenge points and the same_ratio
            // check would fail (with overwhelming probability).  However this error
            // is informative and the check is cheap so we leave it.
            if pubkey.transcript != h {
                return Err(PhaseTwoError::PubKeyTranscriptsDiffer);
            }

            let r: E::G2Affine = hash_to_group(h);

            // Check the signature of knowledge
            if !<C::Pairing as PairingEngineExt>::same_ratio(
                (pubkey.s, pubkey.s_delta),
                (r, pubkey.r_delta),
            ) {
                return Err(PhaseTwoError::SignatureInvalid);
            }

            // Check the change from the old delta is consistent
            if !<C::Pairing as PairingEngineExt>::same_ratio(
                (current_delta, pubkey.delta_after),
                (r, pubkey.r_delta),
            ) {
                return Err(PhaseTwoError::InconsistentDeltaChange);
            }

            current_delta = pubkey.delta_after;

            // Record hash of this contribution
            pubkey
                .serialize(&mut cumulative_hasher)
                .expect("Blake2b Hasher never returns an error");
            result.push(into_array_unchecked(cumulative_hasher.clone().finalize()));
        }

        // Current parameters should have consistent delta in G1
        if current_delta != state.pk.delta_g1 {
            return Err(PhaseTwoError::InconsistentDeltaChange);
        }
        // Current parameters should have consistent delta in G2
        if !<C::Pairing as PairingEngineExt>::same_ratio(
            (C::g1_prime_subgroup_generator(), current_delta),
            (C::g2_prime_subgroup_generator(), state.pk.vk.delta_g2),
        ) {
            return Err(PhaseTwoError::InconsistentDeltaChange);
        }
        // H and L queries should be updated with delta^-1x
        if !<C::Pairing as PairingEngineExt>::same_ratio(
            merge_pairs_affine(&initial_state.pk.l_query, &state.pk.l_query),
            (state.pk.vk.delta_g2, C::g2_prime_subgroup_generator()), // reversed for delta inverse
        ) {
            return Err(PhaseTwoError::InconsistentLChange);
        }
        if !<C::Pairing as PairingEngineExt>::same_ratio(
            merge_pairs_affine(&initial_state.pk.h_query, &state.pk.h_query),
            (state.pk.vk.delta_g2, C::g2_prime_subgroup_generator()), // reversed for delta inverse
        ) {
            return Err(PhaseTwoError::InconsistentHChange);
        }
        Ok(result)
    }

    /// Checks that the parameters which are not changed by Phase 2 contributions
    /// are the same.
    pub fn check_phase_2_invariants(
        state: &State<E>,
        initial_state: &State<E>,
        contribution_and_hashes: &ContributionAndHashes<E, N>,
        initial_contribution_and_hashes: &ContributionAndHashes<E, N>,
    ) -> Result<(), PhaseTwoError> {
        // H/L will change, but should have same length
        if initial_state.pk.h_query.len() != state.pk.h_query.len() {
            return Err(PhaseTwoError::Phase2InvariantViolated("H length changed"));
        }
        if initial_state.pk.l_query.len() != state.pk.l_query.len() {
            return Err(PhaseTwoError::Phase2InvariantViolated("L length changed"));
        }
        // A/B_G1/B_G2 doesn't change at all
        if initial_state.pk.a_query != state.pk.a_query {
            return Err(PhaseTwoError::Phase2InvariantViolated("A query changed"));
        }
        if initial_state.pk.b_g1_query != state.pk.b_g1_query {
            return Err(PhaseTwoError::Phase2InvariantViolated("B_G1 query changed"));
        }
        if initial_state.pk.b_g2_query != state.pk.b_g2_query {
            return Err(PhaseTwoError::Phase2InvariantViolated("B_G2 query changed"));
        }
        // alpha/beta/gamma don't change
        if initial_state.pk.vk.alpha_g1 != state.pk.vk.alpha_g1 {
            return Err(PhaseTwoError::Phase2InvariantViolated("alpha_G1 changed"));
        }
        if initial_state.pk.beta_g1 != state.pk.beta_g1 {
            return Err(PhaseTwoError::Phase2InvariantViolated("beta_G1 changed"));
        }
        if initial_state.pk.vk.beta_g2 != state.pk.vk.beta_g2 {
            return Err(PhaseTwoError::Phase2InvariantViolated("beta_G2 changed"));
        }
        if initial_state.pk.vk.gamma_g2 != state.pk.vk.gamma_g2 {
            return Err(PhaseTwoError::Phase2InvariantViolated("gamma_G2 changed"));
        }
        // IC shouldn't change, as gamma doesn't change
        if initial_state.pk.vk.gamma_abc_g1 != state.pk.vk.gamma_abc_g1 {
            return Err(PhaseTwoError::Phase2InvariantViolated(
                "Public input cross terms changed",
            ));
        }
        // cs_hash should be the same
        if contribution_and_hashes.hash != initial_contribution_and_hashes.hash {
            return Err(PhaseTwoError::Phase2InvariantViolated(
                "Constraint system hash changed",
            ));
        }
        Ok(())
    }
}

/// Specialize all phase1 parameters to phase2 parameters (except `h_query`) at once.
/// This is like doing `eval_poly` in parallel on all four kinds of commitments that
/// phase 2 param.s require (`a_g1`, `b_g1`, `b_g2`, `extra`) where `extra` is the
/// cross term that we (may wish to) compute separately for public/private inputs.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn specialize_to_phase_2<G1, G2>(
    // Powers of tau in Lagrange basis
    tau_basis_g1: &[G1],
    tau_basis_g2: &[G2],
    alpha_tau_basis: &[G1],
    beta_tau_basis: &[G1],
    // Collection of QAP polynomials, specified by value
    a_poly: &[Vec<(G1::ScalarField, usize)>],
    b_poly: &[Vec<(G1::ScalarField, usize)>],
    c_poly: &[Vec<(G1::ScalarField, usize)>],
    // The resulting commitments, which we compute in-place
    a_g1: &mut [G1],
    b_g1: &mut [G1],
    b_g2: &mut [G2],
    ext: &mut [G1],
) where
    G1: ProjectiveCurve,
    G2: ProjectiveCurve<ScalarField = G1::ScalarField>,
{
    // Check lengths of vectors are consistent
    assert_eq!(a_g1.len(), b_g1.len());
    assert_eq!(a_g1.len(), b_g2.len());
    assert_eq!(a_g1.len(), ext.len());

    // Performs matrix multiplications, but not in parallel. Iteration is over the constraints, not the witnesses
    // TODO How can you parallelize this?
    a_poly
        .iter()
        .zip(b_poly.iter())
        .zip(c_poly.iter())
        .zip(tau_basis_g1.iter())
        .zip(tau_basis_g2.iter())
        .zip(alpha_tau_basis.iter())
        .zip(beta_tau_basis.iter())
        .for_each(
            |((((((a_poly, b_poly), c_poly), tau_g1), tau_g2), alpha_tau), beta_tau)| {
                for (coeff, index) in a_poly.iter() {
                    // index is indexing a variable, not a constraint
                    a_g1[*index] += tau_g1.mul(coeff.into_repr());
                    ext[*index] += beta_tau.mul(coeff.into_repr());
                }
                for (coeff, index) in b_poly.iter() {
                    b_g1[*index] += tau_g1.mul(coeff.into_repr());
                    b_g2[*index] += tau_g2.mul(coeff.into_repr());
                    ext[*index] += alpha_tau.mul(coeff.into_repr());
                }
                for (coeff, index) in c_poly.iter() {
                    ext[*index] += tau_g1.mul(coeff.into_repr());
                }
            },
        );
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// TODO
pub enum PhaseTwoError {
    /// TODO
    TooManyConstraints,
    /// TODO
    ConstraintSystemError(ark_relations::r1cs::SynthesisError),
    /// TODO
    MissingCSMatrices,
    /// TODO
    ConstraintSystemHashesDiffer,
    /// TODO
    PubKeyTranscriptsDiffer,
    /// TODO
    SignatureInvalid,
    /// TODO
    InconsistentDeltaChange,
    /// TODO
    InconsistentLChange,
    /// TODO
    InconsistentHChange,
    /// TODO
    Phase2InvariantViolated(&'static str),
}

// /// Reads from file to get a "raw" version of the parameters derived from
// /// the final sapling phase 1 parameters with no contributions made (delta = 1).
// pub fn default_reclaim_mpc() -> MPCParameters<<Sapling as Configuration>::Pairing> {
//     let mut reader = OpenOptions::new()
//         .read(true)
//         .open("phase2_reclaim_raw_mpc")
//         .expect("file not found");

//     CanonicalDeserialize::deserialize_unchecked(&mut reader).unwrap()
// }



