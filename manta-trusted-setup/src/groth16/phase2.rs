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
        merge_pairs_affine, Digest, PairingEngineExt, Sample, Zero,
    },
};
use alloc::{vec, vec::Vec};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
pub use ark_serialize::{CanonicalDeserialize, Read};
use ark_serialize::{CanonicalSerialize, SerializationError, Write};
use ark_std::{
    rand::{CryptoRng, Rng},
    UniformRand,
};
use core::marker::PhantomData;
use manta_crypto::rand::OsRng;
use manta_util::{cfg_into_iter, cfg_reduce};

#[cfg(feature = "rayon")]
use rayon::iter::{IndexedParallelIterator, ParallelIterator};

/// Proof
#[derive(Clone, PartialEq, Eq)]
pub struct Proof<E, const N: usize>
where
    E: PairingEngine,
{
    // TODO: To be refactored
    delta_after: E::G1Affine,
    s: E::G1Affine,
    s_delta: E::G1Affine,
    r_delta: E::G2Affine,
    transcript: [u8; N],
}

/// Server States. TODO: To be used for refactor.
pub struct Server<E, const N: usize>
where
    E: PairingEngine,
{
    /// TODO
    pub state: ProvingKey<E>,

    /// TODO
    pub proof_history: Vec<Proof<E, N>>,
}

/// Groth16 Phase 2
pub struct Phase2<E, const N: usize> {
    __: PhantomData<E>,
}

/// State
#[derive(Clone)]
pub struct State<E>
where
    E: PairingEngine,
{
    /// Groth16 Proving Keys
    pub pk: ProvingKey<E>,
}

/// Challenge
pub struct Challenge<const N: usize> {}

/// Contributions and Hashes
pub struct Contributions<E, const N: usize>
where
    E: PairingEngine,
{
    /// TODO
    pub cs_hash: [u8; N],

    /// TODO
    pub contributions: Vec<Proof<E, N>>,
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
    ) -> Result<(State<E>, Contributions<E, N>), PhaseTwoError>
    where
        B: ConstraintSynthesizer<C::Scalar>,
        C: Configuration<Pairing = E, G1 = E::G1Affine, G2 = E::G2Affine, Scalar = E::Fr>,
        H: Digest<N> + Write,
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
            Contributions {
                contributions: Vec::new(),
                cs_hash: hash,
            },
        ))
    }

    /// Sample `delta` from `rng` and generate a range proof for it.
    fn sample_contribution<D, R, H>(
        state: &State<E>,
        // challenge: xxx [TODO]
        previous_contributions: &Contributions<E, N>,
        rng: &mut R,
    ) -> (E::Fr, Proof<E, N>)
    where
        D: Default,
        R: Rng + CryptoRng,
        E: PairingEngine,
        E::Fr: Sample<D>,
        E::G1Affine: Sample<D>,
        E::G2Affine: Sample<D>,
        H: Digest<N> + Write,
    {
        // Sample random delta
        let delta = E::Fr::gen(rng);

        // Compute delta s-pair in G1
        let s = E::G1Affine::gen(rng); // Is projective mul. faster ?
        let s_delta = s.mul(delta).into_affine();

        let h = [0; N];
        {
            let mut hasher = H::new();
            hasher.update(&previous_contributions.cs_hash[..]);
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
            delta,
            Proof {
                delta_after: state.pk.delta_g1.mul(delta).into_affine(),
                s,
                s_delta,
                r_delta,
                transcript: h,
            },
        )
    }

    /// Contribute randomness to the parameters.  The `PublicKey`
    /// of this contribution is then added to a hash chain
    /// to allow a user to later confirm that their
    /// contribution has been included in the final parameters.
    pub fn contribute<D, R, H>(
        state: &mut State<E>,
        previous_contributions: &mut Contributions<E, N>,
        rng: &mut R,
    ) -> [u8; N]
    where
        D: Default,
        E::Fr: Sample<D>,
        E::G1Affine: Sample<D>,
        E::G2Affine: Sample<D>,
        R: Rng + CryptoRng,
        H: Digest<N> + Write,
    {
        // Generate a keypair
        let (delta, proof) =
            Self::sample_contribution::<D, R, H>(state, previous_contributions, rng);
        // Invert delta and multiply the `l` and `h` parameters
        let delta_inv = delta.inverse().expect("nonzero");
        batch_mul_fixed_scalar(&mut state.pk.l_query, delta_inv);
        batch_mul_fixed_scalar(&mut state.pk.h_query, delta_inv);
        // Multiply the `delta_g1` and `delta_g2` elements by the private key delta
        state.pk.delta_g1 = state.pk.delta_g1.mul(delta).into_affine();
        state.pk.vk.delta_g2 = state.pk.vk.delta_g2.mul(delta).into_affine();
        // Ensure delta (the toxic waste) is no longer used
        let _ = delta;
        previous_contributions.contributions.push(proof);
        let mut hasher = H::new();
        hasher.update(&previous_contributions.cs_hash[..]);
        for pubkey in previous_contributions.contributions.clone() {
            pubkey
                .serialize(&mut hasher)
                .expect("Blake2b Hasher never returns an error");
        }
        hasher.finalize()
    }

    /// Verify the validity of all contributions made so far to these parameters.
    /// This method checks that only the parameters affected by Phase2 have changed
    /// and that they were all modified consistently (i.e. pass the same-ratio check).
    /// Output is a list of hashes of public keys that participants may use to confirm
    /// that their contribution is included.
    pub fn verify<B, C, D, H>(
        state: &State<E>,
        contributions: &Contributions<E, N>,
        cs: B,
        powers: Accumulator<C>,
    ) -> Result<Vec<[u8; N]>, PhaseTwoError>
    where
        B: ConstraintSynthesizer<C::Scalar>,
        C: Configuration<Pairing = E, G1 = E::G1Affine, G2 = E::G2Affine, Scalar = E::Fr>,
        E::G2Affine: Sample<D>,
        D: Default,
        H: Clone + Digest<N> + Write,
        <E as PairingEngine>::G1Prepared: From<<E as PairingEngine>::G1Projective>,
    {
        // Build default MPCParameters from phase 1 accumulator
        let (initial_state, initial_contribution_and_hashes) =
            Self::initialize::<B, C, H>(cs, powers)?;

        Self::check_phase_2_invariants(state, &initial_state)?;
        if initial_contribution_and_hashes.cs_hash != contributions.cs_hash {
            return Err(PhaseTwoError::Phase2InvariantViolated(
                "Constraint system hash changed",
            ));
        }

        let mut cumulative_hasher = H::new();
        cumulative_hasher.update(&contributions.cs_hash[..]);
        let mut current_delta = C::g1_prime_subgroup_generator();
        // Record the hash of each contribution's signature here
        let mut result = Vec::<[u8; N]>::with_capacity(contributions.contributions.len());
        for contribution in &contributions.contributions {
            // Check the validity of this contribution
            // First we need the same G2 challenge point used in `proof`
            let h: [u8; N] = {
                let mut hasher = cumulative_hasher.clone();
                contribution
                    .s
                    .serialize_uncompressed(&mut hasher)
                    .expect("Hasher never returns an error");
                contribution
                    .s_delta
                    .serialize_uncompressed(&mut hasher)
                    .expect("Hasher never returns an error");
                hasher.finalize()
            };

            // This check is superfluous: if the transcripts weren't equal then
            // hash_to_group would produce different challenge points and the same_ratio
            // check would fail (with overwhelming probability).  However this error
            // is informative and the check is cheap so we leave it.
            if contribution.transcript != h {
                return Err(PhaseTwoError::ProofTranscriptsDiffer);
            }

            let r: E::G2Affine = hash_to_group(h);

            // Check the signature of knowledge
            if !<C::Pairing as PairingEngineExt>::same_ratio(
                (contribution.s, contribution.s_delta),
                (r, contribution.r_delta),
            ) {
                return Err(PhaseTwoError::SignatureInvalid);
            }

            // Check the change from the old delta is consistent
            if !<C::Pairing as PairingEngineExt>::same_ratio(
                (current_delta, contribution.delta_after),
                (r, contribution.r_delta),
            ) {
                return Err(PhaseTwoError::InconsistentDeltaChange);
            }

            current_delta = contribution.delta_after;

            // Record hash of this contribution
            contribution
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
        // TODO: check cs_hash elsewhere?
        Ok(())
    }

    /// Verifies whether given the `proof` of contribution, the `last` [`State`] leads to `next` [`State`].
    pub fn verify_transform<H, D>(
        last: State<E>,
        next: State<E>,
        previous_contributions: &Contributions<E, N>, // TODO: change this to challenge to match the trait?
        proof: &Proof<E, N>,
    ) -> Result<State<E>, PhaseTwoError>
    where
        D: Default,
        H: Digest<N> + Write,
        E::Fr: Sample<D>,
        E::G1Affine: Sample<D>,
        E::G2Affine: Sample<D>,
    {
        // check phase 2 invariants:
        Self::check_phase_2_invariants(&last, &next)?;
        // compute challenge
        let h = {
            let mut hasher = H::new();
            hasher.update(&previous_contributions.cs_hash);
            for proof in &previous_contributions.contributions {
                proof
                    .serialize(&mut hasher)
                    .expect("Hasher never returns an error");
            }
            proof
                .s
                .serialize_uncompressed(&mut hasher)
                .expect("Hasher never returns an error");
            proof
                .s_delta
                .serialize_uncompressed(&mut hasher)
                .expect("Hasher never returns an error");
            hasher.finalize()
        };
        // The transcript must be consistent
        if proof.transcript != h {
            return Err(PhaseTwoError::ProofTranscriptsDiffer);
        }

        let r = hash_to_group::<E::G2Affine, _, N>(h);
        // check the signature of knowledge
        if !<E as PairingEngineExt>::same_ratio((proof.s, proof.s_delta), (r, proof.r_delta)) {
            return Err(PhaseTwoError::SignatureInvalid);
        }
        // Check the change from the old delta is consistent
        if !<E as PairingEngineExt>::same_ratio(
            (last.pk.delta_g1, proof.delta_after),
            (r, proof.r_delta),
        ) {
            return Err(PhaseTwoError::InconsistentDeltaChange);
        }
        // Current parameters should have consistent delta in G1
        if proof.delta_after != next.pk.delta_g1 {
            return Err(PhaseTwoError::InconsistentDeltaChange);
        }
        // Current parameters should have consistent delta in G2
        if !<E as PairingEngineExt>::same_ratio(
            (E::G1Affine::prime_subgroup_generator(), proof.delta_after),
            (E::G2Affine::prime_subgroup_generator(), next.pk.vk.delta_g2),
        ) {
            return Err(PhaseTwoError::InconsistentDeltaChange);
        }
        // H and L queries should be updated with delta^-1
        if !<E as PairingEngineExt>::same_ratio(
            random_linear_combinations::<E>(&last.pk.h_query, &next.pk.h_query),
            (next.pk.vk.delta_g2, last.pk.vk.delta_g2), // reversed for inverse
        ) {
            return Err(PhaseTwoError::InconsistentHChange);
        }
        if !<E as PairingEngineExt>::same_ratio(
            random_linear_combinations::<E>(&last.pk.l_query, &next.pk.l_query),
            (next.pk.vk.delta_g2, last.pk.vk.delta_g2), // reversed for inverse
        ) {
            return Err(PhaseTwoError::InconsistentLChange);
        }
        // TODO: if we want to return hash here, adapt the following:
        // https://github.com/Manta-Network/trusted-setup/blob/d1d77633429f3898280dd9b8fd9a8713ceec98a3/src/phase_two.rs#L671-L682

        Ok(next)
    }
}

/// Compress two vectors of curve points into a pair of
/// curve points by random linear combination. The same
/// random linear combination is used for both vectors,
/// allowing this pair to be used in a consistent ratio test.
fn random_linear_combinations<E: PairingEngine>(
    lhs: &[E::G1Affine],
    rhs: &[E::G1Affine],
) -> (E::G1Affine, E::G1Affine) {
    assert_eq!(lhs.len(), rhs.len());
    let tmp = cfg_into_iter!(0..lhs.len())
        .map(|_| {
            let mut rng = OsRng;
            E::Fr::rand(&mut rng)
        })
        .zip(lhs)
        .zip(rhs)
        .map(|((rho, lhs), rhs)| (lhs.mul(rho).into_affine(), rhs.mul(rho).into_affine()));
    cfg_reduce!(tmp, || (Zero::zero(), Zero::zero()), |mut acc, next| {
        acc.0 = acc.0 + next.0;
        acc.1 = acc.1 + next.1;
        acc
    })
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
    ProofTranscriptsDiffer,
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

/// Testing Suite
#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use crate::{
        distribution::{Sample as _, SaplingDistribution},
        groth16::kzg::{Contribution, Pairing, Size},
        serialize::serialize_g1_uncompressed,
        util::{BlakeHasher, HasDistribution},
    };
    use ark_bls12_381::Fr;
    use ark_ec::bls12::Bls12;
    use ark_ff::{field_new, Fp256};
    use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar};
    use ark_std::UniformRand;
    use blake2::{Blake2b, Digest as Blake2bDigest};
    use manta_crypto::{
        constraint::{Allocate, Public, Secret},
        rand::SeedableRng,
    };
    use manta_pay::{
        config::{Mint, Reclaim},
        crypto::constraint::arkworks::{Fp, R1CS},
        test::payment::UtxoAccumulator,
    };
    use rand_chacha::ChaCha20Rng;
    use std::println;

    /// Sapling MPC
    #[derive(Clone, Default)]
    pub struct Sapling;

    impl Size for Sapling {
        // const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
        // const G2_POWERS: usize = 1 << 21;
        const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
        const G2_POWERS: usize = 1 << 3;
    }

    impl HasDistribution for Sapling {
        // TODO
        type Distribution = SaplingDistribution;
    }

    impl Pairing for Sapling {
        type Scalar = ark_bls12_381::Fr;
        type G1 = ark_bls12_381::G1Affine;
        type G1Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Prepared;
        type G2 = ark_bls12_381::G2Affine;
        type G2Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Prepared;
        type Pairing = ark_bls12_381::Bls12_381;

        fn sample_g1_affine<R>(rng: &mut R) -> Self::G1
        where
            R: ark_std::rand::CryptoRng + ark_std::rand::RngCore + ?Sized,
        {
            <ark_bls12_381::Bls12_381 as PairingEngine>::G1Projective::rand(rng).into_affine()
        }

        fn sample_g2_affine<R>(rng: &mut R) -> Self::G2
        where
            R: ark_std::rand::CryptoRng + ark_std::rand::RngCore + ?Sized,
        {
            <ark_bls12_381::Bls12_381 as PairingEngine>::G2Projective::rand(rng).into_affine()
        }

        fn g1_prime_subgroup_generator() -> Self::G1 {
            ark_bls12_381::G1Affine::prime_subgroup_generator()
        }

        fn g2_prime_subgroup_generator() -> Self::G2 {
            ark_bls12_381::G2Affine::prime_subgroup_generator()
        }
    }

    impl Configuration for Sapling {
        type DomainTag = u8;
        type Challenge = [u8; 64];
        type Response = [u8; 64];
        const TAU_DOMAIN_TAG: Self::DomainTag = 0;
        const ALPHA_DOMAIN_TAG: Self::DomainTag = 1;
        const BETA_DOMAIN_TAG: Self::DomainTag = 2;

        fn hash_to_g2(
            domain_tag: Self::DomainTag,
            challenge: &Self::Challenge,
            ratio: (&Self::G1, &Self::G1),
        ) -> Self::G2 {
            // TODO: Use Hash trait.
            let mut hasher = Blake2b::default();
            hasher.update(&[domain_tag]);
            hasher.update(&challenge);
            serialize_g1_uncompressed(ratio.0, &mut hasher).unwrap();
            serialize_g1_uncompressed(ratio.1, &mut hasher).unwrap();
            let digest: [u8; 64] = into_array_unchecked(hasher.finalize());

            let mut digest = digest.as_slice();
            let mut seed = Vec::with_capacity(32);
            for _ in 0..4 {
                let mut le_bytes = [0u8; 8];
                let word = digest
                    .read(&mut le_bytes[..])
                    .expect("This is always possible since we have enough bytes to begin with.");
                seed.extend(word.to_le_bytes());
            }
            let mut rng_chacha =
                <ChaCha20Rng as SeedableRng>::from_seed(into_array_unchecked(seed));
            let distribution = SaplingDistribution;
            <Self::G2 as Sample<SaplingDistribution>>::sample::<ChaCha20Rng>(
                distribution,
                &mut rng_chacha,
            )
            // Self::G2::gen::<ChaCha20Rng>(&mut rng_chacha)
            // hash_to_group::<Self::G2, SaplingDistribution, 64>(into_array_unchecked(hasher.finalize()))
        }

        fn response(
            state: &Accumulator<Self>,
            challenge: &Self::Challenge,
            proof: &crate::groth16::kzg::Proof<Self>,
        ) -> Self::Response {
            // TODO: Use Hash trait.
            // let _ = (state, challenge, proof);
            let mut hasher = Blake2b::default();
            for item in &state.tau_powers_g1 {
                item.serialize_uncompressed(&mut hasher).unwrap();
            }
            for item in &state.tau_powers_g2 {
                item.serialize_uncompressed(&mut hasher).unwrap();
            }
            for item in &state.alpha_tau_powers_g1 {
                item.serialize_uncompressed(&mut hasher).unwrap();
            }
            for item in &state.beta_tau_powers_g1 {
                item.serialize_uncompressed(&mut hasher).unwrap();
            }
            state.beta_g2.serialize_uncompressed(&mut hasher).unwrap();
            hasher.update(&challenge);
            proof
                .tau
                .ratio
                .0
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .tau
                .ratio
                .1
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .tau
                .matching_point
                .serialize_uncompressed(&mut hasher)
                .unwrap();

            proof
                .alpha
                .ratio
                .0
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .alpha
                .ratio
                .1
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .alpha
                .matching_point
                .serialize_uncompressed(&mut hasher)
                .unwrap();

            proof
                .beta
                .ratio
                .0
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .beta
                .ratio
                .1
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .beta
                .matching_point
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            into_array_unchecked(hasher.finalize())
        }
    }

    /// TODO
    #[test]
    pub fn test_create_raw_parameters() {
        // Read the final Accumulator from file
        let last_accumulator = Accumulator::<Sapling>::default();

        // Step2: Contribute to accumulator with Phase 1
        // Also verify contribution
        let mut rng = OsRng;
        let challenge = [0; 64];
        let contribution: Contribution<Sapling> = Contribution::gen(&mut rng);
        let proof = contribution.proof(&challenge, &mut rng).unwrap();
        let mut next_accumulator = last_accumulator.clone();
        next_accumulator.update(&contribution);

        // TODO: Need a function for next challenge.
        let next_accumulator =
            Accumulator::verify_transform(last_accumulator, next_accumulator, challenge, proof)
                .unwrap();

        // Step3: Phase2 initialize
        // 1) Find domain size 2) FFT to find Lagrange Polynomial 3) Get co-efficient from the circuit; 4) generate proving key from coefficient
        // let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let mut rng = OsRng;
        // let utxo_accumulator = UtxoAccumulator::new(manta_crypto::rand::Rand::gen(&mut rng));
        // let parameters = manta_crypto::rand::Rand::gen(&mut rng);
        let mut cs = R1CS::for_contexts();
        let a = Fp(field_new!(Fr, "2")).as_known::<Secret, FpVar<_>>(&mut cs);
        let b = Fp(field_new!(Fr, "3")).as_known::<Secret, FpVar<_>>(&mut cs);
        let c = &a * &b;
        let d = Fp(field_new!(Fr, "6")).as_known::<Public, FpVar<_>>(&mut cs);
        c.enforce_equal(&d)
            .expect("enforce_equal is not allowed to fail");
        // TODO

        let (mut state, mut contributions) =
            Phase2::<Bls12<ark_bls12_381::Parameters>, 64>::initialize::<
                R1CS<Fp256<ark_bls12_381::FrParameters>>,
                Sapling,
                BlakeHasher<64>,
            >(cs, next_accumulator)
            .unwrap();

        let last_state = state.clone();

        // Step4: Contribute to Phase 2 params
        let _ = Phase2::<Bls12<ark_bls12_381::Parameters>, 64>::contribute::<(), _, BlakeHasher<64>>(
            &mut state,
            &mut contributions,
            &mut rng,
        );

        // Step5: Verify contribution

        Phase2::<Bls12<ark_bls12_381::Parameters>, 64>::verify_transform::<BlakeHasher<64>, ()>(
            last_state,
            state,
            &Contributions {
                cs_hash: contributions.cs_hash,
                contributions: Vec::new(),
            },
            &contributions.contributions[0],
        )
        .expect("verify transform failed");

        // Phase 3: Generate Proof from random circuits & verify proof
        // TODO
        println!("Specializing to phase 2 parameters");
    }
}
