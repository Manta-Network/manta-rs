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
    groth16::kzg::{Accumulator, Configuration, RatioProof},
    util::{
        batch_into_projective, batch_mul_fixed_scalar, hash_to_group, AffineCurve,
        CanonicalSerialize, Field, Hash, Pairing, PairingEngineExt, PrimeField, ProjectiveCurve,
        Sample, Write, Zero,
    },
};
use alloc::{vec, vec::Vec};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_std::{
    rand::{CryptoRng, Rng},
    UniformRand,
};
use core::{clone::Clone, marker::PhantomData};
use manta_crypto::rand::OsRng;
use manta_util::{cfg_into_iter, cfg_reduce};

#[cfg(feature = "rayon")]
use rayon::iter::{IndexedParallelIterator, ParallelIterator};

/// State
#[derive(Clone)]
pub struct State<P>
where
    P: Pairing,
{
    /// Groth16 Proving Keys
    pub pk: ProvingKey<P::Pairing>,
}

/// Contributions and Hashes
pub struct Contributions<P, const N: usize>
where
    P: Pairing,
{
    /// Constraint System Hash
    pub cs_hash: [u8; N],

    /// Ratio Proofs
    pub proofs: Vec<RatioProof<P>>,

    /// States
    pub states: Vec<State<P>>,
}

/// Trusted Setup Phase2 Configuuration
pub trait PhaseTwoConfiguration<const N: usize>: Sized {
    /// Challenge Type
    type Challenge;

    /// Pairing Type
    type Pairing: Pairing;

    /// Initializes state and contributions for phase2 trusted setup.
    fn initialize<B, C, H>(
        cs: B,
        powers: Accumulator<C>,
    ) -> Result<(State<Self::Pairing>, Contributions<Self::Pairing, N>), PhaseTwoError>
    where
        B: ConstraintSynthesizer<C::Scalar>,
        C: Configuration<
            Pairing = <Self::Pairing as Pairing>::Pairing,
            G1 = <Self::Pairing as Pairing>::G1,
            G2 = <Self::Pairing as Pairing>::G2,
            Scalar = <Self::Pairing as Pairing>::Scalar,
        >,
        H: Hash<N> + Write;

    /// TODO
    fn challenge<H>(
        challenge: Self::Challenge,
        prev_state: State<Self::Pairing>,
        cur_state: State<Self::Pairing>,
        ratio_proof: RatioProof<Self::Pairing>,
    ) -> Self::Challenge
    where
        H: Hash<N> + Write;

    /// Samples a randomness from `rng`, contributes to `state`, and generates a
    /// ratio proof with `challenge`.
    fn contribute<R, D, H>(
        state: &mut State<Self::Pairing>,
        challenge: Self::Challenge,
        rng: &mut R,
    ) -> (State<Self::Pairing>, RatioProof<Self::Pairing>)
    where
        D: Default,
        R: Rng + CryptoRng,
        <Self::Pairing as Pairing>::Scalar: Sample<D>,
        <Self::Pairing as Pairing>::G1: Sample<D>,
        <Self::Pairing as Pairing>::G2: Sample<D>,
        H: Hash<N> + Write;

    /// Verifies if transformation from `prev_state` to `cur_state` is valid
    /// given the `ratio_proof` and `prev_challenge`.
    fn verify_transform<H, D>(
        prev_challenge: Self::Challenge,
        prev_state: State<Self::Pairing>,
        cur_state: State<Self::Pairing>,
        ratio_proof: RatioProof<Self::Pairing>,
    ) -> Result<(State<Self::Pairing>, Self::Challenge), PhaseTwoError>
    where
        D: Default,
        H: Hash<N> + Write,
        <Self::Pairing as Pairing>::Scalar: Sample<D>,
        <Self::Pairing as Pairing>::G1: Sample<D>,
        <Self::Pairing as Pairing>::G2: Sample<D>,
        State<Self::Pairing>: Clone;

    /// TODO
    fn verify_transform_all<B, C, D, H>(
        state: State<Self::Pairing>,
        contributions: Contributions<Self::Pairing, N>,
        constraint_system: B,
        powers: Accumulator<C>,
    ) -> Result<(), PhaseTwoError>
    where
        B: ConstraintSynthesizer<C::Scalar>,
        C: Configuration<
            Pairing = <Self::Pairing as Pairing>::Pairing,
            G1 = <Self::Pairing as Pairing>::G1,
            G2 = <Self::Pairing as Pairing>::G2,
            Scalar = <Self::Pairing as Pairing>::Scalar,
        >,
        H: Hash<N> + Write,
        // <Self::Pairing as Pairing>::G1Prepared:
        //     From<<<Self::Pairing as Pairing>::G1 as AffineCurve>::Projective>,
        // H: Hash<N> + Write,
        <Self::Pairing as Pairing>::Scalar: Sample<D>,
        <Self::Pairing as Pairing>::G1: Sample<D>,
        <Self::Pairing as Pairing>::G2: Sample<D>,
        State<Self::Pairing>: Clone,
        D: Default;

    /// TODO
    fn update(
        state: State<Self::Pairing>,
        ratio_proof: RatioProof<Self::Pairing>,
        contributions: Contributions<Self::Pairing, N>,
    ) -> Contributions<Self::Pairing, N>;
}

/// Groth16 Phase 2
pub struct Phase2<P, const N: usize> {
    __: PhantomData<P>,
}

impl<P, const N: usize> PhaseTwoConfiguration<N> for Phase2<P, N>
where
    P: Pairing,
{
    type Challenge = [u8; N];

    type Pairing = P;

    /// Initializes state and contributions for phase2 trusted setup.
    fn initialize<B, C, H>(
        cs: B,
        powers: Accumulator<C>,
    ) -> Result<(State<P>, Contributions<P, N>), PhaseTwoError>
    where
        B: ConstraintSynthesizer<C::Scalar>,
        C: Configuration<
            Pairing = <Self::Pairing as Pairing>::Pairing,
            G1 = <Self::Pairing as Pairing>::G1,
            G2 = <Self::Pairing as Pairing>::G2,
            Scalar = <Self::Pairing as Pairing>::Scalar,
        >,
        H: Hash<N> + Write,
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

        let mut hasher = H::new();
        pk.serialize(&mut hasher)
            .expect("Hasher is not allowed to fail");

        Ok((
            State { pk: pk.clone() },
            Contributions {
                cs_hash: hasher.finalize(),
                proofs: Vec::new(),
                states: Vec::new(),
            },
        ))
    }

    fn challenge<H>(
        challenge: Self::Challenge,
        prev_state: State<Self::Pairing>,
        cur_state: State<Self::Pairing>,
        ratio_proof: RatioProof<Self::Pairing>,
    ) -> Self::Challenge
    where
        H: Hash<N> + Write,
    {
        let mut hasher = H::new();
        hasher.update(challenge);
        prev_state
            .pk
            .serialize(&mut hasher)
            .expect("Consuming `prev_state` failed.");
        cur_state
            .pk
            .serialize(&mut hasher)
            .expect("Consuming `cur_state` failed.");
        ratio_proof
            .ratio
            .0
            .serialize(&mut hasher)
            .expect("Consuming ratio_proof failed");
        ratio_proof
            .ratio
            .1
            .serialize(&mut hasher)
            .expect("Consuming ratio_proof failed");
        ratio_proof
            .matching_point
            .serialize(&mut hasher)
            .expect("Consuming ratio_proof failed");
        hasher.finalize()
    }

    /// Sample `delta` from `rng` and generate a range proof for it.
    fn contribute<R, D, H>(
        state: &mut State<Self::Pairing>,
        challenge: Self::Challenge,
        rng: &mut R,
    ) -> (State<Self::Pairing>, RatioProof<Self::Pairing>)
    where
        D: Default,
        R: Rng + CryptoRng,
        <Self::Pairing as Pairing>::Scalar: Sample<D>,
        <Self::Pairing as Pairing>::G1: Sample<D>,
        <Self::Pairing as Pairing>::G2: Sample<D>,
        H: Hash<N> + Write,
    {
        let delta = P::Scalar::gen(rng);
        let delta_inv = delta.inverse().expect("nonzero");
        let g = P::G1::gen(rng);
        batch_mul_fixed_scalar(&mut state.pk.l_query, delta_inv);
        batch_mul_fixed_scalar(&mut state.pk.h_query, delta_inv);
        state.pk.delta_g1 = state.pk.delta_g1.mul(delta).into_affine();
        state.pk.vk.delta_g2 = state.pk.vk.delta_g2.mul(delta).into_affine();
        (
            State {
                pk: state.pk.clone(),
            },
            RatioProof {
                ratio: (g, g.mul(delta).into_affine()),
                matching_point: hash_to_group::<P::G2, _, N>(challenge)
                    .mul(delta)
                    .into_affine(),
            },
        )
    }

    fn verify_transform<H, D>(
        prev_challenge: Self::Challenge,
        prev_state: State<Self::Pairing>,
        cur_state: State<Self::Pairing>,
        ratio_proof: RatioProof<Self::Pairing>,
    ) -> Result<(State<Self::Pairing>, Self::Challenge), PhaseTwoError>
    where
        D: Default,
        H: Hash<N> + Write,
        P::Scalar: Sample<D>,
        P::G1: Sample<D>,
        P::G2: Sample<D>,
        State<Self::Pairing>: Clone,
    {
        check_phase_2_invariants(&prev_state, &cur_state)?;
        if !<P::Pairing as PairingEngineExt>::same_ratio(
            (ratio_proof.ratio.0, ratio_proof.ratio.1),
            (
                hash_to_group::<P::G2, _, N>(prev_challenge),
                ratio_proof.matching_point,
            ),
        ) {
            return Err(PhaseTwoError::InconsistentDeltaChange);
        }
        if !<P::Pairing as PairingEngineExt>::same_ratio(
            (ratio_proof.ratio.0, ratio_proof.ratio.1),
            (prev_state.pk.vk.delta_g2, cur_state.pk.vk.delta_g2),
        ) {
            return Err(PhaseTwoError::InconsistentHChange);
        }
        if !<P::Pairing as PairingEngineExt>::same_ratio(
            (prev_state.pk.delta_g1, cur_state.pk.delta_g1),
            (prev_state.pk.vk.delta_g2, cur_state.pk.vk.delta_g2),
        ) {
            return Err(PhaseTwoError::InconsistentHChange);
        }
        if !<P::Pairing as PairingEngineExt>::same_ratio(
            random_linear_combinations::<P>(&cur_state.pk.h_query, &prev_state.pk.h_query),
            (prev_state.pk.vk.delta_g2, cur_state.pk.vk.delta_g2),
        ) {
            return Err(PhaseTwoError::InconsistentHChange);
        }
        if !<P::Pairing as PairingEngineExt>::same_ratio(
            random_linear_combinations::<P>(&cur_state.pk.l_query, &prev_state.pk.l_query),
            (prev_state.pk.vk.delta_g2, cur_state.pk.vk.delta_g2),
        ) {
            return Err(PhaseTwoError::InconsistentLChange);
        }
        Ok((
            cur_state.clone(),
            Self::challenge::<H>(prev_challenge, prev_state, cur_state, ratio_proof),
        ))
    }

    fn update(
        state: State<Self::Pairing>,
        ratio_proof: RatioProof<Self::Pairing>,
        mut contributions: Contributions<Self::Pairing, N>,
    ) -> Contributions<Self::Pairing, N> {
        contributions.states.push(state);
        contributions.proofs.push(ratio_proof);
        contributions
    }

    fn verify_transform_all<B, C, D, H>(
        state: State<Self::Pairing>,
        contributions: Contributions<Self::Pairing, N>,
        constraint_system: B,
        accumulator: Accumulator<C>,
    ) -> Result<(), PhaseTwoError>
    where
        B: ConstraintSynthesizer<C::Scalar>,
        C: Configuration<
            Pairing = <Self::Pairing as Pairing>::Pairing,
            G1 = <Self::Pairing as Pairing>::G1,
            G2 = <Self::Pairing as Pairing>::G2,
            Scalar = <Self::Pairing as Pairing>::Scalar,
        >,
        H: Hash<N> + Write,
        // <Self::Pairing as Pairing>::G1Prepared:
        //     From<<<Self::Pairing as Pairing>::G1 as AffineCurve>::Projective>,
        <Self::Pairing as Pairing>::Scalar: Sample<D>,
        <Self::Pairing as Pairing>::G1: Sample<D>,
        <Self::Pairing as Pairing>::G2: Sample<D>,
        State<Self::Pairing>: Clone,
        RatioProof<Self::Pairing>: Clone,
        D: Default,
    {
        assert_eq!(
            contributions.proofs.len(),
            contributions.states.len(),
            "Langth of `proofs` and `states` does not match."
        );
        let (initial_state, initial_contribution) =
            Self::initialize::<B, C, H>(constraint_system, accumulator)?;
        check_phase_2_invariants(&state, &initial_state)?;
        if initial_contribution.cs_hash != contributions.cs_hash {
            return Err(PhaseTwoError::ConstraintSystemHashesDiffer);
        }
        let mut cumulative_hasher = H::new();
        cumulative_hasher.update(&contributions.cs_hash[..]);
        let mut challenge = initial_contribution.cs_hash;
        let mut prev_state = initial_state;
        for (proof, state) in contributions.proofs.iter().zip(&contributions.states) {
            (prev_state, challenge) =
                Self::verify_transform::<H, D>(challenge, prev_state, state.clone(), proof.clone())
                    .expect("Verify transform failed.");
        }
        if prev_state.pk != state.pk {
            return Err(PhaseTwoError::InconsistentDeltaChange);
        }
        Ok(())
    }
}

/// Checks that the parameters which are not changed by Phase 2 contributions
/// are the same.
pub fn check_phase_2_invariants<P>(
    state: &State<P>,
    initial_state: &State<P>,
) -> Result<(), PhaseTwoError>
where
    P: Pairing,
{
    if initial_state.pk.h_query.len() != state.pk.h_query.len() {
        return Err(PhaseTwoError::Phase2InvariantViolated("H length changed"));
    }
    if initial_state.pk.l_query.len() != state.pk.l_query.len() {
        return Err(PhaseTwoError::Phase2InvariantViolated("L length changed"));
    }
    if initial_state.pk.a_query != state.pk.a_query {
        return Err(PhaseTwoError::Phase2InvariantViolated("A query changed"));
    }
    if initial_state.pk.b_g1_query != state.pk.b_g1_query {
        return Err(PhaseTwoError::Phase2InvariantViolated("B_G1 query changed"));
    }
    if initial_state.pk.b_g2_query != state.pk.b_g2_query {
        return Err(PhaseTwoError::Phase2InvariantViolated("B_G2 query changed"));
    }
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
    if initial_state.pk.vk.gamma_abc_g1 != state.pk.vk.gamma_abc_g1 {
        return Err(PhaseTwoError::Phase2InvariantViolated(
            "Public input cross terms changed",
        ));
    }
    Ok(())
}

/// Compress two vectors of curve points into a pair of
/// curve points by random linear combination. The same
/// random linear combination is used for both vectors,
/// allowing this pair to be used in a consistent ratio test.
pub fn random_linear_combinations<P>(lhs: &[P::G1], rhs: &[P::G1]) -> (P::G1, P::G1)
where
    P: Pairing,
{
    assert_eq!(lhs.len(), rhs.len());
    cfg_reduce!(
        cfg_into_iter!(0..lhs.len())
            .map(|_| {
                let mut rng = OsRng;
                P::Scalar::rand(&mut rng)
            })
            .zip(lhs)
            .zip(rhs)
            .map(|((rho, lhs), rhs)| (lhs.mul(rho).into_affine(), rhs.mul(rho).into_affine())),
        || (Zero::zero(), Zero::zero()),
        |mut acc, next| {
            acc.0 = acc.0 + next.0;
            acc.1 = acc.1 + next.1;
            acc
        }
    )
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

/// TODO
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PhaseTwoError {
    /// TODO
    TooManyConstraints,
    /// TODO
    ConstraintSystemError(SynthesisError),
    /// TODO
    MissingCSMatrices,
    /// TODO
    ConstraintSystemHashesDiffer,
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
    use super::*;
    use crate::{
        groth16::kzg::{Contribution, Size},
        util::{into_array_unchecked, BlakeHasher, HasDistribution, PairingEngine, Read},
    };
    use ark_bls12_381::{Fr, FrParameters, G1Affine};
    use ark_ff::{field_new, Fp256, ToBytes};
    use ark_groth16::Groth16 as ArkGroth16;
    use ark_r1cs_std::eq::EqGadget;
    use ark_snark::SNARK;
    use ark_std::io;
    use blake2::{Blake2b, Digest};
    use manta_crypto::{
        constraint::Allocate,
        eclair::alloc::mode::{Public, Secret},
        rand::SeedableRng,
    };
    use manta_pay::crypto::constraint::arkworks::{Fp, FpVar, R1CS};
    use rand_chacha::ChaCha20Rng;

    /// Sapling MPC
    #[derive(Clone, Default)]
    pub struct Sapling;

    impl Size for Sapling {
        const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
        const G2_POWERS: usize = 1 << 3;
    }

    impl HasDistribution for Sapling {
        type Distribution = ();
    }

    impl Pairing for Sapling {
        type Scalar = ark_bls12_381::Fr;
        type G1 = ark_bls12_381::G1Affine;
        type G1Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Prepared;
        type G2 = ark_bls12_381::G2Affine;
        type G2Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Prepared;
        type Pairing = ark_bls12_381::Bls12_381;

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

        // TODO: Make this generic with Digest trait.
        // TODO: Have another module outside this library in util.rs.
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
            let mut seed = Vec::with_capacity(8);
            for _ in 0..8 {
                // This forms the `seed` for ChaCha as the first 32 bytes of digest, reversed in chunks of 4 bytes
                // That choice was made to preserve compatibility with ZCash's Sapling Phase 1
                let mut word = [0u8; 4];
                let _ = digest
                    .read(&mut word[..])
                    .expect("This is always possible since we have enough bytes to begin with.");
                word[..].reverse();
                seed.extend(word)
            }

            let mut rng_chacha =
                <ChaCha20Rng as SeedableRng>::from_seed(into_array_unchecked(seed));
            <Self::G2 as Sample<()>>::sample::<ChaCha20Rng>((), &mut rng_chacha)
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
    pub fn serialize_g1_uncompressed<W>(point: &G1Affine, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        let mut res = [0u8; 96];
        if point.is_zero() {
            res[95] |= 1 << 6;
        } else {
            let mut temp_writer = &mut res[..];
            point.y.write(&mut temp_writer)?;
            point.x.write(&mut temp_writer)?;
        }
        res.reverse();
        writer.write_all(&res)?;
        Ok(())
    }

    /// TODO
    pub fn dummy_phase_one_trusted_setup() -> Accumulator<Sapling> {
        let mut rng = OsRng;
        let accumulator = Accumulator::<Sapling>::default();
        let challenge = [0; 64];
        let contribution: Contribution<Sapling> = Contribution::gen(&mut rng);
        let proof = contribution.proof(&challenge, &mut rng).unwrap();
        let mut next_accumulator = accumulator.clone();
        next_accumulator.update(&contribution);
        Accumulator::verify_transform(accumulator, next_accumulator, challenge, proof).unwrap()
    }

    /// TODO
    pub fn dummy_circuit(cs: &mut R1CS<Fp256<FrParameters>>) {
        let a = Fp(field_new!(Fr, "2")).as_known::<Secret, FpVar<_>>(cs);
        let b = Fp(field_new!(Fr, "3")).as_known::<Secret, FpVar<_>>(cs);
        let c = &a * &b;
        let d = Fp(field_new!(Fr, "6")).as_known::<Public, FpVar<_>>(cs);
        c.enforce_equal(&d)
            .expect("enforce_equal is not allowed to fail");
    }

    /// TODO
    pub fn prove_and_verify_circuit<P, R>(pk: ProvingKey<P>, rng: &mut R)
    where
        P: PairingEngine<Fr = Fp256<ark_bls12_381::FrParameters>>,
        R: Rng + CryptoRng,
    {
        let mut cs = R1CS::for_proofs();
        dummy_circuit(&mut cs);
        let proof = ArkGroth16::prove(&pk, cs, rng).unwrap();
        assert_eq!(
            ArkGroth16::verify(&pk.vk, &[field_new!(Fr, "6")], &proof).unwrap(),
            true
        );
    }

    /// TODO
    #[test]
    pub fn trusted_setup_phase_two_is_valid() {
        let mut rng = OsRng;
        let mut cs = R1CS::for_contexts();
        dummy_circuit(&mut cs);
        let accumulator = dummy_phase_one_trusted_setup();
        let (mut state, mut contributions) = Phase2::<Sapling, 64>::initialize::<
            R1CS<Fp256<ark_bls12_381::FrParameters>>,
            Sapling,
            BlakeHasher<64>,
        >(cs, accumulator.clone())
        .unwrap();
        let (mut prev_state, mut ratio_proof);
        let mut challenge = contributions.cs_hash;
        for _ in 0..5 {
            prev_state = state.clone();
            (state, ratio_proof) = Phase2::<Sapling, 64>::contribute::<_, (), BlakeHasher<64>>(
                &mut state, challenge, &mut rng,
            );
            (state, challenge) = Phase2::<Sapling, 64>::verify_transform::<BlakeHasher<64>, ()>(
                challenge,
                prev_state,
                state,
                ratio_proof.clone(),
            )
            .expect("verify transform failed");
            contributions =
                Phase2::<Sapling, 64>::update(state.clone(), ratio_proof.clone(), contributions);
        }
        let mut cs = R1CS::for_contexts();
        dummy_circuit(&mut cs);
        Phase2::<Sapling, 64>::verify_transform_all::<_, _, (), BlakeHasher<64>>(
            state.clone(),
            contributions,
            cs,
            accumulator,
        )
        .expect("Verify transform all failed.");
        prove_and_verify_circuit(state.pk, &mut rng);
    }
}
