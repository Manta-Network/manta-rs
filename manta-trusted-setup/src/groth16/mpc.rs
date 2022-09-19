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

//! Groth16 MPC

use crate::{
    groth16::kzg::{self, Accumulator},
    mpc,
    util::{batch_into_projective, batch_mul_fixed_scalar, merge_pairs_affine},
};
use alloc::{vec, vec::Vec};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use manta_crypto::{
    arkworks::{
        ec::{AffineCurve, PairingEngine, ProjectiveCurve},
        ff::{Field, PrimeField, UniformRand, Zero},
        pairing::{Pairing, PairingEngineExt},
        ratio::{HashToGroup, RatioProof},
        relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError},
    },
    rand::{CryptoRng, RngCore},
};

#[cfg(feature = "serde")]
use {
    manta_crypto::arkworks::serialize::{canonical_deserialize, canonical_serialize},
    manta_util::serde::{Deserialize, Serialize},
};

/// MPC State
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct State<P>(
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "canonical_serialize::<ProvingKey<P::Pairing>, _>",
            deserialize_with = "canonical_deserialize::<'de, _, ProvingKey<P::Pairing>>"
        )
    )]
    pub ProvingKey<P::Pairing>,
)
where
    P: Pairing + ?Sized;

/// MPC Proof
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Proof<P>(
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "canonical_serialize::<RatioProof<P>, _>",
            deserialize_with = "canonical_deserialize::<'de, _, RatioProof<P>>"
        )
    )]
    pub RatioProof<P>,
)
where
    P: Pairing + ?Sized;

/// Proving Key Hasher
pub trait ProvingKeyHasher<P>
where
    P: Pairing,
{
    /// Output Type
    type Output;

    /// Hashes the Groth16 `proving_key` state.
    fn hash(proving_key: &ProvingKey<P::Pairing>) -> Self::Output;
}

/// MPC State Size
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct StateSize {
    /// Size of `gamma_abc_g1` in the [`VerifyingKey`]
    pub gamma_abc_g1: usize,

    /// Size of the `a_query` in the [`ProvingKey`]
    ///
    /// # Note
    ///
    /// This is also the size of the `b_g1_query` and the `b_g2_query`.
    pub a_query: usize,

    /// Size of the `h_query` in the [`ProvingKey`]
    pub h_query: usize,

    /// Size of the `l_query` in the [`ProvingKey`]
    pub l_query: usize,
}

impl StateSize {
    /// Builds a [`StateSize`] from `proving_key` by measuring the lengths of the vectors in
    /// `proving_key`.
    #[inline]
    pub fn from_proving_key<E>(proving_key: &ProvingKey<E>) -> Self
    where
        E: PairingEngine,
    {
        Self {
            gamma_abc_g1: proving_key.vk.gamma_abc_g1.len(),
            a_query: proving_key.a_query.len(),
            h_query: proving_key.h_query.len(),
            l_query: proving_key.l_query.len(),
        }
    }

    /// Returns `true` if the lengths of the vectors in `proving_key` match `self`.
    #[inline]
    pub fn matches<E>(&self, proving_key: &ProvingKey<E>) -> bool
    where
        E: PairingEngine,
    {
        self.gamma_abc_g1 == proving_key.vk.gamma_abc_g1.len()
            && self.a_query == proving_key.a_query.len()
            && self.a_query == proving_key.b_g1_query.len()
            && self.a_query == proving_key.b_g2_query.len()
            && self.h_query == proving_key.h_query.len()
            && self.l_query == proving_key.l_query.len()
    }
}

/// MPC Error
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Too Many Constraints Error
    TooManyConstraints,

    /// Constraint System Error
    ConstraintSystemError(SynthesisError),

    /// Missing Constraint System Matrices Error
    MissingCSMatrices,

    /// Constraint System Hashes Mismatch Error
    ConstraintSystemHashesDiffer,

    /// Invalid Ratio Proof Error
    InvalidRatioProof,

    /// Inconsistent Delta Change Error
    InconsistentDeltaChange,

    /// Inconsistent L Change Error
    InconsistentLChange,

    /// Inconsistent H Change Error
    InconsistentHChange,

    /// Invariant Violation Error
    InvariantViolated(&'static str),
}

/// Specialize all phase1 parameters to phase2 parameters (except `h_query`) at once. This is like
/// doing `eval_poly` in parallel on all four kinds of commitments that phase2 params require
/// (`a_g1`, `b_g1`, `b_g2`, `extra`) where `extra` is the cross term that we (may wish to) compute
/// separately for public/private inputs.
#[allow(clippy::too_many_arguments)] // FIXME: Simplify this in the future.
#[inline]
pub fn specialize_to_phase_2<G1, G2>(
    tau_basis_g1: &[G1],
    tau_basis_g2: &[G2],
    alpha_tau_basis: &[G1],
    beta_tau_basis: &[G1],
    a_poly: &[Vec<(G1::ScalarField, usize)>],
    b_poly: &[Vec<(G1::ScalarField, usize)>],
    c_poly: &[Vec<(G1::ScalarField, usize)>],
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

/// Adds dummy `z_i * 0 = 0` constraint for each public input `z_i`.  This ensures non-malleability
/// of Groth16 proofs even if some public inputs are otherwise unconstrained.
#[inline]
pub fn add_dummy_constraints<G>(
    a: &mut [G],
    ext: &mut [G],
    tau_lagrange: &[G],
    beta_tau_lagrange: &[G],
    num_constraints: usize,
    num_public_inputs: usize,
) where
    G: Clone,
{
    let total = num_public_inputs + num_constraints;
    a[0..num_public_inputs].clone_from_slice(&tau_lagrange[num_constraints..total]);
    ext[0..num_public_inputs].clone_from_slice(&beta_tau_lagrange[num_constraints..total]);
}

/// Checks that the parameters which are not changed by contributions are the same.
#[inline]
pub fn check_invariants<P>(prev: &State<P>, next: &State<P>) -> Result<(), Error>
where
    P: Pairing,
{
    if prev.0.h_query.len() != next.0.h_query.len() {
        return Err(Error::InvariantViolated("H length changed"));
    }
    if prev.0.l_query.len() != next.0.l_query.len() {
        return Err(Error::InvariantViolated("L length changed"));
    }
    if prev.0.a_query != next.0.a_query {
        return Err(Error::InvariantViolated("A query changed"));
    }
    if prev.0.b_g1_query != next.0.b_g1_query {
        return Err(Error::InvariantViolated("B_G1 query changed"));
    }
    if prev.0.b_g2_query != next.0.b_g2_query {
        return Err(Error::InvariantViolated("B_G2 query changed"));
    }
    if prev.0.vk.alpha_g1 != next.0.vk.alpha_g1 {
        return Err(Error::InvariantViolated("alpha_G1 changed"));
    }
    if prev.0.beta_g1 != next.0.beta_g1 {
        return Err(Error::InvariantViolated("beta_G1 changed"));
    }
    if prev.0.vk.beta_g2 != next.0.vk.beta_g2 {
        return Err(Error::InvariantViolated("beta_G2 changed"));
    }
    if prev.0.vk.gamma_g2 != next.0.vk.gamma_g2 {
        return Err(Error::InvariantViolated("gamma_G2 changed"));
    }
    if prev.0.vk.gamma_abc_g1 != next.0.vk.gamma_abc_g1 {
        return Err(Error::InvariantViolated("Public input cross terms changed"));
    }
    Ok(())
}

/// Initialize [`State`] using the KZG accumulator `powers` and the given `constraint_system`.
#[inline]
pub fn initialize<C, S>(powers: Accumulator<C>, constraint_system: S) -> Result<State<C>, Error>
where
    C: kzg::Configuration,
    S: ConstraintSynthesizer<C::Scalar>,
{
    let constraints = ConstraintSystem::new_ref();
    constraint_system
        .generate_constraints(constraints.clone())
        .map_err(Error::ConstraintSystemError)?;
    constraints.finalize();
    let num_constraints = constraints.num_constraints();
    let num_instance_variables = constraints.num_instance_variables();
    let domain = Radix2EvaluationDomain::new(num_constraints + num_instance_variables)
        .ok_or(Error::TooManyConstraints)?;
    let constraint_matrices = constraints.to_matrices().ok_or(Error::MissingCSMatrices)?;
    let beta_g1 = powers.beta_tau_powers_g1[0];
    let degree = domain.size as usize;
    let mut h_query = Vec::with_capacity(degree - 1);
    for i in 0..degree {
        let tmp = powers.tau_powers_g1[i + degree].into_projective();
        let tmp2 = powers.tau_powers_g1[i].into_projective();
        h_query.push((tmp - tmp2).into_affine());
    }
    let tau_lagrange_g1 = domain.ifft(&batch_into_projective(&powers.tau_powers_g1));
    let tau_lagrange_g2 = domain.ifft(&batch_into_projective(&powers.tau_powers_g2));
    let alpha_lagrange_g1 = domain.ifft(&batch_into_projective(&powers.alpha_tau_powers_g1));
    let beta_lagrange_g1 = domain.ifft(&batch_into_projective(&powers.beta_tau_powers_g1));
    let num_witnesses =
        constraint_matrices.num_witness_variables + constraint_matrices.num_instance_variables;
    let mut a_g1 = vec![C::G1::zero().into_projective(); num_witnesses];
    let mut b_g1 = vec![C::G1::zero().into_projective(); num_witnesses];
    let mut b_g2 = vec![C::G2::zero().into_projective(); num_witnesses];
    let mut ext = vec![C::G1::zero().into_projective(); num_witnesses];
    add_dummy_constraints(
        &mut a_g1,
        &mut ext,
        &tau_lagrange_g1,
        &beta_lagrange_g1,
        num_constraints,
        num_instance_variables,
    );
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
    let a_query = ProjectiveCurve::batch_normalization_into_affine(&a_g1);
    let b_g1_query = ProjectiveCurve::batch_normalization_into_affine(&b_g1);
    let b_g2_query = ProjectiveCurve::batch_normalization_into_affine(&b_g2);
    let ext = ProjectiveCurve::batch_normalization_into_affine(&ext);
    let public_cross_terms = Vec::from(&ext[..constraint_matrices.num_instance_variables]);
    let private_cross_terms = Vec::from(&ext[constraint_matrices.num_instance_variables..]);
    Ok(State(ProvingKey {
        vk: VerifyingKey {
            alpha_g1: powers.alpha_tau_powers_g1[0],
            beta_g2: powers.beta_g2,
            gamma_g2: C::g2_prime_subgroup_generator(),
            delta_g2: C::g2_prime_subgroup_generator(),
            gamma_abc_g1: public_cross_terms,
        },
        beta_g1,
        delta_g1: C::g1_prime_subgroup_generator(),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query: private_cross_terms,
    }))
}

/// Configuration
pub trait Configuration: Pairing + mpc::Types<Proof = Proof<Self>, State = State<Self>> {
    /// Hasher Type
    type Hasher: Default + HashToGroup<Self, Self::Challenge>;

    /// Generates the next [`Challenge`] from `challenge`, `prev` state, `next` state, and `proof`.
    ///
    /// [`Challenge`]: mpc::ChallengeType::Challenge
    fn challenge(
        challenge: &Self::Challenge,
        prev: &State<Self>,
        next: &State<Self>,
        proof: &Proof<Self>,
    ) -> Self::Challenge;
}

/// Contributes to `state` with `hasher`, `challenge`, and `rng`, returning a [`proof`](Proof).
#[inline]
pub fn contribute<C, R>(
    hasher: &C::Hasher,
    challenge: &C::Challenge,
    state: &mut State<C>,
    rng: &mut R,
) -> Option<Proof<C>>
where
    C: Configuration,
    R: CryptoRng + RngCore + ?Sized,
{
    let delta = C::Scalar::rand(rng);
    let delta_inverse = delta.inverse()?;
    batch_mul_fixed_scalar(&mut state.0.l_query, delta_inverse);
    batch_mul_fixed_scalar(&mut state.0.h_query, delta_inverse);
    state.0.delta_g1 = state.0.delta_g1.mul(delta).into_affine();
    state.0.vk.delta_g2 = state.0.vk.delta_g2.mul(delta).into_affine();
    RatioProof::prove(hasher, challenge, &delta, rng).map(Proof)
}

/// Verifies transforming from `prev` to `next` is correct given `challenge` and `proof`.
#[inline]
pub fn verify_transform<C>(
    challenge: &C::Challenge,
    prev: &State<C>,
    next: State<C>,
    proof: Proof<C>,
) -> Result<(C::Challenge, State<C>), Error>
where
    C: Configuration,
{
    check_invariants::<C>(prev, &next)?;
    let next_challenge = C::challenge(challenge, prev, &next, &proof);
    let ((ratio_0, ratio_1), _) = proof
        .0
        .verify(&C::Hasher::default(), challenge)
        .ok_or(Error::InvalidRatioProof)?;
    if !C::Pairing::same_ratio((ratio_0, ratio_1), (prev.0.vk.delta_g2, next.0.vk.delta_g2)) {
        return Err(Error::InconsistentDeltaChange);
    }
    if !C::Pairing::same_ratio(
        (prev.0.delta_g1, next.0.delta_g1),
        (prev.0.vk.delta_g2, next.0.vk.delta_g2),
    ) {
        return Err(Error::InconsistentDeltaChange);
    }
    if !C::Pairing::same_ratio(
        merge_pairs_affine(&next.0.h_query, &prev.0.h_query),
        (prev.0.vk.delta_g2, next.0.vk.delta_g2),
    ) {
        return Err(Error::InconsistentHChange);
    }
    if !C::Pairing::same_ratio(
        merge_pairs_affine(&next.0.l_query, &prev.0.l_query),
        (prev.0.vk.delta_g2, next.0.vk.delta_g2),
    ) {
        return Err(Error::InconsistentLChange);
    }
    Ok((next_challenge, next))
}

/// Verifies all contributions in `iter` chaining from an initial `state` and `challenge` returning
/// the newest [`State`] and [`Challenge`] if all the contributions in the chain had valid
/// transitions.
///
/// [`Challenge`]: mpc::ChallengeType::Challenge
#[inline]
pub fn verify_transform_all<C, I>(
    mut challenge: C::Challenge,
    mut state: State<C>,
    iter: I,
) -> Result<(), Error>
where
    C: Configuration,
    I: IntoIterator<Item = (State<C>, Proof<C>)>,
{
    let initial_state = state.clone();
    for (next_state, next_proof) in iter {
        let next_challenge = C::challenge(&challenge, &state, &next_state, &next_proof);
        let ((ratio_0, ratio_1), _) = next_proof
            .0
            .verify(&C::Hasher::default(), &challenge)
            .ok_or(Error::InvalidRatioProof)?;
        if !C::Pairing::same_ratio(
            (ratio_0, ratio_1),
            (state.0.vk.delta_g2, next_state.0.vk.delta_g2),
        ) {
            return Err(Error::InconsistentDeltaChange);
        }
        (state, challenge) = (next_state, next_challenge);
    }
    check_invariants::<C>(&initial_state, &state)?;
    if !C::Pairing::same_ratio(
        (initial_state.0.delta_g1, state.0.delta_g1),
        (initial_state.0.vk.delta_g2, state.0.vk.delta_g2),
    ) {
        return Err(Error::InconsistentDeltaChange);
    }
    if !C::Pairing::same_ratio(
        merge_pairs_affine(&state.0.h_query, &initial_state.0.h_query),
        (initial_state.0.vk.delta_g2, state.0.vk.delta_g2),
    ) {
        return Err(Error::InconsistentHChange);
    }
    if !C::Pairing::same_ratio(
        merge_pairs_affine(&state.0.l_query, &initial_state.0.l_query),
        (initial_state.0.vk.delta_g2, state.0.vk.delta_g2),
    ) {
        return Err(Error::InconsistentLChange);
    }
    Ok(())
}
