// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Consensus bounds and structural validation for `PicklesV1`.

use ark_ff::{BigInt, PrimeField};
use ark_serialize::CanonicalDeserialize;
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};

use crate::format::{
    FeatureFlags, FieldBytes, PicklesProofPayload, PicklesVkPayload, PointBytes, PointEvaluations,
    ProofEvaluations,
};

pub(crate) const MAX_CHUNKS: usize = 8;
pub(crate) const MAX_PROOF_BYTES: usize = 65_536;
pub(crate) const MAX_PUBLIC_FIELDS: usize = 1_024;
pub(crate) const MAX_VK_BYTES: usize = 4_096;
pub(crate) const MIN_STEP_DOMAIN_LOG2: u8 = 3;
// o1js documents up to eight chunks for low-degree constraints over the fixed
// 2^16 step SRS, so the corresponding radix-2 circuit domain can grow through
// 2^19.
pub(crate) const MAX_STEP_DOMAIN_LOG2: u8 = 19;
pub(crate) const WRAP_SRS_LOG2: u8 = 15;
pub(crate) const WRAP_PUBLIC_INPUTS: usize = 40;
pub(crate) const WRAP_PREV_CHALLENGES: usize = 2;
pub(crate) const WRAP_ZK_ROWS: u64 = 3;

/// Number of zero-knowledge rows used by o1js's chunked step circuit. This is
/// the integer formula in Pickles `compile.ml`; the wrap circuit itself keeps
/// the fixed [`WRAP_ZK_ROWS`] value.
pub(crate) const fn step_zk_rows(chunks: usize) -> Option<u64> {
    if chunks == 0 || chunks > MAX_CHUNKS {
        None
    } else {
        let permutations = 7usize;
        Some(((2 * (permutations + 1) * chunks - 2 + permutations) / permutations) as u64)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileError {
    EvaluationChunks,
    FeatureFlags,
    FieldEncoding,
    PointEncoding,
    ProofConfiguration,
    VerificationKeyConfiguration,
}

pub(crate) fn validate_vk(vk: &PicklesVkPayload) -> Result<(), ProfileError> {
    if u64::from(vk.public_input_size) + u64::from(vk.public_output_size) > MAX_PUBLIC_FIELDS as u64
    {
        return Err(ProfileError::VerificationKeyConfiguration);
    }
    validate_pallas_points(
        vk.wrap_index
            .sigma_comm
            .iter()
            .chain(vk.wrap_index.coefficients_comm.iter())
            .chain([
                &vk.wrap_index.generic_comm,
                &vk.wrap_index.psm_comm,
                &vk.wrap_index.complete_add_comm,
                &vk.wrap_index.mul_comm,
                &vk.wrap_index.emul_comm,
                &vk.wrap_index.endomul_scalar_comm,
            ]),
    )
    .map_err(|_| ProfileError::VerificationKeyConfiguration)
}

pub(crate) fn validate_proof(
    proof: &PicklesProofPayload,
    vk: &PicklesVkPayload,
) -> Result<usize, ProfileError> {
    let branch = proof.statement.deferred_values.branch_data;
    let recursion_width = branch.proofs_verified.as_usize();
    if recursion_width > vk.max_proofs_verified.as_usize()
        || !(MIN_STEP_DOMAIN_LOG2..=MAX_STEP_DOMAIN_LOG2).contains(&branch.domain_log2)
        || proof
            .statement
            .messages_for_next_step_proof
            .challenge_polynomial_commitments
            .len()
            != recursion_width
        || proof
            .statement
            .messages_for_next_step_proof
            .old_bulletproof_challenges
            .len()
            != recursion_width
        || proof.wrap_proof.opening.lr.len() != WRAP_SRS_LOG2 as usize
    {
        return Err(ProfileError::ProofConfiguration);
    }

    validate_feature_flags(
        &proof.statement.deferred_values.plonk.feature_flags,
        &proof.prev_evals.evals,
    )?;
    let flags = proof.statement.deferred_values.plonk.feature_flags;
    let uses_lookup = flags.range_check0
        || flags.range_check1
        || flags.foreign_field_mul
        || flags.xor
        || flags.rot
        || flags.lookup;
    if proof
        .statement
        .deferred_values
        .plonk
        .joint_combiner
        .is_some()
        != uses_lookup
    {
        return Err(ProfileError::FeatureFlags);
    }
    let chunks =
        validate_evaluation_chunks(&proof.prev_evals.public_input, &proof.prev_evals.evals)?;
    validate_proof_fields(proof)?;
    validate_proof_points(proof)?;
    Ok(chunks)
}

fn all_evaluations(evals: &ProofEvaluations) -> impl Iterator<Item = &PointEvaluations> {
    evals
        .w
        .iter()
        .chain(evals.coefficients.iter())
        .chain([&evals.z])
        .chain(evals.s.iter())
        .chain([
            &evals.generic_selector,
            &evals.poseidon_selector,
            &evals.complete_add_selector,
            &evals.mul_selector,
            &evals.emul_selector,
            &evals.endomul_scalar_selector,
        ])
        .chain(evals.range_check0_selector.iter())
        .chain(evals.range_check1_selector.iter())
        .chain(evals.foreign_field_add_selector.iter())
        .chain(evals.foreign_field_mul_selector.iter())
        .chain(evals.xor_selector.iter())
        .chain(evals.rot_selector.iter())
        .chain(evals.lookup_aggregation.iter())
        .chain(evals.lookup_table.iter())
        .chain(evals.lookup_sorted.iter().flatten())
        .chain(evals.runtime_lookup_table.iter())
        .chain(evals.runtime_lookup_table_selector.iter())
        .chain(evals.xor_lookup_selector.iter())
        .chain(evals.lookup_gate_lookup_selector.iter())
        .chain(evals.range_check_lookup_selector.iter())
        .chain(evals.foreign_field_mul_lookup_selector.iter())
}

fn validate_evaluation_chunks(
    public_input: &PointEvaluations,
    evals: &ProofEvaluations,
) -> Result<usize, ProfileError> {
    let chunks = public_input.zeta.len();
    if chunks == 0
        || chunks > MAX_CHUNKS
        || public_input.zeta_omega.len() != chunks
        || all_evaluations(evals).any(|evaluation| {
            evaluation.zeta.len() != chunks || evaluation.zeta_omega.len() != chunks
        })
    {
        return Err(ProfileError::EvaluationChunks);
    }
    Ok(chunks)
}

fn validate_feature_flags(
    flags: &FeatureFlags,
    evals: &ProofEvaluations,
) -> Result<(), ProfileError> {
    let enabled = |value: bool, flag: bool| value == flag;
    let range_check_lookup = flags.range_check0 || flags.range_check1 || flags.rot;
    let lookups_per_row_4 = flags.xor || range_check_lookup || flags.foreign_field_mul;
    let lookups_per_row_3 = lookups_per_row_4 || flags.lookup;
    let lookups_per_row_2 = lookups_per_row_3;

    let valid = [
        enabled(evals.range_check0_selector.is_some(), flags.range_check0),
        enabled(evals.range_check1_selector.is_some(), flags.range_check1),
        enabled(
            evals.foreign_field_add_selector.is_some(),
            flags.foreign_field_add,
        ),
        enabled(
            evals.foreign_field_mul_selector.is_some(),
            flags.foreign_field_mul,
        ),
        enabled(evals.xor_selector.is_some(), flags.xor),
        enabled(evals.rot_selector.is_some(), flags.rot),
        enabled(evals.lookup_aggregation.is_some(), lookups_per_row_2),
        enabled(evals.lookup_table.is_some(), lookups_per_row_2),
        enabled(evals.lookup_sorted[0].is_some(), lookups_per_row_2),
        enabled(evals.lookup_sorted[1].is_some(), lookups_per_row_2),
        enabled(evals.lookup_sorted[2].is_some(), lookups_per_row_2),
        enabled(evals.lookup_sorted[3].is_some(), lookups_per_row_3),
        enabled(evals.lookup_sorted[4].is_some(), lookups_per_row_4),
        enabled(evals.runtime_lookup_table.is_some(), flags.runtime_tables),
        enabled(
            evals.runtime_lookup_table_selector.is_some(),
            flags.runtime_tables,
        ),
        enabled(evals.xor_lookup_selector.is_some(), flags.xor),
        enabled(evals.lookup_gate_lookup_selector.is_some(), flags.lookup),
        enabled(
            evals.range_check_lookup_selector.is_some(),
            range_check_lookup,
        ),
        enabled(
            evals.foreign_field_mul_lookup_selector.is_some(),
            flags.foreign_field_mul,
        ),
    ]
    .into_iter()
    .all(|check| check);

    valid.then_some(()).ok_or(ProfileError::FeatureFlags)
}

fn validate_proof_fields(proof: &PicklesProofPayload) -> Result<(), ProfileError> {
    if Fq::from_bigint(BigInt::new(
        proof.statement.sponge_digest_before_evaluations,
    ))
    .is_none()
    {
        return Err(ProfileError::FieldEncoding);
    }

    let mut fp_fields = proof
        .prev_evals
        .public_input
        .zeta
        .iter()
        .chain(proof.prev_evals.public_input.zeta_omega.iter())
        .chain(
            all_evaluations(&proof.prev_evals.evals)
                .flat_map(|eval| eval.zeta.iter().chain(eval.zeta_omega.iter())),
        )
        .chain([&proof.prev_evals.ft_eval1]);
    if fp_fields.any(|field| decode_field::<Fp>(field).is_err()) {
        return Err(ProfileError::FieldEncoding);
    }

    let wrap = &proof.wrap_proof;
    let mut fq_fields = wrap
        .evaluations
        .w
        .iter()
        .flatten()
        .chain(wrap.evaluations.coefficients.iter().flatten())
        .chain(wrap.evaluations.z.iter())
        .chain(wrap.evaluations.s.iter().flatten())
        .chain(wrap.evaluations.generic_selector.iter())
        .chain(wrap.evaluations.poseidon_selector.iter())
        .chain(wrap.evaluations.complete_add_selector.iter())
        .chain(wrap.evaluations.mul_selector.iter())
        .chain(wrap.evaluations.emul_selector.iter())
        .chain(wrap.evaluations.endomul_scalar_selector.iter())
        .chain([&wrap.ft_eval1, &wrap.opening.z1, &wrap.opening.z2]);
    if fq_fields.any(|field| decode_field::<Fq>(field).is_err()) {
        return Err(ProfileError::FieldEncoding);
    }
    Ok(())
}

fn validate_proof_points(proof: &PicklesProofPayload) -> Result<(), ProfileError> {
    let wrap = &proof.wrap_proof;
    validate_pallas_points(
        wrap.commitments
            .w_comm
            .iter()
            .chain([&wrap.commitments.z_comm])
            .chain(wrap.commitments.t_comm.iter())
            .chain(wrap.opening.lr.iter().flatten())
            .chain([
                &wrap.opening.delta,
                &wrap.opening.challenge_polynomial_commitment,
            ])
            .chain(
                proof
                    .statement
                    .messages_for_next_step_proof
                    .challenge_polynomial_commitments
                    .iter(),
            ),
    )?;
    validate_vesta_points([&proof
        .statement
        .messages_for_next_wrap_proof
        .challenge_polynomial_commitment])
}

pub(crate) fn decode_field<F: CanonicalDeserialize>(bytes: &FieldBytes) -> Result<F, ()> {
    F::deserialize_compressed(&bytes[..]).map_err(|_| ())
}

fn validate_pallas_points<'a>(
    points: impl IntoIterator<Item = &'a PointBytes>,
) -> Result<(), ProfileError> {
    for point in points {
        let affine = Pallas::new_unchecked(
            decode_field::<Fp>(&point[0]).map_err(|_| ProfileError::PointEncoding)?,
            decode_field::<Fp>(&point[1]).map_err(|_| ProfileError::PointEncoding)?,
        );
        if !affine.is_on_curve() || !affine.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ProfileError::PointEncoding);
        }
    }
    Ok(())
}

fn validate_vesta_points<'a>(
    points: impl IntoIterator<Item = &'a PointBytes>,
) -> Result<(), ProfileError> {
    for point in points {
        let affine = Vesta::new_unchecked(
            decode_field::<Fq>(&point[0]).map_err(|_| ProfileError::PointEncoding)?,
            decode_field::<Fq>(&point[1]).map_err(|_| ProfileError::PointEncoding)?,
        );
        if !affine.is_on_curve() || !affine.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ProfileError::PointEncoding);
        }
    }
    Ok(())
}
