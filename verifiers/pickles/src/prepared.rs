// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Reconstruction of the fixed 40-field Pickles wrap public input.
//!
//! Pickles carries the step transcript and split evaluations rather than the
//! wrap public input. The verifier must reconstruct every deferred value; none
//! of these security-sensitive scalars are accepted from a client.

use alloc::{vec, vec::Vec};

use ark_ff::{BigInt, Field, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use kimchi::{
    circuits::polynomials::permutation::{eval_permutation_vanishing_polynomial, zk_w, Shifts},
    proof::{PointEvaluations as KimchiPointEvaluations, ProofEvaluations as KimchiEvaluations},
};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::{fp_kimchi, fq_kimchi, FULL_ROUNDS},
    poseidon::{ArithmeticSponge, Sponge},
    sponge::{DefaultFqSponge, FqSponge},
};
use poly_commitment::{commitment::b_poly, ipa::endos};

use crate::{
    format::{
        FeatureFlags, PicklesProofPayload, PicklesVkPayload, PointEvaluations, ProofEvaluations,
        ProofsVerified, ScalarChallenge,
    },
    legacy,
    outer::{pallas_point, scalar_challenge_to_field},
    profile::{decode_field, step_zk_rows, WRAP_PUBLIC_INPUTS},
    Pubs,
};

const STEP_SRS_LOG2: u64 = 16;
const STEP_IPA_ROUNDS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedError {
    Evaluation,
    Field,
    Point,
    PublicInput,
}

struct Deferred {
    combined_inner_product: Fp,
    b: Fp,
    zeta_to_srs_length: Fp,
    zeta_to_domain_size: Fp,
    perm: Fp,
    xi: ScalarChallenge,
    bulletproof_challenges: [Fp; STEP_IPA_ROUNDS],
}

pub(crate) fn public_input(
    proof: &PicklesProofPayload,
    vk: &PicklesVkPayload,
    pubs: &Pubs,
) -> Result<Vec<Fq>, PreparedError> {
    if pubs.public_input.len()
        != usize::try_from(vk.public_input_size).map_err(|_| PreparedError::PublicInput)?
        || pubs.public_output.len()
            != usize::try_from(vk.public_output_size).map_err(|_| PreparedError::PublicInput)?
    {
        return Err(PreparedError::PublicInput);
    }

    let deferred = expand_deferred(proof)?;
    let statement = &proof.statement;
    let plonk = &statement.deferred_values.plonk;
    let flags = plonk.feature_flags;

    let mut fields = Vec::with_capacity(WRAP_PUBLIC_INPUTS);
    fields.extend([
        fp_to_fq(shift(deferred.combined_inner_product))?,
        fp_to_fq(shift(deferred.b))?,
        fp_to_fq(shift(deferred.zeta_to_srs_length))?,
        fp_to_fq(shift(deferred.zeta_to_domain_size))?,
        fp_to_fq(shift(deferred.perm))?,
        limbs_to_field(plonk.beta)?,
        limbs_to_field(plonk.gamma)?,
        limbs_to_field(plonk.alpha)?,
        limbs_to_field(plonk.zeta)?,
        limbs_to_field(deferred.xi)?,
        limbs4_to_field(statement.sponge_digest_before_evaluations)?,
        hash_next_wrap_message(proof)?,
        fp_to_fq(hash_next_step_message(proof, vk, pubs)?)?,
    ]);
    fields.extend(
        deferred
            .bulletproof_challenges
            .into_iter()
            .map(fp_to_fq)
            .collect::<Result<Vec<_>, _>>()?,
    );

    let proof_bits = match statement.deferred_values.branch_data.proofs_verified {
        ProofsVerified::N0 => 0b00,
        ProofsVerified::N1 => 0b10,
        ProofsVerified::N2 => 0b11,
    };
    let branch = (u64::from(statement.deferred_values.branch_data.domain_log2) << 2) | proof_bits;
    fields.push(Fq::from(branch));
    fields.extend(feature_fields(flags));

    let uses_lookup = flags.range_check0
        || flags.range_check1
        || flags.foreign_field_mul
        || flags.xor
        || flags.rot
        || flags.lookup;
    fields.push(Fq::from(uses_lookup));
    fields.push(if uses_lookup {
        plonk
            .joint_combiner
            .map(limbs_to_field)
            .transpose()?
            .unwrap_or_else(Fq::zero)
    } else {
        Fq::zero()
    });

    if fields.len() != WRAP_PUBLIC_INPUTS {
        return Err(PreparedError::PublicInput);
    }
    Ok(fields)
}

fn expand_deferred(proof: &PicklesProofPayload) -> Result<Deferred, PreparedError> {
    let source = &proof.statement.deferred_values;
    let plonk = &source.plonk;
    let (_, step_endo) = endos::<Vesta>();
    let zeta = scalar_challenge_to_field(plonk.zeta, step_endo);
    let alpha = scalar_challenge_to_field(plonk.alpha, step_endo);
    let beta = limbs_to_field::<Fp>(plonk.beta)?;
    let gamma = limbs_to_field::<Fp>(plonk.gamma)?;
    let joint_combiner = plonk
        .joint_combiner
        .map(|challenge| scalar_challenge_to_field(challenge, step_endo));

    let size = 1usize
        .checked_shl(u32::from(source.branch_data.domain_log2))
        .ok_or(PreparedError::Field)?;
    let domain = D::<Fp>::new(size).ok_or(PreparedError::Field)?;
    let zetaw = zeta * domain.group_gen;
    let evals = step_evaluations(&proof.prev_evals.evals)?;
    let combined_evals = combine_evaluations(zeta, zetaw, &evals);
    let public = point_evaluation(&proof.prev_evals.public_input)?;
    let zk_rows = step_zk_rows(public.zeta.len()).ok_or(PreparedError::Evaluation)?;

    let zeta_to_srs_length = square_n(zeta, STEP_SRS_LOG2);
    let zeta_to_domain_size = zeta.pow([domain.size]);
    // Pickles fixes the first permutation alpha at exponent 21. This differs
    // from asking Kimchi's feature-pruned linearization to allocate powers:
    // the Pickles circuit reserves the preceding powers even when its
    // optional gates are disabled.
    let permutation_alphas = [alpha.pow([21]), alpha.pow([22]), alpha.pow([23])];
    let zkp = eval_permutation_vanishing_polynomial(domain, zk_rows, zeta);
    let shifts = Shifts::new(&domain);

    let perm = -combined_evals.s.iter().enumerate().fold(
        combined_evals.z.zeta_omega * beta * permutation_alphas[0] * zkp,
        |acc, (index, evaluation)| {
            acc * (gamma + beta * evaluation.zeta + combined_evals.w[index].zeta)
        },
    );
    let ft_eval0 = ft_eval0(FtEval0 {
        evals: &combined_evals,
        public_zeta: &public.zeta,
        domain,
        zeta,
        alpha,
        beta,
        gamma,
        joint_combiner,
        zeta_to_srs_length,
        zkp,
        shifts: shifts.shifts(),
        feature_flags: plonk.feature_flags,
        permutation_alphas,
        zk_rows,
    })?;

    let old_challenges = proof
        .statement
        .messages_for_next_step_proof
        .old_bulletproof_challenges
        .iter()
        .map(|set| set.map(|challenge| scalar_challenge_to_field(challenge, step_endo)))
        .collect::<Vec<_>>();
    let challenge_fields = old_challenges.iter().flatten().copied().collect::<Vec<_>>();
    let challenges_digest = hash_fp(&challenge_fields);

    let mut sponge =
        DefaultFqSponge::<PallasParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(
            fp_kimchi::static_params(),
        );
    sponge.absorb_fq(&[
        limbs4_to_field(proof.statement.sponge_digest_before_evaluations)?,
        challenges_digest,
        decode_field(&proof.prev_evals.ft_eval1).map_err(|_| PreparedError::Field)?,
    ]);
    sponge.absorb_fq(&public.zeta);
    sponge.absorb_fq(&public.zeta_omega);
    for evaluation in absorption_sequence(&evals) {
        sponge.absorb_fq(&evaluation.zeta);
        sponge.absorb_fq(&evaluation.zeta_omega);
    }
    let xi_limbs = squeeze_limbs(&mut sponge)?;
    let r_limbs = squeeze_limbs(&mut sponge)?;
    let xi = scalar_challenge_to_field(xi_limbs, step_endo);
    let r = scalar_challenge_to_field(r_limbs, step_endo);

    let ft_eval1 = decode_field(&proof.prev_evals.ft_eval1).map_err(|_| PreparedError::Field)?;
    let combined_inner_product = combined_inner_product(
        &evals,
        &public,
        &old_challenges,
        ft_eval0,
        ft_eval1,
        zeta,
        zetaw,
        xi,
        r,
    );
    let effective_bulletproof_challenges = source
        .bulletproof_challenges
        .map(|challenge| scalar_challenge_to_field(challenge, step_endo));
    let b = b_poly(&effective_bulletproof_challenges, zeta)
        + r * b_poly(&effective_bulletproof_challenges, zetaw);
    let bulletproof_challenges = source
        .bulletproof_challenges
        .map(limbs_to_field)
        .into_iter()
        .collect::<Result<Vec<Fp>, _>>()?
        .try_into()
        .unwrap_or_else(|_| unreachable!("Pickles has exactly 16 challenges"));

    Ok(Deferred {
        combined_inner_product,
        b,
        zeta_to_srs_length,
        zeta_to_domain_size,
        perm,
        xi: xi_limbs,
        bulletproof_challenges,
    })
}

struct FtEval0<'a> {
    evals: &'a KimchiEvaluations<KimchiPointEvaluations<Fp>>,
    public_zeta: &'a [Fp],
    domain: D<Fp>,
    zeta: Fp,
    alpha: Fp,
    beta: Fp,
    gamma: Fp,
    joint_combiner: Option<Fp>,
    zeta_to_srs_length: Fp,
    zkp: Fp,
    shifts: &'a [Fp; 7],
    feature_flags: FeatureFlags,
    permutation_alphas: [Fp; 3],
    zk_rows: u64,
}

fn ft_eval0(args: FtEval0<'_>) -> Result<Fp, PreparedError> {
    let FtEval0 {
        evals,
        public_zeta,
        domain,
        zeta,
        alpha,
        beta,
        gamma,
        joint_combiner,
        zeta_to_srs_length,
        zkp,
        shifts,
        feature_flags,
        permutation_alphas: [alpha0, alpha1, alpha2],
        zk_rows,
    } = args;
    let zeta1m1 = zeta.pow([domain.size]) - Fp::one();
    let mut value = evals
        .w
        .iter()
        .zip(evals.s.iter())
        .map(|(w, s)| beta * s.zeta + w.zeta + gamma)
        .fold(
            (evals.w[6].zeta + gamma) * evals.z.zeta_omega * alpha0 * zkp,
            |acc, term| acc * term,
        );
    value -= combine_chunks(public_zeta, zeta_to_srs_length);
    value -= evals
        .w
        .iter()
        .zip(shifts)
        .map(|(w, shift)| gamma + beta * zeta * shift + w.zeta)
        .fold(alpha0 * zkp * evals.z.zeta, |acc, term| acc * term);

    let w = zk_w(domain, zk_rows);
    let numerator = ((zeta1m1 * alpha1 * (zeta - w)) + (zeta1m1 * alpha2 * (zeta - Fp::one())))
        * (Fp::one() - evals.z.zeta);
    let denominator = ((zeta - w) * (zeta - Fp::one()))
        .inverse()
        .ok_or(PreparedError::Evaluation)?;
    value += numerator * denominator;

    let constant_term = legacy::constant_term(&legacy::Context {
        evals,
        domain,
        zeta,
        alpha,
        beta,
        gamma,
        joint_combiner,
        feature_flags,
        zk_rows,
    })?;
    value -= constant_term;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
fn combined_inner_product(
    evals: &KimchiEvaluations<KimchiPointEvaluations<Vec<Fp>>>,
    public: &KimchiPointEvaluations<Vec<Fp>>,
    old_challenges: &[[Fp; STEP_IPA_ROUNDS]],
    ft_eval0: Fp,
    ft_eval1: Fp,
    zeta: Fp,
    zetaw: Fp,
    xi: Fp,
    r: Fp,
) -> Fp {
    let sequence = evaluation_sequence(evals);
    let combine = |at_zeta: bool, ft: Fp, point: Fp| {
        let mut values = old_challenges
            .iter()
            .map(|challenges| b_poly(challenges, point))
            .collect::<Vec<_>>();
        values.extend(if at_zeta {
            public.zeta.iter().copied()
        } else {
            public.zeta_omega.iter().copied()
        });
        values.push(ft);
        for evaluation in &sequence {
            values.extend(if at_zeta {
                evaluation.zeta.iter().copied()
            } else {
                evaluation.zeta_omega.iter().copied()
            });
        }
        values
            .into_iter()
            .rev()
            .reduce(|acc, value| value + xi * acc)
            .unwrap_or_else(Fp::zero)
    };
    combine(true, ft_eval0, zeta) + r * combine(false, ft_eval1, zetaw)
}

fn step_evaluations(
    source: &ProofEvaluations,
) -> Result<KimchiEvaluations<KimchiPointEvaluations<Vec<Fp>>>, PreparedError> {
    Ok(KimchiEvaluations {
        public: None,
        w: try_map_array(&source.w, point_evaluation)?,
        z: point_evaluation(&source.z)?,
        s: try_map_array(&source.s, point_evaluation)?,
        coefficients: try_map_array(&source.coefficients, point_evaluation)?,
        generic_selector: point_evaluation(&source.generic_selector)?,
        poseidon_selector: point_evaluation(&source.poseidon_selector)?,
        complete_add_selector: point_evaluation(&source.complete_add_selector)?,
        mul_selector: point_evaluation(&source.mul_selector)?,
        emul_selector: point_evaluation(&source.emul_selector)?,
        endomul_scalar_selector: point_evaluation(&source.endomul_scalar_selector)?,
        range_check0_selector: option_evaluation(&source.range_check0_selector)?,
        range_check1_selector: option_evaluation(&source.range_check1_selector)?,
        foreign_field_add_selector: option_evaluation(&source.foreign_field_add_selector)?,
        foreign_field_mul_selector: option_evaluation(&source.foreign_field_mul_selector)?,
        xor_selector: option_evaluation(&source.xor_selector)?,
        rot_selector: option_evaluation(&source.rot_selector)?,
        lookup_aggregation: option_evaluation(&source.lookup_aggregation)?,
        lookup_table: option_evaluation(&source.lookup_table)?,
        lookup_sorted: try_map_array(&source.lookup_sorted, option_evaluation)?,
        runtime_lookup_table: option_evaluation(&source.runtime_lookup_table)?,
        runtime_lookup_table_selector: option_evaluation(&source.runtime_lookup_table_selector)?,
        xor_lookup_selector: option_evaluation(&source.xor_lookup_selector)?,
        lookup_gate_lookup_selector: option_evaluation(&source.lookup_gate_lookup_selector)?,
        range_check_lookup_selector: option_evaluation(&source.range_check_lookup_selector)?,
        foreign_field_mul_lookup_selector: option_evaluation(
            &source.foreign_field_mul_lookup_selector,
        )?,
    })
}

fn point_evaluation(
    source: &PointEvaluations,
) -> Result<KimchiPointEvaluations<Vec<Fp>>, PreparedError> {
    Ok(KimchiPointEvaluations {
        zeta: source
            .zeta
            .iter()
            .map(decode_field)
            .collect::<Result<_, _>>()
            .map_err(|_| PreparedError::Field)?,
        zeta_omega: source
            .zeta_omega
            .iter()
            .map(decode_field)
            .collect::<Result<_, _>>()
            .map_err(|_| PreparedError::Field)?,
    })
}

fn option_evaluation(
    source: &Option<PointEvaluations>,
) -> Result<Option<KimchiPointEvaluations<Vec<Fp>>>, PreparedError> {
    source.as_ref().map(point_evaluation).transpose()
}

fn combine_evaluations(
    zeta: Fp,
    zetaw: Fp,
    evals: &KimchiEvaluations<KimchiPointEvaluations<Vec<Fp>>>,
) -> KimchiEvaluations<KimchiPointEvaluations<Fp>> {
    let zeta_n = square_n(zeta, STEP_IPA_ROUNDS as u64);
    let zetaw_n = square_n(zetaw, STEP_IPA_ROUNDS as u64);
    evals.map_ref(&|evaluation| KimchiPointEvaluations {
        zeta: combine_chunks(&evaluation.zeta, zeta_n),
        zeta_omega: combine_chunks(&evaluation.zeta_omega, zetaw_n),
    })
}

fn combine_chunks(values: &[Fp], point_to_srs: Fp) -> Fp {
    values
        .iter()
        .copied()
        .rev()
        .reduce(|acc, value| value + point_to_srs * acc)
        .unwrap_or_else(Fp::zero)
}

fn evaluation_sequence<F>(
    evals: &KimchiEvaluations<KimchiPointEvaluations<F>>,
) -> Vec<&KimchiPointEvaluations<F>> {
    let mut result = vec![
        &evals.z,
        &evals.generic_selector,
        &evals.poseidon_selector,
        &evals.complete_add_selector,
        &evals.mul_selector,
        &evals.emul_selector,
        &evals.endomul_scalar_selector,
    ];
    result.extend(evals.w.iter());
    result.extend(evals.coefficients.iter());
    result.extend(evals.s.iter());
    result.extend(
        [
            &evals.range_check0_selector,
            &evals.range_check1_selector,
            &evals.foreign_field_add_selector,
            &evals.foreign_field_mul_selector,
            &evals.xor_selector,
            &evals.rot_selector,
        ]
        .into_iter()
        .filter_map(Option::as_ref),
    );
    result.extend(evals.lookup_sorted.iter().filter_map(Option::as_ref));
    result.extend(
        [
            &evals.lookup_aggregation,
            &evals.lookup_table,
            &evals.runtime_lookup_table,
            &evals.runtime_lookup_table_selector,
            &evals.xor_lookup_selector,
            &evals.lookup_gate_lookup_selector,
            &evals.range_check_lookup_selector,
            &evals.foreign_field_mul_lookup_selector,
        ]
        .into_iter()
        .filter_map(Option::as_ref),
    );
    result
}

fn absorption_sequence<F>(
    evals: &KimchiEvaluations<KimchiPointEvaluations<F>>,
) -> Vec<&KimchiPointEvaluations<F>> {
    let mut result = vec![
        &evals.z,
        &evals.generic_selector,
        &evals.poseidon_selector,
        &evals.complete_add_selector,
        &evals.mul_selector,
        &evals.emul_selector,
        &evals.endomul_scalar_selector,
    ];
    result.extend(evals.w.iter());
    result.extend(evals.coefficients.iter());
    result.extend(evals.s.iter());
    result.extend(
        [
            &evals.range_check0_selector,
            &evals.range_check1_selector,
            &evals.foreign_field_add_selector,
            &evals.foreign_field_mul_selector,
            &evals.xor_selector,
            &evals.rot_selector,
            &evals.lookup_aggregation,
            &evals.lookup_table,
        ]
        .into_iter()
        .filter_map(Option::as_ref),
    );
    result.extend(evals.lookup_sorted.iter().filter_map(Option::as_ref));
    result.extend(
        [
            &evals.runtime_lookup_table,
            &evals.runtime_lookup_table_selector,
            &evals.xor_lookup_selector,
            &evals.lookup_gate_lookup_selector,
            &evals.range_check_lookup_selector,
            &evals.foreign_field_mul_lookup_selector,
        ]
        .into_iter()
        .filter_map(Option::as_ref),
    );
    result
}

fn hash_next_wrap_message(proof: &PicklesProofPayload) -> Result<Fq, PreparedError> {
    let (_, outer_endo) = endos::<Pallas>();
    let message = &proof.statement.messages_for_next_wrap_proof;
    let mut fields = Vec::with_capacity(32);
    for set in &message.old_bulletproof_challenges {
        fields.extend(
            set.challenges
                .iter()
                .map(|challenge| scalar_challenge_to_field(*challenge, outer_endo)),
        );
    }
    let point = vesta_point(&message.challenge_polynomial_commitment)?;
    fields.extend([point.x, point.y]);
    Ok(hash_fq(&fields))
}

fn hash_next_step_message(
    proof: &PicklesProofPayload,
    vk: &PicklesVkPayload,
    pubs: &Pubs,
) -> Result<Fp, PreparedError> {
    let mut fields = Vec::new();
    let index = &vk.wrap_index;
    for point in index
        .sigma_comm
        .iter()
        .chain(index.coefficients_comm.iter())
        .chain([
            &index.generic_comm,
            &index.psm_comm,
            &index.complete_add_comm,
            &index.mul_comm,
            &index.emul_comm,
            &index.endomul_scalar_comm,
        ])
    {
        let point = pallas_point(point).map_err(|_| PreparedError::Point)?;
        fields.extend([point.x, point.y]);
    }
    fields.extend(
        pubs.public_input
            .iter()
            .chain(pubs.public_output.iter())
            .map(decode_field)
            .collect::<Result<Vec<Fp>, _>>()
            .map_err(|_| PreparedError::PublicInput)?,
    );

    let (_, step_endo) = endos::<Vesta>();
    let message = &proof.statement.messages_for_next_step_proof;
    for (commitment, old_challenges) in message
        .challenge_polynomial_commitments
        .iter()
        .zip(message.old_bulletproof_challenges.iter())
    {
        let commitment = pallas_point(commitment).map_err(|_| PreparedError::Point)?;
        fields.extend([commitment.x, commitment.y]);
        fields.extend(
            old_challenges
                .iter()
                .map(|challenge| scalar_challenge_to_field(*challenge, step_endo)),
        );
    }
    Ok(hash_fp(&fields))
}

fn hash_fp(fields: &[Fp]) -> Fp {
    let mut sponge = ArithmeticSponge::<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(
        fp_kimchi::static_params(),
    );
    sponge.absorb(fields);
    sponge.squeeze()
}

fn hash_fq(fields: &[Fq]) -> Fq {
    let mut sponge = ArithmeticSponge::<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(
        fq_kimchi::static_params(),
    );
    sponge.absorb(fields);
    sponge.squeeze()
}

fn feature_fields(flags: FeatureFlags) -> [Fq; 8] {
    [
        flags.range_check0,
        flags.range_check1,
        flags.foreign_field_add,
        flags.foreign_field_mul,
        flags.xor,
        flags.rot,
        flags.lookup,
        flags.runtime_tables,
    ]
    .map(Fq::from)
}

fn squeeze_limbs(
    sponge: &mut DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
) -> Result<ScalarChallenge, PreparedError> {
    sponge
        .squeeze_limbs(2)
        .try_into()
        .map_err(|_| PreparedError::Field)
}

fn limbs_to_field<F: PrimeField<BigInt = BigInt<4>>>(
    limbs: ScalarChallenge,
) -> Result<F, PreparedError> {
    F::from_bigint(BigInt::new([limbs[0], limbs[1], 0, 0])).ok_or(PreparedError::Field)
}

fn limbs4_to_field<F: PrimeField<BigInt = BigInt<4>>>(limbs: [u64; 4]) -> Result<F, PreparedError> {
    F::from_bigint(BigInt::new(limbs)).ok_or(PreparedError::Field)
}

fn fp_to_fq(value: Fp) -> Result<Fq, PreparedError> {
    Fq::from_bigint(value.into_bigint()).ok_or(PreparedError::Field)
}

fn shift(value: Fp) -> Fp {
    let c = (0..255).fold(Fp::one(), |acc, _| acc + acc) + Fp::one();
    (value - c) * Fp::from(2u64).inverse().expect("two is non-zero")
}

fn square_n(mut value: Fp, count: u64) -> Fp {
    for _ in 0..count {
        value.square_in_place();
    }
    value
}

pub(crate) fn vesta_point(bytes: &[[u8; 32]; 2]) -> Result<Vesta, PreparedError> {
    let point = Vesta::new_unchecked(
        decode_field(&bytes[0]).map_err(|_| PreparedError::Point)?,
        decode_field(&bytes[1]).map_err(|_| PreparedError::Point)?,
    );
    if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
        Ok(point)
    } else {
        Err(PreparedError::Point)
    }
}

fn try_map_array<T, U, E, const N: usize>(
    source: &[T; N],
    map: impl Fn(&T) -> Result<U, E>,
) -> Result<[U; N], E> {
    Ok(source
        .iter()
        .map(map)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .unwrap_or_else(|_| unreachable!("array length is preserved")))
}
