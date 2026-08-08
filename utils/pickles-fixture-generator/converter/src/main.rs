// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{env, fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use mina_p2p_messages::{
    array::ArrayN16,
    bigint::BigInt,
    v2::{
        CompositionTypesBranchDataStableV1, LimbVectorConstantHex64StableV1,
        MinaBaseVerificationKeyWireStableV1, MinaBaseVerificationKeyWireStableV1WrapIndex,
        PicklesBaseProofsVerifiedStableV1, PicklesProofProofsVerified2ReprStableV2,
        PicklesProofProofsVerified2ReprStableV2PrevEvalsEvalsEvals,
        PicklesProofProofsVerified2ReprStableV2StatementProofStateDeferredValuesPlonkFeatureFlags,
        PicklesReducedMessagesForNextProofOverSameFieldWrapChallengesVectorStableV2,
        PicklesReducedMessagesForNextProofOverSameFieldWrapChallengesVectorStableV2A,
        PicklesReducedMessagesForNextProofOverSameFieldWrapChallengesVectorStableV2AChallenge,
        PicklesWrapWireProofCommitmentsStableV1, PicklesWrapWireProofEvaluationsStableV1,
        PicklesWrapWireProofStableV1, PicklesWrapWireProofStableV1Bulletproof,
        TransactionSnarkProofStableV2,
    },
};
use pickles_format::{
    BranchData, DeferredPlonk, DeferredValues, FeatureFlags, FieldBytes, MessagesForNextStepProof,
    MessagesForNextWrapProof, PicklesProofPayload, PicklesVkPayload, PointBytes, PointEvaluations,
    PrevEvals, ProofEvaluations, ProofsVerified, Statement, WrapChallengeSet, WrapCommitments,
    WrapEvaluations, WrapOpeningProof, WrapVerifierIndex, WrapWireProof,
};
use rsexp::{OfSexp as _, Sexp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceFixture {
    format: String,
    reference: SourceReference,
    compile_config: CompileConfig,
    verification_key: SourceVerificationKey,
    proof: SourceJsonProof,
    expected_verification: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct SourceReference {
    package: String,
    version: String,
    #[serde(default, rename = "gitCommit", skip_serializing_if = "Option::is_none")]
    git_commit: Option<String>,
    #[serde(
        default,
        rename = "minaCommit",
        skip_serializing_if = "Option::is_none"
    )]
    mina_commit: Option<String>,
    #[serde(
        default,
        rename = "proofSystemsCommit",
        skip_serializing_if = "Option::is_none"
    )]
    proof_systems_commit: Option<String>,
    #[serde(
        default,
        rename = "bindingsSha256",
        skip_serializing_if = "Option::is_none"
    )]
    bindings_sha256: Option<String>,
    #[serde(
        default,
        rename = "serializationPatch",
        skip_serializing_if = "Option::is_none"
    )]
    serialization_patch: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CompileConfig {
    num_chunks: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    override_wrap_domain: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct SourceVerificationKey {
    data: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceJsonProof {
    public_input: Vec<String>,
    public_output: Vec<String>,
    max_proofs_verified: u8,
    proof: String,
    transaction_proof: String,
}

struct DecodedTransactionProof {
    proof: PicklesProofProofsVerified2ReprStableV2,
    public_input: PointEvaluations,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConvertedFixture {
    format: &'static str,
    profile: &'static str,
    reference: SourceReference,
    compile_config: CompileConfig,
    source_verification_key_hash: String,
    recursion_width: usize,
    max_proofs_verified: usize,
    step_domain_log2: u8,
    wrap_domain_log2: u8,
    public_input_size: u32,
    public_output_size: u32,
    proof: String,
    verification_key: String,
    public_input: Vec<String>,
    public_output: Vec<String>,
    expected_verification: bool,
}

fn main() -> Result<()> {
    let input = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .context("usage: pickles-fixture-converter <source.json> <output-directory>")?;
    let output_directory = env::args_os()
        .nth(2)
        .map(PathBuf::from)
        .context("usage: pickles-fixture-converter <source.json> <output-directory>")?;
    if env::args_os().nth(3).is_some() {
        bail!("usage: pickles-fixture-converter <source.json> <output-directory>");
    }

    let source_bytes = fs::read(&input)
        .with_context(|| format!("cannot read source fixture {}", input.display()))?;
    let source: SourceFixture = serde_json::from_slice(&source_bytes)
        .with_context(|| format!("cannot decode source fixture {}", input.display()))?;
    validate_source_envelope(&source)?;

    let decoded_proof = decode_transaction_proof(&source.proof.transaction_proof)?;
    let proof = convert_proof(&decoded_proof.proof, decoded_proof.public_input)?;
    let source_vk = MinaBaseVerificationKeyWireStableV1::from_base64(&source.verification_key.data)
        .context("cannot decode o1js verification key")?;
    let public_input_size = u32::try_from(source.proof.public_input.len())
        .context("public input length does not fit the canonical format")?;
    let public_output_size = u32::try_from(source.proof.public_output.len())
        .context("public output length does not fit the canonical format")?;
    let vk = convert_vk(&source_vk, public_input_size, public_output_size);

    let recursion_width = proof
        .statement
        .deferred_values
        .branch_data
        .proofs_verified
        .as_usize();
    let max_proofs_verified = vk.max_proofs_verified.as_usize();
    let step_domain_log2 = proof.statement.deferred_values.branch_data.domain_log2;
    let wrap_domain_log2 = wrap_domain_log2(vk.actual_wrap_domain_size);
    let chunks = evaluation_chunks(&proof.prev_evals.public_input, &proof.prev_evals.evals)?;
    if chunks != usize::from(source.compile_config.num_chunks) {
        bail!(
            "proof contains {chunks} evaluation chunks, but compileConfig.numChunks is {}",
            source.compile_config.num_chunks
        );
    }
    if max_proofs_verified != usize::from(source.proof.max_proofs_verified) {
        bail!(
            "verification key declares maxProofsVerified={max_proofs_verified}, but proof JSON declares {}",
            source.proof.max_proofs_verified
        );
    }
    if source
        .compile_config
        .override_wrap_domain
        .is_some_and(|domain| usize::from(domain) != vk.actual_wrap_domain_size.as_usize())
    {
        bail!(
            "verification key declares actualWrapDomainSize={}, but compileConfig.overrideWrapDomain is {:?}",
            vk.actual_wrap_domain_size.as_usize(),
            source.compile_config.override_wrap_domain
        );
    }

    let proof = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .context("cannot encode canonical Pickles proof")?;
    let vk = bincode::serde::encode_to_vec(&vk, bincode::config::standard())
        .context("cannot encode canonical Pickles verification key")?;

    let converted = ConvertedFixture {
        format: "zkverify-pickles-v1",
        profile: "PicklesV1",
        reference: source.reference,
        compile_config: source.compile_config,
        source_verification_key_hash: source.verification_key.hash,
        recursion_width,
        max_proofs_verified,
        step_domain_log2,
        wrap_domain_log2,
        public_input_size,
        public_output_size,
        proof: hex::encode(&proof),
        verification_key: hex::encode(&vk),
        public_input: convert_public_fields(&source.proof.public_input)?,
        public_output: convert_public_fields(&source.proof.public_output)?,
        expected_verification: source.expected_verification,
    };

    fs::create_dir_all(&output_directory).with_context(|| {
        format!(
            "cannot create converted fixture directory {}",
            output_directory.display()
        )
    })?;
    let mut output_bytes = serde_json::to_vec_pretty(&converted)?;
    output_bytes.push(b'\n');
    fs::write(output_directory.join("fixture.json"), output_bytes)
        .context("cannot write converted fixture JSON")?;
    fs::write(output_directory.join("proof.bin"), proof).context("cannot write converted proof")?;
    fs::write(output_directory.join("verifier-index.bin"), vk)
        .context("cannot write converted verification key")?;
    Ok(())
}

fn validate_source_envelope(source: &SourceFixture) -> Result<()> {
    if source.format != "zkverify-pickles-source-v1" {
        bail!("unsupported source fixture format: {}", source.format);
    }
    if source.reference.package != "o1js" {
        bail!(
            "PicklesV1 source fixtures must identify o1js as their prover, got {}",
            source.reference.package
        );
    }
    if !(1..=8).contains(&source.compile_config.num_chunks) {
        bail!("numChunks must be in 1..=8");
    }
    if source
        .compile_config
        .override_wrap_domain
        .is_some_and(|domain| domain > 2)
    {
        bail!("overrideWrapDomain must be in 0..=2");
    }
    if source.proof.max_proofs_verified > 2 {
        bail!("maxProofsVerified must be in 0..=2");
    }
    if source.proof.proof.is_empty() {
        bail!("generic o1js proof must not be empty");
    }
    let public_fields = source
        .proof
        .public_input
        .len()
        .checked_add(source.proof.public_output.len())
        .context("combined public input/output length overflowed")?;
    if public_fields > 1_024 {
        bail!("combined public input/output length must not exceed 1024 fields");
    }
    Ok(())
}

/// Decode both Mina's legacy one-chunk proof S-expression and the chunk-safe
/// representation introduced by MinaProtocol/mina#18884. OpenMina's current
/// stable Rust type still models public-input evaluations as two scalars, so
/// for the new representation we extract the full vectors first and collapse
/// only a temporary S-expression copy before delegating the remaining fields
/// to its generated decoder. Remove this adapter once the upstream Rust wire
/// type models chunked public-input evaluations directly.
fn decode_transaction_proof(encoded: &str) -> Result<DecodedTransactionProof> {
    let decoded = STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .context("cannot decode o1js transaction proof as base64")?;
    let mut sexp = rsexp::from_slice(&decoded)
        .map_err(|error| anyhow::anyhow!("cannot parse o1js proof S-expression: {error:?}"))?;

    if let Ok(transaction) = TransactionSnarkProofStableV2::of_sexp(&sexp) {
        let source = &transaction.0.prev_evals.evals.public_input;
        let public_input = PointEvaluations {
            zeta: vec![field(&source.0)],
            zeta_omega: vec![field(&source.1)],
        };
        return Ok(DecodedTransactionProof {
            proof: transaction.0,
            public_input,
        });
    }

    let public_input = extract_chunked_public_input(&mut sexp)?;
    let transaction = TransactionSnarkProofStableV2::of_sexp(&sexp).map_err(|error| {
        anyhow::anyhow!(
            "cannot decode the non-public-input fields of the chunk-safe o1js proof: {error}"
        )
    })?;
    Ok(DecodedTransactionProof {
        proof: transaction.0,
        public_input,
    })
}

fn record_field_mut<'a>(record: &'a mut Sexp, name: &str) -> Result<&'a mut Sexp> {
    let Sexp::List(fields) = record else {
        bail!("expected an S-expression record while locating {name}");
    };
    let index = fields
        .iter()
        .position(|field| {
            matches!(
                field,
                Sexp::List(pair)
                    if pair.len() == 2
                        && matches!(&pair[0], Sexp::Atom(label) if label == name.as_bytes())
            )
        })
        .with_context(|| format!("proof S-expression is missing the {name} field"))?;
    let Sexp::List(pair) = &mut fields[index] else {
        unreachable!("the selected record field was matched as a list")
    };
    Ok(&mut pair[1])
}

fn sexp_field_vector(value: &Sexp, point: &str) -> Result<Vec<FieldBytes>> {
    let Sexp::List(values) = value else {
        bail!("chunk-safe public_input.{point} must be an S-expression list");
    };
    if !(1..=8).contains(&values.len()) {
        bail!(
            "chunk-safe public_input.{point} contains {} chunks, expected 1..=8",
            values.len()
        );
    }
    values
        .iter()
        .map(|value| {
            BigInt::of_sexp(value)
                .map(|value| field(&value))
                .map_err(|error| {
                    anyhow::anyhow!("invalid field in chunk-safe public_input.{point}: {error}")
                })
        })
        .collect()
}

fn extract_chunked_public_input(sexp: &mut Sexp) -> Result<PointEvaluations> {
    let prev_evals = record_field_mut(sexp, "prev_evals")?;
    let evals = record_field_mut(prev_evals, "evals")?;
    let public_input = record_field_mut(evals, "public_input")?;
    let Sexp::List(points) = public_input else {
        bail!("chunk-safe public_input must contain zeta and zeta_omega lists");
    };
    if points.len() != 2 {
        bail!(
            "chunk-safe public_input contains {} evaluation points, expected 2",
            points.len()
        );
    }

    let zeta = sexp_field_vector(&points[0], "zeta")?;
    let zeta_omega = sexp_field_vector(&points[1], "zeta_omega")?;
    if zeta.len() != zeta_omega.len() {
        bail!(
            "chunk-safe public-input evaluations have inconsistent chunk counts: {} and {}",
            zeta.len(),
            zeta_omega.len()
        );
    }

    let Sexp::List(zeta_sexp) = &points[0] else {
        unreachable!("sexp_field_vector checked the zeta list")
    };
    let Sexp::List(zeta_omega_sexp) = &points[1] else {
        unreachable!("sexp_field_vector checked the zeta_omega list")
    };
    *public_input = Sexp::List(vec![zeta_sexp[0].clone(), zeta_omega_sexp[0].clone()]);

    Ok(PointEvaluations { zeta, zeta_omega })
}

fn convert_public_fields(values: &[String]) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| {
            let bigint = BigInt::from_decimal(value)
                .map_err(|_| anyhow::anyhow!("invalid decimal public field: {value}"))?;
            Ok(hex::encode(bigint.to_bytes()))
        })
        .collect()
}

fn field(value: &BigInt) -> FieldBytes {
    value.to_bytes()
}

fn point(value: &(BigInt, BigInt)) -> PointBytes {
    [field(&value.0), field(&value.1)]
}

fn proofs_verified(value: &PicklesBaseProofsVerifiedStableV1) -> ProofsVerified {
    match value {
        PicklesBaseProofsVerifiedStableV1::N0 => ProofsVerified::N0,
        PicklesBaseProofsVerifiedStableV1::N1 => ProofsVerified::N1,
        PicklesBaseProofsVerifiedStableV1::N2 => ProofsVerified::N2,
    }
}

fn wrap_domain_log2(value: ProofsVerified) -> u8 {
    match value {
        ProofsVerified::N0 => 13,
        ProofsVerified::N1 => 14,
        ProofsVerified::N2 => 15,
    }
}

fn limbs(values: &[LimbVectorConstantHex64StableV1; 2]) -> [u64; 2] {
    values.each_ref().map(|value| value.0.as_u64())
}

fn scalar_challenge(
    value: &PicklesReducedMessagesForNextProofOverSameFieldWrapChallengesVectorStableV2AChallenge,
) -> [u64; 2] {
    limbs(&value.inner.0)
}

fn bulletproof_challenge(
    value: &PicklesReducedMessagesForNextProofOverSameFieldWrapChallengesVectorStableV2A,
) -> [u64; 2] {
    scalar_challenge(&value.prechallenge)
}

fn challenge_vector_15(
    value: &PicklesReducedMessagesForNextProofOverSameFieldWrapChallengesVectorStableV2,
) -> [[u64; 2]; 15] {
    value.0 .0.each_ref().map(bulletproof_challenge)
}

fn branch_data(value: &CompositionTypesBranchDataStableV1) -> BranchData {
    BranchData {
        proofs_verified: proofs_verified(&value.proofs_verified),
        domain_log2: value.domain_log2.0.as_u8(),
    }
}

fn feature_flags(
    value: &PicklesProofProofsVerified2ReprStableV2StatementProofStateDeferredValuesPlonkFeatureFlags,
) -> FeatureFlags {
    FeatureFlags {
        range_check0: value.range_check0,
        range_check1: value.range_check1,
        foreign_field_add: value.foreign_field_add,
        foreign_field_mul: value.foreign_field_mul,
        xor: value.xor,
        rot: value.rot,
        lookup: value.lookup,
        runtime_tables: value.runtime_tables,
    }
}

fn point_evaluations(value: &(ArrayN16<BigInt>, ArrayN16<BigInt>)) -> PointEvaluations {
    PointEvaluations {
        zeta: value.0.iter().map(field).collect(),
        zeta_omega: value.1.iter().map(field).collect(),
    }
}

fn proof_evaluations(
    value: &PicklesProofProofsVerified2ReprStableV2PrevEvalsEvalsEvals,
) -> ProofEvaluations {
    ProofEvaluations {
        w: value.w.0.each_ref().map(point_evaluations),
        coefficients: value.coefficients.0.each_ref().map(point_evaluations),
        z: point_evaluations(&value.z),
        s: value.s.0.each_ref().map(point_evaluations),
        generic_selector: point_evaluations(&value.generic_selector),
        poseidon_selector: point_evaluations(&value.poseidon_selector),
        complete_add_selector: point_evaluations(&value.complete_add_selector),
        mul_selector: point_evaluations(&value.mul_selector),
        emul_selector: point_evaluations(&value.emul_selector),
        endomul_scalar_selector: point_evaluations(&value.endomul_scalar_selector),
        range_check0_selector: value.range_check0_selector.as_ref().map(point_evaluations),
        range_check1_selector: value.range_check1_selector.as_ref().map(point_evaluations),
        foreign_field_add_selector: value
            .foreign_field_add_selector
            .as_ref()
            .map(point_evaluations),
        foreign_field_mul_selector: value
            .foreign_field_mul_selector
            .as_ref()
            .map(point_evaluations),
        xor_selector: value.xor_selector.as_ref().map(point_evaluations),
        rot_selector: value.rot_selector.as_ref().map(point_evaluations),
        lookup_aggregation: value.lookup_aggregation.as_ref().map(point_evaluations),
        lookup_table: value.lookup_table.as_ref().map(point_evaluations),
        lookup_sorted: value
            .lookup_sorted
            .0
            .each_ref()
            .map(|entry| entry.as_ref().map(point_evaluations)),
        runtime_lookup_table: value.runtime_lookup_table.as_ref().map(point_evaluations),
        runtime_lookup_table_selector: value
            .runtime_lookup_table_selector
            .as_ref()
            .map(point_evaluations),
        xor_lookup_selector: value.xor_lookup_selector.as_ref().map(point_evaluations),
        lookup_gate_lookup_selector: value
            .lookup_gate_lookup_selector
            .as_ref()
            .map(point_evaluations),
        range_check_lookup_selector: value
            .range_check_lookup_selector
            .as_ref()
            .map(point_evaluations),
        foreign_field_mul_lookup_selector: value
            .foreign_field_mul_lookup_selector
            .as_ref()
            .map(point_evaluations),
    }
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

fn evaluation_chunks(public_input: &PointEvaluations, evals: &ProofEvaluations) -> Result<usize> {
    let chunks = public_input.zeta.len();
    if !(1..=8).contains(&chunks)
        || public_input.zeta_omega.len() != chunks
        || all_evaluations(evals).any(|evaluation| {
            evaluation.zeta.len() != chunks || evaluation.zeta_omega.len() != chunks
        })
    {
        bail!("proof evaluations do not have a consistent 1..=8 chunk count");
    }
    Ok(chunks)
}

fn wrap_commitments(value: &PicklesWrapWireProofCommitmentsStableV1) -> WrapCommitments {
    WrapCommitments {
        w_comm: value.w_comm.0.each_ref().map(point),
        z_comm: point(&value.z_comm),
        t_comm: value.t_comm.0.each_ref().map(point),
    }
}

fn evaluation_pair(value: &(BigInt, BigInt)) -> [FieldBytes; 2] {
    [field(&value.0), field(&value.1)]
}

fn wrap_evaluations(value: &PicklesWrapWireProofEvaluationsStableV1) -> WrapEvaluations {
    WrapEvaluations {
        w: value.w.0.each_ref().map(evaluation_pair),
        coefficients: value.coefficients.0.each_ref().map(evaluation_pair),
        z: evaluation_pair(&value.z),
        s: value.s.0.each_ref().map(evaluation_pair),
        generic_selector: evaluation_pair(&value.generic_selector),
        poseidon_selector: evaluation_pair(&value.poseidon_selector),
        complete_add_selector: evaluation_pair(&value.complete_add_selector),
        mul_selector: evaluation_pair(&value.mul_selector),
        emul_selector: evaluation_pair(&value.emul_selector),
        endomul_scalar_selector: evaluation_pair(&value.endomul_scalar_selector),
    }
}

fn wrap_opening(value: &PicklesWrapWireProofStableV1Bulletproof) -> Result<WrapOpeningProof> {
    let lr = value
        .lr
        .iter()
        .map(|(left, right)| [point(left), point(right)])
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|lr: Vec<_>| {
            anyhow::anyhow!("wrap opening has {} IPA rounds, expected 15", lr.len())
        })?;
    Ok(WrapOpeningProof {
        lr,
        z1: field(&value.z_1),
        z2: field(&value.z_2),
        delta: point(&value.delta),
        challenge_polynomial_commitment: point(&value.challenge_polynomial_commitment),
    })
}

fn wrap_proof(value: &PicklesWrapWireProofStableV1) -> Result<WrapWireProof> {
    Ok(WrapWireProof {
        commitments: wrap_commitments(&value.commitments),
        evaluations: wrap_evaluations(&value.evaluations),
        ft_eval1: field(&value.ft_eval1),
        opening: wrap_opening(&value.bulletproof)?,
    })
}

fn convert_proof(
    value: &PicklesProofProofsVerified2ReprStableV2,
    public_input: PointEvaluations,
) -> Result<PicklesProofPayload> {
    let source_statement = &value.statement;
    let proof_state = &source_statement.proof_state;
    let deferred = &proof_state.deferred_values;
    let plonk = &deferred.plonk;
    let next_step = &source_statement.messages_for_next_step_proof;
    let next_wrap = &proof_state.messages_for_next_wrap_proof;

    let challenge_polynomial_commitments = next_step
        .challenge_polynomial_commitments
        .iter()
        .map(point)
        .collect::<Vec<_>>();
    let old_bulletproof_challenges = next_step
        .old_bulletproof_challenges
        .iter()
        .map(|challenges| challenges.0.each_ref().map(bulletproof_challenge))
        .collect::<Vec<_>>();
    let recursion_width = proofs_verified(&deferred.branch_data.proofs_verified).as_usize();
    if challenge_polynomial_commitments.len() != recursion_width
        || old_bulletproof_challenges.len() != recursion_width
    {
        bail!("next-step message length does not match the branch recursion width");
    }

    let statement = Statement {
        deferred_values: DeferredValues {
            plonk: DeferredPlonk {
                alpha: scalar_challenge(&plonk.alpha),
                beta: limbs(&plonk.beta.0),
                gamma: limbs(&plonk.gamma.0),
                zeta: scalar_challenge(&plonk.zeta),
                joint_combiner: plonk.joint_combiner.as_ref().map(scalar_challenge),
                feature_flags: feature_flags(&plonk.feature_flags),
            },
            bulletproof_challenges: deferred
                .bulletproof_challenges
                .0
                .each_ref()
                .map(bulletproof_challenge),
            branch_data: branch_data(&deferred.branch_data),
        },
        sponge_digest_before_evaluations: proof_state
            .sponge_digest_before_evaluations
            .0
             .0
            .each_ref()
            .map(|limb| limb.0.as_u64()),
        messages_for_next_wrap_proof: MessagesForNextWrapProof {
            challenge_polynomial_commitment: point(&next_wrap.challenge_polynomial_commitment),
            old_bulletproof_challenges: next_wrap.old_bulletproof_challenges.0.each_ref().map(
                |set| WrapChallengeSet {
                    challenges: challenge_vector_15(set),
                },
            ),
        },
        messages_for_next_step_proof: MessagesForNextStepProof {
            challenge_polynomial_commitments,
            old_bulletproof_challenges,
        },
    };

    let source_prev_evals = &value.prev_evals;
    Ok(PicklesProofPayload {
        statement,
        prev_evals: PrevEvals {
            public_input,
            evals: proof_evaluations(&source_prev_evals.evals.evals),
            ft_eval1: field(&source_prev_evals.ft_eval1),
        },
        wrap_proof: wrap_proof(&value.proof)?,
    })
}

fn wrap_index(value: &MinaBaseVerificationKeyWireStableV1WrapIndex) -> WrapVerifierIndex {
    WrapVerifierIndex {
        sigma_comm: value.sigma_comm.0.each_ref().map(point),
        coefficients_comm: value.coefficients_comm.0.each_ref().map(point),
        generic_comm: point(&value.generic_comm),
        psm_comm: point(&value.psm_comm),
        complete_add_comm: point(&value.complete_add_comm),
        mul_comm: point(&value.mul_comm),
        emul_comm: point(&value.emul_comm),
        endomul_scalar_comm: point(&value.endomul_scalar_comm),
    }
}

fn convert_vk(
    value: &MinaBaseVerificationKeyWireStableV1,
    public_input_size: u32,
    public_output_size: u32,
) -> PicklesVkPayload {
    PicklesVkPayload {
        max_proofs_verified: proofs_verified(&value.max_proofs_verified),
        actual_wrap_domain_size: proofs_verified(&value.actual_wrap_domain_size),
        public_input_size,
        public_output_size,
        wrap_index: wrap_index(&value.wrap_index),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_temporarily_downgrades_chunked_public_input() {
        let mut sexp = rsexp::from_slice(
            b"((prev_evals ((evals ((public_input ((0x01 0x02) (0x03 0x04))))))))",
        )
        .unwrap();

        let public_input = extract_chunked_public_input(&mut sexp).unwrap();
        assert_eq!(public_input.zeta.len(), 2);
        assert_eq!(public_input.zeta_omega.len(), 2);
        assert_eq!(public_input.zeta[0][0], 1);
        assert_eq!(public_input.zeta[1][0], 2);
        assert_eq!(public_input.zeta_omega[0][0], 3);
        assert_eq!(public_input.zeta_omega[1][0], 4);

        let expected =
            rsexp::from_slice(b"((prev_evals ((evals ((public_input (0x01 0x03)))))))").unwrap();
        assert_eq!(sexp, expected);
    }

    #[test]
    fn rejects_mismatched_public_input_chunk_counts() {
        let mut sexp =
            rsexp::from_slice(b"((prev_evals ((evals ((public_input ((0x01 0x02) (0x03))))))))")
                .unwrap();
        assert!(extract_chunked_public_input(&mut sexp)
            .unwrap_err()
            .to_string()
            .contains("inconsistent chunk counts"));
    }
}
