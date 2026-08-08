// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Canonical client-to-runtime encoding for o1js Pickles proofs.
//!
//! These types deliberately do not reuse Mina's bin-prot or S-expression wire
//! types. Clients translate those versioned encodings once; the runtime only
//! accepts canonical bincode-v2 bytes containing fixed-width field elements,
//! points, challenges, and explicitly bounded vectors.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A canonical little-endian Pasta field element.
pub type FieldBytes = [u8; 32];

/// An affine Pasta point encoded as canonical little-endian coordinates.
pub type PointBytes = [FieldBytes; 2];

/// The two 64-bit limbs used by Mina's scalar-challenge encoding.
pub type ScalarChallenge = [u64; 2];

/// Pickles supports at most two verified proofs in a branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofsVerified {
    /// No recursive proof was verified.
    N0,
    /// One recursive proof was verified.
    N1,
    /// Two recursive proofs were verified.
    N2,
}

impl ProofsVerified {
    /// Return the numeric recursion width.
    pub const fn as_usize(self) -> usize {
        match self {
            Self::N0 => 0,
            Self::N1 => 1,
            Self::N2 => 2,
        }
    }
}

/// Branch-specific recursion width and step-domain size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchData {
    /// Number of proofs verified by the branch.
    pub proofs_verified: ProofsVerified,
    /// Base-two logarithm of the step proof domain.
    pub domain_log2: u8,
}

/// Feature flags committed to by the deferred Pickles statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlags {
    pub range_check0: bool,
    pub range_check1: bool,
    pub foreign_field_add: bool,
    pub foreign_field_mul: bool,
    pub xor: bool,
    pub rot: bool,
    pub lookup: bool,
    pub runtime_tables: bool,
}

/// Fiat-Shamir values deferred from the step proof to the wrap proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredPlonk {
    pub alpha: ScalarChallenge,
    pub beta: ScalarChallenge,
    pub gamma: ScalarChallenge,
    pub zeta: ScalarChallenge,
    pub joint_combiner: Option<ScalarChallenge>,
    pub feature_flags: FeatureFlags,
}

/// Deferred values carried in the Pickles statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredValues {
    pub plonk: DeferredPlonk,
    pub bulletproof_challenges: [ScalarChallenge; 16],
    pub branch_data: BranchData,
}

/// A recursion accumulator from a previous wrap proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapChallengeSet {
    pub challenges: [ScalarChallenge; 15],
}

/// Message that will be consumed by the next wrap proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagesForNextWrapProof {
    pub challenge_polynomial_commitment: PointBytes,
    /// Exactly two entries in the stable Pickles representation. Unused
    /// entries are Mina's canonical dummy challenges and are checked later.
    pub old_bulletproof_challenges: [WrapChallengeSet; 2],
}

/// Message that will be consumed by the next step proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagesForNextStepProof {
    /// Contains exactly `branch_data.proofs_verified` points.
    pub challenge_polynomial_commitments: Vec<PointBytes>,
    /// Contains exactly `branch_data.proofs_verified` challenge vectors.
    pub old_bulletproof_challenges: Vec<[ScalarChallenge; 16]>,
}

/// The complete deferred Pickles statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub deferred_values: DeferredValues,
    /// Four 64-bit limbs of the step sponge digest.
    pub sponge_digest_before_evaluations: [u64; 4],
    pub messages_for_next_wrap_proof: MessagesForNextWrapProof,
    pub messages_for_next_step_proof: MessagesForNextStepProof,
}

/// Evaluations of one (possibly chunked) polynomial at zeta and zeta*omega.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointEvaluations {
    pub zeta: Vec<FieldBytes>,
    pub zeta_omega: Vec<FieldBytes>,
}

/// Step-proof evaluations used to reconstruct the wrap public input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEvaluations {
    pub w: [PointEvaluations; 15],
    pub coefficients: [PointEvaluations; 15],
    pub z: PointEvaluations,
    pub s: [PointEvaluations; 6],
    pub generic_selector: PointEvaluations,
    pub poseidon_selector: PointEvaluations,
    pub complete_add_selector: PointEvaluations,
    pub mul_selector: PointEvaluations,
    pub emul_selector: PointEvaluations,
    pub endomul_scalar_selector: PointEvaluations,
    pub range_check0_selector: Option<PointEvaluations>,
    pub range_check1_selector: Option<PointEvaluations>,
    pub foreign_field_add_selector: Option<PointEvaluations>,
    pub foreign_field_mul_selector: Option<PointEvaluations>,
    pub xor_selector: Option<PointEvaluations>,
    pub rot_selector: Option<PointEvaluations>,
    pub lookup_aggregation: Option<PointEvaluations>,
    pub lookup_table: Option<PointEvaluations>,
    pub lookup_sorted: [Option<PointEvaluations>; 5],
    pub runtime_lookup_table: Option<PointEvaluations>,
    pub runtime_lookup_table_selector: Option<PointEvaluations>,
    pub xor_lookup_selector: Option<PointEvaluations>,
    pub lookup_gate_lookup_selector: Option<PointEvaluations>,
    pub range_check_lookup_selector: Option<PointEvaluations>,
    pub foreign_field_mul_lookup_selector: Option<PointEvaluations>,
}

/// Previous step-proof evaluations embedded in the Pickles proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrevEvals {
    /// Public-input polynomial evaluations at zeta and zeta*omega. Mina's
    /// legacy proof encoding stored only the first chunk at each point; the
    /// chunk-safe encoding stores all chunks just like every other split
    /// polynomial evaluation.
    pub public_input: PointEvaluations,
    pub evals: ProofEvaluations,
    pub ft_eval1: FieldBytes,
}

/// Commitments in the fixed Pickles wrap proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapCommitments {
    pub w_comm: [PointBytes; 15],
    pub z_comm: PointBytes,
    pub t_comm: [PointBytes; 7],
}

/// Scalar evaluations in the fixed Pickles wrap proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapEvaluations {
    pub w: [[FieldBytes; 2]; 15],
    pub coefficients: [[FieldBytes; 2]; 15],
    pub z: [FieldBytes; 2],
    pub s: [[FieldBytes; 2]; 6],
    pub generic_selector: [FieldBytes; 2],
    pub poseidon_selector: [FieldBytes; 2],
    pub complete_add_selector: [FieldBytes; 2],
    pub mul_selector: [FieldBytes; 2],
    pub emul_selector: [FieldBytes; 2],
    pub endomul_scalar_selector: [FieldBytes; 2],
}

/// IPA opening proof in the fixed Pickles wrap proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapOpeningProof {
    pub lr: [[PointBytes; 2]; 15],
    pub z1: FieldBytes,
    pub z2: FieldBytes,
    pub delta: PointBytes,
    pub challenge_polynomial_commitment: PointBytes,
}

/// Mina's fixed wrap wire proof, normalized to canonical field bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapWireProof {
    pub commitments: WrapCommitments,
    pub evaluations: WrapEvaluations,
    pub ft_eval1: FieldBytes,
    pub opening: WrapOpeningProof,
}

/// Canonical proof payload accepted by the runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicklesProofPayload {
    pub statement: Statement,
    pub prev_evals: PrevEvals,
    pub wrap_proof: WrapWireProof,
}

/// Fixed commitment portion of a side-loaded Pickles verification key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapVerifierIndex {
    pub sigma_comm: [PointBytes; 7],
    pub coefficients_comm: [PointBytes; 15],
    pub generic_comm: PointBytes,
    pub psm_comm: PointBytes,
    pub complete_add_comm: PointBytes,
    pub mul_comm: PointBytes,
    pub emul_comm: PointBytes,
    pub endomul_scalar_comm: PointBytes,
}

/// Canonical verification-key payload accepted by the runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicklesVkPayload {
    pub max_proofs_verified: ProofsVerified,
    pub actual_wrap_domain_size: ProofsVerified,
    /// Number of fields in the o1js program's declared public input.
    pub public_input_size: u32,
    /// Number of fields in the o1js program's declared public output.
    pub public_output_size: u32,
    pub wrap_index: WrapVerifierIndex,
}
