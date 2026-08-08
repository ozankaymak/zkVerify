// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use alloc::sync::Arc;

use frame_support::traits::ConstU32;
use kimchi::{groupmap::GroupMap, verifier::verify_with_rng};
use mina_curves::pasta::{Fq, Pallas, PallasParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::{
    builtin_srs::BuiltinSrs,
    format::{
        PicklesProofPayload, PicklesVkPayload, PointEvaluations, ProofEvaluations, ProofsVerified,
    },
    index::make_verifier_index,
    outer::convert_outer_proof,
    prepared,
    profile::{self, ProfileError},
    Pubs,
};

struct MockConfig;

impl crate::Config for MockConfig {
    type MaxProofSize = ConstU32<65_536>;
    type MaxPubs = ConstU32<1_024>;
    type MaxVkSize = ConstU32<4_096>;
    type WeightInfo = ();
}

struct OnePublicFieldConfig;

impl crate::Config for OnePublicFieldConfig {
    type MaxProofSize = ConstU32<65_536>;
    type MaxPubs = ConstU32<1>;
    type MaxVkSize = ConstU32<4_096>;
    type WeightInfo = ();
}

fn decode<T: serde::de::DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> T {
    let config = bincode::config::standard().with_limit::<65_536>();
    let (value, consumed) = bincode::serde::decode_from_slice(bytes, config).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(
        bincode::serde::encode_to_vec(&value, bincode::config::standard()).unwrap(),
        bytes
    );
    value
}

fn test_srs(domain_size: usize) -> Arc<BuiltinSrs> {
    Arc::new(
        BuiltinSrs::load(crate::PicklesProfileId::PicklesV1, 1 << 15, domain_size, 40).unwrap(),
    )
}

#[test]
fn scalar_challenge_conversion_matches_proof_systems() {
    let challenge = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
    let (_, endo) = poly_commitment::ipa::endos::<Pallas>();
    assert_eq!(
        crate::outer::scalar_challenge_to_field(challenge, endo),
        mina_poseidon::sponge::ScalarChallenge::from_limbs(challenge).to_field(&endo)
    );
}

fn pubs(input: u8, output: u8) -> Pubs {
    pubs_u64(u64::from(input), u64::from(output))
}

fn pubs_u64(input: u64, output: u64) -> Pubs {
    let mut public_input = [0; 32];
    public_input[..8].copy_from_slice(&input.to_le_bytes());
    let mut public_output = [0; 32];
    public_output[..8].copy_from_slice(&output.to_le_bytes());
    Pubs {
        public_input: vec![public_input],
        public_output: vec![public_output],
    }
}

fn fixture(width: usize) -> (PicklesProofPayload, PicklesVkPayload) {
    let (proof, vk): (&[u8], &[u8]) = match width {
        0 => (
            include_bytes!("resources/width0/proof.bin"),
            include_bytes!("resources/width0/verifier-index.bin"),
        ),
        1 => (
            include_bytes!("resources/width1/proof.bin"),
            include_bytes!("resources/width1/verifier-index.bin"),
        ),
        2 => (
            include_bytes!("resources/width2/proof.bin"),
            include_bytes!("resources/width2/verifier-index.bin"),
        ),
        _ => unreachable!(),
    };
    (decode(proof), decode(vk))
}

fn fixture_bytes(width: usize) -> (&'static [u8], &'static [u8]) {
    match width {
        0 => (
            include_bytes!("resources/width0/proof.bin"),
            include_bytes!("resources/width0/verifier-index.bin"),
        ),
        1 => (
            include_bytes!("resources/width1/proof.bin"),
            include_bytes!("resources/width1/verifier-index.bin"),
        ),
        2 => (
            include_bytes!("resources/width2/proof.bin"),
            include_bytes!("resources/width2/verifier-index.bin"),
        ),
        _ => unreachable!(),
    }
}

fn resize_evaluation(evaluation: &mut PointEvaluations, chunks: usize) {
    let zeta = *evaluation.zeta.last().unwrap();
    let zeta_omega = *evaluation.zeta_omega.last().unwrap();
    evaluation.zeta.resize(chunks, zeta);
    evaluation.zeta_omega.resize(chunks, zeta_omega);
}

fn set_evaluation_chunks(evals: &mut ProofEvaluations, chunks: usize) {
    for evaluation in &mut evals.w {
        resize_evaluation(evaluation, chunks);
    }
    for evaluation in &mut evals.coefficients {
        resize_evaluation(evaluation, chunks);
    }
    resize_evaluation(&mut evals.z, chunks);
    for evaluation in &mut evals.s {
        resize_evaluation(evaluation, chunks);
    }
    for evaluation in [
        &mut evals.generic_selector,
        &mut evals.poseidon_selector,
        &mut evals.complete_add_selector,
        &mut evals.mul_selector,
        &mut evals.emul_selector,
        &mut evals.endomul_scalar_selector,
    ] {
        resize_evaluation(evaluation, chunks);
    }

    macro_rules! resize_optional {
        ($($field:ident),+ $(,)?) => {
            $(
                if let Some(evaluation) = evals.$field.as_mut() {
                    resize_evaluation(evaluation, chunks);
                }
            )+
        };
    }
    resize_optional!(
        range_check0_selector,
        range_check1_selector,
        foreign_field_add_selector,
        foreign_field_mul_selector,
        xor_selector,
        rot_selector,
        lookup_aggregation,
        lookup_table,
        runtime_lookup_table,
        runtime_lookup_table_selector,
        xor_lookup_selector,
        lookup_gate_lookup_selector,
        range_check_lookup_selector,
        foreign_field_mul_lookup_selector,
    );
    for evaluation in evals.lookup_sorted.iter_mut().flatten() {
        resize_evaluation(evaluation, chunks);
    }
}

fn enable_all_optional_evaluations(evals: &mut ProofEvaluations) {
    let evaluation = evals.w[0].clone();
    macro_rules! enable_optional {
        ($($field:ident),+ $(,)?) => {
            $(
                evals.$field.get_or_insert_with(|| evaluation.clone());
            )+
        };
    }
    enable_optional!(
        range_check0_selector,
        range_check1_selector,
        foreign_field_add_selector,
        foreign_field_mul_selector,
        xor_selector,
        rot_selector,
        lookup_aggregation,
        lookup_table,
        runtime_lookup_table,
        runtime_lookup_table_selector,
        xor_lookup_selector,
        lookup_gate_lookup_selector,
        range_check_lookup_selector,
        foreign_field_mul_lookup_selector,
    );
    for entry in &mut evals.lookup_sorted {
        entry.get_or_insert_with(|| evaluation.clone());
    }
}

#[test]
fn converted_o1js_fixtures_have_the_expected_pickles_shapes() {
    for (expected_width, pubs) in [(0, pubs(2, 3)), (1, pubs(5, 6)), (2, pubs(18, 19))] {
        let (proof, vk) = fixture(expected_width);
        profile::validate_vk(&vk).unwrap();
        assert_eq!(profile::validate_proof(&proof, &vk), Ok(1));
        assert_eq!(vk.public_input_size, 1);
        assert_eq!(vk.public_output_size, 1);
        assert_eq!(
            proof
                .statement
                .deferred_values
                .branch_data
                .proofs_verified
                .as_usize(),
            expected_width
        );

        let outer = convert_outer_proof(&proof).unwrap();
        assert_eq!(outer.proof.rounds(), 15);
        assert_eq!(outer.prev_challenges.len(), 2);
        assert!(outer
            .prev_challenges
            .iter()
            .all(|challenge| challenge.chals.len() == 15));
        assert_eq!(
            prepared::public_input(&proof, &vk, &pubs).unwrap().len(),
            40
        );
    }
}

#[test]
fn converted_o1js_fixtures_pass_the_outer_wrap_verifier() {
    for (width, pubs) in [(0, pubs(2, 3)), (1, pubs(5, 6)), (2, pubs(18, 19))] {
        let (proof, vk) = fixture(width);
        let public_input = prepared::public_input(&proof, &vk, &pubs).unwrap();
        let proof = convert_outer_proof(&proof).unwrap();
        let index = make_verifier_index(
            &vk,
            test_srs(1 << crate::index::wrap_domain_log2(vk.actual_wrap_domain_size)),
        )
        .unwrap();
        let group_map = GroupMap::setup();
        let mut rng = ChaCha20Rng::from_seed([width as u8; 32]);

        verify_with_rng::<
            FULL_ROUNDS,
            Pallas,
            DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
            DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
            crate::builtin_opening::BuiltinOpeningProof,
            _,
        >(&group_map, &index, &proof, &public_input, &mut rng)
        .unwrap_or_else(|error| panic!("width {width} failed: {error:?}"));
    }
}

#[test]
fn accelerated_opening_rejects_malformed_and_false_proofs() {
    let (source, vk) = fixture(0);
    let public_input = prepared::public_input(&source, &vk, &pubs(2, 3)).unwrap();
    let index = make_verifier_index(
        &vk,
        test_srs(1 << crate::index::wrap_domain_log2(vk.actual_wrap_domain_size)),
    )
    .unwrap();
    let group_map = GroupMap::setup();

    let verify = |proof: &crate::outer::OuterProof, seed: u8| {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        verify_with_rng::<
            FULL_ROUNDS,
            Pallas,
            DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
            DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
            crate::builtin_opening::BuiltinOpeningProof,
            _,
        >(&group_map, &index, proof, &public_input, &mut rng)
    };

    let mut missing_rounds = convert_outer_proof(&source).unwrap();
    missing_rounds.proof.clear_rounds_for_test();
    assert!(verify(&missing_rounds, 1).is_err());

    let mut extra_round = convert_outer_proof(&source).unwrap();
    extra_round.proof.duplicate_round_for_test();
    assert!(verify(&extra_round, 2).is_err());

    let mut false_opening = convert_outer_proof(&source).unwrap();
    false_opening.proof.corrupt_z1_for_test();
    assert!(verify(&false_opening, 3).is_err());
}

#[test]
fn full_verifier_accepts_all_o1js_recursion_widths() {
    use pallet_verifiers::traits::Verifier;

    for (width, pubs) in [(0, pubs(2, 3)), (1, pubs(5, 6)), (2, pubs(18, 19))] {
        let (proof, verifier_key) = fixture_bytes(width);
        let vk =
            crate::Vk::<MockConfig>::new(verifier_key.to_vec(), crate::PicklesProfileId::PicklesV1);
        crate::Pickles::<MockConfig>::validate_vk(&vk).unwrap();
        assert_eq!(
            crate::Pickles::<MockConfig>::verify_proof(&vk, &proof.to_vec(), &pubs),
            Ok(None)
        );
    }
}

#[test]
fn full_verifier_accepts_an_o1js_feature_enabled_proof() {
    use pallet_verifiers::traits::Verifier;

    let proof = include_bytes!("resources/features/proof.bin");
    let verifier_key = include_bytes!("resources/features/verifier-index.bin");
    let decoded_proof: PicklesProofPayload = decode(proof);
    let decoded_vk: PicklesVkPayload = decode(verifier_key);
    let flags = decoded_proof.statement.deferred_values.plonk.feature_flags;

    assert!(flags.range_check0);
    assert!(flags.xor);
    assert!(flags.rot);
    assert!(decoded_proof
        .statement
        .deferred_values
        .plonk
        .joint_combiner
        .is_some());
    profile::validate_vk(&decoded_vk).unwrap();
    assert_eq!(profile::validate_proof(&decoded_proof, &decoded_vk), Ok(1));

    let vk =
        crate::Vk::<MockConfig>::new(verifier_key.to_vec(), crate::PicklesProfileId::PicklesV1);
    assert_eq!(
        crate::Pickles::<MockConfig>::verify_proof(&vk, &proof.to_vec(), &pubs_u64(2, 5_120),),
        Ok(None)
    );
}

fn assert_full_verifier_accepts_chunked_fixture(proof: &[u8], verifier_key: &[u8], chunks: usize) {
    use pallet_verifiers::traits::Verifier;

    let decoded_proof: PicklesProofPayload = decode(proof);
    let decoded_vk: PicklesVkPayload = decode(verifier_key);

    assert_eq!(decoded_proof.prev_evals.public_input.zeta.len(), chunks);
    assert_eq!(
        decoded_proof.prev_evals.public_input.zeta_omega.len(),
        chunks
    );
    assert_eq!(
        profile::validate_proof(&decoded_proof, &decoded_vk),
        Ok(chunks)
    );
    assert_eq!(crate::accumulator::verify(&decoded_proof), Ok(true));

    let public_input = prepared::public_input(&decoded_proof, &decoded_vk, &pubs(2, 2)).unwrap();
    let outer = convert_outer_proof(&decoded_proof).unwrap();
    let index = make_verifier_index(
        &decoded_vk,
        test_srs(1 << crate::index::wrap_domain_log2(decoded_vk.actual_wrap_domain_size)),
    )
    .unwrap();
    let group_map = GroupMap::setup();
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    verify_with_rng::<
        FULL_ROUNDS,
        Pallas,
        DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
        DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
        crate::builtin_opening::BuiltinOpeningProof,
        _,
    >(&group_map, &index, &outer, &public_input, &mut rng)
    .unwrap();

    let vk =
        crate::Vk::<MockConfig>::new(verifier_key.to_vec(), crate::PicklesProfileId::PicklesV1);
    assert_eq!(
        crate::Pickles::<MockConfig>::verify_proof(&vk, &proof.to_vec(), &pubs(2, 2)),
        Ok(None)
    );
}

#[test]
fn full_verifier_accepts_a_serialized_two_chunk_o1js_proof() {
    assert_full_verifier_accepts_chunked_fixture(
        include_bytes!("resources/chunks2/proof.bin"),
        include_bytes!("resources/chunks2/verifier-index.bin"),
        2,
    );
}

#[test]
fn full_verifier_accepts_a_serialized_eight_chunk_o1js_proof() {
    assert_full_verifier_accepts_chunked_fixture(
        include_bytes!("resources/chunks8/proof.bin"),
        include_bytes!("resources/chunks8/verifier-index.bin"),
        8,
    );
}

#[test]
fn accumulator_check_rejects_a_changed_challenge() {
    let (mut proof, _) = fixture(0);
    assert_eq!(crate::accumulator::verify(&proof), Ok(true));
    proof.statement.deferred_values.bulletproof_challenges[0][0] ^= 1;
    assert_eq!(crate::accumulator::verify(&proof), Ok(false));
}

#[test]
fn profile_rejects_recursion_messages_that_do_not_match_the_branch() {
    let (mut proof, vk) = fixture(1);
    proof
        .statement
        .messages_for_next_step_proof
        .challenge_polynomial_commitments
        .clear();
    assert_eq!(
        profile::validate_proof(&proof, &vk),
        Err(ProfileError::ProofConfiguration)
    );
}

#[test]
fn profile_rejects_inconsistent_evaluation_chunks() {
    let (mut proof, vk) = fixture(0);
    proof.prev_evals.evals.w[0].zeta.push([0; 32]);
    assert_eq!(
        profile::validate_proof(&proof, &vk),
        Err(ProfileError::EvaluationChunks)
    );
}

#[test]
fn profile_accepts_the_documented_eight_chunk_envelope() {
    let (mut proof, vk) = fixture(0);
    proof.statement.deferred_values.branch_data.domain_log2 = 19;
    resize_evaluation(&mut proof.prev_evals.public_input, 8);
    set_evaluation_chunks(&mut proof.prev_evals.evals, 8);
    assert_eq!(profile::validate_proof(&proof, &vk), Ok(8));

    proof.statement.deferred_values.branch_data.domain_log2 = 20;
    assert_eq!(
        profile::validate_proof(&proof, &vk),
        Err(ProfileError::ProofConfiguration)
    );

    proof.statement.deferred_values.branch_data.domain_log2 = 19;
    resize_evaluation(&mut proof.prev_evals.public_input, 9);
    set_evaluation_chunks(&mut proof.prev_evals.evals, 9);
    assert_eq!(
        profile::validate_proof(&proof, &vk),
        Err(ProfileError::EvaluationChunks)
    );
}

#[test]
fn step_zero_knowledge_rows_match_pickles_chunking() {
    assert_eq!(
        (1..=8)
            .map(crate::profile::step_zk_rows)
            .collect::<Vec<_>>(),
        vec![
            Some(3),
            Some(5),
            Some(7),
            Some(9),
            Some(12),
            Some(14),
            Some(16),
            Some(19)
        ]
    );
    assert_eq!(crate::profile::step_zk_rows(0), None);
    assert_eq!(crate::profile::step_zk_rows(9), None);
}

#[test]
fn maximal_structural_proof_encoding_fits_the_consensus_byte_limit() {
    let (mut proof, _) = fixture(2);
    resize_evaluation(&mut proof.prev_evals.public_input, 8);
    set_evaluation_chunks(&mut proof.prev_evals.evals, 8);
    enable_all_optional_evaluations(&mut proof.prev_evals.evals);
    let encoded = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    assert!(
        encoded.len() <= profile::MAX_PROOF_BYTES,
        "maximal PicklesV1 proof shape encoded to {} bytes",
        encoded.len()
    );
}

#[test]
fn profile_treats_wrap_domain_override_as_independent_of_recursion_width() {
    let (_, mut vk) = fixture(0);
    vk.max_proofs_verified = ProofsVerified::N0;
    vk.actual_wrap_domain_size = ProofsVerified::N2;
    assert_eq!(profile::validate_vk(&vk), Ok(()));

    vk.max_proofs_verified = ProofsVerified::N2;
    vk.actual_wrap_domain_size = ProofsVerified::N0;
    assert_eq!(profile::validate_vk(&vk), Ok(()));
}

#[test]
fn profile_rejects_public_arity_above_the_consensus_limit() {
    let (_, mut vk) = fixture(0);
    vk.public_input_size = 1_025;
    vk.public_output_size = 0;
    assert_eq!(
        profile::validate_vk(&vk),
        Err(ProfileError::VerificationKeyConfiguration)
    );
}

#[test]
fn full_verifier_rejects_keys_above_the_runtime_public_field_limit() {
    use pallet_verifiers::traits::Verifier;

    let (_, verifier_key) = fixture_bytes(0);
    let vk = crate::Vk::<OnePublicFieldConfig>::new(
        verifier_key.to_vec(),
        crate::PicklesProfileId::PicklesV1,
    );
    assert_eq!(
        crate::Pickles::<OnePublicFieldConfig>::validate_vk(&vk),
        Err(pallet_verifiers::traits::VerifyError::InvalidVerificationKey)
    );
}

#[test]
fn full_verifier_rejects_repartitioned_public_values() {
    use pallet_verifiers::traits::Verifier;

    let (proof, verifier_key) = fixture_bytes(0);
    let expected = pubs(2, 3);
    let repartitioned = Pubs {
        public_input: expected
            .public_input
            .iter()
            .chain(expected.public_output.iter())
            .copied()
            .collect(),
        public_output: Vec::new(),
    };
    let vk =
        crate::Vk::<MockConfig>::new(verifier_key.to_vec(), crate::PicklesProfileId::PicklesV1);
    assert_eq!(
        crate::Pickles::<MockConfig>::verify_proof(&vk, &proof.to_vec(), &repartitioned),
        Err(pallet_verifiers::traits::VerifyError::InvalidInput)
    );
}

#[test]
fn profile_rejects_non_canonical_fields_and_invalid_points() {
    let (mut proof, vk) = fixture(0);
    proof.prev_evals.ft_eval1 = [0xff; 32];
    assert_eq!(
        profile::validate_proof(&proof, &vk),
        Err(ProfileError::FieldEncoding)
    );

    let (proof, mut vk) = fixture(0);
    vk.wrap_index.generic_comm = [[0; 32], [0; 32]];
    assert_eq!(
        profile::validate_vk(&vk),
        Err(ProfileError::VerificationKeyConfiguration)
    );
    assert!(profile::validate_proof(&proof, &vk).is_ok());
}

#[test]
fn canonical_decoder_rejects_trailing_bytes() {
    use pallet_verifiers::traits::Verifier;

    let (proof, verifier_key) = fixture_bytes(0);
    let mut proof_with_trailing_data = proof.to_vec();
    proof_with_trailing_data.push(0);
    let vk =
        crate::Vk::<MockConfig>::new(verifier_key.to_vec(), crate::PicklesProfileId::PicklesV1);
    assert_eq!(
        crate::Pickles::<MockConfig>::verify_proof(&vk, &proof_with_trailing_data, &pubs(2, 3),),
        Err(pallet_verifiers::traits::VerifyError::InvalidProofData)
    );

    let mut vk_with_trailing_data = verifier_key.to_vec();
    vk_with_trailing_data.push(0);
    let vk =
        crate::Vk::<MockConfig>::new(vk_with_trailing_data, crate::PicklesProfileId::PicklesV1);
    assert_eq!(
        crate::Pickles::<MockConfig>::validate_vk(&vk),
        Err(pallet_verifiers::traits::VerifyError::InvalidVerificationKey)
    );
}
