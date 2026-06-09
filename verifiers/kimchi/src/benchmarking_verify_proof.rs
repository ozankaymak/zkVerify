// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg(feature = "runtime-benchmarks")]

use crate::{
    accelerated_opening::NoopOpeningProof, Config as VerifierConfig, Kimchi as Verifier,
    KimchiSrsId, NativeProof, NativeVerifierIndex, Proof, Pubs, Vk, PUB_SIZE,
};
use alloc::{sync::Arc, vec::Vec};
use ark_ec::VariableBaseMSM;
use ark_ff::UniformRand;
use frame_benchmarking::v2::*;
use kimchi::{proof::ProverProof, verifier::verify_with_rng};
use mina_curves::pasta::{Fp, ProjectiveVesta, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use pallet_verifiers::benchmarking_utils;
use pallet_verifiers::traits::Verifier as _;
use poly_commitment::{
    ipa::{OpeningProof, SRS as IpaSrs},
    SRS as _,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub trait Config: crate::Config {}
pub struct Pallet<T: Config>(crate::Pallet<T>);
impl<T: crate::Config> Config for T {}
pub type Call<T> = pallet_verifiers::Call<T, Verifier<T>>;

type NoopProof = ProverProof<Vesta, NoopOpeningProof, FULL_ROUNDS>;
type UpstreamProof = ProverProof<Vesta, OpeningProof<Vesta, FULL_ROUNDS>, FULL_ROUNDS>;
type UpstreamVerifierIndex =
    kimchi::verifier_index::VerifierIndex<FULL_ROUNDS, Vesta, IpaSrs<Vesta>>;
type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;

#[derive(Clone, Copy)]
struct Fixture {
    proof: &'static [u8],
    verifier_index: &'static [u8],
    srs: &'static [u8],
    pubs: &'static [u8],
}

const DOMAIN_1024: Fixture = Fixture {
    proof: include_bytes!("resources/generated_1024/proof.bin"),
    verifier_index: include_bytes!("resources/generated_1024/verifier_index.bin"),
    srs: include_bytes!("resources/generated_1024/srs.bin"),
    pubs: &[],
};

const DOMAIN_2048: Fixture = Fixture {
    proof: include_bytes!("resources/generated_2048/proof.bin"),
    verifier_index: include_bytes!("resources/generated_2048/verifier_index.bin"),
    srs: include_bytes!("resources/generated_2048/srs.bin"),
    pubs: &[],
};

const DOMAIN_4096: Fixture = Fixture {
    proof: include_bytes!("resources/generated_4096/proof.bin"),
    verifier_index: include_bytes!("resources/generated_4096/verifier_index.bin"),
    srs: include_bytes!("resources/generated_4096/srs.bin"),
    pubs: &[],
};

const DOMAIN_4096_PUBS_64: Fixture = Fixture {
    proof: include_bytes!("resources/generated_4096_pubs_64/proof.bin"),
    verifier_index: include_bytes!("resources/generated_4096_pubs_64/verifier_index.bin"),
    srs: include_bytes!("resources/generated_4096_pubs_64/srs.bin"),
    pubs: include_bytes!("resources/generated_4096_pubs_64/pubs.bin"),
};

fn benchmark_data<T: VerifierConfig>(fixture: Fixture) -> (Proof, Vk<T>, Pubs) {
    let chunks = fixture.pubs.chunks_exact(PUB_SIZE);
    assert!(chunks.remainder().is_empty());
    let pubs = chunks
        .map(|chunk| {
            chunk
                .try_into()
                .expect("public input has the expected size")
        })
        .collect();

    (
        fixture.proof.to_vec(),
        Vk::new(fixture.verifier_index.to_vec(), KimchiSrsId::Vesta16),
        pubs,
    )
}

fn decode_noop_proof(bytes: &[u8]) -> NoopProof {
    let (proof, consumed) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .expect("valid benchmark proof");
    assert_eq!(consumed, bytes.len());
    proof
}

fn prepared_accelerated_data<T: VerifierConfig>(
    fixture: Fixture,
) -> (NativeVerifierIndex, NativeProof, Vec<Fp>, ChaCha20Rng) {
    let (raw_proof, vk, raw_pubs) = benchmark_data::<T>(fixture);
    let proof = crate::decode_proof(&raw_proof).expect("valid benchmark proof");
    let public_input = crate::decode_public_input(&raw_pubs).expect("valid benchmark public input");
    let mut verifier_index = crate::decode_vk(&vk).expect("valid benchmark VK");
    crate::prepare_verifier_index(&mut verifier_index, vk.srs_id).expect("preparable benchmark VK");
    let rng = crate::make_rng(&vk, &raw_proof, &raw_pubs);

    (verifier_index, proof, public_input, rng)
}

fn prepared_noop_data<T: VerifierConfig>(
    fixture: Fixture,
) -> (NativeVerifierIndex, NoopProof, Vec<Fp>, ChaCha20Rng) {
    let (raw_proof, vk, raw_pubs) = benchmark_data::<T>(fixture);
    let proof = decode_noop_proof(&raw_proof);
    let public_input = crate::decode_public_input(&raw_pubs).expect("valid benchmark public input");
    let mut verifier_index = crate::decode_vk(&vk).expect("valid benchmark VK");
    crate::prepare_verifier_index(&mut verifier_index, vk.srs_id).expect("preparable benchmark VK");
    let rng = crate::make_rng(&vk, &raw_proof, &raw_pubs);

    (verifier_index, proof, public_input, rng)
}

fn prepared_upstream_data<T: VerifierConfig>(
    fixture: Fixture,
) -> (UpstreamVerifierIndex, UpstreamProof, Vec<Fp>, ChaCha20Rng) {
    let (raw_proof, vk, raw_pubs) = benchmark_data::<T>(fixture);
    let (proof, consumed) =
        bincode::serde::decode_from_slice(&raw_proof, bincode::config::standard())
            .expect("valid benchmark proof");
    assert_eq!(consumed, raw_proof.len());
    let public_input = crate::decode_public_input(&raw_pubs).expect("valid benchmark public input");
    let (mut verifier_index, consumed): (UpstreamVerifierIndex, _) =
        bincode::serde::decode_from_slice(fixture.verifier_index, bincode::config::standard())
            .expect("valid benchmark verifier index");
    assert_eq!(consumed, fixture.verifier_index.len());
    let (srs, consumed): (IpaSrs<Vesta>, _) =
        bincode::serde::decode_from_slice(fixture.srs, bincode::config::standard())
            .expect("valid benchmark SRS");
    assert_eq!(consumed, fixture.srs.len());
    verifier_index.srs = Arc::new(srs);
    crate::prepare_verifier_index_metadata(&mut verifier_index).expect("preparable benchmark VK");
    let rng = crate::make_rng(&vk, &raw_proof, &raw_pubs);

    (verifier_index, proof, public_input, rng)
}

fn msm_inputs<T: VerifierConfig>(fixture: Fixture) -> (Vec<Vesta>, Vec<Fp>) {
    let _ = core::marker::PhantomData::<T>;
    let (srs, consumed): (IpaSrs<Vesta>, _) =
        bincode::serde::decode_from_slice(fixture.srs, bincode::config::standard())
            .expect("valid benchmark SRS");
    assert_eq!(consumed, fixture.srs.len());
    let mut points = Vec::with_capacity(srs.g.len() + 1);
    points.push(srs.h);
    points.extend_from_slice(&srs.g);

    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    let scalars = (0..points.len()).map(|_| Fp::rand(&mut rng)).collect();
    (points, scalars)
}

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(where T: pallet_verifiers::Config<Verifier<T>>)]
mod benchmarks {
    use super::*;

    benchmarking_utils!(Verifier<T>, crate::Config);

    #[benchmark]
    fn verify_proof_domain_1024() {
        let (proof, vk, pubs) = benchmark_data::<T>(DOMAIN_1024);

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_2048() {
        let (proof, vk, pubs) = benchmark_data::<T>(DOMAIN_2048);

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_4096() {
        let (proof, vk, pubs) = benchmark_data::<T>(DOMAIN_4096);

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_4096_pubs_64() {
        let (proof, vk, pubs) = benchmark_data::<T>(DOMAIN_4096_PUBS_64);

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_only_domain_1024() {
        let (verifier_index, proof, public_input, mut rng) =
            prepared_accelerated_data::<T>(DOMAIN_1024);

        let r;
        #[block]
        {
            r = crate::verify_native_proof_with_rng(
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_only_domain_2048() {
        let (verifier_index, proof, public_input, mut rng) =
            prepared_accelerated_data::<T>(DOMAIN_2048);

        let r;
        #[block]
        {
            r = crate::verify_native_proof_with_rng(
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_only_domain_4096() {
        let (verifier_index, proof, public_input, mut rng) =
            prepared_accelerated_data::<T>(DOMAIN_4096);

        let r;
        #[block]
        {
            r = crate::verify_native_proof_with_rng(
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_without_opening_domain_1024() {
        let (verifier_index, proof, public_input, mut rng) = prepared_noop_data::<T>(DOMAIN_1024);
        let group_map = crate::vesta_group_map();

        let r;
        #[block]
        {
            r = verify_with_rng::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, NoopOpeningProof, _>(
                &group_map,
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_without_opening_domain_2048() {
        let (verifier_index, proof, public_input, mut rng) = prepared_noop_data::<T>(DOMAIN_2048);
        let group_map = crate::vesta_group_map();

        let r;
        #[block]
        {
            r = verify_with_rng::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, NoopOpeningProof, _>(
                &group_map,
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_without_opening_domain_4096() {
        let (verifier_index, proof, public_input, mut rng) = prepared_noop_data::<T>(DOMAIN_4096);
        let group_map = crate::vesta_group_map();

        let r;
        #[block]
        {
            r = verify_with_rng::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, NoopOpeningProof, _>(
                &group_map,
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_only_prewarmed_domain_1024() {
        let (verifier_index, proof, public_input, mut rng) =
            prepared_accelerated_data::<T>(DOMAIN_1024);
        drop(
            verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain),
        );

        let r;
        #[block]
        {
            r = crate::verify_native_proof_with_rng(
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_only_prewarmed_domain_2048() {
        let (verifier_index, proof, public_input, mut rng) =
            prepared_accelerated_data::<T>(DOMAIN_2048);
        drop(
            verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain),
        );

        let r;
        #[block]
        {
            r = crate::verify_native_proof_with_rng(
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_only_prewarmed_domain_4096() {
        let (verifier_index, proof, public_input, mut rng) =
            prepared_accelerated_data::<T>(DOMAIN_4096);
        drop(
            verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain),
        );

        let r;
        #[block]
        {
            r = crate::verify_native_proof_with_rng(
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_upstream_prewarmed_domain_1024() {
        let (verifier_index, proof, public_input, mut rng) =
            prepared_upstream_data::<T>(DOMAIN_1024);
        drop(
            verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain),
        );
        let group_map = crate::vesta_group_map();

        let r;
        #[block]
        {
            r = verify_with_rng::<
                FULL_ROUNDS,
                Vesta,
                BaseSponge,
                ScalarSponge,
                OpeningProof<Vesta, FULL_ROUNDS>,
                _,
            >(&group_map, &verifier_index, &proof, &public_input, &mut rng)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_upstream_prewarmed_domain_2048() {
        let (verifier_index, proof, public_input, mut rng) =
            prepared_upstream_data::<T>(DOMAIN_2048);
        drop(
            verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain),
        );
        let group_map = crate::vesta_group_map();

        let r;
        #[block]
        {
            r = verify_with_rng::<
                FULL_ROUNDS,
                Vesta,
                BaseSponge,
                ScalarSponge,
                OpeningProof<Vesta, FULL_ROUNDS>,
                _,
            >(&group_map, &verifier_index, &proof, &public_input, &mut rng)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_upstream_prewarmed_domain_4096() {
        let (verifier_index, proof, public_input, mut rng) =
            prepared_upstream_data::<T>(DOMAIN_4096);
        drop(
            verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain),
        );
        let group_map = crate::vesta_group_map();

        let r;
        #[block]
        {
            r = verify_with_rng::<
                FULL_ROUNDS,
                Vesta,
                BaseSponge,
                ScalarSponge,
                OpeningProof<Vesta, FULL_ROUNDS>,
                _,
            >(&group_map, &verifier_index, &proof, &public_input, &mut rng)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_without_opening_prewarmed_domain_1024() {
        let (verifier_index, proof, public_input, mut rng) = prepared_noop_data::<T>(DOMAIN_1024);
        drop(
            verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain),
        );
        let group_map = crate::vesta_group_map();

        let r;
        #[block]
        {
            r = verify_with_rng::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, NoopOpeningProof, _>(
                &group_map,
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_without_opening_prewarmed_domain_2048() {
        let (verifier_index, proof, public_input, mut rng) = prepared_noop_data::<T>(DOMAIN_2048);
        drop(
            verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain),
        );
        let group_map = crate::vesta_group_map();

        let r;
        #[block]
        {
            r = verify_with_rng::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, NoopOpeningProof, _>(
                &group_map,
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_without_opening_prewarmed_domain_4096() {
        let (verifier_index, proof, public_input, mut rng) = prepared_noop_data::<T>(DOMAIN_4096);
        drop(
            verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain),
        );
        let group_map = crate::vesta_group_map();

        let r;
        #[block]
        {
            r = verify_with_rng::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, NoopOpeningProof, _>(
                &group_map,
                &verifier_index,
                &proof,
                &public_input,
                &mut rng,
            )
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn lagrange_basis_domain_1024() {
        let (_, vk, _) = benchmark_data::<T>(DOMAIN_1024);
        let mut verifier_index = crate::decode_vk(&vk).expect("valid benchmark VK");
        crate::prepare_verifier_index(&mut verifier_index, vk.srs_id).expect("preparable VK");

        let basis;
        #[block]
        {
            basis = verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain)
        };
        assert_eq!(basis.len(), 0);
    }

    #[benchmark]
    fn lagrange_basis_domain_2048() {
        let (_, vk, _) = benchmark_data::<T>(DOMAIN_2048);
        let mut verifier_index = crate::decode_vk(&vk).expect("valid benchmark VK");
        crate::prepare_verifier_index(&mut verifier_index, vk.srs_id).expect("preparable VK");

        let basis;
        #[block]
        {
            basis = verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain)
        };
        assert_eq!(basis.len(), 0);
    }

    #[benchmark]
    fn lagrange_basis_domain_4096() {
        let (_, vk, _) = benchmark_data::<T>(DOMAIN_4096);
        let mut verifier_index = crate::decode_vk(&vk).expect("valid benchmark VK");
        crate::prepare_verifier_index(&mut verifier_index, vk.srs_id).expect("preparable VK");

        let basis;
        #[block]
        {
            basis = verifier_index
                .srs()
                .get_lagrange_basis(verifier_index.domain)
        };
        assert_eq!(basis.len(), 0);
    }

    #[benchmark]
    fn decode_proof() {
        let r;
        #[block]
        {
            r = crate::decode_proof(DOMAIN_4096.proof)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn decode_public_inputs_64() {
        let (_, _, pubs) = benchmark_data::<T>(DOMAIN_4096_PUBS_64);

        let r;
        #[block]
        {
            r = crate::decode_public_input(&pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn decode_vk_srs_domain_1024() {
        let (_, vk, _) = benchmark_data::<T>(DOMAIN_1024);

        let r;
        #[block]
        {
            r = crate::decode_vk(&vk)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn decode_vk_srs_domain_2048() {
        let (_, vk, _) = benchmark_data::<T>(DOMAIN_2048);

        let r;
        #[block]
        {
            r = crate::decode_vk(&vk)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn decode_vk_srs_domain_4096() {
        let (_, vk, _) = benchmark_data::<T>(DOMAIN_4096);

        let r;
        #[block]
        {
            r = crate::decode_vk(&vk)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn prepare_verifier_index_domain_1024() {
        let (_, vk, _) = benchmark_data::<T>(DOMAIN_1024);
        let mut verifier_index = crate::decode_vk(&vk).expect("valid benchmark VK");

        let r;
        #[block]
        {
            r = crate::prepare_verifier_index(&mut verifier_index, vk.srs_id)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn prepare_verifier_index_domain_2048() {
        let (_, vk, _) = benchmark_data::<T>(DOMAIN_2048);
        let mut verifier_index = crate::decode_vk(&vk).expect("valid benchmark VK");

        let r;
        #[block]
        {
            r = crate::prepare_verifier_index(&mut verifier_index, vk.srs_id)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn prepare_verifier_index_domain_4096() {
        let (_, vk, _) = benchmark_data::<T>(DOMAIN_4096);
        let mut verifier_index = crate::decode_vk(&vk).expect("valid benchmark VK");

        let r;
        #[block]
        {
            r = crate::prepare_verifier_index(&mut verifier_index, vk.srs_id)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn make_rng_domain_1024() {
        let (proof, vk, pubs) = benchmark_data::<T>(DOMAIN_1024);

        let r;
        #[block]
        {
            r = crate::make_rng(&vk, &proof, &pubs)
        };
        let _ = r;
    }

    #[benchmark]
    fn make_rng_domain_2048() {
        let (proof, vk, pubs) = benchmark_data::<T>(DOMAIN_2048);

        let r;
        #[block]
        {
            r = crate::make_rng(&vk, &proof, &pubs)
        };
        let _ = r;
    }

    #[benchmark]
    fn make_rng_domain_4096() {
        let (proof, vk, pubs) = benchmark_data::<T>(DOMAIN_4096);

        let r;
        #[block]
        {
            r = crate::make_rng(&vk, &proof, &pubs)
        };
        let _ = r;
    }

    #[benchmark]
    fn make_rng_domain_4096_pubs_64() {
        let (proof, vk, pubs) = benchmark_data::<T>(DOMAIN_4096_PUBS_64);

        let r;
        #[block]
        {
            r = crate::make_rng(&vk, &proof, &pubs)
        };
        let _ = r;
    }

    #[benchmark]
    fn wasm_msm_domain_1024() {
        let (points, scalars) = msm_inputs::<T>(DOMAIN_1024);

        let r;
        #[block]
        {
            r = ProjectiveVesta::msm(&points, &scalars)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn wasm_msm_domain_2048() {
        let (points, scalars) = msm_inputs::<T>(DOMAIN_2048);

        let r;
        #[block]
        {
            r = ProjectiveVesta::msm(&points, &scalars)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn wasm_msm_domain_4096() {
        let (points, scalars) = msm_inputs::<T>(DOMAIN_4096);

        let r;
        #[block]
        {
            r = ProjectiveVesta::msm(&points, &scalars)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn native_msm_domain_1024() {
        let (points, scalars) = msm_inputs::<T>(DOMAIN_1024);

        let r;
        #[block]
        {
            r = native::vesta::msm(&points, &scalars)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn native_msm_domain_2048() {
        let (points, scalars) = msm_inputs::<T>(DOMAIN_2048);

        let r;
        #[block]
        {
            r = native::vesta::msm(&points, &scalars)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn native_msm_domain_4096() {
        let (points, scalars) = msm_inputs::<T>(DOMAIN_4096);

        let r;
        #[block]
        {
            r = native::vesta::msm(&points, &scalars)
        };
        assert!(r.is_ok());
    }

    impl_benchmark_test_suite!(Pallet, super::mock::test_ext(), super::mock::Test);
}

#[cfg(test)]
mod mock {
    use frame_support::{
        derive_impl, parameter_types,
        sp_runtime::{traits::IdentityLookup, BuildStorage},
        traits::{fungible::HoldConsideration, LinearStoragePrice},
    };
    use sp_core::{ConstU128, ConstU32};

    type Balance = u128;
    type AccountId = u64;

    frame_support::construct_runtime!(
        pub enum Test
        {
            System: frame_system,
            Balances: pallet_balances,
            CommonVerifiersPallet: pallet_verifiers::common,
            VerifierPallet: crate,
        }
    );

    impl crate::Config for Test {
        type MaxProofSize = ConstU32<262144>;
        type MaxPubs = ConstU32<64>;
        type MaxVkSize = ConstU32<65536>;
        type WeightInfo = ();
    }

    #[derive_impl(frame_system::config_preludes::SolochainDefaultConfig as frame_system::DefaultConfig)]
    impl frame_system::Config for Test {
        type Block = frame_system::mocking::MockBlockU32<Test>;
        type AccountId = AccountId;
        type AccountData = pallet_balances::AccountData<Balance>;
        type Lookup = IdentityLookup<Self::AccountId>;
    }

    parameter_types! {
        pub const BaseDeposit: Balance = 1;
        pub const PerByteDeposit: Balance = 2;
        pub const HoldReasonVkRegistration: RuntimeHoldReason = RuntimeHoldReason::CommonVerifiersPallet(pallet_verifiers::common::HoldReason::VkRegistration);
    }

    impl pallet_verifiers::Config<crate::Kimchi<Test>> for Test {
        type RuntimeEvent = RuntimeEvent;
        type OnProofVerified = ();
        type WeightInfo = crate::KimchiWeight<()>;
        type Ticket = HoldConsideration<
            AccountId,
            Balances,
            HoldReasonVkRegistration,
            LinearStoragePrice<BaseDeposit, PerByteDeposit, Balance>,
        >;
        type Currency = Balances;
    }

    impl pallet_balances::Config for Test {
        type RuntimeEvent = RuntimeEvent;
        type RuntimeHoldReason = RuntimeHoldReason;
        type RuntimeFreezeReason = RuntimeFreezeReason;
        type WeightInfo = ();
        type Balance = Balance;
        type DustRemoval = ();
        type ExistentialDeposit = ConstU128<1>;
        type AccountStore = System;
        type ReserveIdentifier = [u8; 8];
        type FreezeIdentifier = RuntimeFreezeReason;
        type MaxLocks = ConstU32<10>;
        type MaxReserves = ConstU32<10>;
        type MaxFreezes = ConstU32<10>;
        type DoneSlashHandler = ();
    }

    impl pallet_verifiers::common::Config for Test {
        type CommonWeightInfo = Test;
    }

    pub fn test_ext() -> sp_io::TestExternalities {
        let mut ext = sp_io::TestExternalities::from(
            frame_system::GenesisConfig::<Test>::default()
                .build_storage()
                .expect("mock genesis storage should build"),
        );
        ext.execute_with(|| System::set_block_number(1));
        ext
    }
}
