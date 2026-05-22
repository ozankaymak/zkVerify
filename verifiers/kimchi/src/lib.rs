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

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod benchmarking;
pub mod benchmarking_verify_proof;
mod verifier_should;
mod vk;
mod weight;
mod weight_verify_proof;

use alloc::{borrow::Cow, vec::Vec};
use core::marker::PhantomData;

use codec::Encode;
use frame_support::{ensure, traits::Get, weights::Weight};
use native::kimchi_verify;
use pallet_verifiers::traits::{Verifier, VerifyError};

pub use crate::vk::KimchiVk as Vk;
pub use crate::weight::WeightInfo;
pub use crate::weight_verify_proof::WeightInfo as WeightInfoVerifyProof;

pub const PUB_SIZE: usize = 32;

pub type Proof = Vec<u8>;
pub type Pubs = Vec<[u8; PUB_SIZE]>;

pub trait Config: 'static {
    /// Maximum number of bytes contained in the proof.
    type MaxProofSize: frame_support::traits::Get<u32>;
    /// Maximum number of public inputs.
    type MaxPubs: frame_support::traits::Get<u32>;
    /// Maximum number of bytes contained in the verifier index payload.
    type MaxVkSize: frame_support::traits::Get<u32>;
    /// Maximum number of bytes contained in the serialized SRS payload.
    type MaxSrsSize: frame_support::traits::Get<u32>;
    /// Parameterized weights for Kimchi proof verification.
    type WeightInfo: WeightInfoVerifyProof;

    fn max_proof_size() -> u32 {
        Self::MaxProofSize::get()
    }

    fn max_pubs() -> u32 {
        Self::MaxPubs::get()
    }

    fn max_vk_size() -> u32 {
        Self::MaxVkSize::get()
    }

    fn max_srs_size() -> u32 {
        Self::MaxSrsSize::get()
    }
}

impl<T: Config> Vk<T> {
    pub fn validate_size(&self) -> Result<(), VerifyError> {
        if self.verifier_index_bytes.is_empty()
            || self.verifier_index_bytes.len() > T::max_vk_size() as usize
        {
            return Err(VerifyError::InvalidVerificationKey);
        }

        if self.srs_bytes.is_empty() || self.srs_bytes.len() > T::max_srs_size() as usize {
            return Err(VerifyError::InvalidVerificationKey);
        }

        Ok(())
    }
}

#[pallet_verifiers::verifier]
pub struct Kimchi<T>;

impl<T: Config> Verifier for Kimchi<T> {
    type Proof = Proof;
    type Pubs = Pubs;
    type Vk = Vk<T>;

    fn hash_context_data() -> &'static [u8] {
        b"kimchi"
    }

    fn verify_proof(
        vk: &Self::Vk,
        raw_proof: &Self::Proof,
        raw_pubs: &Self::Pubs,
    ) -> Result<Option<Weight>, VerifyError> {
        vk.validate_size()?;
        ensure!(
            raw_proof.len() <= T::max_proof_size() as usize,
            VerifyError::InvalidProofData
        );
        ensure!(
            raw_pubs.len() <= T::max_pubs() as usize,
            VerifyError::InvalidInput
        );

        let rng_seed = make_rng_seed(vk, raw_proof, raw_pubs);
        let pubs_bytes: Vec<u8> = raw_pubs.iter().flat_map(|f| f.iter().copied()).collect();

        kimchi_verify::verify_proof(
            &vk.verifier_index_bytes,
            &vk.srs_bytes,
            raw_proof,
            &pubs_bytes,
            &rng_seed,
        )
        .map_err(VerifyError::from)?;

        Ok(Some(T::WeightInfo::verify_proof_domain_4096()))
    }

    fn validate_vk(vk: &Self::Vk) -> Result<(), VerifyError> {
        vk.validate_size()?;
        kimchi_verify::validate_key(&vk.verifier_index_bytes, &vk.srs_bytes)
            .map_err(VerifyError::from)
    }

    fn pubs_bytes(pubs: &Self::Pubs) -> Cow<'_, [u8]> {
        let data = pubs
            .iter()
            .flat_map(|field| field.iter().copied())
            .collect::<Vec<_>>();

        Cow::Owned(data)
    }
}

pub struct KimchiWeight<W: WeightInfo>(PhantomData<W>);

impl<T: Config, W: WeightInfo> pallet_verifiers::WeightInfo<Kimchi<T>> for KimchiWeight<W> {
    fn verify_proof(
        _proof: &<Kimchi<T> as Verifier>::Proof,
        _pubs: &<Kimchi<T> as Verifier>::Pubs,
    ) -> Weight {
        W::verify_proof()
    }

    fn register_vk(_vk: &<Kimchi<T> as Verifier>::Vk) -> Weight {
        W::register_vk()
    }

    fn unregister_vk() -> Weight {
        W::unregister_vk()
    }

    fn get_vk() -> Weight {
        W::get_vk()
    }

    fn validate_vk(_vk: &<Kimchi<T> as Verifier>::Vk) -> Weight {
        W::validate_vk()
    }

    fn compute_statement_hash(
        _proof: &<Kimchi<T> as Verifier>::Proof,
        _pubs: &<Kimchi<T> as Verifier>::Pubs,
    ) -> Weight {
        W::compute_statement_hash()
    }
}

/// Compute a deterministic RNG seed from the statement material so that
/// Kimchi's batch-combination scalars are fully determined by the inputs.
fn make_rng_seed<T: Config>(vk: &Vk<T>, proof: &Proof, pubs: &Pubs) -> [u8; 32] {
    sp_io::hashing::blake2_256(&(vk, proof, pubs).encode())
}
