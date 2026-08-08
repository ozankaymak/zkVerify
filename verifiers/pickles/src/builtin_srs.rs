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

//! Verifier-only adapter for the built-in native Pallas15 SRS.

use alloc::{vec, vec::Vec};

use ark_ff::One;
#[cfg(feature = "std")]
use ark_poly::{univariate::DensePolynomial, Evaluations};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use mina_curves::pasta::{Fq, Pallas};
use poly_commitment::{commitment::BlindedCommitment, error::CommitmentError, PolyComm, SRS};
#[cfg(feature = "std")]
use rand_core::{CryptoRng, RngCore};

use crate::PicklesProfileId;

#[derive(Clone, Debug, Default)]
pub struct BuiltinSrs {
    profile: Option<PicklesProfileId>,
    max_poly_size: usize,
    domain_size: usize,
    blinding_commitment: Pallas,
    lagrange_basis_prefix: Vec<PolyComm<Pallas>>,
    empty_lagrange_basis: Vec<PolyComm<Pallas>>,
}

impl BuiltinSrs {
    pub fn load(
        profile: PicklesProfileId,
        max_poly_size: usize,
        domain_size: usize,
        public_inputs: usize,
    ) -> Result<Self, ()> {
        if profile != PicklesProfileId::PicklesV1
            || max_poly_size != 1 << crate::profile::WRAP_SRS_LOG2
            || !domain_size.is_power_of_two()
            || !(13..=15).contains(&domain_size.trailing_zeros())
            || public_inputs != crate::profile::WRAP_PUBLIC_INPUTS
        {
            return Err(());
        }

        let domain_log2 = domain_size
            .is_power_of_two()
            .then(|| domain_size.trailing_zeros())
            .ok_or(())?;
        let count = u32::try_from(public_inputs).map_err(|_| ())?;

        let blinding_commitment = match profile {
            PicklesProfileId::PicklesV1 => native::pallas::pallas15_blinding_commitment(),
        }?;
        let lagrange_chunks = match profile {
            PicklesProfileId::PicklesV1 => {
                native::pallas::pallas15_lagrange_basis_prefix(domain_log2 as u8, count)
            }
        }?;

        if lagrange_chunks.len() != public_inputs {
            return Err(());
        }

        Ok(Self {
            profile: Some(profile),
            max_poly_size,
            domain_size,
            blinding_commitment,
            lagrange_basis_prefix: lagrange_chunks.into_iter().map(PolyComm::new).collect(),
            empty_lagrange_basis: Vec::new(),
        })
    }

    pub const fn profile(&self) -> Option<PicklesProfileId> {
        self.profile
    }

    #[cfg(feature = "std")]
    fn verifier_only<T>() -> T {
        panic!("BuiltinSrs cannot be used for proving")
    }
}

impl SRS<Pallas> for BuiltinSrs {
    fn max_poly_size(&self) -> usize {
        self.max_poly_size
    }

    fn blinding_commitment(&self) -> Pallas {
        self.blinding_commitment
    }

    fn mask_custom(
        &self,
        com: PolyComm<Pallas>,
        blinders: &PolyComm<Fq>,
    ) -> Result<BlindedCommitment<Pallas>, CommitmentError> {
        let commitment = com
            .zip(blinders)
            .ok_or_else(|| CommitmentError::BlindersDontMatch(blinders.len(), com.len()))?
            .map(|(point, blinder)| {
                let point = PolyComm::new(vec![point]);
                let blinding = PolyComm::new(vec![self.blinding_commitment]);
                PolyComm::multi_scalar_mul(&[&point, &blinding], &[Fq::one(), blinder])
                    .get_first_chunk()
            });

        Ok(BlindedCommitment {
            commitment,
            blinders: blinders.clone(),
        })
    }

    #[cfg(feature = "std")]
    fn commit_non_hiding(
        &self,
        _plnm: &DensePolynomial<Fq>,
        _num_chunks: usize,
    ) -> PolyComm<Pallas> {
        Self::verifier_only()
    }

    #[cfg(feature = "std")]
    fn commit(
        &self,
        _plnm: &DensePolynomial<Fq>,
        _num_chunks: usize,
        _rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<Pallas> {
        Self::verifier_only()
    }

    #[cfg(feature = "std")]
    fn commit_custom(
        &self,
        _plnm: &DensePolynomial<Fq>,
        _num_chunks: usize,
        _blinders: &PolyComm<Fq>,
    ) -> Result<BlindedCommitment<Pallas>, CommitmentError> {
        Self::verifier_only()
    }

    #[cfg(feature = "std")]
    fn commit_evaluations_non_hiding(
        &self,
        _domain: D<Fq>,
        _plnm: &Evaluations<Fq, D<Fq>>,
    ) -> PolyComm<Pallas> {
        Self::verifier_only()
    }

    #[cfg(feature = "std")]
    fn commit_evaluations(
        &self,
        _domain: D<Fq>,
        _plnm: &Evaluations<Fq, D<Fq>>,
        _rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<Pallas> {
        Self::verifier_only()
    }

    #[cfg(feature = "std")]
    fn commit_evaluations_custom(
        &self,
        _domain: D<Fq>,
        _plnm: &Evaluations<Fq, D<Fq>>,
        _blinders: &PolyComm<Fq>,
    ) -> Result<BlindedCommitment<Pallas>, CommitmentError> {
        Self::verifier_only()
    }

    #[cfg(feature = "std")]
    fn create(_depth: usize) -> Self {
        Self::verifier_only()
    }

    fn get_lagrange_basis(
        &self,
        domain: D<Fq>,
    ) -> impl core::ops::Deref<Target = Vec<PolyComm<Pallas>>> + '_ {
        self.get_lagrange_basis_from_domain_size(domain.size())
    }

    fn get_lagrange_basis_from_domain_size(
        &self,
        domain_size: usize,
    ) -> impl core::ops::Deref<Target = Vec<PolyComm<Pallas>>> + '_ {
        if domain_size == self.domain_size {
            &self.lagrange_basis_prefix
        } else {
            &self.empty_lagrange_basis
        }
    }

    #[cfg(feature = "std")]
    fn size(&self) -> usize {
        self.max_poly_size
    }
}
