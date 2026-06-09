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

//! Minimal SRS adapter for Kimchi verification with built-in native parameters.

use alloc::{rc::Rc, vec, vec::Vec};
use core::ops::{AddAssign, Mul};

use ark_ec::CurveGroup;
use ark_poly::Radix2EvaluationDomain;
#[cfg(feature = "std")]
use ark_poly::{univariate::DensePolynomial, Evaluations};
use mina_curves::pasta::{Fp, Vesta};
use poly_commitment::{
    commitment::{BlindedCommitment, PolyComm},
    error::CommitmentError,
    SRS,
};
#[cfg(feature = "std")]
use rand_core::{CryptoRng, RngCore};

use crate::vk::KimchiSrsId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinSrs {
    id: KimchiSrsId,
    max_poly_size: usize,
    public_inputs: usize,
}

impl Default for BuiltinSrs {
    fn default() -> Self {
        Self {
            id: KimchiSrsId::Vesta16,
            max_poly_size: 0,
            public_inputs: 0,
        }
    }
}

impl BuiltinSrs {
    pub(crate) fn new(id: KimchiSrsId, max_poly_size: usize, public_inputs: usize) -> Self {
        Self {
            id,
            max_poly_size,
            public_inputs,
        }
    }

    pub(crate) fn validate_native_access(self, domain_size: usize) -> Result<(), ()> {
        let _ = self.blinding_commitment_result()?;
        if self.public_inputs > 0 {
            let points = self.lagrange_basis_points(domain_size)?;
            if points.len() != self.public_inputs {
                return Err(());
            }
        }

        Ok(())
    }

    fn blinding_commitment_result(self) -> Result<Vesta, ()> {
        match self.id {
            KimchiSrsId::Vesta16 => native::vesta::vesta16_blinding_commitment(),
        }
    }

    fn lagrange_basis_points(self, domain_size: usize) -> Result<Vec<Vesta>, ()> {
        let domain_log2 = domain_size
            .is_power_of_two()
            .then(|| domain_size.trailing_zeros())
            .ok_or(())?;

        match self.id {
            KimchiSrsId::Vesta16 => native::vesta::vesta16_lagrange_basis_prefix(
                domain_log2 as u8,
                self.public_inputs as u32,
            ),
        }
    }

    fn lagrange_basis_prefix(self, domain_size: usize) -> Rc<Vec<PolyComm<Vesta>>> {
        if self.public_inputs == 0 {
            return Rc::new(Vec::new());
        }

        let points = self
            .lagrange_basis_points(domain_size)
            .expect("built-in Kimchi SRS was validated during verifier-index preparation");

        Rc::new(
            points
                .into_iter()
                .map(|point| PolyComm::new(vec![point]))
                .collect(),
        )
    }
}

impl SRS<Vesta> for BuiltinSrs {
    fn max_poly_size(&self) -> usize {
        self.max_poly_size
    }

    fn blinding_commitment(&self) -> Vesta {
        self.blinding_commitment_result()
            .expect("built-in Kimchi SRS was validated during verifier-index preparation")
    }

    fn mask_custom(
        &self,
        com: PolyComm<Vesta>,
        blinders: &PolyComm<Fp>,
    ) -> Result<BlindedCommitment<Vesta>, CommitmentError> {
        let h = self.blinding_commitment();
        let commitment = com
            .zip(blinders)
            .ok_or_else(|| CommitmentError::BlindersDontMatch(blinders.len(), com.len()))?
            .map(|(g, b)| {
                let mut g_masked = h.mul(b);
                g_masked.add_assign(&g);
                g_masked.into_affine()
            });

        Ok(BlindedCommitment {
            commitment,
            blinders: blinders.clone(),
        })
    }

    #[cfg(feature = "std")]
    fn commit_non_hiding(
        &self,
        _plnm: &DensePolynomial<Fp>,
        _num_chunks: usize,
    ) -> PolyComm<Vesta> {
        unreachable!("built-in Kimchi SRS is verifier-only")
    }

    #[cfg(feature = "std")]
    fn commit(
        &self,
        _plnm: &DensePolynomial<Fp>,
        _num_chunks: usize,
        _rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<Vesta> {
        unreachable!("built-in Kimchi SRS is verifier-only")
    }

    #[cfg(feature = "std")]
    fn commit_custom(
        &self,
        _plnm: &DensePolynomial<Fp>,
        _num_chunks: usize,
        _blinders: &PolyComm<Fp>,
    ) -> Result<BlindedCommitment<Vesta>, CommitmentError> {
        unreachable!("built-in Kimchi SRS is verifier-only")
    }

    #[cfg(feature = "std")]
    fn commit_evaluations_non_hiding(
        &self,
        _domain: Radix2EvaluationDomain<Fp>,
        _plnm: &Evaluations<Fp, Radix2EvaluationDomain<Fp>>,
    ) -> PolyComm<Vesta> {
        unreachable!("built-in Kimchi SRS is verifier-only")
    }

    #[cfg(feature = "std")]
    fn commit_evaluations(
        &self,
        _domain: Radix2EvaluationDomain<Fp>,
        _plnm: &Evaluations<Fp, Radix2EvaluationDomain<Fp>>,
        _rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<Vesta> {
        unreachable!("built-in Kimchi SRS is verifier-only")
    }

    #[cfg(feature = "std")]
    fn commit_evaluations_custom(
        &self,
        _domain: Radix2EvaluationDomain<Fp>,
        _plnm: &Evaluations<Fp, Radix2EvaluationDomain<Fp>>,
        _blinders: &PolyComm<Fp>,
    ) -> Result<BlindedCommitment<Vesta>, CommitmentError> {
        unreachable!("built-in Kimchi SRS is verifier-only")
    }

    #[cfg(feature = "std")]
    fn create(depth: usize) -> Self {
        Self::new(KimchiSrsId::Vesta16, depth, 0)
    }

    fn get_lagrange_basis(
        &self,
        domain: Radix2EvaluationDomain<Fp>,
    ) -> impl core::ops::Deref<Target = Vec<PolyComm<Vesta>>> + '_ {
        self.lagrange_basis_prefix(usize::try_from(domain.size).unwrap_or(usize::MAX))
    }

    fn get_lagrange_basis_from_domain_size(
        &self,
        domain_size: usize,
    ) -> impl core::ops::Deref<Target = Vec<PolyComm<Vesta>>> + '_ {
        self.lagrange_basis_prefix(domain_size)
    }

    #[cfg(feature = "std")]
    fn size(&self) -> usize {
        self.max_poly_size
    }
}
