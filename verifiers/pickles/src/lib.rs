// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(feature = "std"), no_std)]
//! Verification of canonicalized o1js Pickles proofs.
//!
//! The public format is defined independently from Mina's S-expression and
//! bin-prot encodings so that runtime consensus is pinned to `PicklesV1`.

extern crate alloc;

/// Canonical proof and verification-key payload types.
pub use pickles_format as format;
mod accumulator;
pub mod benchmarking;
mod builtin_opening;
mod builtin_srs;
mod index;
mod legacy;
mod outer;
mod prepared;
mod profile;
#[cfg(test)]
mod verifier_should;
mod weight;

use alloc::{borrow::Cow, sync::Arc, vec::Vec};
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use core::{fmt, marker::PhantomData};
use frame_support::{ensure, pallet_prelude::TypeInfo, traits::Get, weights::Weight};
use kimchi::{
    error::VerifyError as KimchiVerifyError, groupmap::GroupMap, verifier::verify_with_rng,
};
use mina_curves::pasta::{Fq, Pallas, PallasParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use pallet_verifiers::traits::{Verifier, VerifyError};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub use weight::WeightInfo;

use crate::{
    builtin_srs::BuiltinSrs,
    format::{PicklesProofPayload, PicklesVkPayload},
    index::{make_verifier_index, wrap_domain_log2},
    outer::convert_outer_proof,
};

/// Size of a canonical Pasta field element.
pub const FIELD_SIZE: usize = 32;

/// Encoded proof bytes supplied to the verifier pallet.
pub type Proof = Vec<u8>;

/// Public values proved by an o1js `ZkProgram`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct Pubs {
    /// Flattened o1js public-input fields, in declaration order.
    pub public_input: Vec<[u8; FIELD_SIZE]>,
    /// Flattened o1js public-output fields, in declaration order.
    pub public_output: Vec<[u8; FIELD_SIZE]>,
}

/// Consensus profile for accepted Pickles encodings and parameters.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    MaxEncodedLen,
)]
pub enum PicklesProfileId {
    /// o1js-compatible Pickles proofs, canonical bincode-v2 encoding, widths
    /// zero through two, wrap domains 2^13 through 2^15, and chunks 1..=8.
    PicklesV1,
}

impl PicklesProfileId {
    /// Maximum accepted canonical proof payload size.
    pub const fn max_proof_size(self) -> usize {
        match self {
            Self::PicklesV1 => profile::MAX_PROOF_BYTES,
        }
    }

    /// Maximum combined public input/output field count.
    pub const fn max_public_fields(self) -> usize {
        match self {
            Self::PicklesV1 => profile::MAX_PUBLIC_FIELDS,
        }
    }

    /// Maximum accepted canonical verification-key payload size.
    pub const fn max_vk_size(self) -> usize {
        match self {
            Self::PicklesV1 => profile::MAX_VK_BYTES,
        }
    }

    /// Maximum accepted split-polynomial evaluation chunk count.
    pub const fn max_chunks(self) -> usize {
        match self {
            Self::PicklesV1 => profile::MAX_CHUNKS,
        }
    }
}

/// Stored Pickles verification key.
#[derive(Encode, Decode, DecodeWithMemTracking, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct PicklesVk<T> {
    /// Canonical bincode-v2 [`format::PicklesVkPayload`].
    pub verifier_index_bytes: Vec<u8>,
    /// Consensus parameter profile used to interpret the payload.
    pub profile: PicklesProfileId,
    _marker: PhantomData<T>,
}

impl<T> PicklesVk<T> {
    /// Construct a verification key from a converted payload.
    pub fn new(verifier_index_bytes: Vec<u8>, profile: PicklesProfileId) -> Self {
        Self {
            verifier_index_bytes,
            profile,
            _marker: PhantomData,
        }
    }
}

impl<T> Clone for PicklesVk<T> {
    fn clone(&self) -> Self {
        Self::new(self.verifier_index_bytes.clone(), self.profile)
    }
}

impl<T> fmt::Debug for PicklesVk<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PicklesVk")
            .field("verifier_index_bytes", &self.verifier_index_bytes)
            .field("profile", &self.profile)
            .finish()
    }
}

impl<T> PartialEq for PicklesVk<T> {
    fn eq(&self, other: &Self) -> bool {
        self.verifier_index_bytes == other.verifier_index_bytes && self.profile == other.profile
    }
}

impl<T> Eq for PicklesVk<T> {}

/// Pickles pallet configuration bounds.
pub trait Config: 'static {
    /// Maximum canonical proof byte length.
    type MaxProofSize: frame_support::traits::Get<u32>;
    /// Maximum combined public input and output field count.
    type MaxPubs: frame_support::traits::Get<u32>;
    /// Maximum canonical verification-key payload byte length.
    type MaxVkSize: frame_support::traits::Get<u32>;
    /// Fixed upper-bound weights for Pickles verification and pallet operations.
    type WeightInfo: WeightInfo;
}

/// Adapts generated Pickles weights to the generic verifier pallet.
pub struct PicklesWeight<W: WeightInfo>(PhantomData<W>);

impl<T: Config, W: WeightInfo> pallet_verifiers::WeightInfo<Pickles<T>> for PicklesWeight<W> {
    fn verify_proof(
        _proof: &<Pickles<T> as Verifier>::Proof,
        _pubs: &<Pickles<T> as Verifier>::Pubs,
    ) -> Weight {
        W::verify_proof()
    }

    fn register_vk(_vk: &<Pickles<T> as Verifier>::Vk) -> Weight {
        W::register_vk()
    }

    fn unregister_vk() -> Weight {
        W::unregister_vk()
    }

    fn get_vk() -> Weight {
        W::get_vk()
    }

    fn validate_vk(_vk: &<Pickles<T> as Verifier>::Vk) -> Weight {
        W::validate_vk()
    }

    fn compute_statement_hash(
        _proof: &<Pickles<T> as Verifier>::Proof,
        _pubs: &<Pickles<T> as Verifier>::Pubs,
    ) -> Weight {
        W::compute_statement_hash()
    }
}

impl<T: Config> MaxEncodedLen for PicklesVk<T> {
    fn max_encoded_len() -> usize {
        codec::Compact(T::MaxVkSize::get()).encoded_size()
            + T::MaxVkSize::get() as usize
            + PicklesProfileId::max_encoded_len()
    }
}

/// Public verification-key type used by the pallet.
pub type Vk<T> = PicklesVk<T>;

impl<T: Config> PicklesVk<T> {
    fn validate_size(&self) -> Result<(), VerifyError> {
        ensure!(
            self.profile == PicklesProfileId::PicklesV1
                && !self.verifier_index_bytes.is_empty()
                && self.verifier_index_bytes.len() <= T::MaxVkSize::get() as usize
                && self.verifier_index_bytes.len() <= profile::MAX_VK_BYTES,
            VerifyError::InvalidVerificationKey
        );
        Ok(())
    }
}

/// Pickles verifier pallet implementation.
#[pallet_verifiers::verifier]
pub struct Pickles<T>;

impl<T: Config> Verifier for Pickles<T> {
    type Proof = Proof;
    type Pubs = Pubs;
    type Vk = Vk<T>;

    fn hash_context_data() -> &'static [u8] {
        b"pickles"
    }

    fn verifier_version_hash(_proof: &Self::Proof) -> sp_core::H256 {
        sp_io::hashing::sha2_256(
            b"pickles:v1:o1js:pallas15-vesta16:bincode2-canonical:widths0-2:chunks1-8:chunked-public-evals:pub-io-arity-vk",
        )
        .into()
    }

    fn verify_proof(
        vk: &Self::Vk,
        raw_proof: &Self::Proof,
        pubs: &Self::Pubs,
    ) -> Result<Option<Weight>, VerifyError> {
        vk.validate_size()?;
        ensure!(
            !raw_proof.is_empty()
                && raw_proof.len() <= T::MaxProofSize::get() as usize
                && raw_proof.len() <= profile::MAX_PROOF_BYTES,
            VerifyError::InvalidProofData
        );
        let public_fields = pubs
            .public_input
            .len()
            .checked_add(pubs.public_output.len())
            .ok_or(VerifyError::InvalidInput)?;
        ensure!(
            public_fields <= T::MaxPubs::get() as usize
                && public_fields <= profile::MAX_PUBLIC_FIELDS,
            VerifyError::InvalidInput
        );

        let proof = decode_proof(raw_proof)?;
        let verifier_key = decode_vk(vk)?;
        profile::validate_vk(&verifier_key)
            .inspect_err(|error| log::debug!("Unsupported Pickles verification key: {error:?}"))
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        ensure!(
            u64::from(verifier_key.public_input_size) + u64::from(verifier_key.public_output_size)
                <= u64::from(T::MaxPubs::get()),
            VerifyError::InvalidVerificationKey
        );
        ensure!(
            pubs.public_input.len()
                == usize::try_from(verifier_key.public_input_size)
                    .map_err(|_| VerifyError::InvalidVerificationKey)?
                && pubs.public_output.len()
                    == usize::try_from(verifier_key.public_output_size)
                        .map_err(|_| VerifyError::InvalidVerificationKey)?,
            VerifyError::InvalidInput
        );
        profile::validate_proof(&proof, &verifier_key)
            .inspect_err(|error| log::debug!("Unsupported Pickles proof: {error:?}"))
            .map_err(|_| VerifyError::InvalidProofData)?;

        ensure!(
            accumulator::verify(&proof)
                .inspect_err(|error| log::debug!("Pickles accumulator check failed: {error:?}"))
                .map_err(|_| VerifyError::InvalidProofData)?,
            VerifyError::VerifyError
        );

        let public_input = prepared::public_input(&proof, &verifier_key, pubs)
            .inspect_err(|error| log::debug!("Cannot prepare Pickles statement: {error:?}"))
            .map_err(|error| match error {
                prepared::PreparedError::PublicInput => VerifyError::InvalidInput,
                _ => VerifyError::InvalidProofData,
            })?;
        let outer_proof = convert_outer_proof(&proof)
            .inspect_err(|error| log::debug!("Cannot convert Pickles outer proof: {error:?}"))
            .map_err(|_| VerifyError::InvalidProofData)?;
        let domain_size = 1usize << wrap_domain_log2(verifier_key.actual_wrap_domain_size);
        let srs = Arc::new(
            BuiltinSrs::load(
                vk.profile,
                1 << profile::WRAP_SRS_LOG2,
                domain_size,
                profile::WRAP_PUBLIC_INPUTS,
            )
            .map_err(|_| VerifyError::InvalidVerificationKey)?,
        );
        let verifier_index = make_verifier_index(&verifier_key, srs)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let mut rng = make_rng(vk, raw_proof, pubs);
        verify_with_rng::<
            FULL_ROUNDS,
            Pallas,
            DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
            DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
            builtin_opening::BuiltinOpeningProof,
            _,
        >(
            &GroupMap::setup(),
            &verifier_index,
            &outer_proof,
            &public_input,
            &mut rng,
        )
        .inspect_err(|error| log::debug!("Pickles outer verification failed: {error:?}"))
        .map_err(map_kimchi_error)?;

        Ok(None)
    }

    fn validate_vk(vk: &Self::Vk) -> Result<(), VerifyError> {
        vk.validate_size()?;
        let verifier_key = decode_vk(vk)?;
        profile::validate_vk(&verifier_key).map_err(|_| VerifyError::InvalidVerificationKey)?;
        ensure!(
            u64::from(verifier_key.public_input_size) + u64::from(verifier_key.public_output_size)
                <= u64::from(T::MaxPubs::get()),
            VerifyError::InvalidVerificationKey
        );
        let domain_size = 1usize << wrap_domain_log2(verifier_key.actual_wrap_domain_size);
        let srs = Arc::new(
            BuiltinSrs::load(
                vk.profile,
                1 << profile::WRAP_SRS_LOG2,
                domain_size,
                profile::WRAP_PUBLIC_INPUTS,
            )
            .map_err(|_| VerifyError::InvalidVerificationKey)?,
        );
        make_verifier_index(&verifier_key, srs)
            .map(|_| ())
            .map_err(|_| VerifyError::InvalidVerificationKey)
    }

    fn pubs_bytes(pubs: &Self::Pubs) -> Cow<'_, [u8]> {
        Cow::Owned(pubs.encode())
    }
}

fn decode_canonical<T, C>(
    bytes: &[u8],
    config: C,
    make_error: fn() -> VerifyError,
) -> Result<T, VerifyError>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    C: bincode::config::Config,
{
    let (value, consumed) =
        bincode::serde::decode_from_slice(bytes, config).map_err(|_| make_error())?;
    ensure!(consumed == bytes.len(), make_error());
    ensure!(
        bincode::serde::encode_to_vec(&value, bincode::config::standard())
            .is_ok_and(|encoded| encoded == bytes),
        make_error()
    );
    Ok(value)
}

fn decode_proof(bytes: &[u8]) -> Result<PicklesProofPayload, VerifyError> {
    decode_canonical(
        bytes,
        bincode::config::standard().with_limit::<{ profile::MAX_PROOF_BYTES }>(),
        || VerifyError::InvalidProofData,
    )
}

fn decode_vk<T: Config>(vk: &Vk<T>) -> Result<PicklesVkPayload, VerifyError> {
    decode_canonical(
        &vk.verifier_index_bytes,
        bincode::config::standard().with_limit::<{ profile::MAX_VK_BYTES }>(),
        || VerifyError::InvalidVerificationKey,
    )
}

fn make_rng<T: Config>(vk: &Vk<T>, proof: &Proof, pubs: &Pubs) -> ChaCha20Rng {
    let seed = sp_io::hashing::blake2_256(
        &(b"pickles:v1:pallas15-vesta16:verify-rng", vk, proof, pubs).encode(),
    );
    ChaCha20Rng::from_seed(seed)
}

fn map_kimchi_error(error: KimchiVerifyError) -> VerifyError {
    match error {
        KimchiVerifyError::IncorrectPubicInputLength(_) => VerifyError::InvalidInput,
        KimchiVerifyError::DifferentSRS | KimchiVerifyError::SRSTooSmall => {
            VerifyError::InvalidVerificationKey
        }
        KimchiVerifyError::OpenProof => VerifyError::VerifyError,
        _ => VerifyError::InvalidProofData,
    }
}
