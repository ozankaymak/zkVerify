// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fixed Pallas15 verifier parameters used by the PicklesV1 outer proof.

extern crate alloc;

#[cfg(feature = "std")]
use crate::VerifyError;
use alloc::vec::Vec;
use mina_curves::pasta::{Fq, Pallas, ProjectivePallas};
use sp_runtime_interface::pass_by::{AllocateAndReturnByCodec, PassFatPointerAndRead};
use sp_runtime_interface::runtime_interface;
#[cfg(feature = "std")]
use std::path::Path;

use crate::arkworks_utils as utils;

/// Base-two logarithm of the Pickles outer SRS size.
pub const PALLAS15_SRS_LOG2_SIZE: u8 = 15;
/// Number of bases in the Pickles outer SRS.
pub const PALLAS15_SRS_SIZE: usize = 1 << PALLAS15_SRS_LOG2_SIZE;
/// Smallest supported Pickles outer domain.
pub const PALLAS15_MIN_DOMAIN_LOG2_SIZE: u8 = 13;
/// Largest supported Pickles outer domain.
pub const PALLAS15_MAX_DOMAIN_LOG2_SIZE: u8 = 15;
/// Number of outer public-input Lagrange commitments used by PicklesV1.
pub const PALLAS15_LAGRANGE_PREFIX_SIZE: usize = 40;

/// Result of preparing all PicklesV1 Pallas verifier parameters.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pallas15PrewarmStatus {
    /// The authenticated Lagrange prefixes were loaded from the local cache.
    Loaded,
    /// The prefixes were generated and persisted to the local cache.
    Generated,
    /// The prefixes were generated, but the local cache could not be persisted.
    GeneratedWithoutCache,
}

/// Authenticate and initialize all fixed PicklesV1 Pallas verifier parameters.
#[cfg(feature = "std")]
pub fn prewarm_pallas15_srs(cache_root: &Path) -> Result<Pallas15PrewarmStatus, VerifyError> {
    native_builtin_srs::prewarm(cache_root)
}

/// Returns the fixed Pallas15 blinding commitment.
#[allow(clippy::result_unit_err)]
pub fn pallas15_blinding_commitment() -> Result<Pallas, ()> {
    let result = host_calls::pallas15_blinding_commitment()?;
    utils::decode(&result)
}

/// Returns the requested prefix of Pallas15 Lagrange-basis commitments.
#[allow(clippy::result_unit_err)]
pub fn pallas15_lagrange_basis_prefix(domain_log2: u8, count: u32) -> Result<Vec<Vec<Pallas>>, ()> {
    let result = host_calls::pallas15_lagrange_basis_prefix(domain_log2, count)?;
    utils::decode(&result)
}

/// Computes an MSM whose leading bases are `[h, g[0], ..., g[2^15-1]]`.
#[allow(clippy::result_unit_err)]
pub fn pallas15_srs_msm(
    h_scalar: Fq,
    g_scalars: &[Fq],
    extra_bases: &[Pallas],
    extra_scalars: &[Fq],
) -> Result<ProjectivePallas, ()> {
    if g_scalars.len() != PALLAS15_SRS_SIZE || extra_bases.len() != extra_scalars.len() {
        return Err(());
    }
    let result = host_calls::pallas15_srs_msm(
        &utils::encode(h_scalar),
        &utils::encode(g_scalars),
        &utils::encode(extra_bases),
        &utils::encode(extra_scalars),
    )?;
    utils::decode_proj_sw(&result)
}

/// Native interfaces for the fixed Pickles Pallas15 verifier parameters.
#[runtime_interface]
pub trait HostCalls {
    /// Fixed Pallas15 SRS blinding commitment.
    #[allow(clippy::result_unit_err)]
    fn pallas15_blinding_commitment() -> AllocateAndReturnByCodec<Result<Vec<u8>, ()>> {
        native_builtin_srs::blinding_commitment()
    }

    /// Fixed Pallas15 Lagrange-basis commitment prefix.
    #[allow(clippy::result_unit_err)]
    fn pallas15_lagrange_basis_prefix(
        domain_log2: u8,
        count: u32,
    ) -> AllocateAndReturnByCodec<Result<Vec<u8>, ()>> {
        native_builtin_srs::lagrange_basis_prefix(domain_log2, count)
    }

    /// Fixed Pallas15 SRS-backed variable-base MSM.
    #[allow(clippy::result_unit_err)]
    fn pallas15_srs_msm(
        h_scalar: PassFatPointerAndRead<&[u8]>,
        g_scalars: PassFatPointerAndRead<&[u8]>,
        extra_bases: PassFatPointerAndRead<&[u8]>,
        extra_scalars: PassFatPointerAndRead<&[u8]>,
    ) -> AllocateAndReturnByCodec<Result<Vec<u8>, ()>> {
        native_builtin_srs::srs_msm(h_scalar, g_scalars, extra_bases, extra_scalars)
    }
}

#[cfg(feature = "std")]
mod native_builtin_srs {
    use alloc::vec;
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, BufReader, BufWriter, Read, Write},
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };

    use ark_ec::VariableBaseMSM;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
    use ark_scale::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use blake2::{digest::consts::U32, Blake2b, Digest};
    use poly_commitment::{ipa::SRS as IpaSrs, SRS as _};

    use super::*;

    type Blake2b256 = Blake2b<U32>;
    type LagrangePrefix = Vec<poly_commitment::PolyComm<Pallas>>;
    type LagrangePrefixes = Vec<(u8, LagrangePrefix)>;

    const CACHE_FILE_NAME: &str = "pickles-pallas15-v1.cache";
    const CACHE_MAGIC: &[u8; 16] = b"ZKVPICKLESPAL1\0\0";
    const CACHE_FORMAT_VERSION: u32 = 1;
    const PALLAS_UNCOMPRESSED_POINT_SIZE: usize = 65;
    pub(super) const PALLAS_SRS_15_DIGEST: [u8; 32] = [
        40, 71, 114, 46, 182, 149, 143, 205, 227, 185, 62, 115, 45, 191, 184, 247, 139, 111, 39,
        138, 113, 42, 58, 209, 128, 79, 55, 186, 190, 138, 56, 122,
    ];
    pub(super) const PALLAS_SRS_15_LAGRANGE_PREFIX_DIGESTS: &[(u8, [u8; 32])] = &[
        (
            13,
            [
                220, 218, 25, 204, 30, 126, 1, 100, 112, 2, 127, 108, 211, 111, 66, 228, 195, 242,
                183, 37, 29, 84, 45, 92, 7, 100, 120, 173, 245, 195, 110, 188,
            ],
        ),
        (
            14,
            [
                31, 133, 126, 192, 171, 251, 115, 64, 9, 214, 139, 148, 68, 33, 252, 57, 196, 115,
                246, 220, 158, 55, 70, 118, 187, 119, 173, 2, 143, 80, 52, 176,
            ],
        ),
        (
            15,
            [
                175, 211, 199, 78, 101, 48, 45, 89, 248, 100, 9, 1, 16, 150, 119, 133, 240, 211,
                10, 7, 243, 69, 65, 220, 104, 13, 129, 107, 166, 202, 136, 193,
            ],
        ),
    ];

    static PALLAS15_SRS: OnceLock<IpaSrs<Pallas>> = OnceLock::new();
    static PALLAS15_PARAMETER_CHECK: OnceLock<bool> = OnceLock::new();
    static PALLAS15_LAGRANGE_PREFIXES: OnceLock<LagrangePrefixes> = OnceLock::new();
    static PALLAS15_PREWARM_LOCK: Mutex<()> = Mutex::new(());

    fn srs() -> &'static IpaSrs<Pallas> {
        PALLAS15_SRS.get_or_init(|| IpaSrs::create(PALLAS15_SRS_SIZE))
    }

    fn checked_srs() -> Result<&'static IpaSrs<Pallas>, VerifyError> {
        let srs = srs();
        let matches = PALLAS15_PARAMETER_CHECK
            .get_or_init(|| srs_digest(srs).is_ok_and(|digest| digest == PALLAS_SRS_15_DIGEST));
        (*matches)
            .then_some(srs)
            .ok_or(VerifyError::IncompatibleParameters)
    }

    fn checked_lagrange_basis_prefix(domain_log2: u8) -> Result<LagrangePrefix, VerifyError> {
        checked_lagrange_prefixes()?
            .iter()
            .find_map(|(log2, prefix)| (*log2 == domain_log2).then_some(prefix.clone()))
            .ok_or(VerifyError::InvalidVerificationKey)
    }

    pub(super) fn blinding_commitment() -> Result<Vec<u8>, ()> {
        Ok(utils::encode(checked_srs().map_err(|_| ())?.h))
    }

    pub(super) fn lagrange_basis_prefix(domain_log2: u8, count: u32) -> Result<Vec<u8>, ()> {
        if !(PALLAS15_MIN_DOMAIN_LOG2_SIZE..=PALLAS15_MAX_DOMAIN_LOG2_SIZE).contains(&domain_log2) {
            return Err(());
        }
        let domain_size = 1usize.checked_shl(u32::from(domain_log2)).ok_or(())?;
        let count = usize::try_from(count).map_err(|_| ())?;
        if count > PALLAS15_LAGRANGE_PREFIX_SIZE || count > domain_size {
            return Err(());
        }
        let basis = checked_lagrange_basis_prefix(domain_log2).map_err(|_| ())?;
        let prefix = basis
            .iter()
            .take(count)
            .map(|commitment| commitment.chunks.clone())
            .collect::<Vec<_>>();
        (prefix.len() == count)
            .then(|| utils::encode(prefix))
            .ok_or(())
    }

    pub(super) fn srs_msm(
        h_scalar: &[u8],
        g_scalars: &[u8],
        extra_bases: &[u8],
        extra_scalars: &[u8],
    ) -> Result<Vec<u8>, ()> {
        let h_scalar: Fq = utils::decode(h_scalar)?;
        let g_scalars: Vec<Fq> = utils::decode(g_scalars)?;
        let extra_bases: Vec<Pallas> = utils::decode(extra_bases)?;
        let extra_scalars: Vec<Fq> = utils::decode(extra_scalars)?;
        if g_scalars.len() != PALLAS15_SRS_SIZE || extra_bases.len() != extra_scalars.len() {
            return Err(());
        }

        let parameters = checked_srs().map_err(|_| ())?;
        let mut bases = Vec::with_capacity(PALLAS15_SRS_SIZE + 1 + extra_bases.len());
        bases.push(parameters.h);
        bases.extend_from_slice(&parameters.g);
        bases.extend(extra_bases);
        let mut scalars = Vec::with_capacity(bases.len());
        scalars.push(h_scalar);
        scalars.extend(g_scalars);
        scalars.extend(extra_scalars);
        let result = ProjectivePallas::msm(&bases, &scalars).map_err(|_| ())?;
        Ok(utils::encode_proj_sw(&result))
    }

    pub(super) fn prewarm(cache_root: &Path) -> Result<Pallas15PrewarmStatus, VerifyError> {
        let _guard = PALLAS15_PREWARM_LOCK
            .lock()
            .map_err(|_| VerifyError::IncompatibleParameters)?;
        checked_srs()?;
        if PALLAS15_LAGRANGE_PREFIXES.get().is_some() {
            return Ok(Pallas15PrewarmStatus::Loaded);
        }

        let cache_path = cache_root.join(CACHE_FILE_NAME);
        match load_cache(&cache_path) {
            Ok(prefixes) => {
                install_prefixes(prefixes)?;
                return Ok(Pallas15PrewarmStatus::Loaded);
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                log::warn!(
                    "Ignoring invalid Pickles Pallas15 parameter cache at {}: {error}",
                    cache_path.display()
                );
            }
            Err(_) => {}
        }

        let prefixes = generate_lagrange_prefixes()?;
        install_prefixes(prefixes)?;
        match persist_cache(&cache_path) {
            Ok(()) => Ok(Pallas15PrewarmStatus::Generated),
            Err(error) => {
                log::warn!(
                    "Could not persist Pickles Pallas15 parameter cache at {}: {error}",
                    cache_path.display()
                );
                Ok(Pallas15PrewarmStatus::GeneratedWithoutCache)
            }
        }
    }

    fn checked_lagrange_prefixes() -> Result<&'static LagrangePrefixes, VerifyError> {
        if let Some(prefixes) = PALLAS15_LAGRANGE_PREFIXES.get() {
            return Ok(prefixes);
        }
        install_prefixes(generate_lagrange_prefixes()?)?;
        PALLAS15_LAGRANGE_PREFIXES
            .get()
            .ok_or(VerifyError::IncompatibleParameters)
    }

    fn generate_lagrange_prefixes() -> Result<LagrangePrefixes, VerifyError> {
        let srs = checked_srs()?;
        let mut prefixes = Vec::with_capacity(3);
        for domain_log2 in PALLAS15_MIN_DOMAIN_LOG2_SIZE..=PALLAS15_MAX_DOMAIN_LOG2_SIZE {
            let domain_size = 1usize << domain_log2;
            let domain = D::<Fq>::new(domain_size).ok_or(VerifyError::InvalidVerificationKey)?;
            let basis = srs.get_lagrange_basis(domain);
            let prefix = basis
                .iter()
                .take(PALLAS15_LAGRANGE_PREFIX_SIZE)
                .cloned()
                .collect::<Vec<_>>();
            validate_prefix(domain_log2, &prefix)?;
            prefixes.push((domain_log2, prefix));
        }
        Ok(prefixes)
    }

    fn install_prefixes(prefixes: LagrangePrefixes) -> Result<(), VerifyError> {
        validate_prefixes(&prefixes)?;
        let _ = PALLAS15_LAGRANGE_PREFIXES.set(prefixes);
        validate_prefixes(
            PALLAS15_LAGRANGE_PREFIXES
                .get()
                .ok_or(VerifyError::IncompatibleParameters)?,
        )
    }

    fn validate_prefixes(prefixes: &LagrangePrefixes) -> Result<(), VerifyError> {
        if prefixes.len() != 3 {
            return Err(VerifyError::IncompatibleParameters);
        }
        for domain_log2 in PALLAS15_MIN_DOMAIN_LOG2_SIZE..=PALLAS15_MAX_DOMAIN_LOG2_SIZE {
            let prefix = prefixes
                .iter()
                .find_map(|(log2, prefix)| (*log2 == domain_log2).then_some(prefix))
                .ok_or(VerifyError::IncompatibleParameters)?;
            validate_prefix(domain_log2, prefix)?;
        }
        Ok(())
    }

    fn validate_prefix(
        domain_log2: u8,
        prefix: &[poly_commitment::PolyComm<Pallas>],
    ) -> Result<(), VerifyError> {
        if prefix.len() != PALLAS15_LAGRANGE_PREFIX_SIZE
            || prefix.iter().any(|commitment| commitment.chunks.len() != 1)
            || !expected_lagrange_digest(domain_log2).is_some_and(|expected| {
                lagrange_prefix_digest(domain_log2, prefix).is_ok_and(|digest| &digest == expected)
            })
        {
            return Err(VerifyError::IncompatibleParameters);
        }
        Ok(())
    }

    fn expected_lagrange_digest(domain_log2: u8) -> Option<&'static [u8; 32]> {
        PALLAS_SRS_15_LAGRANGE_PREFIX_DIGESTS
            .iter()
            .find_map(|(log2, digest)| (*log2 == domain_log2).then_some(digest))
    }

    fn srs_digest(srs: &IpaSrs<Pallas>) -> Result<[u8; 32], VerifyError> {
        let mut hasher = Blake2b256::new();
        hasher.update(b"pickles:v1:pallas15:srs");
        hash_usize(&mut hasher, srs.g.len());
        for point in &srs.g {
            hash_point(&mut hasher, point)?;
        }
        hash_point(&mut hasher, &srs.h)?;
        Ok(hasher.finalize().into())
    }

    fn lagrange_prefix_digest(
        domain_log2: u8,
        basis: &[poly_commitment::PolyComm<Pallas>],
    ) -> Result<[u8; 32], VerifyError> {
        if basis.len() < PALLAS15_LAGRANGE_PREFIX_SIZE {
            return Err(VerifyError::IncompatibleParameters);
        }
        let mut hasher = Blake2b256::new();
        hasher.update(b"pickles:v1:pallas15:lagrange-prefix");
        hasher.update([domain_log2]);
        hash_usize(&mut hasher, PALLAS15_LAGRANGE_PREFIX_SIZE);
        for commitment in basis.iter().take(PALLAS15_LAGRANGE_PREFIX_SIZE) {
            hash_usize(&mut hasher, commitment.chunks.len());
            for point in &commitment.chunks {
                hash_point(&mut hasher, point)?;
            }
        }
        Ok(hasher.finalize().into())
    }

    fn hash_usize(hasher: &mut Blake2b256, value: usize) {
        hasher.update((value as u64).to_le_bytes());
    }

    fn hash_point(hasher: &mut Blake2b256, point: &Pallas) -> Result<(), VerifyError> {
        let mut bytes = [0_u8; PALLAS_UNCOMPRESSED_POINT_SIZE];
        if point.uncompressed_size() != bytes.len() {
            return Err(VerifyError::IncompatibleParameters);
        }
        point
            .serialize_uncompressed(bytes.as_mut_slice())
            .map_err(|_| VerifyError::IncompatibleParameters)?;
        hasher.update(bytes);
        Ok(())
    }

    fn persist_cache(cache_path: &Path) -> io::Result<()> {
        let parent = cache_path
            .parent()
            .ok_or_else(|| invalid_cache("Pallas15 cache path has no parent directory"))?;
        fs::create_dir_all(parent)?;
        let temporary_path = temporary_cache_path(cache_path);
        let result =
            write_cache(&temporary_path).and_then(|()| fs::rename(&temporary_path, cache_path));
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    fn temporary_cache_path(cache_path: &Path) -> PathBuf {
        let mut path = cache_path.as_os_str().to_owned();
        path.push(format!(".tmp-{}", std::process::id()));
        path.into()
    }

    fn write_cache(cache_path: &Path) -> io::Result<()> {
        let prefixes = PALLAS15_LAGRANGE_PREFIXES
            .get()
            .ok_or_else(|| invalid_cache("Pallas15 prefixes are not initialized"))?;
        validate_prefixes(prefixes).map_err(cache_parameter_error)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(cache_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(CACHE_MAGIC)?;
        writer.write_all(&CACHE_FORMAT_VERSION.to_le_bytes())?;
        writer.write_all(&cache_fingerprint())?;
        write_u32(&mut writer, prefixes.len())?;
        for (domain_log2, prefix) in prefixes {
            writer.write_all(&[*domain_log2])?;
            write_u32(&mut writer, prefix.len())?;
            for commitment in prefix {
                commitment.chunks[0]
                    .serialize_uncompressed(&mut writer)
                    .map_err(cache_serialization_error)?;
            }
        }
        writer.flush()?;
        writer.get_ref().sync_all()
    }

    fn load_cache(cache_path: &Path) -> io::Result<LagrangePrefixes> {
        let mut reader = BufReader::new(File::open(cache_path)?);
        let mut magic = [0_u8; CACHE_MAGIC.len()];
        reader.read_exact(&mut magic)?;
        if &magic != CACHE_MAGIC || read_u32(&mut reader)? != CACHE_FORMAT_VERSION {
            return Err(invalid_cache("invalid Pallas15 cache header"));
        }
        let mut fingerprint = [0_u8; 32];
        reader.read_exact(&mut fingerprint)?;
        if fingerprint != cache_fingerprint() || read_usize(&mut reader)? != 3 {
            return Err(invalid_cache("Pallas15 cache parameters do not match"));
        }

        let mut prefixes = Vec::with_capacity(3);
        for expected_log2 in PALLAS15_MIN_DOMAIN_LOG2_SIZE..=PALLAS15_MAX_DOMAIN_LOG2_SIZE {
            let domain_log2 = read_u8(&mut reader)?;
            if domain_log2 != expected_log2
                || read_usize(&mut reader)? != PALLAS15_LAGRANGE_PREFIX_SIZE
            {
                return Err(invalid_cache("Pallas15 cache shape does not match"));
            }
            let mut prefix = Vec::with_capacity(PALLAS15_LAGRANGE_PREFIX_SIZE);
            for _ in 0..PALLAS15_LAGRANGE_PREFIX_SIZE {
                let point = Pallas::deserialize_uncompressed(&mut reader)
                    .map_err(cache_serialization_error)?;
                prefix.push(poly_commitment::PolyComm::new(vec![point]));
            }
            validate_prefix(domain_log2, &prefix).map_err(cache_parameter_error)?;
            prefixes.push((domain_log2, prefix));
        }
        let mut trailing = [0_u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(invalid_cache("Pallas15 cache contains trailing data"));
        }
        Ok(prefixes)
    }

    fn cache_fingerprint() -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(b"pickles:v1:pallas15:local-cache");
        hasher.update(CACHE_FORMAT_VERSION.to_le_bytes());
        hasher.update([
            PALLAS15_SRS_LOG2_SIZE,
            PALLAS15_MIN_DOMAIN_LOG2_SIZE,
            PALLAS15_MAX_DOMAIN_LOG2_SIZE,
        ]);
        hash_usize(&mut hasher, PALLAS15_LAGRANGE_PREFIX_SIZE);
        hasher.update(PALLAS_SRS_15_DIGEST);
        for (domain_log2, digest) in PALLAS_SRS_15_LAGRANGE_PREFIX_DIGESTS {
            hasher.update([*domain_log2]);
            hasher.update(digest);
        }
        hasher.finalize().into()
    }

    fn write_u32(writer: &mut impl Write, value: usize) -> io::Result<()> {
        let value = u32::try_from(value)
            .map_err(|_| invalid_cache("cache value does not fit the cache format"))?;
        writer.write_all(&value.to_le_bytes())
    }

    fn read_u8(reader: &mut impl Read) -> io::Result<u8> {
        let mut value = [0_u8; 1];
        reader.read_exact(&mut value)?;
        Ok(value[0])
    }

    fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
        let mut value = [0_u8; 4];
        reader.read_exact(&mut value)?;
        Ok(u32::from_le_bytes(value))
    }

    fn read_usize(reader: &mut impl Read) -> io::Result<usize> {
        usize::try_from(read_u32(reader)?)
            .map_err(|_| invalid_cache("cache value does not fit this platform"))
    }

    fn invalid_cache(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn cache_parameter_error(error: VerifyError) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Pallas15 cache: {error:?}"),
        )
    }

    fn cache_serialization_error(error: ark_scale::ark_serialize::SerializationError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }

    #[cfg(test)]
    pub(super) fn raw_digests_for_test() -> ([u8; 32], Vec<(u8, [u8; 32])>) {
        let srs = IpaSrs::<Pallas>::create(PALLAS15_SRS_SIZE);
        let srs_digest = srs_digest(&srs).unwrap();
        let lagrange = (PALLAS15_MIN_DOMAIN_LOG2_SIZE..=PALLAS15_MAX_DOMAIN_LOG2_SIZE)
            .map(|domain_log2| {
                let domain = D::<Fq>::new(1usize << domain_log2).unwrap();
                let basis = srs.get_lagrange_basis(domain);
                (
                    domain_log2,
                    lagrange_prefix_digest(domain_log2, basis.as_slice()).unwrap(),
                )
            })
            .collect();
        (srs_digest, lagrange)
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::CurveGroup;
    use ark_ff::{One, Zero};
    use poly_commitment::{ipa::SRS as IpaSrs, SRS as _};

    use super::*;

    #[test]
    #[ignore = "expensive raw Pickles SRS digest generation"]
    fn pallas15_authenticated_parameter_digest() {
        let (srs, lagrange) = native_builtin_srs::raw_digests_for_test();
        assert_eq!(srs, native_builtin_srs::PALLAS_SRS_15_DIGEST);
        assert_eq!(
            lagrange.as_slice(),
            native_builtin_srs::PALLAS_SRS_15_LAGRANGE_PREFIX_DIGESTS
        );
    }

    #[test]
    fn fixed_blinding_commitment_matches_reference_srs() {
        let expected = IpaSrs::<Pallas>::create(PALLAS15_SRS_SIZE).h;
        assert_eq!(pallas15_blinding_commitment(), Ok(expected));
    }

    #[test]
    fn fixed_srs_msm_matches_first_generator() {
        let expected = IpaSrs::<Pallas>::create(PALLAS15_SRS_SIZE).g[0];
        let mut scalars = vec![Fq::zero(); PALLAS15_SRS_SIZE];
        scalars[0] = Fq::one();
        assert_eq!(
            pallas15_srs_msm(Fq::zero(), &scalars, &[], &[]).map(|point| point.into_affine()),
            Ok(expected)
        );
    }
}
