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

use ark_serialize::CanonicalSerialize;
use blake2::{digest::consts::U32, Blake2b, Digest};
use kimchi::{
    bench::{BaseSpongeVesta, ScalarSpongeVesta},
    circuits::{
        gate::{CircuitGate, GateType},
        lookup::tables::LookupTable,
        polynomials::{generic::GenericGateSpec, xor},
        wires::{Wire, COLUMNS},
    },
    groupmap::GroupMap,
    mina_curves::pasta::{Fp, Vesta},
    mina_poseidon::pasta::FULL_ROUNDS,
    poly_commitment::{
        commitment::{b_poly_coefficients, CommitmentCurve, PolyComm},
        ipa::{OpeningProof, SRS as IpaSrs},
        SRS as SrsTrait,
    },
    proof::{ProverProof, RecursionChallenge},
    prover_index::testing::new_index_for_test_with_lookups_and_custom_srs,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::{
    array, env, fs,
    path::{Path, PathBuf},
};

type VestaOpeningProof = OpeningProof<Vesta, FULL_ROUNDS>;
type VestaSrs = IpaSrs<Vesta>;
type VestaProof = ProverProof<Vesta, VestaOpeningProof, FULL_ROUNDS>;

#[derive(Clone, Copy)]
struct Variant {
    name: &'static str,
    domain_log2: u32,
    public_inputs: usize,
    previous_challenges: usize,
    generic_lookup: bool,
    xor: bool,
    write_srs: bool,
}

const VARIANTS: &[Variant] = &[
    Variant {
        name: "generated_1024",
        domain_log2: 10,
        public_inputs: 0,
        previous_challenges: 0,
        generic_lookup: false,
        xor: false,
        write_srs: true,
    },
    Variant {
        name: "generated_2048",
        domain_log2: 11,
        public_inputs: 0,
        previous_challenges: 0,
        generic_lookup: false,
        xor: false,
        write_srs: true,
    },
    Variant {
        name: "generated_4096_pubs_64",
        domain_log2: 12,
        public_inputs: 64,
        previous_challenges: 0,
        generic_lookup: false,
        xor: false,
        write_srs: true,
    },
    Variant {
        name: "generated_65536_pubs_64",
        domain_log2: 16,
        public_inputs: 64,
        previous_challenges: 0,
        generic_lookup: false,
        xor: false,
        write_srs: false,
    },
    Variant {
        name: "generated_65536_recursive_3_pubs_64",
        domain_log2: 16,
        public_inputs: 64,
        previous_challenges: 3,
        generic_lookup: false,
        xor: false,
        write_srs: false,
    },
    Variant {
        name: "generated_65536_lookup_recursive_3_pubs_64",
        domain_log2: 16,
        public_inputs: 64,
        previous_challenges: 3,
        generic_lookup: true,
        xor: false,
        write_srs: false,
    },
    Variant {
        name: "generated_65536_xor_lookup_recursive_3_pubs_64",
        domain_log2: 16,
        public_inputs: 64,
        previous_challenges: 3,
        // The XOR gadget supplies its own fixed lookup table and exercises the
        // protocol's maximum lookups-per-row and joint-lookup size.
        generic_lookup: false,
        xor: true,
        write_srs: false,
    },
];

fn main() {
    let output_root = match env::args().nth(1) {
        Some(command) if command == "--print-vesta16-digests" => {
            print_vesta16_parameter_digests();
            return;
        }
        Some(output_root) => PathBuf::from(output_root),
        None => default_output_root(),
    };

    for variant in VARIANTS {
        write_variant(&output_root, *variant);
    }
}

fn default_output_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("verifiers/kimchi/src/resources")
}

fn write_variant(output_root: &Path, variant: Variant) {
    let (proof, verifier_index, srs, public_inputs) = generate_variant(variant);
    let output_dir = output_root.join(variant.name);
    fs::create_dir_all(&output_dir).expect("fixture output directory should be created");

    fs::write(
        output_dir.join("proof.bin"),
        bincode::serde::encode_to_vec(&proof, bincode::config::standard())
            .expect("proof should serialize"),
    )
    .expect("proof fixture should be written");
    fs::write(
        output_dir.join("verifier_index.bin"),
        bincode::serde::encode_to_vec(verifier_index, bincode::config::standard())
            .expect("verifier index should serialize"),
    )
    .expect("verifier index fixture should be written");
    if variant.write_srs {
        fs::write(
            output_dir.join("srs.bin"),
            bincode::serde::encode_to_vec(&srs, bincode::config::standard())
                .expect("SRS should serialize"),
        )
        .expect("SRS fixture should be written");
    }
    fs::write(
        output_dir.join("pubs.bin"),
        serialize_public_inputs(&public_inputs),
    )
    .expect("public inputs fixture should be written");

    println!(
        "wrote {}: domain=2^{}, pubs={}, previous_challenges={}, generic_lookup={}, xor={}, max_poly_size={}, srs_written={}",
        variant.name,
        variant.domain_log2,
        variant.public_inputs,
        variant.previous_challenges,
        variant.generic_lookup,
        variant.xor,
        srs.max_poly_size(),
        variant.write_srs,
    );
}

fn generate_variant(
    variant: Variant,
) -> (
    VestaProof,
    kimchi::verifier_index::VerifierIndex<FULL_ROUNDS, Vesta, VestaSrs>,
    VestaSrs,
    Vec<Fp>,
) {
    let num_gates = (1usize << variant.domain_log2)
        .checked_sub(10)
        .expect("domain should leave room for Kimchi zk rows");
    assert!(
        variant.public_inputs <= num_gates,
        "public inputs must fit into the benchmark circuit"
    );

    let gates = circuit_gates(
        num_gates,
        variant.public_inputs,
        variant.generic_lookup,
        variant.xor,
    );
    let lookup_tables = variant
        .generic_lookup
        .then(|| {
            vec![LookupTable {
                id: 0,
                data: vec![vec![Fp::from(0_u32)], vec![Fp::from(0_u32)]],
            }]
        })
        .unwrap_or_default();
    let mut index = new_index_for_test_with_lookups_and_custom_srs::<FULL_ROUNDS, Vesta, _, _>(
        gates,
        variant.public_inputs,
        variant.previous_challenges,
        lookup_tables,
        None,
        false,
        Some(1usize << variant.domain_log2),
        |domain, size| {
            let srs = IpaSrs::<Vesta>::create(size);
            srs.get_lagrange_basis(domain);
            srs
        },
        false,
    );
    assert_eq!(
        index.cs.domain.d1.log_size_of_group, variant.domain_log2,
        "benchmark circuit should use the requested domain"
    );
    index.compute_verifier_index_digest::<BaseSpongeVesta>();

    let public_inputs = vec![Fp::from(1_u32); variant.public_inputs];
    let witness = circuit_witness(
        num_gates,
        &public_inputs,
        variant.generic_lookup,
        variant.xor,
    );
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let mut rng = ChaCha20Rng::from_seed([variant.domain_log2 as u8; 32]);
    let previous_challenges =
        generate_previous_challenges(&index.srs.g, variant.previous_challenges, &mut rng);
    let proof = ProverProof::create_recursive::<BaseSpongeVesta, ScalarSpongeVesta, _>(
        &group_map,
        witness,
        &[],
        &index,
        previous_challenges,
        None,
        &mut rng,
    )
    .expect("benchmark proof should be created");
    let verifier_index = index
        .verifier_index
        .clone()
        .expect("verifier index should be computed");
    let srs = index.srs.as_ref().clone();

    (proof, verifier_index, srs, public_inputs)
}

fn generate_previous_challenges(
    srs_g: &[Vesta],
    count: usize,
    rng: &mut ChaCha20Rng,
) -> Vec<RecursionChallenge<Vesta>> {
    let commitment_bases: Vec<_> = srs_g
        .iter()
        .copied()
        .map(|point| PolyComm::new(vec![point]))
        .collect();
    let commitment_base_refs: Vec<_> = commitment_bases.iter().collect();
    let rounds = srs_g.len().ilog2() as usize;

    (0..count)
        .map(|_| {
            let chals: Vec<_> = (0..rounds).map(|_| Fp::from(rng.next_u64())).collect();
            let coefficients = b_poly_coefficients(&chals);
            let comm = PolyComm::multi_scalar_mul(&commitment_base_refs, &coefficients);
            RecursionChallenge::new(chals, comm)
        })
        .collect()
}

fn circuit_gates(
    num_gates: usize,
    public_inputs: usize,
    generic_lookup: bool,
    xor: bool,
) -> Vec<CircuitGate<Fp>> {
    let mut gates = (0..public_inputs)
        .map(|row| {
            CircuitGate::create_generic_gadget(Wire::for_row(row), GenericGateSpec::Pub, None)
        })
        .collect::<Vec<_>>();

    if generic_lookup {
        let row = gates.len();
        gates.push(CircuitGate::new(
            GateType::Lookup,
            Wire::for_row(row),
            vec![],
        ));
    }
    if xor {
        CircuitGate::extend_xor_gadget(&mut gates, 64);
    }
    while gates.len() < num_gates {
        let row = gates.len();
        gates.push(CircuitGate::create_generic_gadget(
            Wire::for_row(row),
            GenericGateSpec::Const(1_u32.into()),
            None,
        ));
    }
    assert_eq!(gates.len(), num_gates, "circuit must fit requested domain");
    gates
}

fn circuit_witness(
    num_gates: usize,
    public_inputs: &[Fp],
    generic_lookup: bool,
    xor: bool,
) -> [Vec<Fp>; COLUMNS] {
    let mut witness = array::from_fn(|_| vec![Fp::from(1_u32); num_gates]);
    for (row, input) in public_inputs.iter().enumerate() {
        witness[0][row] = *input;
    }
    let mut next_row = public_inputs.len();
    if generic_lookup {
        for column in &mut witness {
            column[next_row] = Fp::from(0_u32);
        }
        next_row += 1;
    }
    if xor {
        let xor_witness = xor::create_xor_witness(Fp::from(0_u32), Fp::from(0_u32), 64);
        for (column, xor_column) in witness.iter_mut().zip(xor_witness) {
            column[next_row..next_row + xor_column.len()].copy_from_slice(&xor_column);
        }
    }
    witness
}

fn serialize_public_inputs(public_inputs: &[Fp]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(public_inputs.len() * 32);
    for input in public_inputs {
        let start = bytes.len();
        input
            .serialize_compressed(&mut bytes)
            .expect("public input should serialize");
        assert_eq!(
            bytes.len() - start,
            32,
            "Pasta public inputs must serialize to 32 bytes"
        );
    }
    bytes
}

fn print_vesta16_parameter_digests() {
    let srs = IpaSrs::<Vesta>::create(1 << 16);

    println!("srs={:?}", srs_digest(&srs));

    for domain_log2 in 10..=16 {
        let domain_size = 1 << domain_log2;
        let basis = srs.get_lagrange_basis_from_domain_size(domain_size);
        println!(
            "lagrange[{domain_log2}]={:?}",
            lagrange_basis_digest(domain_log2, basis.as_slice())
        );
    }
}

type Blake2b256 = Blake2b<U32>;

fn srs_digest(srs: &VestaSrs) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(b"kimchi:v1:vesta16:srs");
    hash_usize(&mut hasher, srs.g.len());
    for point in &srs.g {
        hash_point(&mut hasher, point);
    }
    hash_point(&mut hasher, &srs.h);
    hasher.finalize().into()
}

fn lagrange_basis_digest(domain_log2: u8, basis: &[PolyComm<Vesta>]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(b"kimchi:v1:vesta16:lagrange");
    hasher.update([domain_log2]);
    hash_usize(&mut hasher, basis.len());
    for commitment in basis {
        hash_usize(&mut hasher, commitment.chunks.len());
        for point in &commitment.chunks {
            hash_point(&mut hasher, point);
        }
    }
    hasher.finalize().into()
}

fn hash_usize(hasher: &mut Blake2b256, value: usize) {
    hasher.update((value as u64).to_le_bytes());
}

fn hash_point(hasher: &mut Blake2b256, point: &Vesta) {
    let mut bytes = [0_u8; 33];
    point
        .serialize_compressed(bytes.as_mut_slice())
        .expect("Vesta point should serialize");
    hasher.update(bytes);
}
