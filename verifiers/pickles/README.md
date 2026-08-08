# Pickles verifier

This pallet verifies recursive proofs emitted by o1js `ZkProgram`, rather than
Mina transaction proofs submitted directly. Clients convert o1js/Mina stable
wire values to the canonical `PicklesV1` payloads in `pickles-format`; the
runtime does not parse S-expressions, bin-prot, or generic o1js JSON.

`PicklesV1` fixes the protocol envelope, not an npm package version:

- recursion widths (`maxProofsVerified`) 0, 1, and 2;
- Pallas wrap SRS `2^15` and wrap domains `2^13` through `2^15`;
- Vesta step-accumulator SRS `2^16`;
- step domains through `2^19`, bounded by eight chunks over that SRS for the
  low-degree circuits o1js documents as supporting that tier;
- 40 reconstructed wrap public-input fields and two previous challenges;
- one through eight split-polynomial evaluation chunks;
- canonical bincode-v2 proof and verification-key payloads;
- at most 65,536 proof bytes, 4,096 verification-key bytes, and 1,024 combined
  public input/output fields.

The canonical verification-key payload also records the program's declared
public-input and public-output arities. Pickles hashes the two arrays as one
flat field sequence, so enforcing those key-bound arities is what makes the
runtime's two-array `Pubs` representation unambiguous. The wrap-domain selector
is validated independently from recursion width because o1js exposes
`overrideWrapDomain` as an independent chunking control.

The checked-in fixtures were generated with o1js 2.15.0. A later o1js version
is compatible if its converted proof satisfies the same `PicklesV1` protocol
profile. Conversely, a package-version match does not override a protocol or
wire-format mismatch.

`resources/chunks2` and `resources/chunks8` contain real low-degree o1js
proofs crossing the `2^16` and `2^18` row boundaries respectively. Their
metadata records the exact o1js, Mina, proof-systems, bindings hash, and the
temporary upstream serializer backport used to preserve every chunk.

Both `pickles-format` and this pallet are `no_std` crates using `alloc`, like
the Kimchi verifier. The Node generator and Rust converter are development
tools and are not part of the runtime dependency graph. In the WASM runtime,
the fixed-SRS MSM and accumulator operations use the authenticated native host
functions described below.

The development check `cargo check -p pickles-format --no-default-features`
must remain green; the complete pallet/runtime WASM build is validated with the
project's Linux cross-compilation toolchain.

Pickles reconstructs deferred transcript values before checking the outer
Kimchi proof. The reconstruction and outer verifier use frozen Pickles-era
constraint expressions generated from `o1-labs/proof-systems` tag 0.3.0,
commit `a73ca6e`. The surrounding verifier and specialized IPA implementation
use the workspace's pinned proof-systems 0.7.0 dependency. Any dependency bump
must re-diff the specialized opening verifier and independently compare the
frozen expressions against the Pickles protocol source.

Native host functions provide the fixed Pallas SRS MSM and Vesta accumulator
check. Node startup authenticates baked SRS/Lagrange digests and prewarms local
caches before block execution.

The development-only generator and converter are documented in
`utils/pickles-fixture-generator/README.md`.
