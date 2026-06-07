# Kimchi Benchmark Fixture Generator

This helper regenerates the Kimchi verifier benchmark fixtures under
`verifiers/kimchi/src/resources`.

Run from the repository root:

```bash
cargo run --manifest-path scripts/kimchi-fixture-generator/Cargo.toml --offline
```

The generator intentionally lives outside the main workspace so prover-only
Kimchi dependencies do not affect runtime or verifier builds. Some legacy
fixtures include SRS files for reproducibility, but the runtime verifier uses a
built-in SRS identifier and does not submit or store these SRS bytes. The
`generated_65536_pubs_64` fixture intentionally omits `srs.bin` to avoid adding
multi-megabyte unused fixture data.

`generated_65536_xor_lookup_recursive_3_pubs_64` is the current maximum
benchmark profile: domain `2^16`, 64 public inputs, three previous challenges,
and an XOR gate. The XOR gadget exercises Kimchi's maximum lookups-per-row and
joint-lookup size. V1 rejects runtime lookup tables. Widening the native shape
limits requires a corresponding benchmark fixture and regenerated weights.

To print the full canonical digests pinned by the native `Vesta16` parameter
self-test:

```bash
cargo run --release --manifest-path scripts/kimchi-fixture-generator/Cargo.toml -- --print-vesta16-digests
```

Changing these digests is a verifier-parameter change and must be paired with
an intentional native digest update.
