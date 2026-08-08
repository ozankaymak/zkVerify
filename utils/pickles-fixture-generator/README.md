# Pickles fixture generator

This development-only utility produces reference Pickles proofs with the
published o1js prover. It deliberately lives outside the workspace so o1js and
the proof converter never enter the runtime dependency graph.

The generator covers `maxProofsVerified` values 0, 1, and 2 with real recursive
proofs, plus a non-recursive proof enabling range-check, XOR, and rotation
features. Every proof is checked with its program-specific verifier both before
and after JSON/base64 serialization. One-chunk artifacts are also required to
pass o1js's side-loaded verification-key API.

The checked-in reference fixtures use o1js 2.15.0, but `PicklesV1` is not an
npm-package-version gate. Compatibility is determined by the canonical wire
format and the pinned Pickles protocol parameters; a later o1js release that
emits the same profile can be converted as well.

Run it with an exact o1js installation:

```console
node utils/pickles-fixture-generator/generate.mjs \
  /path/to/o1js/dist/node/index.js \
  /tmp/pickles-source-fixtures \
  1 \
  all \
  auto
```

The `numChunks` argument must be between 1 and 8. The optional fixture selector
is `all`, `width0`, `width1`, `width2`, `features`, `chunks2`, or `chunks8`; it
defaults to `all`. The chunked fixtures are deliberately excluded from `all`.
`chunks2` builds just above `2^16` rows to request a real two-chunk,
`2^17`-domain proof. `chunks8` builds just above `2^18` rows to request a real
eight-chunk, `2^19`-domain proof. The latter can take hours to compile and prove
and is not part of the routine fixture set.
The final argument is `auto`, `0`, `1`, or `2` and controls
`overrideWrapDomain`. `auto` leaves one-chunk programs at the o1js default,
uses domain 1 for two chunks, and domain 2 for three through eight chunks.
o1js only documents the upper eight-chunk tier for sufficiently low-degree
circuits. The generator reads and records the actual o1js package version.
Source JSON files are inputs to the Rust converter; they are not the format
accepted by the runtime verifier.

When testing an unpublished o1js build, the optional `O1JS_GIT_COMMIT`,
`O1JS_MINA_COMMIT`, `O1JS_PROOF_SYSTEMS_COMMIT`, `O1JS_BINDINGS_SHA256`, and
`O1JS_SERIALIZATION_PATCH` environment variables add exact build provenance to
the source and converted fixture metadata.

Convert one generated fixture with:

```console
cargo run --manifest-path utils/pickles-fixture-generator/converter/Cargo.toml -- \
  path/to/width0.json path/to/converted-width0
```

The output directory contains `fixture.json`, `proof.bin`, and
`verifier-index.bin`. The JSON includes the canonical little-endian public
input/output field elements and hex copies of the two binary payloads. The
canonical verification key binds the declared public-input and public-output
field counts separately.

## Temporary chunk-safe serialization adapter

MinaProtocol/mina#18884 changed Pickles proof S-expressions so
`prev_evals.public_input` retains every split-polynomial chunk. The canonical
zkVerify payload also retains all of those values. OpenMina's current generated
Rust wire type still represents this field as a pair of scalars, so the
development-only converter temporarily decodes the S-expression itself,
extracts both public-input evaluation vectors, and collapses only a copy passed
to OpenMina for decoding the remaining unchanged fields. This adapter should be
removed once OpenMina publishes a matching chunk-safe stable wire type.

The released o1js 2.15.0 serializer predates that fix and drops all but one
public-input evaluation per point. Real chunked fixtures therefore must be
generated with the upstream chunk-safe serializer (or an exact backport onto
the signed 2.15.0 sources). The generator verifies the deserialized proof with
the program-specific verifier before it writes a fixture, preventing a lossy
release serializer from silently producing unusable test data. Build commit and
artifact-hash provenance can be recorded with the environment variables above;
this is temporary fixture tooling and does not enter the runtime verifier.

The o1js side-loaded verification-key encoding separately omits `numChunks`.
Consequently, its generic `verify()` path currently supplies one-chunk defaults
and rejects otherwise valid multi-chunk proofs. Multi-chunk generation records
that result as diagnostic metadata but gates fixture creation on successful
program-specific verification after deserializing the proof. The exported wrap
index is still converted and is subsequently exercised by zkVerify's verifier.
