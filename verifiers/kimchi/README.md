# Kimchi verifier

The Kimchi verifier accepts a consensus-defined compatibility profile rather
than arbitrary Kimchi parameters. The production profile is `Vesta16`.

## Production compatibility profile

`Vesta16` currently fixes the following verification envelope:

| Parameter | Value |
| --- | --- |
| Curve | Vesta |
| IPA SRS size / maximum polynomial size | `2^16` |
| Supported evaluation domains | `2^3` through `2^18` |
| Maximum commitment chunks | `4` |
| Maximum public inputs | `1024` |
| Recursive previous challenges | Unsupported |

The SRS, supported domain/chunk envelope, and authenticated parameter digests
are shared by the runtime verifier and the native Vesta host functions.

## Native compatibility and upgrades

The existing `Vesta16` parameters are a native node compatibility boundary and
must not be changed in place. A different SRS size, curve, domain/chunk
envelope, or parameter set cannot be supported through a runtime-only upgrade.

Supporting such a change requires:

1. re-evaluating the native design and introducing a distinct, versioned
   verifier/profile path;
2. adding or versioning the required host functions while retaining those
   needed by active runtimes;
3. updating the native parameters, authenticated digests, and cache identity;
4. regenerating fixtures, benchmarks, and weights and testing both
   compatibility paths;
5. coordinating a compatible node rollout before activating runtime support.

Upstream expectations about future SRS sizes are planning input, not a
permanent protocol guarantee. Reconfirm them before integrating future Kimchi
or o1js hard-fork changes.

## Experimental precomputed cache seed

A node can load the precomputed Vesta16 Lagrange bases from an authenticated,
read-only seed cache by setting:

```shell
export ZKV_KIMCHI_VESTA16_SEED_CACHE=/absolute/path/to/kimchi-vesta16-v1.cache
```

Use an absolute path: Zombienet starts nodes in separate working directories,
so a relative path may resolve differently for each child process.

The seed file can be taken from another node's
`<base-path>/native-verifier-parameters/kimchi-vesta16-v1.cache`. It is not
copied into the new node's base path. Startup uses the first usable source in
this order:

1. the node's local base-path cache;
2. the configured read-only seed cache;
3. local generation and persistence.

The seed is treated as untrusted input. Its format, parameter fingerprint,
point encodings, complete Lagrange bases, and trailing data are all validated
before any cached basis is installed. Missing, corrupt, or incompatible seeds
are logged and fall back to local generation.

The environment variable is inherited by native Zombienet child processes, so
one cache can be shared by multiple fresh-base-path nodes without committing or
publishing the generated file.

An experiment has exercised the seed only when every fresh-base-path node logs
`(LoadedFromSeed)`. A `(Generated)` or `(GeneratedWithoutCache)` status means
that the seed was unavailable or invalid and startup fell back to cold
generation.
