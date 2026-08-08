// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const [
  o1jsEntry,
  outputDirectory,
  configuredChunks = '1',
  selectedFixture = 'all',
  configuredWrapDomain = 'auto',
] = process.argv.slice(2);

if (o1jsEntry === undefined || outputDirectory === undefined) {
  throw Error(
    'usage: node generate.mjs <path-to-o1js-index.js> <output-directory> [num-chunks] [all|width0|width1|width2|features|chunks2|chunks8] [auto|0|1|2]'
  );
}

const numChunks = Number(configuredChunks);
if (!Number.isInteger(numChunks) || numChunks < 1 || numChunks > 8) {
  throw Error('num-chunks must be an integer from 1 through 8');
}
if (
  !['all', 'width0', 'width1', 'width2', 'features', 'chunks2', 'chunks8'].includes(
    selectedFixture
  )
) {
    throw Error(
      'fixture must be all, width0, width1, width2, features, chunks2, or chunks8'
    );
}
const overrideWrapDomain =
  configuredWrapDomain === 'auto'
    ? numChunks === 1
      ? undefined
      : numChunks === 2
        ? 1
        : 2
    : Number(configuredWrapDomain);
if (
  overrideWrapDomain !== undefined &&
  (!Number.isInteger(overrideWrapDomain) || overrideWrapDomain < 0 || overrideWrapDomain > 2)
) {
  throw Error('wrap-domain must be auto, 0, 1, or 2');
}
if (selectedFixture === 'chunks8' && (numChunks !== 8 || overrideWrapDomain !== 2)) {
  throw Error('the chunks8 fixture requires num-chunks=8 and wrap-domain=2 (or auto)');
}
if (selectedFixture === 'chunks2' && (numChunks !== 2 || overrideWrapDomain !== 1)) {
  throw Error('the chunks2 fixture requires num-chunks=2 and wrap-domain=1 (or auto)');
}
const wrapDomainConfig =
  overrideWrapDomain === undefined ? {} : { overrideWrapDomain };

const packageJson = JSON.parse(
  await readFile(resolve(dirname(o1jsEntry), '..', '..', 'package.json'), 'utf8')
);
if (typeof packageJson.version !== 'string' || packageJson.version.length === 0) {
  throw Error('cannot determine the o1js version from its package.json');
}

const { Cache, Field, Gadgets, SelfProof, ZkProgram, verify } = await import(
  pathToFileURL(resolve(o1jsEntry)).href
);
const bindings = await import(
  pathToFileURL(resolve(dirname(o1jsEntry), 'bindings.js')).href
);

const output = resolve(outputDirectory);
await mkdir(output, { recursive: true });

async function persistFixture(name, program, proof, verificationKey) {
  const jsonProof = proof.toJSON();
  const validWithProgram = await program.verify(proof);
  const Proof = ZkProgram.Proof(program);
  const roundTrippedProof = await Proof.fromJSON(jsonProof);
  const validAfterProofRoundTrip = await program.verify(roundTrippedProof);
  const validWithSideLoadedKey = await verify(jsonProof, verificationKey);

  const fixture = {
    format: 'zkverify-pickles-source-v1',
    reference: {
      package: 'o1js',
      version: packageJson.version,
      ...(process.env.O1JS_GIT_COMMIT
        ? { gitCommit: process.env.O1JS_GIT_COMMIT }
        : {}),
      ...(process.env.O1JS_MINA_COMMIT
        ? { minaCommit: process.env.O1JS_MINA_COMMIT }
        : {}),
      ...(process.env.O1JS_PROOF_SYSTEMS_COMMIT
        ? { proofSystemsCommit: process.env.O1JS_PROOF_SYSTEMS_COMMIT }
        : {}),
      ...(process.env.O1JS_BINDINGS_SHA256
        ? { bindingsSha256: process.env.O1JS_BINDINGS_SHA256 }
        : {}),
      ...(process.env.O1JS_SERIALIZATION_PATCH
        ? { serializationPatch: process.env.O1JS_SERIALIZATION_PATCH }
        : {}),
    },
    compileConfig: {
      numChunks,
      ...wrapDomainConfig,
    },
    verificationKey: {
      data: verificationKey.data,
      hash: verificationKey.hash.toString(),
    },
    proof: {
      ...jsonProof,
      transactionProof: bindings.Pickles.proofToBase64Transaction(proof.proof),
    },
    referenceVerification: {
      inMemoryProgram: validWithProgram,
      serializedProofWithProgram: validAfterProofRoundTrip,
      sideLoadedKey: validWithSideLoadedKey,
      ...(numChunks > 1 && !validWithSideLoadedKey
        ? {
            sideLoadedKeyLimitation:
              'o1js side-loaded verification currently uses default one-chunk metadata',
          }
        : {}),
    },
    expectedVerification: true,
  };

  // o1js's side-loaded verification-key format does not carry numChunks. Its
  // generic verifier therefore uses one-chunk defaults even when the exported
  // wrap index belongs to a chunked program. For multi-chunk fixtures, require
  // the stronger program-specific check both before and after proof
  // serialization, and retain the side-loaded result as diagnostic metadata.
  if (
    !validWithProgram ||
    !validAfterProofRoundTrip ||
    (numChunks === 1 && !validWithSideLoadedKey)
  ) {
    const diagnosticPath = resolve(output, `${name}.diagnostic.json`);
    await writeFile(diagnosticPath, `${JSON.stringify(fixture, null, 2)}\n`);
    throw Error(
      `${name}: reference o1js verification failed ` +
        `(program=${validWithProgram}, serialized-program=${validAfterProofRoundTrip}, ` +
        `side-loaded=${validWithSideLoadedKey}); ` +
        `diagnostic fixture persisted at ${diagnosticPath}`
    );
  }

  const path = resolve(output, `${name}.json`);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(fixture, null, 2)}\n`);
}

if (selectedFixture === 'all' || selectedFixture === 'width0') {
  const Width0 = ZkProgram({
    name: `zkverify-pickles-v1-width0-chunks${numChunks}`,
    publicInput: Field,
    publicOutput: Field,
    numChunks,
    ...wrapDomainConfig,
    methods: {
      base: {
        privateInputs: [],
        async method(input) {
          return { publicOutput: input.add(1) };
        },
      },
    },
  });

  const { verificationKey: width0Vk } = await Width0.compile({ cache: Cache.None });
  const { proof: width0Proof } = await Width0.base(Field(2));
  await persistFixture('width0', Width0, width0Proof, width0Vk);
}

if (selectedFixture === 'all' || selectedFixture === 'width1') {
  const Width1 = ZkProgram({
    name: `zkverify-pickles-v1-width1-chunks${numChunks}`,
    publicInput: Field,
    publicOutput: Field,
    numChunks,
    ...wrapDomainConfig,
    methods: {
      base: {
        privateInputs: [],
        async method(input) {
          return { publicOutput: input };
        },
      },
      step: {
        privateInputs: [SelfProof],
        async method(input, earlier) {
          earlier.verify();
          earlier.publicOutput.assertEquals(input);
          return { publicOutput: input.add(1) };
        },
      },
    },
  });

  const { verificationKey: width1Vk } = await Width1.compile({ cache: Cache.None });
  const { proof: width1Base } = await Width1.base(Field(5));
  const { proof: width1Proof } = await Width1.step(Field(5), width1Base);
  await persistFixture('width1', Width1, width1Proof, width1Vk);
}

if (selectedFixture === 'all' || selectedFixture === 'width2') {
  const Width2 = ZkProgram({
    name: `zkverify-pickles-v1-width2-chunks${numChunks}`,
    publicInput: Field,
    publicOutput: Field,
    numChunks,
    ...wrapDomainConfig,
    methods: {
      base: {
        privateInputs: [],
        async method(input) {
          return { publicOutput: input };
        },
      },
      merge: {
        privateInputs: [SelfProof, SelfProof],
        async method(input, left, right) {
          left.verify();
          right.verify();
          left.publicOutput.add(right.publicOutput).assertEquals(input);
          return { publicOutput: input.add(1) };
        },
      },
    },
  });

  const { verificationKey: width2Vk } = await Width2.compile({ cache: Cache.None });
  const { proof: width2Left } = await Width2.base(Field(7));
  const { proof: width2Right } = await Width2.base(Field(11));
  const { proof: width2Proof } = await Width2.merge(Field(18), width2Left, width2Right);
  await persistFixture('width2', Width2, width2Proof, width2Vk);
}

if (selectedFixture === 'all' || selectedFixture === 'features') {
  const Features = ZkProgram({
    name: `zkverify-pickles-v1-features-chunks${numChunks}`,
    publicInput: Field,
    publicOutput: Field,
    numChunks,
    ...wrapDomainConfig,
    methods: {
      bitwise: {
        privateInputs: [],
        async method(input) {
          Gadgets.rangeCheck64(input);
          const xored = Gadgets.xor(input, Field(42), 64);
          return { publicOutput: Gadgets.rotate64(xored, 7, 'left') };
        },
      },
    },
  });

  const { verificationKey: featuresVk } = await Features.compile({ cache: Cache.None });
  const { proof: featuresProof } = await Features.bitwise(Field(2));
  await persistFixture('features', Features, featuresProof, featuresVk);
}

if (selectedFixture === 'chunks2' || selectedFixture === 'chunks8') {
  const fixtureChunks = selectedFixture === 'chunks2' ? 2 : 8;
  const logPhase = (message) =>
    console.log(`[${new Date().toISOString()}] chunks${fixtureChunks}: ${message}`);
  const { Gates, KimchiGateType } = await import(
    pathToFileURL(resolve(dirname(o1jsEntry), 'lib/provable/gates.js')).href
  );
  // A raw Generic gate carries two low-degree Generic constraints. Emitting
  // complete rows directly avoids constructing a huge expression chain while
  // placing the method just above the selected chunk tier's domain boundary.
  const genericRows = fixtureChunks === 2 ? 65_540 : 262_150;
  const Chunked = ZkProgram({
    name: `zkverify-pickles-v1-chunks${fixtureChunks}-generic`,
    publicInput: Field,
    publicOutput: Field,
    numChunks,
    ...wrapDomainConfig,
    methods: {
      genericRows: {
        privateInputs: [],
        async method(input) {
          const values = Array(15).fill(input);
          const coefficients = [1n, -1n, 0n, 0n, 0n, 1n, -1n, 0n, 0n, 0n];
          for (let i = 0; i < genericRows; i++) {
            // Both constraints are the tautology input - input = 0.
            Gates.raw(KimchiGateType.Generic, values, coefficients);
          }
          return { publicOutput: input };
        },
      },
    },
  });

  logPhase('analyzing the circuit');
  const analysis = await Chunked.analyzeMethods();
  const lowerDomain = fixtureChunks === 2 ? 2 ** 16 : 2 ** 18;
  const upperDomain = fixtureChunks === 2 ? 2 ** 17 : 2 ** 19;
  if (analysis.genericRows.rows <= lowerDomain || analysis.genericRows.rows > upperDomain) {
    throw Error(
      `chunks${fixtureChunks} circuit has unexpected row count ${analysis.genericRows.rows}`
    );
  }
  logPhase(`analysis complete (${analysis.genericRows.rows} rows); compiling`);
  // The chunks8 proving key is larger than Node's maximum single Buffer/write
  // (currently about 3.76 GiB), so avoid the file-system cache for both real
  // chunked fixtures and keep their generation paths identical.
  const { verificationKey: chunkedVk } = await Chunked.compile({
    cache: Cache.None,
    lazyMode: true,
  });
  logPhase('compile complete; proving');
  const { proof: chunkedProof } = await Chunked.genericRows(Field(2));
  logPhase('proof complete; running both reference verification paths');
  await persistFixture(
    `chunks${fixtureChunks}`,
    Chunked,
    chunkedProof,
    chunkedVk
  );
  logPhase('reference verification complete; fixture persisted');
}
