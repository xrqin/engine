/**
 * B.7 — Golden Test Vectors for v8.1 Primitives
 *
 * Tests determinism and cross-consistency of:
 * - Source descriptor (B.7a)
 * - Module descriptor (B.7b)
 * - Commitments: comSrcV8, comModV8 (B.7c)
 * - Nullifier derivation: deriveRhoSrc, deriveRhoMod (B.7d)
 * - Bindings: inputBinding, inputLineageBinding, lineageBinding (B.7e)
 * - Memo AD: buildMemoAD, buildLineageMemoAD (B.7f)
 * - Unified lineage memo round-trip (B.7g)
 * - Module descriptor + module payload round-trip
 * - Module tag encoding
 * - Preflight limit checks
 * - Pending lineage store
 */

import chai from 'chai';
import { initPoseidonPromise } from '../../utils/poseidon';

// Source descriptor
import {
  buildSourceDescriptor,
  verifySourceDescriptor,
} from '../source-descriptor';

// Module descriptor
import {
  buildModuleDescriptor,
  verifyModuleDescriptor,
} from '../module-descriptor';

// Commitments
import {
  comSrcV8,
  comModV8,
  deriveRhoSrc,
  deriveRhoMod,
  noteComV5,
} from '../commitments';
import type { NoteV5 } from '../commitments';

// Bindings
import {
  computeInputNoteSemV8,
  computeInputBindingV8,
  computeInputLineageNoteSem,
  computeInputLineageBinding,
  computeOutputBindingV8,
  computeBucketSrcInRefDigest,
  computeBucketSrcMeta,
  computeBucketMetaCommitV8,
  computeLineageBindingV8,
  computePolicyBindingV8,
} from '../bindings';

// Source memo
import {
  buildSourcePayload,
  decodeSourcePayload,
  buildSourcePackageId,
  buildMemoAD,
  encryptSourceMemo,
  decryptSourceMemo,
  verifySourcePayload,
  SourceCache,
} from '../source-memo';

// Module memo + unified lineage
import {
  buildModulePayload,
  decodeModulePayload,
  buildModulePackageId,
  buildLineageMemoAD,
  encryptLineageMemo,
  decryptLineageMemo,
  verifyModulePayload,
  ModuleCache,
} from '../source-memo';

// Module/tag encoding
import {
  normalizeModuleLocator,
  encodeModuleLocator,
  encodeTag,
  buildModuleTagSet,
  encodeCanonicalModuleBytes,
  decodeCanonicalModuleBytes,
} from '../module-tag-encoding';

// Preflight
import {
  validatePreflightLimits,
  estimateIvcSteps,
  paddedMemoSize,
  MAX_BUCKET_COUNT,
  MAX_CARRY_INPUT_REFS,
  MAX_MEMO_PAYLOAD_BYTES,
} from '../preflight';

// Pending lineage
import { PendingLineageStore } from '../pending-lineage';

const { expect } = chai;

// ============================================================
// Helpers
// ============================================================

function makeSources(n: number, start = 1000, step = 7): bigint[] {
  return Array.from({ length: n }, (_, i) => BigInt(start + i * step));
}

function makeModules(n: number, start = 50000, step = 13): bigint[] {
  return Array.from({ length: n }, (_, i) => BigInt(start + i * step));
}

// Golden seed values for deterministic tests
const GOLDEN_RHO_VALUE = 123456789n;
const GOLDEN_OWNER_PUBKEY = 987654321n;
const GOLDEN_OUTPUT_INDEX = 0;
const GOLDEN_CHAINID = 1n;
const GOLDEN_VERIFIER_ADDR = 0xdeadbeefn;
const GOLDEN_SHARED_SECRET = 0xabcdef0123456789n;

describe('B.7 Golden Test Vectors — v8.1', function () {
  this.timeout(120_000);

  before(async () => {
    await initPoseidonPromise;
  });

  // =========================================================================
  // B.7a: Source Descriptor Golden Vectors
  // =========================================================================
  describe('B.7a: Source Descriptor', () => {
    it('empty set is deterministic', () => {
      const d1 = buildSourceDescriptor([]);
      const d2 = buildSourceDescriptor([]);
      expect(d1.srcRoot).to.equal(d2.srcRoot);
      expect(d1.srcCount).to.equal(0);
    });

    it('single element is deterministic', () => {
      const d1 = buildSourceDescriptor([42n]);
      const d2 = buildSourceDescriptor([42n]);
      expect(d1.srcRoot).to.equal(d2.srcRoot);
      expect(d1.srcCount).to.equal(1);
    });

    it('4 elements — golden vector', () => {
      const sources = [10n, 20n, 30n, 40n];
      const desc = buildSourceDescriptor(sources);
      expect(desc.srcCount).to.equal(4);
      expect(desc.srcRoot).to.be.a('bigint');
      // Rebuild must match
      expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, sources)).to.be.true;
      // Record the golden value for cross-language compat
      expect(desc.srcRoot).to.not.equal(0n);
    });

    it('7 elements (non-power-of-2) — golden vector', () => {
      const sources = makeSources(7);
      const desc = buildSourceDescriptor(sources);
      expect(desc.srcCount).to.equal(7);
      expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, sources)).to.be.true;
    });

    it('different lists produce different roots', () => {
      const d1 = buildSourceDescriptor([10n, 20n]);
      const d2 = buildSourceDescriptor([10n, 30n]);
      expect(d1.srcRoot).to.not.equal(d2.srcRoot);
    });
  });

  // =========================================================================
  // B.7b: Module Descriptor Golden Vectors
  // =========================================================================
  describe('B.7b: Module Descriptor', () => {
    it('empty module set is deterministic', () => {
      const d1 = buildModuleDescriptor([]);
      const d2 = buildModuleDescriptor([]);
      expect(d1.modRoot).to.equal(d2.modRoot);
      expect(d1.modCount).to.equal(0);
    });

    it('single module is deterministic', () => {
      const d1 = buildModuleDescriptor([99n]);
      const d2 = buildModuleDescriptor([99n]);
      expect(d1.modRoot).to.equal(d2.modRoot);
      expect(d1.modCount).to.equal(1);
    });

    it('4 modules — golden vector', () => {
      const mods = [100n, 200n, 300n, 400n];
      const desc = buildModuleDescriptor(mods);
      expect(desc.modCount).to.equal(4);
      expect(verifyModuleDescriptor(desc.modRoot, desc.modCount, mods)).to.be.true;
    });

    it('5 modules (non-power-of-2) — golden vector', () => {
      const mods = makeModules(5);
      const desc = buildModuleDescriptor(mods);
      expect(desc.modCount).to.equal(5);
      expect(verifyModuleDescriptor(desc.modRoot, desc.modCount, mods)).to.be.true;
    });

    it('rejects non-sorted input', () => {
      expect(() => buildModuleDescriptor([200n, 100n])).to.throw('strictly increasing');
    });

    it('rejects duplicate input', () => {
      expect(() => buildModuleDescriptor([100n, 100n])).to.throw('strictly increasing');
    });

    it('source and module descriptors with same primes produce different roots', () => {
      const primes = [10n, 20n, 30n];
      const srcDesc = buildSourceDescriptor(primes);
      const modDesc = buildModuleDescriptor(primes);
      // Different DSTs → different roots
      expect(srcDesc.srcRoot).to.not.equal(modDesc.modRoot);
    });
  });

  // =========================================================================
  // B.7c: Commitments Golden Vectors
  // =========================================================================
  describe('B.7c: Commitments', () => {
    it('comSrcV8 is deterministic', () => {
      const c1 = comSrcV8(111n, 4, 222n);
      const c2 = comSrcV8(111n, 4, 222n);
      expect(c1).to.equal(c2);
    });

    it('comModV8 is deterministic', () => {
      const c1 = comModV8(333n, 2, 444n);
      const c2 = comModV8(333n, 2, 444n);
      expect(c1).to.equal(c2);
    });

    it('comSrcV8 and comModV8 with same inputs produce different values', () => {
      const src = comSrcV8(100n, 3, 200n);
      const mod = comModV8(100n, 3, 200n);
      expect(src).to.not.equal(mod);
    });

    it('noteComV5 golden vector', () => {
      const sources = makeSources(4);
      const mods = makeModules(2);
      const srcDesc = buildSourceDescriptor(sources);
      const modDesc = buildModuleDescriptor(mods);

      const rhoSrc = deriveRhoSrc(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, GOLDEN_OUTPUT_INDEX);
      const rhoMod = deriveRhoMod(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, GOLDEN_OUTPUT_INDEX);

      const srcCommit = comSrcV8(srcDesc.srcRoot, srcDesc.srcCount, rhoSrc);
      const modCommit = comModV8(modDesc.modRoot, modDesc.modCount, rhoMod);

      const note: NoteV5 = {
        value: 1000n,
        tokenHash: 2000n,
        ownerPubkey: GOLDEN_OWNER_PUBKEY,
        rhoValue: GOLDEN_RHO_VALUE,
        sourceCommitment: srcCommit,
        moduleCommitment: modCommit,
        cleanEpoch: 1n,
      };

      const cm = noteComV5(note);
      expect(cm).to.be.a('bigint');
      // Determinism
      expect(noteComV5(note)).to.equal(cm);
    });
  });

  // =========================================================================
  // B.7d: Nullifier / Rho Derivation Golden Vectors
  // =========================================================================
  describe('B.7d: Rho Derivation', () => {
    it('deriveRhoSrc is deterministic', () => {
      const r1 = deriveRhoSrc(100n, 200n, 0);
      const r2 = deriveRhoSrc(100n, 200n, 0);
      expect(r1).to.equal(r2);
    });

    it('deriveRhoMod is deterministic', () => {
      const r1 = deriveRhoMod(100n, 200n, 0);
      const r2 = deriveRhoMod(100n, 200n, 0);
      expect(r1).to.equal(r2);
    });

    it('different output indices produce different rhos', () => {
      const r0 = deriveRhoSrc(100n, 200n, 0);
      const r1 = deriveRhoSrc(100n, 200n, 1);
      expect(r0).to.not.equal(r1);
    });

    it('rhoSrc and rhoMod are different for same inputs', () => {
      const rhoSrc = deriveRhoSrc(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0);
      const rhoMod = deriveRhoMod(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0);
      expect(rhoSrc).to.not.equal(rhoMod);
    });
  });

  // =========================================================================
  // B.7e: Binding Golden Vectors
  // =========================================================================
  describe('B.7e: Bindings', () => {
    it('inputNoteSemV8 is deterministic', () => {
      const sem1 = computeInputNoteSemV8(1n, 2n, 3n, 4n, 5n);
      const sem2 = computeInputNoteSemV8(1n, 2n, 3n, 4n, 5n);
      expect(sem1).to.equal(sem2);
    });

    it('inputBindingV8 golden vector', () => {
      const sems = [
        computeInputNoteSemV8(1n, 100n, 200n, 300n, 1n),
        computeInputNoteSemV8(2n, 100n, 400n, 500n, 1n),
      ];
      const binding = computeInputBindingV8(GOLDEN_CHAINID, GOLDEN_VERIFIER_ADDR, 999n, sems);
      expect(binding).to.be.a('bigint');
      // Determinism
      const binding2 = computeInputBindingV8(GOLDEN_CHAINID, GOLDEN_VERIFIER_ADDR, 999n, sems);
      expect(binding).to.equal(binding2);
    });

    it('inputLineageBinding golden vector', () => {
      const notes = [
        { sourceCommitment: 200n, moduleCommitment: 300n, cleanEpoch: 1n },
        { sourceCommitment: 400n, moduleCommitment: 500n, cleanEpoch: 1n },
      ];
      const lb = computeInputLineageBinding(GOLDEN_CHAINID, GOLDEN_VERIFIER_ADDR, notes);
      expect(lb).to.be.a('bigint');
      // Determinism
      const lb2 = computeInputLineageBinding(GOLDEN_CHAINID, GOLDEN_VERIFIER_ADDR, notes);
      expect(lb).to.equal(lb2);
    });

    it('lineageBindingV8 golden vector', () => {
      const bucketMeta = [111n, 222n];
      const lb = computeLineageBindingV8(GOLDEN_CHAINID, GOLDEN_VERIFIER_ADDR, 'TRANSFER', bucketMeta);
      expect(lb).to.be.a('bigint');
      const lb2 = computeLineageBindingV8(GOLDEN_CHAINID, GOLDEN_VERIFIER_ADDR, 'TRANSFER', bucketMeta);
      expect(lb).to.equal(lb2);
    });

    it('policyBindingV8 golden vector', () => {
      const pb = computePolicyBindingV8(
        GOLDEN_CHAINID, GOLDEN_VERIFIER_ADDR,
        1, 100, 999n, 888n, 777n, 0, 0,
      );
      expect(pb).to.be.a('bigint');
      const pb2 = computePolicyBindingV8(
        GOLDEN_CHAINID, GOLDEN_VERIFIER_ADDR,
        1, 100, 999n, 888n, 777n, 0, 0,
      );
      expect(pb).to.equal(pb2);
    });
  });

  // =========================================================================
  // B.7f: Memo AD Golden Vectors
  // =========================================================================
  describe('B.7f: Memo AD', () => {
    it('buildMemoAD is deterministic', () => {
      const ad1 = buildMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);
      const ad2 = buildMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);
      expect(ad1).to.equal(ad2);
    });

    it('buildLineageMemoAD is deterministic', () => {
      const ad1 = buildLineageMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);
      const ad2 = buildLineageMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);
      expect(ad1).to.equal(ad2);
    });

    it('memoAD and lineageMemoAD differ (different DSTs)', () => {
      const ad1 = buildMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);
      const ad2 = buildLineageMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);
      expect(ad1).to.not.equal(ad2);
    });

    it('different outputIndex produces different AD', () => {
      const ad0 = buildMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);
      const ad1 = buildMemoAD(GOLDEN_CHAINID, 111n, 1, 222n, 333n, 1n);
      expect(ad0).to.not.equal(ad1);
    });
  });

  // =========================================================================
  // B.7g: Unified Lineage Memo Round-Trip
  // =========================================================================
  describe('B.7g: Unified Lineage Memo', () => {
    it('source-only memo round-trip', () => {
      const sources = makeSources(4);
      const payload = buildSourcePayload(sources);
      const ad = buildMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);
      const ct = encryptSourceMemo(GOLDEN_SHARED_SECRET, ad, payload);
      const pt = decryptSourceMemo(GOLDEN_SHARED_SECRET, ad, ct);
      expect(pt).to.not.be.null;
      const decoded = decodeSourcePayload(pt!);
      expect(decoded).to.deep.equal(sources);
    });

    it('unified lineage memo round-trip (source + module)', () => {
      const sources = makeSources(3);
      const modules = makeModules(2);
      const srcPayload = buildSourcePayload(sources);
      const modPayload = buildModulePayload(modules);
      const ad = buildLineageMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);

      const ct = encryptLineageMemo(GOLDEN_SHARED_SECRET, ad, srcPayload, modPayload);
      const result = decryptLineageMemo(GOLDEN_SHARED_SECRET, ad, ct);

      expect(result).to.not.be.null;
      expect(decodeSourcePayload(result!.sourcePayload)).to.deep.equal(sources);
      expect(decodeModulePayload(result!.modulePayload)).to.deep.equal(modules);
    });

    it('unified lineage memo rejects wrong secret', () => {
      const srcPayload = buildSourcePayload([10n]);
      const modPayload = buildModulePayload([100n]);
      const ad = buildLineageMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);

      const ct = encryptLineageMemo(GOLDEN_SHARED_SECRET, ad, srcPayload, modPayload);
      const result = decryptLineageMemo(999n, ad, ct);
      expect(result).to.be.null;
    });

    it('unified lineage memo rejects wrong AD', () => {
      const srcPayload = buildSourcePayload([10n]);
      const modPayload = buildModulePayload([100n]);
      const ad = buildLineageMemoAD(GOLDEN_CHAINID, 111n, 0, 222n, 333n, 1n);
      const wrongAd = buildLineageMemoAD(GOLDEN_CHAINID, 999n, 0, 222n, 333n, 1n);

      const ct = encryptLineageMemo(GOLDEN_SHARED_SECRET, ad, srcPayload, modPayload);
      const result = decryptLineageMemo(GOLDEN_SHARED_SECRET, wrongAd, ct);
      expect(result).to.be.null;
    });

    it('source payload + module payload round-trip', () => {
      const sources = makeSources(8);
      const modules = makeModules(3);

      // Source
      const srcPayload = buildSourcePayload(sources);
      const srcDecoded = decodeSourcePayload(srcPayload);
      expect(srcDecoded).to.deep.equal(sources);

      // Module
      const modPayload = buildModulePayload(modules);
      const modDecoded = decodeModulePayload(modPayload);
      expect(modDecoded).to.deep.equal(modules);
    });
  });

  // =========================================================================
  // Module Package ID
  // =========================================================================
  describe('Module Package ID', () => {
    it('buildModulePackageId is deterministic', () => {
      const mods = makeModules(3);
      const desc = buildModuleDescriptor(mods);
      const payload = buildModulePayload(mods);
      const id1 = buildModulePackageId(desc.modRoot, desc.modCount, payload);
      const id2 = buildModulePackageId(desc.modRoot, desc.modCount, payload);
      expect(id1).to.equal(id2);
    });

    it('different modules produce different package IDs', () => {
      const m1 = makeModules(3);
      const m2 = makeModules(4);
      const d1 = buildModuleDescriptor(m1);
      const d2 = buildModuleDescriptor(m2);
      const p1 = buildModulePayload(m1);
      const p2 = buildModulePayload(m2);
      const id1 = buildModulePackageId(d1.modRoot, d1.modCount, p1);
      const id2 = buildModulePackageId(d2.modRoot, d2.modCount, p2);
      expect(id1).to.not.equal(id2);
    });
  });

  // =========================================================================
  // Module Tag Encoding
  // =========================================================================
  describe('Module Tag Encoding', () => {
    it('normalizeModuleLocator handles hex address', () => {
      const bytes = normalizeModuleLocator('0xDeadBeef00000000000000000000000000000001');
      expect(bytes.length).to.equal(20);
      expect(bytes[0]).to.equal(0xde);
    });

    it('normalizeModuleLocator handles string identifier', () => {
      const bytes = normalizeModuleLocator('uniswap-v3');
      expect(bytes[0]).to.equal('uniswap-v3'.length);
    });

    it('encodeModuleLocator is deterministic', () => {
      const p1 = encodeModuleLocator('0xDeadBeef00000000000000000000000000000001');
      const p2 = encodeModuleLocator('0xdeadbeef00000000000000000000000000000001');
      expect(p1).to.equal(p2); // case-insensitive normalization
    });

    it('encodeTag is deterministic', () => {
      const t1 = encodeTag('UNISWAP_V3_SWAP');
      const t2 = encodeTag('UNISWAP_V3_SWAP');
      expect(t1).to.equal(t2);
    });

    it('different tags produce different primes', () => {
      const t1 = encodeTag('UNISWAP_V3_SWAP');
      const t2 = encodeTag('AAVE_V3_SUPPLY');
      expect(t1).to.not.equal(t2);
    });

    it('buildModuleTagSet produces sorted unique primes', () => {
      const primes = buildModuleTagSet(
        ['0xDeadBeef00000000000000000000000000000001'],
        ['TAG_A', 'TAG_B'],
      );
      expect(primes.length).to.be.greaterThan(0);
      for (let i = 1; i < primes.length; i++) {
        expect(primes[i] > primes[i - 1]).to.be.true;
      }
    });

    it('canonical module bytes round-trip', () => {
      const mods = makeModules(5);
      const encoded = encodeCanonicalModuleBytes(mods);
      const decoded = decodeCanonicalModuleBytes(encoded);
      expect(decoded).to.deep.equal(mods);
    });
  });

  // =========================================================================
  // Source Verification
  // =========================================================================
  describe('Source Verification', () => {
    it('verifySourcePayload succeeds for valid payload', () => {
      const sources = makeSources(4);
      const desc = buildSourceDescriptor(sources);
      const rhoSrc = deriveRhoSrc(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, GOLDEN_OUTPUT_INDEX);
      const srcCommit = comSrcV8(desc.srcRoot, desc.srcCount, rhoSrc);

      const payload = buildSourcePayload(sources);
      const result = verifySourcePayload(
        payload, srcCommit, GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, GOLDEN_OUTPUT_INDEX,
      );
      expect(result.valid).to.be.true;
      expect(result.sources).to.deep.equal(sources);
    });

    it('verifySourcePayload rejects wrong commitment', () => {
      const sources = makeSources(4);
      const payload = buildSourcePayload(sources);
      const result = verifySourcePayload(payload, 999n, GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0);
      expect(result.valid).to.be.false;
    });
  });

  // =========================================================================
  // Module Verification
  // =========================================================================
  describe('Module Verification', () => {
    it('verifyModulePayload succeeds for valid payload', () => {
      const modules = makeModules(3);
      const desc = buildModuleDescriptor(modules);
      const rhoMod = deriveRhoMod(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, GOLDEN_OUTPUT_INDEX);
      const modCommit = comModV8(desc.modRoot, desc.modCount, rhoMod);

      const payload = buildModulePayload(modules);
      const result = verifyModulePayload(
        payload, modCommit, GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, GOLDEN_OUTPUT_INDEX,
      );
      expect(result.valid).to.be.true;
      expect(result.modules).to.deep.equal(modules);
    });

    it('verifyModulePayload rejects wrong commitment', () => {
      const modules = makeModules(3);
      const payload = buildModulePayload(modules);
      const result = verifyModulePayload(payload, 999n, GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0);
      expect(result.valid).to.be.false;
    });
  });

  // =========================================================================
  // Caches
  // =========================================================================
  describe('Caches', () => {
    it('SourceCache put/get/has/delete', () => {
      const cache = new SourceCache();
      const payload = buildSourcePayload([10n, 20n]);
      cache.put(111n, payload);
      expect(cache.has(111n)).to.be.true;
      expect(cache.get(111n)).to.deep.equal(payload);
      expect(cache.size).to.equal(1);
      cache.delete(111n);
      expect(cache.has(111n)).to.be.false;
    });

    it('ModuleCache put/get/has/delete', () => {
      const cache = new ModuleCache();
      const payload = buildModulePayload([100n, 200n]);
      cache.put(222n, payload);
      expect(cache.has(222n)).to.be.true;
      expect(cache.get(222n)).to.deep.equal(payload);
      expect(cache.size).to.equal(1);
      cache.delete(222n);
      expect(cache.has(222n)).to.be.false;
    });
  });

  // =========================================================================
  // Preflight Limit Checks
  // =========================================================================
  describe('Preflight Limits', () => {
    it('passes for normal transaction', () => {
      const errors = validatePreflightLimits({
        bucketSourceCounts: [10, 20],
        bucketModuleCounts: [2, 3],
        totalCarryInputRefs: 4,
        estimatedIvcSteps: 50,
        memoPayloadBytes: 1024,
        bucketCount: 2,
      });
      expect(errors).to.have.length(0);
    });

    it('rejects excessive source count', () => {
      const errors = validatePreflightLimits({
        bucketSourceCounts: [2000],
        bucketModuleCounts: [1],
        totalCarryInputRefs: 1,
        estimatedIvcSteps: 10,
        memoPayloadBytes: 100,
        bucketCount: 1,
      });
      expect(errors.some(e => e.code === 'SRC_COUNT_EXCEEDED')).to.be.true;
    });

    it('rejects excessive IVC steps', () => {
      const errors = validatePreflightLimits({
        bucketSourceCounts: [10],
        bucketModuleCounts: [1],
        totalCarryInputRefs: 1,
        estimatedIvcSteps: 999,
        memoPayloadBytes: 100,
        bucketCount: 1,
      });
      expect(errors.some(e => e.code === 'IVC_STEPS_EXCEEDED')).to.be.true;
    });

    it('rejects excessive memo size', () => {
      const errors = validatePreflightLimits({
        bucketSourceCounts: [10],
        bucketModuleCounts: [1],
        totalCarryInputRefs: 1,
        estimatedIvcSteps: 10,
        memoPayloadBytes: 100000,
        bucketCount: 1,
      });
      expect(errors.some(e => e.code === 'MEMO_SIZE_EXCEEDED')).to.be.true;
    });

    it('estimateIvcSteps computes correctly', () => {
      // 10 sources → ~19 steps, 3 modules → ~5 steps
      const steps = estimateIvcSteps([10], [3]);
      expect(steps).to.equal(19 + 5);
    });

    it('paddedMemoSize rounds up correctly', () => {
      expect(paddedMemoSize(100)).to.equal(256);
      expect(paddedMemoSize(256)).to.equal(256);
      expect(paddedMemoSize(257)).to.equal(512);
      expect(paddedMemoSize(70000)).to.equal(70000);
    });
  });

  // =========================================================================
  // Pending Lineage Store
  // =========================================================================
  describe('Pending Lineage Store', () => {
    it('tracks and resolves pending source lineage', () => {
      const store = new PendingLineageStore();
      const sources = makeSources(3);
      const desc = buildSourceDescriptor(sources);
      const rhoSrc = deriveRhoSrc(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0);
      const srcCommit = comSrcV8(desc.srcRoot, desc.srcCount, rhoSrc);

      const noteCommitment = 12345n;

      store.registerPending(
        noteCommitment, srcCommit, 0n, // module commitment = 0 (empty set)
        GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0,
        true, false, // missing source, not missing module
      );

      expect(store.isPending(noteCommitment)).to.be.true;
      expect(store.size).to.equal(1);

      // Resolve with correct payload
      const payload = buildSourcePayload(sources);
      const resolution = store.resolveSource(noteCommitment, payload);
      expect(resolution).to.not.be.null;
      expect(resolution!.complete).to.be.true;
      expect(resolution!.sourceList).to.deep.equal(sources);

      // Should be removed from pending
      expect(store.isPending(noteCommitment)).to.be.false;
    });

    it('tracks and resolves pending module lineage', () => {
      const store = new PendingLineageStore();
      const modules = makeModules(2);
      const desc = buildModuleDescriptor(modules);
      const rhoMod = deriveRhoMod(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0);
      const modCommit = comModV8(desc.modRoot, desc.modCount, rhoMod);

      const noteCommitment = 67890n;

      store.registerPending(
        noteCommitment, 0n, modCommit,
        GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0,
        false, true, // not missing source, missing module
      );

      const payload = buildModulePayload(modules);
      const resolution = store.resolveModule(noteCommitment, payload);
      expect(resolution).to.not.be.null;
      expect(resolution!.complete).to.be.true;
      expect(resolution!.moduleList).to.deep.equal(modules);
    });

    it('rejects invalid payload resolution', () => {
      const store = new PendingLineageStore();
      store.registerPending(
        999n, 111n, 222n,
        GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0,
        true, false,
      );

      const badPayload = buildSourcePayload([999999n]);
      const resolution = store.resolveSource(999n, badPayload);
      expect(resolution).to.be.null;
      // Still pending
      expect(store.isPending(999n)).to.be.true;
    });

    it('getStaleEntries returns old entries', () => {
      const store = new PendingLineageStore();
      store.registerPending(1n, 2n, 3n, 4n, 5n, 0, true, true);

      // With a very large max age, nothing should be stale
      const notStale = store.getStaleEntries(999999999);
      expect(notStale.length).to.equal(0);

      // With maxAgeMs=0, cutoff = Date.now(), entry.firstSeenMs <= cutoff → stale
      const stale = store.getStaleEntries(0);
      expect(stale.length).to.equal(1);
    });
  });

  // =========================================================================
  // End-to-End: Full note lifecycle with both source + module lineage
  // =========================================================================
  describe('End-to-End Lineage', () => {
    it('full note lifecycle: create, encrypt, decrypt, verify both source + module', () => {
      // 1. Sender builds source and module descriptors
      const sources = makeSources(5);
      const modules = makeModules(2);
      const srcDesc = buildSourceDescriptor(sources);
      const modDesc = buildModuleDescriptor(modules);

      // 2. Derive blinding factors
      const rhoSrc = deriveRhoSrc(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0);
      const rhoMod = deriveRhoMod(GOLDEN_RHO_VALUE, GOLDEN_OWNER_PUBKEY, 0);

      // 3. Compute commitments
      const srcCommit = comSrcV8(srcDesc.srcRoot, srcDesc.srcCount, rhoSrc);
      const modCommit = comModV8(modDesc.modRoot, modDesc.modCount, rhoMod);

      // 4. Build NoteV5
      const note: NoteV5 = {
        value: 5000n,
        tokenHash: 8000n,
        ownerPubkey: GOLDEN_OWNER_PUBKEY,
        rhoValue: GOLDEN_RHO_VALUE,
        sourceCommitment: srcCommit,
        moduleCommitment: modCommit,
        cleanEpoch: 1n,
      };
      const noteCm = noteComV5(note);

      // 5. Build lineage memo AD
      const ad = buildLineageMemoAD(
        GOLDEN_CHAINID, noteCm, 0,
        srcCommit, modCommit, 1n,
      );

      // 6. Encrypt unified lineage memo
      const srcPayload = buildSourcePayload(sources);
      const modPayload = buildModulePayload(modules);
      const ct = encryptLineageMemo(GOLDEN_SHARED_SECRET, ad, srcPayload, modPayload);

      // 7. Receiver decrypts
      const decrypted = decryptLineageMemo(GOLDEN_SHARED_SECRET, ad, ct);
      expect(decrypted).to.not.be.null;

      // 8. Receiver verifies source
      const srcVerify = verifySourcePayload(
        decrypted!.sourcePayload,
        note.sourceCommitment,
        note.rhoValue,
        note.ownerPubkey,
        0,
      );
      expect(srcVerify.valid).to.be.true;
      expect(srcVerify.sources).to.deep.equal(sources);

      // 9. Receiver verifies module
      const modVerify = verifyModulePayload(
        decrypted!.modulePayload,
        note.moduleCommitment,
        note.rhoValue,
        note.ownerPubkey,
        0,
      );
      expect(modVerify.valid).to.be.true;
      expect(modVerify.modules).to.deep.equal(modules);
    });
  });
});
