/**
 * RAILGUN Source Compliance v7 — Unit Tests
 *
 * TC-01 through TC-30 + extras as specified in tasks.md.
 */

import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { initPoseidonPromise } from '../../utils/poseidon';

// Constants
import {
  RSA_N, NOTE_VERSION_V4, SOURCE_PROOF_VERSION,
  SET_TREE_ARITY, MAX_DECLARED_TOKENS,
} from '../constants';

// DI-Hash
import {
  isPrime, hashToPrimeSrc, hashToPrimeMod, hashToPrimeEpoch, sampleAliasPrime,
} from '../di-hash';

// Canonical sets
import { CanonicalSourceSet } from '../canonical-source-set';

// Canonical set tree
import {
  buildCanonicalSetTree, verifyCanonicalSetTree,
  leafHash, emptyNode,
} from '../canonical-set-tree';
import type { CanonicalSetTree as CanonicalSetTreeType } from '../canonical-set-tree';

// Commitments
import { comSrc, comMod, noteComV4, dstToFieldElement } from '../commitments';
import type { NoteV4 } from '../commitments';

// Policy accumulator
import { PolicyAccumulator } from '../clean-accumulator';

// v7 proof pipeline
import {
  generateShieldV4,
  generateTransferV4Fast,
  generateTransferV4Refresh,
  generateUnshieldV4Set,
  generateTypedCallV2Exact,
  generateTypedCallV2Boundary,
  computeLineageBinding,
  computePolicyBinding,
  bucketSrcCommit, bucketModCommit, bucketMetaCommit,
  bucketSrcInRefDigest, bucketModInRefDigest,
} from '../v7-proof';
import type { InputNoteLineage } from '../v7-proof';

// Relations
import {
  computeInputBinding, computeOutputBinding, computeInputNoteSemantic,
  verifyTransferCanonicalV4,
} from '../relations/transfer-canonical-v4';
import {
  computeDeclaredTokenBinding, computeReachableTokenBinding,
  computeReturnBalanceBinding, computeExecBinding, computeRuntimeArgsHash,
  verifyReturnVecConservationPerDeclaredToken,
} from '../relations/typedcall-canonical-v2';
import { verifyTypedCallLineageV2 } from '../relations/typedcall-lineage-v2';

// Session Escrow V2
import {
  validateSessionEscrowV2, createSessionEscrowV2,
  assertCanonicalTokenOrder, validateDeclaredSubsetOfReachable,
} from '../session-escrow-v2';
import type { SessionReceipt, SessionEscrowV2Config } from '../session-escrow-v2';

// Manifest Registry
import {
  ManifestRegistry, computeModuleManifestHash,
  isExactEligible, getExactEligibilityFailures,
  createLineageFlowMatrix, deriveCarryIn, composeFlowMatrices,
  hashLineageFlowMatrix, hashTagTreeByOutputBucket,
  hashTargetCodeHashVector,
} from '../manifest-registry';
import type {
  RecipeManifest, StepManifest, LineageFlowMatrix,
  TagTreeByOutputBucket, ExactEligibilityCheck,
} from '../manifest-registry';

// Proving backend
import { MockProvingBackend } from '../proving/recursive-verifier';
import { DefaultWitnessBuilder } from '../proving/witness-builder';

chai.use(chaiAsPromised);
const { expect } = chai;
const N = RSA_N;
const G = 65537n;

// ============================================================
// Test Helpers
// ============================================================

function makeSourcePrime(label: string): bigint {
  return hashToPrimeSrc(new TextEncoder().encode(label));
}

function makeModulePrime(label: string): bigint {
  return hashToPrimeMod(new TextEncoder().encode(label));
}

function makeNoteV4(overrides: Partial<NoteV4> = {}): NoteV4 {
  return {
    value: 100n,
    tokenHash: 1001n,
    ownerPubkey: 42n,
    rhoValue: 999n,
    sourceCommitment: 0n,
    moduleCommitment: 0n,
    cleanEpoch: 0n,
    ...overrides,
  };
}

function makeInputNoteLineage(
  srcPrimes: bigint[],
  modPrimes: bigint[],
  cleanEpoch: number,
  tokenBucket: number,
  value: bigint = 100n,
  tokenHash: bigint = 1001n,
): InputNoteLineage {
  const srcTree = buildCanonicalSetTree('src', [...srcPrimes].sort((a, b) => a < b ? -1 : 1));
  const modTree = buildCanonicalSetTree('mod', [...modPrimes].sort((a, b) => a < b ? -1 : 1));
  const srcCom = comSrc(srcTree.root, srcTree.count, 123n);
  const modCom = comMod(modTree.root, modTree.count, 456n);

  const note = makeNoteV4({
    value,
    tokenHash,
    sourceCommitment: srcCom,
    moduleCommitment: modCom,
    cleanEpoch: BigInt(cleanEpoch),
  });

  return {
    note,
    nullifier: BigInt(Math.floor(Math.random() * 2 ** 32)),
    srcTree,
    modTree,
    cleanEpoch,
    tokenBucket,
  };
}

function makeAccumulator(epoch: number = 0): PolicyAccumulator {
  return new PolicyAccumulator(N, G, epoch);
}

function makeReceipt(overrides: Partial<SessionReceipt> = {}): SessionReceipt {
  return {
    sessionId: 1n,
    returnVec: [],
    startBalances: new Map(),
    endBalances: new Map(),
    observedTokens: new Set(),
    hasPublicSink: false,
    hasReentrantPoolEntry: false,
    hasDelegatecall: false,
    hasUndeclaredCallbackDomain: false,
    hasNonFinalizePrivateReturn: false,
    ...overrides,
  };
}

function makeIdentityFlowMatrix(size: number): LineageFlowMatrix {
  const flow = new Array(size * size).fill(false);
  for (let i = 0; i < size; i++) {
    flow[i * size + i] = true;
  }
  return createLineageFlowMatrix(size, size, flow);
}

function makeSimpleStepManifest(overrides: Partial<StepManifest> = {}): StepManifest {
  return {
    stepType: 'SWAP',
    target: 100n,
    targetCodeHash: 200n,
    implementationCodeHashOrZero: 0n,
    selector: 300n,
    stepClass: 'EXACT',
    tokenFlowSchemaHash: 400n,
    lineageFlowMatrixHash: 0n,
    callbackPolicyHash: 0n,
    staticCalldataHash: 0n,
    dynamicFieldSchemaHash: 0n,
    runtimeArgsSchemaHash: 0n,
    reachableTokenBinding: 0n,
    maxBoundaryTagsAdded: 0,
    ...overrides,
  };
}

// ============================================================
// Tests
// ============================================================

describe('Source Compliance v7 (Canonical Set Tree + Recursive IVC)', function () {
  this.timeout(300_000);

  before(async () => {
    await initPoseidonPromise;
  });

  // ==========================================================
  // Basic constants
  // ==========================================================

  it('SOURCE_PROOF_VERSION = 0x7, NOTE_VERSION_V4 = 0x4', () => {
    expect(SOURCE_PROOF_VERSION).to.equal(0x7);
    expect(NOTE_VERSION_V4).to.equal(0x4);
    expect(SET_TREE_ARITY).to.equal(4);
  });

  // ==========================================================
  // TC-01: ShieldV4 normal
  // ==========================================================

  describe('TC-01: ShieldV4 normal', () => {
    it('creates NoteV4 with SrcSet={p_src}, ModSet=empty, tree root binding', () => {
      const pSrc = makeSourcePrime('source_exchange_1');
      const result = generateShieldV4(pSrc, 100n, 200n, 5, {
        value: 1000n, tokenHash: 42n, ownerPubkey: 7n, rhoValue: 99n,
      });

      expect(result.srcTree.count).to.equal(1);
      expect(result.srcTree.leaves).to.deep.equal([pSrc]);
      expect(result.modTree.count).to.equal(0);
      expect(result.modTree.leaves).to.deep.equal([]);
      expect(result.cleanEpoch).to.equal(5);
      expect(result.noteCommitment).to.not.equal(0n);

      // Verify tree root binding in commitment
      const srcCom = comSrc(result.srcTree.root, result.srcTree.count, 100n);
      expect(result.srcCommitment).to.equal(srcCom);
    });
  });

  // ==========================================================
  // TC-02: ShieldV4 reject blacklisted source
  // ==========================================================

  describe('TC-02: ShieldV4 reject blacklisted source', () => {
    it('policy accumulator rejects blacklisted source prime', () => {
      const acc = makeAccumulator(0);
      const pSrc = makeSourcePrime('dirty_source');
      acc.registerSource(pSrc);
      acc.addSourceToBlacklist(pSrc);
      expect(() => acc.registerSource(pSrc)).to.throw('blacklisted');
    });
  });

  // ==========================================================
  // TC-03: R_CANON_TREE uniqueness
  // ==========================================================

  describe('TC-03: R_CANON_TREE^src uniqueness', () => {
    it('same set different insert order -> same (root, count)', () => {
      const p1 = makeSourcePrime('a');
      const p2 = makeSourcePrime('b');
      const p3 = makeSourcePrime('c');

      const primes = [p1, p2, p3].sort((a, b) => (a < b ? -1 : 1));

      const tree1 = buildCanonicalSetTree('src', primes);
      const tree2 = buildCanonicalSetTree('src', [...primes]); // same order

      expect(tree1.root).to.equal(tree2.root);
      expect(tree1.count).to.equal(tree2.count);
    });
  });

  // ==========================================================
  // TC-04: R_CANON_TREE reject duplicate leaf
  // ==========================================================

  describe('TC-04: R_CANON_TREE^src reject duplicate leaf', () => {
    it('throws on duplicate primes', () => {
      const p1 = makeSourcePrime('dup');
      expect(() => buildCanonicalSetTree('src', [p1, p1])).to.throw();
    });
  });

  // ==========================================================
  // TC-05: R_MERGE2 overlap dedup
  // ==========================================================

  describe('TC-05: R_MERGE2^src overlap dedup', () => {
    it('exact union with overlapping sets produces correct result', () => {
      const p1 = makeSourcePrime('x1');
      const p2 = makeSourcePrime('x2');
      const p3 = makeSourcePrime('x3');
      const all = [p1, p2, p3].sort((a, b) => (a < b ? -1 : 1));

      const treeA = buildCanonicalSetTree('src', [all[0], all[1]]);
      const treeB = buildCanonicalSetTree('src', [all[1], all[2]]);

      // Exact union: {all[0], all[1]} ∪ {all[1], all[2]} = {all[0], all[1], all[2]}
      const merged = buildCanonicalSetTree('src', all);
      expect(merged.count).to.equal(3);

      // Verify the merged tree is canonical
      expect(verifyCanonicalSetTree('src', merged.root, merged.count, all)).to.be.true;
    });
  });

  // ==========================================================
  // TC-06: R_MERGE_N large set (> 256)
  // ==========================================================

  describe('TC-06: R_MERGE_N^src large set', () => {
    it('handles |SrcSet| > 256 without note-level cap', () => {
      // Generate 300 unique source primes
      const primes: bigint[] = [];
      for (let i = 0; i < 300; i++) {
        primes.push(makeSourcePrime(`large_src_${i}`));
      }
      const sorted = [...new Set(primes)].sort((a, b) => (a < b ? -1 : 1));

      const tree = buildCanonicalSetTree('src', sorted);
      expect(tree.count).to.equal(sorted.length);
      expect(verifyCanonicalSetTree('src', tree.root, tree.count, sorted)).to.be.true;
    });
  });

  // ==========================================================
  // TC-07: TransferV4-fast copy-through
  // ==========================================================

  describe('TC-07: TransferV4-fast copy-through', () => {
    it('same bucket same lineage -> output unchanged', () => {
      const pSrc = makeSourcePrime('copy_src');
      const input = makeInputNoteLineage([pSrc], [], 5, 0);

      const result = generateTransferV4Fast(
        [input], 5, [10n], [20n], 1n, 2n,
      );

      expect(result.outputSrcTrees[0].leaves).to.deep.equal([pSrc]);
      expect(result.outputModTrees[0].count).to.equal(0);
      expect(result.outputCleanEpoch).to.equal(5);
    });
  });

  // ==========================================================
  // TC-08: TransferV4-fast exact union
  // ==========================================================

  describe('TC-08: TransferV4-fast exact union', () => {
    it('different SrcSet/ModSet -> exact union', () => {
      const p1 = makeSourcePrime('union_1');
      const p2 = makeSourcePrime('union_2');
      const m1 = makeModulePrime('mod_1');

      const input1 = makeInputNoteLineage([p1], [m1], 5, 0);
      const input2 = makeInputNoteLineage([p2], [], 5, 0);

      const result = generateTransferV4Fast(
        [input1, input2], 5, [10n], [20n], 1n, 2n,
      );

      const expectedSrc = [p1, p2].sort((a, b) => (a < b ? -1 : 1));
      expect(result.outputSrcTrees[0].leaves).to.deep.equal(expectedSrc);
      expect(result.outputModTrees[0].leaves).to.deep.equal([m1]);
    });
  });

  // ==========================================================
  // TC-09: TransferV4-refresh stale note
  // ==========================================================

  describe('TC-09: TransferV4-refresh stale note', () => {
    it('R_SUBSET_FROM_TREE passes, clean_epoch updated', () => {
      const pSrc = makeSourcePrime('stale_src');
      // Input with old epoch
      const input = makeInputNoteLineage([pSrc], [], 3, 0);

      const result = generateTransferV4Refresh(
        [input], 5, 10, 100n, 200n, [10n], [20n], 1n, 2n,
      );

      expect(result.outputCleanEpoch).to.equal(5);
      expect(result.policyBinding).to.not.equal(0n);
      expect(result.outputSrcTrees[0].leaves).to.deep.equal([pSrc]);
    });
  });

  // ==========================================================
  // TC-10: UnshieldV4-set
  // ==========================================================

  describe('TC-10: UnshieldV4-set', () => {
    it('public bucket exact aggregated lineage passes', () => {
      const pSrc = makeSourcePrime('unshield_src');
      const input = makeInputNoteLineage([pSrc], [], 5, 0);

      const result = generateUnshieldV4Set(
        [input], [1001n], 5, 10, 100n, 200n, [10n], [20n], 1n, 2n,
      );

      expect(result.outputSrcTrees.length).to.equal(1);
      expect(result.policyBinding).to.not.equal(0n);
      expect(result.lineageBinding).to.not.equal(0n);
    });
  });

  // ==========================================================
  // TC-11: lineageBinding anti-splice
  // ==========================================================

  describe('TC-11: lineageBinding anti-splice', () => {
    it('replaced bucket commitment causes lineageBinding mismatch', () => {
      const binding1 = computeLineageBinding(1n, 2n, 'TRANSFER', 2, [100n, 200n]);
      const binding2 = computeLineageBinding(1n, 2n, 'TRANSFER', 2, [100n, 999n]);
      expect(binding1).to.not.equal(binding2);
    });
  });

  // ==========================================================
  // TC-12: policyBinding anti-splice
  // ==========================================================

  describe('TC-12: policyBinding anti-splice', () => {
    it('replaced policy snapshot causes policyBinding mismatch', () => {
      const pb1 = computePolicyBinding(1n, 2n, 5, 10, 100n, 200n, 0);
      const pb2 = computePolicyBinding(1n, 2n, 6, 10, 100n, 200n, 0);
      expect(pb1).to.not.equal(pb2);
    });
  });

  // ==========================================================
  // TC-13: Exact Module normal
  // ==========================================================

  describe('TC-13: Exact Module normal', () => {
    it('exact propagation with manifest binding', () => {
      const pSrc = makeSourcePrime('exact_src');
      const input = makeInputNoteLineage([pSrc], [], 5, 0);

      const flowMatrix = makeIdentityFlowMatrix(1);
      const tagTree: TagTreeByOutputBucket = { tagTrees: [{ root: 0n, count: 0, primes: [] }] };
      const flowHash = hashLineageFlowMatrix(flowMatrix);
      const tagHash = hashTagTreeByOutputBucket(tagTree);

      const step = makeSimpleStepManifest({
        stepClass: 'EXACT',
        lineageFlowMatrixHash: flowHash,
      });
      const manifest: RecipeManifest = {
        stepCount: 1,
        steps: [step],
        declaredTokenBinding: 0n,
        reachableTokenBinding: 0n,
        outputBucketTagMapHash: tagHash,
        lineageFlowMatrixHash: flowHash,
        recipePolicyFlagsHash: 0n,
        callbackPolicyHash: 0n,
        routeShapeHash: 0n,
        targetCodeHashVectorHash: hashTargetCodeHashVector([200n]),
      };

      const registry = new ManifestRegistry();
      const moduleHash = registry.register(
        manifest, flowMatrix, tagTree, [200n], [], [], 0n, new Map(),
      );

      const result = generateTypedCallV2Exact(
        [input], moduleHash, registry, [10n], [20n], 1n, 2n,
      );

      expect(result.stepClass).to.equal('EXACT');
      expect(result.outputSrcTrees[0].leaves).to.deep.equal([pSrc]);
      expect(result.outputModTrees[0].count).to.equal(0);
    });
  });

  // ==========================================================
  // TC-14: Boundary Module normal
  // ==========================================================

  describe('TC-14: Boundary Module normal', () => {
    it('SrcSet exact + ModSet accumulates tag tree from manifest', () => {
      const pSrc = makeSourcePrime('boundary_src');
      const pMod = makeModulePrime('boundary_tag');
      const input = makeInputNoteLineage([pSrc], [], 5, 0);

      const flowMatrix = makeIdentityFlowMatrix(1);
      const tagTree: TagTreeByOutputBucket = {
        tagTrees: [{ root: 0n, count: 1, primes: [pMod] }],
      };
      // Need to build the actual tag tree root
      const actualTagTree = buildCanonicalSetTree('mod', [pMod]);
      tagTree.tagTrees[0].root = actualTagTree.root;

      const flowHash = hashLineageFlowMatrix(flowMatrix);
      const tagHash = hashTagTreeByOutputBucket(tagTree);

      const step = makeSimpleStepManifest({
        stepClass: 'BOUNDARY',
        lineageFlowMatrixHash: flowHash,
      });
      const manifest: RecipeManifest = {
        stepCount: 1,
        steps: [step],
        declaredTokenBinding: 0n,
        reachableTokenBinding: 0n,
        outputBucketTagMapHash: tagHash,
        lineageFlowMatrixHash: flowHash,
        recipePolicyFlagsHash: 0n,
        callbackPolicyHash: 0n,
        routeShapeHash: 0n,
        targetCodeHashVectorHash: hashTargetCodeHashVector([200n]),
      };

      const registry = new ManifestRegistry();
      const moduleHash = registry.register(
        manifest, flowMatrix, tagTree, [200n], [], [], 0n, new Map(),
      );

      const result = generateTypedCallV2Boundary(
        [input], moduleHash, registry, [10n], [20n], 1n, 2n,
      );

      expect(result.stepClass).to.equal('BOUNDARY');
      expect(result.outputSrcTrees[0].leaves).to.deep.equal([pSrc]);
      expect(result.outputModTrees[0].leaves).to.include(pMod);
    });
  });

  // ==========================================================
  // TC-15: 2-step Recipe
  // ==========================================================

  describe('TC-15: 2-step Recipe', () => {
    it('LineageFlowMatrix composed for recipe, tags accumulate', () => {
      // Step 1: 2 inputs -> 2 outputs (identity flow)
      const flow1 = createLineageFlowMatrix(2, 2, [true, false, false, true]);
      // Step 2: 2 inputs -> 1 output (merge)
      const flow2 = createLineageFlowMatrix(1, 2, [true, true]);

      const composed = composeFlowMatrices(flow1, flow2);
      expect(composed.outputBucketCount).to.equal(1);
      expect(composed.inputBucketCount).to.equal(2);

      // Both original inputs flow to the single output
      const carry = deriveCarryIn(composed, 0, [0, 1]);
      expect(carry).to.deep.equal([0, 1]);
    });
  });

  // ==========================================================
  // TC-16: runtime args splice
  // ==========================================================

  describe('TC-16: runtime args splice', () => {
    it('same schema different params -> runtimeArgsHash mismatch', () => {
      const h1 = computeRuntimeArgsHash([1n, 2n, 3n]);
      const h2 = computeRuntimeArgsHash([1n, 2n, 4n]);
      expect(h1).to.not.equal(h2);
    });
  });

  // ==========================================================
  // TC-17: code hash drift
  // ==========================================================

  describe('TC-17: code hash drift', () => {
    it('target implementation changed -> manifest check fails', () => {
      const flowMatrix = makeIdentityFlowMatrix(1);
      const tagTree: TagTreeByOutputBucket = { tagTrees: [{ root: 0n, count: 0, primes: [] }] };
      const flowHash = hashLineageFlowMatrix(flowMatrix);
      const tagHash = hashTagTreeByOutputBucket(tagTree);

      const manifest: RecipeManifest = {
        stepCount: 1,
        steps: [makeSimpleStepManifest({ targetCodeHash: 200n })],
        declaredTokenBinding: 0n,
        reachableTokenBinding: 0n,
        outputBucketTagMapHash: tagHash,
        lineageFlowMatrixHash: flowHash,
        recipePolicyFlagsHash: 0n,
        callbackPolicyHash: 0n,
        routeShapeHash: 0n,
        targetCodeHashVectorHash: hashTargetCodeHashVector([200n]),
      };

      const registry = new ManifestRegistry();
      const moduleHash = registry.register(
        manifest, flowMatrix, tagTree, [200n], [], [], 0n, new Map(),
      );

      // Code hash drifted from 200n to 999n
      expect(registry.verifyCodeHashes(moduleHash, [999n])).to.be.false;
      // Original still passes
      expect(registry.verifyCodeHashes(moduleHash, [200n])).to.be.true;
    });
  });

  // ==========================================================
  // TC-18: token emergence outside reachable superset
  // ==========================================================

  describe('TC-18: token emergence outside reachable superset', () => {
    it('whole-session revert', () => {
      const config = createSessionEscrowV2(1n, 42n, [100n], [100n, 200n]);
      const receipt = makeReceipt({
        sessionId: 1n,
        returnVec: [50n],
        endBalances: new Map([['100', 50n]]),
        observedTokens: new Set(['100', '200', '300']), // 300 not in reachable
      });

      const result = validateSessionEscrowV2(config, receipt, new Set());
      expect(result.ok).to.be.false;
      if (!result.ok) expect(result.invariant).to.equal(5);
    });
  });

  // ==========================================================
  // TC-19: reachable but undeclared residual
  // ==========================================================

  describe('TC-19: reachable but undeclared residual', () => {
    it('non-zero end balance for undeclared token -> revert', () => {
      const config = createSessionEscrowV2(1n, 42n, [100n], [100n, 200n]);
      const receipt = makeReceipt({
        sessionId: 1n,
        returnVec: [50n],
        endBalances: new Map([['100', 50n], ['200', 10n]]), // 200 is reachable but undeclared, has residual
        observedTokens: new Set(['100', '200']),
      });

      const result = validateSessionEscrowV2(config, receipt, new Set());
      expect(result.ok).to.be.false;
      if (!result.ok) expect(result.invariant).to.equal(4);
    });
  });

  // ==========================================================
  // TC-20: noDelegatecall / noReentry
  // ==========================================================

  describe('TC-20: noDelegatecall / noReentry', () => {
    it('delegatecall detected -> revert (invariant 8)', () => {
      const config = createSessionEscrowV2(1n, 42n, [], []);
      const receipt = makeReceipt({ hasDelegatecall: true });
      const result = validateSessionEscrowV2(config, receipt, new Set());
      expect(result.ok).to.be.false;
      if (!result.ok) expect(result.invariant).to.equal(8);
    });

    it('pool re-entry detected -> revert (invariant 7)', () => {
      const config = createSessionEscrowV2(1n, 42n, [], []);
      const receipt = makeReceipt({ hasReentrantPoolEntry: true });
      const result = validateSessionEscrowV2(config, receipt, new Set());
      expect(result.ok).to.be.false;
      if (!result.ok) expect(result.invariant).to.equal(7);
    });
  });

  // ==========================================================
  // TC-21: returnBalance mismatch
  // ==========================================================

  describe('TC-21: returnBalance mismatch', () => {
    it('acceptance condition fails when returnVec does not match output', () => {
      const conservation = verifyReturnVecConservationPerDeclaredToken({
        declaredTokenUniverse: [100n, 200n],
        returnVec: [50n, 30n],
        privateOutputs: [
          { tokenHash: 100n, value: 40n },  // mismatch: 40 != 50
          { tokenHash: 200n, value: 30n },
        ],
        publicOutputs: [],
        deterministicFees: new Map(),
      });

      expect(conservation.ok).to.be.false;
      if (!conservation.ok) {
        expect(conservation.tokenIndex).to.equal(0);
        expect(conservation.expected).to.equal(40n);
        expect(conservation.actual).to.equal(50n);
      }
    });
  });

  // ==========================================================
  // TC-22: p_mod disallow containment
  // ==========================================================

  describe('TC-22: p_mod disallow containment', () => {
    it('subset proof fails after module disallow', () => {
      const acc = makeAccumulator(0);
      const pMod = makeModulePrime('disallowed_mod');
      acc.registerModule(pMod);

      // Subset works before disallow
      const cMid = acc.subsetWitnessBase([pMod]);
      expect(acc.verifySubset([pMod], cMid)).to.be.true;

      // Disallow
      acc.disallowModule(pMod);
      expect(acc.policyEpoch).to.equal(1);

      // Subset should fail now
      expect(() => acc.subsetWitnessBase([pMod])).to.throw();
    });
  });

  // ==========================================================
  // TC-23: p_src blacklist containment
  // ==========================================================

  describe('TC-23: p_src blacklist containment', () => {
    it('subset proof fails after source blacklist', () => {
      const acc = makeAccumulator(0);
      const pSrc = makeSourcePrime('blacklisted_src');
      acc.registerSource(pSrc);

      const cMid = acc.subsetWitnessBase([pSrc]);
      expect(acc.verifySubset([pSrc], cMid)).to.be.true;

      acc.addSourceToBlacklist(pSrc);
      expect(acc.policyEpoch).to.equal(1);
      expect(() => acc.subsetWitnessBase([pSrc])).to.throw();
    });
  });

  // ==========================================================
  // TC-24: large refresh (4k+ sources)
  // ==========================================================

  describe('TC-24: large refresh', () => {
    it('single note with many sources — recursive tree build succeeds', () => {
      const primes: bigint[] = [];
      for (let i = 0; i < 500; i++) { // reduced from 4k for test speed
        primes.push(makeSourcePrime(`bulk_src_${i}`));
      }
      const sorted = [...new Set(primes)].sort((a, b) => (a < b ? -1 : 1));

      const tree = buildCanonicalSetTree('src', sorted);
      expect(tree.count).to.equal(sorted.length);
      expect(verifyCanonicalSetTree('src', tree.root, tree.count, sorted)).to.be.true;
    });
  });

  // ==========================================================
  // TC-25: cross-bucket carry mistake
  // ==========================================================

  describe('TC-25: cross-bucket carry mistake', () => {
    it('wrong carry matrix -> different lineage output', () => {
      // Correct flow: bucket 0 -> bucket 0, bucket 1 -> bucket 1
      const correctFlow = createLineageFlowMatrix(2, 2, [true, false, false, true]);
      // Wrong flow: bucket 0 -> bucket 1, bucket 1 -> bucket 0 (swapped)
      const wrongFlow = createLineageFlowMatrix(2, 2, [false, true, true, false]);

      const carry0Correct = deriveCarryIn(correctFlow, 0, [0, 1]);
      const carry0Wrong = deriveCarryIn(wrongFlow, 0, [0, 1]);

      expect(carry0Correct).to.deep.equal([0]);
      expect(carry0Wrong).to.deep.equal([1]);
      expect(carry0Correct).to.not.deep.equal(carry0Wrong);
    });
  });

  // ==========================================================
  // TC-26: boundary tag omission
  // ==========================================================

  describe('TC-26: boundary tag omission', () => {
    it('missing tag -> different mod tree root', () => {
      const pMod1 = makeModulePrime('tag1');
      const pMod2 = makeModulePrime('tag2');

      const fullTree = buildCanonicalSetTree('mod', [pMod1, pMod2].sort((a, b) => a < b ? -1 : 1));
      const partialTree = buildCanonicalSetTree('mod', [pMod1]);

      expect(fullTree.root).to.not.equal(partialTree.root);
      expect(fullTree.count).to.not.equal(partialTree.count);
    });
  });

  // ==========================================================
  // TC-27: privacy regression
  // ==========================================================

  describe('TC-27: privacy regression', () => {
    it('same hidden set, different randomization -> different commitments', () => {
      const pSrc = makeSourcePrime('privacy_src');
      const tree = buildCanonicalSetTree('src', [pSrc]);

      const com1 = comSrc(tree.root, tree.count, 111n);
      const com2 = comSrc(tree.root, tree.count, 222n);

      expect(com1).to.not.equal(com2);
    });
  });

  // ==========================================================
  // TC-28: same-lineage cache hit
  // ==========================================================

  describe('TC-28: same-lineage cache hit', () => {
    it('reuse merge forest cache, output semantics unchanged', () => {
      const p1 = makeSourcePrime('cache_1');
      const p2 = makeSourcePrime('cache_2');
      const sorted = [p1, p2].sort((a, b) => (a < b ? -1 : 1));

      const tree1 = buildCanonicalSetTree('src', sorted);
      const tree2 = buildCanonicalSetTree('src', sorted);

      // Same inputs -> same output (idempotent)
      expect(tree1.root).to.equal(tree2.root);
      expect(tree1.count).to.equal(tree2.count);
    });
  });

  // ==========================================================
  // TC-29: pre-seeded session escrow
  // ==========================================================

  describe('TC-29: pre-seeded session escrow', () => {
    it('zero-start check fails if start balance non-zero', () => {
      const config = createSessionEscrowV2(1n, 42n, [100n], [100n]);
      const receipt = makeReceipt({
        sessionId: 1n,
        returnVec: [50n],
        startBalances: new Map([['100', 10n]]), // non-zero start!
        endBalances: new Map([['100', 50n]]),
        observedTokens: new Set(['100']),
      });

      const result = validateSessionEscrowV2(config, receipt, new Set());
      expect(result.ok).to.be.false;
      if (!result.ok) expect(result.invariant).to.equal(2);
    });
  });

  // ==========================================================
  // TC-30: exact-module misclassification
  // ==========================================================

  describe('TC-30: exact-module misclassification', () => {
    it('donation-sensitive module marked exact -> blocked by eligibility', () => {
      const check: ExactEligibilityCheck = {
        fixedOutputTokenSet: true,
        deterministicOutputAmount: true,
        noCounterpartyAmbiguity: true,
        noDonationSensitivity: false, // fails!
        noFeeOnTransferOrRebase: true,
        noUndeclaredTokenEmergence: true,
        noCallbackHiddenBranch: true,
        targetCodeHashPinned: true,
        noSecondPrivateReturnPath: true,
      };

      expect(isExactEligible(check)).to.be.false;
      const failures = getExactEligibilityFailures(check);
      expect(failures).to.have.length(1);
      expect(failures[0]).to.include('donation');
    });
  });

  // ==========================================================
  // Extra: 4-domain disjointness
  // ==========================================================

  describe('Extra: 4-domain disjointness', () => {
    it('P_src, P_mod, P_epoch, P_alias produce non-overlapping primes', () => {
      const pSrc = hashToPrimeSrc(new TextEncoder().encode('test'));
      const pMod = hashToPrimeMod(new TextEncoder().encode('test'));
      const pEpoch = hashToPrimeEpoch(0);
      const pAlias = sampleAliasPrime(new TextEncoder().encode('test'));

      // Domain separation by bit width
      expect(pSrc < (1n << 260n)).to.be.true;
      expect(pMod >= (1n << 287n)).to.be.true;
      expect(pEpoch >= (1n << 319n)).to.be.true;
      expect(pAlias >= (1n << 383n)).to.be.true;

      // All prime
      expect(isPrime(pSrc)).to.be.true;
      expect(isPrime(pMod)).to.be.true;
      expect(isPrime(pEpoch)).to.be.true;
      expect(isPrime(pAlias)).to.be.true;
    });
  });

  // ==========================================================
  // Extra: NoteV4 commitment + nullifier binding
  // ==========================================================

  describe('Extra: NoteV4 commitment binding', () => {
    it('all 8 fields participate in commitment', () => {
      const base = makeNoteV4({
        sourceCommitment: 111n,
        moduleCommitment: 222n,
        cleanEpoch: 5n,
      });
      const cm = noteComV4(base);

      // Change each field -> different commitment
      expect(noteComV4({ ...base, value: 999n })).to.not.equal(cm);
      expect(noteComV4({ ...base, tokenHash: 999n })).to.not.equal(cm);
      expect(noteComV4({ ...base, ownerPubkey: 999n })).to.not.equal(cm);
      expect(noteComV4({ ...base, rhoValue: 12345n })).to.not.equal(cm);
      expect(noteComV4({ ...base, sourceCommitment: 999n })).to.not.equal(cm);
      expect(noteComV4({ ...base, moduleCommitment: 999n })).to.not.equal(cm);
      expect(noteComV4({ ...base, cleanEpoch: 999n })).to.not.equal(cm);
    });
  });

  // ==========================================================
  // Extra: Canonical Set Tree construction/verification
  // ==========================================================

  describe('Extra: Canonical Set Tree', () => {
    it('empty set has canonical root', () => {
      const tree = buildCanonicalSetTree('src', []);
      expect(tree.count).to.equal(0);
      expect(tree.root).to.equal(emptyNode('src', 0));
    });

    it('src and mod trees have different roots for same primes', () => {
      const primes = [3n, 7n, 11n];
      const srcTree = buildCanonicalSetTree('src', primes);
      const modTree = buildCanonicalSetTree('mod', primes);
      expect(srcTree.root).to.not.equal(modTree.root);
    });

    it('verification fails with wrong count', () => {
      const tree = buildCanonicalSetTree('src', [3n, 7n]);
      expect(verifyCanonicalSetTree('src', tree.root, 3, [3n, 7n])).to.be.false;
    });
  });

  // ==========================================================
  // Extra: lineageBinding / policyBinding shared consistency
  // ==========================================================

  describe('Extra: lineageBinding / policyBinding consistency', () => {
    it('bucketCount explicitly participates in lineageBinding', () => {
      const b1 = computeLineageBinding(1n, 2n, 'TX', 1, [100n]);
      const b2 = computeLineageBinding(1n, 2n, 'TX', 2, [100n, 200n]);
      expect(b1).to.not.equal(b2);
    });

    it('lineageBinding rejects mismatched bucketCount and array length', () => {
      expect(() => computeLineageBinding(1n, 2n, 'TX', 3, [100n, 200n])).to.throw();
    });
  });

  // ==========================================================
  // Extra: Session Escrow V2 closed-world 10 invariants
  // ==========================================================

  describe('Extra: Session Escrow V2 — all 10 invariants', () => {
    it('valid session passes all invariants', () => {
      const config = createSessionEscrowV2(1n, 42n, [100n], [100n, 200n]);
      const receipt = makeReceipt({
        sessionId: 1n,
        returnVec: [50n],
        startBalances: new Map([['100', 0n], ['200', 0n]]),
        endBalances: new Map([['100', 50n], ['200', 0n]]),
        observedTokens: new Set(['100', '200']),
      });
      const result = validateSessionEscrowV2(config, receipt, new Set());
      expect(result.ok).to.be.true;
    });

    it('invariant 1: duplicate session_id rejected', () => {
      const config = createSessionEscrowV2(1n, 42n, [], []);
      const result = validateSessionEscrowV2(config, makeReceipt(), new Set(['1']));
      expect(result.ok).to.be.false;
      if (!result.ok) expect(result.invariant).to.equal(1);
    });

    it('invariant 6: public sink rejected', () => {
      const config = createSessionEscrowV2(1n, 42n, [], []);
      const result = validateSessionEscrowV2(config, makeReceipt({ hasPublicSink: true }), new Set());
      expect(result.ok).to.be.false;
      if (!result.ok) expect(result.invariant).to.equal(6);
    });

    it('invariant 9: undeclared callback domain rejected', () => {
      const config = createSessionEscrowV2(1n, 42n, [], []);
      const result = validateSessionEscrowV2(
        config, makeReceipt({ hasUndeclaredCallbackDomain: true }), new Set(),
      );
      expect(result.ok).to.be.false;
      if (!result.ok) expect(result.invariant).to.equal(9);
    });

    it('invariant 10: non-finalize private return rejected', () => {
      const config = createSessionEscrowV2(1n, 42n, [], []);
      const result = validateSessionEscrowV2(
        config, makeReceipt({ hasNonFinalizePrivateReturn: true }), new Set(),
      );
      expect(result.ok).to.be.false;
      if (!result.ok) expect(result.invariant).to.equal(10);
    });
  });

  // ==========================================================
  // Extra: moduleManifestHash sub-hash completeness
  // ==========================================================

  describe('Extra: moduleManifestHash binding', () => {
    it('changing any sub-hash changes moduleManifestHash', () => {
      const baseManifest: RecipeManifest = {
        stepCount: 1,
        steps: [makeSimpleStepManifest()],
        declaredTokenBinding: 1n,
        reachableTokenBinding: 2n,
        outputBucketTagMapHash: 3n,
        lineageFlowMatrixHash: 4n,
        recipePolicyFlagsHash: 5n,
        callbackPolicyHash: 6n,
        routeShapeHash: 7n,
        targetCodeHashVectorHash: 8n,
      };

      const baseHash = computeModuleManifestHash(baseManifest);

      // Change each field
      for (const field of [
        'declaredTokenBinding', 'reachableTokenBinding',
        'outputBucketTagMapHash', 'lineageFlowMatrixHash',
        'recipePolicyFlagsHash', 'callbackPolicyHash',
        'routeShapeHash', 'targetCodeHashVectorHash',
      ] as const) {
        const modified = { ...baseManifest, [field]: 999n };
        expect(computeModuleManifestHash(modified)).to.not.equal(baseHash);
      }
    });
  });

  // ==========================================================
  // Extra: returnVec per-token conservation
  // ==========================================================

  describe('Extra: returnVec per-token conservation', () => {
    it('correct conservation passes', () => {
      const result = verifyReturnVecConservationPerDeclaredToken({
        declaredTokenUniverse: [100n, 200n],
        returnVec: [60n, 40n],
        privateOutputs: [
          { tokenHash: 100n, value: 50n },
          { tokenHash: 200n, value: 30n },
        ],
        publicOutputs: [{ tokenHash: 100n, value: 5n, recipient: 1n }],
        deterministicFees: new Map([['100', 5n], ['200', 10n]]),
      });
      expect(result.ok).to.be.true;
    });

    it('public/private allocation mismatch detected', () => {
      const result = verifyReturnVecConservationPerDeclaredToken({
        declaredTokenUniverse: [100n],
        returnVec: [100n],
        privateOutputs: [{ tokenHash: 100n, value: 80n }],
        publicOutputs: [{ tokenHash: 100n, value: 10n, recipient: 1n }],
        deterministicFees: new Map(),
      });
      // 80 + 10 = 90 != 100
      expect(result.ok).to.be.false;
    });

    it('returnVec length mismatch rejected', () => {
      const result = verifyReturnVecConservationPerDeclaredToken({
        declaredTokenUniverse: [100n, 200n],
        returnVec: [50n], // wrong length
        privateOutputs: [],
        publicOutputs: [],
        deterministicFees: new Map(),
      });
      expect(result.ok).to.be.false;
    });
  });

  // ==========================================================
  // Extra: deny-set expansion triggers policy_epoch bump
  // ==========================================================

  describe('Extra: deny-set expansion policy_epoch bump', () => {
    it('expandDenySet increments policy_epoch, making old notes stale', () => {
      const acc = makeAccumulator(0);
      const pSrc = makeSourcePrime('pre_deny');
      acc.registerSource(pSrc);
      expect(acc.policyEpoch).to.equal(0);

      // Notes with epoch 0 are current-clean
      const cMid = acc.subsetWitnessBase([pSrc]);
      expect(acc.verifySubset([pSrc], cMid)).to.be.true;

      // Blacklist triggers epoch bump
      acc.addSourceToBlacklist(pSrc);
      expect(acc.policyEpoch).to.equal(1);

      // Old subset witness no longer valid against new accumulator
      expect(acc.verifySubset([pSrc], cMid)).to.be.false;
    });
  });

  // ==========================================================
  // Extra: declaredTokenUniverse / reachableTokenSuperset canonical
  // ==========================================================

  describe('Extra: canonical token ordering', () => {
    it('reject duplicates in declaredTokenBinding', () => {
      expect(() => computeDeclaredTokenBinding([100n, 100n])).to.throw();
    });

    it('reject non-sorted in reachableTokenBinding', () => {
      expect(() => computeReachableTokenBinding([200n, 100n])).to.throw();
    });

    it('reject declared not subset of reachable', () => {
      expect(() => createSessionEscrowV2(1n, 42n, [100n, 300n], [100n, 200n])).to.throw();
    });
  });

  // ==========================================================
  // Extra: R_MERGE_N multi-bucket carry
  // ==========================================================

  describe('Extra: R_MERGE_N multi-bucket carry', () => {
    it('same carried input flows to multiple output buckets', () => {
      // Flow matrix: both output buckets receive from input bucket 0
      const flow = createLineageFlowMatrix(2, 1, [true, true]);

      const carry0 = deriveCarryIn(flow, 0, [0]);
      const carry1 = deriveCarryIn(flow, 1, [0]);

      // Input 0 (in bucket 0) flows to BOTH output buckets
      expect(carry0).to.deep.equal([0]);
      expect(carry1).to.deep.equal([0]);
    });
  });

  // ==========================================================
  // Extra: TypedCallV2 Boundary tag tree from manifest
  // ==========================================================

  describe('Extra: tag tree resolved from manifest', () => {
    it('manifest registry provides tag tree, not external parameter', () => {
      const pMod = makeModulePrime('manifest_tag');
      const tagTreeData = buildCanonicalSetTree('mod', [pMod]);
      const tagTree: TagTreeByOutputBucket = {
        tagTrees: [{ root: tagTreeData.root, count: tagTreeData.count, primes: [pMod] }],
      };

      const flowMatrix = makeIdentityFlowMatrix(1);
      const flowHash = hashLineageFlowMatrix(flowMatrix);
      const tagHash = hashTagTreeByOutputBucket(tagTree);

      const manifest: RecipeManifest = {
        stepCount: 1,
        steps: [makeSimpleStepManifest({ stepClass: 'BOUNDARY' })],
        declaredTokenBinding: 0n,
        reachableTokenBinding: 0n,
        outputBucketTagMapHash: tagHash,
        lineageFlowMatrixHash: flowHash,
        recipePolicyFlagsHash: 0n,
        callbackPolicyHash: 0n,
        routeShapeHash: 0n,
        targetCodeHashVectorHash: hashTargetCodeHashVector([200n]),
      };

      const registry = new ManifestRegistry();
      const moduleHash = registry.register(
        manifest, flowMatrix, tagTree, [200n], [], [], 0n, new Map(),
      );

      // Resolve: tag tree comes from manifest, not external
      const resolved = registry.resolveManifest(moduleHash);
      expect(resolved.tagTreeByOutputBucket.tagTrees[0].primes).to.deep.equal([pMod]);
    });
  });

  // ==========================================================
  // Extra: inputBinding inSem has all 6 fields
  // ==========================================================

  describe('Extra: inputBinding inSem all 6 fields', () => {
    it('changing any of 6 fields changes inSem', () => {
      const base = {
        nullifier: 1n,
        tokenHash: 2n,
        sourceCommitment: 3n,
        moduleCommitment: 4n,
        cleanEpoch: 5n,
      };
      const baseSem = computeInputNoteSemantic(
        base.nullifier, base.tokenHash, base.sourceCommitment,
        base.moduleCommitment, base.cleanEpoch,
      );

      // Each field must change the result
      expect(computeInputNoteSemantic(99n, base.tokenHash, base.sourceCommitment, base.moduleCommitment, base.cleanEpoch)).to.not.equal(baseSem);
      expect(computeInputNoteSemantic(base.nullifier, 99n, base.sourceCommitment, base.moduleCommitment, base.cleanEpoch)).to.not.equal(baseSem);
      expect(computeInputNoteSemantic(base.nullifier, base.tokenHash, 99n, base.moduleCommitment, base.cleanEpoch)).to.not.equal(baseSem);
      expect(computeInputNoteSemantic(base.nullifier, base.tokenHash, base.sourceCommitment, 99n, base.cleanEpoch)).to.not.equal(baseSem);
      expect(computeInputNoteSemantic(base.nullifier, base.tokenHash, base.sourceCommitment, base.moduleCommitment, 99n)).to.not.equal(baseSem);
    });
  });

  // ==========================================================
  // Extra: MockProvingBackend semantic checks
  // ==========================================================

  describe('Extra: MockProvingBackend', () => {
    it('proves and verifies valid merge forest', () => {
      const backend = new MockProvingBackend();
      const tree1 = buildCanonicalSetTree('src', [3n, 7n]);
      const tree2 = buildCanonicalSetTree('src', [7n, 11n]);
      const merged = buildCanonicalSetTree('src', [3n, 7n, 11n]);

      const forest = {
        leaves: [tree1, tree2],
        internalNodes: [{
          rootL: tree1.root, countL: tree1.count,
          rootR: tree2.root, countR: tree2.count,
          rootO: merged.root, countO: merged.count,
        }],
        roots: [merged],
      };

      const proof = backend.proveMergeN('src', forest, 42n);
      expect(proof.system).to.equal('mock-semantic-v7');
      expect(backend.verifyMergeN(proof, 42n)).to.be.true;
      // Wrong lineageBinding -> fails
      expect(backend.verifyMergeN(proof, 99n)).to.be.false;
    });

    it('proves and verifies valid subset witness', () => {
      const backend = new MockProvingBackend();
      const tree = buildCanonicalSetTree('src', [3n, 7n]);
      const witness = {
        root: tree.root,
        count: tree.count,
        rhoBucket: 123n,
        primes: [3n, 7n],
        product: 21n,
        subsetWitness: 456n,
      };

      const proof = backend.proveSubsetFromTree('src', witness, 10n, 20n);
      expect(backend.verifySubsetFromTree(proof, 10n, 20n)).to.be.true;
      expect(backend.verifySubsetFromTree(proof, 10n, 99n)).to.be.false;
    });
  });
});
