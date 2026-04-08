/**
 * v7 Source Compliance Proof Pipeline — Canonical Set Tree + Recursive IVC
 *
 * Composes the canonical relations from relations/ directory:
 * - ShieldV4: SrcSet={p_src}, ModSet=∅, canonical set tree roots
 * - TransferV4-fast: per-bucket R_MERGE_N exact union, all inputs current-clean
 * - TransferV4-refresh: same + R_SUBSET_FROM_TREE per bucket
 * - UnshieldV4-set: per-public-bucket exact aggregation + subset proof
 * - TypedCallV2 Exact/Boundary: R_TYPEDCALL_CANONICAL_V2 + R_TYPEDCALL_LINEAGE_V2
 */

import { CanonicalSourceSet } from './canonical-source-set';
import {
  buildCanonicalSetTree,
  CanonicalSetTree,
  verifyCanonicalSetTree,
} from './canonical-set-tree';
import { comSrc, comMod, NoteV4, noteComV4 } from './commitments';
import { poseidon } from '../utils/poseidon';
import { dstToFieldElement } from './commitments';
import {
  DST_LINEAGE_BIND_V2,
  DST_POLICY_BIND_V2,
  DST_BUCKET_SRC_COM_V1,
  DST_BUCKET_MOD_COM_V1,
  DST_BUCKET_SRC_IN_REF_V1,
  DST_BUCKET_MOD_IN_REF_V1,
  DST_BUCKET_META_V1,
} from './constants';
import { ManifestRegistry, deriveCarryIn } from './manifest-registry';

// ============================================================
// Bucket Lineage Commitments (v7)
// ============================================================

/** Per-bucket source commitment (spec: no tau, only DST + root + count + rho) */
export function bucketSrcCommit(
  srcRootOut: bigint,
  srcCountOut: number,
  rho: bigint,
): bigint {
  return poseidon([
    dstToFieldElement(DST_BUCKET_SRC_COM_V1),
    srcRootOut,
    BigInt(srcCountOut),
    rho,
  ]);
}

/** Per-bucket module commitment (spec: no tau, only DST + root + count + rho) */
export function bucketModCommit(
  modRootOut: bigint,
  modCountOut: number,
  rho: bigint,
): bigint {
  return poseidon([
    dstToFieldElement(DST_BUCKET_MOD_COM_V1),
    modRootOut,
    BigInt(modCountOut),
    rho,
  ]);
}

/** Per-bucket source input reference digest */
export function bucketSrcInRefDigest(
  tau: number,
  bucketRole: string,
  carriedInputRefList: bigint[],
): bigint {
  const dst = dstToFieldElement(DST_BUCKET_SRC_IN_REF_V1);
  let state = poseidon([dst, BigInt(tau)]);
  state = poseidon([state, dstToFieldElement(bucketRole)]);
  for (const ref of carriedInputRefList) {
    state = poseidon([state, ref]);
  }
  return state;
}

/** Per-bucket module input reference digest */
export function bucketModInRefDigest(
  tau: number,
  bucketRole: string,
  carriedInputRefList: bigint[],
): bigint {
  const dst = dstToFieldElement(DST_BUCKET_MOD_IN_REF_V1);
  let state = poseidon([dst, BigInt(tau)]);
  state = poseidon([state, dstToFieldElement(bucketRole)]);
  for (const ref of carriedInputRefList) {
    state = poseidon([state, ref]);
  }
  return state;
}

/**
 * Per-bucket meta commitment.
 * Spec field order: H(DST, bucketRole, srcInRefDigest, modInRefDigest, srcCommit, modCommit)
 * bucketRole is a semantic tag ("private_out", "public_out", "typedcall_out"), NOT bucket index tau.
 */
export function bucketMetaCommit(
  bucketRole: string,
  bSrcInRef: bigint,
  bModInRef: bigint,
  bSrcCom: bigint,
  bModCom: bigint,
): bigint {
  return poseidon([
    dstToFieldElement(DST_BUCKET_META_V1),
    dstToFieldElement(bucketRole),
    bSrcInRef,
    bModInRef,
    bSrcCom,
    bModCom,
  ]);
}

// ============================================================
// lineageBinding + policyBinding
// ============================================================

/**
 * Compute lineageBinding — unified binding of all bucket lineage commitments.
 * bucketCount MUST explicitly participate in hash (spec requirement).
 */
export function computeLineageBinding(
  chainid: bigint,
  verifierAddr: bigint,
  txType: string,
  bucketCount: number,
  bucketMetaCommits: bigint[],
): bigint {
  if (bucketMetaCommits.length !== bucketCount) {
    throw new Error(
      `lineageBinding: bucketMetaCommits.length (${bucketMetaCommits.length}) != bucketCount (${bucketCount})`,
    );
  }
  const dst = dstToFieldElement(DST_LINEAGE_BIND_V2);
  let state = poseidon([dst, chainid, verifierAddr]);
  state = poseidon([state, dstToFieldElement(txType), BigInt(bucketCount)]);
  for (const mc of bucketMetaCommits) {
    state = poseidon([state, mc]);
  }
  return state;
}

/**
 * Compute policyBinding — pins the policy snapshot.
 */
export function computePolicyBinding(
  chainid: bigint,
  verifierAddr: bigint,
  policyEpoch: number,
  regSeqUsed: number,
  aPolicyHash: bigint,
  qEpoch: bigint,
  subsetModeFlag: number,
): bigint {
  return poseidon([
    dstToFieldElement(DST_POLICY_BIND_V2),
    chainid,
    verifierAddr,
    BigInt(policyEpoch),
    BigInt(regSeqUsed),
    aPolicyHash,
    qEpoch,
    BigInt(subsetModeFlag),
  ]);
}

// ============================================================
// ShieldV4
// ============================================================

export interface V7ShieldResult {
  srcTree: CanonicalSetTree;
  modTree: CanonicalSetTree;
  srcCommitment: bigint;
  modCommitment: bigint;
  cleanEpoch: number;
  noteCommitment: bigint;
}

export function generateShieldV4(
  pSrc: bigint,
  rhoSrc: bigint,
  rhoMod: bigint,
  currentPolicyEpoch: number,
  noteFields: { value: bigint; tokenHash: bigint; ownerPubkey: bigint; rhoValue: bigint },
): V7ShieldResult {
  const srcTree = buildCanonicalSetTree('src', [pSrc]);
  const modTree = buildCanonicalSetTree('mod', []);

  const srcCommitment = comSrc(srcTree.root, srcTree.count, rhoSrc);
  const modCommitment = comMod(modTree.root, modTree.count, rhoMod);

  const note: NoteV4 = {
    value: noteFields.value,
    tokenHash: noteFields.tokenHash,
    ownerPubkey: noteFields.ownerPubkey,
    rhoValue: noteFields.rhoValue,
    sourceCommitment: srcCommitment,
    moduleCommitment: modCommitment,
    cleanEpoch: BigInt(currentPolicyEpoch),
  };

  return {
    srcTree,
    modTree,
    srcCommitment,
    modCommitment,
    cleanEpoch: currentPolicyEpoch,
    noteCommitment: noteComV4(note),
  };
}

// ============================================================
// TransferV4-fast
// ============================================================

export interface InputNoteLineage {
  note: NoteV4;
  nullifier: bigint;
  srcTree: CanonicalSetTree;
  modTree: CanonicalSetTree;
  cleanEpoch: number;
  /** Which token bucket this input belongs to */
  tokenBucket: number;
}

export interface V7TransferFastResult {
  /** Per-bucket output source trees */
  outputSrcTrees: CanonicalSetTree[];
  /** Per-bucket output module trees */
  outputModTrees: CanonicalSetTree[];
  /** Per-bucket source commitments */
  bucketSrcCommits: bigint[];
  /** Per-bucket module commitments */
  bucketModCommits: bigint[];
  /** Per-bucket meta commits */
  bucketMetaCommits: bigint[];
  lineageBinding: bigint;
  outputCleanEpoch: number;
}

export function generateTransferV4Fast(
  inputs: InputNoteLineage[],
  currentPolicyEpoch: number,
  rhosSrc: bigint[],
  rhosMod: bigint[],
  chainid: bigint,
  verifierAddr: bigint,
): V7TransferFastResult {
  // All inputs must be current-clean
  for (let i = 0; i < inputs.length; i++) {
    if (inputs[i].cleanEpoch !== currentPolicyEpoch) {
      throw new Error(`Input ${i} is stale: clean_epoch=${inputs[i].cleanEpoch} != current=${currentPolicyEpoch}`);
    }
  }

  // Group inputs by token bucket
  const bucketMap = groupByBucket(inputs);
  const bucketIndices = [...bucketMap.keys()].sort((a, b) => a - b);
  const bucketCount = bucketIndices.length;

  const outputSrcTrees: CanonicalSetTree[] = [];
  const outputModTrees: CanonicalSetTree[] = [];
  const bSrcCommits: bigint[] = [];
  const bModCommits: bigint[] = [];
  const bMetaCommits: bigint[] = [];

  for (let tauIdx = 0; tauIdx < bucketCount; tauIdx++) {
    const tau = bucketIndices[tauIdx];
    const bucketInputs = bucketMap.get(tau)!;

    // Exact union of source sets
    const srcPrimes = mergeUniqueSorted(bucketInputs.map(inp => inp.srcTree.leaves));
    const srcTree = buildCanonicalSetTree('src', srcPrimes);
    outputSrcTrees.push(srcTree);

    // Exact union of module sets
    const modPrimes = mergeUniqueSorted(bucketInputs.map(inp => inp.modTree.leaves));
    const modTree = buildCanonicalSetTree('mod', modPrimes);
    outputModTrees.push(modTree);

    // Bucket commitments
    const bSrc = bucketSrcCommit(srcTree.root, srcTree.count, rhosSrc[tauIdx]);
    const bMod = bucketModCommit(modTree.root, modTree.count, rhosMod[tauIdx]);
    bSrcCommits.push(bSrc);
    bModCommits.push(bMod);

    // Input reference digests
    const srcRefs = bucketInputs.map(inp => inp.note.sourceCommitment);
    const modRefs = bucketInputs.map(inp => inp.note.moduleCommitment);
    const bSrcRef = bucketSrcInRefDigest(tauIdx, 'private_out', srcRefs);
    const bModRef = bucketModInRefDigest(tauIdx, 'private_out', modRefs);

    bMetaCommits.push(bucketMetaCommit('private_out', bSrcRef, bModRef, bSrc, bMod));
  }

  const binding = computeLineageBinding(
    chainid, verifierAddr, 'TRANSFER_FAST', bucketCount, bMetaCommits,
  );

  return {
    outputSrcTrees,
    outputModTrees,
    bucketSrcCommits: bSrcCommits,
    bucketModCommits: bModCommits,
    bucketMetaCommits: bMetaCommits,
    lineageBinding: binding,
    outputCleanEpoch: currentPolicyEpoch,
  };
}

// ============================================================
// TransferV4-refresh
// ============================================================

export interface V7TransferRefreshResult extends V7TransferFastResult {
  policyBinding: bigint;
}

export function generateTransferV4Refresh(
  inputs: InputNoteLineage[],
  policyEpoch: number,
  regSeqUsed: number,
  aPolicyHash: bigint,
  qEpoch: bigint,
  rhosSrc: bigint[],
  rhosMod: bigint[],
  chainid: bigint,
  verifierAddr: bigint,
): V7TransferRefreshResult {
  // Same exact union logic as fast, but no clean_epoch check on inputs
  const bucketMap = groupByBucket(inputs);
  const bucketIndices = [...bucketMap.keys()].sort((a, b) => a - b);
  const bucketCount = bucketIndices.length;

  const outputSrcTrees: CanonicalSetTree[] = [];
  const outputModTrees: CanonicalSetTree[] = [];
  const bSrcCommits: bigint[] = [];
  const bModCommits: bigint[] = [];
  const bMetaCommits: bigint[] = [];

  for (let tauIdx = 0; tauIdx < bucketCount; tauIdx++) {
    const tau = bucketIndices[tauIdx];
    const bucketInputs = bucketMap.get(tau)!;

    const srcPrimes = mergeUniqueSorted(bucketInputs.map(inp => inp.srcTree.leaves));
    const srcTree = buildCanonicalSetTree('src', srcPrimes);
    outputSrcTrees.push(srcTree);

    const modPrimes = mergeUniqueSorted(bucketInputs.map(inp => inp.modTree.leaves));
    const modTree = buildCanonicalSetTree('mod', modPrimes);
    outputModTrees.push(modTree);

    const bSrc = bucketSrcCommit(srcTree.root, srcTree.count, rhosSrc[tauIdx]);
    const bMod = bucketModCommit(modTree.root, modTree.count, rhosMod[tauIdx]);
    bSrcCommits.push(bSrc);
    bModCommits.push(bMod);

    const srcRefs = bucketInputs.map(inp => inp.note.sourceCommitment);
    const modRefs = bucketInputs.map(inp => inp.note.moduleCommitment);
    const bSrcRef = bucketSrcInRefDigest(tauIdx, 'private_out', srcRefs);
    const bModRef = bucketModInRefDigest(tauIdx, 'private_out', modRefs);

    bMetaCommits.push(bucketMetaCommit('private_out', bSrcRef, bModRef, bSrc, bMod));
  }

  const lineageBinding = computeLineageBinding(
    chainid, verifierAddr, 'TRANSFER_REFRESH', bucketCount, bMetaCommits,
  );
  const policyBinding = computePolicyBinding(
    chainid, verifierAddr, policyEpoch, regSeqUsed, aPolicyHash, qEpoch, 0,
  );

  return {
    outputSrcTrees,
    outputModTrees,
    bucketSrcCommits: bSrcCommits,
    bucketModCommits: bModCommits,
    bucketMetaCommits: bMetaCommits,
    lineageBinding,
    policyBinding,
    outputCleanEpoch: policyEpoch,
  };
}

// ============================================================
// UnshieldV4-set
// ============================================================

export interface V7UnshieldSetResult {
  outputSrcTrees: CanonicalSetTree[];
  outputModTrees: CanonicalSetTree[];
  bucketSrcCommits: bigint[];
  bucketModCommits: bigint[];
  bucketMetaCommits: bigint[];
  lineageBinding: bigint;
  policyBinding: bigint;
}

export function generateUnshieldV4Set(
  inputs: InputNoteLineage[],
  publicBucketTokens: bigint[],
  policyEpoch: number,
  regSeqUsed: number,
  aPolicyHash: bigint,
  qEpoch: bigint,
  rhosSrc: bigint[],
  rhosMod: bigint[],
  chainid: bigint,
  verifierAddr: bigint,
): V7UnshieldSetResult {
  const bucketMap = groupByBucket(inputs);
  const bucketCount = publicBucketTokens.length;

  const outputSrcTrees: CanonicalSetTree[] = [];
  const outputModTrees: CanonicalSetTree[] = [];
  const bSrcCommits: bigint[] = [];
  const bModCommits: bigint[] = [];
  const bMetaCommits: bigint[] = [];

  for (let tau = 0; tau < bucketCount; tau++) {
    const bucketInputs = bucketMap.get(tau) ?? [];

    const srcPrimes = mergeUniqueSorted(bucketInputs.map(inp => inp.srcTree.leaves));
    const srcTree = buildCanonicalSetTree('src', srcPrimes);
    outputSrcTrees.push(srcTree);

    const modPrimes = mergeUniqueSorted(bucketInputs.map(inp => inp.modTree.leaves));
    const modTree = buildCanonicalSetTree('mod', modPrimes);
    outputModTrees.push(modTree);

    const bSrc = bucketSrcCommit(srcTree.root, srcTree.count, rhosSrc[tau]);
    const bMod = bucketModCommit(modTree.root, modTree.count, rhosMod[tau]);
    bSrcCommits.push(bSrc);
    bModCommits.push(bMod);

    const srcRefs = bucketInputs.map(inp => inp.note.sourceCommitment);
    const modRefs = bucketInputs.map(inp => inp.note.moduleCommitment);
    const bSrcRef = bucketSrcInRefDigest(tau, 'public_out', srcRefs);
    const bModRef = bucketModInRefDigest(tau, 'public_out', modRefs);

    bMetaCommits.push(bucketMetaCommit('public_out', bSrcRef, bModRef, bSrc, bMod));
  }

  const lineageBinding = computeLineageBinding(
    chainid, verifierAddr, 'UNSHIELD_SET', bucketCount, bMetaCommits,
  );
  const policyBinding = computePolicyBinding(
    chainid, verifierAddr, policyEpoch, regSeqUsed, aPolicyHash, qEpoch, 0,
  );

  return {
    outputSrcTrees,
    outputModTrees,
    bucketSrcCommits: bSrcCommits,
    bucketModCommits: bModCommits,
    bucketMetaCommits: bMetaCommits,
    lineageBinding,
    policyBinding,
  };
}

// ============================================================
// TypedCallV2 Exact + Boundary
// ============================================================

export interface V7TypedCallResult {
  outputSrcTrees: CanonicalSetTree[];
  outputModTrees: CanonicalSetTree[];
  bucketSrcCommits: bigint[];
  bucketModCommits: bigint[];
  bucketMetaCommits: bigint[];
  lineageBinding: bigint;
  stepClass: 'EXACT' | 'BOUNDARY';
}

/**
 * Generate TypedCallV2 lineage for Exact modules.
 * SrcSet/ModSet are exact unions of carried inputs per flow matrix.
 * tagTree, flowMatrix, codeHash all resolved from manifest internally.
 */
export function generateTypedCallV2Exact(
  inputs: InputNoteLineage[],
  moduleManifestHash: bigint,
  manifestRegistry: ManifestRegistry,
  rhosSrc: bigint[],
  rhosMod: bigint[],
  chainid: bigint,
  verifierAddr: bigint,
): V7TypedCallResult {
  const resolved = manifestRegistry.resolveManifest(moduleManifestHash);
  const flowMatrix = resolved.flowMatrix;
  const bucketCount = flowMatrix.outputBucketCount;
  const inputBucketAssignment = inputs.map(inp => inp.tokenBucket);

  const outputSrcTrees: CanonicalSetTree[] = [];
  const outputModTrees: CanonicalSetTree[] = [];
  const bSrcCommits: bigint[] = [];
  const bModCommits: bigint[] = [];
  const bMetaCommits: bigint[] = [];

  for (let tau = 0; tau < bucketCount; tau++) {
    const carryIndices = deriveCarryIn(flowMatrix, tau, inputBucketAssignment);

    const srcPrimes = mergeUniqueSorted(carryIndices.map(i => inputs[i].srcTree.leaves));
    const srcTree = buildCanonicalSetTree('src', srcPrimes);
    outputSrcTrees.push(srcTree);

    const modPrimes = mergeUniqueSorted(carryIndices.map(i => inputs[i].modTree.leaves));
    const modTree = buildCanonicalSetTree('mod', modPrimes);
    outputModTrees.push(modTree);

    const bSrc = bucketSrcCommit(srcTree.root, srcTree.count, rhosSrc[tau]);
    const bMod = bucketModCommit(modTree.root, modTree.count, rhosMod[tau]);
    bSrcCommits.push(bSrc);
    bModCommits.push(bMod);

    const srcRefs = carryIndices.map(i => inputs[i].note.sourceCommitment);
    const modRefs = carryIndices.map(i => inputs[i].note.moduleCommitment);
    const bSrcRef = bucketSrcInRefDigest(tau, 'typedcall_out', srcRefs);
    const bModRef = bucketModInRefDigest(tau, 'typedcall_out', modRefs);

    bMetaCommits.push(bucketMetaCommit('typedcall_out', bSrcRef, bModRef, bSrc, bMod));
  }

  const binding = computeLineageBinding(
    chainid, verifierAddr, 'TYPEDCALL_EXACT', bucketCount, bMetaCommits,
  );

  return {
    outputSrcTrees,
    outputModTrees,
    bucketSrcCommits: bSrcCommits,
    bucketModCommits: bModCommits,
    bucketMetaCommits: bMetaCommits,
    lineageBinding: binding,
    stepClass: 'EXACT',
  };
}

/**
 * Generate TypedCallV2 lineage for Boundary modules.
 * SrcSet: exact union of carried inputs.
 * ModSet: exact union of carried inputs UNION TagTreeByOutputBucket[τ] from manifest.
 * tagTreeByOutputBucket resolved from manifest, NOT external parameter.
 */
export function generateTypedCallV2Boundary(
  inputs: InputNoteLineage[],
  moduleManifestHash: bigint,
  manifestRegistry: ManifestRegistry,
  rhosSrc: bigint[],
  rhosMod: bigint[],
  chainid: bigint,
  verifierAddr: bigint,
): V7TypedCallResult {
  const resolved = manifestRegistry.resolveManifest(moduleManifestHash);
  const flowMatrix = resolved.flowMatrix;
  const tagTree = resolved.tagTreeByOutputBucket;
  const bucketCount = flowMatrix.outputBucketCount;
  const inputBucketAssignment = inputs.map(inp => inp.tokenBucket);

  const outputSrcTrees: CanonicalSetTree[] = [];
  const outputModTrees: CanonicalSetTree[] = [];
  const bSrcCommits: bigint[] = [];
  const bModCommits: bigint[] = [];
  const bMetaCommits: bigint[] = [];

  for (let tau = 0; tau < bucketCount; tau++) {
    const carryIndices = deriveCarryIn(flowMatrix, tau, inputBucketAssignment);

    // Source: exact union of carried inputs
    const srcPrimes = mergeUniqueSorted(carryIndices.map(i => inputs[i].srcTree.leaves));
    const srcTree = buildCanonicalSetTree('src', srcPrimes);
    outputSrcTrees.push(srcTree);

    // Module: exact union of carried inputs UNION tag tree for this bucket
    const carriedModPrimes = mergeUniqueSorted(carryIndices.map(i => inputs[i].modTree.leaves));
    const tagPrimes = tagTree.tagTrees[tau]?.primes ?? [];
    const allModPrimes = mergeUniqueSorted([carriedModPrimes, tagPrimes]);
    const modTree = buildCanonicalSetTree('mod', allModPrimes);
    outputModTrees.push(modTree);

    const bSrc = bucketSrcCommit(srcTree.root, srcTree.count, rhosSrc[tau]);
    const bMod = bucketModCommit(modTree.root, modTree.count, rhosMod[tau]);
    bSrcCommits.push(bSrc);
    bModCommits.push(bMod);

    const srcRefs = carryIndices.map(i => inputs[i].note.sourceCommitment);
    const modRefs = carryIndices.map(i => inputs[i].note.moduleCommitment);
    const bSrcRef = bucketSrcInRefDigest(tau, 'typedcall_out', srcRefs);
    const bModRef = bucketModInRefDigest(tau, 'typedcall_out', modRefs);

    bMetaCommits.push(bucketMetaCommit('typedcall_out', bSrcRef, bModRef, bSrc, bMod));
  }

  const binding = computeLineageBinding(
    chainid, verifierAddr, 'TYPEDCALL_BOUNDARY', bucketCount, bMetaCommits,
  );

  return {
    outputSrcTrees,
    outputModTrees,
    bucketSrcCommits: bSrcCommits,
    bucketModCommits: bModCommits,
    bucketMetaCommits: bMetaCommits,
    lineageBinding: binding,
    stepClass: 'BOUNDARY',
  };
}

// ============================================================
// Helpers
// ============================================================

function groupByBucket(inputs: InputNoteLineage[]): Map<number, InputNoteLineage[]> {
  const map = new Map<number, InputNoteLineage[]>();
  for (const inp of inputs) {
    const existing = map.get(inp.tokenBucket);
    if (existing) {
      existing.push(inp);
    } else {
      map.set(inp.tokenBucket, [inp]);
    }
  }
  return map;
}

/**
 * Merge multiple sorted bigint arrays into a single sorted, unique array.
 */
function mergeUniqueSorted(arrays: (readonly bigint[])[]): bigint[] {
  const allSet = new Set<bigint>();
  for (const arr of arrays) {
    for (const p of arr) allSet.add(p);
  }
  return [...allSet].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
