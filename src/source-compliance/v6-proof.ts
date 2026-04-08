/**
 * v6 Source Compliance Proof Pipeline — Dual Lineage (SrcSet + ModSet)
 *
 * 1. ShieldV3: SrcSet={p_src}, ModSet={}
 * 2. TransferV3 fast: dual exact union, all inputs current-clean
 * 3. TransferV3 refresh: dual union + dual subset proof
 * 4. UnshieldV3: dual per-bucket subset proof
 * 5. TypedCallV1: Exact (ModSet unchanged) or Boundary (ModSet += tags)
 */

import { CanonicalSourceSet } from './canonical-source-set';
import { PolicyAccumulator } from './clean-accumulator';
import { comSrcset, comModset, commitVec } from './commitments';
import { setDigestSrc, setDigestMod } from './set-digest';
import { createAlias, liftWitness, verifyAliasSubset } from './alias';

// ============================================================
// Interfaces
// ============================================================

export interface DualLineage {
  srcSet: CanonicalSourceSet;
  modSet: CanonicalSourceSet; // empty for shield, accumulated for boundary modules
}

export interface V6ShieldResult {
  srcCommitment: bigint;
  modCommitment: bigint;
  srcDigest: bigint;
  modDigest: bigint;
  cleanEpoch: number;
}

export interface V6TransferFastResult {
  outputSrcCommitment: bigint;
  outputModCommitment: bigint;
  outputSrcDigest: bigint;
  outputModDigest: bigint;
  outputCleanEpoch: number;
}

export interface V6TransferRefreshProof {
  outputSrcCommitment: bigint;
  outputModCommitment: bigint;
  cPSrc: bigint; // commitVec for source set
  cPMod: bigint; // commitVec for module set
  cMid: bigint;
  aAlias: bigint;
  outputCleanEpoch: number;
  regSeqUsed: number;
}

export interface V6UnshieldProof {
  srcCommitment: bigint;
  modCommitment: bigint;
  cPSrc: bigint;
  cPMod: bigint;
  cMid: bigint;
  aAlias: bigint;
  blEpoch: number;
  regSeqUsed: number;
}

export interface V6TypedCallResult {
  outputSrcCommitment: bigint;
  outputModCommitment: bigint;
  outputSrcDigest: bigint;
  outputModDigest: bigint;
  outputCleanEpoch: number;
  moduleType: 'exact' | 'boundary';
}

// ============================================================
// ShieldV3
// ============================================================

export function generateShieldV3(
  pSrc: bigint,
  rhoSrc: bigint,
  rhoMod: bigint,
  currentPolicyEpoch: number,
): V6ShieldResult {
  const srcSet = CanonicalSourceSet.singleton(pSrc);
  const modSet = new CanonicalSourceSet([]); // empty for shield
  const srcDigest = setDigestSrc(srcSet);
  const modDigest = setDigestMod(modSet);
  return {
    srcCommitment: comSrcset(srcDigest, rhoSrc),
    modCommitment: comModset(modDigest, rhoMod),
    srcDigest,
    modDigest,
    cleanEpoch: currentPolicyEpoch,
  };
}

// ============================================================
// TransferV3 Fast Path
// ============================================================

export function generateTransferV3Fast(
  inputLineages: DualLineage[],
  inputCleanEpochs: number[],
  currentPolicyEpoch: number,
  rhoSrcOut: bigint,
  rhoModOut: bigint,
): V6TransferFastResult {
  for (let i = 0; i < inputCleanEpochs.length; i++) {
    if (inputCleanEpochs[i] !== currentPolicyEpoch) {
      throw new Error(`Input ${i} is stale: clean_epoch=${inputCleanEpochs[i]} != current=${currentPolicyEpoch}`);
    }
  }

  const outputSrcSet = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.srcSet));
  const outputModSet = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.modSet));
  const srcDigest = setDigestSrc(outputSrcSet);
  const modDigest = setDigestMod(outputModSet);

  return {
    outputSrcCommitment: comSrcset(srcDigest, rhoSrcOut),
    outputModCommitment: comModset(modDigest, rhoModOut),
    outputSrcDigest: srcDigest,
    outputModDigest: modDigest,
    outputCleanEpoch: currentPolicyEpoch,
  };
}

export function verifyTransferV3Fast(
  result: V6TransferFastResult,
  inputLineages: DualLineage[],
  currentPolicyEpoch: number,
): boolean {
  if (result.outputCleanEpoch !== currentPolicyEpoch) return false;
  const expectedSrc = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.srcSet));
  const expectedMod = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.modSet));
  if (result.outputSrcDigest !== setDigestSrc(expectedSrc)) return false;
  if (result.outputModDigest !== setDigestMod(expectedMod)) return false;
  return true;
}

// ============================================================
// TransferV3 Refresh Path
// ============================================================

export function generateTransferV3Refresh(
  inputLineages: DualLineage[],
  rhoSrcOut: bigint,
  rhoModOut: bigint,
  rhoPSrc: bigint,
  rhoPMod: bigint,
  acc: PolicyAccumulator,
  qAlias: bigint,
  N: bigint,
): V6TransferRefreshProof {
  const outputSrcSet = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.srcSet));
  const outputModSet = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.modSet));
  const srcDigest = setDigestSrc(outputSrcSet);
  const modDigest = setDigestMod(outputModSet);

  const cPSrc = commitVec([...outputSrcSet.primes], rhoPSrc);
  const cPMod = commitVec([...outputModSet.primes], rhoPMod);

  // Combined subset: all source + module primes must be in allowed set
  const allPrimes = [...outputSrcSet.primes, ...outputModSet.primes];
  const cMidBase = acc.subsetWitnessBase(allPrimes);
  const aAlias = createAlias(acc.accumulator, qAlias, N);
  const cMid = liftWitness(cMidBase, qAlias, N);

  return {
    outputSrcCommitment: comSrcset(srcDigest, rhoSrcOut),
    outputModCommitment: comModset(modDigest, rhoModOut),
    cPSrc,
    cPMod,
    cMid,
    aAlias,
    outputCleanEpoch: acc.policyEpoch,
    regSeqUsed: acc.regSeq,
  };
}

export function verifyTransferV3Refresh(
  proof: V6TransferRefreshProof,
  inputLineages: DualLineage[],
  acc: PolicyAccumulator,
  N: bigint,
): boolean {
  const expectedSrc = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.srcSet));
  const expectedMod = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.modSet));
  if (proof.outputCleanEpoch !== acc.policyEpoch) return false;
  if (proof.regSeqUsed > acc.regSeq) return false;

  // Verify combined subset
  const allPrimes = [...expectedSrc.primes, ...expectedMod.primes];
  return verifyAliasSubset(allPrimes, proof.cMid, proof.aAlias, acc.qEpoch, N);
}

// ============================================================
// UnshieldV3
// ============================================================

export function generateUnshieldV3(
  lineage: DualLineage,
  rhoSrc: bigint,
  rhoMod: bigint,
  rhoPSrc: bigint,
  rhoPMod: bigint,
  acc: PolicyAccumulator,
  qAlias: bigint,
  N: bigint,
): V6UnshieldProof {
  const srcDigest = setDigestSrc(lineage.srcSet);
  const modDigest = setDigestMod(lineage.modSet);
  const cPSrc = commitVec([...lineage.srcSet.primes], rhoPSrc);
  const cPMod = commitVec([...lineage.modSet.primes], rhoPMod);

  const allPrimes = [...lineage.srcSet.primes, ...lineage.modSet.primes];
  const cMidBase = acc.subsetWitnessBase(allPrimes);
  const aAlias = createAlias(acc.accumulator, qAlias, N);
  const cMid = liftWitness(cMidBase, qAlias, N);

  return {
    srcCommitment: comSrcset(srcDigest, rhoSrc),
    modCommitment: comModset(modDigest, rhoMod),
    cPSrc,
    cPMod,
    cMid,
    aAlias,
    blEpoch: acc.policyEpoch,
    regSeqUsed: acc.regSeq,
  };
}

export function verifyUnshieldV3(
  proof: V6UnshieldProof,
  lineage: DualLineage,
  acc: PolicyAccumulator,
  N: bigint,
): boolean {
  if (proof.blEpoch !== acc.policyEpoch) return false;
  if (proof.regSeqUsed > acc.regSeq) return false;

  const allPrimes = [...lineage.srcSet.primes, ...lineage.modSet.primes];
  return verifyAliasSubset(allPrimes, proof.cMid, proof.aAlias, acc.qEpoch, N);
}

// ============================================================
// TypedCallV1 — Exact vs Boundary
// ============================================================

/**
 * Exact Module: ModSet unchanged (wrap/unwrap etc.)
 */
export function generateTypedCallExact(
  inputLineages: DualLineage[],
  currentPolicyEpoch: number,
  rhoSrcOut: bigint,
  rhoModOut: bigint,
): V6TypedCallResult {
  const outputSrcSet = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.srcSet));
  const outputModSet = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.modSet));
  const srcDigest = setDigestSrc(outputSrcSet);
  const modDigest = setDigestMod(outputModSet);

  return {
    outputSrcCommitment: comSrcset(srcDigest, rhoSrcOut),
    outputModCommitment: comModset(modDigest, rhoModOut),
    outputSrcDigest: srcDigest,
    outputModDigest: modDigest,
    outputCleanEpoch: currentPolicyEpoch,
    moduleType: 'exact',
  };
}

/**
 * Boundary Module: ModSet += boundary tags (swap, vault, staking etc.)
 */
export function generateTypedCallBoundary(
  inputLineages: DualLineage[],
  boundaryTags: bigint[], // module primes to add
  currentPolicyEpoch: number,
  rhoSrcOut: bigint,
  rhoModOut: bigint,
): V6TypedCallResult {
  const outputSrcSet = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.srcSet));
  const inputModSet = CanonicalSourceSet.canonicalUnion(inputLineages.map(l => l.modSet));

  // Boundary: ModSet_out = union(input ModSets) ∪ TagSet
  const tagSet = new CanonicalSourceSet(
    [...boundaryTags].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
  );
  const outputModSet = CanonicalSourceSet.canonicalUnion([inputModSet, tagSet]);

  const srcDigest = setDigestSrc(outputSrcSet);
  const modDigest = setDigestMod(outputModSet);

  return {
    outputSrcCommitment: comSrcset(srcDigest, rhoSrcOut),
    outputModCommitment: comModset(modDigest, rhoModOut),
    outputSrcDigest: srcDigest,
    outputModDigest: modDigest,
    outputCleanEpoch: currentPolicyEpoch,
    moduleType: 'boundary',
  };
}
