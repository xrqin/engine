/**
 * ProvingBackend Interface — RAILGUN Source Compliance v7
 *
 * Abstract interface for recursive/IVC proving backends.
 * Phase 1: interface definition only.
 * Phase 2+: plug in Groth16 recursion / Nova / IVC etc.
 */

import { CanonicalSetTree } from '../canonical-set-tree';
import { LineageFlowMatrix } from '../manifest-registry';
import { NoteV4 } from '../commitments';

// ============================================================
// Proof Object
// ============================================================

export interface ProofObject {
  /** Proof system identifier */
  system: string;
  /** Serialized proof data */
  data: Uint8Array;
  /** Public inputs bound to the proof */
  publicInputs: bigint[];
}

// ============================================================
// Merge Forest (R_MERGE_N witness structure)
// ============================================================

export interface Merge2Result {
  rootL: bigint;
  countL: number;
  rootR: bigint;
  countR: number;
  rootO: bigint;
  countO: number;
}

export interface MergeForest {
  /** Input set trees (carried from input notes) */
  leaves: CanonicalSetTree[];
  /** Binary merge tree internal nodes */
  internalNodes: Merge2Result[];
  /** Per-bucket output set trees */
  roots: CanonicalSetTree[];
}

// ============================================================
// Subset Witness (R_SUBSET_FROM_TREE)
// ============================================================

export interface SubsetFromTreeWitness {
  root: bigint;
  count: number;
  rhoBucket: bigint;
  primes: bigint[];
  product: bigint;
  subsetWitness: bigint;
}

// ============================================================
// Witness structures for tx types
// ============================================================

export interface BucketSpec {
  tokenHash: bigint;
  outputNotes: NoteV4[];
}

export interface PublicBucketSpec {
  tokenHash: bigint;
  value: bigint;
  recipient: bigint;
}

export interface SessionReceipt {
  sessionId: bigint;
  returnVec: bigint[];
}

export interface ResolvedManifest {
  moduleManifestHash: bigint;
  flowMatrix: LineageFlowMatrix;
  declaredTokenUniverse: bigint[];
}

export interface TransferWitness {
  inputTrees: { src: CanonicalSetTree; mod: CanonicalSetTree }[];
  outputBuckets: BucketSpec[];
  mergeForests: { src: MergeForest; mod: MergeForest };
}

export interface TypedCallWitness {
  inputTrees: { src: CanonicalSetTree; mod: CanonicalSetTree }[];
  mergeForests: { src: MergeForest; mod: MergeForest };
  manifest: ResolvedManifest;
  sessionReceipt: SessionReceipt;
}

export interface UnshieldWitness {
  inputTrees: { src: CanonicalSetTree; mod: CanonicalSetTree }[];
  publicBuckets: PublicBucketSpec[];
  mergeForests: { src: MergeForest; mod: MergeForest };
}

// ============================================================
// ProvingBackend interface
// ============================================================

export interface ProvingBackend {
  /** R_MERGE_N: fold merge forest into constant-size outer proof */
  proveMergeN(
    kind: 'src' | 'mod',
    forest: MergeForest,
    lineageBinding: bigint,
  ): ProofObject;

  /** Verify R_MERGE_N proof */
  verifyMergeN(
    proof: ProofObject,
    lineageBinding: bigint,
  ): boolean;

  /** R_SUBSET_FROM_TREE: prove hidden set is subset of policy */
  proveSubsetFromTree(
    kind: 'src' | 'mod',
    witness: SubsetFromTreeWitness,
    lineageBinding: bigint,
    policyBinding: bigint,
  ): ProofObject;

  /** Verify R_SUBSET_FROM_TREE proof */
  verifySubsetFromTree(
    proof: ProofObject,
    lineageBinding: bigint,
    policyBinding: bigint,
  ): boolean;

  /** Aggregate multiple proofs into one */
  aggregateProofs(proofs: ProofObject[]): ProofObject;
}

// ============================================================
// WitnessBuilder interface
// ============================================================

export interface WitnessBuilder {
  buildTransferWitness(
    inputNotes: NoteV4[],
    outputBuckets: BucketSpec[],
    flowMatrix?: LineageFlowMatrix,
  ): TransferWitness;

  buildTypedCallWitness(
    inputNotes: NoteV4[],
    manifest: ResolvedManifest,
    sessionReceipt: SessionReceipt,
  ): TypedCallWitness;

  buildUnshieldWitness(
    inputNotes: NoteV4[],
    publicBuckets: PublicBucketSpec[],
  ): UnshieldWitness;
}
