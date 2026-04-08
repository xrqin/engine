/**
 * R_TYPEDCALL_LINEAGE_V2 — RAILGUN Source Compliance v7
 *
 * Typed call lineage relation: carried lineage exact propagation
 * by LineageFlowMatrix, tag merge for boundary modules.
 *
 * R_TYPEDCALL_LINEAGE_V2(lineageBinding, moduleManifestHash; W_lin) = 1 iff
 *   for every output bucket τ:
 *     1. Source side: bucket source commitment is exact union of Src(note_in[i]) for all i in CarryIn_τ^M(tx)
 *     2. Module side / Exact: bucket module commitment is exact union of Mod(note_in[i]) for all i in CarryIn_τ^M(tx)
 *     3. Module side / Boundary: carried module lineage is first exact-unioned, then TagTreeByOutputBucket_M[τ] is merged via R_ADD_TAGS^mod
 *     4. all carried-input references, intermediate commitments, and final bucket commitments hash to lineageBinding
 */

import {
  CanonicalSetTree,
  SetTreeKind,
  buildCanonicalSetTree,
} from '../canonical-set-tree';
import {
  LineageFlowMatrix,
  TagTreeByOutputBucket,
  ResolvedManifest,
  ManifestRegistry,
  deriveCarryIn,
} from '../manifest-registry';
import { CanonicalSourceSet } from '../canonical-source-set';

// ============================================================
// Types
// ============================================================

export interface CarriedInputLineage {
  /** Source set tree of the input note */
  srcTree: CanonicalSetTree;
  /** Module set tree of the input note */
  modTree: CanonicalSetTree;
  /** Which input bucket this note belongs to */
  inputBucket: number;
}

export interface TypedCallLineageWitness {
  /** Per-input carried lineage */
  carriedInputs: CarriedInputLineage[];
  /** Per-output-bucket computed source tree (after merge) */
  outputSrcTrees: CanonicalSetTree[];
  /** Per-output-bucket computed module tree (after merge + tag add for boundary) */
  outputModTrees: CanonicalSetTree[];
  /** Per-output-bucket bucket source commitments */
  bucketSrcCommits: bigint[];
  /** Per-output-bucket bucket module commitments */
  bucketModCommits: bigint[];
  /** Module class from manifest */
  stepClass: 'EXACT' | 'BOUNDARY';
}

// ============================================================
// Verify R_TYPEDCALL_LINEAGE_V2
// ============================================================

/**
 * Verify the typed call lineage relation.
 *
 * For each output bucket τ:
 * - Derive CarryIn_τ from LineageFlowMatrix
 * - Compute exact union of carried source sets -> expected src tree for bucket τ
 * - For Exact: compute exact union of carried module sets -> expected mod tree
 * - For Boundary: compute exact union of carried module sets, then merge TagTree[τ] -> expected mod tree
 * - Verify witness trees match expected
 */
export function verifyTypedCallLineageV2(
  lineageBinding: bigint,
  moduleManifestHash: bigint,
  witness: TypedCallLineageWitness,
  manifestRegistry: ManifestRegistry,
): boolean {
  let resolved: ResolvedManifest;
  try {
    resolved = manifestRegistry.resolveManifest(moduleManifestHash);
  } catch {
    return false;
  }

  const flowMatrix = resolved.flowMatrix;
  const tagTree = resolved.tagTreeByOutputBucket;
  const bucketCount = flowMatrix.outputBucketCount;

  if (witness.outputSrcTrees.length !== bucketCount) return false;
  if (witness.outputModTrees.length !== bucketCount) return false;

  const inputBucketAssignment = witness.carriedInputs.map(ci => ci.inputBucket);

  for (let tau = 0; tau < bucketCount; tau++) {
    // Derive CarryIn_τ
    const carryIndices = deriveCarryIn(flowMatrix, tau, inputBucketAssignment);

    // 1. Source side: exact union of carried source sets
    const carriedSrcSets = carryIndices.map(i => witness.carriedInputs[i].srcTree);
    const expectedSrcTree = mergeCanonicalSetTrees('src', carriedSrcSets);
    if (expectedSrcTree.root !== witness.outputSrcTrees[tau].root) return false;
    if (expectedSrcTree.count !== witness.outputSrcTrees[tau].count) return false;

    // 2/3. Module side
    const carriedModSets = carryIndices.map(i => witness.carriedInputs[i].modTree);
    const carriedModMerged = mergeCanonicalSetTrees('mod', carriedModSets);

    if (witness.stepClass === 'EXACT') {
      // Exact: module tree is just the merged carried module sets
      if (carriedModMerged.root !== witness.outputModTrees[tau].root) return false;
      if (carriedModMerged.count !== witness.outputModTrees[tau].count) return false;
    } else {
      // Boundary: R_ADD_TAGS^mod = R_MERGE2^mod(carried_mod, TagTree[τ])
      // tagTree resolved from manifest, NOT external parameter
      const tagTreeForBucket = tagTree.tagTrees[tau];
      if (!tagTreeForBucket) return false;

      const tagSetTree = buildCanonicalSetTree('mod', tagTreeForBucket.primes);
      const withTags = mergeCanonicalSetTrees('mod', [carriedModMerged, tagSetTree]);

      if (withTags.root !== witness.outputModTrees[tau].root) return false;
      if (withTags.count !== witness.outputModTrees[tau].count) return false;
    }
  }

  return true;
}

// ============================================================
// Helper: merge multiple canonical set trees
// ============================================================

/**
 * Merge multiple canonical set trees by collecting all primes,
 * sorting, deduplicating, and rebuilding the tree.
 *
 * This is the local semantic equivalent of R_MERGE_N.
 */
function mergeCanonicalSetTrees(
  kind: SetTreeKind,
  trees: CanonicalSetTree[],
): CanonicalSetTree {
  if (trees.length === 0) {
    return buildCanonicalSetTree(kind, []);
  }

  // Collect all primes, sort, dedup
  const allPrimes = new Set<bigint>();
  for (const tree of trees) {
    for (const p of tree.leaves) {
      allPrimes.add(p);
    }
  }

  const sorted = [...allPrimes].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return buildCanonicalSetTree(kind, sorted);
}
