/**
 * WitnessBuilder — RAILGUN Source Compliance v7
 *
 * Builds complete witnesses from NoteV4 + canonical set trees
 * for transfer, typed call, and unshield operations.
 */

import {
  buildCanonicalSetTree,
  CanonicalSetTree,
  SetTreeKind,
} from '../canonical-set-tree';
import { NoteV4 } from '../commitments';
import { LineageFlowMatrix, deriveCarryIn } from '../manifest-registry';
import {
  WitnessBuilder,
  BucketSpec,
  PublicBucketSpec,
  TransferWitness,
  TypedCallWitness,
  UnshieldWitness,
  MergeForest,
  Merge2Result,
  ResolvedManifest,
  SessionReceipt,
} from './backend-interface';

// ============================================================
// Default Witness Builder
// ============================================================

export class DefaultWitnessBuilder implements WitnessBuilder {
  /**
   * Maps NoteV4 to its carried set trees.
   * In production, these would be looked up from the UTXO set.
   */
  private treeResolver: (note: NoteV4) => { src: CanonicalSetTree; mod: CanonicalSetTree };

  constructor(
    treeResolver: (note: NoteV4) => { src: CanonicalSetTree; mod: CanonicalSetTree },
  ) {
    this.treeResolver = treeResolver;
  }

  buildTransferWitness(
    inputNotes: NoteV4[],
    outputBuckets: BucketSpec[],
    flowMatrix?: LineageFlowMatrix,
  ): TransferWitness {
    const inputTrees = inputNotes.map(n => this.treeResolver(n));

    // For transfer: each input maps to its token bucket, all inputs flow to matching output
    // Build merge forests for src and mod
    const srcForest = this.buildMergeForest(
      'src',
      inputTrees.map(t => t.src),
      outputBuckets.length,
      flowMatrix,
      inputNotes,
    );
    const modForest = this.buildMergeForest(
      'mod',
      inputTrees.map(t => t.mod),
      outputBuckets.length,
      flowMatrix,
      inputNotes,
    );

    return {
      inputTrees,
      outputBuckets,
      mergeForests: { src: srcForest, mod: modForest },
    };
  }

  buildTypedCallWitness(
    inputNotes: NoteV4[],
    manifest: ResolvedManifest,
    sessionReceipt: SessionReceipt,
  ): TypedCallWitness {
    const inputTrees = inputNotes.map(n => this.treeResolver(n));
    const bucketCount = manifest.flowMatrix.outputBucketCount;

    const srcForest = this.buildMergeForest(
      'src',
      inputTrees.map(t => t.src),
      bucketCount,
      manifest.flowMatrix,
      inputNotes,
    );
    const modForest = this.buildMergeForest(
      'mod',
      inputTrees.map(t => t.mod),
      bucketCount,
      manifest.flowMatrix,
      inputNotes,
    );

    return {
      inputTrees,
      mergeForests: { src: srcForest, mod: modForest },
      manifest,
      sessionReceipt,
    };
  }

  buildUnshieldWitness(
    inputNotes: NoteV4[],
    publicBuckets: PublicBucketSpec[],
  ): UnshieldWitness {
    const inputTrees = inputNotes.map(n => this.treeResolver(n));
    const bucketCount = publicBuckets.length;

    const srcForest = this.buildMergeForest(
      'src',
      inputTrees.map(t => t.src),
      bucketCount,
      undefined,
      inputNotes,
    );
    const modForest = this.buildMergeForest(
      'mod',
      inputTrees.map(t => t.mod),
      bucketCount,
      undefined,
      inputNotes,
    );

    return {
      inputTrees,
      publicBuckets,
      mergeForests: { src: srcForest, mod: modForest },
    };
  }

  private buildMergeForest(
    kind: SetTreeKind,
    inputTrees: CanonicalSetTree[],
    bucketCount: number,
    flowMatrix: LineageFlowMatrix | undefined,
    inputNotes: NoteV4[],
  ): MergeForest {
    const internalNodes: Merge2Result[] = [];
    const roots: CanonicalSetTree[] = [];

    for (let tau = 0; tau < bucketCount; tau++) {
      // Determine which inputs carry to this bucket
      let carryIndices: number[];
      if (flowMatrix) {
        // Use flow matrix to derive carry-in
        const inputBucketAssignment = this.assignInputBuckets(inputNotes);
        carryIndices = deriveCarryIn(flowMatrix, tau, inputBucketAssignment);
      } else {
        // Simple: all inputs with same token bucket carry to the matching output
        carryIndices = inputNotes
          .map((_, i) => i)
          .filter(i => this.getTokenBucket(inputNotes[i], bucketCount) === tau);
      }

      // Merge carried input trees for this bucket
      const carried = carryIndices.map(i => inputTrees[i]);
      const merged = this.mergeTreesSequential(kind, carried, internalNodes);
      roots.push(merged);
    }

    return { leaves: inputTrees, internalNodes, roots };
  }

  private mergeTreesSequential(
    kind: SetTreeKind,
    trees: CanonicalSetTree[],
    internalNodes: Merge2Result[],
  ): CanonicalSetTree {
    if (trees.length === 0) return buildCanonicalSetTree(kind, []);
    if (trees.length === 1) return trees[0];

    let acc = trees[0];
    for (let i = 1; i < trees.length; i++) {
      const merged = mergeTwo(kind, acc, trees[i]);
      internalNodes.push({
        rootL: acc.root,
        countL: acc.count,
        rootR: trees[i].root,
        countR: trees[i].count,
        rootO: merged.root,
        countO: merged.count,
      });
      acc = merged;
    }
    return acc;
  }

  private assignInputBuckets(inputNotes: NoteV4[]): number[] {
    // Simple tokenHash-based bucket assignment
    const tokens = [...new Set(inputNotes.map(n => n.tokenHash))].sort(
      (a, b) => (a < b ? -1 : a > b ? 1 : 0),
    );
    return inputNotes.map(n => tokens.indexOf(n.tokenHash));
  }

  private getTokenBucket(note: NoteV4, bucketCount: number): number {
    // Simplified: bucket = tokenHash mod bucketCount
    return Number(note.tokenHash % BigInt(bucketCount));
  }
}

// ============================================================
// Helper: merge two canonical set trees
// ============================================================

function mergeTwo(
  kind: SetTreeKind,
  a: CanonicalSetTree,
  b: CanonicalSetTree,
): CanonicalSetTree {
  const allPrimes = new Set<bigint>();
  for (const p of a.leaves) allPrimes.add(p);
  for (const p of b.leaves) allPrimes.add(p);
  const sorted = [...allPrimes].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return buildCanonicalSetTree(kind, sorted);
}
