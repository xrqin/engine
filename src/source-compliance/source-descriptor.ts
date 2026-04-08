/**
 * Source Descriptor — v8.1 Binary Append-Only Frontier
 *
 * Replaces the B=4 canonical set tree (canonical-set-tree.ts) with a binary
 * frontier + count-bound bag folding, as specified in v8.1 §4.3.2.
 *
 * BuildSourceDescriptor(S_src):
 *   front = EMPTY_DESC_FRONTIER
 *   count = 0
 *   for each s in S_src (strictly increasing):
 *     (front, count) = AppendLeaf_src_desc(front, count, s)
 *   return FinalizeSourceFrontier(front, count)
 */

import { poseidon } from '../utils/poseidon';
import { dstToFieldElement } from './commitments';
import {
  DST_SRC_LEAF_V3,
  DST_SRC_NODE_V3,
  DST_SRC_BAG_V1,
  DST_SRC_ROOT_V1,
  D_DESC,
} from './constants';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EMPTY_SLOT = 0n;
const EMPTY_BAG = 0n;

// Pre-compute DST field elements
let _dstLeaf: bigint | undefined;
let _dstNode: bigint | undefined;
let _dstBag: bigint | undefined;
let _dstRoot: bigint | undefined;

function dstLeaf(): bigint {
  return (_dstLeaf ??= dstToFieldElement(DST_SRC_LEAF_V3));
}
function dstNode(): bigint {
  return (_dstNode ??= dstToFieldElement(DST_SRC_NODE_V3));
}
function dstBag(): bigint {
  return (_dstBag ??= dstToFieldElement(DST_SRC_BAG_V1));
}
function dstRoot(): bigint {
  return (_dstRoot ??= dstToFieldElement(DST_SRC_ROOT_V1));
}

// ---------------------------------------------------------------------------
// Hash primitives
// ---------------------------------------------------------------------------

export function leafHashSrc(s: bigint): bigint {
  return poseidon([dstLeaf(), s]);
}

export function nodeHashSrc(x: bigint, y: bigint): bigint {
  return poseidon([dstNode(), x, y]);
}

export function bagHashSrc(x: bigint, y: bigint): bigint {
  return poseidon([dstBag(), x, y]);
}

export function rootHashSrc(count: number, bag: bigint): bigint {
  return poseidon([dstRoot(), BigInt(count), bag]);
}

// ---------------------------------------------------------------------------
// DescFrontier type
// ---------------------------------------------------------------------------

export interface DescFrontier {
  slots: bigint[]; // length = D_DESC
  count: number;
}

export function emptyDescFrontier(): DescFrontier {
  return {
    slots: new Array(D_DESC).fill(EMPTY_SLOT),
    count: 0,
  };
}

// ---------------------------------------------------------------------------
// AppendLeaf_src_desc
// ---------------------------------------------------------------------------

/**
 * Append a single source leaf to the frontier using binary carry chain logic.
 * Mutates `frontier` in place and returns the updated count.
 */
export function appendLeafSrcDesc(frontier: DescFrontier, s: bigint): void {
  let cur = leafHashSrc(s);
  const c = frontier.count;
  let carry = 1;

  for (let h = 0; h < D_DESC; h++) {
    const bit = (c >> h) & 1;

    if (carry === 1 && bit === 1) {
      // Merge: combine existing subtree at this level with cur
      cur = nodeHashSrc(frontier.slots[h], cur);
      frontier.slots[h] = EMPTY_SLOT;
      // carry remains 1
    } else if (carry === 1 && bit === 0) {
      // Place: store cur at this level, stop carrying
      frontier.slots[h] = cur;
      carry = 0;
    }
    // else: carry === 0, no change at this level
  }

  frontier.count = c + 1;
}

// ---------------------------------------------------------------------------
// FinalizeSourceFrontier
// ---------------------------------------------------------------------------

export interface SourceDescriptor {
  srcRoot: bigint;
  srcCount: number;
}

/**
 * Finalize the frontier into (src_root, src_count) using bag folding.
 *
 * bag = EMPTY_BAG
 * for h in 0..D_desc-1:
 *   if bit_h(count) = 1:
 *     bag = (bag == EMPTY_BAG) ? frontier[h] : BagHash(frontier[h], bag)
 * src_root = RootHash(count, bag)
 */
export function finalizeSourceFrontier(frontier: DescFrontier): SourceDescriptor {
  const count = frontier.count;

  if (count === 0) {
    return {
      srcRoot: rootHashSrc(0, EMPTY_BAG),
      srcCount: 0,
    };
  }

  let bag = EMPTY_BAG;

  for (let h = 0; h < D_DESC; h++) {
    if (((count >> h) & 1) === 1) {
      if (bag === EMPTY_BAG) {
        bag = frontier.slots[h];
      } else {
        bag = bagHashSrc(frontier.slots[h], bag);
      }
    }
  }

  return {
    srcRoot: rootHashSrc(count, bag),
    srcCount: count,
  };
}

// ---------------------------------------------------------------------------
// BuildSourceDescriptor
// ---------------------------------------------------------------------------

/**
 * Build the canonical source descriptor from a sorted, unique source list.
 *
 * @param sortedUniqueSources - strictly increasing source field elements
 * @returns (src_root, src_count)
 */
export function buildSourceDescriptor(sortedUniqueSources: bigint[]): SourceDescriptor {
  validateStrictlyIncreasing(sortedUniqueSources);

  const frontier = emptyDescFrontier();
  for (const s of sortedUniqueSources) {
    appendLeafSrcDesc(frontier, s);
  }
  return finalizeSourceFrontier(frontier);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Verify that a source list produces the expected descriptor.
 */
export function verifySourceDescriptor(
  srcRoot: bigint,
  srcCount: number,
  sortedUniqueSources: bigint[],
): boolean {
  if (sortedUniqueSources.length !== srcCount) return false;
  try {
    const desc = buildSourceDescriptor(sortedUniqueSources);
    return desc.srcRoot === srcRoot && desc.srcCount === srcCount;
  } catch {
    return false;
  }
}

function validateStrictlyIncreasing(sources: bigint[]): void {
  for (let i = 1; i < sources.length; i++) {
    if (sources[i] <= sources[i - 1]) {
      throw new Error(
        `Source descriptor: sources must be strictly increasing at index ${i}`,
      );
    }
  }
}
