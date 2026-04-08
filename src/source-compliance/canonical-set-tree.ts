/**
 * @deprecated v7 Canonical Set Tree — replaced by binary frontier in v8.1.
 * Use source-descriptor.ts (buildSourceDescriptor) for source-side operations.
 * This file is retained for backward compatibility with v7 module-side trees only.
 *
 * Canonical Set Tree (v7)
 *
 * B=4 arity Poseidon Merkle tree over sorted, unique primes.
 * Domain-separated for src and mod via different DSTs.
 *
 * Spec reference: §4.3.2 (v7, superseded by v8.1 §4.3.2)
 *
 * BuildTree_K(S):
 *   L_0 = [LeafHash_K(p_0), ..., LeafHash_K(p_{m-1})]
 *   repeat:
 *     right-pad to multiple of B with EMPTY_K(level)
 *     group consecutive B children
 *     hash upward with NodeHash_K
 *   until one root remains
 *   return (root_K, count_K = m)
 */

import { poseidon } from '../utils/poseidon';
import { dstToFieldElement } from './commitments';
import {
  SET_TREE_ARITY,
  DST_LEAF_SRC_V1, DST_LEAF_MOD_V1,
  DST_NODE_SRC_V1, DST_NODE_MOD_V1,
} from './constants';

export type SetTreeKind = 'src' | 'mod';

export interface CanonicalSetTree {
  root: bigint;
  count: number;
  leaves: bigint[]; // sorted, unique primes
}

const B = SET_TREE_ARITY; // 4

// ---------------------------------------------------------------------------
// DST lookup
// ---------------------------------------------------------------------------

function leafDst(kind: SetTreeKind): bigint {
  return dstToFieldElement(kind === 'src' ? DST_LEAF_SRC_V1 : DST_LEAF_MOD_V1);
}

function nodeDst(kind: SetTreeKind): bigint {
  return dstToFieldElement(kind === 'src' ? DST_NODE_SRC_V1 : DST_NODE_MOD_V1);
}

// ---------------------------------------------------------------------------
// Empty node cache (keyed by kind+level)
// ---------------------------------------------------------------------------

const emptyCache = new Map<string, bigint>();

/** Domain-separated empty node constant for padding at a given level */
export function emptyNode(kind: SetTreeKind, level: number): bigint {
  const key = `${kind}:${level}`;
  const cached = emptyCache.get(key);
  if (cached !== undefined) return cached;

  // EMPTY_K(level) = Poseidon(DST_NODE_K_V1, level, 0, 0, ..., 0)
  // Using B zeros as children to create a unique empty constant per level
  const dst = nodeDst(kind);
  const inputs = [dst, BigInt(level)];
  for (let i = 0; i < B; i++) inputs.push(0n);
  const val = poseidon(inputs);
  emptyCache.set(key, val);
  return val;
}

// ---------------------------------------------------------------------------
// Leaf and node hashing
// ---------------------------------------------------------------------------

/** LeafHash_K(p) = Poseidon(DST_LEAF_K_V1, p) */
export function leafHash(kind: SetTreeKind, prime: bigint): bigint {
  return poseidon([leafDst(kind), prime]);
}

/** NodeHash_K(level, c_0, ..., c_{B-1}) = Poseidon(DST_NODE_K_V1, level, c_0, ..., c_{B-1}) */
export function nodeHash(kind: SetTreeKind, level: number, children: bigint[]): bigint {
  if (children.length !== B) {
    throw new Error(`nodeHash: expected ${B} children, got ${children.length}`);
  }
  return poseidon([nodeDst(kind), BigInt(level), ...children]);
}

// ---------------------------------------------------------------------------
// Build canonical set tree
// ---------------------------------------------------------------------------

/**
 * Build a canonical set tree from sorted unique primes.
 * Returns (root, count) where count = number of primes.
 *
 * For empty set: returns a canonical empty root at level 0.
 */
export function buildCanonicalSetTree(
  kind: SetTreeKind,
  sortedUniquePrimes: bigint[],
): CanonicalSetTree {
  validateSortedUnique(sortedUniquePrimes);

  const count = sortedUniquePrimes.length;

  if (count === 0) {
    return { root: emptyNode(kind, 0), count: 0, leaves: [] };
  }

  // Level 0: hash each leaf
  let currentLevel: bigint[] = sortedUniquePrimes.map(p => leafHash(kind, p));
  let level = 0;

  // Build tree upward until one root remains
  while (currentLevel.length > 1) {
    // Right-pad to multiple of B with EMPTY_K(level)
    const empty = emptyNode(kind, level);
    while (currentLevel.length % B !== 0) {
      currentLevel.push(empty);
    }

    // Group consecutive B children and hash upward
    level += 1;
    const nextLevel: bigint[] = [];
    for (let i = 0; i < currentLevel.length; i += B) {
      const children = currentLevel.slice(i, i + B);
      nextLevel.push(nodeHash(kind, level, children));
    }
    currentLevel = nextLevel;
  }

  return {
    root: currentLevel[0],
    count,
    leaves: [...sortedUniquePrimes],
  };
}

// ---------------------------------------------------------------------------
// Verify canonical set tree
// ---------------------------------------------------------------------------

/**
 * Verify that a given set of primes produces the expected (root, count).
 * Rebuilds the tree and checks equality.
 */
export function verifyCanonicalSetTree(
  kind: SetTreeKind,
  root: bigint,
  count: number,
  primes: bigint[],
): boolean {
  if (primes.length !== count) return false;

  try {
    const tree = buildCanonicalSetTree(kind, primes);
    return tree.root === root && tree.count === count;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function validateSortedUnique(primes: bigint[]): void {
  for (let i = 1; i < primes.length; i++) {
    if (primes[i] <= primes[i - 1]) {
      throw new Error(
        `CanonicalSetTree: primes must be strictly increasing at index ${i}`,
      );
    }
  }
}
