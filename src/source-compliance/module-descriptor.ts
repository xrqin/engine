/**
 * Module Descriptor — v8.1 Binary Append-Only Frontier
 *
 * Mirrors source-descriptor.ts for the module (ModSet) side.
 * Uses module-specific DSTs for domain separation.
 *
 * BuildModuleDescriptor(S_mod):
 *   front = EMPTY_DESC_FRONTIER
 *   count = 0
 *   for each m in S_mod (strictly increasing):
 *     (front, count) = AppendLeaf_mod_desc(front, count, m)
 *   return FinalizeModuleFrontier(front, count)
 */

import { poseidon } from '../utils/poseidon';
import { dstToFieldElement } from './commitments';
import {
  DST_MOD_LEAF_V3,
  DST_MOD_NODE_V3,
  DST_MOD_BAG_V1,
  DST_MOD_ROOT_V1,
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

function dstLeafMod(): bigint {
  return (_dstLeaf ??= dstToFieldElement(DST_MOD_LEAF_V3));
}
function dstNodeMod(): bigint {
  return (_dstNode ??= dstToFieldElement(DST_MOD_NODE_V3));
}
function dstBagMod(): bigint {
  return (_dstBag ??= dstToFieldElement(DST_MOD_BAG_V1));
}
function dstRootMod(): bigint {
  return (_dstRoot ??= dstToFieldElement(DST_MOD_ROOT_V1));
}

// ---------------------------------------------------------------------------
// Hash primitives
// ---------------------------------------------------------------------------

export function leafHashMod(m: bigint): bigint {
  return poseidon([dstLeafMod(), m]);
}

export function nodeHashMod(x: bigint, y: bigint): bigint {
  return poseidon([dstNodeMod(), x, y]);
}

export function bagHashMod(x: bigint, y: bigint): bigint {
  return poseidon([dstBagMod(), x, y]);
}

export function rootHashMod(count: number, bag: bigint): bigint {
  return poseidon([dstRootMod(), BigInt(count), bag]);
}

// ---------------------------------------------------------------------------
// ModDescFrontier type
// ---------------------------------------------------------------------------

export interface ModDescFrontier {
  slots: bigint[]; // length = D_DESC
  count: number;
}

export function emptyModDescFrontier(): ModDescFrontier {
  return {
    slots: new Array(D_DESC).fill(EMPTY_SLOT),
    count: 0,
  };
}

// ---------------------------------------------------------------------------
// AppendLeaf_mod_desc
// ---------------------------------------------------------------------------

/**
 * Append a single module leaf to the frontier using binary carry chain logic.
 * Mutates `frontier` in place.
 */
export function appendLeafModDesc(frontier: ModDescFrontier, m: bigint): void {
  let cur = leafHashMod(m);
  const c = frontier.count;
  let carry = 1;

  for (let h = 0; h < D_DESC; h++) {
    const bit = (c >> h) & 1;

    if (carry === 1 && bit === 1) {
      cur = nodeHashMod(frontier.slots[h], cur);
      frontier.slots[h] = EMPTY_SLOT;
    } else if (carry === 1 && bit === 0) {
      frontier.slots[h] = cur;
      carry = 0;
    }
  }

  frontier.count = c + 1;
}

// ---------------------------------------------------------------------------
// FinalizeModuleFrontier
// ---------------------------------------------------------------------------

export interface ModuleDescriptor {
  modRoot: bigint;
  modCount: number;
}

/**
 * Finalize the frontier into (mod_root, mod_count) using bag folding.
 */
export function finalizeModuleFrontier(frontier: ModDescFrontier): ModuleDescriptor {
  const count = frontier.count;

  if (count === 0) {
    return {
      modRoot: rootHashMod(0, EMPTY_BAG),
      modCount: 0,
    };
  }

  let bag = EMPTY_BAG;

  for (let h = 0; h < D_DESC; h++) {
    if (((count >> h) & 1) === 1) {
      if (bag === EMPTY_BAG) {
        bag = frontier.slots[h];
      } else {
        bag = bagHashMod(frontier.slots[h], bag);
      }
    }
  }

  return {
    modRoot: rootHashMod(count, bag),
    modCount: count,
  };
}

// ---------------------------------------------------------------------------
// BuildModuleDescriptor
// ---------------------------------------------------------------------------

/**
 * Build the canonical module descriptor from a sorted, unique module prime list.
 *
 * @param sortedUniqueModules - strictly increasing module field elements
 * @returns (mod_root, mod_count)
 */
export function buildModuleDescriptor(sortedUniqueModules: bigint[]): ModuleDescriptor {
  validateStrictlyIncreasing(sortedUniqueModules);

  const frontier = emptyModDescFrontier();
  for (const m of sortedUniqueModules) {
    appendLeafModDesc(frontier, m);
  }
  return finalizeModuleFrontier(frontier);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Verify that a module list produces the expected descriptor.
 */
export function verifyModuleDescriptor(
  modRoot: bigint,
  modCount: number,
  sortedUniqueModules: bigint[],
): boolean {
  if (sortedUniqueModules.length !== modCount) return false;
  try {
    const desc = buildModuleDescriptor(sortedUniqueModules);
    return desc.modRoot === modRoot && desc.modCount === modCount;
  } catch {
    return false;
  }
}

function validateStrictlyIncreasing(modules: bigint[]): void {
  for (let i = 1; i < modules.length; i++) {
    if (modules[i] <= modules[i - 1]) {
      throw new Error(
        `Module descriptor: modules must be strictly increasing at index ${i}`,
      );
    }
  }
}
