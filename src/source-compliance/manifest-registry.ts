/**
 * Manifest / Module Registry — RAILGUN Source Compliance v7
 *
 * Defines StepManifest, RecipeManifest, LineageFlowMatrix,
 * TagTreeByOutputBucket, ExactEligible predicates, and
 * resolveManifest() for TypedCallV2 internal use.
 */

import { poseidon } from '../utils/poseidon';

// ============================================================
// Constants
// ============================================================

const BN254_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);

function dstToFieldElement(dst: string): bigint {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(dst);
  let val = 0n;
  for (const b of bytes) val = (val << 8n) | BigInt(b);
  return val % BN254_PRIME;
}

// ============================================================
// LineageFlowMatrix
// ============================================================

/**
 * Boolean matrix Flow[τ][σ] ∈ {0,1}
 * τ = output bucket index, σ = input bucket index
 *
 * Flow[τ][σ] = 1 means input bucket σ's carried lineage flows to output bucket τ.
 */
export interface LineageFlowMatrix {
  /** Number of output buckets (rows) */
  outputBucketCount: number;
  /** Number of input buckets (columns) */
  inputBucketCount: number;
  /** Row-major boolean matrix: flow[τ * inputBucketCount + σ] */
  flow: boolean[];
}

export function createLineageFlowMatrix(
  outputBucketCount: number,
  inputBucketCount: number,
  flow: boolean[],
): LineageFlowMatrix {
  if (flow.length !== outputBucketCount * inputBucketCount) {
    throw new Error(
      `LineageFlowMatrix: flow length ${flow.length} != ${outputBucketCount} * ${inputBucketCount}`,
    );
  }
  return { outputBucketCount, inputBucketCount, flow };
}

/**
 * Get Flow[τ][σ]
 */
export function getFlow(matrix: LineageFlowMatrix, tau: number, sigma: number): boolean {
  if (tau < 0 || tau >= matrix.outputBucketCount) throw new Error(`tau out of range: ${tau}`);
  if (sigma < 0 || sigma >= matrix.inputBucketCount) throw new Error(`sigma out of range: ${sigma}`);
  return matrix.flow[tau * matrix.inputBucketCount + sigma];
}

/**
 * Derive CarryIn_τ: indices of carried inputs for output bucket τ.
 * CarryIn_τ(tx) = { i ∈ RealIn(tx) | Flow[τ][bucket(i)] = 1 }
 *
 * @param matrix - the flow matrix
 * @param tau - output bucket index
 * @param inputBucketAssignment - inputBucketAssignment[i] = σ (input bucket of input i)
 * @returns indices into inputs that carry to output bucket τ
 */
export function deriveCarryIn(
  matrix: LineageFlowMatrix,
  tau: number,
  inputBucketAssignment: number[],
): number[] {
  const result: number[] = [];
  for (let i = 0; i < inputBucketAssignment.length; i++) {
    const sigma = inputBucketAssignment[i];
    if (getFlow(matrix, tau, sigma)) {
      result.push(i);
    }
  }
  return result;
}

/**
 * Compose two flow matrices: M_composed = M_second * M_first (boolean matrix multiply).
 * Used for multi-step recipes: Flow_recipe = Compose(Flow_step_0, ..., Flow_step_{t-1}).
 */
export function composeFlowMatrices(
  first: LineageFlowMatrix,
  second: LineageFlowMatrix,
): LineageFlowMatrix {
  if (first.outputBucketCount !== second.inputBucketCount) {
    throw new Error(
      `Cannot compose: first.outputBucketCount (${first.outputBucketCount}) != second.inputBucketCount (${second.inputBucketCount})`,
    );
  }
  const outRows = second.outputBucketCount;
  const outCols = first.inputBucketCount;
  const mid = first.outputBucketCount;
  const flow: boolean[] = new Array(outRows * outCols).fill(false);

  for (let tau = 0; tau < outRows; tau++) {
    for (let sigma = 0; sigma < outCols; sigma++) {
      for (let k = 0; k < mid; k++) {
        if (
          second.flow[tau * second.inputBucketCount + k] &&
          first.flow[k * first.inputBucketCount + sigma]
        ) {
          flow[tau * outCols + sigma] = true;
          break;
        }
      }
    }
  }

  return createLineageFlowMatrix(outRows, outCols, flow);
}

/**
 * Hash a LineageFlowMatrix for binding into manifest/execBinding.
 */
export function hashLineageFlowMatrix(matrix: LineageFlowMatrix): bigint {
  const dst = dstToFieldElement('RAILGUN_SOURCE_LINEAGE_FLOW_MATRIX_V1');
  const elements: bigint[] = [
    dst,
    BigInt(matrix.outputBucketCount),
    BigInt(matrix.inputBucketCount),
  ];
  // Pack booleans into field elements (32 bools per element)
  for (let i = 0; i < matrix.flow.length; i += 32) {
    let packed = 0n;
    for (let j = 0; j < 32 && i + j < matrix.flow.length; j++) {
      if (matrix.flow[i + j]) packed |= 1n << BigInt(j);
    }
    elements.push(packed);
  }
  // Sponge hash
  let state = poseidon([elements[0], elements[1]]);
  for (let i = 2; i < elements.length; i++) {
    state = poseidon([state, elements[i]]);
  }
  return state;
}

// ============================================================
// TagTreeByOutputBucket
// ============================================================

/**
 * Per-output-bucket canonical set tree of module tag primes.
 * Manifest-fixed, cannot be externally injected.
 */
export interface TagTreeByOutputBucket {
  /** tagTrees[τ] = { root, count, primes } for output bucket τ */
  tagTrees: Array<{ root: bigint; count: number; primes: bigint[] }>;
}

/**
 * Hash the tag tree map for binding into manifest.
 */
export function hashTagTreeByOutputBucket(tags: TagTreeByOutputBucket): bigint {
  const dst = dstToFieldElement('RAILGUN_SOURCE_TAG_TREE_MAP_V1');
  let state = poseidon([dst, BigInt(tags.tagTrees.length)]);
  for (const tree of tags.tagTrees) {
    state = poseidon([state, tree.root, BigInt(tree.count)]);
  }
  return state;
}

// ============================================================
// Step Manifest
// ============================================================

export type StepClass = 'EXACT' | 'BOUNDARY';

export interface StepManifest {
  stepType: string;
  target: bigint;
  targetCodeHash: bigint;
  implementationCodeHashOrZero: bigint;
  selector: bigint;
  stepClass: StepClass;
  tokenFlowSchemaHash: bigint;
  lineageFlowMatrixHash: bigint;
  callbackPolicyHash: bigint;
  staticCalldataHash: bigint;
  dynamicFieldSchemaHash: bigint;
  runtimeArgsSchemaHash: bigint;
  reachableTokenBinding: bigint;
  maxBoundaryTagsAdded: number;
}

// ============================================================
// Recipe Manifest
// ============================================================

export interface RecipeManifest {
  stepCount: number;
  steps: StepManifest[];
  declaredTokenBinding: bigint;
  reachableTokenBinding: bigint;
  outputBucketTagMapHash: bigint;
  lineageFlowMatrixHash: bigint;
  recipePolicyFlagsHash: bigint;
  callbackPolicyHash: bigint;
  routeShapeHash: bigint;
  targetCodeHashVectorHash: bigint;
}

// ============================================================
// Module Manifest Hash
// ============================================================

/**
 * Compute moduleManifestHash that binds all sub-hashes.
 */
export function computeModuleManifestHash(manifest: RecipeManifest): bigint {
  const dst = dstToFieldElement('RAILGUN_SOURCE_MODULE_MANIFEST_V2');
  let state = poseidon([dst, BigInt(manifest.stepCount)]);

  // Bind each step
  for (const step of manifest.steps) {
    state = poseidon([state, computeStepHash(step)]);
  }

  // Bind recipe-level fields
  state = poseidon([state, manifest.declaredTokenBinding]);
  state = poseidon([state, manifest.reachableTokenBinding]);
  state = poseidon([state, manifest.outputBucketTagMapHash]);
  state = poseidon([state, manifest.lineageFlowMatrixHash]);
  state = poseidon([state, manifest.recipePolicyFlagsHash]);
  state = poseidon([state, manifest.callbackPolicyHash]);
  state = poseidon([state, manifest.routeShapeHash]);
  state = poseidon([state, manifest.targetCodeHashVectorHash]);

  return state;
}

function computeStepHash(step: StepManifest): bigint {
  const dst = dstToFieldElement('RAILGUN_SOURCE_STEP_MANIFEST_V2');
  let state = poseidon([dst, step.target]);
  state = poseidon([state, step.targetCodeHash]);
  state = poseidon([state, step.implementationCodeHashOrZero]);
  state = poseidon([state, step.selector]);
  state = poseidon([state, BigInt(step.stepClass === 'EXACT' ? 0 : 1)]);
  state = poseidon([state, step.tokenFlowSchemaHash]);
  state = poseidon([state, step.lineageFlowMatrixHash]);
  state = poseidon([state, step.callbackPolicyHash]);
  state = poseidon([state, step.staticCalldataHash]);
  state = poseidon([state, step.dynamicFieldSchemaHash]);
  state = poseidon([state, step.runtimeArgsSchemaHash]);
  state = poseidon([state, step.reachableTokenBinding]);
  state = poseidon([state, BigInt(step.maxBoundaryTagsAdded)]);
  return state;
}

// ============================================================
// ExactEligible — 9 mandatory predicates
// ============================================================

export interface ExactEligibilityCheck {
  /** 1. output token set is fixed by manifest */
  fixedOutputTokenSet: boolean;
  /** 2. output amount is deterministic function of input + manifest-bound args */
  deterministicOutputAmount: boolean;
  /** 3. no external counterparty provenance ambiguity */
  noCounterpartyAmbiguity: boolean;
  /** 4. no donation sensitivity */
  noDonationSensitivity: boolean;
  /** 5. no fee-on-transfer / rebase / reward accrual / share-price drift */
  noFeeOnTransferOrRebase: boolean;
  /** 6. no undeclared token emergence */
  noUndeclaredTokenEmergence: boolean;
  /** 7. no callback-dependent hidden branch */
  noCallbackHiddenBranch: boolean;
  /** 8. target code hash is pinned and immutable */
  targetCodeHashPinned: boolean;
  /** 9. no second private return path */
  noSecondPrivateReturnPath: boolean;
}

/**
 * Check all 9 ExactEligible predicates.
 * Any failure -> module must be classified as BOUNDARY.
 */
export function isExactEligible(check: ExactEligibilityCheck): boolean {
  return (
    check.fixedOutputTokenSet &&
    check.deterministicOutputAmount &&
    check.noCounterpartyAmbiguity &&
    check.noDonationSensitivity &&
    check.noFeeOnTransferOrRebase &&
    check.noUndeclaredTokenEmergence &&
    check.noCallbackHiddenBranch &&
    check.targetCodeHashPinned &&
    check.noSecondPrivateReturnPath
  );
}

/**
 * Return which predicates failed.
 */
export function getExactEligibilityFailures(check: ExactEligibilityCheck): string[] {
  const failures: string[] = [];
  const predicates: [keyof ExactEligibilityCheck, string][] = [
    ['fixedOutputTokenSet', 'output token set not fixed by manifest'],
    ['deterministicOutputAmount', 'output amount not deterministic'],
    ['noCounterpartyAmbiguity', 'external counterparty provenance ambiguity'],
    ['noDonationSensitivity', 'donation sensitivity detected'],
    ['noFeeOnTransferOrRebase', 'fee-on-transfer/rebase/reward accrual/share-price drift'],
    ['noUndeclaredTokenEmergence', 'undeclared token emergence possible'],
    ['noCallbackHiddenBranch', 'callback-dependent hidden branch'],
    ['targetCodeHashPinned', 'target code hash not pinned/immutable'],
    ['noSecondPrivateReturnPath', 'second private return path exists'],
  ];
  for (const [key, msg] of predicates) {
    if (!check[key]) failures.push(msg);
  }
  return failures;
}

// ============================================================
// Manifest Registry + resolveManifest
// ============================================================

export interface ResolvedManifest {
  moduleManifestHash: bigint;
  manifest: RecipeManifest;
  flowMatrix: LineageFlowMatrix;
  tagTreeByOutputBucket: TagTreeByOutputBucket;
  targetCodeHashVector: bigint[];
  declaredTokenUniverse: bigint[];
  reachableTokenSuperset: bigint[];
  runtimeArgsSchema: bigint;
  deterministicFees: Map<string, bigint>;
}

/**
 * In-memory manifest registry. Maps moduleManifestHash -> registered manifest data.
 */
export class ManifestRegistry {
  private registry = new Map<string, {
    manifest: RecipeManifest;
    flowMatrix: LineageFlowMatrix;
    tagTreeByOutputBucket: TagTreeByOutputBucket;
    targetCodeHashVector: bigint[];
    declaredTokenUniverse: bigint[];
    reachableTokenSuperset: bigint[];
    runtimeArgsSchema: bigint;
    deterministicFees: Map<string, bigint>;
    enabled: boolean;
  }>();

  /**
   * Register a manifest. Computes and returns its moduleManifestHash.
   */
  register(
    manifest: RecipeManifest,
    flowMatrix: LineageFlowMatrix,
    tagTreeByOutputBucket: TagTreeByOutputBucket,
    targetCodeHashVector: bigint[],
    declaredTokenUniverse: bigint[],
    reachableTokenSuperset: bigint[],
    runtimeArgsSchema: bigint,
    deterministicFees: Map<string, bigint>,
  ): bigint {
    const hash = computeModuleManifestHash(manifest);
    const key = hash.toString();

    // Verify sub-hash consistency
    const computedFlowHash = hashLineageFlowMatrix(flowMatrix);
    if (computedFlowHash !== manifest.lineageFlowMatrixHash) {
      throw new Error('lineageFlowMatrixHash mismatch between manifest and provided flowMatrix');
    }
    const computedTagHash = hashTagTreeByOutputBucket(tagTreeByOutputBucket);
    if (computedTagHash !== manifest.outputBucketTagMapHash) {
      throw new Error('outputBucketTagMapHash mismatch between manifest and provided tagTree');
    }

    this.registry.set(key, {
      manifest,
      flowMatrix,
      tagTreeByOutputBucket,
      targetCodeHashVector,
      declaredTokenUniverse,
      reachableTokenSuperset,
      runtimeArgsSchema,
      deterministicFees,
      enabled: true,
    });

    return hash;
  }

  /**
   * Disable a manifest (e.g., after code hash drift detected).
   */
  disable(moduleManifestHash: bigint): void {
    const key = moduleManifestHash.toString();
    const entry = this.registry.get(key);
    if (!entry) throw new Error(`Manifest ${key} not found`);
    entry.enabled = false;
  }

  /**
   * Resolve a moduleManifestHash to its full manifest + derived objects.
   * This is what TypedCallV2 uses internally — tagTree, flowMatrix, codeHashVector
   * all come from here, NOT from external parameters.
   */
  resolveManifest(moduleManifestHash: bigint): ResolvedManifest {
    const key = moduleManifestHash.toString();
    const entry = this.registry.get(key);
    if (!entry) {
      throw new Error(`Manifest ${key} not registered`);
    }
    if (!entry.enabled) {
      throw new Error(`Manifest ${key} is disabled`);
    }
    return {
      moduleManifestHash,
      manifest: entry.manifest,
      flowMatrix: entry.flowMatrix,
      tagTreeByOutputBucket: entry.tagTreeByOutputBucket,
      targetCodeHashVector: entry.targetCodeHashVector,
      declaredTokenUniverse: entry.declaredTokenUniverse,
      reachableTokenSuperset: entry.reachableTokenSuperset,
      runtimeArgsSchema: entry.runtimeArgsSchema,
      deterministicFees: entry.deterministicFees,
    };
  }

  /**
   * Check if a manifest exists and is enabled.
   */
  isRegisteredAndEnabled(moduleManifestHash: bigint): boolean {
    const key = moduleManifestHash.toString();
    const entry = this.registry.get(key);
    return entry !== undefined && entry.enabled;
  }

  /**
   * Verify that current target code hashes match manifest expectations.
   * Returns false if any target has drifted.
   */
  verifyCodeHashes(
    moduleManifestHash: bigint,
    currentCodeHashes: bigint[],
  ): boolean {
    const resolved = this.resolveManifest(moduleManifestHash);
    if (currentCodeHashes.length !== resolved.targetCodeHashVector.length) return false;
    for (let i = 0; i < currentCodeHashes.length; i++) {
      if (currentCodeHashes[i] !== resolved.targetCodeHashVector[i]) return false;
    }
    return true;
  }
}

// ============================================================
// Target Code Hash Vector
// ============================================================

/**
 * Compute targetCodeHashVectorHash from a list of code hashes.
 */
export function hashTargetCodeHashVector(codeHashes: bigint[]): bigint {
  const dst = dstToFieldElement('RAILGUN_SOURCE_TARGET_CODE_HASH_VEC_V1');
  let state = poseidon([dst, BigInt(codeHashes.length)]);
  for (const h of codeHashes) {
    state = poseidon([state, h]);
  }
  return state;
}
