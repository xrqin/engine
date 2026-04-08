/**
 * Transaction Preflight Limit Checks (D.8)
 *
 * Validates that a transaction's parameters are within the configured
 * implementation upper bounds before proof generation begins.
 *
 * Checks:
 * - MAX_SRC_COUNT: per-output source set size
 * - MAX_STREAM_CHUNKS: per-output stream chunk count
 * - MAX_IVC_STEPS: total recursive step count
 * - Memo size / padding policy
 * - Bucket count
 * - Carry input reference count
 * - Flow matrix dimensions (for typed calls)
 */

import {
  MAX_SRC_COUNT,
  MAX_STREAM_CHUNKS,
  MAX_IVC_STEPS,
  B_SCAN,
} from './constants';

// ============================================================
// Types
// ============================================================

export interface PreflightError {
  code: string;
  message: string;
  limit: number;
  actual: number;
}

export interface PreflightInput {
  /** Per-output-bucket source counts */
  bucketSourceCounts: number[];
  /** Per-output-bucket module counts */
  bucketModuleCounts: number[];
  /** Total number of carry-input references across all buckets */
  totalCarryInputRefs: number;
  /** Total estimated IVC steps (source merge + module merge) */
  estimatedIvcSteps: number;
  /** Total memo payload size in bytes (source + module payloads) */
  memoPayloadBytes: number;
  /** Number of output buckets */
  bucketCount: number;
  /** For typed calls: flow matrix dimensions */
  flowMatrixInputBuckets?: number;
  flowMatrixOutputBuckets?: number;
}

// ============================================================
// Configuration
// ============================================================

/** Maximum number of output buckets per transaction */
export const MAX_BUCKET_COUNT = 16;

/** Maximum carry-input references per transaction */
export const MAX_CARRY_INPUT_REFS = 64;

/** Maximum memo payload size in bytes (without encryption overhead) */
export const MAX_MEMO_PAYLOAD_BYTES = 65536; // 64 KiB

/** Maximum flow matrix dimension (input or output buckets) */
export const MAX_FLOW_MATRIX_DIM = 16;

/** Memo size bucket boundaries for optional padding */
export const MEMO_SIZE_BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

// ============================================================
// Validation
// ============================================================

/**
 * Validate all preflight limits. Returns an array of errors (empty = pass).
 */
export function validatePreflightLimits(input: PreflightInput): PreflightError[] {
  const errors: PreflightError[] = [];

  // D.8a: MAX_SRC_COUNT per bucket
  for (let i = 0; i < input.bucketSourceCounts.length; i++) {
    if (input.bucketSourceCounts[i] > MAX_SRC_COUNT) {
      errors.push({
        code: 'SRC_COUNT_EXCEEDED',
        message: `Bucket ${i} source count ${input.bucketSourceCounts[i]} exceeds MAX_SRC_COUNT`,
        limit: MAX_SRC_COUNT,
        actual: input.bucketSourceCounts[i],
      });
    }
  }

  // D.8b: MAX_STREAM_CHUNKS per bucket
  for (let i = 0; i < input.bucketSourceCounts.length; i++) {
    const chunks = Math.ceil(input.bucketSourceCounts[i] / B_SCAN);
    if (chunks > MAX_STREAM_CHUNKS) {
      errors.push({
        code: 'STREAM_CHUNKS_EXCEEDED',
        message: `Bucket ${i} requires ${chunks} stream chunks, exceeds MAX_STREAM_CHUNKS`,
        limit: MAX_STREAM_CHUNKS,
        actual: chunks,
      });
    }
  }

  // D.8c: MAX_IVC_STEPS total
  if (input.estimatedIvcSteps > MAX_IVC_STEPS) {
    errors.push({
      code: 'IVC_STEPS_EXCEEDED',
      message: `Estimated ${input.estimatedIvcSteps} IVC steps exceeds MAX_IVC_STEPS`,
      limit: MAX_IVC_STEPS,
      actual: input.estimatedIvcSteps,
    });
  }

  // D.8d: Memo size
  if (input.memoPayloadBytes > MAX_MEMO_PAYLOAD_BYTES) {
    errors.push({
      code: 'MEMO_SIZE_EXCEEDED',
      message: `Memo payload ${input.memoPayloadBytes} bytes exceeds MAX_MEMO_PAYLOAD_BYTES`,
      limit: MAX_MEMO_PAYLOAD_BYTES,
      actual: input.memoPayloadBytes,
    });
  }

  // D.8e: Carry input refs
  if (input.totalCarryInputRefs > MAX_CARRY_INPUT_REFS) {
    errors.push({
      code: 'CARRY_INPUT_REFS_EXCEEDED',
      message: `Total carry-input refs ${input.totalCarryInputRefs} exceeds MAX_CARRY_INPUT_REFS`,
      limit: MAX_CARRY_INPUT_REFS,
      actual: input.totalCarryInputRefs,
    });
  }

  // Bucket count
  if (input.bucketCount > MAX_BUCKET_COUNT) {
    errors.push({
      code: 'BUCKET_COUNT_EXCEEDED',
      message: `Bucket count ${input.bucketCount} exceeds MAX_BUCKET_COUNT`,
      limit: MAX_BUCKET_COUNT,
      actual: input.bucketCount,
    });
  }

  // D.8f: Flow matrix dimensions
  if (input.flowMatrixInputBuckets !== undefined &&
      input.flowMatrixInputBuckets > MAX_FLOW_MATRIX_DIM) {
    errors.push({
      code: 'FLOW_MATRIX_INPUT_DIM_EXCEEDED',
      message: `Flow matrix input dimension ${input.flowMatrixInputBuckets} exceeds MAX_FLOW_MATRIX_DIM`,
      limit: MAX_FLOW_MATRIX_DIM,
      actual: input.flowMatrixInputBuckets,
    });
  }
  if (input.flowMatrixOutputBuckets !== undefined &&
      input.flowMatrixOutputBuckets > MAX_FLOW_MATRIX_DIM) {
    errors.push({
      code: 'FLOW_MATRIX_OUTPUT_DIM_EXCEEDED',
      message: `Flow matrix output dimension ${input.flowMatrixOutputBuckets} exceeds MAX_FLOW_MATRIX_DIM`,
      limit: MAX_FLOW_MATRIX_DIM,
      actual: input.flowMatrixOutputBuckets,
    });
  }

  return errors;
}

// ============================================================
// Helpers
// ============================================================

/**
 * Estimate IVC steps for a set of source counts (one per bucket).
 * Each source merge tree of size N requires ~2N-1 steps.
 * Module merges add ~2M-1 steps per bucket.
 */
export function estimateIvcSteps(
  bucketSourceCounts: number[],
  bucketModuleCounts: number[],
): number {
  let total = 0;
  for (const sc of bucketSourceCounts) {
    if (sc > 1) total += 2 * sc - 1;
    else if (sc === 1) total += 1;
  }
  for (const mc of bucketModuleCounts) {
    if (mc > 1) total += 2 * mc - 1;
    else if (mc === 1) total += 1;
  }
  return total;
}

/**
 * Compute the padded memo size for a given payload size.
 * Returns the smallest size bucket >= payloadSize, or payloadSize if it
 * exceeds all buckets.
 */
export function paddedMemoSize(payloadSize: number): number {
  for (const bucket of MEMO_SIZE_BUCKETS) {
    if (payloadSize <= bucket) return bucket;
  }
  return payloadSize;
}
