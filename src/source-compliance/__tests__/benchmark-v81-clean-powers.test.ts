/**
 * v8.1 Clean Proof Scaling Benchmark: 2^10..2^16 sources.
 *
 * This benchmark intentionally separates:
 * - legacy online clean-check work: per-source Merkle membership hashing
 * - accumulator warm-cache online proxy: delta-disjoint cache lookup work
 *
 * The accumulator rows are not a hidden-order proof implementation. They model
 * the local online work that remains after NoteAccumulatorCache and
 * BindProofCache have already been built in the background.
 */
import fs from 'fs';
import os from 'os';
import { initPoseidonPromise } from '../../utils/poseidon';
import {
  buildSourceDescriptor,
  leafHashSrc,
  nodeHashSrc,
} from '../source-descriptor';
import { comSrcV8, deriveRhoSrc } from '../commitments';

const MERKLE_DEPTH = 20;
const DEFAULT_DELTA_SIZE = 64;
const FIRST_EXP = 10;
const LAST_EXP = 16;

interface CleanPowerRow {
  exp: number;
  sources: number;
  openDescMs: number;
  membershipMs: number;
  recommitMs: number;
  legacyTotalMs: number;
  legacyHashes: number;
  deltaSize: number;
  deltaOnlineMs: number;
  deltaHits: number;
  heapUsedMB: number;
}

function makeSyntheticSources(count: number): bigint[] {
  const sources: bigint[] = new Array(count);
  for (let i = 0; i < count; i += 1) {
    sources[i] = BigInt(i + 1) * 1_000_003n + 17n;
  }
  return sources;
}

function makeRevokedDeltaOutsideNote(count: number, deltaSize: number): bigint[] {
  const delta: bigint[] = new Array(deltaSize);
  const start = BigInt(count + 1);
  for (let i = 0; i < deltaSize; i += 1) {
    delta[i] = (start + BigInt(i)) * 1_000_003n + 17n;
  }
  return delta;
}

function timeMs<T>(fn: () => T): { value: T; ms: number } {
  const start = performance.now();
  const value = fn();
  return { value, ms: performance.now() - start };
}

function fmtMs(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(2)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function selectedExponents(): number[] {
  const maxExp = Number(process.env.RAILGUN_BENCH_MAX_EXP ?? LAST_EXP);
  const cappedMax = Math.max(FIRST_EXP, Math.min(LAST_EXP, maxExp));
  return Array.from(
    { length: cappedMax - FIRST_EXP + 1 },
    (_, i) => FIRST_EXP + i,
  );
}

function benchLegacyCleanAndDeltaProxy(
  exp: number,
  deltaSize: number,
): CleanPowerRow {
  const sources = makeSyntheticSources(2 ** exp);

  const openDesc = timeMs(() => buildSourceDescriptor(sources));

  let legacyHashes = 0;
  const membership = timeMs(() => {
    for (const s of sources) {
      let cur = leafHashSrc(s);
      for (let d = 0; d < MERKLE_DEPTH; d += 1) {
        cur = nodeHashSrc(cur, BigInt(d + 1));
      }
      legacyHashes += MERKLE_DEPTH + 1;
    }
  });

  const recommit = timeMs(() => {
    const rhoSrc = deriveRhoSrc(999n, 42n, 0);
    return comSrcV8(
      openDesc.value.srcRoot,
      openDesc.value.srcCount,
      rhoSrc,
    );
  });

  const sourceMembershipCache = new Set(sources.map((s) => s.toString()));
  const revokedDelta = makeRevokedDeltaOutsideNote(sources.length, deltaSize);

  let deltaHits = 0;
  const deltaOnline = timeMs(() => {
    for (const s of revokedDelta) {
      if (sourceMembershipCache.has(s.toString())) {
        deltaHits += 1;
      }
    }
  });

  return {
    exp,
    sources: sources.length,
    openDescMs: openDesc.ms,
    membershipMs: membership.ms,
    recommitMs: recommit.ms,
    legacyTotalMs: openDesc.ms + membership.ms + recommit.ms,
    legacyHashes,
    deltaSize,
    deltaOnlineMs: deltaOnline.ms,
    deltaHits,
    heapUsedMB: process.memoryUsage().heapUsed / 1024 / 1024,
  };
}

describe('v8.1 Clean Powers Benchmark', function () {
  this.timeout(30 * 60 * 1000);

  before(async () => {
    await initPoseidonPromise;
  });

  it('measures legacy clean-check and warm-cache delta proxy at 2^10..2^16', () => {
    const deltaSize = Number(
      process.env.RAILGUN_BENCH_DELTA_SIZE ?? DEFAULT_DELTA_SIZE,
    );
    const rows = selectedExponents().map((exp) =>
      benchLegacyCleanAndDeltaProxy(exp, deltaSize),
    );

    console.log('\n  === v8.1 CLEAN PROOF COST: powers of two ===');
    console.log(
      `  Merkle depth=${MERKLE_DEPTH}; delta-disjoint proxy delta=${deltaSize}`,
    );
    console.log(
      '  +-----+---------+-----------+------------+-----------+------------+------------+',
    );
    console.log(
      '  | exp | sources | open desc | membership | recommit  | legacy sum | delta warm |',
    );
    console.log(
      '  +-----+---------+-----------+------------+-----------+------------+------------+',
    );
    for (const row of rows) {
      console.log(
        `  | ${String(row.exp).padStart(3)} ` +
          `| ${String(row.sources).padStart(7)} ` +
          `| ${fmtMs(row.openDescMs).padStart(9)} ` +
          `| ${fmtMs(row.membershipMs).padStart(10)} ` +
          `| ${fmtMs(row.recommitMs).padStart(9)} ` +
          `| ${fmtMs(row.legacyTotalMs).padStart(10)} ` +
          `| ${fmtMs(row.deltaOnlineMs).padStart(10)} |`,
      );
    }
    console.log(
      '  +-----+---------+-----------+------------+-----------+------------+------------+',
    );
    console.log(
      '  Note: delta warm is exact Set lookup over revoked delta after local cache build; it is not a hidden-order proof measurement.',
    );

    const out = {
      date: new Date().toISOString(),
      host: os.hostname(),
      platform: `${os.type()} ${os.release()} ${os.arch()}`,
      merkleDepth: MERKLE_DEPTH,
      deltaSize,
      rows,
    };
    fs.writeFileSync(
      '/tmp/railgun-clean-powers-engine.json',
      JSON.stringify(out, null, 2),
    );
  });
});
