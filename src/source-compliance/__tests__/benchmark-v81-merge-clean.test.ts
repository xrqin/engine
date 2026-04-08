/**
 * v8.1 Benchmark: Merge Proof vs Clean-Check Proof
 *
 * Merge proof (R_SRC_MERGE_N): happens EVERY transfer — exact union of input SrcSets
 * Clean-check proof (R_SRC_CLEAN): happens only on REFRESH after blacklist update
 *
 * Measures at source counts: 256, 512, 1024
 *
 * For each source count, benchmarks:
 * 1. Merge: two equal-size sets with ~25% overlap → exact union → build output descriptor
 * 2. Clean-check: verify every source prime is in cleanSourceRoot (Merkle membership)
 */
import { initPoseidonPromise, poseidon } from '../../utils/poseidon';
import { hashToPrimeSrc } from '../di-hash';
import {
  buildSourceDescriptor,
  verifySourceDescriptor,
  emptyDescFrontier,
  appendLeafSrcDesc,
  finalizeSourceFrontier,
  leafHashSrc,
  nodeHashSrc,
} from '../source-descriptor';
import type { SourceDescriptor, DescFrontier } from '../source-descriptor';
import { comSrcV8, deriveRhoSrc } from '../commitments';
import { dstToFieldElement } from '../commitments';

const enc = new TextEncoder();

function genSrcPrimes(count: number, prefix: string): bigint[] {
  const primes: bigint[] = [];
  for (let i = 0; i < count; i++) {
    primes.push(hashToPrimeSrc(enc.encode(`${prefix}-${i}`)));
  }
  return primes.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function timeMs(fn: () => void): number {
  const start = performance.now();
  fn();
  return performance.now() - start;
}

function fmt(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(1)} us`;
  if (ms < 1000) return `${ms.toFixed(2)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

/**
 * Simulate merge proof: exact union of two sorted source lists.
 *
 * This is what happens on every TransferV5:
 * 1. For each input note, recover SrcSet (from encrypted memo / cache)
 * 2. Compute exact union (sorted merge + dedup)
 * 3. Build output descriptor via frontier
 * 4. Compute source_commitment for output note
 *
 * In ZK (C_SRC_STEP circuit), this is done via SCAN + MERGE2 + Nova fold.
 * Here we benchmark the witness generation / native computation side.
 */
function benchMergeProof(sizeA: number, sizeB: number, overlapFrac: number) {
  // Generate two sets with controlled overlap
  const shared = Math.floor(Math.min(sizeA, sizeB) * overlapFrac);
  const sharedPrimes = genSrcPrimes(shared, 'shared');
  const onlyA = genSrcPrimes(sizeA - shared, 'onlyA');
  const onlyB = genSrcPrimes(sizeB - shared, 'onlyB');

  const setA = [...sharedPrimes, ...onlyA].sort((a, b) => (a < b ? -1 : 1));
  const setB = [...sharedPrimes, ...onlyB].sort((a, b) => (a < b ? -1 : 1));

  let descA: SourceDescriptor, descB: SourceDescriptor;
  let unionSet: bigint[];
  let descUnion: SourceDescriptor;
  let commitment: bigint;

  // Step 1: Build input descriptors (already done when notes were created)
  const buildInputsT = timeMs(() => {
    descA = buildSourceDescriptor(setA);
    descB = buildSourceDescriptor(setB);
  });

  // Step 2: Exact union (sorted merge + dedup) — the core merge operation
  const mergeT = timeMs(() => {
    const merged = new Set([...setA, ...setB]);
    unionSet = [...merged].sort((a, b) => (a < b ? -1 : 1));
  });

  // Step 3: Build output descriptor via frontier
  const buildOutputT = timeMs(() => {
    descUnion = buildSourceDescriptor(unionSet!);
  });

  // Step 4: Compute source_commitment for output note
  const commitT = timeMs(() => {
    const rhoSrc = deriveRhoSrc(999n, 42n, 0);
    commitment = comSrcV8(descUnion!.srcRoot, descUnion!.srcCount, rhoSrc);
  });

  const totalMerge = buildInputsT + mergeT + buildOutputT + commitT;

  return {
    sizeA, sizeB, overlapFrac, shared,
    unionSize: unionSet!.length,
    buildInputsT, mergeT, buildOutputT, commitT, totalMerge,
  };
}

/**
 * Simulate clean-check proof: verify all sources in note are still in clean universe.
 *
 * This happens ONLY after blacklist update (policy_epoch bump):
 * 1. Open source_commitment to get SrcSet leaves
 * 2. For each source prime, verify Merkle membership in cleanSourceRoot
 * 3. Compute new source_commitment with updated clean_epoch
 *
 * In ZK (R_SRC_CLEAN), this is a batch Merkle membership proof.
 * Here we benchmark the witness generation / verification side.
 */
function benchCleanCheckProof(srcCount: number, cleanUniverseSize: number) {
  // Generate source set (the note's SrcSet)
  const sources = genSrcPrimes(srcCount, 'note-src');

  // Generate clean universe (all registered sources minus blacklisted ones)
  // In practice this is a large Merkle tree on-chain
  const cleanUniverse = genSrcPrimes(cleanUniverseSize, 'clean');
  // Ensure our sources are in the clean universe
  const allClean = [...new Set([...cleanUniverse, ...sources])].sort((a, b) => (a < b ? -1 : 1));

  // Build clean source Merkle tree (simplified: just build descriptor)
  let cleanRoot: SourceDescriptor;
  const buildCleanTreeT = timeMs(() => {
    cleanRoot = buildSourceDescriptor(allClean);
  });

  // Step 1: Open source_commitment (retrieve SrcSet from memo cache)
  let noteDesc: SourceDescriptor;
  const openCommitmentT = timeMs(() => {
    noteDesc = buildSourceDescriptor(sources);
  });

  // Step 2: For each source, verify membership in clean universe
  // In real ZK: Merkle path proof per source against cleanSourceRoot
  // Here: simulate by doing Poseidon hash per source (representing path verification)
  // A Merkle path of depth D requires D Poseidon hashes per source
  const MERKLE_DEPTH = 20; // typical depth for ~1M source universe
  let membershipProofs = 0;
  const membershipT = timeMs(() => {
    for (const s of sources) {
      // Simulate Merkle path verification: D hashes per source
      let cur = leafHashSrc(s);
      for (let d = 0; d < MERKLE_DEPTH; d++) {
        cur = nodeHashSrc(cur, BigInt(d)); // simplified: hash with sibling
      }
      membershipProofs++;
    }
  });

  // Step 3: Recompute commitment with new clean_epoch
  const recommitT = timeMs(() => {
    const rhoSrc = deriveRhoSrc(999n, 42n, 0);
    comSrcV8(noteDesc!.srcRoot, noteDesc!.srcCount, rhoSrc);
  });

  const totalClean = openCommitmentT + membershipT + recommitT;

  return {
    srcCount, cleanUniverseSize,
    buildCleanTreeT, openCommitmentT, membershipT, recommitT, totalClean,
    membershipProofs,
    hashesPerSource: MERKLE_DEPTH,
  };
}

describe('v8.1 Benchmark: Merge Proof vs Clean-Check Proof', function () {
  this.timeout(600_000);

  before(async () => {
    await initPoseidonPromise;
  });

  // ==========================================================
  // 1. Merge Proof — happens every transfer
  // ==========================================================
  it('Merge proof cost at 256/512/1024 sources', () => {
    console.log('\n  ========================================');
    console.log('  MERGE PROOF (every transfer)');
    console.log('  Two inputs of equal size, ~25% overlap');
    console.log('  ========================================');
    console.log('  +----------+----------+----------+------------+------------+------------+------------+------------+');
    console.log('  | Size A   | Size B   | Union    | Build In   | Merge      | Build Out  | Commit     | Total      |');
    console.log('  +----------+----------+----------+------------+------------+------------+------------+------------+');

    for (const size of [256, 512, 1024]) {
      const half = Math.floor(size / 2);
      const r = benchMergeProof(half, half, 0.25);
      console.log(
        `  | ${String(r.sizeA).padStart(8)} | ${String(r.sizeB).padStart(8)} | ${String(r.unionSize).padStart(8)} ` +
        `| ${fmt(r.buildInputsT).padStart(10)} | ${fmt(r.mergeT).padStart(10)} | ${fmt(r.buildOutputT).padStart(10)} ` +
        `| ${fmt(r.commitT).padStart(10)} | ${fmt(r.totalMerge).padStart(10)} |`
      );
    }
    console.log('  +----------+----------+----------+------------+------------+------------+------------+------------+');
    console.log('  Note: "Build In" = build both input descriptors; "Merge" = sorted union + dedup;');
    console.log('        "Build Out" = build output descriptor via frontier; "Commit" = Com_src + DeriveRhoSrc');
    console.log('');
  });

  // ==========================================================
  // 2. Merge Proof — varying overlap ratios
  // ==========================================================
  it('Merge proof cost by overlap ratio (512 total sources)', () => {
    console.log('\n  ========================================');
    console.log('  MERGE PROOF — overlap sensitivity (512 total)');
    console.log('  ========================================');
    console.log('  +----------+----------+----------+------------+');
    console.log('  | Overlap  | Union    | Build Out| Total      |');
    console.log('  +----------+----------+----------+------------+');

    for (const overlap of [0.0, 0.25, 0.50, 0.75, 1.0]) {
      const r = benchMergeProof(256, 256, overlap);
      console.log(
        `  | ${(overlap * 100).toFixed(0).padStart(7)}% | ${String(r.unionSize).padStart(8)} ` +
        `| ${fmt(r.buildOutputT).padStart(10)} | ${fmt(r.totalMerge).padStart(10)} |`
      );
    }
    console.log('  +----------+----------+----------+------------+');
    console.log('  Note: Higher overlap → smaller union → faster build');
    console.log('');
  });

  // ==========================================================
  // 3. Clean-check Proof — happens only after blacklist update
  // ==========================================================
  it('Clean-check proof cost at 256/512/1024 sources', () => {
    console.log('\n  ========================================');
    console.log('  CLEAN-CHECK PROOF (only after blacklist update)');
    console.log('  Merkle membership: 20 hashes per source');
    console.log('  ========================================');
    console.log('  +----------+------------+------------+------------+------------+');
    console.log('  | Sources  | Open Desc  | Membership | Recommit   | Total      |');
    console.log('  +----------+------------+------------+------------+------------+');

    for (const srcCount of [256, 512, 1024]) {
      const r = benchCleanCheckProof(srcCount, 10000);
      console.log(
        `  | ${String(r.srcCount).padStart(8)} ` +
        `| ${fmt(r.openCommitmentT).padStart(10)} | ${fmt(r.membershipT).padStart(10)} ` +
        `| ${fmt(r.recommitT).padStart(10)} | ${fmt(r.totalClean).padStart(10)} |`
      );
    }
    console.log('  +----------+------------+------------+------------+------------+');
    console.log('  Note: "Open Desc" = rebuild descriptor from source list;');
    console.log('        "Membership" = simulate Merkle path verification (20 hashes × N sources);');
    console.log('        "Recommit" = Com_src with new clean_epoch');
    console.log('');
  });

  // ==========================================================
  // 4. Comparison summary
  // ==========================================================
  it('Side-by-side comparison at each source count', () => {
    console.log('\n  ========================================');
    console.log('  COMPARISON: Merge (every tx) vs Clean-Check (after blacklist)');
    console.log('  ========================================');
    console.log('  +----------+------------+------------+---------+');
    console.log('  | Sources  | Merge      | Clean-Check| Ratio   |');
    console.log('  +----------+------------+------------+---------+');

    for (const srcCount of [256, 512, 1024]) {
      const half = Math.floor(srcCount / 2);
      const mergeR = benchMergeProof(half, half, 0.25);
      const cleanR = benchCleanCheckProof(srcCount, 10000);
      const ratio = cleanR.totalClean / mergeR.totalMerge;
      console.log(
        `  | ${String(srcCount).padStart(8)} ` +
        `| ${fmt(mergeR.totalMerge).padStart(10)} ` +
        `| ${fmt(cleanR.totalClean).padStart(10)} ` +
        `| ${ratio.toFixed(1).padStart(5)}x  |`
      );
    }
    console.log('  +----------+------------+------------+---------+');
    console.log('');
    console.log('  Merge proof: happens EVERY transfer (high frequency)');
    console.log('  Clean-check: happens ONLY after blacklist update (low frequency)');
    console.log('  Clean-check is more expensive per-operation because it must');
    console.log('  verify Merkle membership for EVERY source in the set.');
    console.log('  But it only runs when policy_epoch changes (blacklist/disallow).');
    console.log('');
  });

  // ==========================================================
  // 5. Component breakdown: Poseidon hash counts
  // ==========================================================
  it('Hash operation counts', () => {
    console.log('\n  ========================================');
    console.log('  HASH OPERATION COUNTS (Poseidon calls)');
    console.log('  ========================================');

    for (const srcCount of [256, 512, 1024]) {
      const half = Math.floor(srcCount / 2);
      const unionSize = Math.floor(half * 1.75); // ~25% overlap → 75% unique each side
      const mergeHashes =
        half * 1 +       // leafHash for set A
        half * 1 +       // leafHash for set B
        unionSize * 1 +  // leafHash for union (output descriptor)
        unionSize +       // nodeHash during frontier build (avg ~1 per leaf due to carry)
        Math.ceil(Math.log2(unionSize)) + // bagHash during finalize
        1 +               // rootHash
        1 +               // deriveRhoSrc
        1;                // comSrcV8

      const cleanHashes =
        srcCount * 1 +            // leafHash to rebuild descriptor
        srcCount +                 // nodeHash during frontier build
        Math.ceil(Math.log2(srcCount)) + // bagHash finalize
        1 +                        // rootHash
        srcCount * 20 +           // Merkle membership: 20 hashes × N sources
        1 +                        // deriveRhoSrc
        1;                         // comSrcV8

      console.log(`  ${srcCount} sources:`);
      console.log(`    Merge:       ~${mergeHashes} Poseidon calls`);
      console.log(`    Clean-check: ~${cleanHashes} Poseidon calls`);
      console.log(`    Ratio:       ${(cleanHashes / mergeHashes).toFixed(1)}x`);
    }
    console.log('');
  });
});
