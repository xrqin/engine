/**
 * IVC Benchmark — RAILGUN Source Compliance
 *
 * Measures IVC fold performance across different source count scales.
 * Compares: Mock (no IVC) vs IVC backend.
 */
import { initPoseidonPromise } from '../../utils/poseidon';
import { hashToPrimeSrc } from '../di-hash';
import { buildCanonicalSetTree } from '../canonical-set-tree';
import type { CanonicalSetTree } from '../canonical-set-tree';
import { MockProvingBackend } from '../proving/recursive-verifier';
import {
  IVCProvingBackend,
  ivcProveMergeN,
  ivcVerifyMergeN,
  ivcInit,
  ivcMergeStep,
} from '../proving/ivc-backend';
import type { IVCStepInput } from '../proving/ivc-backend';
import type { MergeForest } from '../proving/backend-interface';

const enc = new TextEncoder();

function genSrcPrimes(count: number, prefix: string = 'ivc'): bigint[] {
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

/** Build a simple merge forest from N input trees (single output bucket) */
function buildSimpleForest(inputTrees: CanonicalSetTree[]): MergeForest {
  const internalNodes: { rootL: bigint; countL: number; rootR: bigint; countR: number; rootO: bigint; countO: number }[] = [];

  // Sequential binary merge
  let acc = inputTrees[0];
  for (let i = 1; i < inputTrees.length; i++) {
    const merged = [...new Set([...acc.leaves, ...inputTrees[i].leaves])].sort((a, b) => (a < b ? -1 : 1));
    const out = buildCanonicalSetTree('src', merged);
    internalNodes.push({
      rootL: acc.root, countL: acc.count,
      rootR: inputTrees[i].root, countR: inputTrees[i].count,
      rootO: out.root, countO: out.count,
    });
    acc = out;
  }

  return { leaves: inputTrees, internalNodes, roots: [acc] };
}

describe('IVC Benchmark', function () {
  this.timeout(600_000);

  before(async () => {
    await initPoseidonPromise;
  });

  // ==========================================================
  // 1. Single IVC Step (R_MERGE2 fold)
  // ==========================================================
  it('IVC single step cost by set size', () => {
    console.log('\n  === IVC Single Step: ivcMergeStep (fold one R_MERGE2) ===');
    console.log('  +---------+---------+-------------+-------------+');
    console.log('  | AccSize | AddSize | Step Time   | Result Size |');
    console.log('  +---------+---------+-------------+-------------+');

    const scenarios = [
      { accSize: 1, addSize: 1 },
      { accSize: 4, addSize: 4 },
      { accSize: 16, addSize: 16 },
      { accSize: 64, addSize: 4 },
      { accSize: 64, addSize: 64 },
      { accSize: 256, addSize: 4 },
      { accSize: 256, addSize: 256 },
      { accSize: 1024, addSize: 4 },
      { accSize: 1024, addSize: 1024 },
    ];

    for (const { accSize, addSize } of scenarios) {
      const accPrimes = genSrcPrimes(accSize, 'acc');
      const addPrimes = genSrcPrimes(addSize, 'add');
      const accTree = buildCanonicalSetTree('src', accPrimes);
      const addTree = buildCanonicalSetTree('src', addPrimes);

      const state = ivcInit('src', accTree);
      const input: IVCStepInput = {
        rightRoot: addTree.root,
        rightCount: addTree.count,
        rightLeaves: addTree.leaves,
      };

      let resultSize = 0;
      const t = timeMs(() => {
        const { mergedLeaves } = ivcMergeStep('src', state, input, accPrimes);
        resultSize = mergedLeaves.length;
      });

      console.log(`  | ${String(accSize).padStart(7)} | ${String(addSize).padStart(7)} | ${fmt(t).padStart(11)} | ${String(resultSize).padStart(11)} |`);
    }
    console.log('  +---------+---------+-------------+-------------+');
  });

  // ==========================================================
  // 2. Full IVC Fold: N inputs -> 1 output (vary N)
  // ==========================================================
  it('IVC full fold: N inputs (each 4 primes, 25% overlap)', () => {
    console.log('\n  === IVC Full Fold: ivcProveMergeN + ivcVerifyMergeN ===');
    console.log('  +---------+-------------+-------------+-------------+-------------+');
    console.log('  | N       | Prove       | Verify      | Proof Size  | Output Size |');
    console.log('  +---------+-------------+-------------+-------------+-------------+');

    const inputCounts = [2, 4, 8, 16, 32, 64, 128];
    for (const n of inputCounts) {
      const inputTrees: CanonicalSetTree[] = [];
      for (let i = 0; i < n; i++) {
        // Each input has 4 primes, 1 shared across all (25% overlap base)
        const primes = [
          hashToPrimeSrc(enc.encode(`fold-${i}-0`)),
          hashToPrimeSrc(enc.encode(`fold-${i}-1`)),
          hashToPrimeSrc(enc.encode(`fold-${i}-2`)),
          hashToPrimeSrc(enc.encode(`fold-shared`)), // shared
        ].sort((a, b) => (a < b ? -1 : 1));
        inputTrees.push(buildCanonicalSetTree('src', primes));
      }

      const lineageBinding = 42n;
      let proof: ReturnType<typeof ivcProveMergeN> | undefined;
      let proofSize = 0;
      let outputSize = 0;

      const proveT = timeMs(() => {
        proof = ivcProveMergeN('src', inputTrees, lineageBinding);
        outputSize = proof.finalTree.count;
      });

      // Measure serialized proof size
      const proofObj = new IVCProvingBackend().proveMergeN('src', buildSimpleForest(inputTrees), lineageBinding);
      proofSize = proofObj.data.length;

      const verifyT = timeMs(() => {
        ivcVerifyMergeN(proof!, lineageBinding);
      });

      console.log(`  | ${String(n).padStart(7)} | ${fmt(proveT).padStart(11)} | ${fmt(verifyT).padStart(11)} | ${(proofSize / 1024).toFixed(1).padStart(8)} KB | ${String(outputSize).padStart(11)} |`);
    }
    console.log('  +---------+-------------+-------------+-------------+-------------+');
  });

  // ==========================================================
  // 3. IVC vs Mock: same workload comparison
  // ==========================================================
  it('IVC vs Mock backend comparison', () => {
    console.log('\n  === IVC vs Mock Backend (same forest, same workload) ===');
    console.log('  +---------+-------------+-------------+-------------+-------------+');
    console.log('  | N       | Mock Prove  | IVC Prove   | Mock Verify | IVC Verify  |');
    console.log('  +---------+-------------+-------------+-------------+-------------+');

    const mock = new MockProvingBackend();
    const ivc = new IVCProvingBackend();

    for (const n of [2, 4, 8, 16, 32, 64]) {
      const inputTrees: CanonicalSetTree[] = [];
      for (let i = 0; i < n; i++) {
        const primes = [
          hashToPrimeSrc(enc.encode(`cmp-${i}-0`)),
          hashToPrimeSrc(enc.encode(`cmp-${i}-1`)),
          hashToPrimeSrc(enc.encode(`cmp-shared`)),
        ].sort((a, b) => (a < b ? -1 : 1));
        inputTrees.push(buildCanonicalSetTree('src', primes));
      }

      const forest = buildSimpleForest(inputTrees);
      const lb = 99n;

      let mockProof: any, ivcProof: any;
      const mockProveT = timeMs(() => { mockProof = mock.proveMergeN('src', forest, lb); });
      const ivcProveT = timeMs(() => { ivcProof = ivc.proveMergeN('src', forest, lb); });
      const mockVerifyT = timeMs(() => { mock.verifyMergeN(mockProof, lb); });
      const ivcVerifyT = timeMs(() => { ivc.verifyMergeN(ivcProof, lb); });

      console.log(`  | ${String(n).padStart(7)} | ${fmt(mockProveT).padStart(11)} | ${fmt(ivcProveT).padStart(11)} | ${fmt(mockVerifyT).padStart(11)} | ${fmt(ivcVerifyT).padStart(11)} |`);
    }
    console.log('  +---------+-------------+-------------+-------------+-------------+');
  });

  // ==========================================================
  // 4. Scaling: large source counts via IVC
  // ==========================================================
  it('IVC scaling: large source counts (total primes 1 -> 4096)', () => {
    console.log('\n  === IVC Scaling: Total Source Count 1 -> 4096 ===');
    console.log('  (Each input tree has 4 primes, N inputs = totalSources/3)');
    console.log('  +---------+---------+-------------+-------------+-------------+');
    console.log('  | Sources | N Trees | IVC Prove   | IVC Verify  | Proof KB    |');
    console.log('  +---------+---------+-------------+-------------+-------------+');

    const targetSizes = [4, 16, 64, 256, 512, 1024, 2048, 4096];
    const ivc = new IVCProvingBackend();

    for (const target of targetSizes) {
      // Each tree has 4 primes, ~1 shared -> ~3 unique per tree
      const nTrees = Math.max(2, Math.ceil(target / 3));
      const inputTrees: CanonicalSetTree[] = [];
      for (let i = 0; i < nTrees; i++) {
        const primes = [
          hashToPrimeSrc(enc.encode(`scale-${i}-0`)),
          hashToPrimeSrc(enc.encode(`scale-${i}-1`)),
          hashToPrimeSrc(enc.encode(`scale-${i}-2`)),
          hashToPrimeSrc(enc.encode(`scale-shared`)),
        ].sort((a, b) => (a < b ? -1 : 1));
        inputTrees.push(buildCanonicalSetTree('src', primes));
      }

      const forest = buildSimpleForest(inputTrees);
      const lb = 42n;

      let proof: any;
      const proveT = timeMs(() => { proof = ivc.proveMergeN('src', forest, lb); });
      const verifyT = timeMs(() => { ivc.verifyMergeN(proof, lb); });
      const proofKB = proof.data.length / 1024;

      console.log(`  | ${String(target).padStart(7)} | ${String(nTrees).padStart(7)} | ${fmt(proveT).padStart(11)} | ${fmt(verifyT).padStart(11)} | ${proofKB.toFixed(1).padStart(8)} KB |`);
    }
    console.log('  +---------+---------+-------------+-------------+-------------+');
    console.log('  (No protocol-level cap. Cost scales linearly with input count.)');
  });

  // ==========================================================
  // 5. IVC proof correctness: prove + verify round trip
  // ==========================================================
  it('IVC correctness: prove -> verify -> tamper -> reject', () => {
    const primes1 = genSrcPrimes(4, 'correct-1');
    const primes2 = genSrcPrimes(4, 'correct-2');
    const tree1 = buildCanonicalSetTree('src', primes1);
    const tree2 = buildCanonicalSetTree('src', primes2);
    const lb = 12345n;

    // Prove + verify should pass
    const proof = ivcProveMergeN('src', [tree1, tree2], lb);
    const valid = ivcVerifyMergeN(proof, lb);
    if (!valid) throw new Error('IVC proof should be valid');

    // Tamper: wrong lineageBinding
    const invalid = ivcVerifyMergeN(proof, 99999n);
    if (invalid) throw new Error('IVC proof should fail with wrong lineageBinding');

    // Tamper: modify foldedCommitment
    const tamperedProof = { ...proof, foldedCommitment: proof.foldedCommitment + 1n };
    const invalid2 = ivcVerifyMergeN(tamperedProof, lb);
    if (invalid2) throw new Error('IVC proof should fail with tampered commitment');

    console.log('\n  IVC correctness: prove/verify/tamper-reject all passed');
  });
});
