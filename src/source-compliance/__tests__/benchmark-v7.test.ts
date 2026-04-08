/**
 * RAILGUN Source Compliance v7 Benchmark
 *
 * Measures: Canonical Set Tree, R_MERGE2, R_MERGE_N forest, R_SUBSET_FROM_TREE,
 * NoteComV4, lineageBinding, policyBinding, per-relation proof costs.
 */
import { initPoseidonPromise } from '../../utils/poseidon';
import { hashToPrimeSrc, hashToPrimeMod, hashToPrimeEpoch } from '../di-hash';
import { buildCanonicalSetTree, verifyCanonicalSetTree } from '../canonical-set-tree';
import type { CanonicalSetTree } from '../canonical-set-tree';
import { comSrc, comMod, noteComV4, dstToFieldElement } from '../commitments';
import type { NoteV4 } from '../commitments';
import { PolicyAccumulator } from '../clean-accumulator';
import { RSA_N, NOTE_VERSION_V4 } from '../constants';
import {
  bucketSrcCommit, bucketModCommit, bucketMetaCommit,
  bucketSrcInRefDigest, bucketModInRefDigest,
  computeLineageBinding, computePolicyBinding,
  generateShieldV4, generateTransferV4Fast,
} from '../v7-proof';
import type { InputNoteLineage } from '../v7-proof';
import {
  computeInputBinding, computeOutputBinding, computeInputNoteSemantic,
} from '../relations/transfer-canonical-v4';
import {
  computeDeclaredTokenBinding, computeReachableTokenBinding,
  computeReturnBalanceBinding, computeExecBinding, computeRuntimeArgsHash,
} from '../relations/typedcall-canonical-v2';
import { MockProvingBackend } from '../proving/recursive-verifier';
import { DefaultWitnessBuilder } from '../proving/witness-builder';

const SRC_SIZES = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096];
const MOD_SIZES = [1, 2, 4, 8, 16, 24];
const G = 65537n;
const enc = new TextEncoder();

function generateSrcPrimes(count: number): bigint[] {
  const primes: bigint[] = [];
  for (let i = 0; i < count; i++) {
    primes.push(hashToPrimeSrc(enc.encode(`bench-src-${i}`)));
  }
  return primes.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function generateModPrimes(count: number): bigint[] {
  const primes: bigint[] = [];
  for (let i = 0; i < count; i++) {
    primes.push(hashToPrimeMod(enc.encode(`bench-mod-${i}`)));
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

describe('Source Compliance v7 Benchmark', function () {
  this.timeout(600_000);

  before(async () => {
    await initPoseidonPromise;
  });

  // ==========================================================
  // 1. Canonical Set Tree: build + verify by size
  // ==========================================================
  it('Canonical Set Tree: build + verify', () => {
    console.log('\n  === Canonical Set Tree (build + verify) ===');
    console.log('  +---------+-------------+-------------+');
    console.log('  | Size    | Build       | Verify      |');
    console.log('  +---------+-------------+-------------+');

    for (const size of SRC_SIZES) {
      const primes = generateSrcPrimes(size);
      let tree: CanonicalSetTree = { root: 0n, count: 0, leaves: [] };

      const buildT = timeMs(() => { tree = buildCanonicalSetTree('src', primes); });
      const verifyT = timeMs(() => { verifyCanonicalSetTree('src', tree.root, tree.count, primes); });

      console.log(`  | ${String(size).padStart(7)} | ${fmt(buildT).padStart(11)} | ${fmt(verifyT).padStart(11)} |`);
    }
    console.log('  +---------+-------------+-------------+');
  });

  // ==========================================================
  // 2. R_MERGE2: merge two trees of equal size
  // ==========================================================
  it('R_MERGE2: atomic exact union', () => {
    console.log('\n  === R_MERGE2 (merge two equal-size trees, 50% overlap) ===');
    console.log('  +---------+-------------+');
    console.log('  | Size    | Merge       |');
    console.log('  +---------+-------------+');

    const sizes = [4, 16, 64, 256, 1024];
    for (const size of sizes) {
      const primesA = generateSrcPrimes(size);
      // 50% overlap: second half of A + new primes
      const half = Math.floor(size / 2);
      const overlapPrimes = primesA.slice(half);
      const newPrimes = generateSrcPrimes(size).map(p =>
        hashToPrimeSrc(enc.encode(`merge-extra-${p}`))
      ).slice(0, half);
      const primesB = [...overlapPrimes, ...newPrimes].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

      const treeA = buildCanonicalSetTree('src', primesA);
      const treeB = buildCanonicalSetTree('src', primesB);

      const mergeT = timeMs(() => {
        // Merge = union + dedup + rebuild tree
        const allPrimes = [...new Set([...treeA.leaves, ...treeB.leaves])].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
        buildCanonicalSetTree('src', allPrimes);
      });

      console.log(`  | ${String(size).padStart(7)} | ${fmt(mergeT).padStart(11)} |`);
    }
    console.log('  +---------+-------------+');
  });

  // ==========================================================
  // 3. R_MERGE_N: fold N inputs into one output
  // ==========================================================
  it('R_MERGE_N: recursive forest (N inputs -> 1 output)', () => {
    console.log('\n  === R_MERGE_N forest (each input has 4 primes, single output bucket) ===');
    console.log('  +---------+-------------+-------------+');
    console.log('  | N       | Build       | Output Size |');
    console.log('  +---------+-------------+-------------+');

    const inputCounts = [2, 4, 8, 16, 32, 64];
    for (const n of inputCounts) {
      const inputTrees: CanonicalSetTree[] = [];
      for (let i = 0; i < n; i++) {
        const primes = [
          hashToPrimeSrc(enc.encode(`merge-n-${i}-0`)),
          hashToPrimeSrc(enc.encode(`merge-n-${i}-1`)),
          hashToPrimeSrc(enc.encode(`merge-n-${i}-2`)),
          hashToPrimeSrc(enc.encode(`merge-n-shared`)), // shared across all inputs
        ].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
        inputTrees.push(buildCanonicalSetTree('src', primes));
      }

      let outputSize = 0;
      const buildT = timeMs(() => {
        // Sequential binary merge (left fold)
        let accumulated = inputTrees[0].leaves;
        for (let i = 1; i < inputTrees.length; i++) {
          const merged = [...new Set([...accumulated, ...inputTrees[i].leaves])];
          accumulated = merged.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
        }
        const out = buildCanonicalSetTree('src', accumulated);
        outputSize = out.count;
      });

      console.log(`  | ${String(n).padStart(7)} | ${fmt(buildT).padStart(11)} | ${String(outputSize).padStart(11)} |`);
    }
    console.log('  +---------+-------------+-------------+');
  });

  // ==========================================================
  // 4. NoteComV4 + comSrc + comMod
  // ==========================================================
  it('NoteComV4 + commitment costs', () => {
    console.log('\n  === NoteComV4 + comSrc + comMod ===');

    const tree = buildCanonicalSetTree('src', generateSrcPrimes(16));
    const modTree = buildCanonicalSetTree('mod', generateModPrimes(4));
    const rho = 42n;

    const ITERS = 1000;
    const comSrcT = timeMs(() => { for (let i = 0; i < ITERS; i++) comSrc(tree.root, tree.count, rho + BigInt(i)); }) / ITERS;
    const comModT = timeMs(() => { for (let i = 0; i < ITERS; i++) comMod(modTree.root, modTree.count, rho + BigInt(i)); }) / ITERS;

    const note: NoteV4 = {
      value: 100n, tokenHash: 1001n, ownerPubkey: 42n, rhoValue: 999n,
      sourceCommitment: comSrc(tree.root, tree.count, rho),
      moduleCommitment: comMod(modTree.root, modTree.count, rho),
      cleanEpoch: 0n,
    };
    const noteComT = timeMs(() => { for (let i = 0; i < ITERS; i++) noteComV4({ ...note, rhoValue: BigInt(i) }); }) / ITERS;

    console.log(`  comSrc:    ${fmt(comSrcT)} / call (avg over ${ITERS})`);
    console.log(`  comMod:    ${fmt(comModT)} / call`);
    console.log(`  NoteComV4: ${fmt(noteComT)} / call`);
  });

  // ==========================================================
  // 5. Binding costs
  // ==========================================================
  it('Binding computation costs', () => {
    console.log('\n  === Binding Computation ===');
    const ITERS = 500;
    const chainid = 1n;
    const verifier = 0xdeadn;

    // inputBinding with N inputs
    for (const n of [1, 2, 4, 8]) {
      const inputs = Array.from({ length: n }, (_, i) => ({
        nullifier: BigInt(i + 100),
        note: {
          value: 100n, tokenHash: 1001n, ownerPubkey: 42n, rhoValue: BigInt(i),
          sourceCommitment: BigInt(i + 200), moduleCommitment: BigInt(i + 300), cleanEpoch: 0n,
        } as NoteV4,
      }));
      const t = timeMs(() => { for (let i = 0; i < ITERS; i++) computeInputBinding(chainid, verifier, 999n, inputs); }) / ITERS;
      console.log(`  inputBinding (${n} inputs): ${fmt(t)} / call`);
    }

    // lineageBinding
    const metas = [111n, 222n, 333n, 444n];
    const lineT = timeMs(() => { for (let i = 0; i < ITERS; i++) computeLineageBinding(chainid, verifier, 'TRANSFER_FAST', metas.length, metas); }) / ITERS;
    console.log(`  lineageBinding (4 buckets): ${fmt(lineT)} / call`);

    // policyBinding
    const polT = timeMs(() => { for (let i = 0; i < ITERS; i++) computePolicyBinding(chainid, verifier, 0, 5, 42n, 99n, 0); }) / ITERS;
    console.log(`  policyBinding: ${fmt(polT)} / call`);

    // execBinding
    const execT = timeMs(() => {
      for (let i = 0; i < ITERS; i++) computeExecBinding(
        chainid, verifier, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n,
      );
    }) / ITERS;
    console.log(`  execBinding: ${fmt(execT)} / call`);

    // declaredTokenBinding
    const tokens = [100n, 200n, 300n, 400n];
    const dtT = timeMs(() => { for (let i = 0; i < ITERS; i++) computeDeclaredTokenBinding(tokens); }) / ITERS;
    console.log(`  declaredTokenBinding (4 tokens): ${fmt(dtT)} / call`);

    // returnBalanceBinding
    const rbT = timeMs(() => { for (let i = 0; i < ITERS; i++) computeReturnBalanceBinding(chainid, verifier, 99n, 42n, [100n, 200n, 300n, 400n]); }) / ITERS;
    console.log(`  returnBalanceBinding: ${fmt(rbT)} / call`);
  });

  // ==========================================================
  // 6. Per-relation proof (end-to-end)
  // ==========================================================
  it('Per-relation end-to-end proof costs', () => {
    console.log('\n  === Per-Relation End-to-End Proof Costs ===');

    const acc = new PolicyAccumulator(RSA_N, G);
    const pSrc1 = hashToPrimeSrc(enc.encode('e2e-src-1'));
    const pSrc2 = hashToPrimeSrc(enc.encode('e2e-src-2'));
    const pSrc3 = hashToPrimeSrc(enc.encode('e2e-src-3'));
    const pMod1 = hashToPrimeMod(enc.encode('e2e-mod-1'));
    acc.registerSource(pSrc1);
    acc.registerSource(pSrc2);
    acc.registerSource(pSrc3);
    acc.registerModule(pMod1);

    const noteFields = { value: 100n, tokenHash: 1001n, ownerPubkey: 42n, rhoValue: 999n };
    const rhoSrc = 111n;
    const rhoMod = 222n;

    // ShieldV4
    const shieldT = timeMs(() => {
      generateShieldV4(pSrc1, rhoSrc, rhoMod, acc.policyEpoch, noteFields);
    });
    console.log(`  ShieldV4:                  ${fmt(shieldT)}`);

    // Build inputs for transfer
    const shield1 = generateShieldV4(pSrc1, rhoSrc, rhoMod, acc.policyEpoch, noteFields);
    const shield2 = generateShieldV4(pSrc2, rhoSrc + 1n, rhoMod + 1n, acc.policyEpoch, noteFields);

    function makeInputNoteLineage(shield: typeof shield1, nf: bigint, bucket: number): InputNoteLineage {
      return {
        note: {
          value: noteFields.value, tokenHash: noteFields.tokenHash,
          ownerPubkey: noteFields.ownerPubkey, rhoValue: noteFields.rhoValue,
          sourceCommitment: shield.srcCommitment, moduleCommitment: shield.modCommitment,
          cleanEpoch: BigInt(shield.cleanEpoch),
        },
        nullifier: nf,
        srcTree: shield.srcTree,
        modTree: shield.modTree,
        cleanEpoch: shield.cleanEpoch,
        tokenBucket: bucket,
      };
    }

    // TransferV4-fast (2 inputs, same token)
    const in1 = makeInputNoteLineage(shield1, 1001n, 0);
    const in2 = makeInputNoteLineage(shield2, 1002n, 0);
    const transferFastT = timeMs(() => {
      generateTransferV4Fast(
        [in1, in2], acc.policyEpoch,
        [rhoSrc + 10n], [rhoMod + 10n], 1n, 0xdeadn,
      );
    });
    console.log(`  TransferV4-fast (2 in):    ${fmt(transferFastT)}`);

    // TransferV4-fast (4 inputs, 2 buckets)
    const shield3 = generateShieldV4(pSrc3, rhoSrc + 2n, rhoMod + 2n, acc.policyEpoch, noteFields);
    const in3 = makeInputNoteLineage(shield3, 1003n, 0);
    const in4 = makeInputNoteLineage(shield1, 1004n, 1);
    const transferFast4T = timeMs(() => {
      generateTransferV4Fast(
        [in1, in2, in3, in4], acc.policyEpoch,
        [rhoSrc + 20n, rhoSrc + 21n], [rhoMod + 20n, rhoMod + 21n], 1n, 0xdeadn,
      );
    });
    console.log(`  TransferV4-fast (4 in/2b): ${fmt(transferFast4T)}`);

    // MockProvingBackend: merge forest
    const backend = new MockProvingBackend();
    const tree1 = buildCanonicalSetTree('src', [pSrc1, pSrc2].sort((a, b) => (a < b ? -1 : 1)));
    const tree2 = buildCanonicalSetTree('src', [pSrc2, pSrc3].sort((a, b) => (a < b ? -1 : 1)));
    const mergedPrimes = [...new Set([...tree1.leaves, ...tree2.leaves])].sort((a, b) => (a < b ? -1 : 1));
    const mergedTree = buildCanonicalSetTree('src', mergedPrimes);

    const proveT = timeMs(() => {
      backend.proveMergeN('src', {
        leaves: [tree1, tree2],
        internalNodes: [{
          rootL: tree1.root, countL: tree1.count,
          rootR: tree2.root, countR: tree2.count,
          rootO: mergedTree.root, countO: mergedTree.count,
        }],
        roots: [mergedTree],
      }, 42n);
    });
    console.log(`  MockBackend.proveMergeN:   ${fmt(proveT)}`);

    const proof = backend.proveMergeN('src', {
      leaves: [tree1, tree2],
      internalNodes: [{
        rootL: tree1.root, countL: tree1.count,
        rootR: tree2.root, countR: tree2.count,
        rootO: mergedTree.root, countO: mergedTree.count,
      }],
      roots: [mergedTree],
    }, 42n);
    const verifyT = timeMs(() => { backend.verifyMergeN(proof, 42n); });
    console.log(`  MockBackend.verifyMergeN:  ${fmt(verifyT)}`);

    // Bucket commitment chain
    const rho = 12345n;
    const bucketChainT = timeMs(() => {
      for (let tau = 0; tau < 4; tau++) {
        const bSrc = bucketSrcCommit(mergedTree.root, mergedTree.count, rho + BigInt(tau));
        const bMod = bucketModCommit(mergedTree.root, mergedTree.count, rho + BigInt(tau + 100));
        const bSrcRef = bucketSrcInRefDigest(tau, 'private_out', [1n, 2n, 3n]);
        const bModRef = bucketModInRefDigest(tau, 'private_out', [4n, 5n, 6n]);
        bucketMetaCommit('private_out', bSrcRef, bModRef, bSrc, bMod);
      }
    });
    console.log(`  Bucket chain (4 buckets):  ${fmt(bucketChainT)}`);

    // inSem computation
    const inSemT = timeMs(() => {
      for (let i = 0; i < 100; i++) {
        computeInputNoteSemantic(BigInt(i), 1001n, 200n, 300n, 0n);
      }
    }) / 100;
    console.log(`  inSem (per note):          ${fmt(inSemT)}`);

    console.log('');
  });

  // ==========================================================
  // 7. Scaling: tree build as |S| grows (v7 no cap)
  // ==========================================================
  it('Scaling: tree build time as |SrcSet| grows (no cap)', () => {
    console.log('\n  === v7 Scaling: No Note-Level Cap ===');
    console.log('  +---------+-------------+----------+');
    console.log('  | |S|     | TreeBuild   | root     |');
    console.log('  +---------+-------------+----------+');

    for (const size of SRC_SIZES) {
      const primes = generateSrcPrimes(size);
      let root = 0n;
      const t = timeMs(() => {
        const tree = buildCanonicalSetTree('src', primes);
        root = tree.root;
      });
      const rootStr = root.toString(16).slice(0, 8) + '...';
      console.log(`  | ${String(size).padStart(7)} | ${fmt(t).padStart(11)} | ${rootStr.padStart(8)} |`);
    }
    console.log('  +---------+-------------+----------+');
    console.log('  (v6 would reject |S| > CIRCUIT_MAX. v7 scales gracefully.)');
  });
});
