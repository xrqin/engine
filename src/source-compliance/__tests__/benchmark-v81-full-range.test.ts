/**
 * v8.1 Benchmark: Merge + Clean-Check at 2^1 through 2^7 (2,4,8,16,32,64,128)
 * Supplements the 256/512/1024 benchmark.
 */
import { initPoseidonPromise, poseidon } from '../../utils/poseidon';
import { hashToPrimeSrc } from '../di-hash';
import { buildSourceDescriptor, leafHashSrc, nodeHashSrc } from '../source-descriptor';
import { comSrcV8, deriveRhoSrc, dstToFieldElement } from '../commitments';

const enc = new TextEncoder();
function genPrimes(n: number, pfx: string): bigint[] {
  const p: bigint[] = [];
  for (let i = 0; i < n; i++) p.push(hashToPrimeSrc(enc.encode(`${pfx}-${i}`)));
  return p.sort((a, b) => (a < b ? -1 : 1));
}
function timeMs(fn: () => void): number { const s = performance.now(); fn(); return performance.now() - s; }
function fmt(ms: number): string {
  if (ms < 1) return `${(ms*1000).toFixed(1)} us`;
  if (ms < 1000) return `${ms.toFixed(2)} ms`;
  return `${(ms/1000).toFixed(2)} s`;
}

describe('v8.1 Benchmark: Full Range 2^1 to 2^10', function () {
  this.timeout(600_000);
  before(async () => { await initPoseidonPromise; });

  it('Merge + Clean-Check at 2,4,8,16,32,64,128,256,512,1024', () => {
    const sizes = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

    console.log('\n  ========== MERGE PROOF (every transfer) ==========');
    console.log('  Two inputs of equal size, ~25% overlap');
    console.log('  +----------+----------+----------+------------+------------+------------+');
    console.log('  | Total    | Per Side | Union    | Build Desc | Merge+Out  | Total      |');
    console.log('  +----------+----------+----------+------------+------------+------------+');

    const mergeResults: number[] = [];
    for (const total of sizes) {
      const half = Math.max(1, Math.floor(total / 2));
      const shared = Math.floor(half * 0.25);
      const sp = genPrimes(shared, 'sh');
      const a = [...sp, ...genPrimes(half - shared, 'a')].sort((a, b) => (a < b ? -1 : 1));
      const b = [...sp, ...genPrimes(half - shared, 'b')].sort((a, b) => (a < b ? -1 : 1));

      let descA: any, descB: any, unionSet: bigint[], descU: any;
      const t1 = timeMs(() => { descA = buildSourceDescriptor(a); descB = buildSourceDescriptor(b); });
      const t2 = timeMs(() => {
        unionSet = [...new Set([...a, ...b])].sort((x, y) => (x < y ? -1 : 1));
        descU = buildSourceDescriptor(unionSet!);
        deriveRhoSrc(1n, 2n, 0);
        comSrcV8(descU.srcRoot, descU.srcCount, 3n);
      });
      const totalT = t1 + t2;
      mergeResults.push(totalT);
      console.log(`  | ${String(total).padStart(8)} | ${String(half).padStart(8)} | ${String(unionSet!.length).padStart(8)} | ${fmt(t1).padStart(10)} | ${fmt(t2).padStart(10)} | ${fmt(totalT).padStart(10)} |`);
    }
    console.log('  +----------+----------+----------+------------+------------+------------+');

    console.log('\n  ========== CLEAN-CHECK PROOF (after blacklist only) ==========');
    console.log('  Merkle membership: 20 hashes per source');
    console.log('  +----------+------------+------------+------------+');
    console.log('  | Sources  | Build Desc | Membership | Total      |');
    console.log('  +----------+------------+------------+------------+');

    const cleanResults: number[] = [];
    for (const n of sizes) {
      const srcs = genPrimes(n, 'c');
      let desc: any;
      const t1 = timeMs(() => { desc = buildSourceDescriptor(srcs); });
      const t2 = timeMs(() => {
        for (const s of srcs) {
          let cur = leafHashSrc(s);
          for (let d = 0; d < 20; d++) cur = nodeHashSrc(cur, BigInt(d));
        }
        deriveRhoSrc(1n, 2n, 0);
        comSrcV8(desc.srcRoot, desc.srcCount, 3n);
      });
      const totalT = t1 + t2;
      cleanResults.push(totalT);
      console.log(`  | ${String(n).padStart(8)} | ${fmt(t1).padStart(10)} | ${fmt(t2).padStart(10)} | ${fmt(totalT).padStart(10)} |`);
    }
    console.log('  +----------+------------+------------+------------+');

    console.log('\n  ========== COMPARISON ==========');
    console.log('  +----------+------------+------------+---------+');
    console.log('  | Sources  | Merge      | Clean-Check| Ratio   |');
    console.log('  +----------+------------+------------+---------+');
    sizes.forEach((n, i) => {
      const ratio = cleanResults[i] / mergeResults[i];
      console.log(`  | ${String(n).padStart(8)} | ${fmt(mergeResults[i]).padStart(10)} | ${fmt(cleanResults[i]).padStart(10)} | ${ratio.toFixed(1).padStart(5)}x  |`);
    });
    console.log('  +----------+------------+------------+---------+');
    console.log('');
  });
});
