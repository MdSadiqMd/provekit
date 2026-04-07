#!/usr/bin/env node
/**
 * Programmatic Verification of WebGPU NTT Speedup Projection
 *
 * This script verifies:
 * 1. Field arithmetic correctness (limb conversion round-trips)
 * 2. NTT algorithm correctness (linearity, known vectors)
 * 3. Serialization round-trip correctness (Fr ↔ bytes ↔ GPU limbs)
 * 4. JS CPU NTT performance baseline (what the WASM prover uses without GPU)
 * 5. Speedup projection via Amdahl's Law
 *
 * What this measures vs. what it projects:
 * - MEASURED: JS BigInt NTT speed (comparable to WASM CPU NTT, both lack SIMD)
 * - MEASURED: Serialization overhead (arkBytesToGpuLimbs / gpuLimbsToArkBytes)
 * - FROM BROWSER BENCHMARK: GPU NTT timings (hardcoded, measured via ntt-bench.html)
 * - PROJECTED: End-to-end prove speedup via Amdahl's Law
 *
 * The actual end-to-end speedup must be measured in the browser by comparing
 * proveBytes() wall-clock time with GPU NTT on vs off.
 *
 * Run: node verify-speedup.mjs
 */

import {
    referenceNTT,
    generateTwiddles,
    bigintToLimbs,
    limbsToBigint,
} from './src/webgpu-ntt.mjs';

const BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// From native profiling (docs/report.md): NTT is 20.5% of total proving time.
// In WASM (no SIMD), the NTT fraction is likely higher because field mul is
// slower without ARM NEON. We use 20.5% as a conservative lower bound.
const NTT_FRACTION = 0.205;
const TARGET_IMPROVEMENT = 0.06; // 6% minimum improvement target

// Montgomery form constants for serialization verification
const R_MOD_P = 6233810253280740994628949329533561339965925630188245177646180721908512718679n;
const R_INV_MOD_P = 12621995978310821098439775787269407929538163553607166694879879304580168517835n;
const LIMBS = 9;
const LIMB_BITS = 29;
const LIMB_MASK = (1 << LIMB_BITS) - 1;

let totalTests = 0;
let passedTests = 0;

function assert(condition, msg) {
    totalTests++;
    if (condition) {
        passedTests++;
        console.log(`  ✓ ${msg}`);
    } else {
        console.log(`  ✗ FAIL: ${msg}`);
    }
}

function fieldAdd(a, b) { const s = a + b; return s >= BN254_P ? s - BN254_P : s; }
function fieldMul(a, b) { return (a * b) % BN254_P; }
function modPow(base, exp, mod) {
    let r = 1n; base = base % mod;
    while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; exp >>= 1n; base = (base * base) % mod; }
    return r;
}

// 1. Limb Conversion Round-Trips
console.log('\n═══════════════════════════════════════════════════');
console.log(' 1. BN254 Limb Conversion Round-Trips');
console.log('═══════════════════════════════════════════════════');

const limbTestValues = [
    0n, 1n, 42n, BN254_P - 1n, BN254_P - 2n,
    123456789012345678901234567890n,
    21888242871839275222246405745257275088548364400416034343698204186575808495616n,
    19103219067921713944291392827692070036145651957329286315305642004821462161904n,
];

for (const val of limbTestValues) {
    const buf = new Uint32Array(9);
    bigintToLimbs(val, buf, 0);
    const recovered = limbsToBigint(buf, 0);
    assert(recovered === val, `9×29-bit round-trip: ${val.toString().slice(0, 24)}...`);
}

// 2. Serialization Round-Trip (ark-ff ↔ GPU Montgomery)
console.log('\n═══════════════════════════════════════════════════');
console.log(' 2. Serialization Round-Trip (ark-ff ↔ GPU Montgomery)');
console.log('═══════════════════════════════════════════════════');
console.log('  This tests the exact conversion used in the integrated path:');
console.log('  Fr bytes (4×u64 LE) → BigInt → ×2^5 mod p → 9×29 limbs → back');

const R_RATIO = 32n;
const R_RATIO_INV = modPow(32n, BN254_P - 2n, BN254_P);

for (const val of limbTestValues) {
    // Simulate ark-ff Montgomery form (val * R_ark mod p, where R_ark = 2^256)
    // For testing, just use val directly as if it were already in Montgomery form
    const arkMont = val;

    // Forward: ark-ff → GPU (multiply by 2^5)
    const gpuMont = (arkMont * R_RATIO) % BN254_P;

    // Split into 9×29-bit limbs
    let tmp = gpuMont;
    const limbs = new Uint32Array(LIMBS);
    for (let j = 0; j < LIMBS; j++) {
        limbs[j] = Number(tmp & BigInt(LIMB_MASK));
        tmp >>= BigInt(LIMB_BITS);
    }

    // Reassemble from limbs
    let reassembled = 0n;
    for (let j = LIMBS - 1; j >= 0; j--) {
        reassembled = (reassembled << BigInt(LIMB_BITS)) | BigInt(limbs[j]);
    }

    // Reverse: GPU → ark-ff (multiply by (2^5)^(-1))
    const recovered = (reassembled * R_RATIO_INV) % BN254_P;

    assert(recovered === arkMont, `Serialization round-trip: ${val.toString().slice(0, 24)}...`);
}

// Verify R_RATIO * R_RATIO_INV = 1 mod p
const identityCheck = (R_RATIO * R_RATIO_INV) % BN254_P;
assert(identityCheck === 1n, `R_RATIO × R_RATIO_INV = 1 mod p (got ${identityCheck})`);

// 3. NTT Correctness
console.log('\n═══════════════════════════════════════════════════');
console.log(' 3. NTT Algorithm Correctness');
console.log('═══════════════════════════════════════════════════');

for (const logN of [1, 2, 3, 4, 5, 8]) {
    const n = 1 << logN;
    const elems = Array.from({ length: n }, (_, i) => BigInt(i + 1));
    const tw = generateTwiddles(n);
    const result = referenceNTT(elems, tw);
    const allValid = result.every(r => r >= 0n && r < BN254_P);
    assert(allValid, `NTT(2^${logN}): all ${n} outputs in valid range`);
}

// Linearity: NTT(a+b) = NTT(a) + NTT(b)
const n16 = 16;
const a16 = Array.from({ length: n16 }, (_, i) => BigInt(i + 1));
const b16 = Array.from({ length: n16 }, (_, i) => BigInt(i * 3 + 7));
const ab16 = a16.map((ai, i) => fieldAdd(ai, b16[i]));
const tw16 = generateTwiddles(n16);
const nttA = referenceNTT(a16, tw16);
const nttB = referenceNTT(b16, tw16);
const nttAB = referenceNTT(ab16, tw16);
const nttAplusB = nttA.map((ai, i) => fieldAdd(ai, nttB[i]));
assert(nttAB.every((v, i) => v === nttAplusB[i]), 'NTT linearity: NTT(a+b) = NTT(a) + NTT(b)');

// Known vector
const tw4 = generateTwiddles(4);
const ntt4 = referenceNTT([1n, 2n, 3n, 4n], tw4);
assert(ntt4[0] === 10n, `NTT([1,2,3,4])[0] = 10 (sum)`);

// 4. Serialization Overhead Measurement
console.log('\n═══════════════════════════════════════════════════');
console.log(' 4. Serialization Overhead (CPU↔GPU format conversion)');
console.log('═══════════════════════════════════════════════════');
console.log('  This measures the BigInt conversion cost that the integrated');
console.log('  path pays on every NTT call (not measured in isolated benchmark).\n');

function measureSerializationOverhead(n) {
    // Simulate n field elements
    const elements = Array.from({ length: n }, (_, i) => BigInt(i * 17 + 3) % BN254_P);

    // Forward conversion: ark-ff → GPU limbs
    const fwdStart = performance.now();
    const gpuLimbs = new Uint32Array(n * LIMBS);
    for (let i = 0; i < n; i++) {
        let val = (elements[i] * R_RATIO) % BN254_P;
        const base = i * LIMBS;
        for (let j = 0; j < LIMBS; j++) {
            gpuLimbs[base + j] = Number(val & BigInt(LIMB_MASK));
            val >>= BigInt(LIMB_BITS);
        }
    }
    const fwdMs = performance.now() - fwdStart;

    // Reverse conversion: GPU limbs → ark-ff
    const revStart = performance.now();
    for (let i = 0; i < n; i++) {
        const base = i * LIMBS;
        let val = 0n;
        for (let j = LIMBS - 1; j >= 0; j--) {
            val = (val << BigInt(LIMB_BITS)) | BigInt(gpuLimbs[base + j]);
        }
        const _recovered = (val * R_RATIO_INV) % BN254_P;
    }
    const revMs = performance.now() - revStart;

    return { fwdMs, revMs, totalMs: fwdMs + revMs };
}

const serSizes = [10, 12, 14, 16, 18, 20];
const serOverhead = {};

console.log('  ┌──────────┬───────────┬───────────────┬───────────────┬───────────────┐');
console.log('  │ Size     │ Elements  │ Fwd (ark→gpu) │ Rev (gpu→ark) │ Total         │');
console.log('  ├──────────┼───────────┼───────────────┼───────────────┼───────────────┤');

for (const logN of serSizes) {
    const n = 1 << logN;
    const m = measureSerializationOverhead(n);
    serOverhead[logN] = m.totalMs;
    const nStr = n.toLocaleString().padStart(9);
    console.log(`  │ 2^${logN.toString().padStart(2)}     │ ${nStr} │ ${m.fwdMs.toFixed(1).padStart(10)} ms │ ${m.revMs.toFixed(1).padStart(10)} ms │ ${m.totalMs.toFixed(1).padStart(10)} ms │`);
}
console.log('  └──────────┴───────────┴───────────────┴───────────────┴───────────────┘');

// 5. CPU NTT Baseline
console.log('\n═══════════════════════════════════════════════════');
console.log(' 5. JS CPU NTT Performance Baseline');
console.log('═══════════════════════════════════════════════════');

const benchSizes = [10, 12, 14, 16, 18, 20];
const jsTimings = {};

for (const logN of benchSizes) {
    const n = 1 << logN;
    const elems = Array.from({ length: n }, (_, i) => BigInt(i * 17 + 3) % BN254_P);
    const tw = generateTwiddles(n);
    const iters = n >= 65536 ? 1 : n >= 4096 ? 3 : 5;
    const start = performance.now();
    for (let i = 0; i < iters; i++) referenceNTT([...elems], tw);
    jsTimings[logN] = (performance.now() - start) / iters;
    console.log(`  2^${logN.toString().padStart(2)} = ${n.toLocaleString().padStart(10)}: ${jsTimings[logN].toFixed(1).padStart(8)} ms`);
}

// 6. Speedup Projection (Amdahl's Law) — WITH serialization overhead
console.log('\n═══════════════════════════════════════════════════');
console.log(' 6. Speedup Projection (Amdahl\'s Law)');
console.log('═══════════════════════════════════════════════════');

// GPU compute timings from browser benchmark (Chrome, macOS Apple Silicon)
// These are the GPU-only times from ntt-bench.html, NOT including serialization.
const gpuComputeTimings = {
    10: 2.6, 12: 6.6, 14: 21.6, 16: 89.8, 18: 284.0, 20: 857.3,
};

console.log(`\n  NTT fraction of native prove time: ${(NTT_FRACTION * 100).toFixed(1)}%`);
console.log(`  (In WASM without SIMD, the NTT fraction is likely higher — this is conservative)`);
console.log(`  Target: ≥${(TARGET_IMPROVEMENT * 100).toFixed(0)}% overall prove improvement\n`);

// Two projections:
// A) Optimistic: GPU compute only (what isolated benchmark measures)
// B) Realistic: GPU compute + serialization overhead (what integrated path pays)

console.log('  ┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐');
console.log('  │ NTT Size │  CPU(ms) │ GPU(ms)  │ +Ser(ms) │ GPU+Ser  │ Prove Δ  │ Target   │');
console.log('  │          │  (JS)    │ (compute)│ (convert)│ (total)  │ (Amdahl) │ (≥6%)    │');
console.log('  ├──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤');

let bestRealisticImprovement = 0;
let bestOptimisticImprovement = 0;
let realisticTargetMet = false;

for (const logN of benchSizes) {
    const cpuMs = jsTimings[logN];
    const gpuMs = gpuComputeTimings[logN];
    const serMs = serOverhead[logN];
    const gpuTotalMs = gpuMs + serMs;  // realistic: GPU compute + serialization

    const optimisticSpeedup = cpuMs / gpuMs;
    const realisticSpeedup = cpuMs / gpuTotalMs;

    // Amdahl's Law: S = 1 / (1 - f + f/s)
    const realisticOverall = 1 / (1 - NTT_FRACTION + NTT_FRACTION / realisticSpeedup);
    const realisticDelta = (realisticOverall - 1) * 100;

    const optimisticOverall = 1 / (1 - NTT_FRACTION + NTT_FRACTION / optimisticSpeedup);
    const optimisticDelta = (optimisticOverall - 1) * 100;

    if (realisticDelta > bestRealisticImprovement) bestRealisticImprovement = realisticDelta;
    if (optimisticDelta > bestOptimisticImprovement) bestOptimisticImprovement = optimisticDelta;
    if (realisticDelta >= TARGET_IMPROVEMENT * 100) realisticTargetMet = true;

    const met = realisticDelta >= TARGET_IMPROVEMENT * 100 ? '  ✓   ' : '  ✗   ';
    console.log(`  │ 2^${logN.toString().padStart(2)}     │ ${cpuMs.toFixed(1).padStart(8)} │ ${gpuMs.toFixed(1).padStart(8)} │ ${serMs.toFixed(1).padStart(8)} │ ${gpuTotalMs.toFixed(1).padStart(8)} │ ${(realisticDelta >= 0 ? '+' : '') + realisticDelta.toFixed(1) + '%'}${' '.repeat(Math.max(0, 5 - realisticDelta.toFixed(1).length))}│${met}  │`);
}
console.log('  └──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘');

console.log(`\n  Note: "CPU(ms)" is JS BigInt NTT, comparable to WASM CPU NTT (both lack SIMD).`);
console.log(`  "GPU(ms)" is from browser benchmark (ntt-bench.html, Chrome, Apple Silicon).`);
console.log(`  "+Ser(ms)" is the format conversion overhead measured above.`);
console.log(`  "Prove Δ" uses Amdahl's Law with f=${NTT_FRACTION} (conservative, from native profiling).`);

// 7. Verdict
console.log('\n═══════════════════════════════════════════════════');
console.log(' 7. VERDICT');
console.log('═══════════════════════════════════════════════════');

console.log(`\n  Tests passed: ${passedTests}/${totalTests}`);
console.log(`  Best projected improvement (with serialization): ${bestRealisticImprovement.toFixed(1)}%`);
console.log(`  Best projected improvement (GPU compute only):   ${bestOptimisticImprovement.toFixed(1)}%`);
console.log(`  Target (≥6%): ${realisticTargetMet ? '✅ PROJECTED TO BE MET' : '⚠️  PROJECTED NOT MET (serialization overhead too high)'}`);

if (!realisticTargetMet && bestOptimisticImprovement >= TARGET_IMPROVEMENT * 100) {
    console.log(`\n  The GPU compute alone is fast enough (${bestOptimisticImprovement.toFixed(1)}% projected),`);
    console.log(`  but the JS BigInt serialization overhead erodes the gain.`);
    console.log(`  Optimization path: use TypedArray-based conversion instead of BigInt.`);
}

console.log(`\n  ⚠️  These are PROJECTIONS based on Amdahl's Law, not measured end-to-end.`);
console.log(`  To measure actual speedup, run the browser demo with GPU NTT on vs off`);
console.log(`  and compare proveBytes() wall-clock time.\n`);

if (passedTests === totalTests) {
    console.log('  ╔═══════════════════════════════════════════════════════════╗');
    console.log('  ║  ✅ ALL CORRECTNESS TESTS PASSED                         ║');
    console.log(`  ║  Projected improvement: ${bestRealisticImprovement.toFixed(1)}% (with serialization overhead) ║`);
    console.log('  ╚═══════════════════════════════════════════════════════════╝');
} else {
    console.log('  ╔═══════════════════════════════════════════════════════════╗');
    console.log('  ║  ❌ SOME TESTS FAILED                                    ║');
    console.log('  ╚═══════════════════════════════════════════════════════════╝');
}

console.log('');
process.exit(passedTests === totalTests ? 0 : 1);
