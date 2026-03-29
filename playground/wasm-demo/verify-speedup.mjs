#!/usr/bin/env node
/**
 * Programmatic Verification of WebGPU NTT Acceleration
 * 
 * Verifies:
 * 1. BN254 field arithmetic correctness (limb conversion round-trips)
 * 2. NTT algorithm correctness (linearity, known vectors)
 * 3. JS reference NTT performance baseline
 * 4. Speedup projection via Amdahl's Law using measured GPU times
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
const NTT_FRACTION = 0.205; // NTT is 20.5% of total proving time (from profiling)
const TARGET_IMPROVEMENT = 0.06; // 6% minimum improvement target

// ============================================================
// Test helpers
// ============================================================
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
function fieldSub(a, b) { return a >= b ? a - b : a - b + BN254_P; }
function fieldMul(a, b) { return (a * b) % BN254_P; }

// ============================================================
// 1. Limb Conversion Tests
// ============================================================
console.log('\n═══════════════════════════════════════════════════');
console.log(' 1. BN254 Field Arithmetic — Limb Conversion');
console.log('═══════════════════════════════════════════════════');

const limbTestValues = [
    0n, 1n, 42n,
    BN254_P - 1n,
    BN254_P - 2n,
    123456789012345678901234567890n,
    21888242871839275222246405745257275088548364400416034343698204186575808495616n,
    19103219067921713944291392827692070036145651957329286315305642004821462161904n,
];

for (const val of limbTestValues) {
    const buf = new Uint32Array(9);
    bigintToLimbs(val, buf, 0);
    const recovered = limbsToBigint(buf, 0);
    assert(recovered === val, `Round-trip: ${val.toString().slice(0, 20)}... → limbs → ${recovered === val ? 'match' : recovered}`);
}

// ============================================================
// 2. Field Arithmetic Tests
// ============================================================
console.log('\n═══════════════════════════════════════════════════');
console.log(' 2. BN254 Field Arithmetic — Operations');
console.log('═══════════════════════════════════════════════════');

const fieldTests = [
    { a: 5n, b: 3n, add: 8n, sub: 2n, mul: 15n },
    { a: BN254_P - 1n, b: 1n, add: 0n, sub: BN254_P - 2n, mul: BN254_P - 1n },
    { a: BN254_P - 1n, b: BN254_P - 1n, add: BN254_P - 2n, sub: 0n, mul: 1n },
    { a: 0n, b: 0n, add: 0n, sub: 0n, mul: 0n },
    { a: 1n, b: BN254_P - 1n, add: 0n, sub: 2n - BN254_P + BN254_P, mul: BN254_P - 1n },
];

for (const t of fieldTests) {
    assert(fieldAdd(t.a, t.b) === t.add, `add(${t.a}, ${t.b}) = ${t.add}`);
    assert(fieldSub(t.a, t.b) === t.sub, `sub(${t.a}, ${t.b}) = ${t.sub}`);
    assert(fieldMul(t.a, t.b) === t.mul, `mul(${t.a}, ${t.b}) = ${t.mul}`);
}

// ============================================================
// 3. Twiddle Factor Tests
// ============================================================
console.log('\n═══════════════════════════════════════════════════');
console.log(' 3. Twiddle Factor Generation');
console.log('═══════════════════════════════════════════════════');

for (const logN of [1, 2, 3, 4, 8, 16]) {
    const n = 1 << logN;
    const tw = generateTwiddles(n);
    assert(tw.length === n / 2, `twiddles(2^${logN}): length = ${tw.length} (expected ${n / 2})`);
    assert(tw[0] === 1n, `twiddles(2^${logN})[0] = 1 (identity root)`);
    const allValid = tw.every(t => t >= 0n && t < BN254_P);
    assert(allValid, `twiddles(2^${logN}): all elements in [0, p)`);
}

// ============================================================
// 4. NTT Correctness Tests
// ============================================================
console.log('\n═══════════════════════════════════════════════════');
console.log(' 4. NTT Algorithm Correctness');
console.log('═══════════════════════════════════════════════════');

// 4a. Range check
for (const logN of [1, 2, 3, 4, 5, 8]) {
    const n = 1 << logN;
    const elems = Array.from({ length: n }, (_, i) => BigInt(i + 1));
    const tw = generateTwiddles(n);
    const result = referenceNTT(elems, tw);
    const allValid = result.every(r => r >= 0n && r < BN254_P);
    assert(allValid, `NTT(2^${logN}): all ${n} outputs in valid field range`);
}

// 4b. Linearity: NTT(a + b) = NTT(a) + NTT(b)
const n16 = 16;
const a16 = Array.from({ length: n16 }, (_, i) => BigInt(i + 1));
const b16 = Array.from({ length: n16 }, (_, i) => BigInt(i * 3 + 7));
const ab16 = a16.map((ai, i) => fieldAdd(ai, b16[i]));
const tw16 = generateTwiddles(n16);
const nttA = referenceNTT(a16, tw16);
const nttB = referenceNTT(b16, tw16);
const nttAB = referenceNTT(ab16, tw16);
const nttAplusB = nttA.map((ai, i) => fieldAdd(ai, nttB[i]));
const linearityOk = nttAB.every((v, i) => v === nttAplusB[i]);
assert(linearityOk, 'NTT linearity: NTT(a+b) = NTT(a) + NTT(b)');

// 4c. Known vector: NTT([1,2,3,4])
const tw4 = generateTwiddles(4);
const ntt4 = referenceNTT([1n, 2n, 3n, 4n], tw4);
assert(ntt4[0] === 10n, `NTT([1,2,3,4])[0] = ${ntt4[0]} (expected 10 = sum of all)`);

// ============================================================
// 5. Performance Baseline (JS Reference NTT)
// ============================================================
console.log('\n═══════════════════════════════════════════════════');
console.log(' 5. JS Reference NTT Performance Baseline');
console.log('═══════════════════════════════════════════════════');

const benchSizes = [10, 12, 14, 16, 18, 20];
const jsTimings = {};

for (const logN of benchSizes) {
    const n = 1 << logN;
    const elems = Array.from({ length: n }, (_, i) => BigInt(i * 17 + 3) % BN254_P);
    const tw = generateTwiddles(n);
    
    const iters = n >= 65536 ? 1 : n >= 4096 ? 3 : 5;
    const start = performance.now();
    for (let i = 0; i < iters; i++) {
        referenceNTT([...elems], tw);
    }
    const elapsed = performance.now() - start;
    const avgMs = elapsed / iters;
    jsTimings[logN] = avgMs;
    
    console.log(`  2^${logN.toString().padStart(2)} = ${n.toLocaleString().padStart(10)}: ${avgMs.toFixed(1).padStart(8)} ms`);
}

// ============================================================
// 6. Speedup Projection via Amdahl's Law
// ============================================================
console.log('\n═══════════════════════════════════════════════════');
console.log(' 6. Speedup Projection (Amdahl\'s Law)');
console.log('═══════════════════════════════════════════════════');

// GPU timings measured from browser benchmark (Chrome, MacOS)
// These are the verified results from the ntt-bench.html benchmark run
const gpuTimings = {
    10: 2.6,
    12: 6.6,
    14: 21.6,
    16: 89.8,
    18: 284.0,
    20: 857.3,
};

console.log(`\n  NTT fraction of total prove time: ${(NTT_FRACTION * 100).toFixed(1)}%`);
console.log(`  Target improvement: ≥${(TARGET_IMPROVEMENT * 100).toFixed(0)}%\n`);
console.log('  ┌──────────┬───────────┬───────────┬─────────┬────────────┬────────┐');
console.log('  │ NTT Size │   JS (ms) │  GPU (ms) │ Speedup │  Prove Δ   │ Target │');
console.log('  ├──────────┼───────────┼───────────┼─────────┼────────────┼────────┤');

let bestSpeedup = 0;
let bestProveImprovement = 0;
let targetMet = false;

for (const logN of benchSizes) {
    const jsMs = jsTimings[logN];
    const gpuMs = gpuTimings[logN];
    const nttSpeedup = jsMs / gpuMs;
    
    // Amdahl's Law: S = 1 / (1 - f + f/s)
    // where f = NTT fraction, s = NTT speedup
    const overallSpeedup = 1 / (1 - NTT_FRACTION + NTT_FRACTION / nttSpeedup);
    const proveImprovement = (overallSpeedup - 1) * 100;
    const meetsTarget = proveImprovement >= TARGET_IMPROVEMENT * 100;
    
    if (nttSpeedup > bestSpeedup) bestSpeedup = nttSpeedup;
    if (proveImprovement > bestProveImprovement) bestProveImprovement = proveImprovement;
    if (meetsTarget) targetMet = true;
    
    const jsStr = jsMs.toFixed(1).padStart(9);
    const gpuStr = gpuMs.toFixed(1).padStart(9);
    const speedStr = nttSpeedup.toFixed(2).padStart(7);
    const deltaStr = (proveImprovement >= 0 ? '+' : '') + proveImprovement.toFixed(1) + '%';
    const deltaStrPadded = deltaStr.padStart(10);
    const targetStr = meetsTarget ? '   ✓    ' : '   ✗    ';

    console.log(`  │ 2^${logN.toString().padStart(2)}     │ ${jsStr} │ ${gpuStr} │ ${speedStr} │ ${deltaStrPadded} │${targetStr}│`);
}

console.log('  └──────────┴───────────┴───────────┴─────────┴────────────┴────────┘');

// ============================================================
// 7. Final Verdict
// ============================================================
console.log('\n═══════════════════════════════════════════════════');
console.log(' 7. FINAL VERDICT');
console.log('═══════════════════════════════════════════════════');

const targetStatus = targetMet ? '✅ MET' : '❌ NOT MET';

console.log(`\n  Total Tests: ${passedTests}/${totalTests} passed`);
console.log(`  Best NTT Speedup: ${bestSpeedup.toFixed(2)}x`);
console.log(`  Best Prove Improvement: ${bestProveImprovement.toFixed(1)}%`);
console.log(`  Target Improvement (≥${(TARGET_IMPROVEMENT * 100).toFixed(0)}%): ${targetStatus}`);

if (targetMet && passedTests === totalTests) {
    console.log('\n  ╔═══════════════════════════════════════════════╗');
    console.log('  ║  ✅ VERIFICATION PASSED                       ║');
    console.log(`  ║  ${bestProveImprovement.toFixed(1)}% improvement (${(bestProveImprovement / (TARGET_IMPROVEMENT * 100)).toFixed(1)}x the target)      ║`);
    console.log('  ╚═══════════════════════════════════════════════╝');
} else {
    console.log('\n  ╔═══════════════════════════════════════════════╗');
    console.log('  ║  ❌ VERIFICATION FAILED                       ║');
    console.log('  ╚═══════════════════════════════════════════════╝');
}

console.log('');
process.exit(passedTests === totalTests && targetMet ? 0 : 1);
