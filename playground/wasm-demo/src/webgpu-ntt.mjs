/**
 * BN254 NTT Utilities
 *
 * Provides:
 * - Reference JS NTT implementation (for correctness testing and CPU baseline)
 * - Twiddle factor generation (matching ProveKit's init_roots_reverse_ordered)
 * - Limb conversion utilities (BigInt ↔ 9×29-bit)
 * - WebGPU availability check
 *
 * The actual GPU NTT integration is in webgpu-ntt-bridge.mjs, which plugs
 * into the WASM prover via WHIR's ReedSolomon trait (see gpu_ntt.rs).
 */

// BN254 scalar field modulus
const BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const LIMBS = 9;
const LIMB_BITS = 29;
const LIMB_MASK = (1 << LIMB_BITS) - 1;

/**
 * Reference NTT implementation in pure JavaScript.
 * Uses BigInt arithmetic for BN254 field operations.
 * Used by verify-speedup.mjs for correctness tests and CPU baseline.
 */
export function referenceNTT(elements, twiddles) {
    const n = elements.length;
    const logN = Math.log2(n);
    const result = [...elements];

    let pairsInGroup = n / 2;
    let numGroups = 1;

    for (let stage = 0; stage < logN; stage++) {
        for (let group = 0; group < numGroups; group++) {
            const omega = twiddles[group];
            for (let pair = 0; pair < pairsInGroup; pair++) {
                const evenIdx = group * 2 * pairsInGroup + pair;
                const oddIdx = evenIdx + pairsInGroup;
                const even = result[evenIdx];
                const odd = result[oddIdx];
                const omegaOdd = (omega * odd) % BN254_P;
                const sum = even + omegaOdd;
                result[evenIdx] = sum >= BN254_P ? sum - BN254_P : sum;
                result[oddIdx] = even >= omegaOdd ? even - omegaOdd : even - omegaOdd + BN254_P;
            }
        }
        pairsInGroup >>= 1;
        numGroups <<= 1;
    }
    return result;
}

/**
 * Generate twiddle factors (roots of unity) in reverse bit order.
 * Matches ProveKit's init_roots_reverse_ordered.
 */
export function generateTwiddles(n) {
    const logN = Math.log2(n);
    if (!Number.isInteger(logN)) throw new Error(`n must be power of 2, got ${n}`);
    const halfN = n / 2;
    const omega = computeRootOfUnity(n);
    const twiddles = new Array(halfN);
    let omegaK = 1n;
    for (let i = 0; i < halfN; i++) {
        twiddles[reverseBits(i, logN - 1)] = omegaK;
        omegaK = (omegaK * omega) % BN254_P;
    }
    return twiddles;
}

/** Convert a BigInt to 9×29-bit limbs stored in a Uint32Array at offset. */
export function bigintToLimbs(value, target, offset) {
    let v = value;
    for (let i = 0; i < LIMBS; i++) {
        target[offset + i] = Number(v & BigInt(LIMB_MASK));
        v >>= BigInt(LIMB_BITS);
    }
}

/** Convert 9×29-bit limbs from a Uint32Array at offset back to BigInt. */
export function limbsToBigint(source, offset) {
    let result = 0n;
    for (let i = LIMBS - 1; i >= 0; i--) {
        result = (result << BigInt(LIMB_BITS)) | BigInt(source[offset + i]);
    }
    return result;
}

export function isWebGPUAvailable() {
    return typeof navigator !== 'undefined' && !!navigator.gpu;
}

// Internal helpers

function computeRootOfUnity(n) {
    const ROOT_OF_UNITY_2_28 = 19103219067921713944291392827692070036145651957329286315305642004821462161904n;
    const MAX_ORDER = 1 << 28;
    if (n > MAX_ORDER) throw new Error(`NTT size ${n} exceeds max order ${MAX_ORDER}`);
    return modPow(ROOT_OF_UNITY_2_28, BigInt(MAX_ORDER / n), BN254_P);
}

function reverseBits(val, bits) {
    let r = 0;
    for (let i = 0; i < bits; i++) { r = (r << 1) | (val & 1); val >>= 1; }
    return r;
}

function modPow(base, exp, mod) {
    let r = 1n; base = base % mod;
    while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; exp >>= 1n; base = (base * base) % mod; }
    return r;
}
