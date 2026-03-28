/**
 * WebGPU NTT Accelerator for BN254 Scalar Field
 * 
 * Provides GPU-accelerated Number Theoretic Transform (NTT) for BN254 field
 * elements, targeting the proving bottleneck in ProveKit's WASM demo.
 * 
 * Usage:
 *   const gpu = new WebGPUNTT();
 *   await gpu.init();
 *   const result = await gpu.ntt(elements, twiddles);
 *   gpu.destroy();
 */

// BN254 scalar field modulus
const BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const LIMBS = 9;
const LIMB_BITS = 29;
const LIMB_MASK = (1 << LIMB_BITS) - 1;

// Montgomery form constants (R = 2^261)
const R_MOD_P = 6233810253280740994628949329533561339965925630188245177646180721908512718679n;
const R_INV_MOD_P = 12621995978310821098439775787269407929538163553607166694879879304580168517835n;

/** Convert standard field element to Montgomery form: x_mont = x * R mod p */
function toMontgomery(x) {
    return (x * R_MOD_P) % BN254_P;
}

/** Convert Montgomery form back to standard: x = x_mont * R^{-1} mod p */
function fromMontgomery(x) {
    return (x * R_INV_MOD_P) % BN254_P;
}

// ============================================================
// NTT Butterfly Shader (inline for portability)
// ============================================================
const NTT_SHADER = /* wgsl */`
struct NTTParams {
    n: u32,
    log_n: u32,
    stage: u32,
    num_groups: u32,
    pairs_per_group: u32,
};

const LIMBS: u32 = 9u;
const LIMB_MASK_C: u32 = 0x1FFFFFFFu;
const LIMB_BITS_C: u32 = 29u;

const PM0: u32 = 0x10000001u;
const PM1: u32 = 0x1F0FAC9Fu;
const PM2: u32 = 0x0E5C2450u;
const PM3: u32 = 0x07D090F3u;
const PM4: u32 = 0x1585D283u;
const PM5: u32 = 0x02DB40C0u;
const PM6: u32 = 0x00A6E141u;
const PM7: u32 = 0x0E5C2634u;
const PM8: u32 = 0x0030644Eu;
const MU_C: u32 = 0x0FFFFFFFu;

@group(0) @binding(0) var<storage, read_write> elements: array<u32>;
@group(0) @binding(1) var<storage, read> twiddles: array<u32>;
@group(0) @binding(2) var<uniform> params: NTTParams;

fn get_p() -> array<u32, 9> {
    var p: array<u32, 9>;
    p[0] = PM0; p[1] = PM1; p[2] = PM2; p[3] = PM3;
    p[4] = PM4; p[5] = PM5; p[6] = PM6; p[7] = PM7;
    p[8] = PM8;
    return p;
}

fn f_add(a: array<u32, 9>, b: array<u32, 9>) -> array<u32, 9> {
    var result: array<u32, 9>;
    var carry: u32 = 0u;
    for (var i = 0u; i < 9u; i = i + 1u) {
        let sum = a[i] + b[i] + carry;
        result[i] = sum & LIMB_MASK_C;
        carry = sum >> LIMB_BITS_C;
    }
    return f_reduce(result);
}

fn f_sub(a: array<u32, 9>, b: array<u32, 9>) -> array<u32, 9> {
    var result: array<u32, 9>;
    var borrow: u32 = 0u;
    let p = get_p();
    for (var i = 0u; i < 9u; i = i + 1u) {
        let diff_val = a[i] + (1u << LIMB_BITS_C) - b[i] - borrow;
        result[i] = diff_val & LIMB_MASK_C;
        borrow = 1u - (diff_val >> LIMB_BITS_C);
    }
    if (borrow != 0u) {
        var c: u32 = 0u;
        for (var i = 0u; i < 9u; i = i + 1u) {
            let sum = result[i] + p[i] + c;
            result[i] = sum & LIMB_MASK_C;
            c = sum >> LIMB_BITS_C;
        }
    }
    return result;
}

fn f_reduce(a: array<u32, 9>) -> array<u32, 9> {
    let p = get_p();
    var result: array<u32, 9>;
    var borrow: u32 = 0u;
    for (var i = 0u; i < 9u; i = i + 1u) {
        let diff_val = a[i] + (1u << LIMB_BITS_C) - p[i] - borrow;
        result[i] = diff_val & LIMB_MASK_C;
        borrow = 1u - (diff_val >> LIMB_BITS_C);
    }
    if (borrow != 0u) { return a; }
    return result;
}

fn mul29(a: u32, b: u32) -> vec2<u32> {
    let a_lo = a & 0x7FFFu;
    let a_hi = a >> 15u;
    let b_lo = b & 0x7FFFu;
    let b_hi = b >> 15u;
    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;
    let mid = lh + hl;
    let low = ll + ((mid & 0x7FFFu) << 15u);
    let carry_from_low = low >> 29u;
    let lo_result = low & LIMB_MASK_C;
    let hi_result = 2u * (hh + (mid >> 15u)) + carry_from_low;
    return vec2<u32>(lo_result, hi_result);
}

fn f_mul(a: array<u32, 9>, b: array<u32, 9>) -> array<u32, 9> {
    var t: array<u32, 10>;
    for (var k = 0u; k < 10u; k = k + 1u) { t[k] = 0u; }
    let p = get_p();
    for (var i = 0u; i < 9u; i = i + 1u) {
        var carry: u32 = 0u;
        for (var j = 0u; j < 9u; j = j + 1u) {
            let prod = mul29(a[i], b[j]);
            let sum = prod.x + t[j] + carry;
            t[j] = sum & LIMB_MASK_C;
            carry = prod.y + (sum >> LIMB_BITS_C);
        }
        t[9] = t[9] + carry;
        let m = (t[0] * MU_C) & LIMB_MASK_C;
        carry = 0u;
        let prod0 = mul29(m, p[0]);
        let sum0 = prod0.x + t[0] + carry;
        carry = prod0.y + (sum0 >> LIMB_BITS_C);
        for (var j = 1u; j < 9u; j = j + 1u) {
            let prod = mul29(m, p[j]);
            let sum = prod.x + t[j] + carry;
            t[j - 1u] = sum & LIMB_MASK_C;
            carry = prod.y + (sum >> LIMB_BITS_C);
        }
        t[8] = t[9] + carry;
        t[9] = 0u;
    }
    var result: array<u32, 9>;
    for (var i = 0u; i < 9u; i = i + 1u) { result[i] = t[i]; }
    return f_reduce(result);
}

fn load_element(index: u32) -> array<u32, 9> {
    var r: array<u32, 9>;
    let base = index * LIMBS;
    for (var i = 0u; i < LIMBS; i = i + 1u) { r[i] = elements[base + i]; }
    return r;
}

fn store_element(index: u32, val: array<u32, 9>) {
    let base = index * LIMBS;
    for (var i = 0u; i < LIMBS; i = i + 1u) { elements[base + i] = val[i]; }
}

fn load_twiddle(index: u32) -> array<u32, 9> {
    var r: array<u32, 9>;
    let base = index * LIMBS;
    for (var i = 0u; i < LIMBS; i = i + 1u) { r[i] = twiddles[base + i]; }
    return r;
}

@compute @workgroup_size(256)
fn ntt_butterfly(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let thread_id = global_id.x;
    let total_pairs = params.n / 2u;
    if (thread_id >= total_pairs) { return; }
    
    let group_idx = thread_id / params.pairs_per_group;
    let pair_idx = thread_id % params.pairs_per_group;
    let even_idx = group_idx * 2u * params.pairs_per_group + pair_idx;
    let odd_idx = even_idx + params.pairs_per_group;
    
    let omega = load_twiddle(group_idx);
    let even = load_element(even_idx);
    let odd = load_element(odd_idx);
    
    let omega_times_odd = f_mul(omega, odd);
    let new_even = f_add(even, omega_times_odd);
    let new_odd = f_sub(even, omega_times_odd);
    
    store_element(even_idx, new_even);
    store_element(odd_idx, new_odd);
}
`;

export class WebGPUNTT {
    constructor() {
        this.device = null;
        this.pipeline = null;
        this.available = false;
        this._initPromise = null;
    }

    /**
     * Initialize WebGPU device and compile shaders.
     * Returns true if WebGPU is available and initialized.
     */
    async init() {
        if (this._initPromise) return this._initPromise;
        this._initPromise = this._doInit();
        return this._initPromise;
    }

    async _doInit() {
        try {
            if (!navigator.gpu) {
                console.warn('WebGPU not supported in this browser');
                return false;
            }

            const adapter = await navigator.gpu.requestAdapter({
                powerPreference: 'high-performance'
            });
            if (!adapter) {
                console.warn('No WebGPU adapter found');
                return false;
            }

            // Request device with max buffer size
            const limits = adapter.limits;
            this.device = await adapter.requestDevice({
                requiredLimits: {
                    maxStorageBufferBindingSize: limits.maxStorageBufferBindingSize,
                    maxBufferSize: limits.maxBufferSize,
                    maxComputeWorkgroupsPerDimension: limits.maxComputeWorkgroupsPerDimension,
                }
            });

            // Compile NTT shader
            const shaderModule = this.device.createShaderModule({
                code: NTT_SHADER,
            });

            // Check for compilation errors
            const info = await shaderModule.getCompilationInfo();
            for (const msg of info.messages) {
                if (msg.type === 'error') {
                    console.error('Shader compilation error:', msg.message);
                    return false;
                }
            }

            this.pipeline = this.device.createComputePipeline({
                layout: 'auto',
                compute: {
                    module: shaderModule,
                    entryPoint: 'ntt_butterfly',
                },
            });

            this.available = true;
            console.log('WebGPU NTT initialized successfully');
            return true;
        } catch (e) {
            console.warn('WebGPU initialization failed:', e);
            return false;
        }
    }

    /**
     * Perform NTT on an array of BN254 field elements.
     * 
     * @param {BigInt[]} elements - Array of BigInt field elements (length must be power of 2)
     * @param {BigInt[]} twiddles - Precomputed twiddle factors in reverse bit order (length = elements.length / 2)
     * @returns {BigInt[]} - Transformed field elements
     */
    async ntt(elements, twiddles) {
        if (!this.available) throw new Error('WebGPU not initialized');

        const n = elements.length;
        const logN = Math.log2(n);
        if (!Number.isInteger(logN) || n < 2) {
            throw new Error(`NTT size must be a power of 2, got ${n}`);
        }

        // Convert to Montgomery form and then to 9×29-bit limb u32 arrays
        // The GPU shader uses Montgomery multiplication (f_mul computes a*b*R^{-1} mod p),
        // so inputs must be x_mont = x*R mod p for the butterfly to be correct.
        const elemsU32 = new Uint32Array(n * LIMBS);
        for (let i = 0; i < n; i++) {
            bigintToLimbs(toMontgomery(elements[i]), elemsU32, i * LIMBS);
        }

        const twiddlesU32 = new Uint32Array((n / 2) * LIMBS);
        for (let i = 0; i < n / 2; i++) {
            bigintToLimbs(toMontgomery(twiddles[i]), twiddlesU32, i * LIMBS);
        }

        // Create GPU buffers
        const elemBuffer = this.device.createBuffer({
            size: elemsU32.byteLength,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
        });
        this.device.queue.writeBuffer(elemBuffer, 0, elemsU32);

        const twiddleBuffer = this.device.createBuffer({
            size: twiddlesU32.byteLength,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
        });
        this.device.queue.writeBuffer(twiddleBuffer, 0, twiddlesU32);

        const paramsBuffer = this.device.createBuffer({
            size: 5 * 4, // 5 u32 values
            usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
        });

        // Execute NTT stages
        const workgroupSize = 256;
        const totalPairs = n / 2;
        const numWorkgroups = Math.ceil(totalPairs / workgroupSize);

        for (let stage = 0; stage < logN; stage++) {
            const numGroups = 1 << stage;
            const pairsPerGroup = n / (2 * numGroups);

            // Update params
            const paramsData = new Uint32Array([n, logN, stage, numGroups, pairsPerGroup]);
            this.device.queue.writeBuffer(paramsBuffer, 0, paramsData);

            // Create bind group
            const bindGroup = this.device.createBindGroup({
                layout: this.pipeline.getBindGroupLayout(0),
                entries: [
                    { binding: 0, resource: { buffer: elemBuffer } },
                    { binding: 1, resource: { buffer: twiddleBuffer } },
                    { binding: 2, resource: { buffer: paramsBuffer } },
                ],
            });

            // Encode and dispatch
            const encoder = this.device.createCommandEncoder();
            const pass = encoder.beginComputePass();
            pass.setPipeline(this.pipeline);
            pass.setBindGroup(0, bindGroup);
            pass.dispatchWorkgroups(numWorkgroups);
            pass.end();
            this.device.queue.submit([encoder.finish()]);
        }

        // Read back results
        const readBuffer = this.device.createBuffer({
            size: elemsU32.byteLength,
            usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
        });

        const copyEncoder = this.device.createCommandEncoder();
        copyEncoder.copyBufferToBuffer(elemBuffer, 0, readBuffer, 0, elemsU32.byteLength);
        this.device.queue.submit([copyEncoder.finish()]);

        await readBuffer.mapAsync(GPUMapMode.READ);
        const resultData = new Uint32Array(readBuffer.getMappedRange().slice(0));
        readBuffer.unmap();

        // Convert back from Montgomery form to standard BigInts
        const result = new Array(n);
        for (let i = 0; i < n; i++) {
            result[i] = fromMontgomery(limbsToBigint(resultData, i * LIMBS));
        }

        // Cleanup
        elemBuffer.destroy();
        twiddleBuffer.destroy();
        paramsBuffer.destroy();
        readBuffer.destroy();

        return result;
    }

    /**
     * Get info about the GPU device.
     */
    getInfo() {
        if (!this.device) return null;
        return {
            available: this.available,
            limits: {
                maxStorageBufferBindingSize: this.device.limits.maxStorageBufferBindingSize,
                maxBufferSize: this.device.limits.maxBufferSize,
                maxComputeWorkgroupsPerDimension: this.device.limits.maxComputeWorkgroupsPerDimension,
            }
        };
    }

    destroy() {
        if (this.device) {
            this.device.destroy();
            this.device = null;
        }
        this.available = false;
    }
}

// Reference JS NTT implementation (for benchmarking comparison)
/**
 * Reference NTT implementation in pure JavaScript.
 * Uses BigInt arithmetic for BN254 field operations.
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
                const omegaOdd = fieldMulJS(omega, odd);

                result[evenIdx] = fieldAddJS(even, omegaOdd);
                result[oddIdx] = fieldSubJS(even, omegaOdd);
            }
        }
        pairsInGroup >>= 1;
        numGroups <<= 1;
    }

    return result;
}

// JS field arithmetic (BigInt-based, for reference/comparison)
function fieldAddJS(a, b) {
    const sum = a + b;
    return sum >= BN254_P ? sum - BN254_P : sum;
}

function fieldSubJS(a, b) {
    return a >= b ? a - b : a - b + BN254_P;
}

function fieldMulJS(a, b) {
    return (a * b) % BN254_P;
}

// Twiddle factor generation
/**
 * Generate twiddle factors (roots of unity) in reverse bit order.
 * This matches ProveKit's init_roots_reverse_ordered.
 */
export function generateTwiddles(n) {
    const logN = Math.log2(n);
    if (!Number.isInteger(logN)) throw new Error(`n must be power of 2, got ${n}`);

    const halfN = n / 2;
    // BN254 scalar field primitive root of unity for 2^28
    // omega = g^((p-1)/n) where g is a generator
    const omega = computeRootOfUnity(n);

    const twiddles = new Array(halfN);
    let omegaK = 1n;
    for (let i = 0; i < halfN; i++) {
        const rev = reverseBits(i, logN - 1);
        twiddles[rev] = omegaK;
        omegaK = (omegaK * omega) % BN254_P;
    }
    return twiddles;
}

function computeRootOfUnity(n) {
    // Generator of the multiplicative subgroup for BN254 Fr
    // ROOT_OF_UNITY for 2^28 = 19103219067921713944291392827692070036145651957329286315305642004821462161904
    const ROOT_OF_UNITY_2_28 = 19103219067921713944291392827692070036145651957329286315305642004821462161904n;
    const MAX_ORDER = 1 << 28;
    
    if (n > MAX_ORDER) throw new Error(`NTT size ${n} exceeds max order ${MAX_ORDER}`);
    
    // omega = ROOT_OF_UNITY^(MAX_ORDER / n)
    const exp = BigInt(MAX_ORDER / n);
    return modPow(ROOT_OF_UNITY_2_28, exp, BN254_P);
}

function reverseBits(val, bits) {
    let result = 0;
    for (let i = 0; i < bits; i++) {
        result = (result << 1) | (val & 1);
        val >>= 1;
    }
    return result;
}

function modPow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp & 1n) {
            result = (result * base) % mod;
        }
        exp >>= 1n;
        base = (base * base) % mod;
    }
    return result;
}

/**
 * Convert a BigInt to 9×29-bit limbs stored in a Uint32Array at offset.
 */
export function bigintToLimbs(value, target, offset) {
    let v = value;
    for (let i = 0; i < LIMBS; i++) {
        target[offset + i] = Number(v & BigInt(LIMB_MASK));
        v >>= BigInt(LIMB_BITS);
    }
}

/**
 * Convert 9×29-bit limbs from a Uint32Array at offset back to BigInt.
 */
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
