/**
 * WebGPU NTT Bridge — connects Rust WASM prover to GPU NTT.
 *
 * Architecture for synchronous GPU calls from worker threads:
 *
 * The Rust prover runs on Rayon worker threads (Web Workers). WHIR's
 * ReedSolomon::interleaved_encode() is synchronous. WebGPU's mapAsync()
 * is async and its Promise resolves on the thread that submitted the work.
 *
 * If we submit GPU work from the worker and Atomics.wait on the same thread,
 * the Promise can never resolve → deadlock.
 *
 * Solution: The worker posts a message to the MAIN THREAD, which owns the
 * GPU device. The main thread runs the GPU work, reads back results into a
 * SharedArrayBuffer, and signals the worker via Atomics.notify. The worker
 * blocks on Atomics.wait until the main thread is done.
 *
 * Flow:
 *   Worker: gpuNttComputeSync() called by Rust
 *     → serialize elements into SharedArrayBuffer
 *     → postMessage to main thread: "run NTT"
 *     → Atomics.wait(signal, 0, 0)  ← blocks worker
 *   Main thread: onmessage handler
 *     → read elements from SharedArrayBuffer
 *     → convert ark-ff → GPU limbs
 *     → submit GPU dispatches
 *     → await mapAsync (main thread event loop is free!)
 *     → convert GPU limbs → ark-ff
 *     → write results into SharedArrayBuffer
 *     → Atomics.store(signal, 1); Atomics.notify(signal)
 *   Worker: unblocks, reads results from SharedArrayBuffer
 *     → returns Uint8Array to Rust
 */

const BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const LIMBS = 9;
const LIMB_BITS = 29;
const LIMB_MASK = (1 << LIMB_BITS) - 1;

const R_MOD_P = 6233810253280740994628949329533561339965925630188245177646180721908512718679n;

let device = null;
let pipeline = null;
let _initialized = false;
let twiddleCache = new Map();

// Main-thread initialization
export async function initGpuNtt() {
    if (_initialized) return true;
    if (typeof navigator === 'undefined' || !navigator.gpu) {
        console.warn('[GPU NTT Bridge] WebGPU not available');
        return false;
    }
    try {
        const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
        if (!adapter) return false;
        device = await adapter.requestDevice({
            requiredLimits: {
                maxStorageBufferBindingSize: adapter.limits.maxStorageBufferBindingSize,
                maxBufferSize: adapter.limits.maxBufferSize,
                maxComputeWorkgroupsPerDimension: adapter.limits.maxComputeWorkgroupsPerDimension,
            }
        });
        const resp = await fetch('./src/shaders/ntt_butterfly.wgsl');
        if (!resp.ok) throw new Error(`Failed to load shader: ${resp.status}`);
        const shaderCode = await resp.text();
        const shaderModule = device.createShaderModule({ code: shaderCode });
        const info = await shaderModule.getCompilationInfo();
        for (const msg of info.messages) {
            if (msg.type === 'error') { console.error('[GPU NTT] Shader error:', msg.message); return false; }
        }
        pipeline = device.createComputePipeline({
            layout: 'auto',
            compute: { module: shaderModule, entryPoint: 'ntt_butterfly' },
        });
        _initialized = true;
        setupMainThreadHandler();
        console.log('[GPU NTT Bridge] Initialized on main thread');
        return true;
    } catch (e) {
        console.warn('[GPU NTT Bridge] Init failed:', e);
        return false;
    }
}

// Main-thread message handler — runs GPU work on behalf of workers
function setupMainThreadHandler() {
    // Listen for messages from Rayon worker threads requesting GPU NTT
    if (typeof self !== 'undefined' && typeof self.addEventListener === 'function') {
        // We need to intercept messages to ALL workers. The way wasm-bindgen-rayon
        // works: the main thread creates workers, and we can listen on the main
        // thread's message channel. But workers post to main via their own port.
        // Instead, we set a global function that workers can call via
        // a BroadcastChannel or by posting to the main thread.
    }

    // Use a BroadcastChannel for worker↔main communication
    if (typeof BroadcastChannel !== 'undefined') {
        const channel = new BroadcastChannel('gpu-ntt');
        console.log('[GPU NTT Main] BroadcastChannel listener set up');
        channel.onmessage = async (event) => {
            if (event.data.type !== 'gpu-ntt-request') return;
            const { elemBytes, nElements, codewordLength, nPolynomials, signalBuf, resultBuf } = event.data;
            try {
                const result = await runGpuNtt(new Uint8Array(elemBytes), nElements, codewordLength, nPolynomials);
                const resultView = new Uint8Array(resultBuf);
                resultView.set(result);
                const signalView = new Int32Array(signalBuf);
                Atomics.store(signalView, 0, 1);
                Atomics.notify(signalView, 0);
            } catch (err) {
                console.error('[GPU NTT Main] Error:', err);
                const signalView = new Int32Array(signalBuf);
                Atomics.store(signalView, 0, -1);
                Atomics.notify(signalView, 0);
            }
        };
    }
}

// GPU NTT execution (runs on main thread only)
async function runGpuNtt(elemBytes, nElements, codewordLength, nPolynomials) {
    const order = codewordLength;
    if (order <= 1) return new Uint8Array(elemBytes);
    const logOrder = Math.log2(order);
    if (!Number.isInteger(logOrder)) throw new Error(`Order must be power of 2, got ${order}`);

    const elementsU32 = arkBytesToGpuLimbs(elemBytes, nElements);
    const twiddlesU32 = getOrCreateTwiddles(order);

    const elemBuffer = device.createBuffer({
        size: elementsU32.byteLength,
        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
    });
    device.queue.writeBuffer(elemBuffer, 0, elementsU32);

    const twiddleBuffer = device.createBuffer({
        size: twiddlesU32.byteLength,
        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
    });
    device.queue.writeBuffer(twiddleBuffer, 0, twiddlesU32);

    const paramsBuffer = device.createBuffer({
        size: 5 * 4,
        usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
    });

    const totalPairs = nElements / 2;
    const numWorkgroups = Math.ceil(totalPairs / 256);

    for (let stage = 0; stage < logOrder; stage++) {
        const numGroups = 1 << stage;
        const pairsPerGroup = nElements / (2 * numGroups);
        device.queue.writeBuffer(paramsBuffer, 0, new Uint32Array([nElements, logOrder, stage, numGroups, pairsPerGroup]));
        const bindGroup = device.createBindGroup({
            layout: pipeline.getBindGroupLayout(0),
            entries: [
                { binding: 0, resource: { buffer: elemBuffer } },
                { binding: 1, resource: { buffer: twiddleBuffer } },
                { binding: 2, resource: { buffer: paramsBuffer } },
            ],
        });
        const encoder = device.createCommandEncoder();
        const pass = encoder.beginComputePass();
        pass.setPipeline(pipeline);
        pass.setBindGroup(0, bindGroup);
        pass.dispatchWorkgroups(numWorkgroups);
        pass.end();
        device.queue.submit([encoder.finish()]);
    }

    // Readback — this is async and works because we're on the main thread
    const readBuffer = device.createBuffer({
        size: elementsU32.byteLength,
        usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
    });
    const copyEncoder = device.createCommandEncoder();
    copyEncoder.copyBufferToBuffer(elemBuffer, 0, readBuffer, 0, elementsU32.byteLength);
    device.queue.submit([copyEncoder.finish()]);

    await readBuffer.mapAsync(GPUMapMode.READ);
    const resultU32 = new Uint32Array(readBuffer.getMappedRange().slice(0));
    readBuffer.unmap();

    const resultBytes = gpuLimbsToArkBytes(resultU32, nElements);

    elemBuffer.destroy();
    twiddleBuffer.destroy();
    paramsBuffer.destroy();
    readBuffer.destroy();

    return resultBytes;
}

// Worker-side: synchronous GPU NTT via main-thread delegation
// These are set on globalThis so Rust's wasm-bindgen extern can find them
// in both main thread (window) and worker (self) contexts.
const _gpuNttAvailable = function() {
    return _initialized && device !== null && pipeline !== null;
};

const _gpuNttComputeSync = function(elemBytes, nElements, codewordLength, nPolynomials) {
    if (typeof document !== 'undefined') {
        throw new Error('gpuNttComputeSync called from main thread — use async path');
    }

    const byteSize = nElements * 32;

    const signalBuf = new SharedArrayBuffer(4);
    const signalView = new Int32Array(signalBuf);
    Atomics.store(signalView, 0, 0);

    const resultBuf = new SharedArrayBuffer(byteSize);

    const elemCopy = new SharedArrayBuffer(byteSize);
    new Uint8Array(elemCopy).set(new Uint8Array(elemBytes.buffer, elemBytes.byteOffset, byteSize));

    const channel = new BroadcastChannel('gpu-ntt');
    channel.postMessage({
        type: 'gpu-ntt-request',
        elemBytes: elemCopy,
        nElements,
        codewordLength,
        nPolynomials,
        signalBuf,
        resultBuf,
    });

    const waitResult = Atomics.wait(signalView, 0, 0, 30000);

    channel.close();

    if (waitResult === 'timed-out') {
        throw new Error('GPU NTT timed out after 30s — main thread may not have received the message');
    }

    if (Atomics.load(signalView, 0) === -1) {
        throw new Error('GPU NTT failed on main thread');
    }

    return new Uint8Array(resultBuf);
};

// Expose globally for wasm-bindgen extern resolution
if (typeof window !== 'undefined') {
    window.gpuNttAvailable = _gpuNttAvailable;
    window.gpuNttComputeSync = _gpuNttComputeSync;
}
if (typeof globalThis !== 'undefined') {
    globalThis.gpuNttAvailable = _gpuNttAvailable;
    globalThis.gpuNttComputeSync = _gpuNttComputeSync;
}

// Format conversion: ark-ff 4×64-bit LE ↔ GPU 9×29-bit Montgomery
//
// The conversion x_gpu = x_ark * 2^5 mod p requires multi-precision
// arithmetic. We use BigInt but optimize the hot path:
// - DataView for fast u32 reads (no byte-by-byte construction)
// - Pre-computed constants as BigInt literals
// - Minimized BigInt temporaries
//
// Pre-compute R_RATIO_INV once at module load (not per-call)
const _R_RATIO_INV = modPow(32n, BN254_P - 2n, BN254_P);

function arkBytesToGpuLimbs(bytes, count) {
    const result = new Uint32Array(count * LIMBS);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, count * 32);
    
    for (let i = 0; i < count; i++) {
        const off = i * 32;
        // Read as 4×u64 LE using two u32 reads per u64 (DataView is fast)
        const lo0 = dv.getUint32(off, true), hi0 = dv.getUint32(off + 4, true);
        const lo1 = dv.getUint32(off + 8, true), hi1 = dv.getUint32(off + 12, true);
        const lo2 = dv.getUint32(off + 16, true), hi2 = dv.getUint32(off + 20, true);
        const lo3 = dv.getUint32(off + 24, true), hi3 = dv.getUint32(off + 28, true);
        
        // Construct BigInt from u32 pairs (faster than byte-by-byte)
        let val = (BigInt(hi3) << 224n) | (BigInt(lo3) << 192n) |
                  (BigInt(hi2) << 160n) | (BigInt(lo2) << 128n) |
                  (BigInt(hi1) << 96n)  | (BigInt(lo1) << 64n) |
                  (BigInt(hi0) << 32n)  | BigInt(lo0);
        
        // Multiply by 2^5 mod p (Montgomery radix adjustment)
        val = (val << 5n) % BN254_P;
        
        // Extract 9×29-bit limbs
        const base = i * LIMBS;
        result[base]     = Number(val & 0x1FFFFFFFn); val >>= 29n;
        result[base + 1] = Number(val & 0x1FFFFFFFn); val >>= 29n;
        result[base + 2] = Number(val & 0x1FFFFFFFn); val >>= 29n;
        result[base + 3] = Number(val & 0x1FFFFFFFn); val >>= 29n;
        result[base + 4] = Number(val & 0x1FFFFFFFn); val >>= 29n;
        result[base + 5] = Number(val & 0x1FFFFFFFn); val >>= 29n;
        result[base + 6] = Number(val & 0x1FFFFFFFn); val >>= 29n;
        result[base + 7] = Number(val & 0x1FFFFFFFn); val >>= 29n;
        result[base + 8] = Number(val & 0x1FFFFFFFn);
    }
    return result;
}

function gpuLimbsToArkBytes(limbsU32, count) {
    const result = new Uint8Array(count * 32);
    const dv = new DataView(result.buffer);
    
    for (let i = 0; i < count; i++) {
        const base = i * LIMBS;
        
        // Reassemble from 9×29-bit limbs (unrolled for speed)
        let val = BigInt(limbsU32[base + 8]);
        val = (val << 29n) | BigInt(limbsU32[base + 7]);
        val = (val << 29n) | BigInt(limbsU32[base + 6]);
        val = (val << 29n) | BigInt(limbsU32[base + 5]);
        val = (val << 29n) | BigInt(limbsU32[base + 4]);
        val = (val << 29n) | BigInt(limbsU32[base + 3]);
        val = (val << 29n) | BigInt(limbsU32[base + 2]);
        val = (val << 29n) | BigInt(limbsU32[base + 1]);
        val = (val << 29n) | BigInt(limbsU32[base]);
        
        // Reverse Montgomery radix: multiply by (2^5)^(-1) mod p
        val = (val * _R_RATIO_INV) % BN254_P;
        
        // Write as 8×u32 LE (DataView for speed)
        const off = i * 32;
        dv.setUint32(off,      Number(val & 0xFFFFFFFFn), true); val >>= 32n;
        dv.setUint32(off + 4,  Number(val & 0xFFFFFFFFn), true); val >>= 32n;
        dv.setUint32(off + 8,  Number(val & 0xFFFFFFFFn), true); val >>= 32n;
        dv.setUint32(off + 12, Number(val & 0xFFFFFFFFn), true); val >>= 32n;
        dv.setUint32(off + 16, Number(val & 0xFFFFFFFFn), true); val >>= 32n;
        dv.setUint32(off + 20, Number(val & 0xFFFFFFFFn), true); val >>= 32n;
        dv.setUint32(off + 24, Number(val & 0xFFFFFFFFn), true); val >>= 32n;
        dv.setUint32(off + 28, Number(val & 0xFFFFFFFFn), true);
    }
    return result;
}

// Twiddle factors (matches Rust's init_roots_reverse_ordered)
function getOrCreateTwiddles(order) {
    if (twiddleCache.has(order)) return twiddleCache.get(order);
    const halfOrder = order / 2;
    const omega = computeRootOfUnity(order);
    const logHalf = Math.log2(halfOrder);
    const twiddles = new Array(halfOrder);
    let omegaK = 1n;
    for (let i = 0; i < halfOrder; i++) {
        twiddles[reverseBits(i, logHalf)] = omegaK;
        omegaK = (omegaK * omega) % BN254_P;
    }
    const twiddlesU32 = new Uint32Array(halfOrder * LIMBS);
    for (let i = 0; i < halfOrder; i++) {
        let val = (twiddles[i] * R_MOD_P) % BN254_P;
        const base = i * LIMBS;
        for (let j = 0; j < LIMBS; j++) {
            twiddlesU32[base + j] = Number(val & BigInt(LIMB_MASK));
            val >>= BigInt(LIMB_BITS);
        }
    }
    twiddleCache.set(order, twiddlesU32);
    return twiddlesU32;
}

function computeRootOfUnity(n) {
    const ROOT = 19103219067921713944291392827692070036145651957329286315305642004821462161904n;
    return modPow(ROOT, BigInt((1 << 28) / n), BN254_P);
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
