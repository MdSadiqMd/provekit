/**
 * Web Worker for running proveBytes() off the main thread.
 *
 * Required because GPU NTT uses Atomics.wait() for synchronous GPU
 * readback, which is only allowed on worker threads.
 *
 * Protocol (main → worker → main):
 *   { type:'init' }                        → { type:'init-ok', threads }
 *   { type:'init-gpu' }                    → { type:'gpu-ok', available }
 *   { type:'register-cpu-ntt' }            → { type:'ntt-ok', engine:'cpu' }
 *   { type:'register-gpu-ntt' }            → { type:'ntt-ok', engine:'gpu' }
 *   { type:'prove', proverBuf, witness }   → { type:'prove-ok', ms, proofSize }
 *   (any error)                            → { type:'error', message }
 */

let wasm = null;
let gpuAvailable = false;

self.onmessage = async (e) => {
  const msg = e.data;
  try {
    if (msg.type === 'init') {
      // Polyfill window → self for wasm-bindgen extern compatibility
      if (typeof window === 'undefined') self.window = self;

      // Forwarding stubs for GPU NTT externs — wasm-bindgen resolves these
      // at WASM instantiation time and captures the reference. So we can't
      // replace them later. Instead, these stubs forward to self._gpuNttImpl
      // which CAN be replaced after init.
      self._gpuNttAvailableImpl = () => false;
      self._gpuNttComputeSyncImpl = () => { throw new Error('GPU NTT not initialized'); };

      if (typeof self.gpuNttAvailable === 'undefined') {
        self.gpuNttAvailable = (...args) => self._gpuNttAvailableImpl(...args);
        self.gpuNttComputeSync = (...args) => self._gpuNttComputeSyncImpl(...args);
      }

      // Load WASM
      wasm = await import('../pkg/provekit_wasm.js');
      const bin = await (await fetch('../pkg/provekit_wasm_bg.wasm')).arrayBuffer();
      await wasm.default(bin);
      if (wasm.initPanicHook) wasm.initPanicHook();

      // Try thread pool
      let threads = 1;
      const max = navigator.hardwareConcurrency || 4;
      if (typeof SharedArrayBuffer !== 'undefined') {
        try {
          await wasm.initThreadPool(max);
          threads = max;
        } catch (_) { /* single-threaded fallback */ }
      }
      self.postMessage({ type: 'init-ok', threads });

    } else if (msg.type === 'init-gpu') {
      const bridge = await import('./webgpu-ntt-bridge.mjs');

      if (msg.gpuReady) {
        // Replace the forwarding impl with the bridge's real functions
        // The bridge sets globalThis.gpuNttComputeSync at import time,
        // but wasm-bindgen captured our forwarding stubs. So we update
        // the _impl functions that the stubs forward to.
        const bridgeCompute = globalThis.gpuNttComputeSync;
        self._gpuNttAvailableImpl = () => true;
        self._gpuNttComputeSyncImpl = bridgeCompute;
        gpuAvailable = true;
      } else {
        gpuAvailable = false;
      }
      self.postMessage({ type: 'gpu-ok', available: gpuAvailable });

    } else if (msg.type === 'register-cpu-ntt') {
      // gpuNttAvailable() returns false → CPU NTT registered.
      if (wasm.initNtt) wasm.initNtt();
      self.postMessage({ type: 'ntt-ok', engine: 'cpu' });

    } else if (msg.type === 'register-gpu-ntt') {
      // Call initNtt() AFTER GPU bridge is initialized.
      // gpuNttAvailable() returns true → GPU NTT registered (overwrites CPU).
      if (wasm.initNtt) wasm.initNtt();
      self.postMessage({ type: 'ntt-ok', engine: gpuAvailable ? 'gpu' : 'cpu' });

    } else if (msg.type === 'prove') {
      const prover = new wasm.Prover(new Uint8Array(msg.proverBuf));
      const t0 = performance.now();
      const proof = prover.proveBytes(msg.witness);
      const ms = performance.now() - t0;
      self.postMessage({ type: 'prove-ok', ms, proofSize: proof.length });

    } else {
      self.postMessage({ type: 'error', message: 'unknown msg type: ' + msg.type });
    }
  } catch (err) {
    self.postMessage({ type: 'error', message: String(err.message || err) });
  }
};
