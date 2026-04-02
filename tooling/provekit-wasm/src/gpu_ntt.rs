//! WebGPU NTT integration for the WASM prover.
//!
//! Replaces the default CPU NTT with a GPU-accelerated version when WebGPU
//! is available in the browser. The `.wgsl` shader file
//! (`playground/wasm-demo/src/shaders/ntt_butterfly.wgsl`) is the single
//! source of truth for GPU field arithmetic.
//!
//! ## Integration architecture
//!
//! 1. JS side calls `initGpuNtt()` to initialize WebGPU and compile shaders
//! 2. Rust calls `initNtt()` which registers `GpuReedSolomon` as the global
//!    NTT engine via WHIR's `NTT.insert()`
//! 3. During proving, WHIR calls `ReedSolomon::interleaved_encode()` for
//!    every IRS Commit phase in every WHIR round
//! 4. `GpuReedSolomon::interleaved_encode()` serializes field elements,
//!    calls `gpuNttComputeSync()` in JS, which dispatches the GPU shader
//! 5. Results are deserialized back to `Fr` elements
//!
//! This means the GPU NTT is called at exactly the same points in the
//! protocol as the CPU NTT, reflecting the real CPU↔GPU communication
//! pattern including serialization overhead.

use {
    ark_bn254::Fr,
    ark_ff::{AdditiveGroup, PrimeField},
    std::sync::Arc,
    wasm_bindgen::prelude::*,
};

// JS extern functions — implemented in webgpu-ntt-bridge.mjs
#[wasm_bindgen]
extern "C" {
    /// Check if WebGPU NTT is initialized and ready.
    #[wasm_bindgen(js_name = "gpuNttAvailable")]
    fn gpu_ntt_available() -> bool;

    /// Perform NTT on GPU, synchronously from Rust's perspective.
    ///
    /// The JS side uses SharedArrayBuffer + Atomics.wait to block the
    /// calling worker thread until GPU readback completes.
    ///
    /// Parameters:
    /// - elements: flat buffer of 32-byte LE field elements (ark-ff Montgomery form)
    /// - n_elements: total number of field elements in the buffer
    /// - expansion: Reed-Solomon expansion factor
    /// - n_polynomials: number of interleaved polynomials
    ///
    /// Returns: Uint8Array of same size with NTT-transformed elements.
    #[wasm_bindgen(js_name = "gpuNttComputeSync")]
    fn gpu_ntt_compute_sync(
        elements: &[u8],
        n_elements: u32,
        expansion: u32,
        n_polynomials: u32,
    ) -> js_sys::Uint8Array;
}

/// GPU-backed Reed-Solomon encoder.
///
/// Implements WHIR's `ReedSolomon<Fr>` trait, plugging directly into the
/// existing prove flow. Every call to `interleaved_encode` during IRS Commit
/// goes through the GPU.
#[derive(Debug)]
pub struct GpuReedSolomon;

impl whir::algebra::ntt::ReedSolomon<Fr> for GpuReedSolomon {
    fn interleaved_encode(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        // Match the CPU path's layout: lay out coefficients in contiguous blocks,
        // zero-pad each block to codeword_length, then NTT each block.
        if interleaved_coeffs.is_empty() {
            return Vec::new();
        }

        let poly_size = interleaved_coeffs[0].len();
        let message_length = poly_size / interleaving_depth;
        let per_poly_size = codeword_length * interleaving_depth;
        let total_size = per_poly_size * interleaved_coeffs.len();

        // Lay out coefficients in contiguous blocks and zero-pad
        let mut expanded = vec![Fr::ZERO; total_size];
        for (poly_index, poly) in interleaved_coeffs.iter().enumerate() {
            for (block_index, block) in poly.chunks_exact(message_length).enumerate() {
                let dst = poly_index * per_poly_size + block_index * codeword_length;
                expanded[dst..dst + message_length].copy_from_slice(block);
            }
        }

        // Serialize to bytes (4×u64 LE per element, ark-ff Montgomery form)
        let bytes = fr_slice_to_bytes(&expanded);

        // Call GPU NTT via JS bridge
        let result_array = gpu_ntt_compute_sync(
            &bytes,
            expanded.len() as u32,
            codeword_length as u32,
            (interleaved_coeffs.len() * interleaving_depth) as u32,
        );

        // Deserialize back to Fr elements
        let result_bytes = result_array.to_vec();
        bytes_to_fr_slice(&result_bytes, expanded.len())
    }
}

/// Register the GPU NTT if WebGPU is available, otherwise fall back to CPU.
///
/// Must be called from JS after `initGpuNtt()` has initialized the WebGPU
/// bridge. Called via the exported `initNtt()` WASM function.
pub fn register_gpu_ntt_if_available() {
    if gpu_ntt_available() {
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<Fr>> = Arc::new(GpuReedSolomon);
        whir::algebra::ntt::NTT.insert(ntt);
        web_sys::console::log_1(&"[GPU NTT] Registered GPU-backed ReedSolomon encoder".into());
    } else {
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<Fr>> =
            Arc::new(whir::algebra::ntt::ArkNtt::<Fr>::default());
        whir::algebra::ntt::NTT.insert(ntt);
        web_sys::console::log_1(
            &"[GPU NTT] WebGPU not available, using CPU NTT fallback".into(),
        );
    }
}

/// Serialize Fr elements to flat bytes (4×u64 LE per element).
/// This is the ark-ff internal Montgomery representation.
fn fr_slice_to_bytes(elements: &[Fr]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(elements.len() * 32);
    for elem in elements {
        let bigint = elem.into_bigint();
        for limb in bigint.0.iter() {
            buf.extend_from_slice(&limb.to_le_bytes());
        }
    }
    buf
}

/// Deserialize flat bytes back to Fr elements.
fn bytes_to_fr_slice(bytes: &[u8], count: usize) -> Vec<Fr> {
    assert_eq!(bytes.len(), count * 32, "byte buffer size mismatch");
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * 32;
        let mut limbs = [0u64; 4];
        for (j, limb) in limbs.iter_mut().enumerate() {
            let start = offset + j * 8;
            let mut le_bytes = [0u8; 8];
            le_bytes.copy_from_slice(&bytes[start..start + 8]);
            *limb = u64::from_le_bytes(le_bytes);
        }
        result.push(Fr::from_bigint(ark_ff::BigInt(limbs)).unwrap_or(Fr::ZERO));
    }
    result
}
