pub mod file;
pub use file::binary_format;
pub mod hash_config;
mod interner;
mod mavros;
mod noir_proof_scheme;
pub mod optimize;
pub mod prefix_covector;
mod prover;
mod r1cs;
pub mod skyscraper;
pub mod sparse_matrix;
mod transcript_sponge;
pub mod u256_arith;
pub mod utils;
mod verifier;
mod whir_r1cs;
pub mod witness;

use crate::{
    interner::{InternedFieldElement, Interner},
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
};
pub use {
    acir::FieldElement as NoirElement,
    ark_bn254::Fr as FieldElement,
    hash_config::HashConfig,
    mavros::{MavrosProver, MavrosSchemeData},
    noir_proof_scheme::{NoirProof, NoirProofScheme, NoirSchemeData},
    prefix_covector::{OffsetCovector, PrefixCovector},
    prover::{NoirProver, Prover},
    r1cs::R1CS,
    transcript_sponge::TranscriptSponge,
    verifier::Verifier,
    whir_r1cs::{WhirConfig, WhirR1CSProof, WhirR1CSScheme, WhirZkConfig},
    witness::PublicInputs,
};

/// Register provekit's custom implementations in whir's global registries.
///
/// Must be called once before any prove/verify operations.
/// Idempotent — safe to call multiple times.
///
/// On WASM targets, the NTT engine may have already been registered by
/// `initNtt()` (which uses GPU NTT if WebGPU is available). In that case,
/// this function skips NTT registration to avoid overwriting the GPU engine.
pub fn register_ntt() {
    use std::sync::{Arc, Once};
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // On WASM, initNtt() may have already registered a GPU-backed NTT.
        // Only register the default CPU NTT if nothing has been registered yet.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
                Arc::new(whir::algebra::ntt::ArkNtt::<FieldElement>::default());
            whir::algebra::ntt::NTT.insert(ntt);
        }

        #[cfg(target_arch = "wasm32")]
        {
            // On WASM, only register CPU NTT if GPU NTT wasn't already registered.
            // The GPU NTT is registered by initNtt() called from JS before prove.
            if !whir::algebra::ntt::NTT.contains::<FieldElement>() {
                let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
                    Arc::new(whir::algebra::ntt::ArkNtt::<FieldElement>::default());
                whir::algebra::ntt::NTT.insert(ntt);
            }
        }

        // Register Skyscraper (ProveKit-specific); WHIR's built-in engines
        // (SHA2, Keccak, Blake3, etc.) are pre-registered via whir::hash::ENGINES.
        whir::hash::ENGINES.register(Arc::new(skyscraper::SkyscraperHashEngine));
    });
}
