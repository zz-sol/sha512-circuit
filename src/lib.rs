//! # sha512-circuit
//!
//! A [Plonky3](https://github.com/Plonky3/Plonky3) STARK circuit that proves the correct execution
//! of SHA-512 block compression without revealing intermediate computation details.
//!
//! ## Overview
//!
//! This crate implements an Algebraic Intermediate Representation (AIR) for the SHA-512
//! compression function. Given an initial chaining state and a 128-byte message block, the
//! circuit produces a STARK proof that the prover knows a valid execution of all 80 SHA-512
//! rounds.
//!
//! The public inputs to the proof are the 8 working-state words (`a..h`) after round 80
//! (before feed-forward). The feed-forward addition is recomputed outside the AIR during
//! verification by adding those words to the known initial state, so the caller must supply
//! the correct initial state when verifying.
//!
//! ## Cryptographic parameters
//!
//! | Parameter | Value |
//! |-----------|-------|
//! | Field | BabyBear (p = 2³¹ − 2²⁷ + 1) |
//! | Extension degree | 4 (binomial extension over BabyBear) |
//! | Polynomial commitment | FRI over BabyBear with Keccak-256 Merkle trees |
//! | Trace dimensions | 128 rows × 1076 columns per 128-byte block |
//! | Proof size (typical) | 90–200 KB per block |
//!
//! ## Security notice
//!
//! **This implementation has not been audited.** The default [`Sha512ProofSettings`] use
//! test-grade FRI parameters (`log_final_poly_len = 2`) which provide very low security.
//! For any production deployment, supply custom settings with parameters appropriate for
//! your target security level.
//!
//! ## Quick start
//!
//! ### Single-block proof
//!
//! ```rust,no_run
//! use sha512_circuit::{
//!     INITIAL_STATE, Sha512SingleBlockInstance,
//!     prove_single_block, verify_single_block_proof,
//! };
//!
//! let instance = Sha512SingleBlockInstance {
//!     initial_state: INITIAL_STATE,
//!     block: [0u8; 128],
//! };
//! let proof = prove_single_block(instance);
//! assert!(verify_single_block_proof(instance, &proof));
//! ```
//!
//! ### Full-message proof
//!
//! ```rust,no_run
//! use sha512_circuit::{
//!     INITIAL_STATE, Sha512MessageInstance,
//!     prove_message, verify_message_proof,
//! };
//!
//! let instance = Sha512MessageInstance {
//!     initial_state: INITIAL_STATE,
//!     message: b"hello, world".to_vec(),
//! };
//! let proof = prove_message(&instance);
//! assert!(verify_message_proof(&instance, &proof));
//! let digest: [u8; 64] = proof.digest;
//! ```
//!
//! ### Serialization
//!
//! ```rust,no_run
//! use sha512_circuit::{
//!     INITIAL_STATE, Sha512SingleBlockInstance,
//!     prove_single_block, serialize_single_block_proof, deserialize_single_block_proof,
//! };
//!
//! let instance = Sha512SingleBlockInstance {
//!     initial_state: INITIAL_STATE,
//!     block: [0u8; 128],
//! };
//! let proof = prove_single_block(instance);
//! let bytes = serialize_single_block_proof(&proof);
//! let proof2 = deserialize_single_block_proof(&bytes).unwrap();
//! ```
//!
//! ## Module structure
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`Sha512Circuit`] | SHA-512 reference implementation and trace generation |
//! | [`Sha512RoundAir`] | Plonky3 AIR definition and constraint system |
//! | [`BlockTrace`] | Witness data for a single block compression |
//! | `proof_api` | High-level prove / verify / serialize API (re-exported below) |
//! | `constants` | SHA-512 initial values and round constants |
//! | `ops` | Bitwise helper functions (Ch, Maj, Σ0, Σ1, σ0, σ1) |

mod air;
mod constants;
mod logup_experimental;
mod ops;
mod proof_api;
mod sha512;
mod trace;

pub use air::Sha512RoundAir;
pub use constants::INITIAL_STATE;
pub use logup_experimental::{
    Sha512LagLogupBatchProof, Sha512LagLogupConfig, Sha512LagLogupProof, Sha512LagLogupSettings,
    prove_sha_lag_logup, prove_sha_lag_logup_with_settings, verify_sha_lag_logup,
    verify_sha_lag_logup_with_settings,
};
pub use proof_api::{
    Sha512MessageInstance, Sha512MultiBlockProof, Sha512PreprocessedVk, Sha512ProofSettings,
    Sha512SingleBlockInstance, Sha512SingleBlockProof, Sha512StarkConfig, Sha512StarkProof,
    deserialize_message_instance, deserialize_multi_block_proof, deserialize_single_block_instance,
    deserialize_single_block_proof, prove_message, prove_message_with_settings, prove_single_block,
    prove_single_block_with_settings, serialize_message_instance, serialize_multi_block_proof,
    serialize_single_block_instance, serialize_single_block_proof, verify_message_proof,
    verify_message_proof_with_settings, verify_single_block_proof,
    verify_single_block_proof_with_settings,
};
pub use sha512::Sha512Circuit;
pub use trace::BlockTrace;

#[cfg(test)]
mod proof_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_logup_experimental;
#[cfg(test)]
mod tests_logup_sha_range;
