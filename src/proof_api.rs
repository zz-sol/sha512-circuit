//! High-level prove / verify / serialize API for SHA-512 STARK proofs.
//!
//! This module provides the primary interface that most callers will use.  It is
//! completely re-exported from the crate root so you do not need to reference this
//! module path directly.
//!
//! ## Two proof granularities
//!
//! | Level | Input | Output | Blocks proved |
//! |-------|-------|--------|---------------|
//! | Single-block | [`Sha512SingleBlockInstance`] | [`Sha512SingleBlockProof`] | 1 |
//! | Message | [`Sha512MessageInstance`] | [`Sha512MultiBlockProof`] | N (auto-padded) |
//!
//! The message-level API pads the message and proves all resulting blocks in one
//! message-level STARK proof.
//!
//! ## Security note
//!
//! Default [`Sha512ProofSettings`] use test-grade FRI parameters (`log_final_poly_len = 2`)
//! which provide negligible security.  Supply custom settings with appropriate parameters
//! for any deployment that needs real security guarantees.

use bincode::Options;
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{ExtensionMmcs, Pcs as PcsTrait};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{
    PreprocessedVerifierKey, Proof, StarkConfig, prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed,
};
use serde::{Deserialize, Serialize};

use crate::air::Sha512RoundAir;
use crate::ops::bb;
use crate::sha512::Sha512Circuit;

pub type Val = BabyBear;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type Commitment = <Pcs as PcsTrait<Challenge, Challenger>>::Commitment;
const TRACE_DEGREE_BITS: usize = 7;
const MAX_MESSAGE_INSTANCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SINGLE_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_MULTI_PROOF_BYTES: usize = 64 * 1024 * 1024;
const MAX_INNER_PROOF_BYTES: usize = 16 * 1024 * 1024;

/// Concrete Plonky3 STARK configuration used by this crate.
///
/// Built from BabyBear field elements, a degree-4 binomial extension field for challenges,
/// Keccak-256 Merkle trees for commitments, and a Radix-2 DIT for the DFT.
pub type Sha512StarkConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// A serialisable Plonky3 STARK proof under [`Sha512StarkConfig`].
pub type Sha512StarkProof = Proof<Sha512StarkConfig>;

/// The preprocessed (instance-dependent) verifier key.
///
/// Binds the Merkle commitment of the preprocessed trace (initial state, K values,
/// W[0..15], and selector columns) so the verifier can confirm the prover used the
/// correct instance data.
pub type Sha512PreprocessedVk = PreprocessedVerifierKey<Sha512StarkConfig>;

/// FRI and transcript parameters for the STARK prover and verifier.
///
/// Both the prover and verifier must use identical settings; mismatched settings will cause
/// verification to fail.
///
/// ## Fields
///
/// * `log_final_poly_len` — the log₂ of the FRI final polynomial length.  Larger values
///   increase proof security but also proof size and verification time.  The default value
///   of `2` is suitable for testing only.
/// * `rng_seed` — the seed for the Fiat-Shamir challenger transcript.  Changing this
///   produces a different (but equally valid) proof for the same instance.
///
/// ## Default
///
/// The default settings (`log_final_poly_len = 2`, `rng_seed = 1`) prioritise speed for
/// tests and benchmarks.  **Do not use the default in production.**
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Sha512ProofSettings {
    /// Log₂ of the FRI final polynomial length.  Controls proof security and size.
    pub log_final_poly_len: usize,
    /// Seed for the Fiat-Shamir transcript challenger.
    pub rng_seed: u64,
}

impl Default for Sha512ProofSettings {
    fn default() -> Self {
        Self {
            log_final_poly_len: 2,
            rng_seed: 1,
        }
    }
}

/// The public statement for a single-block SHA-512 STARK proof.
///
/// Supplies everything the prover and verifier need to agree on for one 128-byte block:
/// the 8-word input chaining state and the raw block bytes.
///
/// # Correctness responsibility
///
/// The caller is responsible for providing the correct `initial_state`.  For a fresh
/// hash, use [`crate::INITIAL_STATE`].  When chaining blocks manually, pass the
/// `output_state` of the previous block.  Using an incorrect state will produce a
/// valid proof of an incorrect compression — the proof API does **not** validate the
/// relationship between blocks.
#[derive(Clone, Copy, Debug)]
pub struct Sha512SingleBlockInstance {
    /// The 8 SHA-512 chaining words (H0..H7) going into this block.
    pub initial_state: [u64; 8],
    /// The 128-byte (1024-bit) message block, in the layout consumed by SHA-512.
    pub block: [u8; 128],
}

/// The public statement for a full-message SHA-512 STARK proof.
///
/// The message is automatically padded per FIPS 180-4 §5.1.2 and split into 128-byte
/// blocks before proving.  The resulting proof covers all blocks as a sequential chain.
///
/// For the typical case of a complete message starting from the SHA-512 IV, set
/// `initial_state` to [`crate::INITIAL_STATE`].
#[derive(Clone, Debug)]
pub struct Sha512MessageInstance {
    /// Initial chaining state.  Use [`crate::INITIAL_STATE`] for a standard hash.
    pub initial_state: [u64; 8],
    /// Arbitrary-length message to be hashed.  May be empty.
    pub message: Vec<u8>,
}

/// A zero-knowledge STARK proof for a single 128-byte SHA-512 block.
///
/// Contains the raw Plonky3 proof, the preprocessed verifier key (which binds the
/// specific `(initial_state, block)` instance), and the proof settings used when
/// generating the proof.
///
/// Pass an instance of this type along with the matching [`Sha512SingleBlockInstance`]
/// to [`verify_single_block_proof`] to verify.
pub struct Sha512SingleBlockProof {
    /// The raw Plonky3 STARK proof.
    pub proof: Sha512StarkProof,
    /// Preprocessed verifier key committing to the instance-dependent trace columns.
    pub preprocessed_vk: Sha512PreprocessedVk,
    /// The FRI / transcript settings used during proving.
    pub settings: Sha512ProofSettings,
}

/// A zero-knowledge STARK proof for a complete SHA-512 message.
///
/// Wraps one STARK proof over a message-level AIR trace spanning all padded blocks,
/// together with the final chaining state and the 64-byte SHA-512 digest.
///
/// ## Verification
///
/// Pass this along with the original [`Sha512MessageInstance`] to [`verify_message_proof`].
/// The verifier checks one proof and also validates that `final_state` and `digest`
/// are self-consistent.
pub struct Sha512MultiBlockProof {
    /// The raw Plonky3 STARK proof.
    pub proof: Sha512StarkProof,
    /// Preprocessed verifier key committing to the instance-dependent message trace.
    pub preprocessed_vk: Sha512PreprocessedVk,
    /// The SHA-512 chaining state after the last block (post feed-forward).
    pub final_state: [u64; 8],
    /// The 64-byte SHA-512 digest, i.e. `final_state` serialised in big-endian.
    pub digest: [u8; 64],
    /// The FRI / transcript settings shared across all block proofs.
    pub settings: Sha512ProofSettings,
}

#[derive(Serialize, Deserialize)]
struct SerializableVk {
    width: usize,
    degree_bits: usize,
    commitment: Commitment,
}

#[derive(Serialize, Deserialize)]
struct SerializableSingleBlockProof {
    proof_bytes: Vec<u8>,
    vk: SerializableVk,
    settings: Sha512ProofSettings,
}

#[derive(Serialize, Deserialize)]
struct SerializableMultiBlockProof {
    proof_bytes: Vec<u8>,
    vk: SerializableVk,
    final_state: [u64; 8],
    digest: Vec<u8>,
    settings: Sha512ProofSettings,
}

fn setup_config(settings: Sha512ProofSettings) -> Sha512StarkConfig {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: settings.log_final_poly_len,
        num_queries: 2,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(settings.rng_seed.to_le_bytes().to_vec(), byte_hash);
    Sha512StarkConfig::new(pcs, challenger)
}

fn vk_matches(a: &Sha512PreprocessedVk, b: &Sha512PreprocessedVk) -> bool {
    a.commitment == b.commitment && a.degree_bits == b.degree_bits && a.width == b.width
}

fn to_serializable_vk(vk: &Sha512PreprocessedVk) -> SerializableVk {
    SerializableVk {
        width: vk.width,
        degree_bits: vk.degree_bits,
        commitment: vk.commitment,
    }
}

fn from_serializable_vk(vk: SerializableVk) -> Sha512PreprocessedVk {
    Sha512PreprocessedVk {
        width: vk.width,
        degree_bits: vk.degree_bits,
        commitment: vk.commitment,
    }
}

/// Proves correct SHA-512 compression of a single 128-byte block using default settings.
///
/// This is a convenience wrapper around [`prove_single_block_with_settings`] that uses
/// [`Sha512ProofSettings::default`] (test-grade FRI parameters).
///
/// # Panics
///
/// Panics if the Plonky3 prover encounters an internal error (e.g. an invalid trace).
/// In practice this should not occur for valid inputs.
pub fn prove_single_block(instance: Sha512SingleBlockInstance) -> Sha512SingleBlockProof {
    prove_single_block_with_settings(instance, Sha512ProofSettings::default())
}

/// Proves correct SHA-512 compression of a single 128-byte block with custom settings.
///
/// Steps performed:
/// 1. Builds the STARK configuration from `settings`.
/// 2. Runs [`Sha512Circuit::compress_block`] to generate the execution witness.
/// 3. Constructs the main AIR trace and the preprocessed trace from the witness and instance.
/// 4. Calls the Plonky3 prover with the 8 public values (`round_states[80]`).
///
/// The resulting [`Sha512SingleBlockProof`] can be verified with
/// [`verify_single_block_proof_with_settings`] using the same `settings`.
///
/// # Panics
///
/// Panics if Plonky3's `setup_preprocessed` or `prove_with_preprocessed` fails.
pub fn prove_single_block_with_settings(
    instance: Sha512SingleBlockInstance,
    settings: Sha512ProofSettings,
) -> Sha512SingleBlockProof {
    let config = setup_config(settings);

    let trace = Sha512Circuit::compress_block(&instance.initial_state, &instance.block);
    let main = Sha512Circuit::build_plonky3_air_trace(&trace);
    let preprocessed = Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(
        &instance.initial_state,
        &instance.block,
    );

    let air = Sha512RoundAir::new(preprocessed);
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed::<Sha512StarkConfig, _>(&config, &air, TRACE_DEGREE_BITS)
            .expect("has preprocessed");
    // Public values bind to the final compression working state (a..h) before feed-forward.
    let public_values = trace.round_states[80].map(bb);

    let proof = prove_with_preprocessed(
        &config,
        &air,
        main,
        &public_values,
        Some(&preprocessed_prover_data),
    );

    Sha512SingleBlockProof {
        proof,
        preprocessed_vk,
        settings,
    }
}

/// Verifies a single-block proof using the settings embedded in the proof.
///
/// Convenience wrapper around [`verify_single_block_proof_with_settings`] that extracts
/// the settings from `proof.settings`.
///
/// # Returns
///
/// `true` if the proof is valid for the given `instance`, `false` otherwise.
pub fn verify_single_block_proof(
    instance: Sha512SingleBlockInstance,
    proof: &Sha512SingleBlockProof,
) -> bool {
    verify_single_block_proof_with_settings(instance, proof, proof.settings)
}

/// Verifies a single-block proof with explicitly specified settings.
///
/// Steps performed:
/// 1. Reconstructs the preprocessed trace from `instance` and derives the expected
///    verifier key.
/// 2. Checks that the verifier key in `proof.preprocessed_vk` matches the expected key.
///    A mismatch indicates the proof was generated for a different instance.
/// 3. Recomputes the 8 public values (`round_states[80]`) by running `compress_block`.
/// 4. Calls Plonky3's `verify_with_preprocessed` to check the STARK proof.
///
/// # Returns
///
/// `true` if and only if all four checks pass.
pub fn verify_single_block_proof_with_settings(
    instance: Sha512SingleBlockInstance,
    proof: &Sha512SingleBlockProof,
    settings: Sha512ProofSettings,
) -> bool {
    let config = setup_config(settings);
    let preprocessed = Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(
        &instance.initial_state,
        &instance.block,
    );
    // Public values bind to the final compression working state (a..h) before feed-forward.
    let public_values = Sha512Circuit::compress_block(&instance.initial_state, &instance.block)
        .round_states[80]
        .map(bb);
    let air = Sha512RoundAir::new(preprocessed);
    let Some((_, expected_vk)) =
        setup_preprocessed::<Sha512StarkConfig, _>(&config, &air, TRACE_DEGREE_BITS)
    else {
        return false;
    };
    if !vk_matches(&expected_vk, &proof.preprocessed_vk) {
        return false;
    }

    verify_with_preprocessed(
        &config,
        &air,
        &proof.proof,
        &public_values,
        Some(&proof.preprocessed_vk),
    )
    .is_ok()
}

/// Proves correct SHA-512 hashing of an arbitrary-length message using default settings.
///
/// Convenience wrapper around [`prove_message_with_settings`].
pub fn prove_message(instance: &Sha512MessageInstance) -> Sha512MultiBlockProof {
    prove_message_with_settings(instance, Sha512ProofSettings::default())
}

/// Proves correct SHA-512 hashing of an arbitrary-length message with custom settings.
///
/// Steps performed:
/// 1. Pads `instance.message` per FIPS 180-4 §5.1.2 to produce N × 128-byte blocks.
/// 2. Builds one message-level AIR trace over all blocks (padded to a power-of-two
///    number of 128-row block segments).
/// 3. Proves once over the full message trace.
/// 4. Assembles the proof, verifier key, final state, digest, and settings
///    into a [`Sha512MultiBlockProof`].
///
/// # Panics
///
/// Panics if Plonky3 setup/proving fails.
pub fn prove_message_with_settings(
    instance: &Sha512MessageInstance,
    settings: Sha512ProofSettings,
) -> Sha512MultiBlockProof {
    let config = setup_config(settings);
    let bundle =
        Sha512Circuit::build_message_air_bundle(&instance.initial_state, &instance.message);
    let air = Sha512RoundAir::new(bundle.preprocessed.clone());
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed::<Sha512StarkConfig, _>(&config, &air, bundle.degree_bits)
            .expect("has preprocessed");
    let proof = prove_with_preprocessed(
        &config,
        &air,
        bundle.main,
        &bundle.final_public_values,
        Some(&preprocessed_prover_data),
    );

    Sha512MultiBlockProof {
        proof,
        preprocessed_vk,
        final_state: bundle.final_state,
        digest: Sha512Circuit::state_to_digest(&bundle.final_state),
        settings,
    }
}

/// Verifies a full-message proof using the settings embedded in the proof.
///
/// Convenience wrapper around [`verify_message_proof_with_settings`].
///
/// # Returns
///
/// `true` if the entire proof chain is valid for `instance`, `false` otherwise.
pub fn verify_message_proof(
    instance: &Sha512MessageInstance,
    proof: &Sha512MultiBlockProof,
) -> bool {
    verify_message_proof_with_settings(instance, proof, proof.settings)
}

/// Verifies a full-message proof with explicitly specified settings.
///
/// Steps performed:
/// 1. Rebuilds the instance-dependent message preprocessed trace and expected final public values.
/// 2. Checks that `proof.preprocessed_vk` matches the rebuilt verifier key.
/// 3. Verifies the single STARK proof over the full message trace.
/// 4. Verifies that `proof.final_state` and `proof.digest` are self-consistent.
///
/// # Returns
///
/// `true` if and only if all checks pass.
pub fn verify_message_proof_with_settings(
    instance: &Sha512MessageInstance,
    proof: &Sha512MultiBlockProof,
    settings: Sha512ProofSettings,
) -> bool {
    let config = setup_config(settings);
    let bundle =
        Sha512Circuit::build_message_air_bundle(&instance.initial_state, &instance.message);
    if proof.final_state != bundle.final_state
        || proof.digest != Sha512Circuit::state_to_digest(&bundle.final_state)
    {
        return false;
    }

    let air = Sha512RoundAir::new(bundle.preprocessed);
    let Some((_, expected_vk)) =
        setup_preprocessed::<Sha512StarkConfig, _>(&config, &air, bundle.degree_bits)
    else {
        return false;
    };
    if !vk_matches(&expected_vk, &proof.preprocessed_vk) {
        return false;
    }

    verify_with_preprocessed(
        &config,
        &air,
        &proof.proof,
        &bundle.final_public_values,
        Some(&proof.preprocessed_vk),
    )
    .is_ok()
}

/// Serialises a [`Sha512SingleBlockInstance`] to bytes.
///
/// Format (192 bytes total):
/// * 8 × 8 bytes — `initial_state` words in big-endian.
/// * 128 bytes   — `block` verbatim.
pub fn serialize_single_block_instance(instance: &Sha512SingleBlockInstance) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64 + 128);
    for word in instance.initial_state {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&instance.block);
    bytes
}

/// Deserialises a [`Sha512SingleBlockInstance`] from bytes produced by
/// [`serialize_single_block_instance`].
///
/// # Errors
///
/// Returns `Err` if `bytes.len() != 192`.
pub fn deserialize_single_block_instance(
    bytes: &[u8],
) -> Result<Sha512SingleBlockInstance, String> {
    if bytes.len() != 64 + 128 {
        return Err("invalid single-block instance length".to_string());
    }

    let mut initial_state = [0_u64; 8];
    for (i, chunk) in bytes[..64].chunks_exact(8).enumerate() {
        initial_state[i] = u64::from_be_bytes(chunk.try_into().expect("chunk size"));
    }
    let mut block = [0_u8; 128];
    block.copy_from_slice(&bytes[64..]);

    Ok(Sha512SingleBlockInstance {
        initial_state,
        block,
    })
}

/// Serialises a [`Sha512MessageInstance`] to bytes.
///
/// Format:
/// * 8 × 8 bytes — `initial_state` words in big-endian.
/// * 8 bytes     — message length as a big-endian `u64`.
/// * N bytes     — message bytes verbatim.
pub fn serialize_message_instance(instance: &Sha512MessageInstance) -> Vec<u8> {
    assert!(
        instance.message.len() <= MAX_MESSAGE_INSTANCE_BYTES,
        "message instance exceeds configured size limit"
    );
    let mut bytes = Vec::with_capacity(64 + 8 + instance.message.len());
    for word in instance.initial_state {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&(instance.message.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&instance.message);
    bytes
}

/// Deserialises a [`Sha512MessageInstance`] from bytes produced by
/// [`serialize_message_instance`].
///
/// # Errors
///
/// Returns `Err` if:
/// * `bytes.len() < 72` (header too short).
/// * The encoded message length exceeds `MAX_MESSAGE_INSTANCE_BYTES` (16 MiB).
/// * `bytes.len() != 72 + message_len` (length field inconsistent with actual slice).
pub fn deserialize_message_instance(bytes: &[u8]) -> Result<Sha512MessageInstance, String> {
    if bytes.len() < 72 {
        return Err("message instance too short".to_string());
    }

    let mut initial_state = [0_u64; 8];
    for (i, chunk) in bytes[..64].chunks_exact(8).enumerate() {
        initial_state[i] = u64::from_be_bytes(chunk.try_into().expect("chunk size"));
    }

    let len = u64::from_be_bytes(bytes[64..72].try_into().expect("length field")) as usize;
    if len > MAX_MESSAGE_INSTANCE_BYTES {
        return Err("message instance exceeds configured size limit".to_string());
    }
    if bytes.len() != 72 + len {
        return Err("message instance length mismatch".to_string());
    }

    Ok(Sha512MessageInstance {
        initial_state,
        message: bytes[72..].to_vec(),
    })
}

/// Serialises a [`Sha512SingleBlockProof`] to bytes using bincode.
///
/// The inner STARK proof is serialised separately (to allow independent size limiting
/// on deserialization) and embedded as a length-prefixed byte slice in the outer
/// envelope.
///
/// # Panics
///
/// Panics if bincode serialisation fails (should not happen in practice).
pub fn serialize_single_block_proof(proof: &Sha512SingleBlockProof) -> Vec<u8> {
    let proof_bytes =
        bincode::serialize(&proof.proof).expect("single proof inner serialization should succeed");
    assert!(
        proof_bytes.len() <= MAX_INNER_PROOF_BYTES,
        "inner single-block proof exceeds configured size limit"
    );
    let serializable = SerializableSingleBlockProof {
        proof_bytes,
        vk: to_serializable_vk(&proof.preprocessed_vk),
        settings: proof.settings,
    };
    let bytes =
        bincode::serialize(&serializable).expect("single block proof serialization should succeed");
    assert!(
        bytes.len() <= MAX_SINGLE_PROOF_BYTES,
        "serialized single-block proof exceeds configured size limit"
    );
    bytes
}

/// Deserialises a [`Sha512SingleBlockProof`] from bytes produced by
/// [`serialize_single_block_proof`].
///
/// Applies hard size limits to protect against malicious inputs:
/// * Outer envelope: 16 MiB (`MAX_SINGLE_PROOF_BYTES`).
/// * Inner STARK proof: 16 MiB (`MAX_INNER_PROOF_BYTES`).
///
/// # Errors
///
/// Returns `Err` if:
/// * `bytes.len() > MAX_SINGLE_PROOF_BYTES`.
/// * Bincode outer deserialisation fails.
/// * The embedded inner proof exceeds `MAX_INNER_PROOF_BYTES`.
/// * Bincode inner deserialisation fails.
pub fn deserialize_single_block_proof(bytes: &[u8]) -> Result<Sha512SingleBlockProof, String> {
    if bytes.len() > MAX_SINGLE_PROOF_BYTES {
        return Err("serialized single-block proof exceeds configured size limit".to_string());
    }
    let bincode_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SINGLE_PROOF_BYTES as u64);
    let serializable: SerializableSingleBlockProof =
        bincode_opts.deserialize(bytes).map_err(|e| e.to_string())?;
    if serializable.proof_bytes.len() > MAX_INNER_PROOF_BYTES {
        return Err("inner single-block proof exceeds configured size limit".to_string());
    }
    let inner_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_INNER_PROOF_BYTES as u64);
    let proof: Sha512StarkProof = inner_opts
        .deserialize(&serializable.proof_bytes)
        .map_err(|e| e.to_string())?;
    Ok(Sha512SingleBlockProof {
        proof,
        preprocessed_vk: from_serializable_vk(serializable.vk),
        settings: serializable.settings,
    })
}

/// Serialises a [`Sha512MultiBlockProof`] to bytes using bincode.
///
/// Uses a two-level envelope strategy (same as [`serialize_single_block_proof`]):
/// the inner STARK proof is serialised first and embedded as bytes in the outer struct.
///
/// # Panics
///
/// Panics if bincode serialisation fails.
pub fn serialize_multi_block_proof(proof: &Sha512MultiBlockProof) -> Vec<u8> {
    let proof_bytes =
        bincode::serialize(&proof.proof).expect("multi proof inner serialization should succeed");
    assert!(
        proof_bytes.len() <= MAX_INNER_PROOF_BYTES,
        "inner multi-block proof exceeds configured size limit"
    );
    let serializable = SerializableMultiBlockProof {
        proof_bytes,
        vk: to_serializable_vk(&proof.preprocessed_vk),
        final_state: proof.final_state,
        digest: proof.digest.to_vec(),
        settings: proof.settings,
    };
    let bytes =
        bincode::serialize(&serializable).expect("multi block proof serialization should succeed");
    assert!(
        bytes.len() <= MAX_MULTI_PROOF_BYTES,
        "serialized multi-block proof exceeds configured size limit"
    );
    bytes
}

/// Deserialises a [`Sha512MultiBlockProof`] from bytes produced by
/// [`serialize_multi_block_proof`].
///
/// Applies hard size limits:
/// * Outer envelope: 64 MiB (`MAX_MULTI_PROOF_BYTES`).
/// * Inner proof: 16 MiB (`MAX_INNER_PROOF_BYTES`).
///
/// # Errors
///
/// Returns `Err` if:
/// * `bytes.len() > MAX_MULTI_PROOF_BYTES`.
/// * Bincode outer deserialisation fails.
/// * The digest field is not exactly 64 bytes.
/// * The inner proof exceeds `MAX_INNER_PROOF_BYTES` or fails deserialisation.
pub fn deserialize_multi_block_proof(bytes: &[u8]) -> Result<Sha512MultiBlockProof, String> {
    if bytes.len() > MAX_MULTI_PROOF_BYTES {
        return Err("serialized multi-block proof exceeds configured size limit".to_string());
    }
    let bincode_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_MULTI_PROOF_BYTES as u64);
    let serializable: SerializableMultiBlockProof =
        bincode_opts.deserialize(bytes).map_err(|e| e.to_string())?;
    if serializable.digest.len() != 64 {
        return Err("invalid digest length in serialized multi-block proof".to_string());
    }
    if serializable.proof_bytes.len() > MAX_INNER_PROOF_BYTES {
        return Err("inner multi-block proof exceeds configured size limit".to_string());
    }
    let mut digest = [0_u8; 64];
    digest.copy_from_slice(&serializable.digest);

    let inner_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_INNER_PROOF_BYTES as u64);
    let proof: Sha512StarkProof = inner_opts
        .deserialize(&serializable.proof_bytes)
        .map_err(|e| e.to_string())?;

    Ok(Sha512MultiBlockProof {
        proof,
        preprocessed_vk: from_serializable_vk(serializable.vk),
        final_state: serializable.final_state,
        digest,
        settings: serializable.settings,
    })
}
