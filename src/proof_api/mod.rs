//! High-level prove / verify / serialize API for SHA-512 STARK proofs.
//!
//! This module provides the primary interface that most callers will use. It is
//! re-exported from the crate root.

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

mod prove_verify;
mod serialization;

pub use prove_verify::{
    prove_message, prove_message_with_settings, prove_single_block,
    prove_single_block_with_settings, verify_message_proof, verify_message_proof_with_settings,
    verify_single_block_proof, verify_single_block_proof_with_settings,
};
pub use serialization::{
    deserialize_message_instance, deserialize_multi_block_proof, deserialize_single_block_instance,
    deserialize_single_block_proof, serialize_message_instance, serialize_multi_block_proof,
    serialize_single_block_instance, serialize_single_block_proof,
};

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
const MIN_VERIFIER_LOG_FINAL_POLY_LEN: usize = 4;
const MIN_VERIFIER_LOG_BLOWUP: usize = 3;
const MIN_VERIFIER_NUM_QUERIES: usize = 2;
const MIN_VERIFIER_COMMIT_POW_BITS: usize = 1;
const MIN_VERIFIER_QUERY_POW_BITS: usize = 1;
const MAX_MESSAGE_INSTANCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SINGLE_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_MULTI_PROOF_BYTES: usize = 64 * 1024 * 1024;
const MAX_INNER_PROOF_BYTES: usize = 16 * 1024 * 1024;

/// Concrete Plonky3 STARK configuration used by this crate.
pub type Sha512StarkConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// A serialisable Plonky3 STARK proof under [`Sha512StarkConfig`].
pub type Sha512StarkProof = Proof<Sha512StarkConfig>;

/// The preprocessed (instance-dependent) verifier key.
pub type Sha512PreprocessedVk = PreprocessedVerifierKey<Sha512StarkConfig>;

/// FRI and transcript parameters for the STARK prover and verifier.
///
/// Both prover and verifier must use identical settings.
///
/// Defaults are conservative baseline values for this crate, not an audited policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha512ProofSettings {
    /// Log2 of FRI blowup factor.
    pub log_blowup: usize,
    /// Log2 of FRI final polynomial length.
    pub log_final_poly_len: usize,
    /// Number of FRI queries.
    pub num_queries: usize,
    /// Commit-phase proof-of-work bits.
    pub commit_proof_of_work_bits: usize,
    /// Query-phase proof-of-work bits.
    pub query_proof_of_work_bits: usize,
    /// Seed for the Fiat-Shamir transcript challenger.
    pub rng_seed: u64,
}

impl Default for Sha512ProofSettings {
    fn default() -> Self {
        Self {
            log_blowup: 3,
            log_final_poly_len: 4,
            num_queries: 2,
            commit_proof_of_work_bits: 1,
            query_proof_of_work_bits: 1,
            rng_seed: 1,
        }
    }
}

/// The public statement for a single-block SHA-512 STARK proof.
#[derive(Clone, Copy, Debug)]
pub struct Sha512SingleBlockInstance {
    /// The 8 SHA-512 chaining words (H0..H7) going into this block.
    pub initial_state: [u64; 8],
    /// The 128-byte message block.
    pub block: [u8; 128],
}

/// The public statement for a full-message SHA-512 STARK proof.
#[derive(Clone, Debug)]
pub struct Sha512MessageInstance {
    /// Initial chaining state. Use [`crate::INITIAL_STATE`] for a standard hash.
    pub initial_state: [u64; 8],
    /// Arbitrary-length message to be hashed.
    pub message: Vec<u8>,
}

/// A STARK proof for a single 128-byte SHA-512 block.
pub struct Sha512SingleBlockProof {
    /// The raw Plonky3 STARK proof.
    pub proof: Sha512StarkProof,
    /// Preprocessed verifier key committing to instance-dependent trace columns.
    pub preprocessed_vk: Sha512PreprocessedVk,
    /// The proving settings used to generate this proof.
    pub settings: Sha512ProofSettings,
}

/// A STARK proof for a complete SHA-512 message.
pub struct Sha512MultiBlockProof {
    /// The raw Plonky3 STARK proof.
    pub proof: Sha512StarkProof,
    /// Preprocessed verifier key committing to instance-dependent message trace.
    pub preprocessed_vk: Sha512PreprocessedVk,
    /// The SHA-512 chaining state after the last block.
    pub final_state: [u64; 8],
    /// The 64-byte SHA-512 digest.
    pub digest: [u8; 64],
    /// The proving settings used to generate this proof.
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
        log_blowup: settings.log_blowup,
        log_final_poly_len: settings.log_final_poly_len,
        num_queries: settings.num_queries,
        commit_proof_of_work_bits: settings.commit_proof_of_work_bits,
        query_proof_of_work_bits: settings.query_proof_of_work_bits,
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

fn meets_minimum_verifier_policy(settings: Sha512ProofSettings) -> bool {
    settings.log_final_poly_len >= MIN_VERIFIER_LOG_FINAL_POLY_LEN
        && settings.log_blowup >= MIN_VERIFIER_LOG_BLOWUP
        && settings.num_queries >= MIN_VERIFIER_NUM_QUERIES
        && settings.commit_proof_of_work_bits >= MIN_VERIFIER_COMMIT_POW_BITS
        && settings.query_proof_of_work_bits >= MIN_VERIFIER_QUERY_POW_BITS
}

fn validate_settings_for_proving(settings: Sha512ProofSettings) -> Result<(), String> {
    if !meets_minimum_verifier_policy(settings) {
        return Err("proof settings do not meet minimum verifier policy".to_string());
    }
    Ok(())
}

fn validate_message_size(message_len: usize) -> Result<(), String> {
    if message_len > MAX_MESSAGE_INSTANCE_BYTES {
        return Err("message instance exceeds configured size limit".to_string());
    }
    Ok(())
}
