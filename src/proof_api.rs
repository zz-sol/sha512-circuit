use bincode::Options;
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{ExtensionMmcs, Pcs as PcsTrait};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
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
const MAX_MULTI_BLOCK_PROOFS: usize = 4096;

pub type Sha512StarkConfig = StarkConfig<Pcs, Challenge, Challenger>;
pub type Sha512StarkProof = Proof<Sha512StarkConfig>;
pub type Sha512PreprocessedVk = PreprocessedVerifierKey<Sha512StarkConfig>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Sha512ProofSettings {
    pub log_final_poly_len: usize,
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

#[derive(Clone, Copy, Debug)]
pub struct Sha512SingleBlockInstance {
    pub initial_state: [u64; 8],
    pub block: [u8; 128],
}

#[derive(Clone, Debug)]
pub struct Sha512MessageInstance {
    pub initial_state: [u64; 8],
    pub message: Vec<u8>,
}

pub struct Sha512SingleBlockProof {
    pub proof: Sha512StarkProof,
    pub preprocessed_vk: Sha512PreprocessedVk,
    pub settings: Sha512ProofSettings,
}

pub struct Sha512MultiBlockProof {
    pub block_proofs: Vec<Sha512SingleBlockProof>,
    pub final_state: [u64; 8],
    pub digest: [u8; 64],
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
    block_proofs: Vec<SerializableSingleBlockProof>,
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
    let fri_params = create_test_fri_params(challenge_mmcs, settings.log_final_poly_len);
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

pub fn prove_single_block(instance: Sha512SingleBlockInstance) -> Sha512SingleBlockProof {
    prove_single_block_with_settings(instance, Sha512ProofSettings::default())
}

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

pub fn verify_single_block_proof(
    instance: Sha512SingleBlockInstance,
    proof: &Sha512SingleBlockProof,
) -> bool {
    verify_single_block_proof_with_settings(instance, proof, proof.settings)
}

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

pub fn prove_message(instance: &Sha512MessageInstance) -> Sha512MultiBlockProof {
    prove_message_with_settings(instance, Sha512ProofSettings::default())
}

pub fn prove_message_with_settings(
    instance: &Sha512MessageInstance,
    settings: Sha512ProofSettings,
) -> Sha512MultiBlockProof {
    let mut state = instance.initial_state;
    let mut block_proofs = Vec::new();

    for block in Sha512Circuit::padded_blocks(&instance.message) {
        let block_instance = Sha512SingleBlockInstance {
            initial_state: state,
            block,
        };
        let proof = prove_single_block_with_settings(block_instance, settings);
        let trace = Sha512Circuit::compress_block(&state, &block);
        state = trace.output_state;
        block_proofs.push(proof);
    }

    Sha512MultiBlockProof {
        block_proofs,
        final_state: state,
        digest: Sha512Circuit::state_to_digest(&state),
        settings,
    }
}

pub fn verify_message_proof(
    instance: &Sha512MessageInstance,
    proof: &Sha512MultiBlockProof,
) -> bool {
    verify_message_proof_with_settings(instance, proof, proof.settings)
}

pub fn verify_message_proof_with_settings(
    instance: &Sha512MessageInstance,
    proof: &Sha512MultiBlockProof,
    settings: Sha512ProofSettings,
) -> bool {
    let blocks = Sha512Circuit::padded_blocks(&instance.message);
    if blocks.len() != proof.block_proofs.len() {
        return false;
    }

    let mut state = instance.initial_state;
    for (block, block_proof) in blocks.iter().zip(&proof.block_proofs) {
        let block_instance = Sha512SingleBlockInstance {
            initial_state: state,
            block: *block,
        };
        if !verify_single_block_proof_with_settings(block_instance, block_proof, settings) {
            return false;
        }

        let trace = Sha512Circuit::compress_block(&state, block);
        state = trace.output_state;
    }

    proof.final_state == state && proof.digest == Sha512Circuit::state_to_digest(&state)
}

pub fn serialize_single_block_instance(instance: &Sha512SingleBlockInstance) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64 + 128);
    for word in instance.initial_state {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&instance.block);
    bytes
}

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

pub fn serialize_message_instance(instance: &Sha512MessageInstance) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64 + 8 + instance.message.len());
    for word in instance.initial_state {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&(instance.message.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&instance.message);
    bytes
}

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

pub fn serialize_single_block_proof(proof: &Sha512SingleBlockProof) -> Vec<u8> {
    let proof_bytes =
        bincode::serialize(&proof.proof).expect("single proof inner serialization should succeed");
    let serializable = SerializableSingleBlockProof {
        proof_bytes,
        vk: to_serializable_vk(&proof.preprocessed_vk),
        settings: proof.settings,
    };
    bincode::serialize(&serializable).expect("single block proof serialization should succeed")
}

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

pub fn serialize_multi_block_proof(proof: &Sha512MultiBlockProof) -> Vec<u8> {
    let serializable = SerializableMultiBlockProof {
        block_proofs: proof
            .block_proofs
            .iter()
            .map(|p| SerializableSingleBlockProof {
                proof_bytes: bincode::serialize(&p.proof)
                    .expect("single proof inner serialization should succeed"),
                vk: to_serializable_vk(&p.preprocessed_vk),
                settings: p.settings,
            })
            .collect(),
        final_state: proof.final_state,
        digest: proof.digest.to_vec(),
        settings: proof.settings,
    };
    bincode::serialize(&serializable).expect("multi block proof serialization should succeed")
}

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
    if serializable.block_proofs.len() > MAX_MULTI_BLOCK_PROOFS {
        return Err("too many block proofs in serialized multi-block proof".to_string());
    }
    let mut digest = [0_u8; 64];
    digest.copy_from_slice(&serializable.digest);

    let mut block_proofs = Vec::with_capacity(serializable.block_proofs.len());
    let inner_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_INNER_PROOF_BYTES as u64);
    for p in serializable.block_proofs {
        if p.proof_bytes.len() > MAX_INNER_PROOF_BYTES {
            return Err("inner block proof exceeds configured size limit".to_string());
        }
        let proof: Sha512StarkProof = inner_opts
            .deserialize(&p.proof_bytes)
            .map_err(|e| e.to_string())?;
        block_proofs.push(Sha512SingleBlockProof {
            proof,
            preprocessed_vk: from_serializable_vk(p.vk),
            settings: p.settings,
        });
    }

    Ok(Sha512MultiBlockProof {
        block_proofs,
        final_state: serializable.final_state,
        digest,
        settings: serializable.settings,
    })
}
