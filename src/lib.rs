mod air;
mod constants;
mod ops;
mod proof_api;
mod sha512;
mod trace;

pub use air::Sha512RoundAir;
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
