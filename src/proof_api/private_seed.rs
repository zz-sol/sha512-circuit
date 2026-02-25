use bincode::Options;

use super::*;
use crate::INITIAL_STATE;

const MAX_SEED_PRIVATE_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

/// Transitional sealed bundle for a 32-byte seed SHA-512 proof.
///
/// This keeps existing public APIs intact while offering a self-contained proof payload
/// for callers that do not want to pass the seed as a verifier-side instance argument.
///
/// Security note: this is an API-level sealed bundle, not a dedicated private-witness AIR.
#[derive(Clone, Debug)]
pub struct Sha512Seed32PrivateProof {
    pub digest: [u8; 64],
    pub settings: Sha512ProofSettings,
    pub sealed_instance: Vec<u8>,
    pub sealed_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SerializableSeed32PrivateProof {
    digest: Vec<u8>,
    settings: Sha512ProofSettings,
    sealed_instance: Vec<u8>,
    sealed_proof: Vec<u8>,
}

pub fn prove_seed32_private(seed: [u8; 32]) -> Result<Sha512Seed32PrivateProof, String> {
    prove_seed32_private_with_settings(seed, Sha512ProofSettings::default())
}

pub fn prove_seed32_private_with_settings(
    seed: [u8; 32],
    settings: Sha512ProofSettings,
) -> Result<Sha512Seed32PrivateProof, String> {
    let instance = Sha512MessageInstance {
        initial_state: INITIAL_STATE,
        message: seed.to_vec(),
    };
    let proof = prove_message_with_settings(&instance, settings)?;
    let sealed_instance = serialize_message_instance(&instance)?;
    let sealed_proof = serialize_multi_block_proof(&proof)?;
    Ok(Sha512Seed32PrivateProof {
        digest: proof.digest,
        settings,
        sealed_instance,
        sealed_proof,
    })
}

pub fn verify_seed32_private_proof(bundle: &Sha512Seed32PrivateProof) -> bool {
    let verifier_policy = Sha512ProofSettings::default();
    if bundle.settings != verifier_policy {
        return false;
    }
    verify_seed32_private_proof_with_settings(bundle, verifier_policy)
}

pub fn verify_seed32_private_proof_with_settings(
    bundle: &Sha512Seed32PrivateProof,
    settings: Sha512ProofSettings,
) -> bool {
    if !meets_minimum_verifier_policy(settings) || bundle.settings != settings {
        return false;
    }

    let Ok(instance) = deserialize_message_instance(&bundle.sealed_instance) else {
        return false;
    };
    if instance.initial_state != INITIAL_STATE || instance.message.len() != 32 {
        return false;
    }

    let Ok(proof) = deserialize_multi_block_proof(&bundle.sealed_proof) else {
        return false;
    };
    if proof.digest != bundle.digest {
        return false;
    }

    verify_message_proof_with_settings(&instance, &proof, settings)
}

pub fn serialize_seed32_private_proof(
    bundle: &Sha512Seed32PrivateProof,
) -> Result<Vec<u8>, String> {
    let serializable = SerializableSeed32PrivateProof {
        digest: bundle.digest.to_vec(),
        settings: bundle.settings,
        sealed_instance: bundle.sealed_instance.clone(),
        sealed_proof: bundle.sealed_proof.clone(),
    };
    let bytes = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_SEED_PRIVATE_BUNDLE_BYTES {
        return Err("serialized seed32 private proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_seed32_private_proof(bytes: &[u8]) -> Result<Sha512Seed32PrivateProof, String> {
    if bytes.len() > MAX_SEED_PRIVATE_BUNDLE_BYTES {
        return Err("serialized seed32 private proof exceeds configured size limit".to_string());
    }
    let bincode_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SEED_PRIVATE_BUNDLE_BYTES as u64);
    let serializable: SerializableSeed32PrivateProof =
        bincode_opts.deserialize(bytes).map_err(|e| e.to_string())?;
    if serializable.digest.len() != 64 {
        return Err("invalid digest length in serialized seed32 private proof".to_string());
    }
    let mut digest = [0_u8; 64];
    digest.copy_from_slice(&serializable.digest);
    Ok(Sha512Seed32PrivateProof {
        digest,
        settings: serializable.settings,
        sealed_instance: serializable.sealed_instance,
        sealed_proof: serializable.sealed_proof,
    })
}
