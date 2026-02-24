use bincode::Options;

use super::*;

/// Serialises a [`Sha512SingleBlockInstance`] to bytes.
pub fn serialize_single_block_instance(instance: &Sha512SingleBlockInstance) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64 + 128);
    for word in instance.initial_state {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&instance.block);
    bytes
}

/// Deserialises a [`Sha512SingleBlockInstance`] from bytes.
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
/// # Errors
///
/// Returns `Err` if message size exceeds configured limits.
pub fn serialize_message_instance(instance: &Sha512MessageInstance) -> Result<Vec<u8>, String> {
    validate_message_size(instance.message.len())?;

    let mut bytes = Vec::with_capacity(64 + 8 + instance.message.len());
    for word in instance.initial_state {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&(instance.message.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&instance.message);
    Ok(bytes)
}

/// Deserialises a [`Sha512MessageInstance`] from bytes.
///
/// # Errors
///
/// Returns `Err` if the header is malformed, size exceeds limits, or lengths mismatch.
pub fn deserialize_message_instance(bytes: &[u8]) -> Result<Sha512MessageInstance, String> {
    if bytes.len() < 72 {
        return Err("message instance too short".to_string());
    }

    let mut initial_state = [0_u64; 8];
    for (i, chunk) in bytes[..64].chunks_exact(8).enumerate() {
        initial_state[i] = u64::from_be_bytes(chunk.try_into().expect("chunk size"));
    }

    let len = u64::from_be_bytes(bytes[64..72].try_into().expect("length field")) as usize;
    validate_message_size(len)?;
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
/// # Errors
///
/// Returns `Err` if serialization fails or proof-size limits are exceeded.
pub fn serialize_single_block_proof(proof: &Sha512SingleBlockProof) -> Result<Vec<u8>, String> {
    let proof_bytes = bincode::serialize(&proof.proof).map_err(|e| e.to_string())?;
    if proof_bytes.len() > MAX_INNER_PROOF_BYTES {
        return Err("inner single-block proof exceeds configured size limit".to_string());
    }
    let serializable = SerializableSingleBlockProof {
        proof_bytes,
        vk: to_serializable_vk(&proof.preprocessed_vk),
        settings: proof.settings,
    };
    let bytes = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_SINGLE_PROOF_BYTES {
        return Err("serialized single-block proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

/// Deserialises a [`Sha512SingleBlockProof`] from bytes.
///
/// # Errors
///
/// Returns `Err` on envelope limits, bincode decode failures, or oversized inner proof.
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
/// # Errors
///
/// Returns `Err` if serialization fails or proof-size limits are exceeded.
pub fn serialize_multi_block_proof(proof: &Sha512MultiBlockProof) -> Result<Vec<u8>, String> {
    let proof_bytes = bincode::serialize(&proof.proof).map_err(|e| e.to_string())?;
    if proof_bytes.len() > MAX_INNER_PROOF_BYTES {
        return Err("inner multi-block proof exceeds configured size limit".to_string());
    }
    let serializable = SerializableMultiBlockProof {
        proof_bytes,
        vk: to_serializable_vk(&proof.preprocessed_vk),
        final_state: proof.final_state,
        digest: proof.digest.to_vec(),
        settings: proof.settings,
    };
    let bytes = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MULTI_PROOF_BYTES {
        return Err("serialized multi-block proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

/// Deserialises a [`Sha512MultiBlockProof`] from bytes.
///
/// # Errors
///
/// Returns `Err` on envelope limits, bincode decode failures, malformed digest,
/// or oversized inner proof.
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
