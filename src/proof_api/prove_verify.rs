use super::*;

/// Proves correct SHA-512 compression of a single 128-byte block using default settings.
pub fn prove_single_block(
    instance: Sha512SingleBlockInstance,
) -> Result<Sha512SingleBlockProof, String> {
    prove_single_block_with_settings(instance, Sha512ProofSettings::default())
}

/// Proves correct SHA-512 compression of a single 128-byte block with custom settings.
///
/// # Errors
///
/// Returns `Err` if settings are below verifier policy or setup fails.
pub fn prove_single_block_with_settings(
    instance: Sha512SingleBlockInstance,
    settings: Sha512ProofSettings,
) -> Result<Sha512SingleBlockProof, String> {
    validate_settings_for_proving(settings)?;

    let config = setup_config(settings);

    let trace = Sha512Circuit::compress_block(&instance.initial_state, &instance.block);
    let main = Sha512Circuit::build_plonky3_air_trace(&trace);
    let preprocessed = Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(
        &instance.initial_state,
        &instance.block,
    );

    let air = Sha512RoundAir::new(preprocessed);
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed::<Sha512StarkConfig, _>(&config, &air, TRACE_DEGREE_BITS).ok_or_else(
            || "failed to setup preprocessed data for single-block proof".to_string(),
        )?;
    let public_values = trace.round_states[80].map(bb);

    let proof = prove_with_preprocessed(
        &config,
        &air,
        main,
        &public_values,
        Some(&preprocessed_prover_data),
    );

    Ok(Sha512SingleBlockProof {
        proof,
        preprocessed_vk,
        settings,
    })
}

/// Verifies a single-block proof using the settings embedded in the proof.
pub fn verify_single_block_proof(
    instance: Sha512SingleBlockInstance,
    proof: &Sha512SingleBlockProof,
) -> bool {
    let verifier_policy = Sha512ProofSettings::default();
    if proof.settings != verifier_policy {
        return false;
    }
    verify_single_block_proof_with_settings(instance, proof, verifier_policy)
}

/// Verifies a single-block proof with explicitly specified settings.
pub fn verify_single_block_proof_with_settings(
    instance: Sha512SingleBlockInstance,
    proof: &Sha512SingleBlockProof,
    settings: Sha512ProofSettings,
) -> bool {
    if !meets_minimum_verifier_policy(settings) {
        return false;
    }
    let config = setup_config(settings);
    let preprocessed = Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(
        &instance.initial_state,
        &instance.block,
    );
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
pub fn prove_message(instance: &Sha512MessageInstance) -> Result<Sha512MultiBlockProof, String> {
    prove_message_with_settings(instance, Sha512ProofSettings::default())
}

/// Proves correct SHA-512 hashing of an arbitrary-length message with custom settings.
///
/// # Errors
///
/// Returns `Err` if settings are below verifier policy, input exceeds size limits, or setup fails.
pub fn prove_message_with_settings(
    instance: &Sha512MessageInstance,
    settings: Sha512ProofSettings,
) -> Result<Sha512MultiBlockProof, String> {
    validate_settings_for_proving(settings)?;
    validate_message_size(instance.message.len())?;

    let config = setup_config(settings);
    let bundle =
        Sha512Circuit::build_message_air_bundle(&instance.initial_state, &instance.message);
    let air = Sha512RoundAir::new(bundle.preprocessed.clone());
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed::<Sha512StarkConfig, _>(&config, &air, bundle.degree_bits)
            .ok_or_else(|| "failed to setup preprocessed data for message proof".to_string())?;
    let proof = prove_with_preprocessed(
        &config,
        &air,
        bundle.main,
        &bundle.final_public_values,
        Some(&preprocessed_prover_data),
    );

    Ok(Sha512MultiBlockProof {
        proof,
        preprocessed_vk,
        final_state: bundle.final_state,
        digest: Sha512Circuit::state_to_digest(&bundle.final_state),
        settings,
    })
}

/// Verifies a full-message proof using the settings embedded in the proof.
pub fn verify_message_proof(
    instance: &Sha512MessageInstance,
    proof: &Sha512MultiBlockProof,
) -> bool {
    let verifier_policy = Sha512ProofSettings::default();
    if proof.settings != verifier_policy {
        return false;
    }
    verify_message_proof_with_settings(instance, proof, verifier_policy)
}

/// Verifies a full-message proof with explicitly specified settings.
pub fn verify_message_proof_with_settings(
    instance: &Sha512MessageInstance,
    proof: &Sha512MultiBlockProof,
    settings: Sha512ProofSettings,
) -> bool {
    if !meets_minimum_verifier_policy(settings) {
        return false;
    }
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
