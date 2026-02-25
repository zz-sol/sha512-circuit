use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed,
};
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::air::Sha512RoundAir;
use crate::constants::INITIAL_STATE;
use crate::ops::bb;
use crate::proof_api::{
    Sha512MessageInstance, Sha512ProofSettings, Sha512SingleBlockInstance,
    deserialize_message_instance, deserialize_multi_block_proof, deserialize_seed32_private_proof,
    deserialize_single_block_instance, deserialize_single_block_proof, prove_message,
    prove_message_with_settings, prove_seed32_private, prove_single_block,
    prove_single_block_with_settings, serialize_message_instance, serialize_multi_block_proof,
    serialize_seed32_private_proof, serialize_single_block_instance, serialize_single_block_proof,
    verify_message_proof, verify_message_proof_with_settings, verify_seed32_private_proof,
    verify_single_block_proof,
};
use crate::sha512::Sha512Circuit;

type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;

fn setup_test_config() -> Config {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 2,
        num_queries: 2,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    Config::new(pcs, challenger)
}

#[test]
fn prove_and_verify_sha512_air_single_block() {
    let config = setup_test_config();
    let state = INITIAL_STATE;
    let block = [0_u8; 128];

    let trace = Sha512Circuit::compress_block(&state, &block);
    let main = Sha512Circuit::build_plonky3_air_trace(&trace);
    let preprocessed =
        Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(&state, &block);
    let air = Sha512RoundAir::new(preprocessed);
    let public_values = trace.round_states[80].map(bb);

    let degree_bits = 7; // 2^7 = 128 rows
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed::<Config, _>(&config, &air, degree_bits).expect("has preprocessed");

    let proof = prove_with_preprocessed(
        &config,
        &air,
        main,
        &public_values,
        Some(&preprocessed_prover_data),
    );
    verify_with_preprocessed(
        &config,
        &air,
        &proof,
        &public_values,
        Some(&preprocessed_vk),
    )
    .expect("verification should pass");
}

#[test]
fn proof_rejects_wrong_instance_preprocessed_vk() {
    let config = setup_test_config();
    let state = INITIAL_STATE;
    let block = [0_u8; 128];

    let trace = Sha512Circuit::compress_block(&state, &block);
    let main = Sha512Circuit::build_plonky3_air_trace(&trace);

    let preprocessed =
        Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(&state, &block);
    let air = Sha512RoundAir::new(preprocessed);
    let public_values = trace.round_states[80].map(bb);
    let (prover_data, _vk) = setup_preprocessed::<Config, _>(&config, &air, 7).unwrap();
    let proof = prove_with_preprocessed(&config, &air, main, &public_values, Some(&prover_data));

    let mut wrong_block = block;
    wrong_block[0] ^= 1;
    let wrong_preprocessed =
        Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(&state, &wrong_block);
    let wrong_air = Sha512RoundAir::new(wrong_preprocessed);
    let (_wrong_prover_data, wrong_vk) =
        setup_preprocessed::<Config, _>(&config, &wrong_air, 7).expect("has preprocessed");

    let result =
        verify_with_preprocessed(&config, &wrong_air, &proof, &public_values, Some(&wrong_vk));
    assert!(result.is_err());
}

#[test]
fn proof_rejects_wrong_public_values() {
    let config = setup_test_config();
    let state = INITIAL_STATE;
    let block = [0_u8; 128];

    let trace = Sha512Circuit::compress_block(&state, &block);
    let main = Sha512Circuit::build_plonky3_air_trace(&trace);
    let preprocessed =
        Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(&state, &block);
    let air = Sha512RoundAir::new(preprocessed);
    let (prover_data, vk) =
        setup_preprocessed::<Config, _>(&config, &air, 7).expect("has preprocessed");
    let public_values = trace.round_states[80].map(bb);
    let proof = prove_with_preprocessed(&config, &air, main, &public_values, Some(&prover_data));

    let mut wrong_public_values = public_values;
    wrong_public_values[0] += BabyBear::ONE;
    let result = verify_with_preprocessed(&config, &air, &proof, &wrong_public_values, Some(&vk));
    assert!(result.is_err());
}

#[test]
fn public_proof_api_roundtrip() {
    let instance = Sha512SingleBlockInstance {
        initial_state: INITIAL_STATE,
        block: [0_u8; 128],
    };
    let proof = prove_single_block(instance).expect("prove");
    assert!(verify_single_block_proof(instance, &proof));

    let mut wrong_block = instance.block;
    wrong_block[0] ^= 1;
    let wrong_instance = Sha512SingleBlockInstance {
        initial_state: instance.initial_state,
        block: wrong_block,
    };
    assert!(!verify_single_block_proof(wrong_instance, &proof));
}

#[test]
fn public_multiblock_api_boundaries() {
    for len in [127_usize, 128, 129] {
        let instance = Sha512MessageInstance {
            initial_state: INITIAL_STATE,
            message: (0..len).map(|i| ((i * 29 + 7) & 0xff) as u8).collect(),
        };
        let proof = prove_message(&instance).expect("prove");
        assert!(verify_message_proof(&instance, &proof), "len={len}");
    }
}

#[test]
fn public_multiblock_api_long_message() {
    let instance = Sha512MessageInstance {
        initial_state: INITIAL_STATE,
        message: (0..300).map(|i| ((i * 17 + 3) & 0xff) as u8).collect(),
    };
    let settings = Sha512ProofSettings {
        log_blowup: 3,
        log_final_poly_len: 4,
        num_queries: 2,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        rng_seed: 9,
    };
    let proof = prove_message_with_settings(&instance, settings).expect("prove");
    assert!(!verify_message_proof(&instance, &proof));
    assert!(verify_message_proof_with_settings(
        &instance, &proof, settings
    ));

    let mut wrong = instance.clone();
    wrong.message[0] ^= 1;
    assert!(!verify_message_proof(&wrong, &proof));
}

#[test]
fn serialization_roundtrip_instance_and_proof() {
    let single_instance = Sha512SingleBlockInstance {
        initial_state: INITIAL_STATE,
        block: [0_u8; 128],
    };
    let single_bytes = serialize_single_block_instance(&single_instance);
    let single_back = deserialize_single_block_instance(&single_bytes).expect("decode");
    assert_eq!(single_back.initial_state, single_instance.initial_state);
    assert_eq!(single_back.block, single_instance.block);

    let single_proof = prove_single_block(single_instance).expect("prove");
    let single_proof_bytes = serialize_single_block_proof(&single_proof).expect("encode");
    let single_proof_back = deserialize_single_block_proof(&single_proof_bytes).expect("decode");
    assert!(verify_single_block_proof(
        single_instance,
        &single_proof_back
    ));

    let message_instance = Sha512MessageInstance {
        initial_state: INITIAL_STATE,
        message: (0..150).map(|i| ((i * 5 + 11) & 0xff) as u8).collect(),
    };
    let message_bytes = serialize_message_instance(&message_instance).expect("encode");
    let message_back = deserialize_message_instance(&message_bytes).expect("decode");
    assert_eq!(message_back.initial_state, message_instance.initial_state);
    assert_eq!(message_back.message, message_instance.message);

    let message_proof = prove_message(&message_instance).expect("prove");
    let message_proof_bytes = serialize_multi_block_proof(&message_proof).expect("encode");
    let message_proof_back = deserialize_multi_block_proof(&message_proof_bytes).expect("decode");
    assert!(verify_message_proof(&message_instance, &message_proof_back));
}

#[test]
fn deserialize_single_block_proof_rejects_oversized_input() {
    let bytes = vec![0_u8; (16 * 1024 * 1024) + 1];
    assert!(deserialize_single_block_proof(&bytes).is_err());
}

#[test]
fn deserialize_multi_block_proof_rejects_oversized_input() {
    let bytes = vec![0_u8; (64 * 1024 * 1024) + 1];
    assert!(deserialize_multi_block_proof(&bytes).is_err());
}

#[test]
fn deserialize_message_instance_rejects_oversized_declared_length() {
    let mut bytes = vec![0_u8; 72];
    bytes[64..72].copy_from_slice(&u64::MAX.to_be_bytes());
    let err = deserialize_message_instance(&bytes).expect_err("should fail");
    assert!(err.contains("exceeds configured size limit"));
}

#[test]
fn prove_rejects_settings_below_minimum_policy() {
    let block_instance = Sha512SingleBlockInstance {
        initial_state: INITIAL_STATE,
        block: [0_u8; 128],
    };
    let message_instance = Sha512MessageInstance {
        initial_state: INITIAL_STATE,
        message: b"abc".to_vec(),
    };
    let weak = Sha512ProofSettings {
        log_blowup: 2,
        log_final_poly_len: 3,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        rng_seed: 1,
    };

    assert!(prove_single_block_with_settings(block_instance, weak).is_err());
    assert!(prove_message_with_settings(&message_instance, weak).is_err());
}

#[test]
fn verify_with_settings_rejects_weak_policy() {
    let instance = Sha512SingleBlockInstance {
        initial_state: INITIAL_STATE,
        block: [0_u8; 128],
    };
    let proof = prove_single_block(instance).expect("prove");
    let weak = Sha512ProofSettings {
        log_blowup: 2,
        log_final_poly_len: 3,
        num_queries: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        rng_seed: 1,
    };
    assert!(!crate::verify_single_block_proof_with_settings(
        instance, &proof, weak
    ));
}

#[test]
fn prove_message_rejects_oversized_input() {
    let instance = Sha512MessageInstance {
        initial_state: INITIAL_STATE,
        message: vec![0_u8; (16 * 1024 * 1024) + 1],
    };
    let result = prove_message_with_settings(&instance, Sha512ProofSettings::default());
    assert!(result.is_err());
    let err = match result {
        Ok(_) => String::new(),
        Err(e) => e,
    };
    assert!(err.contains("size limit"));
}

#[test]
fn serialize_message_instance_rejects_oversized_input() {
    let instance = Sha512MessageInstance {
        initial_state: INITIAL_STATE,
        message: vec![0_u8; (16 * 1024 * 1024) + 1],
    };
    let err = serialize_message_instance(&instance).expect_err("should reject oversized message");
    assert!(err.contains("size limit"));
}

#[test]
fn seed32_private_api_roundtrip_and_verify() {
    let seed = [42_u8; 32];
    let bundle = prove_seed32_private(seed).expect("prove");
    assert!(verify_seed32_private_proof(&bundle));

    let bytes = serialize_seed32_private_proof(&bundle).expect("encode");
    let decoded = deserialize_seed32_private_proof(&bytes).expect("decode");
    assert_eq!(decoded.digest, bundle.digest);
    assert!(verify_seed32_private_proof(&decoded));
}

#[test]
fn seed32_private_api_rejects_tampered_instance() {
    let seed = [7_u8; 32];
    let mut bundle = prove_seed32_private(seed).expect("prove");
    bundle.sealed_instance[10] ^= 1;
    assert!(!verify_seed32_private_proof(&bundle));
}
