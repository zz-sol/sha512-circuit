use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use sha2::{Digest, Sha512};

use crate::air::{
    AIR_WIDTH_FOR_TESTS, LAG_BASE_FOR_TESTS, LIMB_BASE_FOR_TESTS, LIMBS_PER_WORD_FOR_TESTS,
    RANGE_BIT_BASE_FOR_TESTS, RANGE_BITS_PER_SOURCE_FOR_TESTS, SCHED_CARRY_BASE_FOR_TESTS,
    WORD_A_FOR_TESTS, WORD_E_FOR_TESTS, WORD_K_FOR_TESTS, WORD_SIGMA0_FOR_TESTS, WORD_T1_FOR_TESTS,
    WORD_W_FOR_TESTS,
};
use crate::constants::INITIAL_STATE;
use crate::sha512::Sha512Circuit;

#[test]
fn known_vector_empty_message() {
    let digest = Sha512Circuit::hash(b"");
    let expected = [
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80,
        0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c,
        0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87,
        0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
        0xf9, 0x27, 0xda, 0x3e,
    ];
    assert_eq!(digest, expected);
}

#[test]
fn known_vector_abc() {
    let digest = Sha512Circuit::hash(b"abc");
    let expected = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];
    assert_eq!(digest, expected);
}

#[test]
fn matches_sha2_reference_for_varied_lengths() {
    for len in [
        0_usize, 1, 3, 7, 16, 31, 63, 64, 65, 127, 128, 129, 255, 512, 1024,
    ] {
        let message = make_message(len);

        let ours = Sha512Circuit::hash(&message);
        let mut hasher = Sha512::new();
        hasher.update(&message);
        let expected: [u8; 64] = hasher.finalize().into();

        assert_eq!(ours, expected, "length {len}");
    }
}

#[test]
fn block_trace_is_valid() {
    let state = INITIAL_STATE;
    let block = [0_u8; 128];

    let trace = Sha512Circuit::compress_block(&state, &block);
    assert!(Sha512Circuit::verify_block_trace(&trace));
}

#[test]
fn tampered_trace_is_rejected() {
    let state = INITIAL_STATE;
    let block = [0_u8; 128];

    let mut trace = Sha512Circuit::compress_block(&state, &block);
    trace.words[23] ^= 1;

    assert!(!Sha512Circuit::verify_block_trace(&trace));
}

#[test]
fn plonky3_air_accepts_valid_trace() {
    let (state, block, air_trace) = make_air_trace_with_instance();

    assert!(Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_tampered_trace() {
    let (state, block, mut air_trace) = make_air_trace_with_instance();
    mutate_word(&mut air_trace, 1, WORD_A_FOR_TESTS, 123);
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_tampered_t1_column() {
    let (state, block, mut air_trace) = make_air_trace_with_instance();
    mutate_word(&mut air_trace, 0, WORD_T1_FOR_TESTS, 7);
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_tampered_k_column() {
    let (state, block, mut air_trace) = make_air_trace_with_instance();
    mutate_word(&mut air_trace, 7, WORD_K_FOR_TESTS, 1);
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_tampered_w_column() {
    let (state, block, mut air_trace) = make_air_trace_with_instance();
    mutate_word(&mut air_trace, 20, WORD_W_FOR_TESTS, 1);
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_wrong_trace_length() {
    let (_, _, air_trace) = make_air_trace_with_instance();
    let truncated = RowMajorMatrix::new(
        air_trace.values[..air_trace.values.len() - AIR_WIDTH_FOR_TESTS].to_vec(),
        AIR_WIDTH_FOR_TESTS,
    );

    let state = INITIAL_STATE;
    let block = [0_u8; 128];
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &truncated, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_tampered_sigma0_consistency() {
    let (state, block, mut air_trace) = make_air_trace_with_instance();
    mutate_word(&mut air_trace, 5, WORD_SIGMA0_FOR_TESTS, 9);
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_tampered_e_transition() {
    let (state, block, mut air_trace) = make_air_trace_with_instance();
    mutate_word(&mut air_trace, 1, WORD_E_FOR_TESTS, 77);
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_wrong_public_instance() {
    let (state, mut block, air_trace) = make_air_trace_with_instance();
    block[0] ^= 0x01;

    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_tampered_lag_column() {
    let (state, block, mut air_trace) = make_air_trace_with_instance();
    let row = 30;
    let base = row * AIR_WIDTH_FOR_TESTS;
    air_trace.values[base + LAG_BASE_FOR_TESTS + 3] += BabyBear::ONE;
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_tampered_schedule_carry() {
    let (state, block, mut air_trace) = make_air_trace_with_instance();
    let row = 40;
    let base = row * AIR_WIDTH_FOR_TESTS;
    air_trace.values[base + SCHED_CARRY_BASE_FOR_TESTS] += BabyBear::ONE;
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

#[test]
fn plonky3_air_rejects_tampered_range_bits_with_same_packed_values() {
    let (state, block, mut air_trace) = make_air_trace_with_instance();
    let row = 10;
    let source = 0;
    let bit = 0;
    let base = row * AIR_WIDTH_FOR_TESTS;
    let bit_col = RANGE_BIT_BASE_FOR_TESTS + source * RANGE_BITS_PER_SOURCE_FOR_TESTS + bit;
    air_trace.values[base + bit_col] += BabyBear::ONE;
    assert!(!Sha512Circuit::verify_plonky3_air_trace_with_instance(
        &air_trace, &state, &block
    ));
}

fn make_air_trace_with_instance() -> ([u64; 8], [u8; 128], RowMajorMatrix<BabyBear>) {
    let state = INITIAL_STATE;
    let block = [0_u8; 128];

    let trace = Sha512Circuit::compress_block(&state, &block);
    (state, block, Sha512Circuit::build_plonky3_air_trace(&trace))
}

fn mutate_word(trace: &mut RowMajorMatrix<BabyBear>, row: usize, word: usize, delta: u16) {
    let base = row * AIR_WIDTH_FOR_TESTS;
    let scalar = base + word;
    trace.values[scalar] += BabyBear::from_u16(delta);

    let limb0 = base + LIMB_BASE_FOR_TESTS + word * LIMBS_PER_WORD_FOR_TESTS;
    trace.values[limb0] += BabyBear::from_u16(delta);
}

fn make_message(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 37 + 11) & 0xff) as u8).collect()
}
