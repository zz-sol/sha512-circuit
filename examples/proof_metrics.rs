use std::array;
use std::time::Instant;

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use p3_uni_stark::{
    PreprocessedVerifierKey, Proof, StarkConfig, prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed,
};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use sha2::{Digest, Sha256};
use sha512_circuit::{Sha512Circuit, Sha512RoundAir};

const SHA512_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[derive(Clone, Copy)]
struct PublicInput {
    prefix8: [u8; 8],
    digest: [u8; 64],
}

#[derive(Clone)]
struct Sha256FieldHasher;

impl CryptographicHasher<BabyBear, [BabyBear; 8]> for Sha256FieldHasher {
    fn hash_iter<I>(&self, input: I) -> [BabyBear; 8]
    where
        I: IntoIterator<Item = BabyBear>,
    {
        let mut hasher = Sha256::new();
        for x in input {
            hasher.update(x.as_canonical_u32().to_le_bytes());
        }
        let digest = hasher.finalize();

        array::from_fn(|i| {
            let j = i * 4;
            let word = u32::from_le_bytes([digest[j], digest[j + 1], digest[j + 2], digest[j + 3]]);
            BabyBear::from_u32(word)
        })
    }
}

type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type MyHash = Sha256FieldHasher;
type MyCompress = CompressionFunctionFromHasher<MyHash, 2, 8>;
type ValMmcs = MerkleTreeMmcs<Val, Val, MyHash, MyCompress, 8>;
type Challenge = p3_field::extension::BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;
type StarkProof = Proof<Config>;
type PreVk = PreprocessedVerifierKey<Config>;

fn setup_config() -> Config {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = Sha256FieldHasher;
    let compress = MyCompress::new(hash.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = create_test_fri_params(challenge_mmcs, 2);
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    Config::new(pcs, challenger)
}

fn main() {
    let message: Vec<u8> = (0..256).map(|i| ((i * 17 + 23) & 0xff) as u8).collect();
    let public_input = PublicInput {
        prefix8: message[..8].try_into().expect("prefix length"),
        digest: Sha512Circuit::hash(&message),
    };

    let config = setup_config();
    let blocks = Sha512Circuit::padded_blocks(&message);

    let prove_start = Instant::now();
    let mut state = SHA512_IV;
    let mut proofs: Vec<StarkProof> = Vec::with_capacity(blocks.len());
    let mut vks: Vec<PreVk> = Vec::with_capacity(blocks.len());
    let mut total_circuit_size = 0_usize;
    let mut total_proof_size = 0_usize;

    for block in &blocks {
        let trace = Sha512Circuit::compress_block(&state, block);
        let main_trace = Sha512Circuit::build_plonky3_air_trace(&trace);
        let preprocessed =
            Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(&state, block);
        let air = Sha512RoundAir::new(preprocessed);
        let (prover_data, vk) =
            setup_preprocessed::<Config, _>(&config, &air, 7).expect("has preprocessed");

        let public_values = trace.round_states[80].map(BabyBear::from_u64);
        let proof = prove_with_preprocessed(
            &config,
            &air,
            main_trace.clone(),
            &public_values,
            Some(&prover_data),
        );

        total_circuit_size += main_trace.width() * main_trace.height();
        total_proof_size += bincode::serialize(&proof).expect("serialize proof").len();

        proofs.push(proof);
        vks.push(vk);
        state = trace.output_state;
    }
    let proving_time = prove_start.elapsed();

    let verify_start = Instant::now();

    if public_input.prefix8 != message[..8] {
        eprintln!("public prefix mismatch");
        std::process::exit(1);
    }

    let mut verify_state = SHA512_IV;
    for ((block, proof), vk) in blocks.iter().zip(&proofs).zip(&vks) {
        let trace = Sha512Circuit::compress_block(&verify_state, block);
        let preprocessed =
            Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(&verify_state, block);
        let air = Sha512RoundAir::new(preprocessed);
        let public_values = trace.round_states[80].map(BabyBear::from_u64);

        verify_with_preprocessed(&config, &air, proof, &public_values, Some(vk))
            .expect("proof verification must succeed");
        verify_state = trace.output_state;
    }

    let computed_digest = Sha512Circuit::state_to_digest(&verify_state);
    if computed_digest != public_input.digest {
        eprintln!("public digest mismatch");
        std::process::exit(1);
    }

    let verification_time = verify_start.elapsed();

    println!(
        "proving time: {:.3} ms",
        proving_time.as_secs_f64() * 1000.0
    );
    println!(
        "verification time: {:.3} ms",
        verification_time.as_secs_f64() * 1000.0
    );
    println!("circuit size: {}", total_circuit_size);
    println!("proof size: {} bytes", total_proof_size);
}
