use std::time::Instant;

use sha512_circuit::{
    INITIAL_STATE, Sha512Circuit, Sha512MessageInstance, prove_message,
    serialize_multi_block_proof, verify_message_proof,
};

fn main() {
    let sizes = [32_usize, 64, 128, 256, 512, 1024];

    println!(
        "{:<10} {:>16} {:>20} {:>8} {:>8} {:>16} {:>16}",
        "input", "proving(ms)", "verification(ms)", "rows", "cols", "circuit size", "proof size"
    );
    println!("{}", "-".repeat(110));

    for size in sizes {
        let message: Vec<u8> = (0..size).map(|i| ((i * 17 + 23) & 0xff) as u8).collect();
        let instance = Sha512MessageInstance {
            initial_state: INITIAL_STATE,
            message: message.clone(),
        };

        let blocks = Sha512Circuit::padded_blocks(&message);
        let segment_count = blocks.len().next_power_of_two();
        let total_rows = segment_count * 128;
        let cols = 1076;

        let prove_start = Instant::now();
        let proof = prove_message(&instance);
        let proving_time = prove_start.elapsed();

        let verify_start = Instant::now();
        let ok = verify_message_proof(&instance, &proof);
        let verification_time = verify_start.elapsed();
        if !ok {
            eprintln!("proof verification failed");
            std::process::exit(1);
        }

        let expected_digest = Sha512Circuit::hash(&message);
        if proof.digest != expected_digest {
            eprintln!("digest mismatch");
            std::process::exit(1);
        }

        let proof_size = serialize_multi_block_proof(&proof).len();
        println!(
            "{:<10} {:>16.3} {:>20.3} {:>8} {:>8} {:>16} {:>16}",
            format!("{} B", size),
            proving_time.as_secs_f64() * 1000.0,
            verification_time.as_secs_f64() * 1000.0,
            total_rows,
            cols,
            total_rows * cols,
            format!("{} B", proof_size),
        );
    }
}
