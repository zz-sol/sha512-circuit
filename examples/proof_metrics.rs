use std::time::Instant;

use sha512_circuit::{
    Sha512SingleBlockInstance, prove_single_block, serialize_single_block_proof,
    verify_single_block_proof,
};

fn main() {
    let instance = Sha512SingleBlockInstance {
        initial_state: [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ],
        block: [0_u8; 128],
    };

    let prove_start = Instant::now();
    let proof = prove_single_block(instance);
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let proof_bytes = serialize_single_block_proof(&proof);

    let verify_start = Instant::now();
    let ok = verify_single_block_proof(instance, &proof);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    println!(
        "{{\"prove_ms\":{prove_ms:.3},\"verify_ms\":{verify_ms:.3},\"proof_bytes\":{},\"verified\":{ok}}}",
        proof_bytes.len()
    );
}
