# sha512-circuit

A Plonky3 STARK circuit for SHA-512 block compression, written in Rust. Includes a full AIR constraint system, single-block and multi-block proof APIs, and serialization helpers.

## Overview

The library proves that a SHA-512 compression was computed correctly, without revealing the computation details beyond the public instance (initial state + message block) and the final working state.

- **Field**: BabyBear (2^31 − 2^27 + 1)
- **Polynomial commitment**: FRI over BabyBear with Keccak-256 Merkle trees
- **Trace size**: 128 rows × 1076 columns per 128-byte block
- **Proof size**: single message proof; grows with trace height (not one proof per block)

## Usage

### Single-block proof

```rust
use sha512_circuit::{
    Sha512SingleBlockInstance, prove_single_block, verify_single_block_proof,
    serialize_single_block_proof, deserialize_single_block_proof,
};

const INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

let instance = Sha512SingleBlockInstance {
    initial_state: INITIAL_STATE,
    block: [0u8; 128],
};

let proof = prove_single_block(instance).unwrap();
assert!(verify_single_block_proof(instance, &proof));

// Serialization
let bytes = serialize_single_block_proof(&proof).unwrap();
let proof2 = deserialize_single_block_proof(&bytes).unwrap();
```

### Multi-block (full message) proof

```rust
use sha512_circuit::{
    Sha512MessageInstance, prove_message, verify_message_proof,
};

const INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

let instance = Sha512MessageInstance {
    initial_state: INITIAL_STATE,
    message: b"hello world".to_vec(),
};

let proof = prove_message(&instance).unwrap();
assert!(verify_message_proof(&instance, &proof));

// The final hash digest is available without re-hashing:
let digest: [u8; 64] = proof.digest;
```

### Proof settings

```rust
use sha512_circuit::{Sha512ProofSettings, prove_single_block_with_settings};

let settings = Sha512ProofSettings {
    log_blowup: 3,
    log_final_poly_len: 4,  // larger = more security, larger proofs
    num_queries: 28,
    commit_proof_of_work_bits: 16,
    query_proof_of_work_bits: 16,
    rng_seed: 1,            // domain-separated transcript seed
};
let proof = prove_single_block_with_settings(instance, settings).unwrap();
```

Default rationale: `num_queries = 28` is chosen with `log_blowup = 3` and
`query_proof_of_work_bits = 16` to target roughly 100 bits of conjectured FRI
soundness (`3*28 + 16`). Treat this as a practical baseline, not a universal
production target.

## Architecture

### Trace layout (128 rows)

| Rows | Content |
|------|---------|
| 0–79 | SHA-512 compression rounds |
| 80 | Final working state `(a..h)` after round 80 |
| 81–127 | Padding rows (degenerate rounds, W=K=0) to reach 2^7 |

### Column layout (1076 columns per row)

| Range | Content |
|-------|---------|
| 0–63 | 16-bit limb decompositions (4 limbs × 16 words) |
| 64–79 | Carry columns for T1, T2, A, E additions (4 limbs each) |
| 80–143 | Lag limbs (4 limbs × 16 lags) |
| 144–147 | Schedule carries (4 limbs) |
| 148–531 | Bit decompositions: 64 bits × 6 words (A, B, C, E, F, G) |
| 532–659 | Lag sigma bits: 64 bits × {lag1, lag14} |
| 660–1043 | Range-proof bit columns: 16 bits × (D/H/W/K/T1/T2 limbs) |
| 1044–1075 | Carry-bit columns (minimal-width per carry type) |

### Preprocessed (instance-dependent) trace

A separate matrix of the same width (AIR_WIDTH), committed separately, used to bind:
- Initial state `(a..h)` on row 0
- Round constants `K[0..79]`
- Message words `W[0..15]` from the block
- Row-type selectors at the final five columns (block-start, transition, round, init-W, final)

## AIR Constraints

The constraint system enforces:

- **Round-state transitions**: `a' = T1 + T2`, `e' = d + T1`, and register shifts `b←a, c←b, …, h←g`
- **Round constants**: `K` column matches preprocessed `K[i]` values
- **Message words**: `W[0..15]` bound to the preprocessed instance; `W[16..79]` constrained by the schedule recurrence `W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16]`
- **Bitwise operations**: `Σ0(a)`, `Σ1(e)`, `Ch(e,f,g)`, `Maj(a,b,c)` computed bit-by-bit from bit-decomposed columns
- **Limb arithmetic**: 64-bit additions decomposed into four 16-bit limbs with explicit carry propagation
- **Range proofs**: D/H/W/K/T1/T2 limbs and carry columns are proven via bit decomposition + boolean assertions
- **Lag schedule inputs**: lag1 and lag14 are constrained by dedicated 64-bit Boolean decompositions used by the schedule σ functions
- **Public-value binding**: `(a..h)` at row 80 is bound to public values, linking the proof to the correct output state

## Public Values and Feed-Forward

The STARK proof's eight public values are `round_states[80]` — the working state **after** 80 rounds, **before** the SHA-512 feed-forward addition. The final hash output is:

```
output_state[i] = initial_state[i] + round_states[80][i]  (mod 2^64)
```

This addition is performed by the verifier (not inside the STARK). In the multi-block API, `verify_message_proof` handles this correctly and chains blocks via their output states.

## Known Limitations

- **Not audited.** This is a prototype and has not undergone a security review.
- **No audited security parameter policy.** The crate exposes full FRI controls (`log_blowup`, `log_final_poly_len`, `num_queries`, `commit_proof_of_work_bits`, `query_proof_of_work_bits`, `rng_seed`); production deployments should enforce verifier-owned policy.
- **No recursive proof composition.** Multi-block uses one message-level STARK proof, but there is no recursive aggregation layer.
- **Soundness depends on correct instance wiring by the caller.** The proof binds to `(initial_state, block)`; a caller that passes wrong instance values to the verifier will get incorrect results.

## CI

GitHub Actions runs:
- formatting check (`cargo fmt --check`)
- linting (`cargo clippy -D warnings`)
- tests (`cargo test --all-targets`)
- proof metrics benchmark artifact (`examples/proof_metrics.rs`)
