# sha512-circuit

A Plonky3 STARK circuit for SHA-512 block compression, written in Rust. Includes a full AIR constraint system, single-block and multi-block proof APIs, and serialization helpers.

## Overview

The library proves that a SHA-512 compression was computed correctly, without revealing the computation details beyond the public instance (initial state + message block) and the final working state.

- **Field**: BabyBear (2^31 − 2^27 + 1)
- **Polynomial commitment**: FRI over BabyBear with Keccak256 Merkle trees
- **Trace size**: 128 rows × ~1280 columns per 128-byte block
- **Proof size**: ~200–400 KB per block (varies with FRI parameters)

## Usage

### Single-block proof

```rust
use sha512_circuit::{
    Sha512SingleBlockInstance, prove_single_block, verify_single_block_proof,
    serialize_single_block_proof, deserialize_single_block_proof,
};
use sha512_circuit::INITIAL_STATE;

let instance = Sha512SingleBlockInstance {
    initial_state: INITIAL_STATE,
    block: [0u8; 128],
};

let proof = prove_single_block(instance);
assert!(verify_single_block_proof(instance, &proof));

// Serialization
let bytes = serialize_single_block_proof(&proof);
let proof2 = deserialize_single_block_proof(&bytes).unwrap();
```

### Multi-block (full message) proof

```rust
use sha512_circuit::{
    Sha512MessageInstance, prove_message, verify_message_proof,
};
use sha512_circuit::INITIAL_STATE;

let instance = Sha512MessageInstance {
    initial_state: INITIAL_STATE,
    message: b"hello world".to_vec(),
};

let proof = prove_message(&instance);
assert!(verify_message_proof(&instance, &proof));

// The final hash digest is available without re-hashing:
let digest: [u8; 64] = proof.digest;
```

### Proof settings

```rust
use sha512_circuit::{Sha512ProofSettings, prove_single_block_with_settings};

let settings = Sha512ProofSettings {
    log_final_poly_len: 4,  // larger = more security, larger proofs
    rng_seed: 1,            // domain-separated transcript seed
};
let proof = prove_single_block_with_settings(instance, settings);
```

## Architecture

### Trace layout (128 rows)

| Rows | Content |
|------|---------|
| 0–79 | SHA-512 compression rounds |
| 80 | Final working state `(a..h)` after round 80 |
| 81–127 | Padding rows (degenerate rounds, W=K=0) to reach 2^7 |

### Column layout (~1280 columns per row)

| Range | Content |
|-------|---------|
| 0–15 | Main words: `a, b, c, d, e, f, g, h, W, K, Σ0, Σ1, Ch, Maj, T1, T2` |
| 16–79 | 16-bit limb decompositions (4 limbs × 16 words) |
| 80–95 | Carry columns for T1, T2, A, E additions (4 limbs each) |
| 96–111 | Lag words W[i−1] … W[i−16] |
| 112–175 | Lag limbs (4 limbs × 16 lags) |
| 176–179 | Schedule carries (4 limbs) |
| 180–819 | Bit decompositions: 64 bits × 10 words (A, B, C, E, F, G, Σ0, Σ1, Ch, Maj) |
| 820–… | Range-proof bit columns: 16 bits × (word limbs + lag limbs + carries) |

### Preprocessed (instance-dependent) trace

A separate matrix of the same width (AIR_WIDTH), committed separately, used to bind:
- Initial state `(a..h)` on row 0
- Round constants `K[0..79]`
- Message words `W[0..15]` from the block
- Row-type selectors at the final four columns (round, init-W, schedule, final)

## AIR Constraints

The constraint system enforces:

- **Round-state transitions**: `a' = T1 + T2`, `e' = d + T1`, and register shifts `b←a, c←b, …, h←g`
- **Round constants**: `K` column matches preprocessed `K[i]` values
- **Message words**: `W[0..15]` bound to the preprocessed instance; `W[16..79]` constrained by the schedule recurrence `W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16]`
- **Bitwise operations**: `Σ0(a)`, `Σ1(e)`, `Ch(e,f,g)`, `Maj(a,b,c)` computed bit-by-bit from bit-decomposed columns
- **Limb arithmetic**: 64-bit additions decomposed into four 16-bit limbs with explicit carry propagation
- **Range proofs**: all limbs and carries proven to be genuine 16-bit values via bit decomposition + boolean assertions
- **Public-value binding**: `(a..h)` at row 80 is bound to public values, linking the proof to the correct output state

## Public Values and Feed-Forward

The STARK proof's eight public values are `round_states[80]` — the working state **after** 80 rounds, **before** the SHA-512 feed-forward addition. The final hash output is:

```
output_state[i] = initial_state[i] + round_states[80][i]  (mod 2^64)
```

This addition is performed by the verifier (not inside the STARK). In the multi-block API, `verify_message_proof` handles this correctly and chains blocks via their output states.

## Known Limitations

- **Not audited.** This is a prototype and has not undergone a security review.
- **Test-grade FRI parameters by default.** The default `log_final_poly_len: 2` provides minimal concrete security. Production use requires tuning `Sha512ProofSettings` with appropriate blowup factor and query count, using non-test FRI setup.
- **No recursive proof composition.** Multi-block proofs are a flat list of independent single-block proofs; proof size scales linearly with the number of blocks.
- **Soundness depends on correct instance wiring by the caller.** The proof binds to `(initial_state, block)`; a caller that passes wrong instance values to the verifier will get incorrect results.

## CI

GitHub Actions runs:
- formatting check (`cargo fmt --check`)
- linting (`cargo clippy -D warnings`)
- tests (`cargo test --all-targets`)
- proof metrics benchmark artifact (`examples/proof_metrics.rs`)
