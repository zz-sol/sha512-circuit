# sha512-circuit

A Rust SHA-512 trace/AIR prototype with Plonky3 integration, single-block and multi-block proof APIs, and serialization helpers.

## Security Model (Current)

The AIR enforces:
- round-state transitions (`a'`, `e'`, register shifts),
- per-round constants (`K`) binding,
- message word behavior:
  - first 16 `W` words bound to instance,
  - `W[16..79]` constrained by in-AIR schedule recurrence,
- intrinsic bitwise constraints for `Sigma0`, `Sigma1`, `ch`, and `maj`,
- limb/carry arithmetic constraints,
- 16-bit range constraints for limbs and carries via bit decomposition.
- public-value binding of the final compression working state (`a..h` at row 80).

The verifier path intended for correctness/soundness is:
- `Sha512Circuit::verify_plonky3_air_trace_with_instance`

## Important Assumptions / Remaining Gaps

- This is still a prototype and not audited.
- Soundness depends on correct public-instance wiring by the caller.
- No recursive proof composition is included.
- Performance/security parameter tuning for production is not finalized.

## CI

GitHub Actions runs:
- formatting check (`cargo fmt --check`),
- linting (`cargo clippy -D warnings`),
- tests (`cargo test --all-targets`),
- proof metrics benchmark artifact (`examples/proof_metrics.rs`).
