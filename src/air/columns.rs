//! Column index constants and helper functions for the SHA-512 AIR trace.
//!
//! The main AIR trace has `AIR_WIDTH` columns per row.  This module defines a name for
//! every column (or column group) and provides accessor functions that compute the
//! concrete column index from logical identifiers (word index, limb index, bit index,
//! etc.).
//!
//! ## Column layout (in order)
//!
//! ```text
//! ┌─ Words ────────────────────────── cols 0 – 15 ─────────────────────────────────────┐
//! │  WORD_A..WORD_H  — working state (a, b, c, d, e, f, g, h)                          │
//! │  WORD_W          — current message schedule word                                    │
//! │  WORD_K          — round constant                                                   │
//! │  WORD_SIGMA0     — Σ0(a)                                                            │
//! │  WORD_SIGMA1     — Σ1(e)                                                            │
//! │  WORD_CH         — Ch(e, f, g)                                                      │
//! │  WORD_MAJ        — Maj(a, b, c)                                                     │
//! │  WORD_T1         — T1 = h + Σ1(e) + Ch + K + W                                     │
//! │  WORD_T2         — T2 = Σ0(a) + Maj(a, b, c)                                       │
//! ├─ Limbs ─────────────────────────────────────────────────────────────────────────────┤
//! │  16 words × 4 limbs (16-bit each) = 64 columns                                     │
//! ├─ Carries ───────────────────────────────────────────────────────────────────────────┤
//! │  Carry_T1 (4), Carry_T2 (4), Carry_A (4), Carry_E (4)  = 16 columns               │
//! ├─ Lags ──────────────────────────────────────────────────────────────────────────────┤
//! │  16 previous W values (ring buffer), stored as 4 limbs each = 64 columns            │
//! ├─ Schedule carries ──────────────────────────────────────────────────────────────────┤
//! │  4 carries for W recurrence = 4 columns                                            │
//! ├─ Bit decompositions ────────────────────────────────────────────────────────────────┤
//! │  64 bits × {A, B, C, E, F, G} = 384 columns                                        │
//! ├─ Range-proof bits ──────────────────────────────────────────────────────────────────┤
//! │  RANGE_SOURCES sources × 16 bits each (word + lag limbs)                           │
//! ├─ Carry bits ────────────────────────────────────────────────────────────────────────┤
//! │  Minimal-width carry bit decompositions (T1=3 bits, T2/A/E=1 bit, sched=2 bits)   │
//! ├─ Preprocessed columns (at the tail — shared with the preprocessed trace) ───────────┤
//! │  PREP_ROUND_SELECTOR_COL    — 1 in rounds 0..79, 0 elsewhere                       │
//! │  PREP_INIT_W_SELECTOR_COL   — 1 in rows 0..15, 0 elsewhere                         │
//! │  PREP_SCHEDULE_SELECTOR_COL — 1 in rows 16..79, 0 elsewhere                        │
//! │  PREP_FINAL_SELECTOR_COL    — 1 in row 80 only                                      │
//! └─────────────────────────────────────────────────────────────────────────────────────┘
//! ```

// ─── Trace dimensions ────────────────────────────────────────────────────────

/// Total number of rows in the AIR trace (must be a power of two).
///
/// Rows 0–79 are the 80 SHA-512 compression rounds.
/// Row 80 holds the post-round working state and the public value bindings.
/// Rows 81–127 are degenerate padding rows.
pub(super) const TRACE_ROWS: usize = 128;

/// First row index that is not a real SHA-512 round (row 80 = final state, rows 81+ = padding).
pub(super) const SHA_ROUNDS_PLUS_INIT: usize = 81;

// ─── Word columns (0–15) ─────────────────────────────────────────────────────

/// Working variable `a` — the new value of the `a` register after each round.
pub(super) const WORD_A: usize = 0;
/// Working variable `b` (equals previous round's `a`).
pub(super) const WORD_B: usize = 1;
/// Working variable `c` (equals previous round's `b`).
pub(super) const WORD_C: usize = 2;
/// Working variable `d` (equals previous round's `c`).
pub(super) const WORD_D: usize = 3;
/// Working variable `e` — the new value of the `e` register after each round.
pub(super) const WORD_E: usize = 4;
/// Working variable `f` (equals previous round's `e`).
pub(super) const WORD_F: usize = 5;
/// Working variable `g` (equals previous round's `f`).
pub(super) const WORD_G: usize = 6;
/// Working variable `h` (equals previous round's `g`).
pub(super) const WORD_H: usize = 7;
/// Current message schedule word W[i].
pub(super) const WORD_W: usize = 8;
/// Round constant K[i] (also present in the preprocessed trace).
pub(super) const WORD_K: usize = 9;
/// Σ0(a) — upper-case Sigma-0 of the `a` register.
pub(super) const WORD_SIGMA0: usize = 10;
/// Σ1(e) — upper-case Sigma-1 of the `e` register.
pub(super) const WORD_SIGMA1: usize = 11;
/// Ch(e, f, g) — choose function output.
pub(super) const WORD_CH: usize = 12;
/// Maj(a, b, c) — majority function output.
pub(super) const WORD_MAJ: usize = 13;
/// T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i] (mod 2⁶⁴).
pub(super) const WORD_T1: usize = 14;
/// T2 = Σ0(a) + Maj(a,b,c) (mod 2⁶⁴).
pub(super) const WORD_T2: usize = 15;
/// Total number of word columns.
pub(super) const WORD_COUNT: usize = 16;

// ─── Limb columns ────────────────────────────────────────────────────────────

/// Number of 16-bit limbs per 64-bit word.
pub(super) const LIMBS_PER_WORD: usize = 4;

/// First column of the limb section.
///
/// Limbs are stored as `LIMB_BASE + word * LIMBS_PER_WORD + limb` where `limb ∈ 0..4`
/// with limb 0 being the least significant 16 bits.  Use [`limb_col`] to compute.
pub(super) const LIMB_BASE: usize = WORD_COUNT;

// ─── Carry columns ───────────────────────────────────────────────────────────

/// First carry column for the T1 = h + Σ1(e) + Ch + K + W limb-wise addition.
///
/// Four consecutive columns, one per limb (least to most significant).
pub(super) const CARRY_T1_BASE: usize = LIMB_BASE + WORD_COUNT * LIMBS_PER_WORD;

/// First carry column for the T2 = Σ0(a) + Maj limb-wise addition.
pub(super) const CARRY_T2_BASE: usize = CARRY_T1_BASE + LIMBS_PER_WORD;

/// First carry column for the new-`a` addition: A = T1 + T2 (cross-row).
pub(super) const CARRY_A_BASE: usize = CARRY_T2_BASE + LIMBS_PER_WORD;

/// First carry column for the new-`e` addition: E = d + T1 (cross-row).
pub(super) const CARRY_E_BASE: usize = CARRY_A_BASE + LIMBS_PER_WORD;

// ─── Lag columns (message schedule history) ──────────────────────────────────

/// Number of previous W values tracked in the lag ring buffer.
///
/// The SHA-512 schedule recurrence references W[i−2], W[i−7], W[i−15], and W[i−16],
/// so the circuit needs to remember the last 16 W values.
pub(super) const LAG_COUNT: usize = 16;

/// First column of the lag-word limb section.
///
/// Each lag word is also decomposed into 4 × 16-bit limbs for range-proof purposes.
/// Use [`lag_limb_col`] to compute.
pub(super) const LAG_LIMB_BASE: usize = CARRY_E_BASE + LIMBS_PER_WORD;

// ─── Schedule carry columns ───────────────────────────────────────────────────

/// First carry column for the 4-operand message schedule recurrence addition.
///
/// The recurrence W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16] requires
/// four carry columns (one per 16-bit limb).
pub(super) const SCHED_CARRY_BASE: usize = LAG_LIMB_BASE + LAG_COUNT * LIMBS_PER_WORD;

// ─── Bit-decomposition columns ────────────────────────────────────────────────

/// First bit column for the Boolean decomposition of `a`.
pub(super) const BIT_A_BASE: usize = SCHED_CARRY_BASE + LIMBS_PER_WORD;
/// First bit column for the Boolean decomposition of `b`.
pub(super) const BIT_B_BASE: usize = BIT_A_BASE + 64;
/// First bit column for the Boolean decomposition of `c`.
pub(super) const BIT_C_BASE: usize = BIT_B_BASE + 64;
/// First bit column for the Boolean decomposition of `e`.
pub(super) const BIT_E_BASE: usize = BIT_C_BASE + 64;
/// First bit column for the Boolean decomposition of `f`.
pub(super) const BIT_F_BASE: usize = BIT_E_BASE + 64;
/// First bit column for the Boolean decomposition of `g`.
pub(super) const BIT_G_BASE: usize = BIT_F_BASE + 64;

// ─── Range-proof columns ─────────────────────────────────────────────────────

/// Number of 16-bit values that receive a range proof.
///
/// Sources: `WORD_COUNT * LIMBS_PER_WORD` (word limbs)
///        + `LAG_COUNT * LIMBS_PER_WORD`  (lag limbs).
pub(super) const RANGE_SOURCES: usize = (WORD_COUNT + LAG_COUNT) * LIMBS_PER_WORD;

/// Number of Boolean bits allocated per range-proof source (= 16, covering 0..65535).
pub(super) const RANGE_BITS_PER_SOURCE: usize = 16;

/// First column of the range-proof bit section.
pub(super) const RANGE_BIT_BASE: usize = BIT_G_BASE + 64;

/// First column of carry-bit decomposition section.
pub(super) const CARRY_BIT_BASE: usize = RANGE_BIT_BASE + RANGE_SOURCES * RANGE_BITS_PER_SOURCE;

/// First carry-bit column for T1 carry limbs (3 bits per limb).
pub(super) const CARRY_T1_BIT_BASE: usize = CARRY_BIT_BASE;
/// First carry-bit column for T2 carry limbs (1 bit per limb).
pub(super) const CARRY_T2_BIT_BASE: usize = CARRY_T1_BIT_BASE + LIMBS_PER_WORD * 3;
/// First carry-bit column for A carry limbs (1 bit per limb).
pub(super) const CARRY_A_BIT_BASE: usize = CARRY_T2_BIT_BASE + LIMBS_PER_WORD;
/// First carry-bit column for E carry limbs (1 bit per limb).
pub(super) const CARRY_E_BIT_BASE: usize = CARRY_A_BIT_BASE + LIMBS_PER_WORD;
/// First carry-bit column for schedule carry limbs (2 bits per limb).
pub(super) const CARRY_SCHED_BIT_BASE: usize = CARRY_E_BIT_BASE + LIMBS_PER_WORD;

/// Total number of columns in the AIR trace (main and preprocessed share the same width).
pub(super) const AIR_WIDTH: usize = CARRY_SCHED_BIT_BASE + LIMBS_PER_WORD * 2;

// ─── Preprocessed selector columns (at the tail of the shared column space) ──

/// Preprocessed selector: 1 for rows 0..79 (active SHA-512 rounds), 0 elsewhere.
///
/// Guards constraints that only apply during real compression rounds (e.g. Σ0/Σ1
/// bit decomposition checks, T1/T2 addition constraints).
pub(super) const PREP_ROUND_SELECTOR_COL: usize = AIR_WIDTH - 4;

/// Preprocessed selector: 1 for rows 0..15 (initial W words from the block), 0 elsewhere.
///
/// Binds the W column to the preprocessed W[0..15] values during the first 16 rows.
pub(super) const PREP_INIT_W_SELECTOR_COL: usize = AIR_WIDTH - 3;

/// Preprocessed selector: 1 for rows 16..79 (schedule recurrence), 0 elsewhere.
///
/// Enables the schedule recurrence constraint W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16].
pub(super) const PREP_SCHEDULE_SELECTOR_COL: usize = AIR_WIDTH - 2;

/// Preprocessed selector: 1 only on row 80 (final working state), 0 elsewhere.
///
/// Binds the 8 public values to the working-state columns on this row.
pub(super) const PREP_FINAL_SELECTOR_COL: usize = AIR_WIDTH - 1;

// ─── Index accessor functions ─────────────────────────────────────────────────

/// Returns the column index for `limb` (0–3, LSB first) of `word` (0–15).
pub(super) fn limb_col(word: usize, limb: usize) -> usize {
    LIMB_BASE + word * LIMBS_PER_WORD + limb
}

/// Returns the column index for `limb` (0–3) of lag word `lag`.
pub(super) fn lag_limb_col(lag: usize, limb: usize) -> usize {
    LAG_LIMB_BASE + lag * LIMBS_PER_WORD + limb
}

/// Returns the range-source index for limb `limb` of lag word `lag`.
///
/// Used by [`range_bit_col`] to map lag limbs into the range-proof bit section.
pub(super) fn lag_limb_range_source(lag: usize, limb: usize) -> usize {
    WORD_COUNT * LIMBS_PER_WORD + lag * LIMBS_PER_WORD + limb
}

/// Returns the **column** index of range-proof source `source`.
///
/// Maps logical source indices (word limbs → lag limbs → carry limbs) to the
/// concrete column that holds the 16-bit value being range-proved.  Used by the
/// constraint system to assert `source_col == Σ bit_col[source][k] * 2^k`.
pub(super) fn range_source_col(source: usize) -> usize {
    let word_limb_count = WORD_COUNT * LIMBS_PER_WORD;
    let lag_limb_count = LAG_COUNT * LIMBS_PER_WORD;
    if source < word_limb_count {
        LIMB_BASE + source
    } else if source < word_limb_count + lag_limb_count {
        LAG_LIMB_BASE + (source - word_limb_count)
    } else {
        unreachable!("range sources only include word and lag limbs");
    }
}

/// Returns the column index for bit `bit` (0 = LSB) of range-proof source `source`.
pub(super) fn range_bit_col(source: usize, bit: usize) -> usize {
    RANGE_BIT_BASE + source * RANGE_BITS_PER_SOURCE + bit
}

/// Returns the number of carry bits allocated for `carry_col`.
pub(super) fn carry_bit_width(carry_col: usize) -> usize {
    if (CARRY_T1_BASE..CARRY_T2_BASE).contains(&carry_col) {
        3
    } else if (CARRY_T2_BASE..LAG_LIMB_BASE).contains(&carry_col) {
        1
    } else if (SCHED_CARRY_BASE..BIT_A_BASE).contains(&carry_col) {
        2
    } else {
        unreachable!("carry_col is out of carry column ranges");
    }
}

/// Returns the carry-bit column index for bit `bit` of `carry_col`.
pub(super) fn carry_bit_col(carry_col: usize, bit: usize) -> usize {
    if (CARRY_T1_BASE..CARRY_T2_BASE).contains(&carry_col) {
        CARRY_T1_BIT_BASE + (carry_col - CARRY_T1_BASE) * 3 + bit
    } else if (CARRY_T2_BASE..CARRY_A_BASE).contains(&carry_col) {
        CARRY_T2_BIT_BASE + (carry_col - CARRY_T2_BASE) + bit
    } else if (CARRY_A_BASE..CARRY_E_BASE).contains(&carry_col) {
        CARRY_A_BIT_BASE + (carry_col - CARRY_A_BASE) + bit
    } else if (CARRY_E_BASE..LAG_LIMB_BASE).contains(&carry_col) {
        CARRY_E_BIT_BASE + (carry_col - CARRY_E_BASE) + bit
    } else if (SCHED_CARRY_BASE..BIT_A_BASE).contains(&carry_col) {
        CARRY_SCHED_BIT_BASE + (carry_col - SCHED_CARRY_BASE) * 2 + bit
    } else {
        unreachable!("carry_col is out of carry column ranges");
    }
}

// ─── Test re-exports ──────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) const AIR_WIDTH_FOR_TESTS: usize = AIR_WIDTH;
#[cfg(test)]
pub(crate) const WORD_T1_FOR_TESTS: usize = WORD_T1;
#[cfg(test)]
pub(crate) const WORD_W_FOR_TESTS: usize = WORD_W;
#[cfg(test)]
pub(crate) const WORD_K_FOR_TESTS: usize = WORD_K;
#[cfg(test)]
pub(crate) const WORD_SIGMA0_FOR_TESTS: usize = WORD_SIGMA0;
#[cfg(test)]
pub(crate) const WORD_A_FOR_TESTS: usize = WORD_A;
#[cfg(test)]
pub(crate) const WORD_E_FOR_TESTS: usize = WORD_E;
#[cfg(test)]
pub(crate) const LIMB_BASE_FOR_TESTS: usize = LIMB_BASE;
#[cfg(test)]
pub(crate) const LIMBS_PER_WORD_FOR_TESTS: usize = LIMBS_PER_WORD;
#[cfg(test)]
pub(crate) const LAG_LIMB_BASE_FOR_TESTS: usize = LAG_LIMB_BASE;
#[cfg(test)]
pub(crate) const SCHED_CARRY_BASE_FOR_TESTS: usize = SCHED_CARRY_BASE;
#[cfg(test)]
pub(crate) const RANGE_BIT_BASE_FOR_TESTS: usize = RANGE_BIT_BASE;
#[cfg(test)]
pub(crate) const RANGE_BITS_PER_SOURCE_FOR_TESTS: usize = RANGE_BITS_PER_SOURCE;
