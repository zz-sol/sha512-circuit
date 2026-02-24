pub(super) const TRACE_ROWS: usize = 128;
pub(super) const SHA_ROUNDS_PLUS_INIT: usize = 81;

pub(super) const WORD_A: usize = 0;
pub(super) const WORD_B: usize = 1;
pub(super) const WORD_C: usize = 2;
pub(super) const WORD_D: usize = 3;
pub(super) const WORD_E: usize = 4;
pub(super) const WORD_F: usize = 5;
pub(super) const WORD_G: usize = 6;
pub(super) const WORD_H: usize = 7;
pub(super) const WORD_W: usize = 8;
pub(super) const WORD_K: usize = 9;
pub(super) const WORD_SIGMA0: usize = 10;
pub(super) const WORD_SIGMA1: usize = 11;
pub(super) const WORD_CH: usize = 12;
pub(super) const WORD_MAJ: usize = 13;
pub(super) const WORD_T1: usize = 14;
pub(super) const WORD_T2: usize = 15;
pub(super) const WORD_COUNT: usize = 16;

pub(super) const LIMBS_PER_WORD: usize = 4;
pub(super) const LIMB_BASE: usize = WORD_COUNT;
pub(super) const CARRY_T1_BASE: usize = LIMB_BASE + WORD_COUNT * LIMBS_PER_WORD;
pub(super) const CARRY_T2_BASE: usize = CARRY_T1_BASE + LIMBS_PER_WORD;
pub(super) const CARRY_A_BASE: usize = CARRY_T2_BASE + LIMBS_PER_WORD;
pub(super) const CARRY_E_BASE: usize = CARRY_A_BASE + LIMBS_PER_WORD;
pub(super) const LAG_COUNT: usize = 16;
pub(super) const LAG_BASE: usize = CARRY_E_BASE + LIMBS_PER_WORD;
pub(super) const LAG_LIMB_BASE: usize = LAG_BASE + LAG_COUNT;
pub(super) const SCHED_CARRY_BASE: usize = LAG_LIMB_BASE + LAG_COUNT * LIMBS_PER_WORD;
pub(super) const BIT_A_BASE: usize = SCHED_CARRY_BASE + LIMBS_PER_WORD;
pub(super) const BIT_B_BASE: usize = BIT_A_BASE + 64;
pub(super) const BIT_C_BASE: usize = BIT_B_BASE + 64;
pub(super) const BIT_E_BASE: usize = BIT_C_BASE + 64;
pub(super) const BIT_F_BASE: usize = BIT_E_BASE + 64;
pub(super) const BIT_G_BASE: usize = BIT_F_BASE + 64;
pub(super) const BIT_SIGMA0_BASE: usize = BIT_G_BASE + 64;
pub(super) const BIT_SIGMA1_BASE: usize = BIT_SIGMA0_BASE + 64;
pub(super) const BIT_CH_BASE: usize = BIT_SIGMA1_BASE + 64;
pub(super) const BIT_MAJ_BASE: usize = BIT_CH_BASE + 64;
pub(super) const RANGE_SOURCES: usize =
    (WORD_COUNT + LAG_COUNT) * LIMBS_PER_WORD + LIMBS_PER_WORD * 5;
pub(super) const RANGE_BITS_PER_SOURCE: usize = 16;
pub(super) const RANGE_BIT_BASE: usize = BIT_MAJ_BASE + 64;
pub(super) const AIR_WIDTH: usize = RANGE_BIT_BASE + RANGE_SOURCES * RANGE_BITS_PER_SOURCE;
pub(super) const PREP_ROUND_SELECTOR_COL: usize = AIR_WIDTH - 4;
pub(super) const PREP_INIT_W_SELECTOR_COL: usize = AIR_WIDTH - 3;
pub(super) const PREP_SCHEDULE_SELECTOR_COL: usize = AIR_WIDTH - 2;
pub(super) const PREP_FINAL_SELECTOR_COL: usize = AIR_WIDTH - 1;

pub(super) fn limb_col(word: usize, limb: usize) -> usize {
    LIMB_BASE + word * LIMBS_PER_WORD + limb
}

pub(super) fn lag_col(lag: usize) -> usize {
    LAG_BASE + lag
}

pub(super) fn lag_limb_col(lag: usize, limb: usize) -> usize {
    LAG_LIMB_BASE + lag * LIMBS_PER_WORD + limb
}

pub(super) fn lag_limb_range_source(lag: usize, limb: usize) -> usize {
    WORD_COUNT * LIMBS_PER_WORD + lag * LIMBS_PER_WORD + limb
}

pub(super) fn range_source_col(source: usize) -> usize {
    let word_limb_count = WORD_COUNT * LIMBS_PER_WORD;
    let lag_limb_count = LAG_COUNT * LIMBS_PER_WORD;
    if source < word_limb_count {
        LIMB_BASE + source
    } else if source < word_limb_count + lag_limb_count {
        LAG_LIMB_BASE + (source - word_limb_count)
    } else {
        let carry_offset = source - word_limb_count - lag_limb_count;
        if carry_offset < 4 * LIMBS_PER_WORD {
            CARRY_T1_BASE + carry_offset
        } else {
            SCHED_CARRY_BASE + (carry_offset - 4 * LIMBS_PER_WORD)
        }
    }
}

pub(super) fn range_bit_col(source: usize, bit: usize) -> usize {
    RANGE_BIT_BASE + source * RANGE_BITS_PER_SOURCE + bit
}

pub(super) fn carry_range_source(carry_col: usize) -> usize {
    let word_limb_count = WORD_COUNT * LIMBS_PER_WORD;
    let lag_limb_count = LAG_COUNT * LIMBS_PER_WORD;
    let carry_offset = if (CARRY_T1_BASE..CARRY_T2_BASE).contains(&carry_col) {
        carry_col - CARRY_T1_BASE
    } else if (CARRY_T2_BASE..CARRY_A_BASE).contains(&carry_col) {
        LIMBS_PER_WORD + (carry_col - CARRY_T2_BASE)
    } else if (CARRY_A_BASE..CARRY_E_BASE).contains(&carry_col) {
        2 * LIMBS_PER_WORD + (carry_col - CARRY_A_BASE)
    } else if (CARRY_E_BASE..LAG_BASE).contains(&carry_col) {
        3 * LIMBS_PER_WORD + (carry_col - CARRY_E_BASE)
    } else if (SCHED_CARRY_BASE..BIT_A_BASE).contains(&carry_col) {
        4 * LIMBS_PER_WORD + (carry_col - SCHED_CARRY_BASE)
    } else {
        unreachable!("carry_col is out of carry column ranges");
    };
    word_limb_count + lag_limb_count + carry_offset
}

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
pub(crate) const LAG_BASE_FOR_TESTS: usize = LAG_BASE;
#[cfg(test)]
pub(crate) const SCHED_CARRY_BASE_FOR_TESTS: usize = SCHED_CARRY_BASE;
#[cfg(test)]
pub(crate) const RANGE_BIT_BASE_FOR_TESTS: usize = RANGE_BIT_BASE;
#[cfg(test)]
pub(crate) const RANGE_BITS_PER_SOURCE_FOR_TESTS: usize = RANGE_BITS_PER_SOURCE;
