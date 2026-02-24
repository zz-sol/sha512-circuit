use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use crate::constants::K;
use crate::ops::{bb, big_sigma0, big_sigma1, ch, maj, small_sigma0, small_sigma1};
use crate::sha512::Sha512Circuit;
use crate::trace::BlockTrace;

const TRACE_ROWS: usize = 128;
const SHA_ROUNDS_PLUS_INIT: usize = 81;

const WORD_A: usize = 0;
const WORD_B: usize = 1;
const WORD_C: usize = 2;
const WORD_D: usize = 3;
const WORD_E: usize = 4;
const WORD_F: usize = 5;
const WORD_G: usize = 6;
const WORD_H: usize = 7;
const WORD_W: usize = 8;
const WORD_K: usize = 9;
const WORD_SIGMA0: usize = 10;
const WORD_SIGMA1: usize = 11;
const WORD_CH: usize = 12;
const WORD_MAJ: usize = 13;
const WORD_T1: usize = 14;
const WORD_T2: usize = 15;
const WORD_COUNT: usize = 16;
const PREP_ROUND_SELECTOR_COL: usize = WORD_T1;
const PREP_INIT_W_SELECTOR_COL: usize = WORD_T2;
const PREP_SCHEDULE_SELECTOR_COL: usize = WORD_SIGMA0;

const LIMBS_PER_WORD: usize = 4;
const LIMB_BASE: usize = WORD_COUNT;
const CARRY_T1_BASE: usize = LIMB_BASE + WORD_COUNT * LIMBS_PER_WORD;
const CARRY_T2_BASE: usize = CARRY_T1_BASE + LIMBS_PER_WORD;
const CARRY_A_BASE: usize = CARRY_T2_BASE + LIMBS_PER_WORD;
const CARRY_E_BASE: usize = CARRY_A_BASE + LIMBS_PER_WORD;
const LAG_COUNT: usize = 16;
const LAG_BASE: usize = CARRY_E_BASE + LIMBS_PER_WORD;
const LAG_LIMB_BASE: usize = LAG_BASE + LAG_COUNT;
const SCHED_CARRY_BASE: usize = LAG_LIMB_BASE + LAG_COUNT * LIMBS_PER_WORD;
const BIT_A_BASE: usize = SCHED_CARRY_BASE + LIMBS_PER_WORD;
const BIT_B_BASE: usize = BIT_A_BASE + 64;
const BIT_C_BASE: usize = BIT_B_BASE + 64;
const BIT_E_BASE: usize = BIT_C_BASE + 64;
const BIT_F_BASE: usize = BIT_E_BASE + 64;
const BIT_G_BASE: usize = BIT_F_BASE + 64;
const BIT_SIGMA0_BASE: usize = BIT_G_BASE + 64;
const BIT_SIGMA1_BASE: usize = BIT_SIGMA0_BASE + 64;
const BIT_CH_BASE: usize = BIT_SIGMA1_BASE + 64;
const BIT_MAJ_BASE: usize = BIT_CH_BASE + 64;
const RANGE_SOURCES: usize = (WORD_COUNT + LAG_COUNT) * LIMBS_PER_WORD + LIMBS_PER_WORD * 5;
const RANGE_BITS_PER_SOURCE: usize = 16;
const RANGE_BIT_BASE: usize = BIT_MAJ_BASE + 64;
const AIR_WIDTH: usize = RANGE_BIT_BASE + RANGE_SOURCES * RANGE_BITS_PER_SOURCE;

#[derive(Clone, Debug)]
pub struct Sha512RoundAir {
    preprocessed: RowMajorMatrix<BabyBear>,
}

impl Sha512RoundAir {
    pub(crate) fn new(preprocessed: RowMajorMatrix<BabyBear>) -> Self {
        Self { preprocessed }
    }
}

impl BaseAir<BabyBear> for Sha512RoundAir {
    fn width(&self) -> usize {
        AIR_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BabyBear>> {
        Some(self.preprocessed.clone())
    }
}

impl<AB> Air<AB> for Sha512RoundAir
where
    AB: AirBuilder<F = BabyBear> + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let prep = builder.preprocessed();
        let local = main.row_slice(0).expect("window has local row");
        let next = main.row_slice(1).expect("window has next row");
        let local_prep = prep
            .row_slice(0)
            .expect("window has local preprocessed row");

        builder.assert_eq(local[WORD_K].clone(), local_prep[WORD_K].clone());
        builder.assert_zero(
            local_prep[PREP_INIT_W_SELECTOR_COL].clone()
                * (local[WORD_W].clone() - local_prep[WORD_W].clone()),
        );
        builder.assert_zero(
            (AB::Expr::ONE - local_prep[PREP_ROUND_SELECTOR_COL].clone()) * local[WORD_W].clone(),
        );

        for col in WORD_A..=WORD_H {
            builder
                .when_first_row()
                .assert_eq(local[col].clone(), local_prep[col].clone());
        }

        let two16 = BabyBear::from_u32(1 << 16);
        let two32 = BabyBear::from_u64(1_u64 << 32);
        let two48 = BabyBear::from_u64(1_u64 << 48);

        for word in 0..WORD_COUNT {
            let packed = local[limb_col(word, 0)].clone()
                + local[limb_col(word, 1)].clone() * two16
                + local[limb_col(word, 2)].clone() * two32
                + local[limb_col(word, 3)].clone() * two48;
            builder.assert_eq(local[word].clone(), packed);
        }

        for (word, base) in [
            (WORD_A, BIT_A_BASE),
            (WORD_B, BIT_B_BASE),
            (WORD_C, BIT_C_BASE),
            (WORD_E, BIT_E_BASE),
            (WORD_F, BIT_F_BASE),
            (WORD_G, BIT_G_BASE),
            (WORD_SIGMA0, BIT_SIGMA0_BASE),
            (WORD_SIGMA1, BIT_SIGMA1_BASE),
            (WORD_CH, BIT_CH_BASE),
            (WORD_MAJ, BIT_MAJ_BASE),
        ] {
            for bit in 0..64 {
                builder.assert_bool(local[base + bit].clone());
            }
            builder.assert_eq(local[word].clone(), pack_bits::<AB>(&local, base));
        }

        for bit in 0..64 {
            let a = local[BIT_A_BASE + bit].clone();
            let b = local[BIT_B_BASE + bit].clone();
            let c = local[BIT_C_BASE + bit].clone();
            let e = local[BIT_E_BASE + bit].clone();
            let f = local[BIT_F_BASE + bit].clone();
            let g = local[BIT_G_BASE + bit].clone();
            let round_sel = local_prep[PREP_ROUND_SELECTOR_COL].clone();

            let sigma0 = xor3_expr::<AB>(
                local[BIT_A_BASE + ((bit + 28) % 64)].clone().into(),
                local[BIT_A_BASE + ((bit + 34) % 64)].clone().into(),
                local[BIT_A_BASE + ((bit + 39) % 64)].clone().into(),
            );
            builder
                .assert_zero(round_sel.clone() * (local[BIT_SIGMA0_BASE + bit].clone() - sigma0));

            let sigma1 = xor3_expr::<AB>(
                local[BIT_E_BASE + ((bit + 14) % 64)].clone().into(),
                local[BIT_E_BASE + ((bit + 18) % 64)].clone().into(),
                local[BIT_E_BASE + ((bit + 41) % 64)].clone().into(),
            );
            builder
                .assert_zero(round_sel.clone() * (local[BIT_SIGMA1_BASE + bit].clone() - sigma1));

            let ch_expr = e.clone() * f.clone() + (AB::Expr::ONE - e) * g.clone();
            builder.assert_zero(round_sel.clone() * (local[BIT_CH_BASE + bit].clone() - ch_expr));

            let ab = a.clone() * b.clone();
            let ac = a.clone() * c.clone();
            let bc = b.clone() * c.clone();
            let abc = a * b * c;
            let maj_expr = ab + ac + bc - abc * BabyBear::TWO;
            builder.assert_zero(round_sel.clone() * (local[BIT_MAJ_BASE + bit].clone() - maj_expr));
        }

        for lag in 0..LAG_COUNT {
            let packed = local[lag_limb_col(lag, 0)].clone()
                + local[lag_limb_col(lag, 1)].clone() * two16
                + local[lag_limb_col(lag, 2)].clone() * two32
                + local[lag_limb_col(lag, 3)].clone() * two48;
            builder.assert_eq(local[lag_col(lag)].clone(), packed);
        }

        for src in 0..RANGE_SOURCES {
            let mut packed = AB::Expr::ZERO;
            for bit in 0..RANGE_BITS_PER_SOURCE {
                let b = local[range_bit_col(src, bit)].clone();
                builder.assert_bool(b.clone());
                packed += b * BabyBear::from_u32(1 << bit);
            }
            builder.assert_eq(local[range_source_col(src)].clone(), packed);
        }

        let mut transition = builder.when_transition();
        constrain_add_5_limbs(
            &mut transition,
            &local,
            [WORD_H, WORD_SIGMA1, WORD_CH, WORD_K, WORD_W],
            WORD_T1,
            CARRY_T1_BASE,
        );
        constrain_add_2_limbs(
            &mut transition,
            &local,
            WORD_SIGMA0,
            WORD_MAJ,
            WORD_T2,
            CARRY_T2_BASE,
        );
        constrain_add_2_limbs_across_rows(
            &mut transition,
            &local,
            &next,
            WORD_T1,
            WORD_T2,
            WORD_A,
            CARRY_A_BASE,
        );
        constrain_add_2_limbs_across_rows(
            &mut transition,
            &local,
            &next,
            WORD_D,
            WORD_T1,
            WORD_E,
            CARRY_E_BASE,
        );

        for limb in 0..LIMBS_PER_WORD {
            transition.assert_eq(
                next[limb_col(WORD_B, limb)].clone(),
                local[limb_col(WORD_A, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_C, limb)].clone(),
                local[limb_col(WORD_B, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_D, limb)].clone(),
                local[limb_col(WORD_C, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_F, limb)].clone(),
                local[limb_col(WORD_E, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_G, limb)].clone(),
                local[limb_col(WORD_F, limb)].clone(),
            );
            transition.assert_eq(
                next[limb_col(WORD_H, limb)].clone(),
                local[limb_col(WORD_G, limb)].clone(),
            );
        }

        transition.assert_eq(next[lag_col(0)].clone(), local[WORD_W].clone());
        for lag in 1..LAG_COUNT {
            transition.assert_eq(next[lag_col(lag)].clone(), local[lag_col(lag - 1)].clone());
        }
        for lag in 0..LAG_COUNT {
            for limb in 0..LIMBS_PER_WORD {
                let expected = if lag == 0 {
                    local[limb_col(WORD_W, limb)].clone()
                } else {
                    local[lag_limb_col(lag - 1, limb)].clone()
                };
                transition.assert_eq(next[lag_limb_col(lag, limb)].clone(), expected);
            }
        }

        let sched_sel = local_prep[PREP_SCHEDULE_SELECTOR_COL].clone();
        constrain_schedule_recurrence(&mut transition, &local, sched_sel);

        let mut last = builder.when_last_row();
        for word in WORD_W..WORD_COUNT {
            last.assert_eq(local[word].clone(), BabyBear::ZERO);
            for limb in 0..LIMBS_PER_WORD {
                last.assert_eq(local[limb_col(word, limb)].clone(), BabyBear::ZERO);
            }
        }
        for col in CARRY_T1_BASE..BIT_A_BASE {
            last.assert_eq(local[col].clone(), BabyBear::ZERO);
        }
    }
}

fn constrain_add_5_limbs<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    row: &[AB::Var],
    ops: [usize; 5],
    out: usize,
    carry_base: usize,
) {
    let two16 = BabyBear::from_u32(1 << 16);
    let mut carry_in = AB::Expr::ZERO;

    for limb in 0..LIMBS_PER_WORD {
        let carry_out = row[carry_base + limb].clone();
        let sum = row[limb_col(ops[0], limb)].clone()
            + row[limb_col(ops[1], limb)].clone()
            + row[limb_col(ops[2], limb)].clone()
            + row[limb_col(ops[3], limb)].clone()
            + row[limb_col(ops[4], limb)].clone()
            + carry_in;
        let rhs = row[limb_col(out, limb)].clone() + carry_out.clone() * two16;
        builder.assert_eq(sum, rhs);
        carry_in = carry_out.into();
    }
}

fn constrain_add_2_limbs<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    row: &[AB::Var],
    lhs: usize,
    rhs: usize,
    out: usize,
    carry_base: usize,
) {
    let two16 = BabyBear::from_u32(1 << 16);
    let mut carry_in = AB::Expr::ZERO;

    for limb in 0..LIMBS_PER_WORD {
        let carry_out = row[carry_base + limb].clone();
        let sum = row[limb_col(lhs, limb)].clone() + row[limb_col(rhs, limb)].clone() + carry_in;
        let expected = row[limb_col(out, limb)].clone() + carry_out.clone() * two16;
        builder.assert_eq(sum, expected);
        carry_in = carry_out.into();
    }
}

fn constrain_add_2_limbs_across_rows<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    lhs: usize,
    rhs: usize,
    out_next: usize,
    carry_base: usize,
) {
    let two16 = BabyBear::from_u32(1 << 16);
    let mut carry_in = AB::Expr::ZERO;

    for limb in 0..LIMBS_PER_WORD {
        let carry_out = local[carry_base + limb].clone();
        let sum =
            local[limb_col(lhs, limb)].clone() + local[limb_col(rhs, limb)].clone() + carry_in;
        let expected = next[limb_col(out_next, limb)].clone() + carry_out.clone() * two16;
        builder.assert_eq(sum, expected);
        carry_in = carry_out.into();
    }
}

fn constrain_schedule_recurrence<B: AirBuilder<F = BabyBear>>(
    builder: &mut B,
    row: &[B::Var],
    selector: B::Var,
) {
    let two16 = BabyBear::from_u32(1 << 16);
    let mut carry_in = B::Expr::ZERO;

    for limb in 0..LIMBS_PER_WORD {
        let sigma1_limb = pack_small_sigma1_limb::<B>(row, limb);
        let sigma0_limb = pack_small_sigma0_limb::<B>(row, limb);
        let lag7_limb = row[lag_limb_col(6, limb)].clone();
        let lag16_limb = row[lag_limb_col(15, limb)].clone();
        let carry_out = row[SCHED_CARRY_BASE + limb].clone();

        let sum = sigma1_limb + lag7_limb + sigma0_limb + lag16_limb + carry_in;
        let expected = row[limb_col(WORD_W, limb)].clone() + carry_out.clone() * two16;
        builder.assert_zero(selector.clone() * (sum - expected));
        carry_in = carry_out.into();
    }
}

fn pack_small_sigma0_limb<B: AirBuilder<F = BabyBear>>(row: &[B::Var], limb: usize) -> B::Expr {
    let mut out = B::Expr::ZERO;
    for bit in 0..16 {
        let b = small_sigma0_bit::<B>(row, limb * 16 + bit);
        out += b * BabyBear::from_u32(1 << bit);
    }
    out
}

fn pack_small_sigma1_limb<B: AirBuilder<F = BabyBear>>(row: &[B::Var], limb: usize) -> B::Expr {
    let mut out = B::Expr::ZERO;
    for bit in 0..16 {
        let b = small_sigma1_bit::<B>(row, limb * 16 + bit);
        out += b * BabyBear::from_u32(1 << bit);
    }
    out
}

fn small_sigma0_bit<B: AirBuilder<F = BabyBear>>(row: &[B::Var], bit: usize) -> B::Expr {
    xor3_expr::<B>(
        lag_bit_expr::<B>(row, 14, (bit + 1) % 64),
        lag_bit_expr::<B>(row, 14, (bit + 8) % 64),
        if bit + 7 < 64 {
            lag_bit_expr::<B>(row, 14, bit + 7)
        } else {
            B::Expr::ZERO
        },
    )
}

fn small_sigma1_bit<B: AirBuilder<F = BabyBear>>(row: &[B::Var], bit: usize) -> B::Expr {
    xor3_expr::<B>(
        lag_bit_expr::<B>(row, 1, (bit + 19) % 64),
        lag_bit_expr::<B>(row, 1, (bit + 61) % 64),
        if bit + 6 < 64 {
            lag_bit_expr::<B>(row, 1, bit + 6)
        } else {
            B::Expr::ZERO
        },
    )
}

fn lag_bit_expr<B: AirBuilder<F = BabyBear>>(row: &[B::Var], lag: usize, bit: usize) -> B::Expr {
    let limb = bit / 16;
    let offset = bit % 16;
    let src = lag_limb_range_source(lag, limb);
    row[range_bit_col(src, offset)].clone().into()
}

fn pack_bits<AB: AirBuilder<F = BabyBear>>(row: &[AB::Var], bit_base: usize) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    for i in (0..64).rev() {
        acc = acc * BabyBear::TWO + row[bit_base + i].clone();
    }
    acc
}

fn xor2_expr<AB: AirBuilder<F = BabyBear>>(x: AB::Expr, y: AB::Expr) -> AB::Expr {
    x.clone() + y.clone() - (x * y) * BabyBear::TWO
}

fn xor3_expr<AB: AirBuilder<F = BabyBear>>(x: AB::Expr, y: AB::Expr, z: AB::Expr) -> AB::Expr {
    xor2_expr::<AB>(xor2_expr::<AB>(x, y), z)
}

#[derive(Clone)]
struct AirConstraintChecker {
    main: RowMajorMatrix<BabyBear>,
    preprocessed: RowMajorMatrix<BabyBear>,
    is_first: BabyBear,
    is_last: BabyBear,
    is_transition: BabyBear,
    violated: bool,
}

impl AirConstraintChecker {
    fn new(
        main: RowMajorMatrix<BabyBear>,
        preprocessed: RowMajorMatrix<BabyBear>,
        is_first: bool,
        is_last: bool,
    ) -> Self {
        Self {
            main,
            preprocessed,
            is_first: BabyBear::from_bool(is_first),
            is_last: BabyBear::from_bool(is_last),
            is_transition: BabyBear::from_bool(!is_last),
            violated: false,
        }
    }
}

impl AirBuilder for AirConstraintChecker {
    type F = BabyBear;
    type Expr = BabyBear;
    type Var = BabyBear;
    type M = RowMajorMatrix<BabyBear>;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size <= 2 {
            self.is_transition
        } else {
            BabyBear::ZERO
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        if x.into() != BabyBear::ZERO {
            self.violated = true;
        }
    }
}

impl PairBuilder for AirConstraintChecker {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

impl Sha512Circuit {
    pub fn build_plonky3_preprocessed_trace_from_instance(
        initial_state: &[u64; 8],
        block: &[u8; 128],
    ) -> RowMajorMatrix<BabyBear> {
        let trace = Sha512Circuit::compress_block(initial_state, block);
        let full = Sha512Circuit::build_plonky3_air_trace(&trace);
        let mut values = vec![BabyBear::ZERO; TRACE_ROWS * AIR_WIDTH];

        for row in 0..TRACE_ROWS {
            let src = full.row_slice(row).expect("row exists");
            let dst = &mut values[row * AIR_WIDTH..(row + 1) * AIR_WIDTH];
            dst[WORD_W] = src[WORD_W];
            dst[WORD_K] = src[WORD_K];
            dst[PREP_ROUND_SELECTOR_COL] = BabyBear::from_bool(row < 80);
            dst[PREP_INIT_W_SELECTOR_COL] = BabyBear::from_bool(row < 16);
            dst[PREP_SCHEDULE_SELECTOR_COL] = BabyBear::from_bool((16..80).contains(&row));
        }

        let first = &mut values[..AIR_WIDTH];
        for (i, word) in initial_state.iter().enumerate() {
            first[i] = bb(*word);
        }

        RowMajorMatrix::new(values, AIR_WIDTH)
    }

    pub fn build_plonky3_air_trace(trace: &BlockTrace) -> RowMajorMatrix<BabyBear> {
        let mut values = Vec::with_capacity(TRACE_ROWS * AIR_WIDTH);
        let mut lags = [0_u64; LAG_COUNT];

        for (i, &constant) in K.iter().enumerate() {
            let s = trace.round_states[i];
            let word = trace.words[i];
            let sigma0 = big_sigma0(s[0]);
            let sigma1 = big_sigma1(s[4]);
            let choose = ch(s[4], s[5], s[6]);
            let majority = maj(s[0], s[1], s[2]);
            let t1 = s[7]
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(constant)
                .wrapping_add(word);
            let t2 = sigma0.wrapping_add(majority);

            let (_, carry_t1) = add_with_carries_5(s[7], sigma1, choose, constant, word);
            let (_, carry_t2) = add_with_carries_2(sigma0, majority);
            let (_, carry_a) = add_with_carries_2(t1, t2);
            let (_, carry_e) = add_with_carries_2(s[3], t1);
            let sched_carries = if i >= 16 {
                let w2 = trace.words[i - 2];
                let w7 = trace.words[i - 7];
                let w15 = trace.words[i - 15];
                let w16 = trace.words[i - 16];
                let (_, carries) = add_with_carries_4(small_sigma1(w2), w7, small_sigma0(w15), w16);
                carries
            } else {
                [0; LIMBS_PER_WORD]
            };

            let mut row = [BabyBear::ZERO; AIR_WIDTH];
            let words = [
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], word, constant, sigma0, sigma1,
                choose, majority, t1, t2,
            ];
            for (w, &value) in words.iter().enumerate() {
                row[w] = bb(value);
                set_word_limbs(&mut row, w, value);
            }
            set_lag_words(&mut row, &lags);
            set_helper_bits(&mut row);
            set_carries(&mut row, CARRY_T1_BASE, carry_t1);
            set_carries(&mut row, CARRY_T2_BASE, carry_t2);
            set_carries(&mut row, CARRY_A_BASE, carry_a);
            set_carries(&mut row, CARRY_E_BASE, carry_e);
            set_carries(&mut row, SCHED_CARRY_BASE, sched_carries);
            set_range_bits(&mut row);

            values.extend(row);
            advance_lags(&mut lags, word);
        }

        let mut row80 = [BabyBear::ZERO; AIR_WIDTH];
        let s = trace.round_states[80];
        let words = [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
        for (w, &value) in words.iter().enumerate() {
            row80[w] = bb(value);
            set_word_limbs(&mut row80, w, value);
        }
        set_lag_words(&mut row80, &lags);
        set_helper_bits(&mut row80);
        // Row 80 starts the deterministic padding segment; set helper columns so row 80 -> row 81
        // satisfies transition constraints.
        seed_padding_helpers(&mut row80);
        set_range_bits(&mut row80);
        values.extend(row80);
        advance_lags(&mut lags, 0);

        let mut state = trace.round_states[80];
        for row_idx in SHA_ROUNDS_PLUS_INIT..TRACE_ROWS {
            let next_state = [
                state[7],
                state[0],
                state[1],
                state[2],
                state[3].wrapping_add(state[7]),
                state[4],
                state[5],
                state[6],
            ];

            let mut row = [BabyBear::ZERO; AIR_WIDTH];
            let words = [
                next_state[0],
                next_state[1],
                next_state[2],
                next_state[3],
                next_state[4],
                next_state[5],
                next_state[6],
                next_state[7],
            ];
            for (w, &value) in words.iter().enumerate() {
                row[w] = bb(value);
                set_word_limbs(&mut row, w, value);
            }
            set_lag_words(&mut row, &lags);
            set_helper_bits(&mut row);
            if row_idx == TRACE_ROWS - 1 {
                // Last row keeps helper columns zero.
            } else {
                seed_padding_helpers(&mut row);
            }
            set_range_bits(&mut row);
            values.extend(row);
            advance_lags(&mut lags, 0);
            state = next_state;
        }

        RowMajorMatrix::new(values, AIR_WIDTH)
    }

    #[deprecated(
        note = "Use verify_plonky3_air_trace_with_instance; this infers instance from witness."
    )]
    pub fn verify_plonky3_air_trace(main_trace: &RowMajorMatrix<BabyBear>) -> bool {
        if main_trace.width() != AIR_WIDTH || main_trace.height() != TRACE_ROWS {
            return false;
        }

        let Some((initial_state, block)) = infer_instance_from_main(main_trace) else {
            return false;
        };
        let preprocessed_trace =
            Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(&initial_state, &block);
        verify_with_preprocessed(main_trace, &preprocessed_trace)
    }

    pub fn verify_plonky3_air_trace_with_instance(
        main_trace: &RowMajorMatrix<BabyBear>,
        initial_state: &[u64; 8],
        block: &[u8; 128],
    ) -> bool {
        if main_trace.width() != AIR_WIDTH || main_trace.height() != TRACE_ROWS {
            return false;
        }

        let preprocessed_trace =
            Sha512Circuit::build_plonky3_preprocessed_trace_from_instance(initial_state, block);
        verify_with_preprocessed(main_trace, &preprocessed_trace)
    }
}

fn verify_with_preprocessed(
    main_trace: &RowMajorMatrix<BabyBear>,
    preprocessed_trace: &RowMajorMatrix<BabyBear>,
) -> bool {
    if preprocessed_trace.width() != AIR_WIDTH || preprocessed_trace.height() != TRACE_ROWS {
        return false;
    }

    let air = Sha512RoundAir::new(preprocessed_trace.clone());

    for row in 0..main_trace.height() {
        let local = main_trace.row_slice(row).expect("row exists");
        let next = if row + 1 < main_trace.height() {
            main_trace.row_slice(row + 1).expect("next row exists")
        } else {
            main_trace.row_slice(row).expect("row exists")
        };

        let local_prep = preprocessed_trace.row_slice(row).expect("row exists");
        let next_prep = if row + 1 < preprocessed_trace.height() {
            preprocessed_trace
                .row_slice(row + 1)
                .expect("next row exists")
        } else {
            preprocessed_trace.row_slice(row).expect("row exists")
        };

        let mut main_window = Vec::with_capacity(2 * AIR_WIDTH);
        main_window.extend(local.iter().copied());
        main_window.extend(next.iter().copied());

        let mut prep_window = Vec::with_capacity(2 * AIR_WIDTH);
        prep_window.extend(local_prep.iter().copied());
        prep_window.extend(next_prep.iter().copied());

        let mut checker = AirConstraintChecker::new(
            RowMajorMatrix::new(main_window, AIR_WIDTH),
            RowMajorMatrix::new(prep_window, AIR_WIDTH),
            row == 0,
            row + 1 == main_trace.height(),
        );
        air.eval(&mut checker);

        if checker.violated {
            return false;
        }
    }

    true
}

fn infer_instance_from_main(
    main_trace: &RowMajorMatrix<BabyBear>,
) -> Option<([u64; 8], [u8; 128])> {
    let row0 = main_trace.row_slice(0)?;
    let state = [
        decode_word_from_row(&row0, WORD_A)?,
        decode_word_from_row(&row0, WORD_B)?,
        decode_word_from_row(&row0, WORD_C)?,
        decode_word_from_row(&row0, WORD_D)?,
        decode_word_from_row(&row0, WORD_E)?,
        decode_word_from_row(&row0, WORD_F)?,
        decode_word_from_row(&row0, WORD_G)?,
        decode_word_from_row(&row0, WORD_H)?,
    ];

    let mut block = [0_u8; 128];
    for i in 0..16 {
        let row = main_trace.row_slice(i)?;
        let w = decode_word_from_row(&row, WORD_W)?;
        block[i * 8..(i + 1) * 8].copy_from_slice(&w.to_be_bytes());
    }

    Some((state, block))
}

fn limb_col(word: usize, limb: usize) -> usize {
    LIMB_BASE + word * LIMBS_PER_WORD + limb
}

fn lag_col(lag: usize) -> usize {
    LAG_BASE + lag
}

fn lag_limb_col(lag: usize, limb: usize) -> usize {
    LAG_LIMB_BASE + lag * LIMBS_PER_WORD + limb
}

fn lag_limb_range_source(lag: usize, limb: usize) -> usize {
    WORD_COUNT * LIMBS_PER_WORD + lag * LIMBS_PER_WORD + limb
}

fn range_source_col(source: usize) -> usize {
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

fn range_bit_col(source: usize, bit: usize) -> usize {
    RANGE_BIT_BASE + source * RANGE_BITS_PER_SOURCE + bit
}

fn set_word_limbs(row: &mut [BabyBear; AIR_WIDTH], word: usize, value: u64) {
    let limbs = u64_to_limbs(value);
    for (i, limb) in limbs.into_iter().enumerate() {
        row[limb_col(word, i)] = BabyBear::from_u16(limb);
    }
}

fn set_lag_words(row: &mut [BabyBear; AIR_WIDTH], lags: &[u64; LAG_COUNT]) {
    for (lag, value) in lags.iter().copied().enumerate() {
        row[lag_col(lag)] = bb(value);
        let limbs = u64_to_limbs(value);
        for (limb, limb_value) in limbs.into_iter().enumerate() {
            row[lag_limb_col(lag, limb)] = BabyBear::from_u16(limb_value);
        }
    }
}

fn set_carries(row: &mut [BabyBear; AIR_WIDTH], base: usize, carries: [u16; LIMBS_PER_WORD]) {
    for (i, carry) in carries.into_iter().enumerate() {
        row[base + i] = BabyBear::from_u16(carry);
    }
}

fn set_range_bits(row: &mut [BabyBear; AIR_WIDTH]) {
    for source in 0..RANGE_SOURCES {
        let value = range_source_col(source);
        let x = row[value].as_canonical_u32();
        for bit in 0..RANGE_BITS_PER_SOURCE {
            row[range_bit_col(source, bit)] = BabyBear::from_bool(((x >> bit) & 1) == 1);
        }
    }
}

fn advance_lags(lags: &mut [u64; LAG_COUNT], word: u64) {
    for i in (1..LAG_COUNT).rev() {
        lags[i] = lags[i - 1];
    }
    lags[0] = word;
}

fn seed_padding_helpers(row: &mut [BabyBear; AIR_WIDTH]) {
    let h = decode_word_from_inline(row, WORD_H);
    let d = decode_word_from_inline(row, WORD_D);

    let t1 = h;
    let t2 = 0_u64;
    let (_, carry_t1) = add_with_carries_5(h, 0, 0, 0, 0);
    let (_, carry_t2) = add_with_carries_2(0, 0);
    let (_, carry_a) = add_with_carries_2(t1, t2);
    let (_, carry_e) = add_with_carries_2(d, t1);

    row[WORD_W] = BabyBear::ZERO;
    row[WORD_K] = BabyBear::ZERO;
    row[WORD_SIGMA0] = BabyBear::ZERO;
    row[WORD_SIGMA1] = BabyBear::ZERO;
    row[WORD_CH] = BabyBear::ZERO;
    row[WORD_MAJ] = BabyBear::ZERO;
    row[WORD_T1] = bb(t1);
    row[WORD_T2] = BabyBear::ZERO;

    set_word_limbs(row, WORD_W, 0);
    set_word_limbs(row, WORD_K, 0);
    set_word_limbs(row, WORD_SIGMA0, 0);
    set_word_limbs(row, WORD_SIGMA1, 0);
    set_word_limbs(row, WORD_CH, 0);
    set_word_limbs(row, WORD_MAJ, 0);
    set_word_limbs(row, WORD_T1, t1);
    set_word_limbs(row, WORD_T2, 0);
    set_helper_bits(row);

    set_carries(row, CARRY_T1_BASE, carry_t1);
    set_carries(row, CARRY_T2_BASE, carry_t2);
    set_carries(row, CARRY_A_BASE, carry_a);
    set_carries(row, CARRY_E_BASE, carry_e);
}

fn set_helper_bits(row: &mut [BabyBear; AIR_WIDTH]) {
    for (word, base) in [
        (WORD_A, BIT_A_BASE),
        (WORD_B, BIT_B_BASE),
        (WORD_C, BIT_C_BASE),
        (WORD_E, BIT_E_BASE),
        (WORD_F, BIT_F_BASE),
        (WORD_G, BIT_G_BASE),
        (WORD_SIGMA0, BIT_SIGMA0_BASE),
        (WORD_SIGMA1, BIT_SIGMA1_BASE),
        (WORD_CH, BIT_CH_BASE),
        (WORD_MAJ, BIT_MAJ_BASE),
    ] {
        let value = decode_word_from_inline(row, word);
        for i in 0..64 {
            row[base + i] = BabyBear::from_bool(((value >> i) & 1) == 1);
        }
    }
}

fn u64_to_limbs(value: u64) -> [u16; LIMBS_PER_WORD] {
    [
        (value & 0xffff) as u16,
        ((value >> 16) & 0xffff) as u16,
        ((value >> 32) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
    ]
}

fn decode_word_from_row(row: &[BabyBear], word: usize) -> Option<u64> {
    let mut out = 0_u64;
    for limb in 0..LIMBS_PER_WORD {
        let x = row[limb_col(word, limb)].as_canonical_u32();
        if x > u16::MAX as u32 {
            return None;
        }
        out |= u64::from(x) << (16 * limb);
    }

    (row[word] == bb(out)).then_some(out)
}

fn decode_word_from_inline(row: &[BabyBear; AIR_WIDTH], word: usize) -> u64 {
    let mut out = 0_u64;
    for limb in 0..LIMBS_PER_WORD {
        let x = row[limb_col(word, limb)].as_canonical_u32();
        out |= u64::from(x) << (16 * limb);
    }
    out
}

fn add_with_carries_5(a: u64, b: u64, c: u64, d: u64, e: u64) -> (u64, [u16; LIMBS_PER_WORD]) {
    let al = u64_to_limbs(a);
    let bl = u64_to_limbs(b);
    let cl = u64_to_limbs(c);
    let dl = u64_to_limbs(d);
    let el = u64_to_limbs(e);
    let mut out = [0_u16; LIMBS_PER_WORD];
    let mut carries = [0_u16; LIMBS_PER_WORD];
    let mut carry = 0_u32;

    for i in 0..LIMBS_PER_WORD {
        let sum = al[i] as u32 + bl[i] as u32 + cl[i] as u32 + dl[i] as u32 + el[i] as u32 + carry;
        out[i] = (sum & 0xffff) as u16;
        carry = sum >> 16;
        carries[i] = carry as u16;
    }

    (
        u64::from(out[0])
            | (u64::from(out[1]) << 16)
            | (u64::from(out[2]) << 32)
            | (u64::from(out[3]) << 48),
        carries,
    )
}

fn add_with_carries_2(a: u64, b: u64) -> (u64, [u16; LIMBS_PER_WORD]) {
    let al = u64_to_limbs(a);
    let bl = u64_to_limbs(b);
    let mut out = [0_u16; LIMBS_PER_WORD];
    let mut carries = [0_u16; LIMBS_PER_WORD];
    let mut carry = 0_u32;

    for i in 0..LIMBS_PER_WORD {
        let sum = al[i] as u32 + bl[i] as u32 + carry;
        out[i] = (sum & 0xffff) as u16;
        carry = sum >> 16;
        carries[i] = carry as u16;
    }

    (
        u64::from(out[0])
            | (u64::from(out[1]) << 16)
            | (u64::from(out[2]) << 32)
            | (u64::from(out[3]) << 48),
        carries,
    )
}

fn add_with_carries_4(a: u64, b: u64, c: u64, d: u64) -> (u64, [u16; LIMBS_PER_WORD]) {
    let al = u64_to_limbs(a);
    let bl = u64_to_limbs(b);
    let cl = u64_to_limbs(c);
    let dl = u64_to_limbs(d);
    let mut out = [0_u16; LIMBS_PER_WORD];
    let mut carries = [0_u16; LIMBS_PER_WORD];
    let mut carry = 0_u32;

    for i in 0..LIMBS_PER_WORD {
        let sum = al[i] as u32 + bl[i] as u32 + cl[i] as u32 + dl[i] as u32 + carry;
        out[i] = (sum & 0xffff) as u16;
        carry = sum >> 16;
        carries[i] = carry as u16;
    }

    (
        u64::from(out[0])
            | (u64::from(out[1]) << 16)
            | (u64::from(out[2]) << 32)
            | (u64::from(out[3]) << 48),
        carries,
    )
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
