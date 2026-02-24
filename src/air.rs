#[path = "air/columns.rs"]
mod columns;
#[path = "air/constraints.rs"]
mod constraints;
#[path = "air/trace_builder.rs"]
mod trace_builder;

use p3_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues, PairBuilder,
};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use crate::constants::K;
use crate::ops::{bb, big_sigma0, big_sigma1, ch, maj, small_sigma0, small_sigma1};
use crate::sha512::Sha512Circuit;
use crate::trace::BlockTrace;
use columns::*;
use constraints::*;
use trace_builder::*;

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

impl BaseAirWithPublicValues<BabyBear> for Sha512RoundAir {
    fn num_public_values(&self) -> usize {
        8
    }
}

impl<AB> Air<AB> for Sha512RoundAir
where
    AB: AirBuilderWithPublicValues<F = BabyBear> + PairBuilder,
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

        let public: [AB::PublicVar; 8] = core::array::from_fn(|i| builder.public_values()[i]);
        let final_sel = local_prep[PREP_FINAL_SELECTOR_COL].clone();
        for i in 0..8 {
            builder.assert_zero(final_sel.clone() * (public[i].into() - local[i].clone()));
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

#[derive(Clone)]
struct AirConstraintChecker {
    main: RowMajorMatrix<BabyBear>,
    preprocessed: RowMajorMatrix<BabyBear>,
    is_first: BabyBear,
    is_last: BabyBear,
    is_transition: BabyBear,
    public_values: [BabyBear; 8],
    violated: bool,
}

impl AirConstraintChecker {
    fn new(
        main: RowMajorMatrix<BabyBear>,
        preprocessed: RowMajorMatrix<BabyBear>,
        is_first: bool,
        is_last: bool,
        public_values: [BabyBear; 8],
    ) -> Self {
        Self {
            main,
            preprocessed,
            is_first: BabyBear::from_bool(is_first),
            is_last: BabyBear::from_bool(is_last),
            is_transition: BabyBear::from_bool(!is_last),
            public_values,
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

impl AirBuilderWithPublicValues for AirConstraintChecker {
    type PublicVar = BabyBear;

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
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
            dst[PREP_FINAL_SELECTOR_COL] = BabyBear::from_bool(row == 80);
            dst[WORD_A] = bb(initial_state[0]);
            dst[WORD_B] = bb(initial_state[1]);
            dst[WORD_C] = bb(initial_state[2]);
            dst[WORD_D] = bb(initial_state[3]);
            dst[WORD_E] = bb(initial_state[4]);
            dst[WORD_F] = bb(initial_state[5]);
            dst[WORD_G] = bb(initial_state[6]);
            dst[WORD_H] = bb(initial_state[7]);
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
            if row_idx != TRACE_ROWS - 1 {
                seed_padding_helpers(&mut row);
            }
            set_range_bits(&mut row);
            values.extend(row);
            advance_lags(&mut lags, 0);
            state = next_state;
        }

        RowMajorMatrix::new(values, AIR_WIDTH)
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
        let trace = Sha512Circuit::compress_block(initial_state, block);
        let public_values = trace.round_states[80].map(bb);
        verify_with_preprocessed(main_trace, &preprocessed_trace, public_values)
    }
}

fn verify_with_preprocessed(
    main_trace: &RowMajorMatrix<BabyBear>,
    preprocessed_trace: &RowMajorMatrix<BabyBear>,
    public_values: [BabyBear; 8],
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
            public_values,
        );
        air.eval(&mut checker);

        if checker.violated {
            return false;
        }
    }

    true
}

#[cfg(test)]
pub(crate) use columns::{
    AIR_WIDTH_FOR_TESTS, LAG_BASE_FOR_TESTS, LIMB_BASE_FOR_TESTS, LIMBS_PER_WORD_FOR_TESTS,
    RANGE_BIT_BASE_FOR_TESTS, RANGE_BITS_PER_SOURCE_FOR_TESTS, SCHED_CARRY_BASE_FOR_TESTS,
    WORD_A_FOR_TESTS, WORD_E_FOR_TESTS, WORD_K_FOR_TESTS, WORD_SIGMA0_FOR_TESTS, WORD_T1_FOR_TESTS,
    WORD_W_FOR_TESTS,
};
