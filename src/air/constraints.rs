use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

use super::columns::{
    LIMBS_PER_WORD, SCHED_CARRY_BASE, WORD_W, lag_limb_col, lag_limb_range_source, limb_col,
    range_bit_col,
};

pub(super) fn constrain_add_5_limbs<AB: AirBuilder<F = BabyBear>>(
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

pub(super) fn constrain_add_2_limbs<AB: AirBuilder<F = BabyBear>>(
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

pub(super) fn constrain_add_2_limbs_across_rows<AB: AirBuilder<F = BabyBear>>(
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

pub(super) fn constrain_schedule_recurrence<B: AirBuilder<F = BabyBear>>(
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

pub(super) fn pack_bits<AB: AirBuilder<F = BabyBear>>(
    row: &[AB::Var],
    bit_base: usize,
) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    for i in (0..64).rev() {
        acc = acc * BabyBear::TWO + row[bit_base + i].clone();
    }
    acc
}

pub(super) fn xor2_expr<AB: AirBuilder<F = BabyBear>>(x: AB::Expr, y: AB::Expr) -> AB::Expr {
    x.clone() + y.clone() - (x * y) * BabyBear::TWO
}

pub(super) fn xor3_expr<AB: AirBuilder<F = BabyBear>>(
    x: AB::Expr,
    y: AB::Expr,
    z: AB::Expr,
) -> AB::Expr {
    xor2_expr::<AB>(xor2_expr::<AB>(x, y), z)
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
