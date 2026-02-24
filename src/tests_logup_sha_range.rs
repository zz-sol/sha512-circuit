use core::fmt::Debug;

use p3_air_git::symbolic::{SymbolicAirBuilder, SymbolicExpression};
use p3_air_git::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PermutationAirBuilder};
use p3_baby_bear_git::BabyBear;
use p3_batch_stark_git::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_challenger_git::{HashChallenger, SerializingChallenger32};
use p3_commit_git::ExtensionMmcs;
use p3_dft_git::Radix2DitParallel;
use p3_field_git::extension::BinomialExtensionField;
use p3_field_git::{Field, PrimeCharacteristicRing};
use p3_fri_git::{TwoAdicFriPcs, create_test_fri_params};
use p3_keccak_git::Keccak256Hash;
use p3_lookup_git::lookup_traits::{Direction, Kind, Lookup};
use p3_matrix::Matrix as Matrix042;
use p3_matrix_git::Matrix as MatrixGit;
use p3_matrix_git::dense::RowMajorMatrix;
use p3_merkle_tree_git::MerkleTreeMmcs;
use p3_symmetric_git::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark_git::StarkConfig;

use crate::air::{RANGE_SOURCES_FOR_TESTS, range_source_col_for_tests};
use crate::constants::INITIAL_STATE;
use crate::sha512::Sha512Circuit;
use p3_field::PrimeField32;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = Radix2DitParallel<Val>;
type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

const LOG_HEIGHT: usize = 16;
const TABLE_SIZE: usize = 1 << LOG_HEIGHT;

fn make_config(seed: u64) -> MyConfig {
    let byte_hash = ByteHash {};
    let hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = create_test_fri_params(challenge_mmcs, 2);
    let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(seed.to_le_bytes().to_vec(), byte_hash);
    StarkConfig::new(pcs, challenger)
}

#[derive(Debug, Clone, Copy)]
struct LogupU16Air {
    num_lookups: usize,
}

impl LogupU16Air {
    const fn new() -> Self {
        Self { num_lookups: 0 }
    }
}

impl<F: Field> BaseAir<F> for LogupU16Air {
    fn width(&self) -> usize {
        // 0: checked_value
        // 1: checked_mult (0/1)
        // 2: table_value (0..65535)
        // 3: table_mult (histogram count)
        4
    }
}

impl<AB> Air<AB> for LogupU16Air
where
    AB::Var: Debug,
    AB: AirBuilder + PermutationAirBuilder + AirBuilderWithPublicValues,
{
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_idx = self.num_lookups;
        self.num_lookups += 1;
        vec![new_idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<AB::F>> {
        self.num_lookups = 0;
        let symbolic_air_builder = SymbolicAirBuilder::<AB::F>::new(0, 4, 0, 0, 0);
        let symbolic_main = symbolic_air_builder.main();
        let local = symbolic_main.row_slice(0).expect("local row");
        let checked_value = local[0];
        let checked_mult = local[1];
        let table_value = local[2];
        let table_mult = local[3];

        let inputs = vec![
            (
                vec![SymbolicExpression::from(checked_value)],
                SymbolicExpression::from(checked_mult),
                Direction::Receive,
            ),
            (
                vec![SymbolicExpression::from(table_value)],
                SymbolicExpression::from(table_mult),
                Direction::Send,
            ),
        ];
        vec![Air::<AB>::register_lookup(self, Kind::Local, &inputs)]
    }

    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("local row");
        let next = main.row_slice(1).expect("next row");

        builder.assert_bool(local[1].clone());
        builder
            .when_first_row()
            .assert_eq(local[2].clone(), AB::F::ZERO);
        builder
            .when_transition()
            .assert_eq(next[2].clone(), local[2].clone() + AB::F::ONE);
        builder
            .when_last_row()
            .assert_eq(local[2].clone(), AB::F::from_u32((TABLE_SIZE - 1) as u32));
    }
}

fn collect_sha_range_values() -> Vec<u32> {
    let block = [0_u8; 128];
    let block_trace = Sha512Circuit::compress_block(&INITIAL_STATE, &block);
    let main = Sha512Circuit::build_plonky3_air_trace(&block_trace);

    let mut out = Vec::with_capacity(main.height() * RANGE_SOURCES_FOR_TESTS);
    for row in 0..main.height() {
        let row_slice = main.row_slice(row).expect("row exists");
        for src in 0..RANGE_SOURCES_FOR_TESTS {
            let col = range_source_col_for_tests(src);
            out.push(row_slice[col].as_canonical_u32());
        }
    }
    out
}

fn build_lookup_trace(checked_values: &[u32]) -> RowMajorMatrix<Val> {
    assert!(checked_values.len() <= TABLE_SIZE);
    let mut histogram = vec![0_u32; TABLE_SIZE];
    for &x in checked_values {
        if x < TABLE_SIZE as u32 {
            histogram[x as usize] += 1;
        }
    }

    let mut values = Vec::with_capacity(TABLE_SIZE * 4);
    for row in 0..TABLE_SIZE {
        let checked = if row < checked_values.len() {
            checked_values[row]
        } else {
            0
        };
        let checked_mult = if row < checked_values.len() { 1 } else { 0 };
        values.push(Val::from_u32(checked));
        values.push(Val::from_bool(checked_mult == 1));
        values.push(Val::from_u32(row as u32));
        values.push(Val::from_u32(histogram[row]));
    }
    RowMajorMatrix::new(values, 4)
}

#[test]
fn sha_limb_ranges_pass_logup() {
    let config = make_config(123);
    let air = LogupU16Air::new();
    let mut airs = [air];
    let prover_data =
        ProverData::<MyConfig>::from_airs_and_degrees(&config, &mut airs, &[LOG_HEIGHT]);
    let common = &prover_data.common;

    let checked_values = collect_sha_range_values();
    let traces = vec![build_lookup_trace(&checked_values)];
    let pvs = vec![vec![]];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs, common);
    let proof = prove_batch(&config, &instances, &prover_data);
    verify_batch(&config, &airs, &proof, &pvs, common).expect("verification should pass");
}

#[test]
#[should_panic]
fn sha_limb_ranges_reject_out_of_table_value() {
    let config = make_config(124);
    let air = LogupU16Air::new();
    let mut airs = [air];
    let prover_data =
        ProverData::<MyConfig>::from_airs_and_degrees(&config, &mut airs, &[LOG_HEIGHT]);
    let common = &prover_data.common;

    let mut checked_values = collect_sha_range_values();
    checked_values[0] = 70_000;
    let traces = vec![build_lookup_trace(&checked_values)];
    let pvs = vec![vec![]];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs, common);
    let _proof = prove_batch(&config, &instances, &prover_data);
}
