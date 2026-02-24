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
use p3_matrix_git::Matrix;
use p3_matrix_git::dense::RowMajorMatrix;
use p3_merkle_tree_git::MerkleTreeMmcs;
use p3_symmetric_git::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark_git::StarkConfig;

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
struct LogupRange16Air {
    log_height: usize,
    num_lookups: usize,
}

impl LogupRange16Air {
    const fn new(log_height: usize) -> Self {
        Self {
            log_height,
            num_lookups: 0,
        }
    }
}

impl<F: Field> BaseAir<F> for LogupRange16Air {
    fn width(&self) -> usize {
        // Col 0: value to range-check.
        // Col 1: fixed lookup table value (0..15).
        // Col 2: multiplicity for table value.
        3
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let n = 1 << self.log_height;
        let mut m = RowMajorMatrix::new(F::zero_vec(n), 1);
        for (i, v) in m.values.iter_mut().enumerate() {
            *v = F::from_u64(i as u64);
        }
        Some(m)
    }
}

impl<AB> Air<AB> for LogupRange16Air
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
        let symbolic_air_builder = SymbolicAirBuilder::<AB::F>::new(1, 3, 0, 0, 0);
        let symbolic_main = symbolic_air_builder.main();
        let local = symbolic_main.row_slice(0).expect("local row");
        let value = local[0];
        let table = local[1];
        let table_mult = local[2];

        let inputs = vec![
            (
                vec![SymbolicExpression::from(value)],
                SymbolicExpression::ONE,
                Direction::Receive,
            ),
            (
                vec![SymbolicExpression::from(table)],
                SymbolicExpression::from(table_mult),
                Direction::Send,
            ),
        ];
        vec![Air::<AB>::register_lookup(self, Kind::Local, &inputs)]
    }

    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let prep = builder.preprocessed().expect("preprocessed row exists");
        let local = main.row_slice(0).expect("local row");
        let prep_local = prep.row_slice(0).expect("local prep row");

        // Fix the lookup-table column to the preprocessed row index value.
        builder.assert_eq(local[1].clone(), prep_local[0].clone());
    }
}

fn make_trace(values: &[u16]) -> RowMajorMatrix<Val> {
    let n = values.len();
    assert_eq!(n, 16);
    assert!(n.is_power_of_two());

    let mut histogram = [0_u32; 16];
    for &v in values {
        if usize::from(v) < 16 {
            histogram[usize::from(v)] += 1;
        }
    }

    let mut trace = Vec::with_capacity(n * 3);
    for row in 0..n {
        trace.push(Val::from_u16(values[row]));
        trace.push(Val::from_u16(row as u16));
        trace.push(Val::from_u32(histogram[row]));
    }
    RowMajorMatrix::new(trace, 3)
}

#[test]
fn logup_rangecheck_valid() {
    let config = make_config(42);
    let log_height = 4;
    let air = LogupRange16Air::new(log_height);
    let mut airs = [air];
    let prover_data =
        ProverData::<MyConfig>::from_airs_and_degrees(&config, &mut airs, &[log_height]);
    let common = &prover_data.common;

    let values = [0_u16, 2, 3, 15, 1, 1, 4, 8, 9, 10, 11, 12, 13, 14, 5, 6];
    let traces = vec![make_trace(&values)];
    let pvs = vec![vec![]];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs, common);
    let proof = prove_batch(&config, &instances, &prover_data);
    verify_batch(&config, &airs, &proof, &pvs, common).expect("verification should pass");
}

#[test]
#[should_panic]
fn logup_rangecheck_invalid_value_panics_during_prove() {
    let config = make_config(43);
    let log_height = 4;
    let air = LogupRange16Air::new(log_height);
    let mut airs = [air];
    let prover_data =
        ProverData::<MyConfig>::from_airs_and_degrees(&config, &mut airs, &[log_height]);
    let common = &prover_data.common;

    // 16 is not in the fixed lookup table [0..15], so this should fail.
    let values = [0_u16, 2, 3, 15, 1, 1, 4, 8, 9, 10, 11, 12, 13, 14, 5, 16];
    let traces = vec![make_trace(&values)];
    let pvs = vec![vec![]];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs, common);
    let _proof = prove_batch(&config, &instances, &prover_data);
}
