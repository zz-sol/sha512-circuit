use core::fmt::Debug;

use p3_air_git::symbolic::{SymbolicAirBuilder, SymbolicExpression};
use p3_air_git::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PermutationAirBuilder};
use p3_baby_bear_git::BabyBear;
use p3_batch_stark_git::{BatchProof, ProverData, StarkInstance, prove_batch, verify_batch};
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
use serde::{Deserialize, Serialize};

use crate::Sha512SingleBlockInstance;
use crate::sha512::Sha512Circuit;

const LOG_HEIGHT: usize = 16;
const TABLE_SIZE: usize = 1 << LOG_HEIGHT;

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
pub type Sha512LagLogupConfig = StarkConfig<MyPcs, Challenge, Challenger>;
pub type Sha512LagLogupBatchProof = BatchProof<Sha512LagLogupConfig>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Sha512LagLogupSettings {
    pub log_final_poly_len: usize,
    pub rng_seed: u64,
}

impl Default for Sha512LagLogupSettings {
    fn default() -> Self {
        Self {
            log_final_poly_len: 2,
            rng_seed: 1,
        }
    }
}

pub struct Sha512LagLogupProof {
    pub proof: Sha512LagLogupBatchProof,
    pub settings: Sha512LagLogupSettings,
}

#[derive(Debug, Clone)]
struct LogupU16Air {
    preprocessed_u32: Vec<u32>,
    num_lookups: usize,
}

impl LogupU16Air {
    fn new(preprocessed_u32: Vec<u32>) -> Self {
        Self {
            preprocessed_u32,
            num_lookups: 0,
        }
    }
}

impl<F: Field + PrimeCharacteristicRing> BaseAir<F> for LogupU16Air {
    fn width(&self) -> usize {
        // 0: checked_value
        // 1: checked_mult (0/1)
        // 2: table_value (0..65535)
        // 3: table_mult (histogram count)
        4
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let out = self
            .preprocessed_u32
            .iter()
            .copied()
            .map(F::from_u32)
            .collect::<Vec<_>>();
        Some(RowMajorMatrix::new(out, 2))
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
        let symbolic_air_builder = SymbolicAirBuilder::<AB::F>::new(2, 4, 0, 0, 0);
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
        let prep = builder
            .preprocessed()
            .expect("preprocessed trace is required for instance binding");
        let local = main.row_slice(0).expect("local row");
        let next = main.row_slice(1).expect("next row");
        let prep_local = prep.row_slice(0).expect("local prep row");

        // Bind checked values and active flags to the instance-dependent preprocessed trace.
        builder.assert_eq(local[0].clone(), prep_local[0].clone());
        builder.assert_eq(local[1].clone(), prep_local[1].clone());

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

fn setup_config(settings: Sha512LagLogupSettings) -> Sha512LagLogupConfig {
    let byte_hash = ByteHash {};
    let hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = create_test_fri_params(challenge_mmcs, settings.log_final_poly_len);
    let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(settings.rng_seed.to_le_bytes().to_vec(), byte_hash);
    StarkConfig::new(pcs, challenger)
}

fn build_lag_lookup_instance_data(instance: Sha512SingleBlockInstance) -> (Vec<u32>, Vec<Val>) {
    let checked_values =
        Sha512Circuit::collect_lag_range_values_for_logup(&instance.initial_state, &instance.block);
    assert!(checked_values.len() <= TABLE_SIZE);

    let mut histogram = vec![0_u32; TABLE_SIZE];
    for &x in &checked_values {
        if x < TABLE_SIZE as u32 {
            histogram[x as usize] += 1;
        }
    }

    let mut trace_vals = Vec::with_capacity(TABLE_SIZE * 4);
    let mut prep_vals = Vec::with_capacity(TABLE_SIZE * 2);
    for row in 0..TABLE_SIZE {
        let checked = if row < checked_values.len() {
            checked_values[row]
        } else {
            0
        };
        let checked_mult = if row < checked_values.len() {
            1_u32
        } else {
            0_u32
        };
        trace_vals.push(Val::from_u32(checked));
        trace_vals.push(Val::from_u32(checked_mult));
        trace_vals.push(Val::from_u32(row as u32));
        trace_vals.push(Val::from_u32(histogram[row]));

        prep_vals.push(checked);
        prep_vals.push(checked_mult);
    }
    (prep_vals, trace_vals)
}

pub fn prove_sha_lag_logup(instance: Sha512SingleBlockInstance) -> Sha512LagLogupProof {
    prove_sha_lag_logup_with_settings(instance, Sha512LagLogupSettings::default())
}

pub fn prove_sha_lag_logup_with_settings(
    instance: Sha512SingleBlockInstance,
    settings: Sha512LagLogupSettings,
) -> Sha512LagLogupProof {
    let config = setup_config(settings);
    let (prep_vals, trace_vals) = build_lag_lookup_instance_data(instance);
    let air = LogupU16Air::new(prep_vals);
    let mut airs = [air];
    let prover_data = ProverData::<Sha512LagLogupConfig>::from_airs_and_degrees(
        &config,
        &mut airs,
        &[LOG_HEIGHT],
    );
    let common = &prover_data.common;
    let traces = vec![RowMajorMatrix::new(trace_vals, 4)];
    let pvs = vec![vec![]];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs, common);
    let proof = prove_batch(&config, &instances, &prover_data);
    Sha512LagLogupProof { proof, settings }
}

pub fn verify_sha_lag_logup(
    instance: Sha512SingleBlockInstance,
    proof: &Sha512LagLogupProof,
) -> bool {
    verify_sha_lag_logup_with_settings(instance, proof, proof.settings)
}

pub fn verify_sha_lag_logup_with_settings(
    instance: Sha512SingleBlockInstance,
    proof: &Sha512LagLogupProof,
    settings: Sha512LagLogupSettings,
) -> bool {
    let config = setup_config(settings);
    let (prep_vals, _) = build_lag_lookup_instance_data(instance);
    let air = LogupU16Air::new(prep_vals);
    let mut airs = [air];
    let prover_data = ProverData::<Sha512LagLogupConfig>::from_airs_and_degrees(
        &config,
        &mut airs,
        &[LOG_HEIGHT],
    );
    let common = &prover_data.common;
    let pvs = vec![vec![]];
    verify_batch(&config, &airs, &proof.proof, &pvs, common).is_ok()
}
