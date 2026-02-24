#[derive(Clone, Debug)]
pub struct BlockTrace {
    pub input_state: [u64; 8],
    pub words: [u64; 80],
    pub round_states: [[u64; 8]; 81],
    pub output_state: [u64; 8],
}
