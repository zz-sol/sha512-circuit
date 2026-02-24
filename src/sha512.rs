use crate::constants::{INITIAL_STATE, K};
use crate::ops::{big_sigma0, big_sigma1, ch, maj, small_sigma0, small_sigma1};
use crate::trace::BlockTrace;

pub struct Sha512Circuit;

impl Sha512Circuit {
    pub fn hash(message: &[u8]) -> [u8; 64] {
        let mut state = INITIAL_STATE;
        for block in Self::padded_blocks(message) {
            let trace = Self::compress_block(&state, &block);
            state = trace.output_state;
        }

        Self::state_to_digest(&state)
    }

    pub fn padded_blocks(message: &[u8]) -> Vec<[u8; 128]> {
        pad_message(message)
            .chunks_exact(128)
            .map(|chunk| chunk.try_into().expect("block size is 128"))
            .collect()
    }

    pub fn state_to_digest(state: &[u64; 8]) -> [u8; 64] {
        let mut out = [0_u8; 64];
        for (chunk, word) in out.chunks_exact_mut(8).zip(state.iter().copied()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn compress_block(state: &[u64; 8], block: &[u8; 128]) -> BlockTrace {
        let mut words = [0_u64; 80];
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            words[i] = u64::from_be_bytes(chunk.try_into().expect("word size is 8"));
        }
        for i in 16..80 {
            words[i] = small_sigma1(words[i - 2])
                .wrapping_add(words[i - 7])
                .wrapping_add(small_sigma0(words[i - 15]))
                .wrapping_add(words[i - 16]);
        }

        let mut round_states = [[0_u64; 8]; 81];
        round_states[0] = *state;

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..80 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(words[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);

            round_states[i + 1] = [a, b, c, d, e, f, g, h];
        }

        let output_state = [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ];

        BlockTrace {
            input_state: *state,
            words,
            round_states,
            output_state,
        }
    }

    pub fn verify_block_trace(trace: &BlockTrace) -> bool {
        for i in 16..80 {
            let expected = small_sigma1(trace.words[i - 2])
                .wrapping_add(trace.words[i - 7])
                .wrapping_add(small_sigma0(trace.words[i - 15]))
                .wrapping_add(trace.words[i - 16]);
            if trace.words[i] != expected {
                return false;
            }
        }

        if trace.round_states[0] != trace.input_state {
            return false;
        }

        for (i, &round_constant) in K.iter().enumerate() {
            let s = trace.round_states[i];
            let next = trace.round_states[i + 1];
            let (a, b, c, d, e, f, g, h) = (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);

            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(round_constant)
                .wrapping_add(trace.words[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

            let expected_next = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];

            if next != expected_next {
                return false;
            }
        }

        let last = trace.round_states[80];
        let expected_output = [
            trace.input_state[0].wrapping_add(last[0]),
            trace.input_state[1].wrapping_add(last[1]),
            trace.input_state[2].wrapping_add(last[2]),
            trace.input_state[3].wrapping_add(last[3]),
            trace.input_state[4].wrapping_add(last[4]),
            trace.input_state[5].wrapping_add(last[5]),
            trace.input_state[6].wrapping_add(last[6]),
            trace.input_state[7].wrapping_add(last[7]),
        ];

        trace.output_state == expected_output
    }
}

fn pad_message(message: &[u8]) -> Vec<u8> {
    let bit_len = (message.len() as u128) * 8;

    let mut out = Vec::with_capacity(((message.len() + 17).div_ceil(128)) * 128);
    out.extend_from_slice(message);
    out.push(0x80);

    while (out.len() + 16) % 128 != 0 {
        out.push(0);
    }

    out.extend_from_slice(&bit_len.to_be_bytes());
    out
}
