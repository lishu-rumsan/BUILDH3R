use std::fmt::Write;
use std::io::{self, Read};
use std::num::ParseIntError;

pub struct Sha1 {
    buffer: [u8; 64],
    buffer_len: usize,
    block_count: usize,
    state: [u32; 5],
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            buffer: [0; 64],
            buffer_len: 0,
            block_count: 0,
            state: [
                0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
            ],
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            self.process_byte(byte);
        }
    }

    fn process_byte(&mut self, byte: u8) {
        self.buffer[self.buffer_len] = byte;
        self.buffer_len += 1;
        if self.buffer_len == 64 {
            self.process_block();
            self.buffer.fill(0);
            self.block_count += 1;
            self.buffer_len = 0;
        }
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 80];
        for (i, chunk) in self.buffer.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = w[i].rotate_left(1);
        }
        let mut state = self.state;
        for i in 0..80 {
            let f = if i < 20 {
                (state[1] & state[2]) | (!state[1] & state[3])
            } else if i < 40 {
                state[1] ^ state[2] ^ state[3]
            } else if i < 60 {
                (state[1] & state[2]) | (state[1] & state[3]) | (state[2] & state[3])
            } else {
                state[1] ^ state[2] ^ state[3]
            };
            let temp = state[0].rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(state[4])
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            state[4] = state[3];
            state[3] = state[2];
            state[2] = state[1].rotate_left(30);
            state[1] = state[0];
            state[0] = temp;
        }
        for (s, state_val) in self.state.iter_mut().zip(state.iter()) {
            *s = s.wrapping_add(*state_val);
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let total_bits = (self.buffer_len * 8) + (self.block_count * 512);
        let padding_len = (448 - total_bits % 512) % 512;
        let mut padded_buffer = Vec::with_capacity(padding_len as usize / 8 + 8);
        padded_buffer.push(0x80);
        padded_buffer.extend(vec![0; (padding_len / 8) as usize]);
        padded_buffer.extend((total_bits as u64).to_be_bytes());

        self.absorb(&padded_buffer);
        let mut hash = [0u8; 20];
        for (chunk, state_val) in hash.chunks_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&state_val.to_be_bytes());
        }
        hash
    }
}

fn decode_hex(hex_str: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| format!("{:02x}", b)).collect()
}

fn main() {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let inputs: Vec<&str> = input.trim().split_whitespace().collect();
    if inputs.len() != 2 {
        eprintln!("Invalid input format");
        return;
    }

    let mut hasher = Sha1::new();
    hasher.absorb(inputs[1].as_bytes());
    let hashed_output = hasher.finalize();

    let expected_output = decode_hex(inputs[0]).expect("Failed to decode hex");
    assert_eq!(hashed_output.to_vec(), expected_output);

    println!("{}", true);
}

const K: [u32; 80] = [
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6, 
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
];