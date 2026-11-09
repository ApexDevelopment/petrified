//! The murmur3-based hashing used by `github.com/bits-and-blooms/bloom/v3`.
//! Bloom filters are exchanged between nodes, so this must be bit-identical.

const C1: u64 = 0x87c37b91114253d5;
const C2: u64 = 0x4cf5ad432745937f;
const BLOCK_SIZE: usize = 16;

#[derive(Default)]
struct Digest128 {
	h1: u64,
	h2: u64,
}

fn fmix64(mut k: u64) -> u64 {
	k ^= k >> 33;
	k = k.wrapping_mul(0xff51afd7ed558ccd);
	k ^= k >> 33;
	k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
	k ^= k >> 33;
	k
}

fn mix_k1(k1: u64) -> u64 {
	k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2)
}

fn mix_k2(k2: u64) -> u64 {
	k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1)
}

impl Digest128 {
	fn bmix(&mut self, data: &[u8]) {
		for block in data.chunks_exact(BLOCK_SIZE) {
			let k1 = u64::from_le_bytes(block[..8].try_into().unwrap());
			let k2 = u64::from_le_bytes(block[8..].try_into().unwrap());
			self.bmix_words(k1, k2);
		}
	}

	fn bmix_words(&mut self, k1: u64, k2: u64) {
		let (mut h1, mut h2) = (self.h1, self.h2);
		h1 ^= mix_k1(k1);
		h1 = h1.rotate_left(27).wrapping_add(h2);
		h1 = h1.wrapping_mul(5).wrapping_add(0x52dce729);
		h2 ^= mix_k2(k2);
		h2 = h2.rotate_left(31).wrapping_add(h1);
		h2 = h2.wrapping_mul(5).wrapping_add(0x38495ab5);
		self.h1 = h1;
		self.h2 = h2;
	}

	/// Finalizes without modifying the running state. With `pad_tail`, a
	/// virtual 0x01 byte is appended after `tail`.
	fn sum128(&self, pad_tail: bool, length: u64, tail: &[u8]) -> (u64, u64) {
		let (mut h1, mut h2) = (self.h1, self.h2);
		let mut bytes = [0u8; BLOCK_SIZE];
		bytes[..tail.len()].copy_from_slice(tail);
		let mut tail_len = tail.len();
		if pad_tail {
			bytes[tail_len] = 1;
			tail_len += 1;
		}
		let k1 = u64::from_le_bytes(bytes[..8].try_into().unwrap());
		let k2 = u64::from_le_bytes(bytes[8..].try_into().unwrap());
		if tail_len > 8 {
			h2 ^= mix_k2(k2);
		}
		if tail_len > 0 {
			h1 ^= mix_k1(k1);
		}
		h1 ^= length;
		h2 ^= length;
		h1 = h1.wrapping_add(h2);
		h2 = h2.wrapping_add(h1);
		h1 = fmix64(h1);
		h2 = fmix64(h2);
		h1 = h1.wrapping_add(h2);
		h2 = h2.wrapping_add(h1);
		(h1, h2)
	}
}

/// Returns the four base hashes for `data`, as `baseHashes` does in Go.
pub(crate) fn base_hashes(data: &[u8]) -> [u64; 4] {
	let mut digest = Digest128::default();
	digest.bmix(data);
	let length = data.len() as u64;
	let tail_length = data.len() % BLOCK_SIZE;
	let tail = &data[data.len() - tail_length..];
	let (hash1, hash2) = digest.sum128(false, length, tail);
	let (hash3, hash4) = if tail_length + 1 == BLOCK_SIZE {
		let mut block = [0u8; BLOCK_SIZE];
		block[..tail_length].copy_from_slice(tail);
		block[tail_length] = 1;
		let word1 = u64::from_le_bytes(block[..8].try_into().unwrap());
		let word2 = u64::from_le_bytes(block[8..].try_into().unwrap());
		digest.bmix_words(word1, word2);
		digest.sum128(false, length + 1, &[])
	} else {
		digest.sum128(true, length + 1, tail)
	};
	[hash1, hash2, hash3, hash4]
}

pub(crate) fn location(h: &[u64; 4], i: u64) -> u64 {
	h[(i % 2) as usize].wrapping_add(i.wrapping_mul(h[2 + (((i + (i % 2)) % 4) / 2) as usize]))
}
