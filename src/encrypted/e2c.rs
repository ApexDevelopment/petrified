//! Conversion of ed25519 keys to curve25519 keys.
//!
//! The public key conversion uses plain arithmetic modulo 2^255-19 rather
//! than point decompression, so it gives the same answer as Go's `math/big`
//! version for every 32-byte input, including ones that are not curve points.

use sha2::{Digest, Sha512};

/// Little-endian 64-bit limbs, always kept below p.
type Fe = [u64; 4];

const P: Fe = [
	0xffffffffffffffed,
	0xffffffffffffffff,
	0xffffffffffffffff,
	0x7fffffffffffffff,
];
const ONE: Fe = [1, 0, 0, 0];

fn geq_p(a: &Fe) -> bool {
	for idx in (0..4).rev() {
		if a[idx] != P[idx] {
			return a[idx] > P[idx];
		}
	}
	true
}

fn sub_p(a: &mut Fe) {
	let mut borrow = 0u64;
	for idx in 0..4 {
		let (diff, b1) = a[idx].overflowing_sub(P[idx]);
		let (diff, b2) = diff.overflowing_sub(borrow);
		a[idx] = diff;
		borrow = (b1 | b2) as u64;
	}
}

/// Reduces a value below 2^256 to its canonical form.
fn reduce(mut a: Fe) -> Fe {
	// Fold bit 255 back in, since 2^255 = 19 (mod p)
	let top = a[3] >> 63;
	a[3] &= 0x7fffffffffffffff;
	let mut carry = top * 19;
	for limb in a.iter_mut() {
		let (sum, overflow) = limb.overflowing_add(carry);
		*limb = sum;
		carry = overflow as u64;
	}
	if geq_p(&a) {
		sub_p(&mut a);
	}
	a
}

fn add(a: &Fe, b: &Fe) -> Fe {
	let mut out = [0u64; 4];
	let mut carry = 0u64;
	for idx in 0..4 {
		let (sum, c1) = a[idx].overflowing_add(b[idx]);
		let (sum, c2) = sum.overflowing_add(carry);
		out[idx] = sum;
		carry = (c1 | c2) as u64;
	}
	// Both inputs are below p < 2^255, so the sum cannot overflow 256 bits
	reduce(out)
}

fn sub(a: &Fe, b: &Fe) -> Fe {
	let mut out = [0u64; 4];
	let mut borrow = 0u64;
	for idx in 0..4 {
		let (diff, b1) = a[idx].overflowing_sub(b[idx]);
		let (diff, b2) = diff.overflowing_sub(borrow);
		out[idx] = diff;
		borrow = (b1 | b2) as u64;
	}
	if borrow != 0 {
		// Wrapped below zero, so add p back
		let mut carry = 0u64;
		for idx in 0..4 {
			let (sum, c1) = out[idx].overflowing_add(P[idx]);
			let (sum, c2) = sum.overflowing_add(carry);
			out[idx] = sum;
			carry = (c1 | c2) as u64;
		}
	}
	out
}

fn mul(a: &Fe, b: &Fe) -> Fe {
	let mut wide = [0u64; 8];
	for i in 0..4 {
		let mut carry = 0u128;
		for j in 0..4 {
			let t = wide[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
			wide[i + j] = t as u64;
			carry = t >> 64;
		}
		wide[i + 4] = carry as u64;
	}
	// 2^256 = 38 (mod p), so fold the high half down
	let mut folded = [0u64; 5];
	let mut carry = 0u128;
	for idx in 0..4 {
		let t = wide[idx] as u128 + (wide[idx + 4] as u128) * 38 + carry;
		folded[idx] = t as u64;
		carry = t >> 64;
	}
	folded[4] = carry as u64;
	let mut out = [folded[0], folded[1], folded[2], folded[3]];
	let mut carry = (folded[4] as u128) * 38;
	for limb in out.iter_mut() {
		let t = *limb as u128 + carry;
		*limb = t as u64;
		carry = t >> 64;
	}
	if carry != 0 {
		// At most one more small wrap, again worth 38
		let mut carry = 38u128;
		for limb in out.iter_mut() {
			let t = *limb as u128 + carry;
			*limb = t as u64;
			carry = t >> 64;
		}
	}
	reduce(out)
}

/// a^(p-2), which is the inverse for nonzero a and zero for zero.
fn invert(a: &Fe) -> Fe {
	let mut exponent = P;
	exponent[0] -= 2;
	let mut result = ONE;
	for idx in (0..4).rev() {
		for bit in (0..64).rev() {
			result = mul(&result, &result);
			if (exponent[idx] >> bit) & 1 == 1 {
				result = mul(&result, a);
			}
		}
	}
	result
}

fn from_le_bytes(bytes: &[u8; 32]) -> Fe {
	core::array::from_fn(|idx| u64::from_le_bytes(bytes[idx * 8..idx * 8 + 8].try_into().unwrap()))
}

fn to_le_bytes(a: &Fe) -> [u8; 32] {
	let mut out = [0u8; 32];
	for (idx, limb) in a.iter().enumerate() {
		out[idx * 8..idx * 8 + 8].copy_from_slice(&limb.to_le_bytes());
	}
	out
}

/// Maps an ed25519 public key to the Montgomery u-coordinate u = (1 + y) / (1 - y).
pub(crate) fn ed25519_public_key_to_curve25519(pk: &[u8; 32]) -> [u8; 32] {
	let mut y = from_le_bytes(pk);
	// Drop the sign of x
	y[3] &= 0x7fffffffffffffff;
	let y = reduce(y);
	let numerator = add(&ONE, &y);
	let denominator = sub(&ONE, &y);
	to_le_bytes(&mul(&numerator, &invert(&denominator)))
}

/// The unclamped scalar ed25519 derives from the seed. X25519 clamps it on use.
pub(crate) fn ed25519_private_key_to_curve25519(seed: &[u8; 32]) -> [u8; 32] {
	let hash = Sha512::digest(seed);
	hash[..32].try_into().unwrap()
}

#[cfg(test)]
mod tests {
	use super::*;
	use curve25519_dalek::edwards::CompressedEdwardsY;

	#[test]
	fn matches_point_conversion_for_valid_keys() {
		for seed in 0u8..32 {
			let key = crate::types::PrivateKey::from_seed(&[seed; 32]).public_key();
			let expected = CompressedEdwardsY(key.0)
				.decompress()
				.unwrap()
				.to_montgomery()
				.to_bytes();
			assert_eq!(ed25519_public_key_to_curve25519(&key.0), expected);
		}
	}

	#[test]
	fn degenerate_y_maps_to_zero() {
		let mut one = [0u8; 32];
		one[0] = 1;
		assert_eq!(ed25519_public_key_to_curve25519(&one), [0u8; 32]);
	}

	#[test]
	fn field_inverse() {
		let a: Fe = [12345, 678, 9, 0x1234];
		assert_eq!(mul(&a, &invert(&a)), ONE);
	}
}
