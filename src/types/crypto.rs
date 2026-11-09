use curve25519_dalek::edwards::CompressedEdwardsY;

/// Rejects keys that are not canonical encodings of a curve point, and low-order points.
pub fn is_public_key_valid(key: &[u8; 32]) -> bool {
	let Some(point) = CompressedEdwardsY(*key).decompress() else {
		return false;
	};
	if point.compress().as_bytes() != key {
		return false;
	}
	!point.is_small_order()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rejects_invalid_keys() {
		let keys = [
			"0200000000000000000000000000000000000000000000000000000000000000",
			"0100000000000000000000000000000000000000000000000000000000000080",
			"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		];
		for key in keys {
			let bytes: [u8; 32] = hex::decode(key).unwrap().try_into().unwrap();
			assert!(
				!is_public_key_valid(&bytes),
				"key {key} should not be valid"
			);
		}
	}
}
