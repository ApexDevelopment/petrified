use alloc::vec::Vec;

use curve25519_dalek::montgomery::MontgomeryPoint;
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use salsa20::XSalsa20;
use salsa20::cipher::{KeyIvInit, StreamCipher, consts::U10};
use sha2::{Digest, Sha256};

use super::e2c;
use crate::types::{Platform, PrivateKey, PublicKey, SIGNATURE_SIZE, is_public_key_valid};

pub(crate) const BOX_PUB_SIZE: usize = 32;
pub(crate) const BOX_OVERHEAD: usize = 16;
pub(crate) const ED_SIG_SIZE: usize = SIGNATURE_SIZE;

pub(crate) type BoxPub = [u8; BOX_PUB_SIZE];
pub(crate) type BoxPriv = [u8; 32];
pub(crate) type BoxShared = [u8; 32];
pub(crate) type EdSig = [u8; ED_SIG_SIZE];

/******
 * ed *
 ******/

pub(crate) fn ed_sign(msg: &[u8], key: &PrivateKey, preimage: &[u8]) -> EdSig {
	if preimage.is_empty() {
		return key.sign(msg);
	}
	let mut full = Vec::with_capacity(preimage.len() + msg.len());
	full.extend_from_slice(preimage);
	full.extend_from_slice(msg);
	key.sign(&full)
}

pub(crate) fn ed_check(msg: &[u8], sig: &EdSig, key: &PublicKey, preimage: &[u8]) -> bool {
	if !is_public_key_valid(&key.0) {
		return false;
	}
	if preimage.is_empty() {
		return key.verify(msg, sig);
	}
	let mut full = Vec::with_capacity(preimage.len() + msg.len());
	full.extend_from_slice(preimage);
	full.extend_from_slice(msg);
	key.verify(&full, sig)
}

pub(crate) fn ed_pub_to_box(key: &PublicKey) -> BoxPub {
	e2c::ed25519_public_key_to_curve25519(&key.0)
}

pub(crate) fn ed_priv_to_box(key: &PrivateKey) -> BoxPriv {
	e2c::ed25519_private_key_to_curve25519(key.seed())
}

/*******
 * box *
 *******/

pub(crate) fn box_pub_for_priv(private: &BoxPriv) -> BoxPub {
	MontgomeryPoint::mul_base_clamped(*private).to_bytes()
}

pub(crate) fn new_box_keys(platform: &mut dyn Platform) -> (BoxPub, BoxPriv) {
	let mut private = [0u8; 32];
	platform.fill_random(&mut private);
	(box_pub_for_priv(&private), private)
}

/// NaCl's `box.Precompute`: HSalsa20 over the X25519 shared point.
pub(crate) fn get_shared(public: &BoxPub, private: &BoxPriv) -> BoxShared {
	let point = MontgomeryPoint(*public).mul_clamped(*private).to_bytes();
	salsa20::hsalsa::<U10>(&point.into(), &[0u8; 16].into()).into()
}

pub(crate) fn nonce_for_u64(nonce: u64) -> [u8; 24] {
	let mut out = [0u8; 24];
	out[16..].copy_from_slice(&nonce.to_be_bytes());
	out
}

/// Encrypts `msg` with XSalsa20-Poly1305 and appends `tag || ciphertext` to `out`.
pub(crate) fn box_seal(out: &mut Vec<u8>, msg: &[u8], nonce: u64, shared: &BoxShared) {
	let mut cipher = XSalsa20::new(&(*shared).into(), &nonce_for_u64(nonce).into());
	let mut poly_key = [0u8; 32];
	cipher.apply_keystream(&mut poly_key);
	let start = out.len();
	out.extend_from_slice(&[0u8; BOX_OVERHEAD]);
	out.extend_from_slice(msg);
	cipher.apply_keystream(&mut out[start + BOX_OVERHEAD..]);
	let tag = Poly1305::new(&poly_key.into()).compute_unpadded(&out[start + BOX_OVERHEAD..]);
	out[start..start + BOX_OVERHEAD].copy_from_slice(&tag);
}

/// Authenticates and decrypts `tag || ciphertext`.
pub(crate) fn box_open(boxed: &[u8], nonce: u64, shared: &BoxShared) -> Option<Vec<u8>> {
	if boxed.len() < BOX_OVERHEAD {
		return None;
	}
	let (tag, ciphertext) = boxed.split_at(BOX_OVERHEAD);
	let mut cipher = XSalsa20::new(&(*shared).into(), &nonce_for_u64(nonce).into());
	let mut poly_key = [0u8; 32];
	cipher.apply_keystream(&mut poly_key);
	let expected = Poly1305::new(&poly_key.into()).compute_unpadded(ciphertext);
	let mismatch = expected
		.iter()
		.zip(tag)
		.fold(0u8, |acc, (a, b)| acc | (a ^ b));
	if mismatch != 0 {
		return None;
	}
	let mut msg = ciphertext.to_vec();
	cipher.apply_keystream(&mut msg);
	Some(msg)
}

/*********
 * group *
 *********/

/// Optional password authentication, folded into the handshake signature preimage.
#[derive(Clone, Default)]
pub(crate) struct GroupAuth {
	secret: Option<[u8; 32]>,
}

impl GroupAuth {
	pub(crate) fn new(password: &str) -> Self {
		if password.is_empty() {
			return GroupAuth::default();
		}
		let mut hasher = Sha256::new();
		hasher.update(b"ironwood/encrypted\x00");
		hasher.update(password.as_bytes());
		GroupAuth {
			secret: Some(hasher.finalize().into()),
		}
	}

	pub(crate) fn preimage(&self) -> &[u8] {
		self.secret.as_ref().map_or(&[], |secret| secret)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn box_round_trips() {
		let shared = [7u8; 32];
		let mut sealed = Vec::new();
		box_seal(&mut sealed, b"hello", 3, &shared);
		assert_eq!(sealed.len(), 5 + BOX_OVERHEAD);
		assert_eq!(box_open(&sealed, 3, &shared).unwrap(), b"hello");
		assert!(box_open(&sealed, 4, &shared).is_none());
	}

	#[test]
	fn ed_keys_convert_to_matching_box_keys() {
		let ed = PrivateKey::from_seed(&[9; 32]);
		let box_priv = ed_priv_to_box(&ed);
		assert_eq!(box_pub_for_priv(&box_priv), ed_pub_to_box(&ed.public_key()));
	}
}
