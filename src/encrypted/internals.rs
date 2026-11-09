//! Hooks used by the differential tests against the Go implementation.
//! Not a stable API.

use alloc::vec::Vec;

use super::crypto::{self, GroupAuth};
use super::session::SessionInit;
use crate::types::{PrivateKey, PublicKey};

pub fn ed_pub_to_box(key: &PublicKey) -> [u8; 32] {
	crypto::ed_pub_to_box(key)
}

pub fn ed_priv_to_box(key: &PrivateKey) -> [u8; 32] {
	crypto::ed_priv_to_box(key)
}

pub fn box_pub_for_priv(private: &[u8; 32]) -> [u8; 32] {
	crypto::box_pub_for_priv(private)
}

pub fn get_shared(public: &[u8; 32], private: &[u8; 32]) -> [u8; 32] {
	crypto::get_shared(public, private)
}

pub fn box_seal(msg: &[u8], nonce: u64, shared: &[u8; 32]) -> Vec<u8> {
	let mut out = Vec::new();
	crypto::box_seal(&mut out, msg, nonce, shared);
	out
}

pub fn box_open(boxed: &[u8], nonce: u64, shared: &[u8; 32]) -> Option<Vec<u8>> {
	crypto::box_open(boxed, nonce, shared)
}

/// Fields of a session handshake: current key, next key, key seq, and seq.
pub type SessionInitFields = ([u8; 32], [u8; 32], u64, u64);

/// Encrypts a session init from `from` to `to`, using the ephemeral private key `ephemeral`.
pub fn session_init_encrypt(
	from: &PrivateKey,
	to: &PublicKey,
	password: &str,
	(current, next, key_seq, seq): SessionInitFields,
	ephemeral: &[u8; 32],
) -> Vec<u8> {
	let init = SessionInit {
		current,
		next,
		key_seq,
		seq,
	};
	let ephemeral = (crypto::box_pub_for_priv(ephemeral), *ephemeral);
	init.encrypt(from, to, &GroupAuth::new(password), ephemeral)
}

pub fn session_init_decrypt(
	own: &PrivateKey,
	from: &PublicKey,
	data: &[u8],
	password: &str,
) -> Option<SessionInitFields> {
	let init = SessionInit::decrypt(
		&crypto::ed_priv_to_box(own),
		from,
		data,
		&GroupAuth::new(password),
	)?;
	Some((init.current, init.next, init.key_seq, init.seq))
}
