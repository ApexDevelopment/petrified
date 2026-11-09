use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const PRIVATE_KEY_SIZE: usize = 64;
pub const SIGNATURE_SIZE: usize = 64;

/// An ed25519 public key. Its `Display` form is lowercase hex, like Go's `types.Addr`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
	pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
		&self.0
	}

	/// Verifies an ed25519 signature with the same rules as Go's `ed25519.Verify`.
	pub fn verify(&self, message: &[u8], sig: &[u8; SIGNATURE_SIZE]) -> bool {
		let Ok(key) = VerifyingKey::from_bytes(&self.0) else {
			return false;
		};
		key.verify(message, &Signature::from_bytes(sig)).is_ok()
	}

	/// Bytewise comparison, matching Ironwood's `publicKey.less`.
	pub fn less(&self, other: &PublicKey) -> bool {
		self.0 < other.0
	}
}

impl From<[u8; PUBLIC_KEY_SIZE]> for PublicKey {
	fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
		PublicKey(bytes)
	}
}

impl AsRef<[u8]> for PublicKey {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl fmt::Display for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		for byte in self.0 {
			write!(f, "{byte:02x}")?;
		}
		Ok(())
	}
}

impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "PublicKey({self})")
	}
}

/// An ed25519 private key in Go's 64-byte layout: the seed followed by the public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey(pub [u8; PRIVATE_KEY_SIZE]);

impl PrivateKey {
	pub fn from_seed(seed: &[u8; 32]) -> Self {
		let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
		let mut bytes = [0u8; PRIVATE_KEY_SIZE];
		bytes[..32].copy_from_slice(seed);
		bytes[32..].copy_from_slice(&public);
		PrivateKey(bytes)
	}

	pub fn seed(&self) -> &[u8; 32] {
		self.0[..32].try_into().unwrap()
	}

	/// The public key derived from the seed, like Go's `PrivateKey.Public()`.
	pub fn public_key(&self) -> PublicKey {
		PublicKey(
			SigningKey::from_bytes(self.seed())
				.verifying_key()
				.to_bytes(),
		)
	}

	pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
		SigningKey::from_bytes(self.seed()).sign(message).to_bytes()
	}
}

impl fmt::Debug for PrivateKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "PrivateKey({})", self.public_key())
	}
}
