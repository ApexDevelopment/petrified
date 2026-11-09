//! Helpers shared by the interop tests: building and driving the Go harness.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

use petrified::types::{PrivateKey, PublicKey};
use serde_json::Value;

/// Builds the Go harness once per test binary and returns its path.
pub fn harness_bin() -> PathBuf {
	static BIN: OnceLock<PathBuf> = OnceLock::new();
	BIN.get_or_init(|| {
		let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		let exe = std::env::current_exe().unwrap();
		let name = exe.file_stem().unwrap().to_string_lossy().into_owned();
		let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("interop-go-{name}"));
		let status = Command::new("sh")
			.arg(root.join("interop/build.sh"))
			.arg(&out)
			.status()
			.expect("failed to run interop/build.sh");
		assert!(
			status.success(),
			"building the Go harness failed; these tests need a Go toolchain (set GO=/path/to/go if it is not on PATH)"
		);
		out.join("harness-bin")
	})
	.clone()
}

/// A deterministic random number generator (splitmix64), so failures can be reproduced.
pub struct Rng(u64);

impl Rng {
	pub fn new(seed: u64) -> Self {
		Rng(seed)
	}

	pub fn next_u64(&mut self) -> u64 {
		self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
		let mut z = self.0;
		z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
		z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
		z ^ (z >> 31)
	}

	pub fn below(&mut self, n: u64) -> u64 {
		self.next_u64() % n
	}

	pub fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
		self.below(denominator) < numerator
	}

	pub fn bytes(&mut self, len: usize) -> Vec<u8> {
		(0..len).map(|_| self.next_u64() as u8).collect()
	}

	pub fn array<const N: usize>(&mut self) -> [u8; N] {
		self.bytes(N).try_into().unwrap()
	}

	pub fn private_key(&mut self) -> PrivateKey {
		PrivateKey::from_seed(&self.array())
	}
}

pub fn hex_key(key: &PublicKey) -> String {
	hex::encode(key.0)
}

pub fn parse_key(s: &str) -> PublicKey {
	PublicKey(hex::decode(s).unwrap().try_into().unwrap())
}

/// The harness in `vectors` mode, answering one JSON request per line.
pub struct Vectors {
	io: Mutex<(Child, ChildStdin, BufReader<ChildStdout>)>,
}

impl Vectors {
	pub fn spawn() -> Self {
		let mut child = Command::new(harness_bin())
			.arg("vectors")
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn()
			.expect("failed to start the Go harness");
		let stdin = child.stdin.take().unwrap();
		let stdout = BufReader::new(child.stdout.take().unwrap());
		Vectors {
			io: Mutex::new((child, stdin, stdout)),
		}
	}

	pub fn call(&self, request: Value) -> Value {
		let mut io = self.io.lock().unwrap();
		let (_, stdin, stdout) = &mut *io;
		writeln!(stdin, "{request}").unwrap();
		stdin.flush().unwrap();
		let mut line = String::new();
		stdout.read_line(&mut line).unwrap();
		serde_json::from_str(&line)
			.unwrap_or_else(|_| panic!("bad harness reply {line:?} to {request}"))
	}
}

impl Drop for Vectors {
	fn drop(&mut self) {
		if let Ok(mut io) = self.io.lock() {
			let _ = io.0.kill();
			let _ = io.0.wait();
		}
	}
}
