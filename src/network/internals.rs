//! Hooks used by the differential tests against the Go implementation.
//! Not a stable API.

use alloc::vec::Vec;

use super::bloomfilter::{BLOOM_FILTER_U, Bloom};
use super::config::Config;
use super::packetconn::PacketConn;
use super::pathfinder::{PathBroken, PathLookup, PathNotify, PathNotifyInfo};
use super::router::{RouterAnnounce, RouterSigReq, RouterSigRes};
use super::traffic::Traffic;
use super::wire::WireEncode;
use crate::types::{Error, Instant, PeerId, Platform, PrivateKey, PublicKey, SIGNATURE_SIZE};

/// The message kinds [`reencode`] understands.
pub const KINDS: [&str; 8] = [
	"sigreq", "sigres", "announce", "bloom", "lookup", "notify", "broken", "traffic",
];

fn encode(message: &dyn WireEncode) -> Vec<u8> {
	let mut out = Vec::new();
	message.encode(&mut out);
	debug_assert_eq!(out.len(), message.size());
	out
}

/// Decodes `data` as a `kind` message and encodes it again.
pub fn reencode(kind: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
	Ok(match kind {
		"sigreq" => encode(&RouterSigReq::decode(data)?),
		"sigres" => encode(&RouterSigRes::decode(data)?),
		"announce" => encode(&RouterAnnounce::decode(data)?),
		"bloom" => encode(&Bloom::decode(data)?),
		"lookup" => encode(&PathLookup::decode(data)?),
		"notify" => encode(&PathNotify::decode(data)?),
		"broken" => encode(&PathBroken::decode(data)?),
		"traffic" => encode(&Traffic::decode(data)?),
		_ => return Err(Error::UnrecognizedMessage),
	})
}

/// Runs the signature check for a decoded `kind` message. Messages without one always pass.
pub fn check(kind: &str, data: &[u8], node: &PublicKey, parent: &PublicKey) -> Result<bool, Error> {
	Ok(match kind {
		"sigres" => RouterSigRes::decode(data)?.check(node, parent),
		"announce" => RouterAnnounce::decode(data)?.check(),
		"notify" => PathNotify::decode(data)?.check(),
		_ => {
			reencode(kind, data)?;
			true
		}
	})
}

pub fn bloom_words(keys: &[PublicKey]) -> [u64; BLOOM_FILTER_U] {
	let mut bloom = Bloom::default();
	for key in keys {
		bloom.add_key(key);
	}
	bloom.words
}

/// Raw hash locations for arbitrary data, as `bloom.Locations` gives them.
pub fn bloom_locations(data: &[u8]) -> [u64; 8] {
	let h = super::murmur::base_hashes(data);
	core::array::from_fn(|i| super::murmur::location(&h, i as u64))
}

pub fn bloom_test(words: &[u64; BLOOM_FILTER_U], key: &PublicKey) -> bool {
	Bloom { words: *words }.test(key)
}

/// An encoded, signed announcement of `node`'s parent.
pub fn signed_announce(
	node: &PrivateKey,
	parent: &PrivateKey,
	seq: u64,
	nonce: u64,
	port: u64,
) -> Vec<u8> {
	let (node_key, parent_key) = (node.public_key(), parent.public_key());
	let mut res = RouterSigRes {
		req: RouterSigReq { seq, nonce },
		port,
		psig: [0; SIGNATURE_SIZE],
	};
	let bs = res.bytes_for_sig(&node_key, &parent_key);
	res.psig = parent.sign(&bs);
	encode(&RouterAnnounce {
		key: node_key,
		parent: parent_key,
		res,
		sig: node.sign(&bs),
	})
}

/// An encoded, signed pathNotify.
pub fn signed_notify(
	source: &PrivateKey,
	dest: &PublicKey,
	path: &[u64],
	watermark: u64,
	seq: u64,
	coords: &[u64],
) -> Vec<u8> {
	let mut info = PathNotifyInfo {
		seq,
		path: coords.to_vec(),
		sig: [0; SIGNATURE_SIZE],
	};
	info.sign(source);
	encode(&PathNotify {
		path: path.to_vec(),
		watermark,
		source: source.public_key(),
		dest: *dest,
		info,
	})
}

/// A platform with a frozen clock and a deterministic (insecure) random source.
pub struct FixedPlatform {
	counter: u64,
}

impl Platform for FixedPlatform {
	fn now(&self) -> Instant {
		Instant::default()
	}

	fn unix_time(&self) -> u64 {
		1
	}

	fn fill_random(&mut self, buf: &mut [u8]) {
		for byte in buf {
			self.counter = self
				.counter
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			*byte = (self.counter >> 56) as u8;
		}
	}
}

/// Direct access to the tree logic of a node with no live peers or timers.
pub struct RouterHarness {
	conn: PacketConn,
}

impl RouterHarness {
	pub fn new(secret: &PrivateKey) -> Result<Self, Error> {
		Ok(RouterHarness {
			conn: PacketConn::new(secret, FixedPlatform { counter: 0 }, Config::default())?,
		})
	}

	/// Applies a router announcement, returning whether it was accepted.
	pub fn update(&mut self, announce: &[u8]) -> Result<bool, Error> {
		let ann = RouterAnnounce::decode(announce)?;
		Ok(self.conn.core.router_update(&ann))
	}

	/// Adds a link to a peer with a given latency, returning its order.
	pub fn add_peer(&mut self, key: &PublicKey, prio: u8, lag_ms: u64) -> Result<u64, Error> {
		let id = self.conn.core.peers_add_peer(*key, prio)?;
		self.conn
			.core
			.router
			.lags
			.insert(id, (lag_ms * 1_000_000) as i64);
		Ok(id.0)
	}

	pub fn root_and_path(&mut self, key: &PublicKey) -> (PublicKey, Vec<u64>) {
		self.conn.core.router_get_root_and_path(key)
	}

	pub fn root_and_dists(&self, key: &PublicKey) -> (PublicKey, Vec<(PublicKey, u64)>, bool) {
		let (root, dists, valid) = self.conn.core.router_get_root_and_dists(key);
		(root, dists.into_iter().collect(), valid)
	}

	pub fn dist(&mut self, path: &[u64], key: &PublicKey) -> u64 {
		self.conn.core.router_get_dist(path, key)
	}

	pub fn ancestry(&self, key: &PublicKey) -> Vec<PublicKey> {
		self.conn.core.router_get_ancestry(key)
	}

	/// The key and order of the next hop towards `path`, and the updated watermark.
	pub fn lookup(
		&mut self,
		path: &[u64],
		watermark: Option<u64>,
	) -> (Option<(PublicKey, u64)>, Option<u64>) {
		let mut watermark = watermark;
		let id = self.conn.core.router_lookup(path, watermark.as_mut());
		let next = id.and_then(|id: PeerId| {
			self.conn
				.core
				.peers
				.get(id)
				.map(|peer| (peer.key, peer.order))
		});
		(next, watermark)
	}
}
