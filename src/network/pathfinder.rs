use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::debug::DebugLookupInfo;
use super::packetconn::Core;
use super::packetqueue::PqPacket;
use super::router::Signature;
use super::traffic::Traffic;
use super::wire::*;
use crate::types::{Error, Instant, PrivateKey, PublicKey, SIGNATURE_SIZE};

pub(crate) type LookupLogger = Box<dyn FnMut(&DebugLookupInfo) + Send>;

#[derive(Default)]
pub(crate) struct Pathfinder {
	/// Our most recently signed coordinates.
	pub info: PathNotifyInfo,
	pub paths: BTreeMap<PublicKey, PathInfo>,
	/// Keyed by the bloom-transformed destination key.
	pub rumors: BTreeMap<PublicKey, PathRumor>,
	pub logger: Option<LookupLogger>,
}

pub(crate) struct PathInfo {
	/// Not zero terminated, and must be free of zeros.
	pub path: Vec<PeerPort>,
	pub seq: u64,
	/// When a lookup was last sent, to prevent spamming.
	pub req_time: Instant,
	/// Expiry deadline, pushed back whenever we receive traffic from this node.
	pub timer: Instant,
	pub traffic: Option<Box<Traffic>>,
	/// Set by a pathBroken, which stops the timer from being reset until a new notify arrives.
	pub broken: bool,
}

pub(crate) struct PathRumor {
	pub traffic: Option<Box<Traffic>>,
	/// When a lookup was last sent, to prevent spamming.
	pub send_time: Instant,
	pub timer: Instant,
}

impl Core {
	pub(crate) fn pathfinder_init(&mut self) {
		let mut info = PathNotifyInfo::default();
		info.sign(&self.crypto.private_key);
		self.router.pathfinder.info = info;
	}

	fn pathfinder_send_lookup(&mut self, dest: PublicKey) {
		let now = self.now();
		let throttle = self.config.path_throttle;
		if let Some(info) = self.router.pathfinder.paths.get_mut(&dest) {
			if now.saturating_duration_since(info.req_time) < throttle {
				return;
			}
			info.req_time = now;
		}
		let self_key = self.crypto.public_key;
		let (_, from) = self.router_get_root_and_path(&self_key);
		let lookup = PathLookup {
			source: self_key,
			dest,
			from,
		};
		self.pathfinder_handle_lookup_from(self_key, lookup);
	}

	pub(crate) fn pathfinder_handle_lookup(&mut self, peer_key: PublicKey, lookup: PathLookup) {
		if !self.blooms_is_on_tree(&peer_key) {
			return;
		}
		self.pathfinder_handle_lookup_from(peer_key, lookup);
	}

	fn pathfinder_handle_lookup_from(&mut self, from_key: PublicKey, lookup: PathLookup) {
		if let Some(logger) = self.router.pathfinder.logger.as_mut() {
			logger(&DebugLookupInfo::from_lookup(&lookup));
		}
		// Continue the multicast
		self.blooms_send_multicast(&PqPacket::Lookup(lookup.clone()), &from_key, &lookup.dest);
		// Check if we should send a response too
		let self_key = self.crypto.public_key;
		if self.x_key(&lookup.dest) != self.x_key(&self_key) {
			return;
		}
		let (_, path) = self.router_get_root_and_path(&self_key);
		let mut notify = PathNotify {
			path: lookup.from,
			watermark: u64::MAX,
			source: self_key,
			dest: lookup.source,
			info: PathNotifyInfo {
				seq: self.platform.unix_time(),
				path,
				sig: [0; SIGNATURE_SIZE],
			},
		};
		if !self.router.pathfinder.info.equal(&notify.info) {
			notify.info.sign(&self.crypto.private_key);
			self.router.pathfinder.info = notify.info.clone();
		} else {
			notify.info = self.router.pathfinder.info.clone();
		}
		self.pathfinder_handle_notify(notify);
	}

	pub(crate) fn pathfinder_handle_notify(&mut self, mut notify: PathNotify) {
		let path = core::mem::take(&mut notify.path);
		let next = self.router_lookup(&path, Some(&mut notify.watermark));
		notify.path = path;
		if let Some(id) = next {
			self.peer_send_queued(id, PqPacket::Notify(notify));
			return;
		}
		// Check if we should accept this response
		if notify.dest != self.crypto.public_key {
			return;
		}
		let now = self.now();
		let path_timeout = self.config.path_timeout;
		let mut info = match self.router.pathfinder.paths.remove(&notify.source) {
			Some(info) => {
				let reject = notify.info.seq <= info.seq
					// Only the seq changed, so this adds nothing new
					|| info.path == notify.info.path
					|| !notify.check();
				if reject {
					self.router.pathfinder.paths.insert(notify.source, info);
					return;
				}
				PathInfo {
					timer: now + path_timeout,
					..info
				}
			}
			None => {
				let xform = self.x_key(&notify.source);
				if !self.router.pathfinder.rumors.contains_key(&xform) || !notify.check() {
					return;
				}
				let rumor = self.router.pathfinder.rumors.get_mut(&xform).unwrap();
				let traffic = match &rumor.traffic {
					Some(tr) if tr.dest == notify.source => rumor.traffic.take(),
					_ => None,
				};
				PathInfo {
					path: Vec::new(),
					seq: 0,
					req_time: now,
					timer: now + path_timeout,
					traffic,
					broken: false,
				}
			}
		};
		info.path = notify.info.path;
		info.seq = notify.info.seq;
		info.broken = false;
		let pending = info.traffic.take();
		self.router.pathfinder.paths.insert(notify.source, info);
		(self.config.path_notify)(&notify.source);
		if let Some(tr) = pending {
			self.pathfinder_handle_traffic(tr);
		}
	}

	pub(crate) fn pathfinder_rumor_send_lookup(&mut self, dest: PublicKey) {
		let now = self.now();
		let xform = self.x_key(&dest);
		let (throttle, timeout) = (self.config.path_throttle, self.config.path_timeout);
		match self.router.pathfinder.rumors.get_mut(&xform) {
			Some(rumor) => {
				if now.saturating_duration_since(rumor.send_time) < throttle {
					return;
				}
				rumor.send_time = now;
				rumor.timer = now + timeout;
			}
			None => {
				self.router.pathfinder.rumors.insert(
					xform,
					PathRumor {
						traffic: None,
						send_time: now,
						timer: now + timeout,
					},
				);
			}
		}
		self.pathfinder_send_lookup(dest);
	}

	pub(crate) fn pathfinder_handle_traffic(&mut self, mut tr: Box<Traffic>) {
		if let Some(info) = self.router.pathfinder.paths.get(&tr.dest) {
			tr.path.clone_from(&info.path);
			let (_, from) = self.router_get_root_and_path(&self.crypto.public_key.clone());
			tr.from = from;
			// Keep a copy, so it can be resent if the path changes
			if let Some(info) = self.router.pathfinder.paths.get_mut(&tr.dest) {
				info.traffic = Some(tr.clone());
			}
			self.router_handle_traffic(tr);
		} else {
			self.pathfinder_rumor_send_lookup(tr.dest);
			let xform = self.x_key(&tr.dest);
			if let Some(rumor) = self.router.pathfinder.rumors.get_mut(&xform) {
				rumor.traffic = Some(tr);
			}
		}
	}

	pub(crate) fn pathfinder_do_broken(&mut self, tr: &Traffic) {
		let broken = PathBroken {
			path: tr.from.clone(),
			watermark: u64::MAX,
			source: tr.source,
			dest: tr.dest,
		};
		self.pathfinder_handle_broken(broken);
	}

	pub(crate) fn pathfinder_handle_broken(&mut self, mut broken: PathBroken) {
		let path = core::mem::take(&mut broken.path);
		let next = self.router_lookup(&path, Some(&mut broken.watermark));
		broken.path = path;
		if let Some(id) = next {
			self.peer_send_queued(id, PqPacket::Broken(broken));
			return;
		}
		// Check if we should accept this pathBroken
		if broken.source != self.crypto.public_key {
			return;
		}
		if let Some(info) = self.router.pathfinder.paths.get_mut(&broken.dest) {
			info.broken = true;
			self.pathfinder_send_lookup(broken.dest); // Throttled inside
		}
	}

	/// Call when receiving a packet from `key`. Sending must not reset it, so
	/// paths still time out if e.g. a node restarts and resets its seqs.
	pub(crate) fn pathfinder_reset_timeout(&mut self, key: &PublicKey) {
		let deadline = self.now() + self.config.path_timeout;
		if let Some(info) = self.router.pathfinder.paths.get_mut(key)
			&& !info.broken
		{
			info.timer = deadline;
		}
	}

	pub(crate) fn pathfinder_next_timeout(&self) -> Option<Instant> {
		let pf = &self.router.pathfinder;
		let paths = pf.paths.values().map(|info| info.timer);
		let rumors = pf.rumors.values().map(|rumor| rumor.timer);
		paths.chain(rumors).min()
	}

	pub(crate) fn pathfinder_handle_timeouts(&mut self, now: Instant) {
		let pf = &mut self.router.pathfinder;
		pf.paths.retain(|_, info| info.timer > now);
		pf.rumors.retain(|_, rumor| rumor.timer > now);
	}
}

/**************
 * pathLookup *
 **************/

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PathLookup {
	pub source: PublicKey,
	pub dest: PublicKey,
	pub from: Vec<PeerPort>,
}

impl WireEncode for PathLookup {
	fn size(&self) -> usize {
		32 + 32 + wire_size_path(&self.from)
	}

	fn encode(&self, out: &mut Vec<u8>) {
		out.extend_from_slice(&self.source.0);
		out.extend_from_slice(&self.dest.0);
		wire_append_path(out, &self.from);
	}
}

impl PathLookup {
	pub(crate) fn decode(mut data: &[u8]) -> Result<Self, Error> {
		let mut lookup = PathLookup::default();
		if !wire_chop_key(&mut lookup.source, &mut data)
			|| !wire_chop_key(&mut lookup.dest, &mut data)
			|| !wire_chop_path(&mut lookup.from, &mut data)
			|| !data.is_empty()
		{
			return Err(Error::Decode);
		}
		Ok(lookup)
	}
}

/******************
 * pathNotifyInfo *
 ******************/

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PathNotifyInfo {
	pub seq: u64,
	/// Path from the root to the source, aka coords.
	pub path: Vec<PeerPort>,
	/// Signature from the source key.
	pub sig: Signature,
}

impl Default for PathNotifyInfo {
	fn default() -> Self {
		PathNotifyInfo {
			seq: 0,
			path: Vec::new(),
			sig: [0; SIGNATURE_SIZE],
		}
	}
}

impl PathNotifyInfo {
	/// Compares seq and path, ignoring the signature.
	pub(crate) fn equal(&self, other: &PathNotifyInfo) -> bool {
		self.seq == other.seq && self.path == other.path
	}

	pub(crate) fn bytes_for_sig(&self) -> Vec<u8> {
		let mut out = Vec::new();
		wire_append_uint(&mut out, self.seq);
		wire_append_path(&mut out, &self.path);
		out
	}

	pub(crate) fn sign(&mut self, key: &PrivateKey) {
		self.sig = key.sign(&self.bytes_for_sig());
	}

	pub(crate) fn decode(mut data: &[u8]) -> Result<Self, Error> {
		let mut info = PathNotifyInfo::default();
		if !wire_chop_uint(&mut info.seq, &mut data)
			|| !wire_chop_path(&mut info.path, &mut data)
			|| !wire_chop_slice(&mut info.sig, &mut data)
			|| !data.is_empty()
		{
			return Err(Error::Decode);
		}
		Ok(info)
	}
}

impl WireEncode for PathNotifyInfo {
	fn size(&self) -> usize {
		wire_size_uint(self.seq) + wire_size_path(&self.path) + SIGNATURE_SIZE
	}

	fn encode(&self, out: &mut Vec<u8>) {
		wire_append_uint(out, self.seq);
		wire_append_path(out, &self.path);
		out.extend_from_slice(&self.sig);
	}
}

/**************
 * pathNotify *
 **************/

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PathNotify {
	pub path: Vec<PeerPort>,
	pub watermark: u64,
	/// Who sent the response, not who requested it.
	pub source: PublicKey,
	/// Exact key we are sending the response to.
	pub dest: PublicKey,
	pub info: PathNotifyInfo,
}

impl PathNotify {
	pub(crate) fn check(&self) -> bool {
		self.source
			.verify(&self.info.bytes_for_sig(), &self.info.sig)
	}

	pub(crate) fn decode(mut data: &[u8]) -> Result<Self, Error> {
		let mut notify = PathNotify::default();
		if !wire_chop_path(&mut notify.path, &mut data)
			|| !wire_chop_uint(&mut notify.watermark, &mut data)
			|| !wire_chop_key(&mut notify.source, &mut data)
			|| !wire_chop_key(&mut notify.dest, &mut data)
		{
			return Err(Error::Decode);
		}
		notify.info = PathNotifyInfo::decode(data)?;
		Ok(notify)
	}
}

impl WireEncode for PathNotify {
	fn size(&self) -> usize {
		wire_size_path(&self.path) + wire_size_uint(self.watermark) + 32 + 32 + self.info.size()
	}

	fn encode(&self, out: &mut Vec<u8>) {
		wire_append_path(out, &self.path);
		wire_append_uint(out, self.watermark);
		out.extend_from_slice(&self.source.0);
		out.extend_from_slice(&self.dest.0);
		self.info.encode(out);
	}
}

/**************
 * pathBroken *
 **************/

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PathBroken {
	pub path: Vec<PeerPort>,
	pub watermark: u64,
	pub source: PublicKey,
	pub dest: PublicKey,
}

impl PathBroken {
	pub(crate) fn decode(mut data: &[u8]) -> Result<Self, Error> {
		let mut broken = PathBroken::default();
		if !wire_chop_path(&mut broken.path, &mut data)
			|| !wire_chop_uint(&mut broken.watermark, &mut data)
			|| !wire_chop_key(&mut broken.source, &mut data)
			|| !wire_chop_key(&mut broken.dest, &mut data)
			|| !data.is_empty()
		{
			return Err(Error::Decode);
		}
		Ok(broken)
	}
}

impl WireEncode for PathBroken {
	fn size(&self) -> usize {
		wire_size_path(&self.path) + wire_size_uint(self.watermark) + 32 + 32
	}

	fn encode(&self, out: &mut Vec<u8>) {
		wire_append_path(out, &self.path);
		wire_append_uint(out, self.watermark);
		out.extend_from_slice(&self.source.0);
		out.extend_from_slice(&self.dest.0);
	}
}
