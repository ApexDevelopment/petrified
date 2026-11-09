use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::time::Duration;

use super::bloomfilter::Blooms;
use super::packetconn::Core;
use super::pathfinder::Pathfinder;
use super::traffic::Traffic;
use super::wire::*;
use crate::types::{Error, Instant, PeerId, PublicKey, SIGNATURE_SIZE};

/// Latency in nanoseconds for a link that has not answered a request yet.
const ROUTER_UNKNOWN_LATENCY: i64 = u32::MAX as i64;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) type Signature = [u8; SIGNATURE_SIZE];

#[derive(Clone)]
pub(crate) struct RouterPath {
	pub root: PublicKey,
	pub path: Vec<PeerPort>,
}

#[derive(Default)]
pub(crate) struct Router {
	pub pathfinder: Pathfinder,
	pub blooms: Blooms,
	/// Every connection to each peer node.
	pub peers: BTreeMap<PublicKey, BTreeSet<PeerId>>,
	/// Which infos have been sent to each peer node.
	pub sent: BTreeMap<PublicKey, BTreeSet<PublicKey>>,
	pub ports: BTreeMap<PeerPort, PublicKey>,
	pub infos: BTreeMap<PublicKey, RouterInfo>,
	/// Refresh deadline for our own info, expiry deadline for everyone else's.
	pub timers: BTreeMap<PublicKey, Instant>,
	pub ancs: BTreeMap<PublicKey, Vec<PublicKey>>,
	pub cache: BTreeMap<PublicKey, RouterPath>,
	/// Exponentially weighted average response latency per link, in nanoseconds.
	pub lags: BTreeMap<PeerId, i64>,
	pub requests: BTreeMap<PublicKey, RouterSigReq>,
	pub responses: BTreeMap<PublicKey, RouterSigRes>,
	pub responded: BTreeSet<PeerId>,
	pub res_seqs: BTreeMap<PublicKey, u64>,
	pub res_seq_ctr: u64,
	pub refresh: bool,
	pub do_root1: bool,
	pub do_root2: bool,
	pub main_timer: Option<Instant>,
}

impl Core {
	pub(crate) fn router_init(&mut self) {
		self.pathfinder_init();
		self.router.main_timer = Some(self.now() + MAINTENANCE_INTERVAL);
		self.router.do_root2 = true;
		self.router_do_maintenance();
	}

	fn router_do_maintenance(&mut self) {
		if self.router.main_timer.is_none() {
			return;
		}
		self.router.do_root2 = self.router.do_root2 || self.router.do_root1;
		self.router.cache.clear();
		self.router_update_ancestries();
		self.router_fix();
		self.router_send_announces();
		self.blooms_do_maintenance();
		self.router.main_timer = Some(self.now() + MAINTENANCE_INTERVAL);
	}

	pub(crate) fn router_shutdown(&mut self) {
		self.router.main_timer = None;
	}

	pub(crate) fn router_peer_ids(&self, key: &PublicKey) -> Vec<PeerId> {
		self.router
			.peers
			.get(key)
			.map(|ps| ps.iter().copied().collect())
			.unwrap_or_default()
	}

	pub(crate) fn router_add_peer(&mut self, id: PeerId, key: PublicKey, port: PeerPort) {
		if let alloc::collections::btree_map::Entry::Vacant(e) = self.router.peers.entry(key) {
			e.insert(BTreeSet::new());
			self.router.sent.insert(key, BTreeSet::new());
			self.router.ports.insert(port, key);
			self.blooms_add_info(key);
		} else {
			// Send anything we've already sent over previous connections to this node
			let sent: Vec<PublicKey> = self.router.sent[&key].iter().copied().collect();
			for k in sent {
				if let Some(info) = self.router.infos.get(&k) {
					let ann = info.get_announce(k);
					self.peer_send_announce(id, &ann);
				}
			}
		}
		self.router.peers.get_mut(&key).unwrap().insert(id);
		self.router.lags.insert(id, ROUTER_UNKNOWN_LATENCY);
		if !self.router.requests.contains_key(&key) {
			let req = self.router_new_req();
			self.router.requests.insert(key, req);
		}
		let req = self.router.requests[&key];
		self.router.responded.remove(&id);
		self.peer_send_sig_req(id, &req);
		self.blooms_send_bloom(id, &key);
	}

	pub(crate) fn router_remove_peer(&mut self, id: PeerId, key: PublicKey, port: PeerPort) {
		let remaining: Vec<PeerId> = match self.router.peers.get_mut(&key) {
			Some(ps) => {
				ps.remove(&id);
				ps.iter().copied().collect()
			}
			None => Vec::new(),
		};
		self.router.lags.remove(&id);
		self.router.responded.remove(&id);
		if remaining.is_empty() {
			self.router.peers.remove(&key);
			self.router.sent.remove(&key);
			self.router.ports.remove(&port);
			self.router.requests.remove(&key);
			self.router.responses.remove(&key);
			self.router.res_seqs.remove(&key);
			self.router.ancs.remove(&key);
			self.router.cache.remove(&key);
			self.blooms_remove_info(&key);
		} else {
			// The bloom the remote node is tracking could be wrong due to a race
			for p in remaining {
				self.blooms_send_bloom(p, &key);
			}
		}
	}

	fn router_clear_reqs(&mut self) {
		self.router.requests.clear();
		self.router.responses.clear();
		self.router.res_seqs.clear();
		self.router.res_seq_ctr = 0;
	}

	fn router_send_reqs(&mut self) {
		self.router_clear_reqs();
		let keys: Vec<PublicKey> = self.router.peers.keys().copied().collect();
		for pk in keys {
			let req = self.router_new_req();
			self.router.requests.insert(pk, req);
			for id in self.router_peer_ids(&pk) {
				self.router.responded.remove(&id);
				self.peer_send_sig_req(id, &req);
			}
		}
	}

	fn router_update_ancestries(&mut self) {
		let keys: Vec<PublicKey> = self.router.peers.keys().copied().collect();
		for pkey in keys {
			let anc = self.router_get_ancestry(&pkey);
			if self.router.ancs.get(&pkey) != Some(&anc) {
				self.router.ancs.insert(pkey, anc);
			}
		}
	}

	pub(crate) fn router_get_cost(&self, id: PeerId) -> u64 {
		// Cost must be non-zero, since it is used in multiplication and division
		let lag = self.router.lags.get(&id).copied().unwrap_or(0);
		match (lag / 1_000_000) as u64 {
			0 => 1,
			cost => cost,
		}
	}

	fn router_fix(&mut self) {
		let self_key = self.crypto.public_key;
		let mut best_root = self_key;
		let mut best_parent = self_key;
		let mut best_cost = u64::MAX;
		let self_parent = self
			.router
			.infos
			.get(&self_key)
			.map(|info| info.parent)
			.unwrap_or_default();
		// Check if our current parent leads to a better root than ourself
		if self.router.peers.contains_key(&self_parent) {
			let (root, dists, valid) = self.router_get_root_and_dists(&self_key);
			// Only retain the current path when it reaches a confirmed root.
			if valid && root.less(&best_root) {
				let root_dist = dists[&root];
				let cost = self
					.router_peer_ids(&self_parent)
					.into_iter()
					.map(|id| root_dist.wrapping_mul(self.router_get_cost(id)))
					.fold(u64::MAX, u64::min);
				(best_root, best_parent, best_cost) = (root, self_parent, cost);
			}
		}
		// Check if we know a better root/parent
		let response_keys: Vec<PublicKey> = self.router.responses.keys().copied().collect();
		for pk in response_keys {
			if !self.router.infos.contains_key(&pk) {
				continue;
			}
			let (p_root, p_dists, valid) = self.router_get_root_and_dists(&pk);
			if !valid || p_dists.contains_key(&self_key) {
				// Incomplete, looping, or would loop through us
				continue;
			}
			let root_dist = p_dists[&p_root].wrapping_add(1);
			let cost = self
				.router_peer_ids(&pk)
				.into_iter()
				.map(|id| root_dist.wrapping_mul(self.router_get_cost(id)))
				.fold(u64::MAX, u64::min);
			if p_root.less(&best_root) {
				(best_root, best_parent, best_cost) = (p_root, pk, cost);
			} else if p_root != best_root {
				continue;
			}
			if (self.router.refresh && cost.wrapping_mul(2) < best_cost)
				|| (best_parent != self_parent && cost < best_cost)
			{
				(best_root, best_parent, best_cost) = (p_root, pk, cost);
			}
		}
		let router = &self.router;
		if router.refresh || router.do_root1 || router.do_root2 || self_parent != best_parent {
			let response = router.responses.get(&best_parent).cloned();
			let used_response = match response {
				Some(res) if best_root != self_key => self.router_use_response(best_parent, &res),
				_ => false,
			};
			if used_response {
				// Somebody else should be root
				self.router.refresh = false;
				self.router.do_root1 = false;
				self.router.do_root2 = false;
				self.router_send_reqs();
			} else if self.router.do_root2 {
				let became_root = self.router_become_root();
				debug_assert!(became_root);
				self.router.refresh = false;
				self.router.do_root1 = false;
				self.router.do_root2 = false;
				self.router_send_reqs();
			} else if !self.router.do_root1 {
				// Become root on the next maintenance unless something better shows up
				self.router.do_root1 = true;
			}
		}
	}

	fn router_send_announces(&mut self) {
		// This is insanely delicate, lots of correctness is implicit across how nodes behave.
		let self_anc = self.router_get_ancestry(&self.crypto.public_key);
		let peer_keys: Vec<PublicKey> = self.router.sent.keys().copied().collect();
		for peer_key in peer_keys {
			let peer_anc = self.router_get_ancestry(&peer_key);
			let sent = self.router.sent.get_mut(&peer_key).unwrap();
			let to_send: Vec<PublicKey> = self_anc
				.iter()
				.chain(peer_anc.iter())
				.filter(|&&k| sent.insert(k))
				.copied()
				.collect();
			let anns: Vec<RouterAnnounce> = to_send
				.into_iter()
				.filter_map(|k| self.router.infos.get(&k).map(|info| info.get_announce(k)))
				.collect();
			for id in self.router_peer_ids(&peer_key) {
				for ann in &anns {
					self.peer_send_announce(id, ann);
				}
			}
		}
	}

	fn router_new_req(&mut self) -> RouterSigReq {
		let mut nonce = [0u8; 8];
		self.platform.fill_random(&mut nonce);
		let seq = self
			.router
			.infos
			.get(&self.crypto.public_key)
			.map_or(0, |info| info.res.req.seq);
		RouterSigReq {
			seq: seq.wrapping_add(1),
			nonce: u64::from_be_bytes(nonce),
		}
	}

	fn router_become_root(&mut self) -> bool {
		let self_key = self.crypto.public_key;
		let req = self.router_new_req();
		let mut res = RouterSigRes {
			req,
			port: 0,
			psig: [0; SIGNATURE_SIZE],
		};
		res.psig = self
			.crypto
			.private_key
			.sign(&res.bytes_for_sig(&self_key, &self_key));
		let ann = RouterAnnounce {
			key: self_key,
			parent: self_key,
			sig: res.psig,
			res,
		};
		debug_assert!(ann.check());
		self.router_update(&ann)
	}

	pub(crate) fn router_handle_request(
		&mut self,
		id: PeerId,
		peer_key: PublicKey,
		port: PeerPort,
		req: RouterSigReq,
	) {
		let mut res = RouterSigRes {
			req,
			port,
			psig: [0; SIGNATURE_SIZE],
		};
		res.psig = self
			.crypto
			.private_key
			.sign(&res.bytes_for_sig(&peer_key, &self.crypto.public_key));
		self.peer_send_sig_res(id, &res);
	}

	pub(crate) fn router_handle_response(
		&mut self,
		id: PeerId,
		peer_key: PublicKey,
		res: RouterSigRes,
		rtt: Duration,
	) {
		if self
			.router
			.requests
			.get(&peer_key)
			.copied()
			.unwrap_or_default()
			!= res.req
		{
			return;
		}
		if !self.router.responses.contains_key(&peer_key) {
			self.router.res_seq_ctr += 1;
			self.router
				.res_seqs
				.insert(peer_key, self.router.res_seq_ctr);
			self.router.responses.insert(peer_key, res);
		}
		if self.router.responded.insert(id) {
			let rtt = i64::try_from(rtt.as_nanos()).unwrap_or(i64::MAX);
			let lag = self.router.lags.get(&id).copied().unwrap_or(0);
			let new_lag = if lag == ROUTER_UNKNOWN_LATENCY {
				// Start new links with a penalty to prioritize stability
				rtt.wrapping_mul(2)
			} else {
				lag.wrapping_mul(7) / 8 + rtt.min(lag.wrapping_mul(2)) / 8
			};
			self.router.lags.insert(id, new_lag);
		}
	}

	fn router_use_response(&mut self, peer_key: PublicKey, res: &RouterSigRes) -> bool {
		let bs = res.bytes_for_sig(&self.crypto.public_key, &peer_key);
		let info = RouterInfo {
			parent: peer_key,
			res: res.clone(),
			sig: self.crypto.private_key.sign(&bs),
		};
		let ann = info.get_announce(self.crypto.public_key);
		self.router_update(&ann)
	}

	pub(crate) fn router_update(&mut self, ann: &RouterAnnounce) -> bool {
		if let Some(info) = self.router.infos.get(&ann.key) {
			// This logic *must* be the same on every node, or peers can
			// infinitely spam announcements at each other for expired infos.
			let (info_seq, ann_seq) = (info.res.req.seq, ann.res.req.seq);
			let newer = if info_seq > ann_seq {
				false
			} else if info_seq < ann_seq {
				true
			} else if info.parent.less(&ann.parent) {
				false
			} else if ann.parent.less(&info.parent) {
				true
			} else {
				ann.res.req.nonce < info.res.req.nonce
			};
			if !newer {
				return false;
			}
		}
		// Clean up sent info and cache
		for sent in self.router.sent.values_mut() {
			sent.remove(&ann.key);
		}
		self.router.cache.clear();
		let info = RouterInfo {
			parent: ann.parent,
			res: ann.res.clone(),
			sig: ann.sig,
		};
		let delay = if ann.key == self.crypto.public_key {
			self.config.router_refresh
		} else {
			self.config.router_timeout
		};
		self.router.timers.insert(ann.key, self.now() + delay);
		self.router.infos.insert(ann.key, info);
		true
	}

	fn router_handle_info_timer(&mut self, key: PublicKey) {
		self.router.timers.remove(&key);
		if key == self.crypto.public_key {
			self.router.refresh = true;
		} else {
			self.router.infos.remove(&key);
			for sent in self.router.sent.values_mut() {
				sent.remove(&key);
			}
			self.router.cache.clear();
		}
	}

	pub(crate) fn router_handle_announce(
		&mut self,
		peer_key: PublicKey,
		id: PeerId,
		ann: RouterAnnounce,
	) {
		if self.router_update(&ann) {
			if ann.key == self.crypto.public_key {
				// Our own info came back from a peer, so we probably restarted and
				// our seq reset. Refresh, as if our refresh timer had passed.
				self.router.refresh = true;
			}
			// No point in sending this back to the original sender
			if let Some(sent) = self.router.sent.get_mut(&peer_key) {
				sent.insert(ann.key);
			}
			return;
		}
		// We didn't accept the info, because we already know it or something better
		let info = RouterInfo {
			parent: ann.parent,
			res: ann.res.clone(),
			sig: ann.sig,
		};
		if let Some(sent) = self.router.sent.get_mut(&peer_key) {
			sent.insert(ann.key);
		}
		let old_info = self.router.infos.get(&ann.key).cloned().unwrap_or_default();
		if info != old_info {
			// They sent something worse, so tell them what we know
			self.peer_send_announce(id, &old_info.get_announce(ann.key));
		}
	}

	pub(crate) fn router_send_traffic(&mut self, tr: Box<Traffic>) {
		self.pathfinder_handle_traffic(tr);
	}

	pub(crate) fn router_handle_traffic(&mut self, mut tr: Box<Traffic>) {
		let path = core::mem::take(&mut tr.path);
		let next = self.router_lookup(&path, Some(&mut tr.watermark));
		tr.path = path;
		if let Some(id) = next {
			self.peer_send_traffic(id, tr);
		} else if tr.dest == self.crypto.public_key {
			self.pathfinder_reset_timeout(&tr.source);
			self.pconn_handle_traffic(tr);
		} else {
			// Not addressed to us, and we don't know a next hop, so the path is broken
			self.pathfinder_do_broken(&tr);
		}
	}

	/// Returns each known ancestor's distance from `dest`. Only valid if the
	/// ancestry ends at a node that identifies itself as root.
	pub(crate) fn router_get_root_and_dists(
		&self,
		dest: &PublicKey,
	) -> (PublicKey, BTreeMap<PublicKey, u64>, bool) {
		let mut dists = BTreeMap::new();
		let mut next = *dest;
		let mut dist = 0u64;
		loop {
			if dists.contains_key(&next) {
				return (PublicKey::default(), dists, false);
			}
			let Some(info) = self.router.infos.get(&next) else {
				return (PublicKey::default(), dists, false);
			};
			dists.insert(next, dist);
			if info.parent == next {
				return (next, dists, true);
			}
			dist += 1;
			next = info.parent;
		}
	}

	/// Computes and caches the root and coordinates for `dest`, if it has a complete ancestry.
	fn router_cache_root_and_path(&mut self, dest: &PublicKey) {
		if self.router.cache.contains_key(dest) {
			return;
		}
		let mut ports = Vec::new();
		let mut visited = BTreeSet::new();
		let mut root;
		let mut next = *dest;
		loop {
			if !visited.insert(next) {
				return; // We hit a loop
			}
			let Some(info) = self.router.infos.get(&next) else {
				return; // We hit a dead end
			};
			root = next;
			if next == info.parent {
				break; // We reached a root, whose port is not part of the path
			}
			ports.push(info.res.port);
			next = info.parent;
		}
		ports.reverse();
		self.router
			.cache
			.insert(*dest, RouterPath { root, path: ports });
	}

	/// The cached result of [`Self::router_cache_root_and_path`], or `dest` with an empty path.
	fn router_cached_root_and_path(&self, dest: &PublicKey) -> (PublicKey, &[PeerPort]) {
		match self.router.cache.get(dest) {
			Some(cached) => (cached.root, &cached.path),
			None => (*dest, &[]),
		}
	}

	pub(crate) fn router_get_root_and_path(
		&mut self,
		dest: &PublicKey,
	) -> (PublicKey, Vec<PeerPort>) {
		self.router_cache_root_and_path(dest);
		let (root, path) = self.router_cached_root_and_path(dest);
		(root, path.to_vec())
	}

	pub(crate) fn router_get_dist(&mut self, dest_path: &[PeerPort], key: &PublicKey) -> u64 {
		let self_key = self.crypto.public_key;
		self.router_cache_root_and_path(key);
		self.router_cache_root_and_path(&self_key);
		let (root, key_path) = self.router_cached_root_and_path(key);
		if !self
			.router
			.infos
			.get(&root)
			.is_some_and(|info| info.parent == root)
		{
			// A failed ancestry walk is not the empty path of a real root.
			return u64::MAX;
		}
		if self.router_cached_root_and_path(&self_key).0 != root {
			// Coordinates from different roots are not comparable.
			return u64::MAX;
		}
		let mut dist = (key_path.len() + dest_path.len()) as u64;
		for (a, b) in key_path.iter().zip(dest_path.iter()) {
			if a != b {
				break;
			}
			dist -= 2;
		}
		dist
	}

	/// Finds the next hop (in tree space) towards `path`.
	pub(crate) fn router_lookup(
		&mut self,
		path: &[PeerPort],
		watermark: Option<&mut u64>,
	) -> Option<PeerId> {
		let mut best_dist = u64::MAX;
		if let Some(watermark) = watermark {
			let dist = self.router_get_dist(path, &self.crypto.public_key.clone());
			if dist < *watermark {
				// Self dist, so other nodes must be strictly better by distance
				best_dist = dist;
				*watermark = dist;
			} else {
				return None;
			}
		}
		// First work out which peers take us closer to the destination, ignoring
		// link costs altogether, to guarantee loop-free next hops.
		let mut candidates = Vec::new();
		let keys: Vec<PublicKey> = self.router.peers.keys().copied().collect();
		for k in keys {
			if self.router_get_dist(path, &k) < best_dist {
				candidates.extend(self.router_peer_ids(&k).into_iter().map(|id| (id, k)));
			}
		}
		// Then pick the best candidate, accounting for the link cost.
		struct Best {
			id: PeerId,
			key: PublicKey,
			prio: u8,
			order: u64,
			cost: u64,
			dist: u64,
		}
		let mut best: Option<Best> = None;
		for (id, key) in candidates {
			let Some(peer) = self.peers.get(id) else {
				continue;
			};
			let (prio, order) = (peer.prio, peer.order);
			let dist = self.router_get_dist(path, &key);
			let cost = self.router_get_cost(id);
			let accept = match &best {
				None => true,
				Some(b) if key == b.key && prio < b.prio => true,
				Some(b) if key == b.key && prio > b.prio => false,
				Some(b) => {
					// Minimize link cost times remaining distance, then distance, then cost, then age.
					let (score, best_score) =
						(cost.wrapping_mul(dist), b.cost.wrapping_mul(b.dist));
					if score != best_score {
						score < best_score
					} else if dist != b.dist {
						dist < b.dist
					} else if cost != b.cost {
						cost < b.cost
					} else {
						order < b.order
					}
				}
			};
			if accept {
				best = Some(Best {
					id,
					key,
					prio,
					order,
					cost,
					dist,
				});
			}
		}
		best.map(|b| b.id)
	}

	/// The ancestry of `key`, starting from the root side.
	pub(crate) fn router_get_ancestry(&self, key: &PublicKey) -> Vec<PublicKey> {
		let mut anc = self.router_backwards_ancestry(key);
		anc.reverse();
		anc
	}

	/// The ancestry of `key`, from `key` to the root (or the end of the line).
	fn router_backwards_ancestry(&self, key: &PublicKey) -> Vec<PublicKey> {
		let mut anc = Vec::new();
		let mut here = *key;
		while !anc.contains(&here) {
			let Some(info) = self.router.infos.get(&here) else {
				break;
			};
			anc.push(here);
			here = info.parent;
		}
		anc
	}

	pub(crate) fn router_next_timeout(&self) -> Option<Instant> {
		let info_timer = self.router.timers.values().min().copied();
		[self.router.main_timer, info_timer]
			.into_iter()
			.flatten()
			.min()
	}

	pub(crate) fn router_handle_timeouts(&mut self, now: Instant) {
		let expired: Vec<PublicKey> = self
			.router
			.timers
			.iter()
			.filter(|&(_, &deadline)| deadline <= now)
			.map(|(&key, _)| key)
			.collect();
		for key in expired {
			self.router_handle_info_timer(key);
		}
		if self
			.router
			.main_timer
			.is_some_and(|deadline| deadline <= now)
		{
			self.router_do_maintenance();
		}
	}
}

/*****************
 * routerSigReq *
 *****************/

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RouterSigReq {
	pub seq: u64,
	pub nonce: u64,
}

impl RouterSigReq {
	pub(crate) fn bytes_for_sig(&self, node: &PublicKey, parent: &PublicKey) -> Vec<u8> {
		let mut out = Vec::with_capacity(32 * 2 + 10 + 10 + 10);
		out.extend_from_slice(&node.0);
		out.extend_from_slice(&parent.0);
		self.encode(&mut out);
		out
	}

	fn chop(data: &mut &[u8]) -> Result<Self, Error> {
		let mut rest = *data;
		let mut req = RouterSigReq::default();
		if !wire_chop_uint(&mut req.seq, &mut rest) || !wire_chop_uint(&mut req.nonce, &mut rest) {
			return Err(Error::Decode);
		}
		*data = rest;
		Ok(req)
	}

	pub(crate) fn decode(mut data: &[u8]) -> Result<Self, Error> {
		let req = Self::chop(&mut data)?;
		if !data.is_empty() {
			return Err(Error::Decode);
		}
		Ok(req)
	}
}

impl WireEncode for RouterSigReq {
	fn size(&self) -> usize {
		wire_size_uint(self.seq) + wire_size_uint(self.nonce)
	}

	fn encode(&self, out: &mut Vec<u8>) {
		wire_append_uint(out, self.seq);
		wire_append_uint(out, self.nonce);
	}
}

/*****************
 * routerSigRes *
 *****************/

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterSigRes {
	pub req: RouterSigReq,
	pub port: PeerPort,
	pub psig: Signature,
}

impl Default for RouterSigRes {
	fn default() -> Self {
		RouterSigRes {
			req: RouterSigReq::default(),
			port: 0,
			psig: [0; SIGNATURE_SIZE],
		}
	}
}

impl RouterSigRes {
	pub(crate) fn check(&self, node: &PublicKey, parent: &PublicKey) -> bool {
		if self.port == 0 && node != parent {
			return false;
		}
		parent.verify(&self.bytes_for_sig(node, parent), &self.psig)
	}

	pub(crate) fn bytes_for_sig(&self, node: &PublicKey, parent: &PublicKey) -> Vec<u8> {
		let mut bs = self.req.bytes_for_sig(node, parent);
		wire_append_uint(&mut bs, self.port);
		bs
	}

	fn chop(data: &mut &[u8]) -> Result<Self, Error> {
		let mut rest = *data;
		let mut res = RouterSigRes {
			req: RouterSigReq::chop(&mut rest)?,
			..Default::default()
		};
		if !wire_chop_uint(&mut res.port, &mut rest) || !wire_chop_slice(&mut res.psig, &mut rest) {
			return Err(Error::Decode);
		}
		*data = rest;
		Ok(res)
	}

	pub(crate) fn decode(mut data: &[u8]) -> Result<Self, Error> {
		let res = Self::chop(&mut data)?;
		if !data.is_empty() {
			return Err(Error::Decode);
		}
		Ok(res)
	}
}

impl WireEncode for RouterSigRes {
	fn size(&self) -> usize {
		self.req.size() + wire_size_uint(self.port) + SIGNATURE_SIZE
	}

	fn encode(&self, out: &mut Vec<u8>) {
		self.req.encode(out);
		wire_append_uint(out, self.port);
		out.extend_from_slice(&self.psig);
	}
}

/*******************
 * routerAnnounce *
 *******************/

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAnnounce {
	pub key: PublicKey,
	pub parent: PublicKey,
	pub res: RouterSigRes,
	pub sig: Signature,
}

impl RouterAnnounce {
	pub(crate) fn check(&self) -> bool {
		if self.res.port == 0 && self.key != self.parent {
			return false;
		}
		let bs = self.res.bytes_for_sig(&self.key, &self.parent);
		self.key.verify(&bs, &self.sig) && self.parent.verify(&bs, &self.res.psig)
	}

	pub(crate) fn decode(mut data: &[u8]) -> Result<Self, Error> {
		let mut key = PublicKey::default();
		let mut parent = PublicKey::default();
		if !wire_chop_key(&mut key, &mut data) || !wire_chop_key(&mut parent, &mut data) {
			return Err(Error::Decode);
		}
		let res = RouterSigRes::chop(&mut data)?;
		let mut sig = [0u8; SIGNATURE_SIZE];
		if !wire_chop_slice(&mut sig, &mut data) || !data.is_empty() {
			return Err(Error::Decode);
		}
		Ok(RouterAnnounce {
			key,
			parent,
			res,
			sig,
		})
	}
}

impl WireEncode for RouterAnnounce {
	fn size(&self) -> usize {
		32 + 32 + self.res.size() + SIGNATURE_SIZE
	}

	fn encode(&self, out: &mut Vec<u8>) {
		out.extend_from_slice(&self.key.0);
		out.extend_from_slice(&self.parent.0);
		self.res.encode(out);
		out.extend_from_slice(&self.sig);
	}
}

/***************
 * routerInfo *
 ***************/

/// The value stored for each node in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterInfo {
	pub parent: PublicKey,
	pub res: RouterSigRes,
	pub sig: Signature,
}

impl Default for RouterInfo {
	fn default() -> Self {
		RouterInfo {
			parent: PublicKey::default(),
			res: RouterSigRes::default(),
			sig: [0; SIGNATURE_SIZE],
		}
	}
}

impl RouterInfo {
	pub(crate) fn get_announce(&self, key: PublicKey) -> RouterAnnounce {
		RouterAnnounce {
			key,
			parent: self.parent,
			res: self.res.clone(),
			sig: self.sig,
		}
	}
}
