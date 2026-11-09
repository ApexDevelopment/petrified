use alloc::vec::Vec;
use core::time::Duration;

use super::bloomfilter::BLOOM_FILTER_U;
use super::packetconn::Core;
use super::pathfinder::PathLookup;
use crate::types::{PeerId, PublicKey};

/// Read-only views of a node's internal state.
pub struct Debug<'a> {
	pub(crate) core: &'a Core,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugSelfInfo {
	pub key: PublicKey,
	pub routing_entries: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugPeerInfo {
	pub key: PublicKey,
	pub peer: PeerId,
	pub port: u64,
	pub cost: u64,
	pub priority: u8,
	pub rx: u64,
	pub tx: u64,
	pub latency: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugTreeInfo {
	pub key: PublicKey,
	pub parent: PublicKey,
	pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugPathInfo {
	pub key: PublicKey,
	pub path: Vec<u64>,
	pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugBloomInfo {
	pub key: PublicKey,
	pub send: [u64; BLOOM_FILTER_U],
	pub recv: [u64; BLOOM_FILTER_U],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugLookupInfo {
	pub key: PublicKey,
	pub path: Vec<u64>,
	pub target: PublicKey,
}

impl DebugLookupInfo {
	pub(crate) fn from_lookup(lookup: &PathLookup) -> Self {
		DebugLookupInfo {
			key: lookup.source,
			path: lookup.from.clone(),
			target: lookup.dest,
		}
	}
}

/// Rounds to the nearest 10µs, half away from zero, like Go's `Duration.Round`.
fn round_latency(rtt: Duration) -> Duration {
	const STEP: u128 = 10_000;
	let nanos = rtt.as_nanos();
	let rounded = (nanos + STEP / 2) / STEP * STEP;
	Duration::from_nanos(rounded as u64)
}

impl Debug<'_> {
	pub fn get_self(&self) -> DebugSelfInfo {
		DebugSelfInfo {
			key: self.core.crypto.public_key,
			routing_entries: self.core.router.infos.len() as u64,
		}
	}

	pub fn get_peers(&self) -> Vec<DebugPeerInfo> {
		self.core
			.peers
			.iter()
			.map(|(id, peer)| DebugPeerInfo {
				key: peer.key,
				peer: id,
				port: peer.port,
				cost: if self.core.router.lags.contains_key(&id) {
					self.core.router_get_cost(id)
				} else {
					0
				},
				priority: peer.prio,
				rx: peer.rx,
				tx: peer.tx,
				latency: round_latency(peer.srrt.saturating_duration_since(peer.srst)),
			})
			.collect()
	}

	pub fn get_tree(&self) -> Vec<DebugTreeInfo> {
		self.core
			.router
			.infos
			.iter()
			.map(|(key, info)| DebugTreeInfo {
				key: *key,
				parent: info.parent,
				sequence: info.res.req.seq,
			})
			.collect()
	}

	pub fn get_paths(&self) -> Vec<DebugPathInfo> {
		self.core
			.router
			.pathfinder
			.paths
			.iter()
			.map(|(key, info)| DebugPathInfo {
				key: *key,
				path: info.path.clone(),
				sequence: info.seq,
			})
			.collect()
	}

	pub fn get_blooms(&self) -> Vec<DebugBloomInfo> {
		self.core
			.router
			.blooms
			.blooms
			.iter()
			.map(|(key, info)| DebugBloomInfo {
				key: *key,
				send: info.send.words,
				recv: info.recv.words,
			})
			.collect()
	}

	/// The root this node currently believes in, and its coordinates under it.
	pub fn get_coords(&self) -> (PublicKey, Vec<u64>) {
		let core = self.core;
		let self_key = core.crypto.public_key;
		if let Some(cached) = core.router.cache.get(&self_key) {
			return (cached.root, cached.path.clone());
		}
		let mut path = Vec::new();
		let mut here = self_key;
		let mut visited = Vec::new();
		while let Some(info) = core.router.infos.get(&here) {
			if visited.contains(&here) {
				return (self_key, Vec::new());
			}
			visited.push(here);
			if info.parent == here {
				path.reverse();
				return (here, path);
			}
			path.push(info.res.port);
			here = info.parent;
		}
		(self_key, Vec::new())
	}
}
