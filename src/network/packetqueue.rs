use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::heap::{self, HeapInterface};
use super::pathfinder::{PathBroken, PathLookup, PathNotify};
use super::traffic::Traffic;
use super::wire::{WireEncode, WirePacketType};
use crate::types::{Instant, PublicKey};

/// A packet that is sent through a peer's queue rather than written directly.
#[derive(Clone, Debug)]
pub(crate) enum PqPacket {
	Traffic(Box<Traffic>),
	Lookup(PathLookup),
	Notify(PathNotify),
	Broken(PathBroken),
}

impl PqPacket {
	pub(crate) fn wire_type(&self) -> WirePacketType {
		match self {
			PqPacket::Traffic(_) => WirePacketType::Traffic,
			PqPacket::Lookup(_) => WirePacketType::ProtoPathLookup,
			PqPacket::Notify(_) => WirePacketType::ProtoPathNotify,
			PqPacket::Broken(_) => WirePacketType::ProtoPathBroken,
		}
	}

	pub(crate) fn source_key(&self) -> PublicKey {
		match self {
			PqPacket::Traffic(tr) => tr.source,
			PqPacket::Lookup(lookup) => lookup.source,
			PqPacket::Notify(notify) => notify.source,
			PqPacket::Broken(broken) => broken.source,
		}
	}

	pub(crate) fn dest_key(&self) -> PublicKey {
		match self {
			PqPacket::Traffic(tr) => tr.dest,
			PqPacket::Lookup(lookup) => lookup.dest,
			PqPacket::Notify(notify) => notify.dest,
			PqPacket::Broken(broken) => broken.dest,
		}
	}

	pub(crate) fn encodeable(&self) -> &dyn WireEncode {
		match self {
			PqPacket::Traffic(tr) => tr.as_ref(),
			PqPacket::Lookup(lookup) => lookup,
			PqPacket::Notify(notify) => notify,
			PqPacket::Broken(broken) => broken,
		}
	}
}

pub(crate) struct PqPacketInfo {
	pub packet: PqPacket,
	pub size: u64,
	pub time: Instant,
}

struct PqSource {
	key: PublicKey,
	infos: VecDeque<PqPacketInfo>,
	size: u64,
}

struct PqDest {
	key: PublicKey,
	sources: Vec<PqSource>,
	size: u64,
}

/// Per-destination, per-source packet queues. When full, the oldest packet of
/// the largest flow to the largest destination is dropped first.
#[derive(Default)]
pub(crate) struct PacketQueue {
	dests: Vec<PqDest>,
	pub size: u64,
}

struct DestHeap<'a>(&'a mut Vec<PqDest>);
struct SourceHeap<'a>(&'a mut Vec<PqSource>);

impl HeapInterface for DestHeap<'_> {
	fn len(&self) -> usize {
		self.0.len()
	}
	fn less(&self, i: usize, j: usize) -> bool {
		self.0[i].sources[0].infos[0].time < self.0[j].sources[0].infos[0].time
	}
	fn swap(&mut self, i: usize, j: usize) {
		self.0.swap(i, j);
	}
	fn pop_last(&mut self) {
		self.0.pop();
	}
}

impl HeapInterface for SourceHeap<'_> {
	fn len(&self) -> usize {
		self.0.len()
	}
	fn less(&self, i: usize, j: usize) -> bool {
		self.0[i].infos[0].time < self.0[j].infos[0].time
	}
	fn swap(&mut self, i: usize, j: usize) {
		self.0.swap(i, j);
	}
	fn pop_last(&mut self) {
		self.0.pop();
	}
}

fn index_of_largest(sizes: impl Iterator<Item = u64>) -> usize {
	let mut best_idx = 0;
	let mut best_size = 0;
	for (idx, size) in sizes.enumerate() {
		if idx == 0 || size > best_size {
			best_idx = idx;
			best_size = size;
		}
	}
	best_idx
}

impl PacketQueue {
	/// Removes the oldest packet from the largest source queue of the largest destination.
	pub(crate) fn drop_packet(&mut self) -> bool {
		if self.size == 0 {
			return false;
		}
		let d_idx = index_of_largest(self.dests.iter().map(|d| d.size));
		let dest = &mut self.dests[d_idx];
		let s_idx = index_of_largest(dest.sources.iter().map(|s| s.size));
		let source = &mut dest.sources[s_idx];
		let info = source.infos.pop_front().expect("non-empty source queue");
		source.size -= info.size;
		if source.size > 0 {
			heap::fix(&mut SourceHeap(&mut dest.sources), s_idx);
		} else {
			heap::remove(&mut SourceHeap(&mut dest.sources), s_idx);
		}
		dest.size -= info.size;
		if dest.size > 0 {
			heap::fix(&mut DestHeap(&mut self.dests), d_idx);
		} else {
			heap::remove(&mut DestHeap(&mut self.dests), d_idx);
		}
		self.size -= info.size;
		true
	}

	pub(crate) fn push(&mut self, packet: PqPacket, now: Instant) {
		let source_key = packet.source_key();
		let dest_key = packet.dest_key();
		let size = packet.encodeable().size() as u64;
		let info = PqPacketInfo {
			packet,
			size,
			time: now,
		};
		let d_idx = match self.dests.iter().position(|d| d.key == dest_key) {
			Some(idx) => idx,
			None => {
				self.dests.push(PqDest {
					key: dest_key,
					sources: Vec::new(),
					size: 0,
				});
				self.dests.len() - 1
			}
		};
		let dest = &mut self.dests[d_idx];
		let s_idx = match dest.sources.iter().position(|s| s.key == source_key) {
			Some(idx) => idx,
			None => {
				dest.sources.push(PqSource {
					key: source_key,
					infos: VecDeque::new(),
					size: 0,
				});
				dest.sources.len() - 1
			}
		};
		let source = &mut dest.sources[s_idx];
		source.infos.push_back(info);
		source.size += size;
		dest.size += size;
		self.size += size;
	}

	/// Removes and returns the oldest packet across all source/destination pairs.
	pub(crate) fn pop(&mut self) -> Option<PqPacketInfo> {
		if self.size == 0 {
			return None;
		}
		let dest = &mut self.dests[0];
		let source = &mut dest.sources[0];
		let info = source.infos.pop_front().expect("non-empty source queue");
		source.size -= info.size;
		dest.size -= info.size;
		self.size -= info.size;
		if !source.infos.is_empty() {
			heap::fix(&mut SourceHeap(&mut dest.sources), 0);
		} else {
			heap::remove(&mut SourceHeap(&mut dest.sources), 0);
		}
		if !dest.sources.is_empty() {
			heap::fix(&mut DestHeap(&mut self.dests), 0);
		} else {
			heap::remove(&mut DestHeap(&mut self.dests), 0);
		}
		Some(info)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::time::Duration;

	fn traffic(source: u8, dest: u8, payload_len: usize) -> PqPacket {
		PqPacket::Traffic(Box::new(Traffic {
			source: PublicKey([source; 32]),
			dest: PublicKey([dest; 32]),
			payload: alloc::vec![0; payload_len],
			..Default::default()
		}))
	}

	fn at(ms: u64) -> Instant {
		Instant::from_duration(Duration::from_millis(ms))
	}

	#[test]
	fn pops_oldest_first() {
		let mut q = PacketQueue::default();
		q.push(traffic(1, 2, 10), at(1));
		q.push(traffic(3, 4, 10), at(2));
		q.push(traffic(1, 2, 10), at(3));
		q.push(traffic(5, 2, 10), at(4));
		let order: Vec<_> = core::iter::from_fn(|| q.pop()).map(|i| i.time).collect();
		assert_eq!(order, [at(1), at(2), at(3), at(4)]);
		assert_eq!(q.size, 0);
	}

	#[test]
	fn drops_from_largest_flow() {
		let mut q = PacketQueue::default();
		q.push(traffic(1, 2, 10), at(1));
		q.push(traffic(3, 4, 100), at(2));
		q.push(traffic(3, 4, 100), at(3));
		q.push(traffic(5, 4, 10), at(4));
		assert!(q.drop_packet());
		let remaining: Vec<_> = core::iter::from_fn(|| q.pop()).map(|i| i.time).collect();
		assert_eq!(remaining, [at(1), at(3), at(4)]);
		assert!(!q.drop_packet());
	}
}
