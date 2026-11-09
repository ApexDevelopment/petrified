use alloc::vec::Vec;

use super::murmur::{base_hashes, location};
use super::packetconn::Core;
use super::packetqueue::PqPacket;
use super::wire::*;
use crate::types::{Error, PeerId, PublicKey};

/// Bytes of flags in the wire format, one bit per backing word.
pub(crate) const BLOOM_FILTER_F: usize = 16;
/// Number of u64 words in the backing array.
pub const BLOOM_FILTER_U: usize = BLOOM_FILTER_F * 8;
const BLOOM_FILTER_B: usize = BLOOM_FILTER_U * 8;
const BLOOM_FILTER_M: u64 = (BLOOM_FILTER_B * 8) as u64;
/// Hashes per inserted key.
const BLOOM_FILTER_K: u64 = 8;

/// A fixed-size bloom filter, bit-compatible with the `bits-and-blooms/bloom` filter Ironwood uses.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Bloom {
	pub words: [u64; BLOOM_FILTER_U],
}

impl Default for Bloom {
	fn default() -> Self {
		Bloom {
			words: [0; BLOOM_FILTER_U],
		}
	}
}

impl Bloom {
	pub(crate) fn add_key(&mut self, key: &PublicKey) {
		let h = base_hashes(&key.0);
		for i in 0..BLOOM_FILTER_K {
			let bit = location(&h, i) % BLOOM_FILTER_M;
			self.words[(bit / 64) as usize] |= 1 << (bit % 64);
		}
	}

	pub(crate) fn test(&self, key: &PublicKey) -> bool {
		let h = base_hashes(&key.0);
		(0..BLOOM_FILTER_K).all(|i| {
			let bit = location(&h, i) % BLOOM_FILTER_M;
			self.words[(bit / 64) as usize] & (1 << (bit % 64)) != 0
		})
	}

	pub(crate) fn add_filter(&mut self, other: &Bloom) {
		for (word, other_word) in self.words.iter_mut().zip(other.words.iter()) {
			*word |= other_word;
		}
	}

	pub(crate) fn decode(mut data: &[u8]) -> Result<Self, Error> {
		let mut flags0 = [0u8; BLOOM_FILTER_F];
		let mut flags1 = [0u8; BLOOM_FILTER_F];
		if !wire_chop_slice(&mut flags0, &mut data) || !wire_chop_slice(&mut flags1, &mut data) {
			return Err(Error::Decode);
		}
		let mut bloom = Bloom::default();
		for idx in 0..BLOOM_FILTER_U {
			let mask = 0x80u8 >> (idx % 8);
			let flag0 = flags0[idx / 8] & mask != 0;
			let flag1 = flags1[idx / 8] & mask != 0;
			bloom.words[idx] = match (flag0, flag1) {
				(true, true) => return Err(Error::Decode),
				(true, false) => 0,
				(false, true) => u64::MAX,
				(false, false) if data.len() >= 8 => {
					let word = u64::from_be_bytes(data[..8].try_into().unwrap());
					data = &data[8..];
					word
				}
				(false, false) => return Err(Error::Decode),
			};
		}
		if !data.is_empty() {
			return Err(Error::Decode);
		}
		Ok(bloom)
	}
}

impl WireEncode for Bloom {
	fn size(&self) -> usize {
		let kept = self
			.words
			.iter()
			.filter(|&&u| u != 0 && u != u64::MAX)
			.count();
		BLOOM_FILTER_F * 2 + kept * 8
	}

	fn encode(&self, out: &mut Vec<u8>) {
		let mut flags0 = [0u8; BLOOM_FILTER_F];
		let mut flags1 = [0u8; BLOOM_FILTER_F];
		for (idx, &u) in self.words.iter().enumerate() {
			if u == 0 {
				flags0[idx / 8] |= 0x80 >> (idx % 8);
			} else if u == u64::MAX {
				flags1[idx / 8] |= 0x80 >> (idx % 8);
			}
		}
		out.extend_from_slice(&flags0);
		out.extend_from_slice(&flags1);
		for &u in self.words.iter().filter(|&&u| u != 0 && u != u64::MAX) {
			out.extend_from_slice(&u.to_be_bytes());
		}
	}
}

/*****************************
 * router bloom filter stuff *
 *****************************/

#[derive(Clone, Default)]
pub(crate) struct BloomInfo {
	pub send: Bloom,
	pub recv: Bloom,
	/// Forces a filter to be resent once an hour.
	pub seq: u16,
	pub on_tree: bool,
	pub z_dirty: bool,
}

#[derive(Default)]
pub(crate) struct Blooms {
	pub blooms: alloc::collections::BTreeMap<PublicKey, BloomInfo>,
}

impl Core {
	pub(crate) fn blooms_is_on_tree(&self, key: &PublicKey) -> bool {
		self.router
			.blooms
			.blooms
			.get(key)
			.is_some_and(|info| info.on_tree)
	}

	fn blooms_fix_on_tree(&mut self) {
		let self_key = self.crypto.public_key;
		let Some(self_parent) = self.router.infos.get(&self_key).map(|info| info.parent) else {
			debug_assert!(false, "no self info during bloom maintenance");
			return;
		};
		let keys: Vec<PublicKey> = self.router.blooms.blooms.keys().copied().collect();
		for pk in keys {
			let parent_is_self = self
				.router
				.infos
				.get(&pk)
				.map(|info| info.parent == self_key);
			let pbi = self.router.blooms.blooms.get_mut(&pk).unwrap();
			let was_on = pbi.on_tree;
			pbi.on_tree = self_parent == pk || parent_is_self == Some(true);
			if was_on && !pbi.on_tree {
				// Send a blank filter, so the link doesn't start with false positives if it returns to the tree.
				pbi.send = Bloom::default();
				let blank = pbi.send.clone();
				for id in self.router_peer_ids(&pk) {
					self.peer_send_bloom(id, &blank);
				}
			}
		}
	}

	pub(crate) fn x_key(&self, key: &PublicKey) -> PublicKey {
		(self.config.bloom_transform)(key)
	}

	pub(crate) fn blooms_add_info(&mut self, key: PublicKey) {
		self.router.blooms.blooms.insert(key, BloomInfo::default());
	}

	pub(crate) fn blooms_remove_info(&mut self, key: &PublicKey) {
		self.router.blooms.blooms.remove(key);
	}

	pub(crate) fn blooms_handle_bloom(&mut self, from_key: &PublicKey, bloom: Bloom) {
		if let Some(pbi) = self.router.blooms.blooms.get_mut(from_key) {
			pbi.recv = bloom;
		}
	}

	pub(crate) fn blooms_do_maintenance(&mut self) {
		self.blooms_fix_on_tree();
		self.blooms_send_all_blooms();
	}

	fn blooms_get_bloom_for(&mut self, key: &PublicKey, keep_ones: bool) -> (Bloom, bool) {
		let mut bloom = Bloom::default();
		bloom.add_key(&self.x_key(&self.crypto.public_key));
		for (k, pbi) in &self.router.blooms.blooms {
			if pbi.on_tree && k != key {
				bloom.add_filter(&pbi.recv);
			}
		}
		let pbi = self
			.router
			.blooms
			.blooms
			.get_mut(key)
			.expect("bloom info for peer");
		if keep_ones {
			// Keep existing 1 bits, so 1s travel faster than 0s, to help prevent flapping.
			if !pbi.z_dirty {
				let before = bloom.clone();
				bloom.add_filter(&pbi.send);
				if bloom != before {
					pbi.z_dirty = true;
				}
			} else {
				bloom.add_filter(&pbi.send);
			}
		} else {
			pbi.z_dirty = false;
		}
		let is_new = bloom != pbi.send;
		if is_new {
			pbi.send = bloom.clone();
		}
		(bloom, is_new)
	}

	pub(crate) fn blooms_send_bloom(&mut self, id: PeerId, key: &PublicKey) {
		let bloom = self
			.router
			.blooms
			.blooms
			.get(key)
			.map(|pbi| pbi.send.clone())
			.unwrap_or_default();
		self.peer_send_bloom(id, &bloom);
	}

	fn blooms_send_all_blooms(&mut self) {
		let keys: Vec<PublicKey> = self.router.blooms.blooms.keys().copied().collect();
		for k in keys {
			let pbi = &self.router.blooms.blooms[&k];
			if !pbi.on_tree {
				continue;
			}
			let keep_ones = !pbi.z_dirty;
			let (bloom, is_new) = self.blooms_get_bloom_for(&k, keep_ones);
			let pbi = self.router.blooms.blooms.get_mut(&k).unwrap();
			pbi.seq += 1;
			if is_new || pbi.seq >= 3600 {
				pbi.seq = 0;
				for id in self.router_peer_ids(&k) {
					self.peer_send_bloom(id, &bloom);
				}
			}
		}
	}

	pub(crate) fn blooms_send_multicast(
		&mut self,
		packet: &PqPacket,
		from_key: &PublicKey,
		to_key: &PublicKey,
	) {
		let xform = self.x_key(to_key);
		let mut targets = Vec::new();
		for (k, pbi) in &self.router.blooms.blooms {
			if !pbi.on_tree || k == from_key || !pbi.recv.test(&xform) {
				continue;
			}
			let best = self
				.router_peer_ids(k)
				.into_iter()
				.filter_map(|id| self.peers.get(id).map(|p| (p.prio, id)))
				.min_by_key(|&(prio, _)| prio);
			if let Some((_, id)) = best {
				targets.push(id);
			}
		}
		for id in targets {
			self.peer_send_queued(id, packet.clone());
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn round_trip(bloom: &Bloom) {
		let mut buf = Vec::new();
		bloom.encode(&mut buf);
		assert_eq!(buf.len(), bloom.size());
		assert!(Bloom::decode(&buf).unwrap() == *bloom);
	}

	#[test]
	fn encoding_round_trips() {
		let mut bloom = Bloom::default();
		round_trip(&bloom);
		let mut key = PublicKey::default();
		bloom.add_key(&key);
		for idx in 0..32 {
			key.0[idx] = !key.0[idx];
			bloom.add_key(&key);
			assert!(bloom.test(&key));
		}
		round_trip(&bloom);
		bloom.words = [u64::MAX; BLOOM_FILTER_U];
		round_trip(&bloom);
	}
}
