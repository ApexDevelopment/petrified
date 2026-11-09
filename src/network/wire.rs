//! Wire primitives shared by every protocol message.

use alloc::vec::Vec;

use crate::types::PublicKey;

pub(crate) type PeerPort = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum WirePacketType {
	Dummy = 0,
	KeepAlive = 1,
	ProtoSigReq = 2,
	ProtoSigRes = 3,
	ProtoAnnounce = 4,
	ProtoBloomFilter = 5,
	ProtoPathLookup = 6,
	ProtoPathNotify = 7,
	ProtoPathBroken = 8,
	Traffic = 9,
}

impl WirePacketType {
	pub(crate) fn from_byte(byte: u8) -> Option<Self> {
		Some(match byte {
			0 => Self::Dummy,
			1 => Self::KeepAlive,
			2 => Self::ProtoSigReq,
			3 => Self::ProtoSigRes,
			4 => Self::ProtoAnnounce,
			5 => Self::ProtoBloomFilter,
			6 => Self::ProtoPathLookup,
			7 => Self::ProtoPathNotify,
			8 => Self::ProtoPathBroken,
			9 => Self::Traffic,
			_ => return None,
		})
	}
}

pub(crate) const MAX_VARINT_LEN64: usize = 10;

/// Decodes a uvarint exactly like Go's `binary.Uvarint`, including its
/// acceptance of non-minimal encodings. Returns `None` on truncation or overflow.
pub(crate) fn uvarint(buf: &[u8]) -> Option<(u64, usize)> {
	let mut x: u64 = 0;
	let mut s: u32 = 0;
	for (i, &b) in buf.iter().enumerate() {
		if i == MAX_VARINT_LEN64 {
			return None;
		}
		if b < 0x80 {
			if i == MAX_VARINT_LEN64 - 1 && b > 1 {
				return None;
			}
			return Some((x | (b as u64) << s, i + 1));
		}
		x |= ((b & 0x7f) as u64) << s;
		s += 7;
	}
	None
}

pub(crate) fn wire_size_uint(mut u: u64) -> usize {
	let mut size = 1;
	while u >= 0x80 {
		u >>= 7;
		size += 1;
	}
	size
}

pub(crate) fn wire_append_uint(out: &mut Vec<u8>, mut u: u64) {
	while u >= 0x80 {
		out.push(u as u8 | 0x80);
		u >>= 7;
	}
	out.push(u as u8);
}

/// Writes a uvarint into the front of `out`, returning the number of bytes used.
pub(crate) fn put_uvarint(out: &mut [u8], mut u: u64) -> usize {
	let mut idx = 0;
	while u >= 0x80 {
		out[idx] = u as u8 | 0x80;
		u >>= 7;
		idx += 1;
	}
	out[idx] = u as u8;
	idx + 1
}

pub(crate) fn wire_chop_slice(out: &mut [u8], data: &mut &[u8]) -> bool {
	if data.len() < out.len() {
		return false;
	}
	out.copy_from_slice(&data[..out.len()]);
	*data = &data[out.len()..];
	true
}

pub(crate) fn wire_chop_key(out: &mut PublicKey, data: &mut &[u8]) -> bool {
	wire_chop_slice(&mut out.0, data)
}

pub(crate) fn wire_chop_uint(out: &mut u64, data: &mut &[u8]) -> bool {
	match uvarint(data) {
		Some((u, len)) => {
			*out = u;
			*data = &data[len..];
			true
		}
		None => false,
	}
}

pub(crate) fn wire_size_path(path: &[PeerPort]) -> usize {
	path.iter().map(|&port| wire_size_uint(port)).sum::<usize>() + wire_size_uint(0)
}

pub(crate) fn wire_append_path(out: &mut Vec<u8>, path: &[PeerPort]) {
	for &port in path {
		wire_append_uint(out, port);
	}
	wire_append_uint(out, 0);
}

pub(crate) fn wire_chop_path(out: &mut Vec<PeerPort>, data: &mut &[u8]) -> bool {
	let mut rest = *data;
	let start = out.len();
	loop {
		let mut u = 0;
		if !wire_chop_uint(&mut u, &mut rest) {
			out.truncate(start);
			return false;
		}
		if u == 0 {
			break;
		}
		out.push(u);
	}
	*data = rest;
	true
}

/// A message that can be written to the wire.
pub(crate) trait WireEncode {
	fn size(&self) -> usize;
	fn encode(&self, out: &mut Vec<u8>);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn uvarint_matches_go_edge_cases() {
		assert_eq!(uvarint(&[0x80, 0x00]), Some((0, 2)));
		assert_eq!(uvarint(&[0x80]), None);
		let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
		assert_eq!(uvarint(&max), Some((u64::MAX, 10)));
		let overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
		assert_eq!(uvarint(&overflow), None);
		let too_long = [
			0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
		];
		assert_eq!(uvarint(&too_long), None);
	}

	#[test]
	fn uint_round_trips() {
		for u in [0, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
			let mut out = Vec::new();
			wire_append_uint(&mut out, u);
			assert_eq!(out.len(), wire_size_uint(u));
			assert_eq!(uvarint(&out), Some((u, out.len())));
		}
	}
}
