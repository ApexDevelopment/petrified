use alloc::vec::Vec;

use super::wire::*;
use crate::types::{Error, PublicKey};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Traffic {
	/// Not zero terminated.
	pub path: Vec<PeerPort>,
	pub from: Vec<PeerPort>,
	pub source: PublicKey,
	pub dest: PublicKey,
	pub watermark: u64,
	pub payload: Vec<u8>,
}

impl WireEncode for Traffic {
	fn size(&self) -> usize {
		wire_size_path(&self.path)
			+ wire_size_path(&self.from)
			+ 32 + 32 + wire_size_uint(self.watermark)
			+ self.payload.len()
	}

	fn encode(&self, out: &mut Vec<u8>) {
		wire_append_path(out, &self.path);
		wire_append_path(out, &self.from);
		out.extend_from_slice(&self.source.0);
		out.extend_from_slice(&self.dest.0);
		wire_append_uint(out, self.watermark);
		out.extend_from_slice(&self.payload);
	}
}

impl Traffic {
	pub(crate) fn decode(mut data: &[u8]) -> Result<Self, Error> {
		let mut tr = Traffic::default();
		if !wire_chop_path(&mut tr.path, &mut data)
			|| !wire_chop_path(&mut tr.from, &mut data)
			|| !wire_chop_key(&mut tr.source, &mut data)
			|| !wire_chop_key(&mut tr.dest, &mut data)
			|| !wire_chop_uint(&mut tr.watermark, &mut data)
		{
			return Err(Error::Decode);
		}
		tr.payload = data.to_vec();
		Ok(tr)
	}
}
