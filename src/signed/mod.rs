//! Signed (but not encrypted) packets on top of [`crate::network`], mirroring Ironwood's `signed` package.

use alloc::vec::Vec;

use crate::network::{self, Config};
use crate::types::{
	self, Error, Event, Instant, PacketConn as _, PeerId, Platform, PrivateKey, PublicKey,
	SIGNATURE_SIZE,
};

/// An Ironwood node that signs every packet for its destination and drops packets with bad signatures.
pub struct PacketConn {
	net: network::PacketConn,
}

impl PacketConn {
	pub fn new(
		secret: &PrivateKey,
		platform: impl Platform + Send + 'static,
		config: Config,
	) -> Result<Self, Error> {
		Ok(PacketConn {
			net: network::PacketConn::new(secret, platform, config)?,
		})
	}

	pub fn network(&self) -> &network::PacketConn {
		&self.net
	}

	fn sign(&self, to_key: &PublicKey, msg: &[u8]) -> Vec<u8> {
		let mut sig_bytes = Vec::with_capacity(32 + msg.len());
		sig_bytes.extend_from_slice(&to_key.0);
		sig_bytes.extend_from_slice(msg);
		let mut out = Vec::with_capacity(SIGNATURE_SIZE + msg.len());
		out.extend_from_slice(&self.net.private_key().sign(&sig_bytes));
		out.extend_from_slice(msg);
		out
	}

	fn unpack(&self, bs: &[u8], from_key: &PublicKey) -> Option<Vec<u8>> {
		if bs.len() < SIGNATURE_SIZE {
			return None;
		}
		let (sig, msg) = bs.split_at(SIGNATURE_SIZE);
		let mut sig_bytes = Vec::with_capacity(32 + msg.len());
		sig_bytes.extend_from_slice(&self.net.public_key().0);
		sig_bytes.extend_from_slice(msg);
		from_key
			.verify(&sig_bytes, sig.try_into().unwrap())
			.then(|| msg.to_vec())
	}
}

impl types::PacketConn for PacketConn {
	fn handle_conn(&mut self, key: &PublicKey, prio: u8) -> Result<PeerId, Error> {
		self.net.handle_conn(key, prio)
	}

	fn handle_peer_data(&mut self, peer: PeerId, data: &[u8]) -> Result<(), Error> {
		self.net.handle_peer_data(peer, data)
	}

	fn peer_transmit(&self, peer: PeerId) -> &[u8] {
		self.net.peer_transmit(peer)
	}

	fn peer_consume(&mut self, peer: PeerId, n: usize) {
		self.net.peer_consume(peer, n);
	}

	fn remove_peer(&mut self, peer: PeerId) -> Result<(), Error> {
		self.net.remove_peer(peer)
	}

	fn read_from(&mut self, buf: &mut [u8]) -> Option<(usize, PublicKey)> {
		let (from, msg) = self.recv()?;
		let n = msg.len().min(buf.len());
		buf[..n].copy_from_slice(&msg[..n]);
		Some((n, from))
	}

	fn recv(&mut self) -> Option<(PublicKey, Vec<u8>)> {
		while let Some((from, bs)) = self.net.recv() {
			if let Some(msg) = self.unpack(&bs, &from) {
				return Some((from, msg));
			}
		}
		None
	}

	fn write_to(&mut self, data: &[u8], dest: &PublicKey) -> Result<usize, Error> {
		let msg = self.sign(dest, data);
		let n = self.net.write_to(&msg, dest)?;
		Ok(n.saturating_sub(SIGNATURE_SIZE))
	}

	fn now(&self) -> Instant {
		self.net.now()
	}

	fn poll_timeout(&self) -> Option<Instant> {
		self.net.poll_timeout()
	}

	fn handle_timeout(&mut self) {
		self.net.handle_timeout();
	}

	fn poll_event(&mut self) -> Option<Event> {
		self.net.poll_event()
	}

	fn close(&mut self) -> Result<(), Error> {
		self.net.close()
	}

	fn is_closed(&self) -> bool {
		self.net.is_closed()
	}

	fn private_key(&self) -> &PrivateKey {
		self.net.private_key()
	}

	fn public_key(&self) -> PublicKey {
		self.net.public_key()
	}

	fn mtu(&self) -> u64 {
		self.net.mtu() - SIGNATURE_SIZE as u64
	}

	fn send_lookup(&mut self, target: &PublicKey) {
		self.net.send_lookup(target);
	}
}
