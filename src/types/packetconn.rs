use alloc::vec::Vec;

use super::{Error, Instant, PrivateKey, PublicKey};

/// Identifies one connection to a peer. A peer node may have several.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u64);

/// Something the host must act on, returned by [`PacketConn::poll_event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
	/// The protocol dropped this peer connection. The host should close the
	/// underlying stream. The peer is already removed, so no call to
	/// [`PacketConn::remove_peer`] is needed.
	PeerClosed { peer: PeerId, error: Error },
}

/// The sans-IO equivalent of Ironwood's `types.PacketConn` interface.
///
/// Peer connections must be reliable, ordered byte streams (TCP-like).
pub trait PacketConn {
	/// Registers a new connection to the peer with `key`, like Go's `HandleConn`.
	/// Lower `prio` values are preferred when several links lead to the same peer.
	fn handle_conn(&mut self, key: &PublicKey, prio: u8) -> Result<PeerId, Error>;
	/// Feeds bytes read from a peer's stream. On error, the peer has been removed
	/// and the stream should be closed.
	fn handle_peer_data(&mut self, peer: PeerId, data: &[u8]) -> Result<(), Error>;
	/// Bytes waiting to be written to a peer's stream.
	fn peer_transmit(&self, peer: PeerId) -> &[u8];
	/// Marks the first `n` bytes of [`PacketConn::peer_transmit`] as written.
	fn peer_consume(&mut self, peer: PeerId, n: usize);
	/// Tells the protocol a peer's stream has closed.
	fn remove_peer(&mut self, peer: PeerId) -> Result<(), Error>;

	/// Takes the next received packet, copying as much as fits into `buf`.
	/// Returns the full packet length and the sender.
	fn read_from(&mut self, buf: &mut [u8]) -> Option<(usize, PublicKey)>;
	/// Takes the next received packet without truncation.
	fn recv(&mut self) -> Option<(PublicKey, Vec<u8>)>;
	/// Queues a packet for `dest`.
	fn write_to(&mut self, data: &[u8], dest: &PublicKey) -> Result<usize, Error>;

	/// The current time on this conn's [`crate::types::Platform`] clock.
	fn now(&self) -> Instant;
	/// The earliest time [`PacketConn::handle_timeout`] needs to be called.
	fn poll_timeout(&self) -> Option<Instant>;
	/// Runs every timer that has expired.
	fn handle_timeout(&mut self);
	/// Takes the next event the host must act on.
	fn poll_event(&mut self) -> Option<Event>;

	fn close(&mut self) -> Result<(), Error>;
	fn is_closed(&self) -> bool;
	fn private_key(&self) -> &PrivateKey;
	fn public_key(&self) -> PublicKey;
	/// The largest payload [`PacketConn::write_to`] accepts.
	fn mtu(&self) -> u64;
	/// Sends a lookup for a (possibly partial) key.
	fn send_lookup(&mut self, target: &PublicKey);
}

impl<T: PacketConn + ?Sized> PacketConn for alloc::boxed::Box<T> {
	fn handle_conn(&mut self, key: &PublicKey, prio: u8) -> Result<PeerId, Error> {
		(**self).handle_conn(key, prio)
	}
	fn handle_peer_data(&mut self, peer: PeerId, data: &[u8]) -> Result<(), Error> {
		(**self).handle_peer_data(peer, data)
	}
	fn peer_transmit(&self, peer: PeerId) -> &[u8] {
		(**self).peer_transmit(peer)
	}
	fn peer_consume(&mut self, peer: PeerId, n: usize) {
		(**self).peer_consume(peer, n)
	}
	fn remove_peer(&mut self, peer: PeerId) -> Result<(), Error> {
		(**self).remove_peer(peer)
	}
	fn read_from(&mut self, buf: &mut [u8]) -> Option<(usize, PublicKey)> {
		(**self).read_from(buf)
	}
	fn recv(&mut self) -> Option<(PublicKey, Vec<u8>)> {
		(**self).recv()
	}
	fn write_to(&mut self, data: &[u8], dest: &PublicKey) -> Result<usize, Error> {
		(**self).write_to(data, dest)
	}
	fn now(&self) -> Instant {
		(**self).now()
	}
	fn poll_timeout(&self) -> Option<Instant> {
		(**self).poll_timeout()
	}
	fn handle_timeout(&mut self) {
		(**self).handle_timeout()
	}
	fn poll_event(&mut self) -> Option<Event> {
		(**self).poll_event()
	}
	fn close(&mut self) -> Result<(), Error> {
		(**self).close()
	}
	fn is_closed(&self) -> bool {
		(**self).is_closed()
	}
	fn private_key(&self) -> &PrivateKey {
		(**self).private_key()
	}
	fn public_key(&self) -> PublicKey {
		(**self).public_key()
	}
	fn mtu(&self) -> u64 {
		(**self).mtu()
	}
	fn send_lookup(&mut self, target: &PublicKey) {
		(**self).send_lookup(target)
	}
}
