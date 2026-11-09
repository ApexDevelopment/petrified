use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::config::Config;
use super::debug::{Debug, DebugLookupInfo};
use super::packetqueue::{PacketQueue, PqPacket};
use super::peers::Peers;
use super::router::Router;
use super::traffic::Traffic;
use super::wire::WireEncode;
use crate::types::{
	self, Error, Event, Instant, PeerId, Platform, PrivateKey, PublicKey, is_public_key_valid,
};

pub(crate) struct Crypto {
	pub private_key: PrivateKey,
	pub public_key: PublicKey,
}

#[derive(Default)]
pub(crate) struct PConnState {
	pub recvq: PacketQueue,
	pub closed: bool,
}

/// All protocol state for one node. Go splits this across several actors.
pub(crate) struct Core {
	pub config: Config,
	pub crypto: Crypto,
	pub router: Router,
	pub peers: Peers,
	pub pconn: PConnState,
	pub platform: Box<dyn Platform + Send>,
	pub events: VecDeque<Event>,
}

impl Core {
	pub(crate) fn now(&self) -> Instant {
		self.platform.now()
	}

	pub(crate) fn pconn_handle_traffic(&mut self, tr: Box<Traffic>) {
		if tr.dest != self.crypto.public_key {
			return;
		}
		let now = self.now();
		let recvq = &mut self.pconn.recvq;
		recvq.push(PqPacket::Traffic(tr), now);
		while recvq.size > self.config.peer_max_message_size {
			recvq.drop_packet();
		}
	}
}

/// An unencrypted Ironwood node. Packets are routed by public key, but are
/// neither encrypted nor authenticated end to end.
pub struct PacketConn {
	pub(crate) core: Core,
}

impl PacketConn {
	pub fn new(
		secret: &PrivateKey,
		platform: impl Platform + Send + 'static,
		config: Config,
	) -> Result<Self, Error> {
		let public_key = secret.public_key();
		if !is_public_key_valid(&public_key.0) {
			return Err(Error::BadKey);
		}
		let mut core = Core {
			config,
			crypto: Crypto {
				private_key: secret.clone(),
				public_key,
			},
			router: Router::default(),
			peers: Peers::default(),
			pconn: PConnState::default(),
			platform: Box::new(platform),
			events: VecDeque::new(),
		};
		core.router_init();
		Ok(PacketConn { core })
	}

	pub fn debug(&self) -> Debug<'_> {
		Debug { core: &self.core }
	}

	/// Calls `logger` for every lookup this node handles.
	pub fn set_debug_lookup_logger(
		&mut self,
		logger: impl FnMut(&DebugLookupInfo) + Send + 'static,
	) {
		self.core.router.pathfinder.logger = Some(Box::new(logger));
	}

	pub(crate) fn now(&self) -> Instant {
		self.core.now()
	}

	pub(crate) fn platform_mut(&mut self) -> &mut (dyn Platform + Send) {
		self.core.platform.as_mut()
	}

	fn pop_traffic(&mut self) -> Option<Box<Traffic>> {
		match self.core.pconn.recvq.pop()?.packet {
			PqPacket::Traffic(tr) => Some(tr),
			_ => None,
		}
	}
}

impl types::PacketConn for PacketConn {
	fn handle_conn(&mut self, key: &PublicKey, prio: u8) -> Result<PeerId, Error> {
		if *key == self.core.crypto.public_key {
			return Err(Error::BadKey);
		}
		self.core.peers_add_peer(*key, prio)
	}

	fn handle_peer_data(&mut self, peer: PeerId, data: &[u8]) -> Result<(), Error> {
		self.core.peer_handle_data(peer, data)
	}

	fn peer_transmit(&self, peer: PeerId) -> &[u8] {
		self.core.peer_transmit(peer)
	}

	fn peer_consume(&mut self, peer: PeerId, n: usize) {
		self.core.peer_consume(peer, n);
	}

	fn remove_peer(&mut self, peer: PeerId) -> Result<(), Error> {
		self.core.peers_remove_peer(peer)
	}

	fn read_from(&mut self, buf: &mut [u8]) -> Option<(usize, PublicKey)> {
		let tr = self.pop_traffic()?;
		let n = tr.payload.len().min(buf.len());
		buf[..n].copy_from_slice(&tr.payload[..n]);
		Some((n, tr.source))
	}

	fn recv(&mut self) -> Option<(PublicKey, Vec<u8>)> {
		self.pop_traffic().map(|tr| (tr.source, tr.payload))
	}

	fn write_to(&mut self, data: &[u8], dest: &PublicKey) -> Result<usize, Error> {
		if self.core.pconn.closed {
			return Err(Error::Closed);
		}
		if data.len() as u64 > self.mtu() {
			return Err(Error::OversizedMessage);
		}
		let tr = Box::new(Traffic {
			source: self.core.crypto.public_key,
			dest: *dest,
			watermark: u64::MAX,
			payload: data.to_vec(),
			..Default::default()
		});
		self.core.router_send_traffic(tr);
		Ok(data.len())
	}

	fn now(&self) -> Instant {
		self.core.now()
	}

	fn poll_timeout(&self) -> Option<Instant> {
		if self.core.pconn.closed {
			return None;
		}
		let core = &self.core;
		[
			core.router_next_timeout(),
			core.pathfinder_next_timeout(),
			core.peers_next_timeout(),
		]
		.into_iter()
		.flatten()
		.min()
	}

	fn handle_timeout(&mut self) {
		if self.core.pconn.closed {
			return;
		}
		let now = self.now();
		self.core.router_handle_timeouts(now);
		self.core.pathfinder_handle_timeouts(now);
		self.core.peers_handle_timeouts(now);
	}

	fn poll_event(&mut self) -> Option<Event> {
		self.core.events.pop_front()
	}

	fn close(&mut self) -> Result<(), Error> {
		if self.core.pconn.closed {
			return Err(Error::Closed);
		}
		self.core.pconn.closed = true;
		for id in self.core.peers.ids() {
			self.core.peers_drop_peer(id, Error::Closed);
		}
		self.core.router_shutdown();
		Ok(())
	}

	fn is_closed(&self) -> bool {
		self.core.pconn.closed
	}

	fn private_key(&self) -> &PrivateKey {
		&self.core.crypto.private_key
	}

	fn public_key(&self) -> PublicKey {
		self.core.crypto.public_key
	}

	fn mtu(&self) -> u64 {
		let tr = Traffic {
			watermark: u64::MAX,
			..Default::default()
		};
		// 1 byte of packet type overhead
		let overhead = tr.size() as u64 + 1;
		self.core.config.peer_max_message_size - overhead
	}

	fn send_lookup(&mut self, target: &PublicKey) {
		self.core.pathfinder_rumor_send_lookup(*target);
	}
}
