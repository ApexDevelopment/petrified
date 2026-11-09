use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::time::Duration;

use super::crypto::{BoxPriv, GroupAuth, ed_priv_to_box};
use super::session::{SESSION_TRAFFIC_OVERHEAD, SessionContext, SessionManager};
use crate::network::{self, Config};
use crate::types::{
	self, Error, Event, Instant, PacketConn as _, PeerId, Platform, PrivateKey, PublicKey,
};

/// An Ironwood node with end-to-end encrypted, authenticated sessions.
pub struct PacketConn {
	net: network::PacketConn,
	secret_ed: PrivateKey,
	secret_box: BoxPriv,
	auth: GroupAuth,
	sessions: SessionManager,
	/// Decrypted packets waiting for the application.
	received: VecDeque<(PublicKey, Vec<u8>)>,
	received_size: u64,
	max_received_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugSessionInfo {
	pub key: PublicKey,
	pub uptime: Duration,
	pub rx: u64,
	pub tx: u64,
}

impl PacketConn {
	pub fn new(
		secret: &PrivateKey,
		platform: impl Platform + Send + 'static,
		config: Config,
	) -> Result<Self, Error> {
		Self::with_auth(secret, GroupAuth::default(), platform, config)
	}

	/// Like [`PacketConn::new`], but only completes handshakes with nodes using
	/// the same password. The packet format is unchanged.
	pub fn new_with_password(
		secret: &PrivateKey,
		password: &str,
		platform: impl Platform + Send + 'static,
		config: Config,
	) -> Result<Self, Error> {
		Self::with_auth(secret, GroupAuth::new(password), platform, config)
	}

	fn with_auth(
		secret: &PrivateKey,
		auth: GroupAuth,
		platform: impl Platform + Send + 'static,
		config: Config,
	) -> Result<Self, Error> {
		let max_received_size = config.peer_max_message_size;
		let net = network::PacketConn::new(secret, platform, config)?;
		Ok(PacketConn {
			net,
			secret_ed: secret.clone(),
			secret_box: ed_priv_to_box(secret),
			auth,
			sessions: SessionManager::default(),
			received: VecDeque::new(),
			received_size: 0,
			max_received_size,
		})
	}

	/// The underlying routing layer, e.g. for its debug information.
	pub fn network(&self) -> &network::PacketConn {
		&self.net
	}

	/// Mutable access to the routing layer, e.g. to set its debug lookup logger.
	pub fn network_mut(&mut self) -> &mut network::PacketConn {
		&mut self.net
	}

	pub fn get_sessions(&self) -> Vec<DebugSessionInfo> {
		let now = self.net.now();
		self.sessions
			.sessions
			.iter()
			.map(|(key, info)| DebugSessionInfo {
				key: *key,
				uptime: now.saturating_duration_since(info.since),
				rx: info.rx,
				tx: info.tx,
			})
			.collect()
	}

	/// Runs `f` with the session manager and everything it needs.
	fn with_sessions<T>(
		&mut self,
		f: impl FnOnce(&mut SessionManager, &mut SessionContext) -> T,
	) -> T {
		let received = &mut self.received;
		let received_size = &mut self.received_size;
		let max_received_size = self.max_received_size;
		let mut deliver = |key: PublicKey, msg: Vec<u8>| {
			*received_size += msg.len() as u64;
			received.push_back((key, msg));
			while *received_size > max_received_size {
				let Some((_, dropped)) = received.pop_front() else {
					break;
				};
				*received_size -= dropped.len() as u64;
			}
		};
		let mut ctx = SessionContext {
			net: &mut self.net,
			secret_ed: &self.secret_ed,
			secret_box: &self.secret_box,
			auth: &self.auth,
			deliver: &mut deliver,
		};
		f(&mut self.sessions, &mut ctx)
	}

	/// Hands everything the routing layer received to the sessions.
	fn process_network(&mut self) {
		while let Some((from, data)) = self.net.recv() {
			self.with_sessions(|sessions, ctx| sessions.handle_data(ctx, &from, data));
		}
	}
}

impl types::PacketConn for PacketConn {
	fn handle_conn(&mut self, key: &PublicKey, prio: u8) -> Result<PeerId, Error> {
		self.net.handle_conn(key, prio)
	}

	fn handle_peer_data(&mut self, peer: PeerId, data: &[u8]) -> Result<(), Error> {
		let result = self.net.handle_peer_data(peer, data);
		self.process_network();
		result
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
		let (from, msg) = self.received.pop_front()?;
		self.received_size -= msg.len() as u64;
		Some((from, msg))
	}

	fn write_to(&mut self, data: &[u8], dest: &PublicKey) -> Result<usize, Error> {
		if self.net.is_closed() {
			return Err(Error::Closed);
		}
		if data.len() as u64 > self.mtu() {
			return Err(Error::OversizedMessage);
		}
		self.with_sessions(|sessions, ctx| sessions.write_to(ctx, *dest, data));
		self.process_network();
		Ok(data.len())
	}

	fn now(&self) -> Instant {
		self.net.now()
	}

	fn poll_timeout(&self) -> Option<Instant> {
		if self.net.is_closed() {
			return None;
		}
		[self.net.poll_timeout(), self.sessions.next_timeout()]
			.into_iter()
			.flatten()
			.min()
	}

	fn handle_timeout(&mut self) {
		self.net.handle_timeout();
		let now = self.net.now();
		self.sessions.handle_timeouts(now);
		self.process_network();
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
		self.net.mtu() - SESSION_TRAFFIC_OVERHEAD as u64
	}

	fn send_lookup(&mut self, target: &PublicKey) {
		self.net.send_lookup(target);
		self.process_network();
	}
}
