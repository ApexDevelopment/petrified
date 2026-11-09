use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::bloomfilter::Bloom;
use super::packetconn::Core;
use super::packetqueue::{PacketQueue, PqPacket};
use super::pathfinder::{PathBroken, PathLookup, PathNotify};
use super::router::{RouterAnnounce, RouterSigReq, RouterSigRes};
use super::traffic::Traffic;
use super::wire::*;
use crate::types::{Error, Event, Instant, PeerId, PublicKey, is_public_key_valid};

/// Queued packets are written once the outgoing buffer drops below this many
/// bytes, like the `bufio.Writer` in front of each Go connection.
const WRITE_BUFFER_SIZE: usize = 4096;

pub(crate) struct Peer {
	pub key: PublicKey,
	pub port: PeerPort,
	pub prio: u8,
	/// Order in which peers were connected (relative uptime).
	pub order: u64,
	pub queue: PacketQueue,
	/// Encoded bytes waiting to be written to the stream.
	pub out: Vec<u8>,
	/// Bytes read from the stream that do not form a full frame yet.
	pub in_buf: Vec<u8>,
	pub keep_alive_timer: Option<Instant>,
	pub read_deadline: Option<Instant>,
	pub deadlined: bool,
	/// When the last sigReq was sent.
	pub srst: Instant,
	/// When the last sigRes was received.
	pub srrt: Instant,
	pub rx: u64,
	pub tx: u64,
}

#[derive(Default)]
pub(crate) struct Peers {
	ports: BTreeSet<PeerPort>,
	peers: BTreeMap<PublicKey, BTreeSet<PeerId>>,
	all: BTreeMap<PeerId, Peer>,
	/// Global counter for `Peer::order`.
	order: u64,
}

impl Peers {
	pub(crate) fn get(&self, id: PeerId) -> Option<&Peer> {
		self.all.get(&id)
	}

	fn get_mut(&mut self, id: PeerId) -> Option<&mut Peer> {
		self.all.get_mut(&id)
	}

	pub(crate) fn iter(&self) -> impl Iterator<Item = (PeerId, &Peer)> {
		self.all.iter().map(|(&id, peer)| (id, peer))
	}

	pub(crate) fn ids(&self) -> Vec<PeerId> {
		self.all.keys().copied().collect()
	}

	fn add(&mut self, key: PublicKey, prio: u8, now: Instant) -> (PeerId, PeerPort) {
		let port = match self.peers.get(&key).and_then(|ps| ps.first()) {
			Some(existing) => self.all[existing].port,
			None => {
				let port = (1..).find(|port| !self.ports.contains(port)).unwrap();
				self.ports.insert(port);
				port
			}
		};
		let id = PeerId(self.order);
		self.all.insert(
			id,
			Peer {
				key,
				port,
				prio,
				order: self.order,
				queue: PacketQueue::default(),
				out: Vec::new(),
				in_buf: Vec::new(),
				keep_alive_timer: None,
				read_deadline: None,
				deadlined: false,
				srst: now,
				srrt: now,
				rx: 0,
				tx: 0,
			},
		);
		self.peers.entry(key).or_default().insert(id);
		self.order += 1;
		(id, port)
	}

	fn remove(&mut self, id: PeerId) -> Result<Peer, Error> {
		let peer = self.all.remove(&id).ok_or(Error::PeerNotFound)?;
		let kps = self.peers.get_mut(&peer.key).unwrap();
		kps.remove(&id);
		if kps.is_empty() {
			self.peers.remove(&peer.key);
			self.ports.remove(&peer.port);
		}
		Ok(peer)
	}
}

/// Result of trying to read a frame length from the start of a buffer.
enum FrameLength {
	Incomplete,
	Overflow,
	Complete(u64, usize),
}

/// Reads a uvarint the way Go's `binary.ReadUvarint` does on a stream.
fn read_frame_length(buf: &[u8]) -> FrameLength {
	for (i, &b) in buf.iter().enumerate().take(MAX_VARINT_LEN64) {
		if b < 0x80 {
			return match uvarint(&buf[..=i]) {
				Some((u, len)) => FrameLength::Complete(u, len),
				None => FrameLength::Overflow,
			};
		}
	}
	if buf.len() >= MAX_VARINT_LEN64 {
		FrameLength::Overflow
	} else {
		FrameLength::Incomplete
	}
}

impl Core {
	pub(crate) fn peers_add_peer(&mut self, key: PublicKey, prio: u8) -> Result<PeerId, Error> {
		if !is_public_key_valid(&key.0) {
			return Err(Error::BadKey);
		}
		if self.pconn.closed {
			return Err(Error::Closed);
		}
		let now = self.now();
		let (id, port) = self.peers.add(key, prio, now);
		// Add the peer to the router, to kick off protocol exchanges
		self.router_add_peer(id, key, port);
		Ok(id)
	}

	/// Tears down a peer connection, as Go does when a connection's handler returns.
	pub(crate) fn peers_remove_peer(&mut self, id: PeerId) -> Result<(), Error> {
		let peer = self.peers.remove(id)?;
		self.router_remove_peer(id, peer.key, peer.port);
		Ok(())
	}

	/// Removes a peer the protocol gave up on, and tells the host.
	pub(crate) fn peers_drop_peer(&mut self, id: PeerId, error: Error) {
		if self.peers_remove_peer(id).is_ok() {
			self.events.push_back(Event::PeerClosed { peer: id, error });
		}
	}

	pub(crate) fn peer_handle_data(&mut self, id: PeerId, data: &[u8]) -> Result<(), Error> {
		let result = self.peer_read_frames(id, data);
		if let Err(error) = result {
			let _ = self.peers_remove_peer(id);
			return Err(error);
		}
		Ok(())
	}

	fn peer_read_frames(&mut self, id: PeerId, data: &[u8]) -> Result<(), Error> {
		let max_size = self.config.peer_max_message_size;
		let peer = self.peers.get_mut(id).ok_or(Error::PeerNotFound)?;
		peer.in_buf.extend_from_slice(data);
		let mut buf = core::mem::take(&mut peer.in_buf);
		let mut offset = 0;
		let result = loop {
			let (size, len) = match read_frame_length(&buf[offset..]) {
				FrameLength::Incomplete => break Ok(()),
				FrameLength::Overflow => break Err(Error::Decode),
				FrameLength::Complete(size, len) => (size, len),
			};
			if size > max_size {
				break Err(Error::OversizedMessage);
			}
			let end = offset + len + size as usize;
			if buf.len() < end {
				break Ok(());
			}
			if let Err(error) = self.peer_handle_packet(id, &buf[offset + len..end]) {
				break Err(error);
			}
			offset = end;
			if self.peers.get(id).is_none() {
				break Ok(());
			}
		};
		buf.drain(..offset);
		if let Some(peer) = self.peers.get_mut(id) {
			peer.rx += data.len() as u64;
			peer.in_buf = buf;
		}
		result
	}

	fn peer_handle_packet(&mut self, id: PeerId, bs: &[u8]) -> Result<(), Error> {
		let Some(&type_byte) = bs.first() else {
			return Err(Error::EmptyMessage);
		};
		let peer = self.peers.get(id).ok_or(Error::PeerNotFound)?;
		let (key, port) = (peer.key, peer.port);
		let p_type = WirePacketType::from_byte(type_byte);
		self.monitor_recv(id, p_type);
		let body = &bs[1..];
		match p_type.ok_or(Error::UnrecognizedMessage)? {
			WirePacketType::Dummy | WirePacketType::KeepAlive => {}
			WirePacketType::ProtoSigReq => {
				let req = RouterSigReq::decode(body)?;
				self.router_handle_request(id, key, port, req);
			}
			WirePacketType::ProtoSigRes => {
				let res = RouterSigRes::decode(body)?;
				if !res.check(&self.crypto.public_key, &key) {
					return Err(Error::BadMessage);
				}
				let now = self.now();
				let peer = self.peers.get_mut(id).unwrap();
				peer.srrt = now;
				let rtt = now.saturating_duration_since(peer.srst);
				self.router_handle_response(id, key, res, rtt);
			}
			WirePacketType::ProtoAnnounce => {
				let ann = RouterAnnounce::decode(body)?;
				if !ann.check() {
					return Err(Error::BadMessage);
				}
				self.router_handle_announce(key, id, ann);
			}
			WirePacketType::ProtoBloomFilter => {
				let bloom = Bloom::decode(body)?;
				self.blooms_handle_bloom(&key, bloom);
			}
			WirePacketType::ProtoPathLookup => {
				let lookup = PathLookup::decode(body)?;
				self.pathfinder_handle_lookup(key, lookup);
			}
			WirePacketType::ProtoPathNotify => {
				let notify = PathNotify::decode(body)?;
				self.pathfinder_handle_notify(notify);
			}
			WirePacketType::ProtoPathBroken => {
				let broken = PathBroken::decode(body)?;
				self.pathfinder_handle_broken(broken);
			}
			WirePacketType::Traffic => {
				let tr = Traffic::decode(body)?;
				self.router_handle_traffic(Box::new(tr));
			}
		}
		Ok(())
	}

	/*****************
	 * peer monitor *
	 *****************/

	fn monitor_sent(&mut self, id: PeerId, p_type: WirePacketType) {
		let deadline = self.now() + self.config.peer_timeout;
		let Some(peer) = self.peers.get_mut(id) else {
			return;
		};
		// Sending anything makes a keepalive unnecessary
		peer.keep_alive_timer = None;
		if peer.deadlined || matches!(p_type, WirePacketType::Dummy | WirePacketType::KeepAlive) {
			return;
		}
		// We expect some kind of acknowledgement (at least a keepalive)
		peer.read_deadline = Some(deadline);
		peer.deadlined = true;
	}

	fn monitor_recv(&mut self, id: PeerId, p_type: Option<WirePacketType>) {
		let deadline = self.now() + self.config.peer_keep_alive_delay;
		let Some(peer) = self.peers.get_mut(id) else {
			return;
		};
		peer.read_deadline = None;
		peer.deadlined = false;
		let is_keep_alive = matches!(
			p_type,
			Some(WirePacketType::Dummy | WirePacketType::KeepAlive)
		);
		if peer.keep_alive_timer.is_none() && !is_keep_alive {
			// The other side expects a response, so send a keepalive later if nothing else goes out
			peer.keep_alive_timer = Some(deadline);
		}
	}

	pub(crate) fn peers_next_timeout(&self) -> Option<Instant> {
		self.peers
			.iter()
			.flat_map(|(_, peer)| [peer.keep_alive_timer, peer.read_deadline])
			.flatten()
			.min()
	}

	pub(crate) fn peers_handle_timeouts(&mut self, now: Instant) {
		for id in self.peers.ids() {
			let Some(peer) = self.peers.get(id) else {
				continue;
			};
			if peer.read_deadline.is_some_and(|deadline| deadline <= now) {
				self.peers_drop_peer(id, Error::Timeout);
				continue;
			}
			if peer
				.keep_alive_timer
				.is_some_and(|deadline| deadline <= now)
			{
				self.peer_write(
					id,
					&[0x01, WirePacketType::KeepAlive as u8],
					WirePacketType::KeepAlive,
				);
			}
		}
	}

	/****************
	 * peer writer *
	 ****************/

	fn peer_write(&mut self, id: PeerId, bs: &[u8], p_type: WirePacketType) {
		self.monitor_sent(id, p_type);
		if let Some(peer) = self.peers.get_mut(id) {
			peer.out.extend_from_slice(bs);
			peer.tx += bs.len() as u64;
		}
	}

	fn peer_send_packet(&mut self, id: PeerId, p_type: WirePacketType, data: &dyn WireEncode) {
		// The +1 is for the packet type byte
		let size = data.size() as u64 + 1;
		if size > self.config.peer_max_message_size {
			return;
		}
		let mut buf = Vec::with_capacity(size as usize + MAX_VARINT_LEN64);
		wire_append_uint(&mut buf, size);
		buf.push(p_type as u8);
		data.encode(&mut buf);
		self.peer_write(id, &buf, p_type);
	}

	pub(crate) fn peer_send_sig_req(&mut self, id: PeerId, req: &RouterSigReq) {
		self.peer_send_packet(id, WirePacketType::ProtoSigReq, req);
		let now = self.now();
		if let Some(peer) = self.peers.get_mut(id) {
			peer.srst = now;
		}
	}

	pub(crate) fn peer_send_sig_res(&mut self, id: PeerId, res: &RouterSigRes) {
		self.peer_send_packet(id, WirePacketType::ProtoSigRes, res);
	}

	pub(crate) fn peer_send_announce(&mut self, id: PeerId, ann: &RouterAnnounce) {
		self.peer_send_packet(id, WirePacketType::ProtoAnnounce, ann);
	}

	pub(crate) fn peer_send_bloom(&mut self, id: PeerId, bloom: &Bloom) {
		self.peer_send_packet(id, WirePacketType::ProtoBloomFilter, bloom);
	}

	pub(crate) fn peer_send_traffic(&mut self, id: PeerId, tr: Box<Traffic>) {
		self.peer_send_queued(id, PqPacket::Traffic(tr));
	}

	pub(crate) fn peer_send_queued(&mut self, id: PeerId, packet: PqPacket) {
		let now = self.now();
		let max_size = self.config.peer_max_message_size;
		let Some(peer) = self.peers.get_mut(id) else {
			return;
		};
		if peer.out.len() < WRITE_BUFFER_SIZE {
			self.peer_send_packet(id, packet.wire_type(), packet.encodeable());
			return;
		}
		// The writer is busy, so queue the packet and drop any excess
		peer.queue.push(packet, now);
		while peer.queue.size > max_size {
			peer.queue.drop_packet();
		}
	}

	pub(crate) fn peer_transmit(&self, id: PeerId) -> &[u8] {
		self.peers.get(id).map_or(&[], |peer| &peer.out)
	}

	pub(crate) fn peer_consume(&mut self, id: PeerId, n: usize) {
		let Some(peer) = self.peers.get_mut(id) else {
			return;
		};
		peer.out.drain(..n.min(peer.out.len()));
		// Ask for more traffic to send
		while self
			.peers
			.get(id)
			.is_some_and(|peer| peer.out.len() < WRITE_BUFFER_SIZE)
		{
			let Some(info) = self.peers.get_mut(id).and_then(|peer| peer.queue.pop()) else {
				break;
			};
			self.peer_send_packet(id, info.packet.wire_type(), info.packet.encodeable());
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn frame_lengths_follow_read_uvarint() {
		assert!(matches!(read_frame_length(&[]), FrameLength::Incomplete));
		assert!(matches!(
			read_frame_length(&[0x80, 0x80]),
			FrameLength::Incomplete
		));
		assert!(matches!(
			read_frame_length(&[0x05, 0xff]),
			FrameLength::Complete(5, 1)
		));
		assert!(matches!(
			read_frame_length(&[0x80, 0x01]),
			FrameLength::Complete(128, 2)
		));
		assert!(matches!(
			read_frame_length(&[0xff; 10]),
			FrameLength::Overflow
		));
		let mut overflow = [0xff; 10];
		overflow[9] = 0x02;
		assert!(matches!(
			read_frame_length(&overflow),
			FrameLength::Overflow
		));
	}
}
