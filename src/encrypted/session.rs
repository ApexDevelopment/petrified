use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::time::Duration;

use super::crypto::*;
use crate::network;
use crate::network::wire::{put_uvarint, uvarint};
use crate::types::{Instant, PacketConn as _, Platform, PrivateKey, PublicKey};

pub(crate) const SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const ROTATION_INTERVAL: Duration = Duration::from_secs(60);
/// Header, three uvarints, the box overhead, and the next public key.
pub(crate) const SESSION_TRAFFIC_OVERHEAD_MIN: usize = 1 + 1 + 1 + 1 + BOX_OVERHEAD + BOX_PUB_SIZE;
pub(crate) const SESSION_TRAFFIC_OVERHEAD: usize = SESSION_TRAFFIC_OVERHEAD_MIN + 9 + 9 + 9;
pub(crate) const SESSION_INIT_SIZE: usize =
	1 + BOX_PUB_SIZE + BOX_OVERHEAD + ED_SIG_SIZE + BOX_PUB_SIZE + BOX_PUB_SIZE + 8 + 8;

const SESSION_TYPE_DUMMY: u8 = 0;
const SESSION_TYPE_INIT: u8 = 1;
const SESSION_TYPE_ACK: u8 = 2;
const SESSION_TYPE_TRAFFIC: u8 = 3;

/// Everything sessions need from the encrypted PacketConn.
pub(crate) struct SessionContext<'a> {
	pub net: &'a mut network::PacketConn,
	pub secret_ed: &'a PrivateKey,
	pub secret_box: &'a BoxPriv,
	pub auth: &'a GroupAuth,
	/// Decrypted packets for the application.
	pub deliver: &'a mut dyn FnMut(PublicKey, Vec<u8>),
}

impl SessionContext<'_> {
	fn now(&self) -> Instant {
		self.net.now()
	}

	fn platform(&mut self) -> &mut dyn Platform {
		self.net.platform_mut()
	}

	fn new_box_keys(&mut self) -> (BoxPub, BoxPriv) {
		new_box_keys(self.platform())
	}

	fn new_session_init(&mut self, current: BoxPub, next: BoxPub, key_seq: u64) -> SessionInit {
		SessionInit {
			current,
			next,
			key_seq,
			seq: self.platform().unix_time(),
		}
	}

	fn send_handshake(&mut self, dest: &PublicKey, init: &SessionInit, session_type: u8) {
		let ephemeral = self.new_box_keys();
		let mut bs = init.encrypt(self.secret_ed, dest, self.auth, ephemeral);
		bs[0] = session_type;
		let _ = self.net.write_to(&bs, dest);
	}

	fn send_init(&mut self, dest: &PublicKey, init: &SessionInit) {
		self.send_handshake(dest, init, SESSION_TYPE_INIT);
	}

	fn send_ack(&mut self, dest: &PublicKey, ack: &SessionInit) {
		self.send_handshake(dest, ack, SESSION_TYPE_ACK);
	}
}

/******************
 * sessionManager *
 ******************/

#[derive(Default)]
pub(crate) struct SessionManager {
	pub sessions: BTreeMap<PublicKey, SessionInfo>,
	buffers: BTreeMap<PublicKey, SessionBuffer>,
}

impl SessionManager {
	fn new_session(
		&mut self,
		ctx: &mut SessionContext,
		ed: PublicKey,
		recv: BoxPub,
		send: BoxPub,
		seq: u64,
	) {
		let mut info = SessionInfo::new(ctx, ed, recv, send, seq);
		info.reset_timer(ctx.now());
		self.sessions.insert(ed, info);
	}

	/// Gets or creates the session for `key`. If a buffered packet was waiting
	/// for the session, its keys are adopted and the packet is returned for the
	/// caller to send once the handshake is handled.
	fn session_for_init(
		&mut self,
		ctx: &mut SessionContext,
		key: &PublicKey,
		init: &SessionInit,
	) -> Option<Vec<u8>> {
		if self.sessions.contains_key(key) {
			return None;
		}
		self.new_session(ctx, *key, init.current, init.next, init.seq);
		let buf = self.buffers.remove(key)?;
		let info = self.sessions.get_mut(key).unwrap();
		info.send_pub = buf.init.current;
		info.send_priv = buf.current_priv;
		info.next_pub = buf.init.next;
		info.next_priv = buf.next_priv;
		info.fix_shared(0, 0);
		buf.data
	}

	pub(crate) fn handle_data(&mut self, ctx: &mut SessionContext, key: &PublicKey, data: Vec<u8>) {
		let Some(&session_type) = data.first() else {
			return;
		};
		match session_type {
			SESSION_TYPE_DUMMY => {}
			SESSION_TYPE_INIT => {
				if let Some(init) = SessionInit::decrypt(ctx.secret_box, key, &data, ctx.auth) {
					self.handle_init(ctx, key, &init);
				}
			}
			SESSION_TYPE_ACK => {
				if let Some(ack) = SessionInit::decrypt(ctx.secret_box, key, &data, ctx.auth) {
					self.handle_ack(ctx, key, &ack);
				}
			}
			SESSION_TYPE_TRAFFIC => self.handle_traffic(ctx, key, &data),
			_ => {}
		}
	}

	fn handle_init(&mut self, ctx: &mut SessionContext, key: &PublicKey, init: &SessionInit) {
		let buffered = self.session_for_init(ctx, key, init);
		let info = self.sessions.get_mut(key).unwrap();
		info.handle_init(ctx, init);
		if let Some(data) = buffered {
			info.do_send(ctx, &data);
		}
	}

	fn handle_ack(&mut self, ctx: &mut SessionContext, key: &PublicKey, ack: &SessionInit) {
		let is_old = self.sessions.contains_key(key);
		let buffered = self.session_for_init(ctx, key, ack);
		let info = self.sessions.get_mut(key).unwrap();
		if is_old {
			info.handle_ack(ctx, ack);
		} else {
			info.handle_init(ctx, ack);
		}
		if let Some(data) = buffered {
			info.do_send(ctx, &data);
		}
	}

	fn handle_traffic(&mut self, ctx: &mut SessionContext, key: &PublicKey, msg: &[u8]) {
		if let Some(info) = self.sessions.get_mut(key) {
			info.do_recv(ctx, msg);
			return;
		}
		// The sender could be spoofed or a replay, so don't save any state for it.
		// Send an init with keys we'll forget; if they ack, a session gets set up.
		let (current, _) = ctx.new_box_keys();
		let (next, _) = ctx.new_box_keys();
		let init = ctx.new_session_init(current, next, 0);
		ctx.send_init(key, &init);
	}

	pub(crate) fn write_to(&mut self, ctx: &mut SessionContext, to_key: PublicKey, msg: &[u8]) {
		match self.sessions.get_mut(&to_key) {
			Some(info) => info.do_send(ctx, msg),
			None => self.buffer_and_init(ctx, to_key, msg),
		}
	}

	fn buffer_and_init(&mut self, ctx: &mut SessionContext, to_key: PublicKey, msg: &[u8]) {
		self.buffers.entry(to_key).or_insert_with(|| {
			let (current_pub, current_priv) = ctx.new_box_keys();
			let (next_pub, next_priv) = ctx.new_box_keys();
			let init = ctx.new_session_init(current_pub, next_pub, 0);
			SessionBuffer {
				data: None,
				init,
				current_priv,
				next_priv,
				timer: ctx.now(),
			}
		});
		let now = ctx.now();
		let buf = self.buffers.get_mut(&to_key).unwrap();
		buf.data = Some(msg.to_vec());
		buf.timer = now + SESSION_TIMEOUT;
		let init = buf.init.clone();
		ctx.send_init(&to_key, &init);
	}

	pub(crate) fn next_timeout(&self) -> Option<Instant> {
		let sessions = self.sessions.values().map(|info| info.timer);
		let buffers = self.buffers.values().map(|buf| buf.timer);
		sessions.chain(buffers).min()
	}

	pub(crate) fn handle_timeouts(&mut self, now: Instant) {
		self.sessions.retain(|_, info| info.timer > now);
		self.buffers.retain(|_, buf| buf.timer > now);
	}
}

/***************
 * sessionInfo *
 ***************/

pub(crate) struct SessionInfo {
	/// Remote seq.
	seq: u64,
	/// Remote ed key.
	ed: PublicKey,
	/// Signals rotation of current/next.
	remote_key_seq: u64,
	/// Send to this, expect to receive from it.
	current: BoxPub,
	/// If we receive from this, rotate it to current.
	next: BoxPub,
	/// Signals rotation of recv/send/next.
	local_key_seq: u64,
	recv_priv: BoxPriv,
	recv_pub: BoxPub,
	recv_shared: BoxShared,
	recv_nonce: u64,
	/// Becomes recv when we ratchet forward.
	send_priv: BoxPriv,
	send_pub: BoxPub,
	send_shared: BoxShared,
	send_nonce: u64,
	/// Becomes send when we ratchet forward.
	next_priv: BoxPriv,
	next_pub: BoxPub,
	timer: Instant,
	pub since: Instant,
	/// Last time we rotated keys.
	rotated: Option<Instant>,
	pub rx: u64,
	pub tx: u64,
	next_send_shared: BoxShared,
	next_send_nonce: u64,
	next_recv_shared: BoxShared,
	next_recv_nonce: u64,
}

/// Which shared key an incoming packet was encrypted with.
#[derive(Clone, Copy)]
enum RecvKey {
	Current,
	NextSend,
	NextRecv,
}

impl SessionInfo {
	fn new(
		ctx: &mut SessionContext,
		ed: PublicKey,
		current: BoxPub,
		next: BoxPub,
		seq: u64,
	) -> Self {
		let (recv_pub, recv_priv) = ctx.new_box_keys();
		let (send_pub, send_priv) = ctx.new_box_keys();
		let (next_pub, next_priv) = ctx.new_box_keys();
		let now = ctx.now();
		let mut info = SessionInfo {
			// So the first update works
			seq: seq.wrapping_sub(1),
			ed,
			remote_key_seq: 0,
			current,
			next,
			local_key_seq: 0,
			recv_priv,
			recv_pub,
			recv_shared: [0; 32],
			recv_nonce: 0,
			send_priv,
			send_pub,
			send_shared: [0; 32],
			send_nonce: 0,
			next_priv,
			next_pub,
			timer: now,
			since: now,
			rotated: None,
			rx: 0,
			tx: 0,
			next_send_shared: [0; 32],
			next_send_nonce: 0,
			next_recv_shared: [0; 32],
			next_recv_nonce: 0,
		};
		info.fix_shared(0, 0);
		info
	}

	/// Happens at session creation or after receiving an init/ack.
	fn fix_shared(&mut self, recv_nonce: u64, send_nonce: u64) {
		self.recv_shared = get_shared(&self.current, &self.recv_priv);
		self.send_shared = get_shared(&self.current, &self.send_priv);
		self.next_send_shared = get_shared(&self.next, &self.send_priv);
		self.next_recv_shared = get_shared(&self.next, &self.recv_priv);
		self.next_send_nonce = 0;
		self.next_recv_nonce = 0;
		self.recv_nonce = recv_nonce;
		self.send_nonce = send_nonce;
	}

	fn reset_timer(&mut self, now: Instant) {
		self.timer = now + SESSION_TIMEOUT;
	}

	fn handle_init(&mut self, ctx: &mut SessionContext, init: &SessionInit) {
		if init.seq <= self.seq {
			return;
		}
		self.handle_update(ctx, init);
		self.send_ack(ctx);
	}

	fn handle_ack(&mut self, ctx: &mut SessionContext, ack: &SessionInit) {
		if ack.seq <= self.seq {
			return;
		}
		self.handle_update(ctx, ack);
	}

	/// Rotates our own keys forward: send becomes recv, next becomes send.
	fn ratchet_local_keys(&mut self, ctx: &mut SessionContext) {
		self.recv_pub = self.send_pub;
		self.recv_priv = self.send_priv;
		self.send_pub = self.next_pub;
		self.send_priv = self.next_priv;
		(self.next_pub, self.next_priv) = ctx.new_box_keys();
		self.local_key_seq = self.local_key_seq.wrapping_add(1);
	}

	fn handle_update(&mut self, ctx: &mut SessionContext, init: &SessionInit) {
		self.current = init.current;
		self.next = init.next;
		self.seq = init.seq;
		self.remote_key_seq = init.key_seq;
		// Advance our keys, since this counts as a response
		self.ratchet_local_keys(ctx);
		// Don't roll back sendNonce, just to be extra safe
		self.fix_shared(0, self.send_nonce);
		self.reset_timer(ctx.now());
	}

	fn do_send(&mut self, ctx: &mut SessionContext, msg: &[u8]) {
		// Advance the nonce before anything else
		self.send_nonce = self.send_nonce.wrapping_add(1);
		if self.send_nonce == 0 {
			// Nonce overflowed, so rotate keys
			self.ratchet_local_keys(ctx);
			self.fix_shared(0, 0);
		}
		let mut bs = Vec::with_capacity(SESSION_TRAFFIC_OVERHEAD + msg.len());
		bs.push(SESSION_TYPE_TRAFFIC);
		let mut header = [0u8; 30];
		let mut len = put_uvarint(&mut header, self.local_key_seq);
		len += put_uvarint(&mut header[len..], self.remote_key_seq);
		len += put_uvarint(&mut header[len..], self.send_nonce);
		bs.extend_from_slice(&header[..len]);
		// Include nextPub under the encryption, so the remote side knows it's us when we send from it later
		let mut inner = Vec::with_capacity(BOX_PUB_SIZE + msg.len());
		inner.extend_from_slice(&self.next_pub);
		inner.extend_from_slice(msg);
		box_seal(&mut bs, &inner, self.send_nonce, &self.send_shared);
		let _ = ctx.net.write_to(&bs, &self.ed);
		self.tx += msg.len() as u64;
		self.reset_timer(ctx.now());
	}

	fn do_recv(&mut self, ctx: &mut SessionContext, msg: &[u8]) {
		if msg.len() < SESSION_TRAFFIC_OVERHEAD_MIN || msg[0] != SESSION_TYPE_TRAFFIC {
			return;
		}
		let mut offset = 1;
		let next_uvarint = |offset: &mut usize| {
			let (value, len) = uvarint(&msg[*offset..])?;
			*offset += len;
			Some(value)
		};
		let Some(remote_key_seq) = next_uvarint(&mut offset) else {
			return;
		};
		let Some(local_key_seq) = next_uvarint(&mut offset) else {
			return;
		};
		let Some(nonce) = next_uvarint(&mut offset) else {
			return;
		};
		let boxed = &msg[offset..];
		let from_current = remote_key_seq == self.remote_key_seq;
		let from_next = remote_key_seq == self.remote_key_seq.wrapping_add(1);
		let to_recv = local_key_seq.wrapping_add(1) == self.local_key_seq;
		let to_send = local_key_seq == self.local_key_seq;
		let (recv_key, shared) = if from_current && to_recv {
			// The boring case, nothing to ratchet, just update the nonce
			if self.recv_nonce >= nonce {
				return;
			}
			(RecvKey::Current, &self.recv_shared)
		} else if from_next && to_send {
			// The remote side appears to have ratcheted forward
			if self.next_send_nonce >= nonce {
				return;
			}
			(RecvKey::NextSend, &self.next_send_shared)
		} else if from_next && to_recv {
			// The remote side appears to have ratcheted forward early
			if self.next_recv_nonce >= nonce {
				return;
			}
			(RecvKey::NextRecv, &self.next_recv_shared)
		} else {
			// We can't make sense of their message, so send an init and hope they ack
			self.send_init(ctx);
			return;
		};
		let Some(unboxed) = box_open(boxed, nonce, shared) else {
			// Keys somehow became out of sync, which can happen if a node restarts
			self.send_init(ctx);
			return;
		};
		if unboxed.len() < BOX_PUB_SIZE {
			return;
		}
		let inner_key: BoxPub = unboxed[..BOX_PUB_SIZE].try_into().unwrap();
		let payload = unboxed[BOX_PUB_SIZE..].to_vec();
		let payload_len = payload.len() as u64;
		(ctx.deliver)(self.ed, payload);
		self.on_recv_success(ctx, recv_key, nonce, inner_key);
		self.rx += payload_len;
		self.reset_timer(ctx.now());
	}

	fn on_recv_success(
		&mut self,
		ctx: &mut SessionContext,
		recv_key: RecvKey,
		nonce: u64,
		inner_key: BoxPub,
	) {
		match recv_key {
			RecvKey::Current => {
				self.recv_nonce = nonce;
				return;
			}
			RecvKey::NextSend => self.next_send_nonce = nonce,
			RecvKey::NextRecv => self.next_recv_nonce = nonce,
		}
		let now = ctx.now();
		let may_rotate = self
			.rotated
			.is_none_or(|rotated| now.saturating_duration_since(rotated) > ROTATION_INTERVAL);
		if !may_rotate {
			return;
		}
		// Rotate their keys
		self.current = self.next;
		self.next = inner_key;
		self.remote_key_seq = self.remote_key_seq.wrapping_add(1);
		self.ratchet_local_keys(ctx);
		self.fix_shared(nonce, 0);
		self.rotated = Some(now);
	}

	fn send_init(&mut self, ctx: &mut SessionContext) {
		let init = ctx.new_session_init(self.send_pub, self.next_pub, self.local_key_seq);
		ctx.send_init(&self.ed, &init);
	}

	fn send_ack(&mut self, ctx: &mut SessionContext) {
		let ack = ctx.new_session_init(self.send_pub, self.next_pub, self.local_key_seq);
		ctx.send_ack(&self.ed, &ack);
	}
}

/***************
 * sessionInit *
 ***************/

/// A handshake. An ack has the same contents, with a different type byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionInit {
	pub current: BoxPub,
	pub next: BoxPub,
	pub key_seq: u64,
	/// A timestamp or similar.
	pub seq: u64,
}

impl SessionInit {
	/// Encrypts the handshake for `to`, using the given ephemeral key pair.
	pub(crate) fn encrypt(
		&self,
		from: &PrivateKey,
		to: &PublicKey,
		auth: &GroupAuth,
		(from_pub, from_priv): (BoxPub, BoxPriv),
	) -> Vec<u8> {
		let to_box = ed_pub_to_box(to);
		let mut sig_bytes = Vec::with_capacity(BOX_PUB_SIZE * 3 + 16);
		sig_bytes.extend_from_slice(&from_pub);
		sig_bytes.extend_from_slice(&self.current);
		sig_bytes.extend_from_slice(&self.next);
		sig_bytes.extend_from_slice(&self.key_seq.to_be_bytes());
		sig_bytes.extend_from_slice(&self.seq.to_be_bytes());
		let sig = ed_sign(&sig_bytes, from, auth.preimage());
		let mut payload = Vec::with_capacity(ED_SIG_SIZE + sig_bytes.len());
		payload.extend_from_slice(&sig);
		payload.extend_from_slice(&sig_bytes[BOX_PUB_SIZE..]);
		let shared = get_shared(&to_box, &from_priv);
		let mut data = Vec::with_capacity(SESSION_INIT_SIZE);
		data.push(SESSION_TYPE_INIT);
		data.extend_from_slice(&from_pub);
		box_seal(&mut data, &payload, 0, &shared);
		debug_assert_eq!(data.len(), SESSION_INIT_SIZE);
		data
	}

	pub(crate) fn decrypt(
		private: &BoxPriv,
		from: &PublicKey,
		data: &[u8],
		auth: &GroupAuth,
	) -> Option<Self> {
		if data.len() != SESSION_INIT_SIZE {
			return None;
		}
		let from_box: BoxPub = data[1..1 + BOX_PUB_SIZE].try_into().unwrap();
		let shared = get_shared(&from_box, private);
		let payload = box_open(&data[1 + BOX_PUB_SIZE..], 0, &shared)?;
		let sig: EdSig = payload[..ED_SIG_SIZE].try_into().unwrap();
		let signed = &payload[ED_SIG_SIZE..];
		let init = SessionInit {
			current: signed[..32].try_into().unwrap(),
			next: signed[32..64].try_into().unwrap(),
			key_seq: u64::from_be_bytes(signed[64..72].try_into().unwrap()),
			seq: u64::from_be_bytes(signed[72..80].try_into().unwrap()),
		};
		let mut sig_bytes = Vec::with_capacity(BOX_PUB_SIZE + signed.len());
		sig_bytes.extend_from_slice(&from_box);
		sig_bytes.extend_from_slice(signed);
		ed_check(&sig_bytes, &sig, from, auth.preimage()).then_some(init)
	}
}

/*****************
 * sessionBuffer *
 *****************/

struct SessionBuffer {
	data: Option<Vec<u8>>,
	init: SessionInit,
	/// Pairs with `init.current`.
	current_priv: BoxPriv,
	/// Pairs with `init.next`.
	next_priv: BoxPriv,
	/// Cleanup deadline.
	timer: Instant,
}

#[cfg(test)]
mod tests {
	use super::*;

	fn keys(seed: u8) -> (BoxPub, BoxPriv) {
		let private = [seed; 32];
		(box_pub_for_priv(&private), private)
	}

	#[test]
	fn session_init_password_auth() {
		let sender = PrivateKey::from_seed(&[1; 32]);
		let receiver = PrivateKey::from_seed(&[2; 32]);
		let init = SessionInit {
			current: keys(3).0,
			next: keys(4).0,
			key_seq: 9,
			seq: 12345,
		};
		let receiver_box = ed_priv_to_box(&receiver);
		let cases = [
			("", "", true),
			("shared-password", "shared-password", true),
			("shared-password", "", false),
			("", "shared-password", false),
			("shared-password", "wrong-password", false),
		];
		for (sender_password, receiver_password, want_ok) in cases {
			let data = init.encrypt(
				&sender,
				&receiver.public_key(),
				&GroupAuth::new(sender_password),
				keys(5),
			);
			let decoded = SessionInit::decrypt(
				&receiver_box,
				&sender.public_key(),
				&data,
				&GroupAuth::new(receiver_password),
			);
			assert_eq!(
				decoded.is_some(),
				want_ok,
				"{sender_password:?} -> {receiver_password:?}"
			);
			if let Some(decoded) = decoded {
				assert_eq!(decoded, init);
			}
		}
	}

	#[test]
	fn decrypt_rejects_any_length_without_panicking() {
		let receiver_box = ed_priv_to_box(&PrivateKey::from_seed(&[2; 32]));
		let from = PrivateKey::from_seed(&[1; 32]).public_key();
		for len in 0..SESSION_INIT_SIZE + 9 {
			let data = alloc::vec![0xab; len];
			assert!(
				SessionInit::decrypt(&receiver_box, &from, &data, &GroupAuth::default()).is_none()
			);
		}
	}
}
