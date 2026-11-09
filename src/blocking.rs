//! A thread-based wrapper with the blocking semantics of Go's `net.PacketConn`
//! and Ironwood's `HandleConn`.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use crate::types::{self, Error, Event, PeerId, PrivateKey, PublicKey};

const READ_BUFFER_SIZE: usize = 64 * 1024;

/// A reliable, ordered byte stream to a peer.
pub trait Stream: Read + Write + Send + Sized + 'static {
	fn try_clone(&self) -> io::Result<Self>;
	/// Unblocks any pending reads and writes on every clone of the stream.
	fn shutdown(&self);
}

impl Stream for TcpStream {
	fn try_clone(&self) -> io::Result<Self> {
		TcpStream::try_clone(self)
	}

	fn shutdown(&self) {
		let _ = TcpStream::shutdown(self, Shutdown::Both);
	}
}

#[cfg(unix)]
impl Stream for std::os::unix::net::UnixStream {
	fn try_clone(&self) -> io::Result<Self> {
		std::os::unix::net::UnixStream::try_clone(self)
	}

	fn shutdown(&self) {
		let _ = std::os::unix::net::UnixStream::shutdown(self, Shutdown::Both);
	}
}

/// Why [`PacketConn::handle_conn`] returned.
#[derive(Debug)]
pub enum ConnError {
	Protocol(Error),
	Io(io::Error),
}

impl fmt::Display for ConnError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ConnError::Protocol(error) => error.fmt(f),
			ConnError::Io(error) => error.fmt(f),
		}
	}
}

impl std::error::Error for ConnError {}

impl From<Error> for ConnError {
	fn from(error: Error) -> Self {
		ConnError::Protocol(error)
	}
}

struct State<C> {
	conn: C,
	/// Shuts down each live peer's stream.
	closers: HashMap<PeerId, Box<dyn Fn() + Send>>,
	/// Why the protocol dropped a peer, for its `handle_conn` call to return.
	peer_errors: HashMap<PeerId, Error>,
	alive: HashSet<PeerId>,
	read_deadline: Option<std::time::Instant>,
}

impl<C: types::PacketConn> State<C> {
	/// Acts on protocol events. Call after every change to `conn`.
	fn process_events(&mut self) {
		while let Some(event) = self.conn.poll_event() {
			match event {
				Event::PeerClosed { peer, error } => {
					self.peer_errors.insert(peer, error);
					if let Some(close) = self.closers.get(&peer) {
						close();
					}
				}
			}
		}
	}
}

struct Shared<C> {
	state: Mutex<State<C>>,
	changed: Condvar,
}

impl<C: types::PacketConn> Shared<C> {
	fn lock(&self) -> MutexGuard<'_, State<C>> {
		self.state
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Runs `f` on the state, then handles events and wakes every waiting thread.
	fn update<T>(&self, f: impl FnOnce(&mut State<C>) -> T) -> T {
		let mut state = self.lock();
		let result = f(&mut state);
		state.process_events();
		drop(state);
		self.changed.notify_all();
		result
	}
}

/// Drives any sans-IO [`types::PacketConn`] with background threads.
/// Cloning gives another handle to the same node.
pub struct PacketConn<C> {
	shared: Arc<Shared<C>>,
}

impl<C> Clone for PacketConn<C> {
	fn clone(&self) -> Self {
		PacketConn {
			shared: self.shared.clone(),
		}
	}
}

impl<C: types::PacketConn + Send + 'static> PacketConn<C> {
	/// Starts a timer thread for `conn`. It runs until [`PacketConn::close`].
	pub fn new(conn: C) -> Self {
		let shared = Arc::new(Shared {
			state: Mutex::new(State {
				conn,
				closers: HashMap::new(),
				peer_errors: HashMap::new(),
				alive: HashSet::new(),
				read_deadline: None,
			}),
			changed: Condvar::new(),
		});
		let timer_shared = shared.clone();
		thread::spawn(move || run_timers(&timer_shared));
		PacketConn { shared }
	}

	/// Runs a peer connection until it fails or the conn is closed, like Go's
	/// `HandleConn`. The stream is shut down before this returns.
	pub fn handle_conn<S: Stream>(
		&self,
		key: &PublicKey,
		stream: S,
		prio: u8,
	) -> Result<(), ConnError> {
		let closer = stream.try_clone().map_err(ConnError::Io)?;
		let id = match self
			.shared
			.update(|state| state.conn.handle_conn(key, prio))
		{
			Ok(id) => id,
			Err(error) => {
				stream.shutdown();
				return Err(error.into());
			}
		};
		let writer = match stream.try_clone() {
			Ok(writer) => writer,
			Err(error) => {
				self.shared.update(|state| state.conn.remove_peer(id)).ok();
				stream.shutdown();
				return Err(ConnError::Io(error));
			}
		};
		self.shared.update(|state| {
			state.alive.insert(id);
			state
				.closers
				.insert(id, Box::new(move || closer.shutdown()));
		});
		let writer_shared = self.shared.clone();
		let writer_thread = thread::spawn(move || run_writer(&writer_shared, id, writer));
		let result = self.read_loop(id, stream);
		writer_thread.join().ok();
		result
	}

	fn read_loop<S: Stream>(&self, id: PeerId, mut stream: S) -> Result<(), ConnError> {
		let mut buf = vec![0u8; READ_BUFFER_SIZE];
		let result = loop {
			let n = match stream.read(&mut buf) {
				Ok(0) => break Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into())),
				Ok(n) => n,
				Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
				Err(error) => break Err(ConnError::Io(error)),
			};
			if let Err(error) = self
				.shared
				.update(|state| state.conn.handle_peer_data(id, &buf[..n]))
			{
				break Err(ConnError::Protocol(error));
			}
		};
		stream.shutdown();
		self.shared.update(|state| {
			state.alive.remove(&id);
			state.closers.remove(&id);
			// Already gone if the protocol dropped it
			let _ = state.conn.remove_peer(id);
			match state.peer_errors.remove(&id) {
				Some(error) => Err(ConnError::Protocol(error)),
				None => result,
			}
		})
	}

	/// Blocks until a packet arrives, the read deadline passes, or the conn is closed.
	pub fn read_from(&self, buf: &mut [u8]) -> Result<(usize, PublicKey), Error> {
		let mut state = self.shared.lock();
		loop {
			if state.conn.is_closed() {
				return Err(Error::Closed);
			}
			if let Some(packet) = state.conn.read_from(buf) {
				return Ok(packet);
			}
			let wait = match state.read_deadline {
				Some(deadline) => {
					let now = std::time::Instant::now();
					if deadline <= now {
						return Err(Error::Timeout);
					}
					deadline - now
				}
				None => Duration::from_secs(3600),
			};
			state = self
				.shared
				.changed
				.wait_timeout(state, wait)
				.unwrap_or_else(|poisoned| poisoned.into_inner())
				.0;
		}
	}

	pub fn write_to(&self, data: &[u8], dest: &PublicKey) -> Result<usize, Error> {
		self.shared.update(|state| state.conn.write_to(data, dest))
	}

	/// Sets the deadline for [`PacketConn::read_from`]. `None` means no deadline.
	pub fn set_read_deadline(&self, deadline: Option<std::time::Instant>) {
		self.shared.update(|state| state.read_deadline = deadline);
	}

	pub fn close(&self) -> Result<(), Error> {
		self.shared.update(|state| state.conn.close())
	}

	pub fn is_closed(&self) -> bool {
		self.shared.lock().conn.is_closed()
	}

	pub fn private_key(&self) -> PrivateKey {
		self.shared.lock().conn.private_key().clone()
	}

	pub fn public_key(&self) -> PublicKey {
		self.shared.lock().conn.public_key()
	}

	pub fn mtu(&self) -> u64 {
		self.shared.lock().conn.mtu()
	}

	pub fn send_lookup(&self, target: &PublicKey) {
		self.shared.update(|state| state.conn.send_lookup(target));
	}

	/// Runs `f` with exclusive access to the wrapped conn, e.g. to read debug information.
	pub fn with<T>(&self, f: impl FnOnce(&mut C) -> T) -> T {
		self.shared.update(|state| f(&mut state.conn))
	}
}

fn run_timers<C: types::PacketConn>(shared: &Shared<C>) {
	let mut state = shared.lock();
	loop {
		if state.conn.is_closed() {
			return;
		}
		state.conn.handle_timeout();
		state.process_events();
		shared.changed.notify_all();
		let wait = match state.conn.poll_timeout() {
			Some(deadline) => deadline.saturating_duration_since(state.conn.now()),
			None => Duration::from_secs(1),
		};
		state = shared
			.changed
			.wait_timeout(state, wait.max(Duration::from_millis(1)))
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.0;
	}
}

fn run_writer<C: types::PacketConn, S: Stream>(shared: &Shared<C>, id: PeerId, mut stream: S) {
	let mut buf = Vec::new();
	loop {
		{
			let mut state = shared.lock();
			loop {
				if !state.alive.contains(&id) {
					return;
				}
				let pending = state.conn.peer_transmit(id);
				if !pending.is_empty() {
					buf.clear();
					buf.extend_from_slice(pending);
					break;
				}
				state = shared
					.changed
					.wait(state)
					.unwrap_or_else(|poisoned| poisoned.into_inner());
			}
		}
		if stream.write_all(&buf).and_then(|_| stream.flush()).is_err() {
			stream.shutdown();
			return;
		}
		shared.update(|state| state.conn.peer_consume(id, buf.len()));
	}
}
