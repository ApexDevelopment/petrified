//! Live interop: Go and Rust nodes in the same networks over localhost TCP.

mod common;

use std::collections::{BTreeSet, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use common::{Rng, harness_bin, hex_key, parse_key};
use petrified::blocking;
use petrified::network::{self, Config};
use petrified::types::{PacketConn, PrivateKey, PublicKey, StdPlatform};
use petrified::{encrypted, signed};

type Received = Arc<Mutex<HashSet<(PublicKey, Vec<u8>)>>>;

#[derive(Clone, Copy, Debug)]
enum Layer {
	Network,
	Encrypted,
	Signed,
}

impl Layer {
	fn name(self) -> &'static str {
		match self {
			Layer::Network => "network",
			Layer::Encrypted => "encrypted",
			Layer::Signed => "signed",
		}
	}
}

trait LiveNode {
	fn key(&self) -> PublicKey;
	fn addr(&self) -> String;
	fn connect(&self, addr: &str);
	fn send(&self, dest: &PublicKey, msg: &[u8]);
	/// The root and coordinates this node currently believes in.
	fn coords(&self) -> (PublicKey, Vec<u64>);
	fn received(&self) -> &Received;
	fn close(&self);
	fn describe(&self) -> String;
}

/********
 * Go *
 ********/

struct GoNode {
	child: Mutex<Child>,
	stdin: Mutex<ChildStdin>,
	key: PublicKey,
	addr: String,
	replies: Mutex<Receiver<String>>,
	received: Received,
}

impl GoNode {
	fn spawn(layer: Layer, seed: &[u8; 32], password: &str) -> Self {
		let mut child = Command::new(harness_bin())
			.args([
				"node",
				"-type",
				layer.name(),
				"-seed",
				&hex::encode(seed),
				"-password",
				password,
			])
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn()
			.expect("failed to start the Go harness");
		let stdin = child.stdin.take().unwrap();
		let mut stdout = BufReader::new(child.stdout.take().unwrap());
		let mut first = String::new();
		stdout.read_line(&mut first).unwrap();
		let fields: Vec<&str> = first.split_whitespace().collect();
		assert_eq!(fields[0], "listening", "{first}");
		let (addr, key) = (fields[1].to_string(), parse_key(fields[2]));
		let received: Received = Default::default();
		let (tx, rx) = channel();
		let sink = received.clone();
		thread::spawn(move || {
			for line in stdout.lines() {
				let Ok(line) = line else { return };
				let fields: Vec<&str> = line.split_whitespace().collect();
				match fields.first() {
					Some(&"recv") => {
						let msg = hex::decode(fields.get(2).unwrap_or(&"")).unwrap();
						sink.lock().unwrap().insert((parse_key(fields[1]), msg));
					}
					Some(&"coords") => {
						let _ = tx.send(line.clone());
					}
					_ => {}
				}
			}
		});
		GoNode {
			child: Mutex::new(child),
			stdin: Mutex::new(stdin),
			key,
			addr,
			replies: Mutex::new(rx),
			received,
		}
	}

	fn command(&self, line: &str) {
		let mut stdin = self.stdin.lock().unwrap();
		let _ = writeln!(stdin, "{line}");
		let _ = stdin.flush();
	}
}

impl LiveNode for GoNode {
	fn key(&self) -> PublicKey {
		self.key
	}

	fn addr(&self) -> String {
		self.addr.clone()
	}

	fn connect(&self, addr: &str) {
		self.command(&format!("connect {addr}"));
	}

	fn send(&self, dest: &PublicKey, msg: &[u8]) {
		self.command(&format!("send {} {}", hex_key(dest), hex::encode(msg)));
	}

	fn coords(&self) -> (PublicKey, Vec<u64>) {
		let replies = self.replies.lock().unwrap();
		self.command("coords");
		let line = replies
			.recv_timeout(Duration::from_secs(5))
			.expect("no coords reply");
		let fields: Vec<&str> = line.split_whitespace().collect();
		(
			parse_key(fields[1]),
			serde_json::from_str(fields[2]).unwrap(),
		)
	}

	fn received(&self) -> &Received {
		&self.received
	}

	fn close(&self) {
		self.command("close");
	}

	fn describe(&self) -> String {
		format!("go:{}", &hex_key(&self.key)[..8])
	}
}

impl Drop for GoNode {
	fn drop(&mut self) {
		self.command("quit");
		let mut child = self.child.lock().unwrap();
		let _ = child.kill();
		let _ = child.wait();
	}
}

/**********
 * Rust *
 **********/

struct RustNode<C: PacketConn + Send + 'static> {
	conn: blocking::PacketConn<C>,
	key: PublicKey,
	addr: String,
	network: fn(&C) -> &network::PacketConn,
	received: Received,
}

/// Exchanges public keys, then runs the connection until it ends.
fn rust_handshake<C: PacketConn + Send + 'static>(
	conn: &blocking::PacketConn<C>,
	mut stream: TcpStream,
) {
	let own = conn.public_key();
	let mut peer = [0u8; 32];
	if stream.write_all(&own.0).is_err() || stream.read_exact(&mut peer).is_err() {
		return;
	}
	let _ = conn.handle_conn(&PublicKey(peer), stream, 0);
}

impl<C: PacketConn + Send + 'static> RustNode<C> {
	fn spawn(inner: C, network: fn(&C) -> &network::PacketConn) -> Self {
		let key = inner.public_key();
		let conn = blocking::PacketConn::new(inner);
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let addr = listener.local_addr().unwrap().to_string();
		let acceptor = conn.clone();
		thread::spawn(move || {
			for stream in listener.incoming() {
				let Ok(stream) = stream else { return };
				if acceptor.is_closed() {
					return;
				}
				let conn = acceptor.clone();
				thread::spawn(move || rust_handshake(&conn, stream));
			}
		});
		let received: Received = Default::default();
		let reader = conn.clone();
		let sink = received.clone();
		thread::spawn(move || {
			let mut buf = vec![0u8; 65535];
			while let Ok((n, from)) = reader.read_from(&mut buf) {
				sink.lock().unwrap().insert((from, buf[..n].to_vec()));
			}
		});
		RustNode {
			conn,
			key,
			addr,
			network,
			received,
		}
	}
}

impl<C: PacketConn + Send + 'static> LiveNode for RustNode<C> {
	fn key(&self) -> PublicKey {
		self.key
	}

	fn addr(&self) -> String {
		self.addr.clone()
	}

	fn connect(&self, addr: &str) {
		let stream = TcpStream::connect(addr).unwrap();
		let conn = self.conn.clone();
		thread::spawn(move || rust_handshake(&conn, stream));
	}

	fn send(&self, dest: &PublicKey, msg: &[u8]) {
		self.conn.write_to(msg, dest).unwrap();
	}

	fn coords(&self) -> (PublicKey, Vec<u64>) {
		let network = self.network;
		self.conn.with(|c| network(c).debug().get_coords())
	}

	fn received(&self) -> &Received {
		&self.received
	}

	fn close(&self) {
		let _ = self.conn.close();
	}

	fn describe(&self) -> String {
		format!("rust:{}", &hex_key(&self.key)[..8])
	}
}

impl<C: PacketConn + Send + 'static> Drop for RustNode<C> {
	fn drop(&mut self) {
		let _ = self.conn.close();
		// Wakes the accept loop so it notices the conn is closed
		let _ = TcpStream::connect(&self.addr);
	}
}

fn spawn_rust(layer: Layer, seed: &[u8; 32], password: &str) -> Box<dyn LiveNode> {
	let key = PrivateKey::from_seed(seed);
	let platform = StdPlatform::new();
	match layer {
		Layer::Network => {
			let conn = network::PacketConn::new(&key, platform, Config::default()).unwrap();
			Box::new(RustNode::spawn(conn, |c| c))
		}
		Layer::Encrypted => {
			let conn = encrypted::PacketConn::new_with_password(
				&key,
				password,
				platform,
				Config::default(),
			)
			.unwrap();
			Box::new(RustNode::spawn(conn, |c| c.network()))
		}
		Layer::Signed => {
			let conn = signed::PacketConn::new(&key, platform, Config::default()).unwrap();
			Box::new(RustNode::spawn(conn, |c| c.network()))
		}
	}
}

/***********
 * helpers *
 ***********/

struct Network {
	nodes: Vec<Box<dyn LiveNode>>,
}

impl Network {
	/// `go[i]` says whether node `i` runs the Go implementation.
	fn spawn(rng: &mut Rng, layer: Layer, go: &[bool], password: &str) -> Self {
		let nodes = go
			.iter()
			.map(|&is_go| {
				let seed: [u8; 32] = rng.array();
				if is_go {
					Box::new(GoNode::spawn(layer, &seed, password)) as Box<dyn LiveNode>
				} else {
					spawn_rust(layer, &seed, password)
				}
			})
			.collect();
		Network { nodes }
	}

	fn connect(&self, a: usize, b: usize) {
		self.nodes[a].connect(&self.nodes[b].addr());
	}

	/// Waits until every live node reports the lowest key as root, then checks that coordinates are unique.
	fn wait_for_root(&self, live: &[usize], timeout: Duration) {
		let lowest = live.iter().map(|&n| self.nodes[n].key()).min().unwrap();
		let start = Instant::now();
		loop {
			let coords: Vec<(PublicKey, Vec<u64>)> =
				live.iter().map(|&n| self.nodes[n].coords()).collect();
			if coords.iter().all(|(root, _)| *root == lowest) {
				let unique: BTreeSet<&Vec<u64>> = coords.iter().map(|(_, path)| path).collect();
				assert_eq!(unique.len(), coords.len(), "duplicate coords: {coords:?}");
				return;
			}
			if start.elapsed() > timeout {
				let report: Vec<String> = live
					.iter()
					.zip(&coords)
					.map(|(&n, (root, path))| {
						format!(
							"{} -> {} {:?}",
							self.nodes[n].describe(),
							&hex_key(root)[..8],
							path
						)
					})
					.collect();
				panic!("no single root after {timeout:?}:\n{}", report.join("\n"));
			}
			thread::sleep(Duration::from_millis(250));
		}
	}

	/// Sends a message between every ordered pair, resending once a second until each arrives.
	fn assert_all_pairs(&self, live: &[usize], timeout: Duration) {
		let message = |a: usize, b: usize| format!("hello from {a} to {b}").into_bytes();
		let mut pending: Vec<(usize, usize)> = live
			.iter()
			.flat_map(|&a| live.iter().filter(move |&&b| b != a).map(move |&b| (a, b)))
			.collect();
		let start = Instant::now();
		while !pending.is_empty() {
			assert!(
				start.elapsed() < timeout,
				"undelivered after {timeout:?}: {:?}",
				pending
					.iter()
					.map(|&(a, b)| format!(
						"{} -> {}",
						self.nodes[a].describe(),
						self.nodes[b].describe()
					))
					.collect::<Vec<_>>()
			);
			for &(a, b) in &pending {
				self.nodes[a].send(&self.nodes[b].key(), &message(a, b));
			}
			for _ in 0..4 {
				thread::sleep(Duration::from_millis(250));
				pending.retain(|&(a, b)| {
					let wanted = (self.nodes[a].key(), message(a, b));
					!self.nodes[b].received().lock().unwrap().contains(&wanted)
				});
			}
		}
	}

	fn assert_never_delivered(&self, a: usize, b: usize, wait: Duration) {
		let msg = b"should not arrive".to_vec();
		let start = Instant::now();
		while start.elapsed() < wait {
			self.nodes[a].send(&self.nodes[b].key(), &msg);
			thread::sleep(Duration::from_millis(500));
		}
		let wanted = (self.nodes[a].key(), msg);
		assert!(!self.nodes[b].received().lock().unwrap().contains(&wanted));
	}
}

const CONVERGE: Duration = Duration::from_secs(45);
const DELIVER: Duration = Duration::from_secs(60);

fn pair_test(layer: Layer, seed: u64) {
	let mut rng = Rng::new(seed);
	let net = Network::spawn(&mut rng, layer, &[true, false], "");
	net.connect(1, 0);
	net.wait_for_root(&[0, 1], CONVERGE);
	net.assert_all_pairs(&[0, 1], DELIVER);
}

#[test]
fn pair_network() {
	pair_test(Layer::Network, 1);
}

#[test]
fn pair_encrypted() {
	pair_test(Layer::Encrypted, 2);
}

#[test]
fn pair_signed() {
	pair_test(Layer::Signed, 3);
}

#[test]
fn encrypted_passwords() {
	let mut rng = Rng::new(4);
	let go = [true, false];
	let matching = Network::spawn(&mut rng, Layer::Encrypted, &go, "hunter2");
	matching.connect(0, 1);
	matching.wait_for_root(&[0, 1], CONVERGE);
	matching.assert_all_pairs(&[0, 1], DELIVER);

	let seeds: [[u8; 32]; 2] = [rng.array(), rng.array()];
	let mismatched = Network {
		nodes: vec![
			Box::new(GoNode::spawn(Layer::Encrypted, &seeds[0], "hunter2")),
			spawn_rust(Layer::Encrypted, &seeds[1], "other"),
		],
	};
	mismatched.connect(0, 1);
	mismatched.wait_for_root(&[0, 1], CONVERGE);
	mismatched.assert_never_delivered(0, 1, Duration::from_secs(4));
	mismatched.assert_never_delivered(1, 0, Duration::from_secs(4));
}

#[test]
fn mixed_line() {
	let mut rng = Rng::new(5);
	let go: Vec<bool> = (0..8).map(|idx| idx % 2 == 0).collect();
	let net = Network::spawn(&mut rng, Layer::Encrypted, &go, "");
	for idx in 1..go.len() {
		net.connect(idx, idx - 1);
	}
	let all: Vec<usize> = (0..go.len()).collect();
	net.wait_for_root(&all, CONVERGE);
	net.assert_all_pairs(&all, DELIVER);
}

/// Builds a random connected mesh over `count` nodes.
fn mesh(rng: &mut Rng, layer: Layer, count: usize) -> Network {
	let go: Vec<bool> = (0..count).map(|_| rng.chance(1, 2)).collect();
	let net = Network::spawn(rng, layer, &go, "");
	for idx in 1..count {
		net.connect(idx, rng.below(idx as u64) as usize);
	}
	for _ in 0..count / 2 {
		let (a, b) = (
			rng.below(count as u64) as usize,
			rng.below(count as u64) as usize,
		);
		if a != b {
			net.connect(a, b);
		}
	}
	net
}

#[test]
fn mixed_mesh_network_layer() {
	let mut rng = Rng::new(6);
	let net = mesh(&mut rng, Layer::Network, 12);
	let all: Vec<usize> = (0..12).collect();
	net.wait_for_root(&all, CONVERGE);
	net.assert_all_pairs(&all, DELIVER);
}

#[test]
fn mixed_mesh_survives_departures() {
	let mut rng = Rng::new(7);
	let count = 12;
	// A ring plus chords, so no single departure partitions it
	let go: Vec<bool> = (0..count).map(|idx| idx % 3 != 0).collect();
	let net = Network::spawn(&mut rng, Layer::Encrypted, &go, "");
	for idx in 0..count {
		net.connect(idx, (idx + 1) % count);
	}
	for idx in (0..count).step_by(3) {
		net.connect(idx, (idx + count / 2) % count);
	}
	let all: Vec<usize> = (0..count).collect();
	net.wait_for_root(&all, CONVERGE);
	net.assert_all_pairs(&all, DELIVER);

	// The root leaves, then a Rust node leaves too
	let root = all
		.iter()
		.copied()
		.min_by_key(|&n| net.nodes[n].key())
		.unwrap();
	let rust = all.iter().copied().find(|&n| !go[n] && n != root).unwrap();
	net.nodes[root].close();
	net.nodes[rust].close();
	let remaining: Vec<usize> = all
		.into_iter()
		.filter(|&n| n != root && n != rust)
		.collect();
	net.wait_for_root(&remaining, Duration::from_secs(90));
	net.assert_all_pairs(&remaining, DELIVER);
}
