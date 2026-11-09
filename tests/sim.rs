//! Deterministic simulations: nodes wired together in memory, driven by a virtual clock.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::Rng;
use petrified::network::{self, Config};
use petrified::types::{
	Error, Event, Instant, PacketConn, PeerId, Platform, PrivateKey, PublicKey,
};
use petrified::{encrypted, signed};

const UNIX_BASE: u64 = 1_800_000_000;

struct SimPlatform {
	clock_ms: Arc<AtomicU64>,
	rng: Rng,
}

impl Platform for SimPlatform {
	fn now(&self) -> Instant {
		Instant::from_duration(Duration::from_millis(self.clock_ms.load(Ordering::Relaxed)))
	}

	fn unix_time(&self) -> u64 {
		UNIX_BASE + self.clock_ms.load(Ordering::Relaxed) / 1000
	}

	fn fill_random(&mut self, buf: &mut [u8]) {
		buf.copy_from_slice(&self.rng.bytes(buf.len()));
	}
}

#[derive(Clone, Copy)]
enum Layer {
	Network,
	Encrypted,
	Signed,
}

struct Link {
	a: usize,
	a_id: PeerId,
	b: usize,
	b_id: PeerId,
	/// When false, bytes from `b` to `a` are lost, simulating a stalled peer.
	b_to_a: bool,
}

#[allow(clippy::large_enum_variant)]
enum Node {
	Network(network::PacketConn),
	Encrypted(encrypted::PacketConn),
	Signed(signed::PacketConn),
}

impl Node {
	fn conn(&mut self) -> &mut dyn PacketConn {
		match self {
			Node::Network(conn) => conn,
			Node::Encrypted(conn) => conn,
			Node::Signed(conn) => conn,
		}
	}

	fn network(&self) -> &network::PacketConn {
		match self {
			Node::Network(conn) => conn,
			Node::Encrypted(conn) => conn.network(),
			Node::Signed(conn) => conn.network(),
		}
	}
}

struct Sim {
	clock_ms: Arc<AtomicU64>,
	rng: Rng,
	nodes: Vec<Node>,
	links: Vec<Link>,
	events: Vec<(usize, Event)>,
}

impl Sim {
	fn new(seed: u64) -> Self {
		Sim {
			clock_ms: Arc::new(AtomicU64::new(0)),
			rng: Rng::new(seed),
			nodes: Vec::new(),
			links: Vec::new(),
			events: Vec::new(),
		}
	}

	fn platform(&mut self) -> SimPlatform {
		SimPlatform {
			clock_ms: self.clock_ms.clone(),
			rng: Rng::new(self.rng.next_u64()),
		}
	}

	fn make_node(&mut self, layer: Layer, key: &PrivateKey, password: &str) -> Node {
		let platform = self.platform();
		let config = Config::default();
		match layer {
			Layer::Network => {
				Node::Network(network::PacketConn::new(key, platform, config).unwrap())
			}
			Layer::Encrypted => Node::Encrypted(
				encrypted::PacketConn::new_with_password(key, password, platform, config).unwrap(),
			),
			Layer::Signed => Node::Signed(signed::PacketConn::new(key, platform, config).unwrap()),
		}
	}

	fn add_node(&mut self, layer: Layer) -> usize {
		let key = self.rng.private_key();
		self.add_node_with(layer, &key, "")
	}

	fn add_node_with(&mut self, layer: Layer, key: &PrivateKey, password: &str) -> usize {
		let node = self.make_node(layer, key, password);
		self.nodes.push(node);
		self.nodes.len() - 1
	}

	fn add_node_with_queued_paths(&mut self) -> usize {
		let key = self.rng.private_key();
		let platform = self.platform();
		let config = Config::default().with_path_notify_queue();
		let conn = network::PacketConn::new(&key, platform, config).unwrap();
		self.nodes.push(Node::Network(conn));
		self.nodes.len() - 1
	}

	fn key(&self, node: usize) -> PublicKey {
		self.nodes[node].network().debug().get_self().key
	}

	fn connect(&mut self, a: usize, b: usize) -> usize {
		let (key_a, key_b) = (self.key(a), self.key(b));
		let a_id = self.nodes[a].conn().handle_conn(&key_b, 0).unwrap();
		let b_id = self.nodes[b].conn().handle_conn(&key_a, 0).unwrap();
		self.links.push(Link {
			a,
			a_id,
			b,
			b_id,
			b_to_a: true,
		});
		self.links.len() - 1
	}

	fn disconnect(&mut self, link: usize) {
		let link = self.links.remove(link);
		let _ = self.nodes[link.a].conn().remove_peer(link.a_id);
		let _ = self.nodes[link.b].conn().remove_peer(link.b_id);
	}

	/// Moves bytes across links until every queue is empty.
	fn pump(&mut self) {
		loop {
			let mut moved = false;
			let mut idx = 0;
			while idx < self.links.len() {
				let link = &self.links[idx];
				let directions = [
					(link.a, link.a_id, link.b, link.b_id, true),
					(link.b, link.b_id, link.a, link.a_id, link.b_to_a),
				];
				let mut broken = false;
				for (from, from_id, to, to_id, delivered) in directions {
					let bytes = self.nodes[from].conn().peer_transmit(from_id).to_vec();
					if bytes.is_empty() {
						continue;
					}
					moved = true;
					self.nodes[from].conn().peer_consume(from_id, bytes.len());
					if delivered
						&& self.nodes[to]
							.conn()
							.handle_peer_data(to_id, &bytes)
							.is_err()
					{
						broken = true;
						break;
					}
				}
				if broken {
					self.disconnect(idx);
				} else {
					idx += 1;
				}
			}
			self.collect_events();
			if !moved {
				return;
			}
		}
	}

	fn collect_events(&mut self) {
		for idx in 0..self.nodes.len() {
			while let Some(event) = self.nodes[idx].conn().poll_event() {
				let Event::PeerClosed { peer, .. } = event;
				self.events.push((idx, event));
				if let Some(pos) = self
					.links
					.iter()
					.position(|l| (l.a == idx && l.a_id == peer) || (l.b == idx && l.b_id == peer))
				{
					self.disconnect(pos);
				}
			}
		}
	}

	/// Advances the clock, running timers and moving traffic every 10ms.
	fn run(&mut self, duration: Duration) {
		let end = self.clock_ms.load(Ordering::Relaxed) + duration.as_millis() as u64;
		self.pump();
		while self.clock_ms.load(Ordering::Relaxed) < end {
			self.clock_ms.fetch_add(10, Ordering::Relaxed);
			for node in self.nodes.iter_mut() {
				let node = node.conn();
				if node
					.poll_timeout()
					.is_some_and(|deadline| deadline <= node.now())
				{
					node.handle_timeout();
				}
			}
			self.pump();
		}
	}

	/// Sends `msg` from `a` to `b` once a second until it arrives. Returns how long that took.
	fn deliver(&mut self, a: usize, b: usize, msg: &[u8], limit: Duration) -> Option<Duration> {
		let start = self.clock_ms.load(Ordering::Relaxed);
		let key_a = self.key(a);
		let key_b = self.key(b);
		let mut elapsed = 0;
		while elapsed <= limit.as_millis() as u64 {
			if elapsed % 1000 == 0 {
				self.nodes[a].conn().write_to(msg, &key_b).unwrap();
			}
			self.run(Duration::from_millis(50));
			elapsed = self.clock_ms.load(Ordering::Relaxed) - start;
			while let Some((from, data)) = self.nodes[b].conn().recv() {
				if from == key_a && data == msg {
					return Some(Duration::from_millis(elapsed));
				}
			}
		}
		None
	}

	fn assert_all_pairs(&mut self, nodes: &[usize]) {
		for &a in nodes {
			for &b in nodes {
				if a != b {
					let msg = format!("{a} to {b}").into_bytes();
					assert!(
						self.deliver(a, b, &msg, Duration::from_secs(20)).is_some(),
						"{a} could not reach {b}"
					);
				}
			}
		}
	}

	/// Runs until every node agrees on the lowest key as root, like Go's `waitForRoot`.
	fn wait_for_root(&mut self, timeout: Duration) {
		let lowest = (0..self.nodes.len()).map(|n| self.key(n)).min().unwrap();
		let start = self.clock_ms.load(Ordering::Relaxed);
		while self.roots() != BTreeSet::from([lowest]) {
			assert!(
				self.clock_ms.load(Ordering::Relaxed) - start < timeout.as_millis() as u64,
				"no single root after {timeout:?}: {:?}",
				self.roots()
			);
			self.run(Duration::from_millis(100));
		}
	}

	fn roots(&self) -> BTreeSet<PublicKey> {
		self.nodes
			.iter()
			.map(|node| node.network().debug().get_coords().0)
			.collect()
	}
}

fn line(sim: &mut Sim, layers: &[Layer]) -> Vec<usize> {
	let nodes: Vec<usize> = layers.iter().map(|&layer| sim.add_node(layer)).collect();
	for pair in nodes.windows(2) {
		sim.connect(pair[0], pair[1]);
	}
	nodes
}

#[test]
fn two_nodes_every_layer() {
	for layer in [Layer::Network, Layer::Encrypted, Layer::Signed] {
		let mut sim = Sim::new(1);
		let nodes = line(&mut sim, &[layer, layer]);
		sim.run(Duration::from_secs(3));
		sim.assert_all_pairs(&nodes);
	}
}

#[test]
fn line_network() {
	let mut sim = Sim::new(2);
	let nodes = line(&mut sim, &[Layer::Encrypted; 8]);
	sim.wait_for_root(Duration::from_secs(30));
	sim.assert_all_pairs(&nodes);
}

#[test]
fn random_tree_network() {
	let mut sim = Sim::new(3);
	let nodes: Vec<usize> = (0..24).map(|_| sim.add_node(Layer::Network)).collect();
	for idx in 1..nodes.len() {
		let parent = sim.rng.below(idx as u64) as usize;
		sim.connect(nodes[idx], nodes[parent]);
	}
	sim.wait_for_root(Duration::from_secs(30));
	let sample: Vec<usize> = nodes.iter().copied().step_by(3).collect();
	sim.assert_all_pairs(&sample);
}

#[test]
fn coords_are_unique_and_consistent() {
	let mut sim = Sim::new(4);
	let nodes: Vec<usize> = (0..16).map(|_| sim.add_node(Layer::Network)).collect();
	for idx in 1..nodes.len() {
		let parent = sim.rng.below(idx as u64) as usize;
		sim.connect(nodes[idx], nodes[parent]);
	}
	for _ in 0..8 {
		let (a, b) = (sim.rng.below(16) as usize, sim.rng.below(16) as usize);
		if a != b {
			sim.connect(a, b);
		}
	}
	sim.wait_for_root(Duration::from_secs(30));
	sim.run(Duration::from_secs(5));
	let coords: Vec<Vec<u64>> = nodes
		.iter()
		.map(|&n| sim.nodes[n].network().debug().get_coords().1)
		.collect();
	let unique: BTreeSet<&Vec<u64>> = coords.iter().collect();
	assert_eq!(unique.len(), coords.len(), "duplicate coords: {coords:?}");
	// Each node's view of its own path to the root matches what every ancestor believes.
	// (Info about nodes off that path is allowed to go stale until it times out.)
	let own_parent = |sim: &Sim, n: usize| {
		let key = sim.key(n);
		sim.nodes[n]
			.network()
			.debug()
			.get_tree()
			.into_iter()
			.find(|t| t.key == key)
			.unwrap()
			.parent
	};
	let node_of =
		|sim: &Sim, key: PublicKey| nodes.iter().copied().find(|&n| sim.key(n) == key).unwrap();
	for &m in &nodes {
		let view = sim.nodes[m].network().debug().get_tree();
		let mut here = sim.key(m);
		loop {
			let parent = view.iter().find(|t| t.key == here).unwrap().parent;
			assert_eq!(
				parent,
				own_parent(&sim, node_of(&sim, here)),
				"node {m}'s view of {here}"
			);
			if parent == here {
				break;
			}
			here = parent;
		}
	}
}

#[test]
fn reroutes_around_a_failed_link() {
	let mut sim = Sim::new(5);
	// A ring, so there is always a second way around
	let nodes: Vec<usize> = (0..8).map(|_| sim.add_node(Layer::Encrypted)).collect();
	for idx in 0..nodes.len() {
		sim.connect(nodes[idx], nodes[(idx + 1) % nodes.len()]);
	}
	sim.wait_for_root(Duration::from_secs(30));
	sim.assert_all_pairs(&[0, 4]);
	// Cut the link on the current path between 0 and 4
	let tree_link = (0..sim.links.len())
		.find(|&l| {
			let link = &sim.links[l];
			let parent_of_a = sim.nodes[link.a]
				.network()
				.debug()
				.get_tree()
				.into_iter()
				.find(|t| t.key == sim.key(link.a))
				.unwrap()
				.parent;
			parent_of_a == sim.key(link.b)
		})
		.unwrap();
	sim.disconnect(tree_link);
	sim.wait_for_root(Duration::from_secs(30));
	sim.assert_all_pairs(&nodes);
}

#[test]
fn stalled_peer_times_out() {
	let mut sim = Sim::new(6);
	let nodes = line(&mut sim, &[Layer::Network, Layer::Network]);
	sim.run(Duration::from_secs(2));
	sim.links[0].b_to_a = false;
	let key_b = sim.key(nodes[1]);
	sim.nodes[0].conn().write_to(b"ping", &key_b).unwrap();
	sim.run(Duration::from_secs(5));
	assert!(
		sim.events.iter().any(|(node, event)| *node == 0
			&& matches!(
				event,
				Event::PeerClosed {
					error: Error::Timeout,
					..
				}
			)),
		"{:?}",
		sim.events
	);
}

#[test]
fn idle_links_stay_up() {
	let mut sim = Sim::new(7);
	// The middle node only forwards, so it can use a different layer
	let nodes = line(
		&mut sim,
		&[Layer::Encrypted, Layer::Network, Layer::Encrypted],
	);
	sim.wait_for_root(Duration::from_secs(30));
	sim.assert_all_pairs(&[0, 2]);
	sim.run(Duration::from_secs(60));
	assert!(sim.events.is_empty(), "{:?}", sim.events);
	assert_eq!(sim.links.len(), nodes.len() - 1);
}

#[test]
fn multiple_links_between_the_same_nodes() {
	let mut sim = Sim::new(8);
	let nodes = line(&mut sim, &[Layer::Encrypted, Layer::Encrypted]);
	sim.connect(nodes[0], nodes[1]);
	sim.connect(nodes[1], nodes[0]);
	sim.run(Duration::from_secs(3));
	sim.assert_all_pairs(&nodes);
	sim.disconnect(0);
	sim.disconnect(0);
	sim.run(Duration::from_secs(2));
	sim.assert_all_pairs(&nodes);
}

#[test]
fn encrypted_session_survives_a_restart() {
	let mut sim = Sim::new(9);
	let key_b = sim.rng.private_key();
	let a = sim.add_node(Layer::Encrypted);
	let b = sim.add_node_with(Layer::Encrypted, &key_b, "");
	sim.connect(a, b);
	sim.run(Duration::from_secs(3));
	sim.assert_all_pairs(&[a, b]);
	// Restart b with the same key, losing all of its session state
	sim.disconnect(0);
	sim.nodes[b] = sim.make_node(Layer::Encrypted, &key_b, "");
	sim.run(Duration::from_secs(2));
	sim.connect(a, b);
	sim.run(Duration::from_secs(3));
	sim.assert_all_pairs(&[a, b]);
}

#[test]
fn passwords_gate_sessions() {
	let mut sim = Sim::new(10);
	let keys: Vec<PrivateKey> = (0..3).map(|_| sim.rng.private_key()).collect();
	let a = sim.add_node_with(Layer::Encrypted, &keys[0], "secret");
	let b = sim.add_node_with(Layer::Encrypted, &keys[1], "secret");
	let c = sim.add_node_with(Layer::Encrypted, &keys[2], "wrong");
	sim.connect(a, b);
	sim.connect(b, c);
	sim.run(Duration::from_secs(3));
	sim.assert_all_pairs(&[a, b]);
	assert!(sim.deliver(a, c, b"no", Duration::from_secs(5)).is_none());
	assert!(sim.deliver(c, b, b"no", Duration::from_secs(5)).is_none());
}

/// A framed sigRes whose signature does not verify.
fn bad_sig_res() -> Vec<u8> {
	let mut frame = vec![68, 0x03, 0x01, 0x01, 0x01];
	frame.extend([0u8; 64]);
	frame
}

#[test]
fn rejects_bad_peer_data() {
	let mut sim = Sim::new(11);
	let a = sim.add_node(Layer::Network);
	let other = sim.rng.private_key().public_key();
	let cases: [(&[u8], Error); 4] = [
		(&[0x00], Error::EmptyMessage),
		(&[0x01, 0x63], Error::UnrecognizedMessage),
		(&[0x80, 0x80, 0x80, 0x01], Error::OversizedMessage),
		(&bad_sig_res(), Error::BadMessage),
	];
	for (data, expected) in cases {
		let id = sim.nodes[a].conn().handle_conn(&other, 0).unwrap();
		assert_eq!(
			sim.nodes[a].conn().handle_peer_data(id, data),
			Err(expected)
		);
		assert_eq!(
			sim.nodes[a].conn().remove_peer(id),
			Err(Error::PeerNotFound)
		);
	}
	let own = sim.key(a);
	assert_eq!(sim.nodes[a].conn().handle_conn(&own, 0), Err(Error::BadKey));
	assert_eq!(
		sim.nodes[a].conn().handle_conn(&PublicKey([0; 32]), 0),
		Err(Error::BadKey)
	);
}

#[test]
fn writes_respect_the_mtu_and_close() {
	let mut sim = Sim::new(12);
	for layer in [Layer::Network, Layer::Encrypted, Layer::Signed] {
		let a = sim.add_node(layer);
		let dest = sim.rng.private_key().public_key();
		let conn = sim.nodes[a].conn();
		let mtu = conn.mtu() as usize;
		assert!(conn.write_to(&vec![0; mtu], &dest).is_ok());
		assert_eq!(
			conn.write_to(&vec![0; mtu + 1], &dest),
			Err(Error::OversizedMessage)
		);
		conn.close().unwrap();
		assert_eq!(conn.close(), Err(Error::Closed));
		assert_eq!(conn.write_to(b"x", &dest), Err(Error::Closed));
		assert_eq!(conn.handle_conn(&dest, 0), Err(Error::Closed));
	}
}

#[test]
fn queued_path_notifications() {
	let mut sim = Sim::new(9);
	let source = sim.add_node_with_queued_paths();
	let middle = sim.add_node(Layer::Network);
	let target = sim.add_node(Layer::Network);
	sim.connect(source, middle);
	sim.connect(middle, target);
	sim.wait_for_root(Duration::from_secs(30));
	let Node::Network(conn) = &mut sim.nodes[source] else {
		unreachable!()
	};
	assert_eq!(conn.poll_path_notify(), None);
	let target_key = sim.key(target);
	assert!(
		sim.deliver(source, target, b"hello", Duration::from_secs(20))
			.is_some()
	);
	let Node::Network(conn) = &mut sim.nodes[source] else {
		unreachable!()
	};
	assert_eq!(conn.poll_path_notify(), Some(target_key));
	assert_eq!(conn.poll_path_notify(), None);
}
