//! A minimal encrypted node over TCP.
//!
//! ```text
//! cargo run --example node -- --listen 127.0.0.1:9000
//! cargo run --example node -- --connect 127.0.0.1:9000
//! ```
//!
//! Type `<destination key hex> <message>` to send. Received messages are printed.
//! Peers exchange 32-byte public keys before handing the stream to Ironwood,
//! which is the same handshake the interop harness uses.

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use petrified::blocking;
use petrified::encrypted::PacketConn;
use petrified::network::Config;
use petrified::types::{Platform, PrivateKey, PublicKey, StdPlatform};

type Node = blocking::PacketConn<PacketConn>;

fn run_peer(node: &Node, mut stream: TcpStream) {
	let mut peer = [0u8; 32];
	if stream.write_all(&node.public_key().0).is_err() || stream.read_exact(&mut peer).is_err() {
		return;
	}
	let peer = PublicKey(peer);
	println!("connected to {peer}");
	if let Err(error) = node.handle_conn(&peer, stream, 0) {
		println!("disconnected from {peer}: {error}");
	}
}

fn main() {
	let mut platform = StdPlatform::new();
	let mut seed = [0u8; 32];
	platform.fill_random(&mut seed);
	let conn = PacketConn::new(&PrivateKey::from_seed(&seed), platform, Config::default())
		.expect("valid key");
	let node = Node::new(conn);
	println!("our key: {}", node.public_key());

	let args: Vec<String> = std::env::args().skip(1).collect();
	for pair in args.chunks(2) {
		match (pair[0].as_str(), pair.get(1)) {
			("--listen", Some(addr)) => {
				let listener = TcpListener::bind(addr).expect("bind");
				let node = node.clone();
				thread::spawn(move || {
					for stream in listener.incoming().flatten() {
						let node = node.clone();
						thread::spawn(move || run_peer(&node, stream));
					}
				});
			}
			("--connect", Some(addr)) => {
				let stream = TcpStream::connect(addr).expect("connect");
				let node = node.clone();
				thread::spawn(move || run_peer(&node, stream));
			}
			_ => {
				eprintln!("usage: node [--listen ADDR] [--connect ADDR]...");
				return;
			}
		}
	}

	let reader = node.clone();
	thread::spawn(move || {
		let mut buf = vec![0u8; 65535];
		while let Ok((n, from)) = reader.read_from(&mut buf) {
			println!("{from}: {}", String::from_utf8_lossy(&buf[..n]));
		}
	});

	for line in std::io::stdin().lock().lines().map_while(Result::ok) {
		let Some((dest, message)) = line.split_once(' ') else {
			continue;
		};
		let Some(dest) = hex::decode(dest)
			.ok()
			.and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
		else {
			eprintln!("destination must be a 64 character hex key");
			continue;
		};
		if let Err(error) = node.write_to(message.as_bytes(), &PublicKey(dest)) {
			eprintln!("send failed: {error}");
		}
	}
}
