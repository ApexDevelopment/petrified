//! Differential tests: the same inputs go through the Go implementation and
//! through petrified, and the results must be identical.

mod common;

use common::{Rng, Vectors, hex_key, parse_key};
use petrified::encrypted::internals as enc;
use petrified::network::internals::{self as net, KINDS, RouterHarness};
use petrified::types::{PrivateKey, PublicKey, is_public_key_valid};
use serde_json::{Value, json};

fn go_reencode(go: &Vectors, kind: &str, data: &[u8]) -> Option<Vec<u8>> {
	let reply = go.call(json!({"op": "reencode", "kind": kind, "data": hex::encode(data)}));
	reply["data"].as_str().map(|s| hex::decode(s).unwrap())
}

fn assert_reencode_matches(go: &Vectors, kind: &str, data: &[u8]) {
	let ours = net::reencode(kind, data).ok();
	let theirs = go_reencode(go, kind, data);
	assert_eq!(ours, theirs, "{kind} {}", hex::encode(data));
}

/// Builds wire messages from random fields, sometimes with non-minimal varints.
struct MessageGen<'a> {
	rng: &'a mut Rng,
}

impl MessageGen<'_> {
	fn uint(&mut self, out: &mut Vec<u8>) {
		let value = match self.rng.below(4) {
			0 => self.rng.below(128),
			1 => self.rng.below(1 << 20),
			2 => u64::MAX - self.rng.below(3),
			_ => self.rng.next_u64(),
		};
		let mut v = value;
		while v >= 0x80 {
			out.push(v as u8 | 0x80);
			v >>= 7;
		}
		if self.rng.chance(1, 10) && out.len() < 9 {
			// A non-minimal encoding, which Go accepts
			out.push(v as u8 | 0x80);
			out.push(0);
		} else {
			out.push(v as u8);
		}
	}

	fn path(&mut self, out: &mut Vec<u8>) {
		for _ in 0..self.rng.below(6) {
			let port = 1 + self.rng.below(300);
			out.extend(varint(port));
		}
		out.push(0);
	}

	fn bytes(&mut self, out: &mut Vec<u8>, len: usize) {
		out.extend(self.rng.bytes(len));
	}

	fn bloom(&mut self, out: &mut Vec<u8>) {
		let mut flags0 = [0u8; 16];
		let mut flags1 = [0u8; 16];
		let mut words = Vec::new();
		for idx in 0..128 {
			match self.rng.below(3) {
				0 => flags0[idx / 8] |= 0x80 >> (idx % 8),
				1 => flags1[idx / 8] |= 0x80 >> (idx % 8),
				_ => words.extend(self.rng.bytes(8)),
			}
		}
		out.extend(flags0);
		out.extend(flags1);
		out.extend(words);
	}

	fn message(&mut self, kind: &str) -> Vec<u8> {
		let mut out = Vec::new();
		match kind {
			"sigreq" => {
				self.uint(&mut out);
				self.uint(&mut out);
			}
			"sigres" => {
				self.uint(&mut out);
				self.uint(&mut out);
				self.uint(&mut out);
				self.bytes(&mut out, 64);
			}
			"announce" => {
				self.bytes(&mut out, 64);
				self.uint(&mut out);
				self.uint(&mut out);
				self.uint(&mut out);
				self.bytes(&mut out, 128);
			}
			"bloom" => self.bloom(&mut out),
			"lookup" => {
				self.bytes(&mut out, 64);
				self.path(&mut out);
			}
			"notify" => {
				self.path(&mut out);
				self.uint(&mut out);
				self.bytes(&mut out, 64);
				self.uint(&mut out);
				self.path(&mut out);
				self.bytes(&mut out, 64);
			}
			"broken" => {
				self.path(&mut out);
				self.uint(&mut out);
				self.bytes(&mut out, 64);
			}
			"traffic" => {
				self.path(&mut out);
				self.path(&mut out);
				self.bytes(&mut out, 64);
				self.uint(&mut out);
				let len = self.rng.below(40) as usize;
				self.bytes(&mut out, len);
			}
			_ => unreachable!(),
		}
		out
	}

	/// Truncates, extends, or flips bits in a message.
	fn mutate(&mut self, mut data: Vec<u8>) -> Vec<u8> {
		match self.rng.below(4) {
			0 if !data.is_empty() => {
				let len = self.rng.below(data.len() as u64) as usize;
				data.truncate(len);
			}
			1 => {
				let len = 1 + self.rng.below(4) as usize;
				data.extend(self.rng.bytes(len));
			}
			_ if !data.is_empty() => {
				for _ in 0..1 + self.rng.below(3) {
					let idx = self.rng.below(data.len() as u64) as usize;
					data[idx] ^= 1 << self.rng.below(8);
				}
			}
			_ => {}
		}
		data
	}
}

fn varint(mut v: u64) -> Vec<u8> {
	let mut out = Vec::new();
	while v >= 0x80 {
		out.push(v as u8 | 0x80);
		v >>= 7;
	}
	out.push(v as u8);
	out
}

#[test]
fn wire_formats_match() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(1);
	for kind in KINDS {
		for _ in 0..150 {
			let message = MessageGen { rng: &mut rng }.message(kind);
			assert_reencode_matches(&go, kind, &message);
			let mutated = MessageGen { rng: &mut rng }.mutate(message);
			assert_reencode_matches(&go, kind, &mutated);
		}
		for len in 0..80 {
			let noise = rng.bytes(len);
			assert_reencode_matches(&go, kind, &noise);
		}
	}
}

#[test]
fn varint_edge_cases_match() {
	let go = Vectors::spawn();
	let cases: [&[u8]; 6] = [
		&[
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00,
		],
		&[
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00,
		],
		&[
			0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00,
		],
		&[0x80, 0x00, 0x80, 0x00],
		&[0x80],
		&[],
	];
	for case in cases {
		assert_reencode_matches(&go, "sigreq", case);
	}
}

#[test]
fn signature_checks_match() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(2);
	for _ in 0..60 {
		let node = rng.private_key();
		let parent = if rng.chance(1, 4) {
			node.clone()
		} else {
			rng.private_key()
		};
		let port = if rng.chance(1, 4) {
			0
		} else {
			1 + rng.below(100)
		};
		let mut ann = net::signed_announce(&node, &parent, rng.below(1000), rng.next_u64(), port);
		if rng.chance(1, 3) {
			let idx = rng.below(ann.len() as u64) as usize;
			ann[idx] ^= 1 << rng.below(8);
		}
		let (nk, pk) = (node.public_key(), parent.public_key());
		let ours = net::check("announce", &ann, &nk, &pk).ok();
		let reply = go.call(json!({"op": "check", "kind": "announce", "data": hex::encode(&ann), "node": hex_key(&nk), "parent": hex_key(&pk)}));
		assert_eq!(
			ours,
			reply["valid"].as_bool(),
			"announce {}",
			hex::encode(&ann)
		);

		// The sigRes embedded in the announcement, checked against both keys
		if let Ok(reencoded) = net::reencode("announce", &ann) {
			let res = &reencoded[64..reencoded.len() - 64];
			for (a, b) in [(nk, pk), (pk, nk)] {
				let ours = net::check("sigres", res, &a, &b).ok();
				let reply = go.call(json!({"op": "check", "kind": "sigres", "data": hex::encode(res), "node": hex_key(&a), "parent": hex_key(&b)}));
				assert_eq!(ours, reply["valid"].as_bool());
			}
		}

		let coords: Vec<u64> = (0..rng.below(5)).map(|_| 1 + rng.below(50)).collect();
		let mut notify = net::signed_notify(&node, &pk, &[1, 2], u64::MAX, rng.next_u64(), &coords);
		if rng.chance(1, 3) {
			let idx = rng.below(notify.len() as u64) as usize;
			notify[idx] ^= 1 << rng.below(8);
		}
		let ours = net::check("notify", &notify, &nk, &pk).ok();
		let reply = go.call(
			json!({"op": "check", "kind": "notify", "data": hex::encode(&notify), "node": "", "parent": ""}),
		);
		assert_eq!(
			ours,
			reply["valid"].as_bool(),
			"notify {}",
			hex::encode(&notify)
		);
	}
}

/// Keys that exercise the edges of point decoding: small-order points,
/// non-canonical encodings, and values at or above the field prime.
fn edge_case_keys() -> Vec<[u8; 32]> {
	let mut keys: Vec<[u8; 32]> = [
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"0200000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	]
	.iter()
	.map(|s| hex::decode(s).unwrap().try_into().unwrap())
	.collect();
	// y = p + 1 and p + 2 encode the same points as 1 and 2
	let mut p_plus =
		hex::decode("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").unwrap();
	p_plus[0] = 0xef;
	keys.push(p_plus.try_into().unwrap());
	keys
}

#[test]
fn key_validation_matches() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(3);
	let mut keys = edge_case_keys();
	keys.extend((0..300).map(|_| rng.array::<32>()));
	keys.extend((0..20).map(|_| rng.private_key().public_key().0));
	for key in keys {
		let reply = go.call(json!({"op": "key_valid", "key": hex::encode(key)}));
		assert_eq!(
			Some(is_public_key_valid(&key)),
			reply["valid"].as_bool(),
			"{}",
			hex::encode(key)
		);
	}
}

#[test]
fn ed25519_verification_matches() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(4);
	let signer = rng.private_key();
	let mut cases: Vec<([u8; 32], Vec<u8>, [u8; 64])> = Vec::new();
	for _ in 0..80 {
		let len = rng.below(50) as usize;
		let msg = rng.bytes(len);
		let mut sig = signer.sign(&msg);
		let mut key = signer.public_key().0;
		match rng.below(6) {
			0 => {}
			1 => sig[rng.below(64) as usize] ^= 1 << rng.below(8),
			2 => key = rng.array(),
			3 => {
				// Push S out of range by adding the group order
				let l: [u8; 32] =
					hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
						.unwrap()
						.try_into()
						.unwrap();
				let mut carry = 0u16;
				for idx in 0..32 {
					let sum = sig[32 + idx] as u16 + l[idx] as u16 + carry;
					sig[32 + idx] = sum as u8;
					carry = sum >> 8;
				}
			}
			4 => key = edge_case_keys()[rng.below(edge_case_keys().len() as u64) as usize],
			_ => sig = rng.array(),
		}
		cases.push((key, msg, sig));
	}
	// The identity key with a matching zero-scalar signature
	let mut identity = [0u8; 32];
	identity[0] = 1;
	let mut sig = [0u8; 64];
	sig[0] = 1;
	cases.push((identity, b"anything".to_vec(), sig));
	for (key, msg, sig) in cases {
		let reply = go.call(json!({"op": "verify", "key": hex::encode(key), "msg": hex::encode(&msg), "data": hex::encode(sig)}));
		assert_eq!(
			Some(PublicKey(key).verify(&msg, &sig)),
			reply["valid"].as_bool(),
			"key {} msg {} sig {}",
			hex::encode(key),
			hex::encode(&msg),
			hex::encode(sig)
		);
	}
	for _ in 0..10 {
		let seed: [u8; 32] = rng.array();
		let msg = rng.bytes(40);
		let reply =
			go.call(json!({"op": "sign", "seed": hex::encode(seed), "msg": hex::encode(&msg)}));
		assert_eq!(
			reply["sig"].as_str().unwrap(),
			hex::encode(PrivateKey::from_seed(&seed).sign(&msg))
		);
	}
}

#[test]
fn bloom_filters_match() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(5);
	for round in 0..40 {
		let count = if round == 0 {
			0
		} else {
			rng.below(60) as usize
		};
		let keys: Vec<PublicKey> = (0..count).map(|_| PublicKey(rng.array())).collect();
		let words = net::bloom_words(&keys);
		let reply = go.call(
			json!({"op": "bloom_words", "keys": keys.iter().map(hex_key).collect::<Vec<_>>()}),
		);
		let theirs: Vec<u64> = reply["words"]
			.as_array()
			.unwrap()
			.iter()
			.map(|w| w.as_u64().unwrap())
			.collect();
		assert_eq!(words.to_vec(), theirs);
		for _ in 0..10 {
			let probe = PublicKey(rng.array());
			let reply = go
				.call(json!({"op": "bloom_test", "words": words.to_vec(), "key": hex_key(&probe)}));
			assert_eq!(
				Some(net::bloom_test(&words, &probe)),
				reply["present"].as_bool()
			);
		}
	}
}

#[test]
fn bloom_hashing_matches_for_any_length() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(10);
	for len in 0..70 {
		for _ in 0..3 {
			let data = rng.bytes(len);
			let reply = go.call(json!({"op": "bloom_locations", "data": hex::encode(&data)}));
			let theirs: Vec<u64> = reply["locations"]
				.as_array()
				.unwrap()
				.iter()
				.map(|w| w.as_u64().unwrap())
				.collect();
			assert_eq!(
				net::bloom_locations(&data).to_vec(),
				theirs,
				"{}",
				hex::encode(&data)
			);
		}
	}
}

#[test]
fn key_conversion_matches() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(6);
	let mut keys = edge_case_keys();
	keys.extend((0..200).map(|_| rng.array::<32>()));
	keys.extend((0..20).map(|_| rng.private_key().public_key().0));
	for key in keys {
		let reply = go.call(json!({"op": "ed_pub_to_box", "key": hex::encode(key)}));
		assert_eq!(
			reply["key"].as_str().unwrap(),
			hex::encode(enc::ed_pub_to_box(&PublicKey(key))),
			"{}",
			hex::encode(key)
		);
	}
	for _ in 0..20 {
		let seed: [u8; 32] = rng.array();
		let reply = go.call(json!({"op": "ed_priv_to_box", "seed": hex::encode(seed)}));
		assert_eq!(
			reply["key"].as_str().unwrap(),
			hex::encode(enc::ed_priv_to_box(&PrivateKey::from_seed(&seed)))
		);
	}
}

#[test]
fn box_crypto_matches() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(7);
	for round in 0..60 {
		let private: [u8; 32] = rng.array();
		let reply = go.call(json!({"op": "box_pub", "priv": hex::encode(private)}));
		assert_eq!(
			reply["key"].as_str().unwrap(),
			hex::encode(enc::box_pub_for_priv(&private))
		);

		// Includes low-order and off-curve public keys
		let public: [u8; 32] = if round % 5 == 0 {
			edge_case_keys()[round % 16]
		} else {
			rng.array()
		};
		let shared = enc::get_shared(&public, &private);
		let reply = go.call(
			json!({"op": "shared", "pub": hex::encode(public), "priv": hex::encode(private)}),
		);
		assert_eq!(reply["key"].as_str().unwrap(), hex::encode(shared));

		let len = rng.below(200) as usize;
		let msg = rng.bytes(len);
		let nonce = if rng.chance(1, 4) {
			u64::MAX
		} else {
			rng.next_u64()
		};
		let sealed = enc::box_seal(&msg, nonce, &shared);
		let reply = go.call(json!({"op": "box_seal", "msg": hex::encode(&msg), "nonce": nonce, "shared": hex::encode(shared)}));
		assert_eq!(reply["data"].as_str().unwrap(), hex::encode(&sealed));

		let mut tampered = sealed.clone();
		if rng.chance(1, 2) && !tampered.is_empty() {
			let idx = rng.below(tampered.len() as u64) as usize;
			tampered[idx] ^= 1;
		}
		let reply = go.call(json!({"op": "box_open", "data": hex::encode(&tampered), "nonce": nonce, "shared": hex::encode(shared)}));
		let theirs = reply["msg"].as_str().map(|s| hex::decode(s).unwrap());
		assert_eq!(enc::box_open(&tampered, nonce, &shared), theirs);
	}
}

#[test]
fn session_handshakes_interoperate() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(8);
	let passwords = [
		("", "", true),
		("pw", "pw", true),
		("pw", "", false),
		("", "pw", false),
		("pw", "other", false),
	];
	for (sender_password, receiver_password, want_ok) in passwords {
		for _ in 0..4 {
			let (sender_seed, receiver_seed): ([u8; 32], [u8; 32]) = (rng.array(), rng.array());
			let sender = PrivateKey::from_seed(&sender_seed);
			let receiver = PrivateKey::from_seed(&receiver_seed);
			let fields = (rng.array(), rng.array(), rng.next_u64(), rng.next_u64());

			// Rust encrypts, Go decrypts
			let data = enc::session_init_encrypt(
				&sender,
				&receiver.public_key(),
				sender_password,
				fields,
				&rng.array(),
			);
			let reply = go.call(json!({
				"op": "init_decrypt", "seed": hex::encode(receiver_seed), "key": hex_key(&sender.public_key()),
				"data": hex::encode(&data), "password": receiver_password,
			}));
			assert_eq!(reply.get("error").is_none(), want_ok, "{reply}");
			if want_ok {
				assert_eq!(reply["current"].as_str().unwrap(), hex::encode(fields.0));
				assert_eq!(reply["next"].as_str().unwrap(), hex::encode(fields.1));
				assert_eq!(reply["key_seq"].as_u64(), Some(fields.2));
				assert_eq!(reply["seq"].as_u64(), Some(fields.3));
			}

			// Go encrypts, Rust decrypts
			let reply = go.call(json!({
				"op": "init_encrypt", "seed": hex::encode(sender_seed), "key": hex_key(&receiver.public_key()),
				"password": sender_password, "current": hex::encode(fields.0), "next": hex::encode(fields.1),
				"key_seq": fields.2, "seq": fields.3,
			}));
			let data = hex::decode(reply["data"].as_str().unwrap()).unwrap();
			let decoded = enc::session_init_decrypt(
				&receiver,
				&sender.public_key(),
				&data,
				receiver_password,
			);
			assert_eq!(decoded, want_ok.then_some(fields));
		}
	}
}

/// Drives the same tree logic in both implementations.
struct RouterPair<'a> {
	go: &'a Vectors,
	ours: RouterHarness,
}

impl RouterPair<'_> {
	fn update(&mut self, ann: &[u8]) {
		let ours = self.ours.update(ann).unwrap();
		let reply = self
			.go
			.call(json!({"op": "router_update", "data": hex::encode(ann)}));
		assert_eq!(
			Some(ours),
			reply["accepted"].as_bool(),
			"update {}",
			hex::encode(ann)
		);
	}

	fn compare_views(&mut self, keys: &[PublicKey]) {
		for key in keys {
			let (root, path) = self.ours.root_and_path(key);
			let reply = self
				.go
				.call(json!({"op": "router_root_and_path", "key": hex_key(key)}));
			assert_eq!(
				reply["root"].as_str().unwrap(),
				hex_key(&root),
				"root of {key}"
			);
			assert_eq!(reply["path"], json!(path), "path of {key}");

			let (root, dists, valid) = self.ours.root_and_dists(key);
			let reply = self
				.go
				.call(json!({"op": "router_root_and_dists", "key": hex_key(key)}));
			assert_eq!(reply["root"].as_str().unwrap(), hex_key(&root));
			assert_eq!(reply["valid"].as_bool(), Some(valid));
			let ours: serde_json::Map<String, Value> =
				dists.iter().map(|(k, d)| (hex_key(k), json!(d))).collect();
			assert_eq!(reply["dists"], Value::Object(ours), "dists of {key}");

			let reply = self
				.go
				.call(json!({"op": "router_ancestry", "key": hex_key(key)}));
			let ours: Vec<String> = self.ours.ancestry(key).iter().map(hex_key).collect();
			assert_eq!(reply["ancestry"], json!(ours), "ancestry of {key}");
		}
	}

	fn compare_routing(&mut self, rng: &mut Rng, keys: &[PublicKey]) {
		for _ in 0..60 {
			let target = keys[rng.below(keys.len() as u64) as usize];
			let (_, mut path) = self.ours.root_and_path(&target);
			if rng.chance(1, 3) {
				path.push(1 + rng.below(4));
			}
			if rng.chance(1, 4) && !path.is_empty() {
				path.pop();
			}
			for key in keys.iter().take(4) {
				let ours = self.ours.dist(&path, key);
				let reply = self
					.go
					.call(json!({"op": "router_dist", "path": path, "key": hex_key(key)}));
				assert_eq!(reply["dist"].as_u64(), Some(ours));
			}
			let watermark = match rng.below(3) {
				0 => None,
				1 => Some(u64::MAX),
				_ => Some(rng.below(6)),
			};
			let (next, new_watermark) = self.ours.lookup(&path, watermark);
			let reply = self
				.go
				.call(json!({"op": "router_lookup", "path": path, "watermark": watermark}));
			let theirs = reply["next"]
				.as_str()
				.map(|key| (parse_key(key), reply["order"].as_u64().unwrap()));
			assert_eq!(theirs, next, "lookup {path:?} {watermark:?}");
			assert_eq!(reply["watermark"].as_u64(), new_watermark);
		}
	}
}

#[test]
fn tree_logic_matches() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(9);
	for scenario in 0..6 {
		let seeds: Vec<[u8; 32]> = (0..12).map(|_| rng.array()).collect();
		let privs: Vec<PrivateKey> = seeds.iter().map(PrivateKey::from_seed).collect();
		let keys: Vec<PublicKey> = privs.iter().map(PrivateKey::public_key).collect();
		// Node 0 is the harness itself
		go.call(json!({"op": "router_new", "seed": hex::encode(seeds[0])}));
		let mut pair = RouterPair {
			go: &go,
			ours: RouterHarness::new(&privs[0]).unwrap(),
		};
		// One link per peer node keeps the choice deterministic; equal latencies exercise the tie-breaks
		for key in keys.iter().skip(1).take(5) {
			let prio = rng.below(3) as u8;
			let lag = rng.below(3);
			let order = pair.ours.add_peer(key, prio, lag).unwrap();
			let reply = go.call(
				json!({"op": "router_add_peer", "key": hex_key(key), "prio": prio, "lag_ms": lag}),
			);
			assert_eq!(reply["order"].as_u64(), Some(order));
		}
		// Random churn, including loops, dead ends, and competing roots
		for step in 0..80 {
			let node = 1 + rng.below(11) as usize;
			let parent = match rng.below(6) {
				0 => node,
				_ => rng.below(12) as usize,
			};
			let port = if node == parent {
				0
			} else {
				1 + rng.below(4 + scenario)
			};
			let seq = 1 + rng.below(3);
			let nonce = rng.below(4);
			let ann = net::signed_announce(&privs[node], &privs[parent], seq, nonce, port);
			pair.update(&ann);
			if step % 10 == 9 {
				pair.compare_views(&keys);
				pair.compare_routing(&mut rng, &keys);
			}
		}
		// A coherent tree that includes the harness node, so lookups have many comparable candidates
		build_tree(&mut pair, &mut rng, &privs);
		pair.compare_views(&keys);
		for _ in 0..5 {
			pair.compare_routing(&mut rng, &keys);
		}
	}
}

/// Announces a random, valid tree over every node.
fn build_tree(pair: &mut RouterPair, rng: &mut Rng, privs: &[PrivateKey]) {
	let mut order: Vec<usize> = (0..privs.len()).collect();
	for idx in (1..order.len()).rev() {
		order.swap(idx, rng.below(idx as u64 + 1) as usize);
	}
	let mut children = vec![0u64; privs.len()];
	for (position, &node) in order.iter().enumerate() {
		let parent = if position == 0 {
			node
		} else {
			order[rng.below(position as u64) as usize]
		};
		let port = if parent == node {
			0
		} else {
			children[parent] += 1;
			children[parent]
		};
		let ann = net::signed_announce(&privs[node], &privs[parent], 100, rng.below(4), port);
		pair.update(&ann);
	}
}

#[test]
fn link_selection_matches() {
	let go = Vectors::spawn();
	let mut rng = Rng::new(11);
	for _ in 0..8 {
		let seeds: Vec<[u8; 32]> = (0..8).map(|_| rng.array()).collect();
		let privs: Vec<PrivateKey> = seeds.iter().map(PrivateKey::from_seed).collect();
		let keys: Vec<PublicKey> = privs.iter().map(PrivateKey::public_key).collect();
		go.call(json!({"op": "router_new", "seed": hex::encode(seeds[0])}));
		let mut pair = RouterPair {
			go: &go,
			ours: RouterHarness::new(&privs[0]).unwrap(),
		};
		// Several links to a single peer node, differing in priority and latency
		for _ in 0..4 {
			let prio = rng.below(3) as u8;
			let lag = rng.below(4);
			let order = pair.ours.add_peer(&keys[1], prio, lag).unwrap();
			let reply = go.call(
				json!({"op": "router_add_peer", "key": hex_key(&keys[1]), "prio": prio, "lag_ms": lag}),
			);
			assert_eq!(reply["order"].as_u64(), Some(order));
		}
		build_tree(&mut pair, &mut rng, &privs);
		pair.compare_routing(&mut rng, &keys);
	}
}
