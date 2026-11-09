# Petrified

A Rust port of [Ironwood](https://github.com/Arceliar/ironwood), the routing protocol that powers [Yggdrasil](https://yggdrasil-network.github.io/). It is compatible with Ironwood at commit [`0712ecc`](https://github.com/Arceliar/ironwood/commit/0712eccbb962).

Petrified was designed with bare-metal targets in mind. The protocol core is `no_std` and only needs `alloc`, and it builds for `thumbv7em-none-eabihf` and `riscv32imc-unknown-none-elf` with `default-features = false`. The `fast` feature (on by default) adds precomputed curve tables, which speed up signing but take extra flash.

The modules mirror Ironwood's packages, aside from `petrified::blocking`.

## Usage

### With `std`

`blocking::PacketConn` wraps any layer and behaves like Go's `net.PacketConn` plus `HandleConn`:

```rust
use petrified::{blocking, encrypted, network::Config, types::{PrivateKey, StdPlatform}};

let key = PrivateKey::from_seed(&seed);
let conn = encrypted::PacketConn::new(&key, StdPlatform::new(), Config::default())?;
let node = blocking::PacketConn::new(conn);

// For each peer stream (TCP, Unix socket, ...), once you know the peer's key:
std::thread::spawn({
	let node = node.clone();
	move || node.handle_conn(&peer_key, stream, 0)
});

node.write_to(b"hello", &dest_key)?;
let (n, from) = node.read_from(&mut buf)?;
```

See `examples/node.rs` for a complete program.

### Without `std`

Each layer is a sans-IO state machine implementing `types::PacketConn`. Implement `types::Platform` for your device:

```rust
impl Platform for MyBoard {
	fn now(&self) -> Instant { /* monotonic clock */ }
	fn unix_time(&self) -> u64 { /* seconds since 1970 */ }
	fn fill_random(&mut self, buf: &mut [u8]) { /* hardware RNG */ }
}
```

Then drive the node from your event loop:

- `handle_conn(key, prio)` when a peer connects, and `remove_peer(id)` when it disconnects.
- `handle_peer_data(id, bytes)` with bytes read from a peer's stream.
- `peer_transmit(id)` for bytes to write to a peer, then `peer_consume(id, n)` for what was written.
- `handle_timeout()` once `poll_timeout()` has passed.
- `poll_event()` for peers the protocol dropped, whose streams you should close.
- `write_to(data, dest)` and `recv()` for application packets.

Ironwood uses Unix time as a sequence number for session handshakes and path notifications. On a device without a real-time clock, `unix_time` must still never go backwards, including across reboots. Otherwise peers ignore the device's handshakes until their old state times out (about a minute).

## Differences from Go

- Go's actors, goroutines, and timers are replaced by one state machine per layer, driven by the host.
- Configuration is a `network::Config` builder rather than functional options.
- `DebugPeerInfo` identifies a link by `PeerId` instead of `net.Conn`, and omits the `Root` and `Updated` fields, which Go never fills in.
- `Debug::get_coords` reports the node's root and coordinates.

## Testing

```sh
cargo test --lib --test sim    # Rust only
cargo test                     # also runs the Go interop tests
```

The interop tests need Go 1.26 or newer and will download Ironwood. `interop/build.sh` builds a harness from an unmodified copy of upstream Ironwood, adding files to export internals, then:

- Sends the same inputs through both implementations and compares the results.
- Runs mixed networks of Go and Rust nodes over TCP on every layer, checking that they agree on the tree and deliver traffic between every pair of nodes.

`tests/sim.rs` runs larger networks deterministically on a virtual clock.
