//! End-to-end encryption on top of [`crate::network`], mirroring Ironwood's `encrypted` package.
//!
//! Sessions are set up with signed handshakes and use NaCl boxes with
//! ratcheting ephemeral keys for traffic.

mod crypto;
mod e2c;
mod packetconn;
mod session;

#[doc(hidden)]
pub mod internals;

pub use packetconn::{DebugSessionInfo, PacketConn};
