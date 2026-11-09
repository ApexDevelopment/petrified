//! Types shared by every layer, mirroring Ironwood's `types` package.

mod crypto;
mod error;
mod keys;
mod packetconn;
mod platform;

pub use crypto::is_public_key_valid;
pub use error::Error;
pub use keys::{PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, PrivateKey, PublicKey, SIGNATURE_SIZE};
pub use packetconn::{Event, PacketConn, PeerId};
pub use platform::{Instant, Platform};

#[cfg(feature = "std")]
pub use platform::StdPlatform;
