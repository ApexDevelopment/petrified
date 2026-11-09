//! The routing layer, mirroring Ironwood's `network` package.
//!
//! Nodes build a spanning tree rooted at the lowest key, use tree
//! coordinates for greedy routing, and find each other's coordinates with
//! bloom-filter guided lookups.

mod bloomfilter;
mod config;
mod debug;
mod heap;
mod murmur;
mod packetconn;
mod packetqueue;
mod pathfinder;
mod peers;
mod router;
mod traffic;
pub(crate) mod wire;

#[doc(hidden)]
pub mod internals;

pub use bloomfilter::BLOOM_FILTER_U;
pub use config::{BloomTransform, Config, PathNotify};
pub use debug::{
	Debug, DebugBloomInfo, DebugLookupInfo, DebugPathInfo, DebugPeerInfo, DebugSelfInfo,
	DebugTreeInfo,
};
pub use packetconn::PacketConn;
