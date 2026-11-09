use alloc::boxed::Box;
use core::time::Duration;

use crate::types::PublicKey;

pub(crate) const DEFAULT_MAX_MESSAGE_SIZE: u64 = 1048576;

/// Maps a key to the form used in bloom filters and lookups (Yggdrasil truncates keys to address prefixes).
pub type BloomTransform = Box<dyn Fn(&PublicKey) -> PublicKey + Send>;
/// Called whenever a path to a node is found or updated.
pub type PathNotify = Box<dyn FnMut(&PublicKey) + Send>;

pub(crate) enum PathNotifier {
	Callback(PathNotify),
	Queue,
}

/// Application-level configuration. The values must match on every node in a network.
pub struct Config {
	pub(crate) router_refresh: Duration,
	pub(crate) router_timeout: Duration,
	pub(crate) peer_keep_alive_delay: Duration,
	pub(crate) peer_timeout: Duration,
	pub(crate) peer_max_message_size: u64,
	pub(crate) bloom_transform: BloomTransform,
	pub(crate) path_notify: PathNotifier,
	pub(crate) path_timeout: Duration,
	pub(crate) path_throttle: Duration,
}

impl Default for Config {
	fn default() -> Self {
		Config {
			router_refresh: Duration::from_secs(4 * 60),
			router_timeout: Duration::from_secs(5 * 60),
			peer_keep_alive_delay: Duration::from_secs(1),
			peer_timeout: Duration::from_secs(3),
			peer_max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
			bloom_transform: Box::new(|key| *key),
			path_notify: PathNotifier::Callback(Box::new(|_| {})),
			path_timeout: Duration::from_secs(60),
			path_throttle: Duration::from_secs(1),
		}
	}
}

impl Config {
	pub fn with_router_refresh(mut self, duration: Duration) -> Self {
		self.router_refresh = duration;
		self
	}

	pub fn with_router_timeout(mut self, duration: Duration) -> Self {
		self.router_timeout = duration;
		self
	}

	pub fn with_peer_keep_alive_delay(mut self, duration: Duration) -> Self {
		self.peer_keep_alive_delay = duration;
		self
	}

	pub fn with_peer_timeout(mut self, duration: Duration) -> Self {
		self.peer_timeout = duration;
		self
	}

	pub fn with_peer_max_message_size(mut self, size: u64) -> Self {
		self.peer_max_message_size = size;
		self
	}

	pub fn with_bloom_transform(
		mut self,
		xform: impl Fn(&PublicKey) -> PublicKey + Send + 'static,
	) -> Self {
		self.bloom_transform = Box::new(xform);
		self
	}

	pub fn with_path_notify(mut self, notify: impl FnMut(&PublicKey) + Send + 'static) -> Self {
		self.path_notify = PathNotifier::Callback(Box::new(notify));
		self
	}

	/// Queues path notifications for `poll_path_notify` instead of calling a
	/// function, for hosts that cannot share state with a `Send` closure.
	pub fn with_path_notify_queue(mut self) -> Self {
		self.path_notify = PathNotifier::Queue;
		self
	}

	pub fn with_path_timeout(mut self, duration: Duration) -> Self {
		self.path_timeout = duration;
		self
	}

	pub fn with_path_throttle(mut self, duration: Duration) -> Self {
		self.path_throttle = duration;
		self
	}
}
