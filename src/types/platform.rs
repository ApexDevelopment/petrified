use core::ops::{Add, Sub};
use core::time::Duration;

/// A point on a monotonic clock, measured from an arbitrary epoch chosen by the [`Platform`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

impl Instant {
	pub const fn from_duration(since_epoch: Duration) -> Self {
		Instant(since_epoch)
	}

	pub const fn as_duration(self) -> Duration {
		self.0
	}

	/// Time elapsed from `earlier` to `self`, or zero if `earlier` is later.
	pub fn saturating_duration_since(self, earlier: Instant) -> Duration {
		self.0.saturating_sub(earlier.0)
	}
}

impl Add<Duration> for Instant {
	type Output = Instant;
	fn add(self, rhs: Duration) -> Instant {
		Instant(self.0.saturating_add(rhs))
	}
}

impl Sub<Instant> for Instant {
	type Output = Duration;
	fn sub(self, rhs: Instant) -> Duration {
		self.saturating_duration_since(rhs)
	}
}

/// Everything the protocol needs from the device it runs on.
pub trait Platform {
	/// The current time on a monotonic clock.
	fn now(&self) -> Instant;
	/// Seconds since the Unix epoch.
	///
	/// Ironwood uses this as a sequence number for session handshakes and path
	/// notifications. A device without a real-time clock should return a value
	/// that never goes backwards, even across reboots, or remote nodes will
	/// ignore it until their old state times out.
	fn unix_time(&self) -> u64;
	/// Fills `buf` with cryptographically secure random bytes.
	fn fill_random(&mut self, buf: &mut [u8]);
}

/// A [`Platform`] backed by the standard library and the OS random number generator.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct StdPlatform {
	epoch: std::time::Instant,
}

#[cfg(feature = "std")]
impl StdPlatform {
	pub fn new() -> Self {
		StdPlatform {
			epoch: std::time::Instant::now(),
		}
	}
}

#[cfg(feature = "std")]
impl Default for StdPlatform {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(feature = "std")]
impl Platform for StdPlatform {
	fn now(&self) -> Instant {
		Instant(self.epoch.elapsed())
	}

	fn unix_time(&self) -> u64 {
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0)
	}

	fn fill_random(&mut self, buf: &mut [u8]) {
		getrandom::fill(buf).expect("OS random number generator failed");
	}
}
