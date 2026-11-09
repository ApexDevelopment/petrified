//! Petrified is a Rust port of [Ironwood](https://github.com/Arceliar/ironwood),
//! the routing protocol used by Yggdrasil.
//!
//! The protocol logic is written as sans-IO state machines that only need
//! `alloc`. The host feeds bytes from peer connections in, writes the bytes
//! the state machine produces out, and calls [`types::PacketConn::handle_timeout`]
//! when [`types::PacketConn::poll_timeout`] says so. Time and randomness come
//! from a [`types::Platform`] implementation.
//!
//! The `std` feature adds [`blocking::PacketConn`], a thread-based wrapper that
//! mirrors the Go `net.PacketConn` API.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod encrypted;
pub mod network;
pub mod signed;
pub mod types;

#[cfg(feature = "std")]
pub mod blocking;
