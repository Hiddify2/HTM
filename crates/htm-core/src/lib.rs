//! HTM — Hiddify Tunnel Manager, core engine.
//!
//! This crate contains everything HTM does apart from drawing pixels: the SSH
//! transport, remote host management, the tunnel provider abstraction, the
//! benchmark engine, persistence and the background job system. The GUI crate
//! is a thin layer on top.
//!
//! # How the pieces fit together
//!
//! ```text
//!   htm-gui
//!      │  spawns jobs, drains events
//!      ▼
//!   jobs ──────────────► orchestrator ──────────► provider (trait)
//!                             │                        │
//!                             ▼                        ▼
//!                          remote               candytunnel, ...
//!                       (facts, pkg,
//!                        systemd, net)
//!                             │
//!                             ▼
//!                            ssh
//!                    (dial → host key → session)
//! ```
//!
//! # Extending it
//!
//! A second tunnel implementation needs one new module under
//! [`provider`] and one line in [`provider::registry::all`]. Nothing in the
//! GUI, the benchmark engine or the store names a specific provider; settings
//! travel as [`model::OptionMap`] and are described by the provider's own
//! [`model::OptionSpace`].

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod crypto;
pub mod error;
pub mod jobs;
pub mod model;
pub mod orchestrator;
pub mod provider;
pub mod remote;
pub mod ssh;
pub mod store;
pub mod util;

pub use error::{Error, Result};

/// The version of HTM, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
