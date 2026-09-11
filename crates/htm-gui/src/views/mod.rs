//! The views. Each one draws part of the interface and pushes
//! [`crate::app::Action`]s; none of them performs work directly.

pub mod benchmark;
pub mod install;
pub mod logs;
pub mod modals;
pub mod servers;
pub mod settings;
pub mod shell;
pub mod tunnels;
pub mod wizard;
