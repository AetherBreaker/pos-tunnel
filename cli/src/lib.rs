//! The core `posctl` and `posctl-admin` share: config, keys, the NinjaOne API, and the fleet and admin
//! operations. Design: `docs/design.md`.

pub mod admin;
pub mod bundle;
pub mod config;
pub mod fleet;
pub mod keys;
pub mod ninja;

#[cfg(test)]
mod fake;
