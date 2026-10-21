//! The core `posctl` and `posctl-admin` share: config, keys, the NinjaOne API, the fleet and admin
//! operations, and `posctl`'s sessions.

pub mod adhoc;
pub mod admin;
pub mod bundle;
pub mod completion;
pub mod config;
pub mod fleet;
pub mod keys;
pub mod ninja;
pub mod rekey;
pub mod relay;
pub mod session;
pub mod workstation;

#[cfg(test)]
mod fake;
