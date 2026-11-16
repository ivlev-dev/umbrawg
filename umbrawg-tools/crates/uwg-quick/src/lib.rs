//! Rust port of `uwg-quick`: configure an UmbraWG interface from a
//! wg-quick style configuration file.
//!
//! The behaviour mirrors `legacy-c/wg-quick/linux.bash`:
//!
//! * configuration files live in `/etc/umbrawg/<iface>.conf`;
//! * runtime state of the userspace implementation lives in
//!   `/var/run/umbrawg/`;
//! * `UWG_QUICK_USERSPACE_IMPLEMENTATION` selects the userspace fallback
//!   (`umbrawg` by default);
//! * `UWG_COLOR_MODE` and `UWG_HIDE_KEYS` are inherited by every `uwg`
//!   subprocess, exactly like `WG_COLOR_MODE`/`WG_HIDE_KEYS` are inherited
//!   by `awg` in the shell implementation.

pub mod command;
pub mod commands;
pub mod config;
pub mod dns;
pub mod error;
pub mod firewall;
pub mod mtu;
pub mod route;
pub mod save;
pub mod usage;

pub use config::QuickConfig;
pub use error::{QuickError, QuickResult};

/// Directory holding `*.conf` files.
pub const CONFIG_DIR: &str = "/etc/umbrawg";

/// Suffix of a configuration file.
pub const CONFIG_SUFFIX: &str = ".conf";

/// Directory used by `umbrawg-ctl`/`umbrawg` for UAPI sockets.
pub const RUNTIME_DIR: &str = "/var/run/umbrawg";

/// Kernel module marker used for the userspace fallback decision.
pub const KERNEL_MODULE_PATH: &str = "/sys/module/umbrawg";

/// Kernel link type created by `ip link add ... type ...`.
pub const KERNEL_INTERFACE_TYPE: &str = "umbrawg";

/// Default userspace implementation.
pub const DEFAULT_USERSPACE_IMPLEMENTATION: &str = "umbrawg";

/// Environment variable overriding the userspace implementation.
pub const ENV_USERSPACE_IMPLEMENTATION: &str = "UWG_QUICK_USERSPACE_IMPLEMENTATION";

/// Environment variable consumed by `uwg show` (passed through).
pub const ENV_COLOR_MODE: &str = "UWG_COLOR_MODE";

/// Environment variable consumed by `uwg show` (passed through).
pub const ENV_HIDE_KEYS: &str = "UWG_HIDE_KEYS";

/// First routing table used for a default route when no fwmark exists.
pub const DEFAULT_ROUTE_TABLE_START: u32 = 51820;

/// resolvconf interface ordering file.
pub const RESOLVCONF_INTERFACE_ORDER: &str = "/etc/resolvconf/interface-order";

/// resolvconf fallback directory for `save`.
pub const RESOLVCONF_RUN_DIR: &str = "/etc/resolvconf/run/interface";

/// `uwg` executable name.
pub const UWG_PROGRAM: &str = "uwg";

/// `ip` executable name.
pub const IP_PROGRAM: &str = "ip";

/// Re-export controller socket directory to use `umbrawg-ctl` instead of hardcoding.
pub const CONTROLLER_SOCKET_DIR: &str = umbrawg_ctl::DEFAULT_SOCKET_DIR;
