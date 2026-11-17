use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Config(#[from] umbrawg_config::Error),
    #[error("netlink error: {0}")]
    Netlink(String),
    #[error("kernel UmbraWG interface support is not available: {0}")]
    NoKernelSupport(String),
    #[error("UAPI error {errno}: {message}")]
    Uapi { errno: i64, message: String },
    #[error("interface `{0}` not found")]
    InterfaceNotFound(String),
    #[error("invalid interface name: `{0}`")]
    InvalidInterfaceName(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl Error {
    pub fn from_errno(errno: i64) -> Self {
        let message = if errno < 0 {
            io::Error::from_raw_os_error(-errno as i32).to_string()
        } else {
            io::Error::from_raw_os_error(errno as i32).to_string()
        };
        Self::Uapi { errno, message }
    }
}
