use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("random number generator failed: {0}")]
    Random(String),
    #[error("invalid key: {0}")]
    InvalidKey(&'static str),
    #[error("line {line}: unrecognized line: `{text}`")]
    UnrecognizedLine { line: usize, text: String },
    #[error("line {line}: unrecognized key: `{key}`")]
    UnrecognizedKey { line: usize, key: String },
    #[error("line {line}: invalid value for `{key}`: `{value}`")]
    InvalidValue {
        line: usize,
        key: String,
        value: String,
    },
    #[error("invalid range: `{0}`")]
    InvalidRange(String),
    #[error("invalid endpoint: `{value}`")]
    InvalidEndpoint { value: String },
    #[error("invalid allowed IP: `{value}`")]
    InvalidAllowedIp { value: String },
    #[error("peer is missing a public key")]
    MissingPeerPublicKey,
    #[error("unknown section: `{0}`")]
    UnknownSection(String),
    #[error("invalid argument: `{0}`")]
    InvalidArgument(String),
}
