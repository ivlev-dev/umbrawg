use std::io;

/// Error type returned by every `uwg-quick` operation.
///
/// `Die` mirrors the shell helper of the reference implementation: the
/// caller prints `PROGRAM: message` and exits with status 1. `Command`
/// mirrors a failing command under `set -e`: the caller exits with the
/// command status and prints nothing extra.
#[derive(Debug, thiserror::Error)]
pub enum QuickError {
    #[error("{0}")]
    Die(String),
    #[error("command `{program}` failed with status {status}")]
    Command { program: String, status: i32 },
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl QuickError {
    pub fn die(message: impl Into<String>) -> Self {
        Self::Die(message.into())
    }

    pub fn command(program: impl Into<String>, status: i32) -> Self {
        Self::Command {
            program: program.into(),
            status: normalize_status(status),
        }
    }

    /// Exit status matching the shell implementation.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Die(_) | Self::Io(_) => 1,
            Self::Command { status, .. } => normalize_status(*status),
        }
    }
}

fn normalize_status(status: i32) -> i32 {
    if status <= 0 {
        1
    } else {
        status.min(255)
    }
}

pub type QuickResult<T> = Result<T, QuickError>;
