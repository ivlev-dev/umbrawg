//! Unix-domain listener for the UAPI control socket.
//!
//! The listener creates `/var/run/umbrawg/<iface>.sock` (or the directory
//! selected by `UWG_RUNTIME_DIR`), restricts it to the root user and serves
//! connections sequentially on a dedicated thread.

use std::fs;
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};

use crate::error::UapiError;
use crate::protocol::{serve_stream, write_error};
use crate::types::DeviceControl;

/// Directory used for control sockets when `UWG_RUNTIME_DIR` is not set.
pub const DEFAULT_SOCKET_DIR: &str = "/var/run/umbrawg";

/// Suffix appended to the interface name to build the socket path.
pub const SOCKET_SUFFIX: &str = ".sock";

/// Returns the control-socket directory.
///
/// `UWG_RUNTIME_DIR` overrides the default, matching `umbrawg-ctl`.
#[must_use]
pub fn socket_dir() -> PathBuf {
    std::env::var_os("UWG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_DIR))
}

/// Returns the control-socket path for `iface` in the default directory.
pub fn socket_path(iface: &str) -> Result<PathBuf, UapiError> {
    socket_path_in(&socket_dir(), iface)
}

/// Returns the control-socket path for `iface` inside `directory`.
pub fn socket_path_in(directory: &Path, iface: &str) -> Result<PathBuf, UapiError> {
    validate_interface_name(iface)?;
    Ok(directory.join(format!("{iface}{SOCKET_SUFFIX}")))
}

/// Validates an interface name before it is used in a socket path.
///
/// Mirrors `umbrawg-ctl::uapi::validate_interface_name`: the name must be
/// non-empty, shorter than `IFNAMSIZ`, and must not contain `/` or NUL.
pub fn validate_interface_name(name: &str) -> Result<(), UapiError> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('/') || name.contains('\0')
    {
        return Err(UapiError::InvalidValue {
            key: "interface".to_owned(),
            value: name.to_owned(),
        });
    }
    Ok(())
}

/// A bound UAPI control socket.
///
/// Dropping the listener closes the socket and removes the socket file if it
/// still belongs to this listener.
#[derive(Debug)]
pub struct UapiListener {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
    stop: Arc<AtomicBool>,
    active: Arc<Mutex<Option<UnixStream>>>,
    wake_reader: UnixStream,
    wake_writer: UnixStream,
}

impl UapiListener {
    /// Creates the directory if necessary, removes a stale socket and binds
    /// `directory/<iface>.sock`.
    ///
    /// The directory is created with mode `0700` and the socket is created
    /// with mode `0600`.
    pub fn bind(directory: &Path, iface: &str) -> Result<Self, UapiError> {
        let path = socket_path_in(directory, iface)?;
        create_directory(directory)?;
        remove_stale_socket(&path)?;

        let listener = {
            let _guard = UmaskGuard::new(0o077);
            UnixListener::bind(&path)?
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        let metadata = fs::metadata(&path)?;
        let identity = (metadata.dev(), metadata.ino());

        let (wake_reader, wake_writer) = UnixStream::pair()?;
        wake_reader.set_nonblocking(true)?;
        wake_writer.set_nonblocking(true)?;

        Ok(Self {
            listener,
            path,
            identity,
            stop: Arc::new(AtomicBool::new(false)),
            active: Arc::new(Mutex::new(None)),
            wake_reader,
            wake_writer,
        })
    }

    /// Returns the socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a handle that can stop the listener from another thread.
    pub fn handle(&self) -> Result<ServerHandle, UapiError> {
        Ok(ServerHandle {
            stop: Arc::clone(&self.stop),
            active: Arc::clone(&self.active),
            wake: self.wake_writer.try_clone()?,
            join: None,
        })
    }

    /// Serves the control socket until [`ServerHandle::shutdown`] is called.
    ///
    /// Only the root user is allowed to connect.
    pub fn run(self, control: &dyn DeviceControl) -> Result<(), UapiError> {
        self.run_with_authorizer(control, |uid| uid == 0)
    }

    /// Serves the control socket with a custom authorization predicate.
    ///
    /// The predicate receives the uid reported by `SO_PEERCRED`. This is
    /// exposed for tests and for deployments that delegate access to another
    /// user; [`Self::run`] uses the root-only policy.
    pub fn run_with_authorizer<F>(
        self,
        control: &dyn DeviceControl,
        authorizer: F,
    ) -> Result<(), UapiError>
    where
        F: Fn(u32) -> bool,
    {
        while !self.stop.load(Ordering::SeqCst) {
            if !self.wait_for_activity()? {
                break;
            }
            let mut stream = match self.listener.accept() {
                Ok((stream, _address)) => stream,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };

            let uid = match peer_uid(&stream) {
                Ok(uid) => uid,
                Err(error) => {
                    log::debug!("UAPI could not read peer credentials: {error}");
                    continue;
                }
            };
            if !authorizer(uid) {
                log::warn!("UAPI rejected connection from uid {uid}");
                let _ = write_error(&mut stream, &UapiError::PermissionDenied);
                continue;
            }

            let Ok(active) = stream.try_clone() else {
                log::debug!("UAPI could not clone connection for shutdown tracking");
                continue;
            };
            set_active(&self.active, Some(active));
            if self.stop.load(Ordering::SeqCst) {
                break;
            }

            if let Err(error) = serve_stream(stream, control) {
                log::debug!("UAPI connection closed with error: {error}");
            }
            set_active(&self.active, None);
        }
        set_active(&self.active, None);
        Ok(())
    }

    /// Spawns a dedicated listener thread.
    ///
    /// Connections are handled one at a time on that thread, so the packet
    /// data path is never blocked by control-plane work.
    pub fn spawn<C>(self, control: Arc<C>) -> Result<ServerHandle, UapiError>
    where
        C: DeviceControl + Send + Sync + 'static,
    {
        let mut handle = self.handle()?;
        let join = thread::Builder::new()
            .name("umbrawg-uapi".to_owned())
            .spawn(move || {
                if let Err(error) = self.run(control.as_ref()) {
                    log::error!("UAPI listener failed: {error}");
                }
            })?;
        handle.join = Some(join);
        Ok(handle)
    }

    fn wait_for_activity(&self) -> Result<bool, UapiError> {
        let mut fds = [
            libc::pollfd {
                fd: self.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.wake_reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        loop {
            fds[0].revents = 0;
            fds[1].revents = 0;
            // SAFETY: `fds` is a valid array of two `pollfd` values and the
            // timeout is infinite, so `poll` only fills in `revents`.
            let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if fds[1].revents != 0 {
                return Ok(false);
            }
            if fds[0].revents != 0 {
                return Ok(true);
            }
        }
    }
}

impl Drop for UapiListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.wake_writer.write_all(b"x");
        if let Ok(metadata) = fs::metadata(&self.path) {
            if (metadata.dev(), metadata.ino()) == self.identity {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

/// Handle used to stop a running listener.
///
/// Dropping the handle requests shutdown and waits for the listener thread.
#[derive(Debug)]
pub struct ServerHandle {
    stop: Arc<AtomicBool>,
    active: Arc<Mutex<Option<UnixStream>>>,
    wake: UnixStream,
    join: Option<JoinHandle<()>>,
}

impl ServerHandle {
    /// Requests shutdown of the listener.
    pub fn shutdown(&self) -> Result<(), UapiError> {
        self.stop.store(true, Ordering::SeqCst);
        {
            let active = lock_active(&self.active);
            if let Some(stream) = active.as_ref() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        let mut wake = &self.wake;
        match wake.write_all(b"x") {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Returns `true` while the listener has not been asked to stop.
    #[must_use]
    pub fn is_running(&self) -> bool {
        !self.stop.load(Ordering::SeqCst)
    }

    /// Requests shutdown and waits for the listener thread to finish.
    ///
    /// # Errors
    ///
    /// Returns [`UapiError::Internal`] if the listener thread panicked.
    pub fn join(mut self) -> Result<(), UapiError> {
        self.shutdown()?;
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| UapiError::Internal("UAPI listener thread panicked".to_owned()))?;
        }
        Ok(())
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn create_directory(directory: &Path) -> Result<(), UapiError> {
    fs::create_dir_all(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn lock_active(slot: &Mutex<Option<UnixStream>>) -> MutexGuard<'_, Option<UnixStream>> {
    slot.lock().unwrap_or_else(|error| error.into_inner())
}

fn set_active(slot: &Mutex<Option<UnixStream>>, stream: Option<UnixStream>) {
    *lock_active(slot) = stream;
}

fn remove_stale_socket(path: &Path) -> Result<(), UapiError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(UapiError::Protocol(format!(
                    "`{}` exists and is not a Unix socket",
                    path.display()
                )));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(UapiError::AddressInUse);
            }
            match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn new(mask: libc::mode_t) -> Self {
        // SAFETY: `umask` has no memory-safety preconditions. The previous
        // value is restored as soon as the socket is created.
        let previous = unsafe { libc::umask(mask) };
        Self(previous)
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: restores the value returned by the matching `UmaskGuard::new`.
        unsafe { libc::umask(self.0) };
    }
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32, UapiError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the socket is valid, `credentials` is a correctly sized
    // `ucred`, and `length` describes its size.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast::<libc::c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(credentials.uid)
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(_stream: &UnixStream) -> Result<u32, UapiError> {
    Err(UapiError::Internal(
        "SO_PEERCRED authorization is only implemented on Linux".to_owned(),
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn peer_uid_matches_effective_uid() {
        let (first, _second) = UnixStream::pair().expect("socket pair");
        // SAFETY: `geteuid` has no memory-safety preconditions.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(peer_uid(&first).expect("peer credentials"), uid);
    }
}
