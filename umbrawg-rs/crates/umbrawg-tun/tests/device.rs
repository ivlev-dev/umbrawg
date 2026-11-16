//! Tests that need `/dev/net/tun` and `CAP_NET_ADMIN`.
//!
//! Every test skips itself when the clone device or the required privileges are
//! unavailable, so the suite stays green in unprivileged containers.

use std::io::ErrorKind;
use std::path::Path;

use umbrawg_tun::{Tun, TunConfig, TunError, TunSet, VirtioNetHdr};

fn device_exists() -> bool {
    Path::new("/dev/net/tun").exists()
}

fn is_skip_error(error: &TunError) -> bool {
    if matches!(error, TunError::Unsupported(_)) {
        return true;
    }
    let Some(error) = error.as_io_error() else {
        return false;
    };
    if matches!(
        error.kind(),
        ErrorKind::PermissionDenied | ErrorKind::NotFound
    ) {
        return true;
    }
    matches!(
        error.raw_os_error(),
        Some(code)
            if code == libc::EPERM
                || code == libc::EACCES
                || code == libc::ENOENT
                || code == libc::ENODEV
                || code == libc::ENOTTY
                || code == libc::EOPNOTSUPP
    )
}

fn open_single(config: &TunConfig) -> Option<Tun> {
    if !device_exists() {
        eprintln!("skipping: /dev/net/tun is unavailable");
        return None;
    }
    match Tun::open(config) {
        Ok(tun) => Some(tun),
        Err(error) if is_skip_error(&error) => {
            eprintln!("skipping: {error}");
            None
        }
        Err(error) => panic!("failed to open TUN device: {error}"),
    }
}

#[test]
fn opens_nonblocking_queue_and_reports_batch_size() {
    let config = TunConfig::new("umbrawg%d").with_offload(true);
    let Some(mut tun) = open_single(&config) else {
        return;
    };

    assert!(tun.name().starts_with("umbrawg"));
    assert!(tun.fd() >= 0);
    assert_eq!(tun.vnet_hdr_len(), VirtioNetHdr::LEN);
    assert!(tun.vnet_hdr());
    assert_eq!(tun.batch_size(), umbrawg_tun::IDEAL_BATCH_SIZE);
    assert!(tun.mtu() > 0);
    assert!(tun.interface_index().is_some());

    let mut buf = [0u8; 2048];
    assert_eq!(
        tun.read(&mut buf).unwrap_err().io_kind(),
        Some(ErrorKind::WouldBlock)
    );

    let mut batch_buf = [0u8; 2048];
    let mut bufs: [&mut [u8]; 1] = [&mut batch_buf];
    assert_eq!(
        tun.read_batch(&mut bufs).unwrap_err().io_kind(),
        Some(ErrorKind::WouldBlock)
    );

    assert_eq!(tun.write_batch(&[]).unwrap(), 0);
}

#[test]
fn opens_v1_header_when_supported() {
    let config = TunConfig::new("umbrawg%d")
        .with_vnet_hdr_size(VirtioNetHdr::LEN_WITH_NUM_BUFFERS)
        .with_offload(true);
    let Some(tun) = open_single(&config) else {
        return;
    };

    assert_eq!(tun.vnet_hdr_len(), VirtioNetHdr::LEN_WITH_NUM_BUFFERS);
}

#[test]
fn sets_and_reads_mtu() {
    let config = TunConfig::new("umbrawg%d").with_mtu(0);
    let Some(mut tun) = open_single(&config) else {
        return;
    };

    let original = tun.mtu();
    let target = if original == 1400 { 1300 } else { 1400 };
    tun.set_mtu(target).unwrap();
    assert_eq!(tun.mtu(), target);
    tun.set_mtu(original).unwrap();
    assert_eq!(tun.mtu(), original);
}

#[test]
fn opens_multiple_queues_with_one_interface_name() {
    if !device_exists() {
        eprintln!("skipping: /dev/net/tun is unavailable");
        return;
    }
    let config = TunConfig::new("umbrawgq%d")
        .with_multi_queue(true)
        .with_offload(true);
    let set = match TunSet::open(&config, 2) {
        Ok(set) => set,
        Err(error) if is_skip_error(&error) => {
            eprintln!("skipping: {error}");
            return;
        }
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            eprintln!("skipping: multi-queue is not supported: {error}");
            return;
        }
        Err(error) => panic!("failed to open multi-queue TUN device: {error}"),
    };

    assert_eq!(set.len(), 2);
    assert!(!set.is_empty());
    assert_eq!(set.raw_fds().len(), 2);
    let name = set.name().to_owned();
    assert!(set.iter().all(|queue| queue.name() == name));
    assert!(set.get(0).is_some());
    assert!(set.get(2).is_none());
    assert_eq!(set.batch_size(), umbrawg_tun::IDEAL_BATCH_SIZE);
    assert_eq!(set.into_queues().len(), 2);
}

#[test]
fn opens_queue_without_offload() {
    let config = TunConfig::new("umbrawg%d").with_offload(false).with_mtu(0);
    let Some(mut tun) = open_single(&config) else {
        return;
    };

    assert!(!tun.vnet_hdr());
    assert_eq!(tun.vnet_hdr_len(), 0);
    assert_eq!(tun.batch_size(), 1);

    let mut buf = [0u8; 2048];
    let error = tun.read(&mut buf).unwrap_err();
    assert_eq!(error.io_kind(), Some(ErrorKind::WouldBlock));
}
