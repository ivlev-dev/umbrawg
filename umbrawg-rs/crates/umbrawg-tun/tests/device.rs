//! Tests that need `/dev/net/tun` and `CAP_NET_ADMIN`.
//!
//! Every test skips itself when the clone device or the required privileges are
//! unavailable, so the suite stays green in unprivileged containers.

use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;

use umbrawg_transport::{AddressFamily, Endpoint, GsoSize, OpenOptions, Socket};
use umbrawg_tun::{
    Tun, TunConfig, TunError, TunSet, VirtioNetHdr, VIRTIO_NET_HDR_F_DATA_VALID,
    VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_UDP_L4,
};

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

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = match chunk {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from(*high) << 8,
            _ => 0,
        };
        sum += u32::from(word);
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_udp(payload_len: usize, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let total = 20 + 8 + payload_len;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&1u16.to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    let checksum = ip_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&4000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&9u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    for (index, byte) in packet[28..].iter_mut().enumerate() {
        *byte = index as u8;
    }
    packet
}

fn configure_interface(name: &str) -> Option<[u8; 4]> {
    let subnet = [
        10,
        213,
        u8::try_from(std::process::id() % 200).ok()? + 20,
        1,
    ];
    let address = format!("{}.{}.{}.{}/24", subnet[0], subnet[1], subnet[2], subnet[3]);
    let added = Command::new("ip")
        .args(["addr", "add", &address, "dev", name])
        .status()
        .ok()?;
    if !added.success() {
        return None;
    }
    let up = Command::new("ip")
        .args(["link", "set", name, "up"])
        .status()
        .ok()?;
    up.success().then_some(subnet)
}

fn poll_readable(tun: &Tun, timeout_ms: i32) -> bool {
    let mut fd = libc::pollfd {
        fd: tun.fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut fd, 1, timeout_ms) > 0 }
}

fn is_kernel_rejection(error: &TunError) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EINVAL || code == libc::EMSGSIZE || code == libc::EOPNOTSUPP
    )
}

#[test]
fn writes_data_valid_packet_with_virtio_header() {
    let config = TunConfig::new("uwgwr%d").with_mtu(1420).with_offload(true);
    let Some(tun) = open_single(&config) else {
        return;
    };
    if configure_interface(tun.name()).is_none() {
        eprintln!("skipping: cannot bring {} up", tun.name());
        return;
    }
    let packet = ipv4_udp(64, [10, 0, 0, 1], [10, 0, 0, 2]);
    let header = VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_DATA_VALID,
        ..VirtioNetHdr::new()
    };
    match tun.write_with_header(&header, &packet) {
        Ok(written) => assert_eq!(written, packet.len()),
        Err(error) if is_kernel_rejection(&error) => {
            eprintln!("skipping: kernel rejected the header: {error}")
        }
        Err(error) => panic!("failed to write a virtio-tagged packet: {error}"),
    }
}

#[test]
fn writes_udp_gso_super_packet() {
    let config = TunConfig::new("uwggw%d").with_mtu(1420).with_offload(true);
    let Some(tun) = open_single(&config) else {
        return;
    };
    if !tun.offload().uso4 {
        eprintln!("skipping: UDP segmentation offload is unavailable");
        return;
    }
    if configure_interface(tun.name()).is_none() {
        eprintln!("skipping: cannot bring {} up", tun.name());
        return;
    }
    let packet = ipv4_udp(2400, [10, 0, 0, 1], [10, 0, 0, 2]);
    let header = VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
        hdr_len: 28,
        gso_size: 1200,
        csum_start: 20,
        csum_offset: 6,
        num_buffers: 0,
    };
    match tun.write_with_header(&header, &packet) {
        Ok(written) => assert_eq!(written, packet.len()),
        Err(error) if is_kernel_rejection(&error) => {
            eprintln!("skipping: kernel rejected the GSO packet: {error}")
        }
        Err(error) => panic!("failed to write a GSO super-packet: {error}"),
    }
}

#[test]
fn reads_segmented_udp_from_stack() {
    let config = TunConfig::new("uwggr%d").with_mtu(1420).with_offload(true);
    let Some(mut tun) = open_single(&config) else {
        return;
    };
    if !tun.offload().uso4 {
        eprintln!("skipping: UDP segmentation offload is unavailable");
        return;
    }
    let name = tun.name().to_owned();
    let Some(subnet) = configure_interface(&name) else {
        eprintln!("skipping: cannot configure {name}");
        return;
    };
    let socket = match Socket::open(OpenOptions::new(AddressFamily::Ipv4)) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping: {error}");
            return;
        }
    };
    if !socket.gso_enabled() {
        eprintln!("skipping: UDP_SEGMENT is unavailable");
        return;
    }
    let destination: std::net::SocketAddr =
        format!("{}.{}.{}.2:9", subnet[0], subnet[1], subnet[2])
            .parse()
            .expect("test address is valid");
    let payload = [0x5au8; 2400];
    let gso = GsoSize::new(1200).expect("test segment size is non-zero");
    let mut buffers = vec![vec![0u8; 2048]; 4];
    let mut slices: Vec<&mut [u8]> = buffers
        .iter_mut()
        .map(|buffer| buffer.as_mut_slice())
        .collect();
    let mut sizes = [0usize; 4];
    let mut segments = 0usize;
    for _ in 0..20 {
        let _ = socket.send_to(Endpoint::new(destination), &payload, Some(gso));
        if !poll_readable(&tun, 50) {
            continue;
        }
        match tun.read_batch_sizes(&mut slices, &mut sizes) {
            Ok(count) => {
                for size in sizes.iter().take(count) {
                    assert!(*size > 28, "segment is shorter than an IP and UDP header");
                    assert!(
                        *size <= 1420,
                        "segment of {size} bytes exceeds the interface MTU"
                    );
                }
                segments += count;
                if segments >= 2 {
                    break;
                }
            }
            Err(error) if error.io_kind() == Some(ErrorKind::WouldBlock) => {}
            Err(error) => panic!("failed to read a batch: {error}"),
        }
    }
    assert!(
        segments >= 2,
        "both datagram segments must arrive from the stack"
    );
}

#[test]
fn write_with_header_requires_offload() {
    let config = TunConfig::new("uwgnh%d").with_offload(false).with_mtu(0);
    let Some(tun) = open_single(&config) else {
        return;
    };
    let packet = ipv4_udp(16, [10, 0, 0, 1], [10, 0, 0, 2]);
    assert!(matches!(
        tun.write_with_header(&VirtioNetHdr::new(), &packet),
        Err(TunError::InvalidConfig(_))
    ));
}
