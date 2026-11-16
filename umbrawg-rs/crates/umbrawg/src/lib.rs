//! UmbraWG userspace daemon.

use std::env;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use umbrawg_device::{DatagramSink, Device, DeviceConfig, IncomingMeta, IoContext, PacketIo, Peer};
use umbrawg_transport::{
    AddressFamily, Endpoint, GsoSize, OpenOptions, RecvQueue, Socket, TransportError,
};
use umbrawg_tun::{Tun, TunConfig, TunError, TunSet};
use umbrawg_uapi::{socket_dir, UapiListener};

const MAX_PACKET: usize = 65_535;
const RECV_BATCH: usize = 64;
const IDLE_TIMEOUT_MS: i32 = 10;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Разобранные аргументы командной строки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Имя интерфейса.
    pub ifname: Option<String>,
    /// Запуск на переднем плане.
    pub foreground: bool,
    /// Показать версию.
    pub version: bool,
    /// Показать справку.
    pub help: bool,
}

/// Разбирает аргументы командной строки (без имени программы).
pub fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut parsed = Args {
        ifname: None,
        foreground: false,
        version: false,
        help: false,
    };
    let mut positional = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => parsed.help = true,
            "--version" | "-v" => parsed.version = true,
            "--foreground" | "-f" => parsed.foreground = true,
            value if value.starts_with('-') => {
                return Err(format!("неизвестный параметр: {value}"));
            }
            value => positional.push(value.to_owned()),
        }
    }

    if positional.len() > 1 {
        return Err("ожидается не более одного имени интерфейса".to_owned());
    }
    if let Some(name) = positional.first() {
        parsed.ifname = Some(name.clone());
    }
    if !parsed.help && !parsed.version && parsed.ifname.is_none() {
        return Err("не указано имя интерфейса".to_owned());
    }

    Ok(parsed)
}

/// Определяет число рабочих потоков.
pub fn worker_count(requested: Option<&str>, available: usize) -> usize {
    let available = available.max(1);
    let default = 4.min(available);
    match requested {
        Some(value) => value
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|count| *count > 0)
            .map_or(default, |count| count.min(available)),
        None => default,
    }
}

/// Запрашивает остановку демона.
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Возвращает true, если запрошена остановка.
pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Устанавливает обработчики SIGINT/SIGTERM.
pub fn install_signal_handlers() {
    let handler = signal_handler as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

extern "C" fn signal_handler(_signal: libc::c_int) {
    request_shutdown();
}

struct WorkerIo<'a> {
    socket: &'a Socket,
    tun: &'a Tun,
}

impl DatagramSink for WorkerIo<'_> {
    fn send_datagram(
        &mut self,
        endpoint: SocketAddr,
        _peer: Option<&Peer>,
        payload: &[u8],
        gso_size: Option<usize>,
    ) {
        let gso = gso_size.and_then(|size| GsoSize::from_usize(size).ok());
        log::debug!(
            "tx {} bytes to {endpoint} (gso {gso_size:?})",
            payload.len()
        );
        if let Err(error) = self.socket.send_to(Endpoint::new(endpoint), payload, gso) {
            log::debug!("send to {endpoint} failed: {error}");
        }
    }
}

impl PacketIo for WorkerIo<'_> {
    fn deliver(&mut self, _peer: &Peer, packet: &[u8]) {
        if let Err(error) = self.tun.write(packet) {
            log::debug!("tun write failed: {error}");
        }
    }
}

fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&packet[16..20]);
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        Some(6) if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn open_socket(port: u16, fwmark: u32) -> io::Result<Socket> {
    let mut options = OpenOptions::new(AddressFamily::Ipv4)
        .reuse_port(true)
        .nonblocking(true);
    if port != 0 {
        options = options.port(port);
    }
    if fwmark != 0 {
        options = options.mark(fwmark);
    }
    Socket::open(options).map_err(|error| io::Error::other(error.to_string()))
}

fn is_tun_would_block(error: &TunError) -> bool {
    matches!(error, TunError::Io(source) if source.kind() == io::ErrorKind::WouldBlock)
}

fn is_socket_would_block(error: &TransportError) -> bool {
    matches!(error, TransportError::WouldBlock)
}

fn worker_loop(device: Arc<Device>, mut tun: Tun) -> io::Result<()> {
    let mut rng = rand_core::OsRng;
    let mut packet = vec![0u8; MAX_PACKET];
    let mut scratch = vec![0u8; MAX_PACKET + 512];
    let mut tx_buffer = vec![0u8; MAX_PACKET + 512];
    let mut recv_queue =
        RecvQueue::new(RECV_BATCH).map_err(|error| io::Error::other(error.to_string()))?;
    let mut recv_buffers: Vec<Vec<u8>> = (0..RECV_BATCH).map(|_| vec![0u8; MAX_PACKET]).collect();
    let mut socket: Option<Socket> = None;

    while !shutdown_requested() {
        let now = Instant::now();
        let want_port = device.listen_port();
        let rebind = match socket.as_ref() {
            None => true,
            Some(current) => want_port != 0 && current.local_addr().port() != want_port,
        };
        if rebind {
            match open_socket(want_port, device.fwmark()) {
                Ok(new_socket) => {
                    log::info!("listening on {}", new_socket.local_addr());
                    socket = Some(new_socket);
                }
                Err(error) => {
                    log::error!("cannot bind UDP socket: {error}");
                    thread::sleep(Duration::from_millis(200));
                    continue;
                }
            }
        }
        let active = socket.as_ref().expect("socket is bound");
        let mut busy = false;

        loop {
            match tun.read(&mut packet) {
                Ok(length) if length > 0 => {
                    busy = true;
                    let Some(destination) = packet_destination(&packet[..length]) else {
                        continue;
                    };
                    let Some(peer) = device.route(destination) else {
                        log::debug!("no peer for {destination}");
                        continue;
                    };
                    let mut io = WorkerIo {
                        socket: active,
                        tun: &tun,
                    };
                    let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut io);
                    if let Err(error) =
                        device.send_packet(&peer, &packet[..length], &mut tx_buffer, &mut context)
                    {
                        log::debug!("encrypt failed: {error}");
                    }
                }
                Ok(_) => break,
                Err(error) if is_tun_would_block(&error) => break,
                Err(error) => {
                    log::debug!("tun read failed: {error}");
                    break;
                }
            }
        }

        loop {
            let received = {
                let mut buffers: Vec<&mut [u8]> = recv_buffers
                    .iter_mut()
                    .map(|buffer| buffer.as_mut_slice())
                    .collect();
                active.recv_batch(&mut recv_queue, &mut buffers)
            };
            match received {
                Ok(0) => break,
                Ok(count) => {
                    busy = true;
                    log::debug!("rx batch of {count} datagrams");
                    for (index, buffer) in recv_buffers.iter_mut().enumerate().take(count) {
                        let Some(meta) = recv_queue.meta(index) else {
                            continue;
                        };
                        let Some(endpoint) = meta.endpoint else {
                            continue;
                        };
                        if meta.truncated || meta.size == 0 {
                            continue;
                        }
                        let gro_size = meta.gro_size.map(GsoSize::as_usize);
                        let slice = &mut buffer[..meta.size];
                        let mut io = WorkerIo {
                            socket: active,
                            tun: &tun,
                        };
                        let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut io);
                        match device.handle_incoming(
                            slice,
                            IncomingMeta::new(endpoint.dst(), gro_size),
                            &mut context,
                        ) {
                            Ok(outcome) => log::debug!("incoming {} bytes: {outcome:?}", meta.size),
                            Err(error) => log::debug!("incoming failed: {error}"),
                        }
                    }
                }
                Err(error) if is_socket_would_block(&error) => break,
                Err(error) => {
                    log::debug!("recv failed: {error}");
                    break;
                }
            }
        }

        for peer in device.peers() {
            let mut io = WorkerIo {
                socket: active,
                tun: &tun,
            };
            let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut io);
            if let Err(error) = device.flush_staged(&peer, &mut context) {
                log::debug!("flush failed: {error}");
            }
        }

        if device
            .next_deadline()
            .is_some_and(|deadline| deadline <= now)
        {
            let mut io = WorkerIo {
                socket: active,
                tun: &tun,
            };
            let started = Instant::now();
            let mut context = IoContext::new(&mut rng, started, &mut scratch, &mut io);
            if let Err(error) = device.tick(&mut context) {
                log::debug!("timer tick failed: {error}");
            }
        }

        if !busy {
            let mut fds = [
                libc::pollfd {
                    fd: tun.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: active.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            unsafe {
                libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, IDLE_TIMEOUT_MS);
            }
        }
    }

    Ok(())
}

fn daemonize() -> io::Result<()> {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid > 0 {
            process::exit(0);
        }
        libc::setsid();
    }
    let devnull = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&devnull);
    unsafe {
        libc::dup2(fd, 0);
        libc::dup2(fd, 1);
        libc::dup2(fd, 2);
    }
    Ok(())
}

/// Запускает демон.
pub fn run(ifname: &str, foreground: bool) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(value) = env::var("UMBRAWG_RUNTIME_DIR") {
        env::set_var("UWG_RUNTIME_DIR", value);
    }

    install_signal_handlers();

    if !foreground {
        daemonize()?;
    }

    let available = thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    let requested = env::var("UMBRAWG_THREADS").ok();
    let workers = worker_count(requested.as_deref(), available);

    let device = Arc::new(Device::new(DeviceConfig::default())?);
    device.up();

    let config = TunConfig::new(ifname)
        .with_multi_queue(workers > 1)
        .with_offload(false)
        .with_nonblocking(true)
        .with_mtu(u32::from(device.mtu()));
    let tun_set = TunSet::open(&config, workers)?;

    let listener = UapiListener::bind(&socket_dir(), ifname)?;
    let server = listener.spawn(Arc::clone(&device))?;

    let mut handles = Vec::with_capacity(workers);
    for tun in tun_set.into_queues() {
        let device = Arc::clone(&device);
        let handle = thread::Builder::new()
            .name("umbrawg-worker".to_owned())
            .spawn(move || {
                if let Err(error) = worker_loop(device, tun) {
                    log::error!("worker stopped: {error}");
                }
            })?;
        handles.push(handle);
    }

    while !shutdown_requested() {
        thread::sleep(Duration::from_millis(100));
    }

    server.shutdown()?;
    server.join()?;
    for handle in handles {
        let _ = handle.join();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_foreground() {
        let args = parse_args(vec!["uwg0".to_owned(), "--foreground".to_owned()]).unwrap();
        assert_eq!(args.ifname.as_deref(), Some("uwg0"));
        assert!(args.foreground);
        assert!(!args.version);
        assert!(!args.help);
    }

    #[test]
    fn parses_version_and_help() {
        let version = parse_args(vec!["--version".to_owned()]).unwrap();
        assert!(version.version);
        let help = parse_args(vec!["--help".to_owned()]).unwrap();
        assert!(help.help);
    }

    #[test]
    fn rejects_unknown_and_missing() {
        assert!(parse_args(vec!["--bogus".to_owned()]).is_err());
        assert!(parse_args(vec![]).is_err());
        assert!(parse_args(vec!["a".to_owned(), "b".to_owned()]).is_err());
    }

    #[test]
    fn worker_count_default() {
        assert_eq!(worker_count(None, 8), 4);
        assert_eq!(worker_count(None, 2), 2);
    }

    #[test]
    fn worker_count_override() {
        assert_eq!(worker_count(Some("6"), 8), 6);
        assert_eq!(worker_count(Some("0"), 8), 4);
        assert_eq!(worker_count(Some("64"), 8), 8);
    }

    #[test]
    fn shutdown_flag() {
        request_shutdown();
        assert!(shutdown_requested());
    }

    #[test]
    fn parses_packet_destination() {
        let mut v4 = [0u8; 20];
        v4[0] = 0x45;
        v4[16..20].copy_from_slice(&[10, 9, 0, 2]);
        assert_eq!(
            packet_destination(&v4),
            Some(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2)))
        );
        assert_eq!(packet_destination(&[0u8; 4]), None);
    }
}
