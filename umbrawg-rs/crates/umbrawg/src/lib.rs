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

use umbrawg_crypto::random::BufferedRng;
use umbrawg_device::{
    device::BbrBatch, BbrMode, DatagramSink, Device, DeviceConfig, DeviceError, ExtConfig, FecMode,
    IncomingMeta, IoContext, PacketIo, Peer, DEFAULT_MAX_SHARD_LEN, DEFAULT_UNDER_LOAD_PPS,
    MIN_MAX_SHARD_LEN,
};
use umbrawg_transport::{
    AddressFamily, Endpoint, GsoLimits, GsoSize, OpenOptions, RecvQueue, Socket, SocketSet,
    SocketSource, TransportError, MAX_BATCH_SIZE,
};
use umbrawg_tun::{Tun, TunConfig, TunError, TunSet, VirtioNetHdr};
use umbrawg_uapi::{socket_dir, ServerHandle, UapiListener};

mod control;
mod mtu;
mod parallel;
mod ring;
mod rx;
mod tx;

use control::ConfigControl;
use mtu::{fec_max_shard_len, fec_tun_mtu, MtuGuard, Underlay};
use rx::RxBatch;
use tx::TxBatch;

const MAX_PACKET: usize = 65_535;
const RECV_BATCH: usize = 64;
const TUN_BATCH: usize = 128;
const TUN_PACKET_MARGIN: usize = 256;
const IDLE_TIMEOUT_MS: i32 = 10;
const SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const SOCKET_BUFFER_MIN_BYTES: usize = 212 * 1024;
const SOCKET_BUFFER_MAX_BYTES: usize = 64 * 1024 * 1024;
const SOCKET_BUFFER_TOLERANCE_BYTES: usize = 4096;

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

fn under_load_detection_enabled(value: Option<&str>) -> bool {
    !matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("0" | "false" | "no" | "off")
    )
}

fn under_load_threshold(value: Option<&str>) -> u32 {
    value
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|threshold| *threshold > 0)
        .unwrap_or(DEFAULT_UNDER_LOAD_PPS)
}

fn apply_under_load_config(device: &Device) {
    let threshold = under_load_threshold(env::var("UMBRAWG_UNDER_LOAD_PPS").ok().as_deref());
    device.set_under_load_threshold(threshold);
    let enabled = under_load_detection_enabled(env::var("UMBRAWG_UNDER_LOAD").ok().as_deref());
    device.set_under_load_detection(enabled);
    log::info!("under-load detector: enabled={enabled} threshold={threshold} initiations/s");
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
    socket: &'a dyn SocketSource,
    tun: &'a Tun,
    rx: &'a mut RxBatch,
    stats: Option<&'a parallel::RxStats>,
    /// Устройство доступно только на путях демона: внутренние вызовы
    /// устройства передают `None`, чтобы не заходить в него повторно.
    device: Option<&'a Device>,
}

impl DatagramSink for WorkerIo<'_> {
    fn send_datagram(
        &mut self,
        endpoint: SocketAddr,
        peer: Option<&Peer>,
        payload: &[u8],
        gso_size: Option<usize>,
    ) {
        let gso = gso_size.and_then(|size| GsoSize::from_usize(size).ok());
        log::debug!(
            "tx {} bytes to {endpoint} (gso {gso_size:?})",
            payload.len()
        );
        if let Err(error) = self
            .socket
            .next()
            .send_to(Endpoint::new(endpoint), payload, gso)
        {
            // The datagram was already registered with the congestion
            // controller: a local send error must return its bytes to the
            // window instead of waiting for the watermark sweep.
            if let (Some(device), Some(peer)) = (self.device, peer) {
                device.on_send_drop(peer, payload.len());
            }
            log::debug!("send to {endpoint} failed: {error}");
        }
    }
}

impl PacketIo for WorkerIo<'_> {
    fn deliver(&mut self, _peer: &Peer, packet: &[u8]) {
        if self.rx.push(packet) {
            return;
        }
        self.rx.flush(self.tun);
        if self.rx.push(packet) {
            return;
        }
        if let Err(error) = self.tun.write(packet) {
            if let Some(stats) = self.stats {
                stats.drops_tun.fetch_add(1, Ordering::Relaxed);
            }
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

fn socket_buffer_bytes(value: Option<&str>) -> Result<usize, String> {
    let Some(raw) = value else {
        return Ok(SOCKET_BUFFER_BYTES);
    };
    let text = raw.trim();
    let size = text.parse::<usize>().map_err(|_| {
        format!("UMBRAWG_SOCKET_BUFFER: ожидается размер в байтах, получено {text:?}")
    })?;
    if !(SOCKET_BUFFER_MIN_BYTES..=SOCKET_BUFFER_MAX_BYTES).contains(&size) {
        return Err(format!(
            "UMBRAWG_SOCKET_BUFFER: размер {size} вне диапазона \
             {SOCKET_BUFFER_MIN_BYTES}..={SOCKET_BUFFER_MAX_BYTES} байт"
        ));
    }
    Ok(size)
}

fn effective_socket_buffer(actual: usize) -> usize {
    actual / 2
}

fn socket_buffer_shortfall(requested: usize, actual: usize) -> Option<usize> {
    let effective = effective_socket_buffer(actual);
    (effective.saturating_add(SOCKET_BUFFER_TOLERANCE_BYTES) < requested).then_some(effective)
}

fn read_socket_buffer(fd: libc::c_int, option: libc::c_int) -> io::Result<usize> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sockopt {option} returned negative value {value}"),
        )
    })
}

fn warn_if_buffer_clamped(
    fd: libc::c_int,
    option: libc::c_int,
    name: &str,
    sysctl: &str,
    requested: usize,
) {
    match read_socket_buffer(fd, option) {
        Ok(actual) => match socket_buffer_shortfall(requested, actual) {
            Some(effective) => log::warn!(
                "{name} was clamped by the kernel: effective {effective} bytes, \
                 requested {requested} bytes; raise {sysctl} or lower UMBRAWG_SOCKET_BUFFER"
            ),
            None => log::debug!(
                "{name}: requested {requested} bytes, effective {} bytes",
                effective_socket_buffer(actual)
            ),
        },
        Err(error) => log::debug!("cannot read {name}: {error}"),
    }
}

fn open_socket(port: u16, fwmark: u32, buffer: usize, limits: GsoLimits) -> io::Result<Socket> {
    let mut options = OpenOptions::new(AddressFamily::Ipv4)
        .reuse_port(true)
        .nonblocking(true)
        .receive_buffer(buffer)
        .send_buffer(buffer)
        .gso_limits(limits);
    if port != 0 {
        options = options.port(port);
    }
    if fwmark != 0 {
        options = options.mark(fwmark);
    }
    let socket = Socket::open(options).map_err(|error| io::Error::other(error.to_string()))?;
    warn_if_buffer_clamped(
        socket.fd(),
        libc::SO_RCVBUF,
        "SO_RCVBUF",
        "net.core.rmem_max",
        buffer,
    );
    warn_if_buffer_clamped(
        socket.fd(),
        libc::SO_SNDBUF,
        "SO_SNDBUF",
        "net.core.wmem_max",
        buffer,
    );
    Ok(socket)
}

fn apply_socket_mark(sockets: &SocketSet, mark: u32) -> bool {
    let mut ok = true;
    for socket in sockets.all() {
        if let Err(error) = socket.set_mark(mark) {
            log::warn!(
                "cannot set SO_MARK {mark} on {}: {error}",
                socket.local_addr()
            );
            ok = false;
        }
    }
    ok
}

fn open_socket_set(
    port: u16,
    extra: usize,
    fwmark: u32,
    buffer: usize,
    limits: GsoLimits,
    gso_segments: Option<usize>,
) -> io::Result<SocketSet> {
    let mut sockets = Vec::with_capacity(extra + 1);
    let primary = open_socket(port, fwmark, buffer, limits)?;
    log::info!("listening on {}", primary.local_addr());
    sockets.push(primary);
    for index in 0..extra {
        match open_socket(0, fwmark, buffer, limits) {
            Ok(socket) => {
                log::info!("extra udp port {}: {}", index + 1, socket.local_addr());
                sockets.push(socket);
            }
            Err(error) => {
                log::warn!(
                    "cannot bind extra UDP socket {index} of {extra}: {error}; \
                     continuing with {} port(s)",
                    sockets.len()
                );
                break;
            }
        }
    }
    let set = SocketSet::new(sockets).map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(segments) = gso_segments {
        for socket in set.all() {
            socket.limit_gso_segments(segments);
        }
    }
    Ok(set)
}

/// Проверяет, нужно ли пересоздать набор сокетов.
///
/// `bound_epoch` — эпоха `listen_port`, при которой набор был привязан.
/// Запрос `listen-port 0` не меняет значение порта, поэтому повторный запрос
/// эфемерного порта виден только по смене эпохи.
///
/// `bound_underlay` — MTU подложки, из которого посчитаны GSO-лимиты сокетов:
/// смена `underlay-mtu` через UAPI требует новой привязки, иначе сегменты
/// остаются ограничены старым MTU до рестарта.
///
/// `bound_extra` — число дополнительных портов, запрошенное при последней
/// успешной привязке: при частичном сбое набор может содержать меньше сокетов,
/// и повторная привязка каждый цикл только вредила бы.
#[allow(clippy::too_many_arguments)]
fn rebind_needed(
    current: Option<&SocketSet>,
    bound_epoch: Option<u64>,
    want_epoch: u64,
    bound_extra: Option<usize>,
    bound_underlay: Option<u16>,
    want_port: u16,
    want_extra: usize,
    want_underlay: u16,
) -> bool {
    let Some(current) = current else {
        return true;
    };
    if bound_epoch != Some(want_epoch) || bound_underlay != Some(want_underlay) {
        return true;
    }
    let port_matches = want_port == 0 || current.primary().local_addr().port() == want_port;
    !port_matches || bound_extra != Some(want_extra)
}

/// Порт, который нужно запросить при перепривязке.
///
/// Перепривязка из-за смены GSO-лимитов не должна менять эфемерный порт:
/// пиры уже знают старый endpoint. Новый порт выбирается только для явного
/// `listen-port 0` (сменилась эпоха) или для нового фиксированного порта.
fn rebind_port(
    requested: u16,
    bound_epoch: Option<u64>,
    want_epoch: u64,
    current: Option<u16>,
) -> u16 {
    if requested != 0 {
        return requested;
    }
    if bound_epoch == Some(want_epoch) {
        current.unwrap_or(0)
    } else {
        0
    }
}

fn poll_inputs(source: &dyn SocketSource, tun: &Tun, fds: &mut Vec<libc::pollfd>) {
    fds.clear();
    fds.push(libc::pollfd {
        fd: tun.fd(),
        events: libc::POLLIN,
        revents: 0,
    });
    for socket in source.all() {
        fds.push(libc::pollfd {
            fd: socket.fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
}

/// Миллисекунды до ближайшего дедлайна в пределах `1..=IDLE_TIMEOUT_MS`.
///
/// ACK и partial-блок FEC имеют дедлайны 0.5..=5 мс; опрос по ближайшему из
/// них убирает ожидание до 10 мс. Минимум 1 мс не превращает цикл в busy-loop,
/// а отсутствие дедлайна сохраняет прежний 10-мс простой.
pub(crate) fn poll_timeout_ms(now: Instant, deadline: Option<Instant>) -> i32 {
    let Some(deadline) = deadline else {
        return IDLE_TIMEOUT_MS;
    };
    let wait = deadline.saturating_duration_since(now);
    let millis = wait.as_micros().div_ceil(1000);
    i32::try_from(millis)
        .unwrap_or(i32::MAX)
        .clamp(1, IDLE_TIMEOUT_MS)
}

/// Более ранний из двух необязательных дедлайнов.
pub(crate) fn earliest_deadline(
    first: Option<Instant>,
    second: Option<Instant>,
) -> Option<Instant> {
    match (first, second) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

/// Ограничения подложки с MTU, актуальным для устройства.
///
/// Стартовые значения приходят из env, но `underlay-mtu` можно изменить
/// через UAPI. GSO-лимиты и `max_datagram_len` сокета выводятся из MTU,
/// поэтому их нужно пересчитывать, а не хранить снимок времени старта.
pub(crate) fn runtime_underlay(base: Underlay, device: &Device) -> Underlay {
    base.with_mtu(u32::from(device.underlay_mtu()))
        .unwrap_or(base)
}

fn is_tun_would_block(error: &TunError) -> bool {
    matches!(error, TunError::Io(source) if source.kind() == io::ErrorKind::WouldBlock)
}

fn is_socket_would_block(error: &TransportError) -> bool {
    matches!(error, TransportError::WouldBlock)
}

fn batch_flush_needed(used: usize, packets: usize, record: usize, capacity: usize) -> bool {
    used.saturating_add(packets.saturating_mul(record)) > capacity
}

#[allow(clippy::too_many_arguments)]
fn send_run<R: rand_core::RngCore>(
    device: &Device,
    socket: &dyn SocketSource,
    tun: &Tun,
    rng: &mut R,
    now: Instant,
    scratch: &mut [u8],
    fallback: &mut [u8],
    batch_buffer: &mut [u8],
    batch: &mut TxBatch,
    peer: &Arc<Peer>,
    plaintexts: &[&[u8]],
    rekey: &mut Vec<Arc<Peer>>,
    rx: &mut RxBatch,
) {
    if plaintexts.is_empty() {
        return;
    }
    if device.bbr_queue_active(peer) {
        let mut small: [&[u8]; TUN_BATCH] = [&[]; TUN_BATCH];
        let mut small_len = 0usize;
        for packet in plaintexts {
            if packet.len() <= 256 {
                small[small_len] = packet;
                small_len += 1;
            } else if !device.bbr_enqueue(peer, packet) {
                log::debug!(
                    "BBR queue is full: dropped {} bytes ({} dropped so far)",
                    packet.len(),
                    device.bbr_queue_drop_count()
                );
            }
        }
        if small_len > 0 {
            send_run_inner(
                device,
                socket,
                tun,
                rng,
                now,
                scratch,
                fallback,
                batch_buffer,
                batch,
                peer,
                &small[..small_len],
                rekey,
                rx,
            );
        }
        return;
    }
    {
        let bytes: usize = plaintexts.iter().map(|packet| packet.len()).sum();
        let delay = device.pacing_delay(peer, bytes, now);
        if delay > Duration::from_millis(2) && plaintexts.len() > 1 {
            thread::sleep(delay.min(Duration::from_millis(50)));
        }
    }
    if let Some(limit) = device.fec_packet_limit(peer) {
        for chunk in plaintexts.chunks(limit.max(1)) {
            send_run_inner(
                device,
                socket,
                tun,
                rng,
                now,
                scratch,
                fallback,
                batch_buffer,
                batch,
                peer,
                chunk,
                rekey,
                rx,
            );
        }
        return;
    }
    send_run_inner(
        device,
        socket,
        tun,
        rng,
        now,
        scratch,
        fallback,
        batch_buffer,
        batch,
        peer,
        plaintexts,
        rekey,
        rx,
    );
}

#[allow(clippy::too_many_arguments)]
fn send_run_inner<R: rand_core::RngCore>(
    device: &Device,
    socket: &dyn SocketSource,
    tun: &Tun,
    rng: &mut R,
    now: Instant,
    scratch: &mut [u8],
    fallback: &mut [u8],
    batch_buffer: &mut [u8],
    batch: &mut TxBatch,
    peer: &Arc<Peer>,
    plaintexts: &[&[u8]],
    rekey: &mut Vec<Arc<Peer>>,
    rx: &mut RxBatch,
) {
    if plaintexts.is_empty() {
        return;
    }
    let record = tun.mtu() as usize + TUN_PACKET_MARGIN;
    if batch_flush_needed(batch.used(), plaintexts.len(), record, batch_buffer.len()) {
        batch.flush_with(socket, batch_buffer, |peer, bytes| {
            device.on_send_drop(peer, bytes);
        });
    }
    let mut offset = batch.used();
    let mut retried = false;
    let result = loop {
        let mut io = WorkerIo {
            socket,
            tun,
            rx,
            stats: None,
            device: Some(device),
        };
        let mut context = IoContext::new(rng, now, scratch, &mut io);
        match device.send_batch(peer, plaintexts, &mut batch_buffer[offset..], &mut context) {
            Ok(sent) => break Ok(sent),
            Err(error) => {
                let retry =
                    matches!(error, DeviceError::BufferTooSmall { .. }) && !retried && offset > 0;
                if !retry {
                    break Err(error);
                }
                retried = true;
                batch.flush_with(socket, batch_buffer, |peer, bytes| {
                    device.on_send_drop(peer, bytes);
                });
                offset = batch.used();
            }
        }
    };
    match result {
        Ok(sent) => {
            if sent.staged > 0 {
                batch.flush_with(socket, batch_buffer, |peer, bytes| {
                    device.on_send_drop(peer, bytes);
                });
                if sent.needs_handshake {
                    let mut io = WorkerIo {
                        socket,
                        tun,
                        rx,
                        stats: None,
                        device: Some(device),
                    };
                    let mut context = IoContext::new(rng, now, scratch, &mut io);
                    if let Err(error) = device.initiate_handshake(peer, &mut context) {
                        log::debug!("handshake failed: {error}");
                    }
                }
                return;
            }
            if sent.sent == 0 {
                return;
            }
            let Some(endpoint) = sent.endpoint else {
                return;
            };
            if !batch.push_for_peer(peer, endpoint, offset, &sent.layout) {
                batch.flush_with(socket, batch_buffer, |peer, bytes| {
                    device.on_send_drop(peer, bytes);
                });
                if !batch.push_for_peer(peer, endpoint, offset, &sent.layout) {
                    return;
                }
            }
            if !rekey.iter().any(|known| Arc::ptr_eq(known, peer)) {
                rekey.push(Arc::clone(peer));
            }
        }
        Err(DeviceError::BufferTooSmall { .. }) => {
            batch.flush_with(socket, batch_buffer, |peer, bytes| {
                device.on_send_drop(peer, bytes);
            });
            let mut io = WorkerIo {
                socket,
                tun,
                rx,
                stats: None,
                device: Some(device),
            };
            let mut context = IoContext::new(rng, now, scratch, &mut io);
            for plaintext in plaintexts {
                if let Err(error) = device.send_packet(peer, plaintext, fallback, &mut context) {
                    log::debug!("send failed: {error}");
                }
            }
        }
        Err(error) => log::debug!("batch send failed: {error}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn flush_plain_run<R: rand_core::RngCore>(
    device: &Device,
    socket: &dyn SocketSource,
    tun: &Tun,
    rng: &mut R,
    now: Instant,
    scratch: &mut [u8],
    tx_buffer: &mut [u8],
    batch_buffer: &mut [u8],
    batch: &mut TxBatch,
    peer: &Arc<Peer>,
    tx_plain: &[u8],
    offsets: &[(usize, usize); TUN_BATCH],
    pending: usize,
    rekey: &mut Vec<Arc<Peer>>,
    rx: &mut RxBatch,
) {
    if pending == 0 {
        return;
    }
    let mut plaintexts: [&[u8]; TUN_BATCH] = [&[]; TUN_BATCH];
    for index in 0..pending {
        let (start, length) = offsets[index];
        plaintexts[index] = &tx_plain[start..start + length];
    }
    send_run(
        device,
        socket,
        tun,
        rng,
        now,
        scratch,
        tx_buffer,
        batch_buffer,
        batch,
        peer,
        &plaintexts[..pending],
        rekey,
        rx,
    );
}

#[allow(clippy::too_many_arguments)]
fn pump_tun_tx<R: rand_core::RngCore>(
    device: &Device,
    socket: &dyn SocketSource,
    tun: &mut Tun,
    rng: &mut R,
    now: Instant,
    scratch: &mut [u8],
    tx_buffer: &mut [u8],
    tx_plain: &mut [u8],
    batch_buffer: &mut [u8],
    batch: &mut TxBatch,
    rx: &mut RxBatch,
    tun_slices: &mut [&mut [u8]],
    tun_sizes: &mut [usize],
    rekey: &mut Vec<Arc<Peer>>,
) -> bool {
    let mut busy = false;
    let mut offsets = [(0usize, 0usize); TUN_BATCH];
    let mut pending = 0usize;
    let mut used = 0usize;
    let mut current: Option<Arc<Peer>> = None;

    loop {
        match tun.read_batch_sizes(tun_slices, tun_sizes) {
            Ok(0) => break,
            Ok(count) => {
                busy = true;
                log::debug!("tun batch of {count} segments");
                for index in 0..count {
                    let length = tun_sizes[index];
                    if length == 0 {
                        continue;
                    }
                    let packet = &tun_slices[index][..length];
                    let Some(destination) = packet_destination(packet) else {
                        continue;
                    };
                    let Some(peer) = device.route(destination) else {
                        log::debug!("no peer for {destination}");
                        continue;
                    };
                    let same = current
                        .as_ref()
                        .is_some_and(|known| Arc::ptr_eq(known, &peer));
                    if !same {
                        if let Some(previous) = current.as_ref() {
                            flush_plain_run(
                                device,
                                socket,
                                tun,
                                rng,
                                now,
                                scratch,
                                tx_buffer,
                                batch_buffer,
                                batch,
                                previous,
                                tx_plain,
                                &offsets,
                                pending,
                                rekey,
                                rx,
                            );
                            pending = 0;
                            used = 0;
                        }
                        current = Some(peer);
                    }
                    if used + length > tx_plain.len() {
                        if let Some(previous) = current.as_ref() {
                            flush_plain_run(
                                device,
                                socket,
                                tun,
                                rng,
                                now,
                                scratch,
                                tx_buffer,
                                batch_buffer,
                                batch,
                                previous,
                                tx_plain,
                                &offsets,
                                pending,
                                rekey,
                                rx,
                            );
                        }
                        pending = 0;
                        used = 0;
                    }
                    tx_plain[used..used + length].copy_from_slice(packet);
                    offsets[pending] = (used, length);
                    used += length;
                    pending += 1;
                    if pending == TUN_BATCH {
                        if let Some(peer) = current.as_ref() {
                            flush_plain_run(
                                device,
                                socket,
                                tun,
                                rng,
                                now,
                                scratch,
                                tx_buffer,
                                batch_buffer,
                                batch,
                                peer,
                                tx_plain,
                                &offsets,
                                pending,
                                rekey,
                                rx,
                            );
                        }
                        pending = 0;
                        used = 0;
                    }
                }
            }
            Err(error) if is_tun_would_block(&error) => break,
            Err(TunError::BufferTooSmall { needed, available }) => {
                log::warn!(
                    "TUN buffer is too small: packet needs {needed} bytes, have {available}; \
                     restart the daemon after changing the interface MTU"
                );
                break;
            }
            Err(error) => {
                log::debug!("tun read failed: {error}");
                break;
            }
        }
    }
    if pending > 0 {
        if let Some(peer) = current.as_ref() {
            flush_plain_run(
                device,
                socket,
                tun,
                rng,
                now,
                scratch,
                tx_buffer,
                batch_buffer,
                batch,
                peer,
                tx_plain,
                &offsets,
                pending,
                rekey,
                rx,
            );
        }
    }
    busy
}

fn worker_loop(
    device: Arc<Device>,
    mut tun: Tun,
    socket_buffer: usize,
    underlay: Underlay,
) -> io::Result<()> {
    let mut rng = BufferedRng::new(rand_core::OsRng);
    let mut scratch = vec![0u8; MAX_PACKET + 512];
    let mut tx_buffer = vec![0u8; MAX_PACKET + 512];
    let mut recv_queue =
        RecvQueue::new(RECV_BATCH).map_err(|error| io::Error::other(error.to_string()))?;
    let mut recv_buffers: Vec<Vec<u8>> = (0..RECV_BATCH).map(|_| vec![0u8; MAX_PACKET]).collect();
    let mut recv_slices: Vec<&mut [u8]> = recv_buffers
        .iter_mut()
        .map(|buffer| buffer.as_mut_slice())
        .collect();
    let slot = usize::from(device.mtu()).max(tun.mtu() as usize) + TUN_PACKET_MARGIN;
    let mut tx_plain = vec![0u8; TUN_BATCH * slot];
    let mut tun_bufs: Vec<Vec<u8>> = (0..TUN_BATCH).map(|_| vec![0u8; slot]).collect();
    let mut tun_slices: Vec<&mut [u8]> = tun_bufs
        .iter_mut()
        .map(|buffer| buffer.as_mut_slice())
        .collect();
    let mut tun_sizes = [0usize; TUN_BATCH];
    let mut batch_buffer = vec![0u8; TUN_BATCH * slot];
    let mut batch =
        TxBatch::new(MAX_BATCH_SIZE).map_err(|error| io::Error::other(error.to_string()))?;
    let mut rx = RxBatch::new(slot);
    let mut rekey: Vec<Arc<Peer>> = Vec::with_capacity(TUN_BATCH);
    let mut socket: Option<SocketSet> = None;
    let mut bound_extra: Option<usize> = None;
    let mut bound_epoch: Option<u64> = None;
    let mut bound_underlay: Option<u16> = None;
    let mut bound_mark: Option<u32> = None;
    let mut bound_gso_limit = usize::MAX;
    let mut rebind_after = Instant::now();

    while !shutdown_requested() {
        let now = Instant::now();
        device.refresh_under_load(now);
        let (want_port, want_epoch) = device.listen_port_request();
        let want_extra = usize::from(device.extra_ports());
        let want_mark = device.fwmark();
        let want_underlay = device.underlay_mtu();
        if now >= rebind_after
            && rebind_needed(
                socket.as_ref(),
                bound_epoch,
                want_epoch,
                bound_extra,
                bound_underlay,
                want_port,
                want_extra,
                want_underlay,
            )
        {
            let current_port = socket
                .as_ref()
                .map(|current| current.primary().local_addr().port());
            let bind_port = rebind_port(want_port, bound_epoch, want_epoch, current_port);
            match open_socket_set(
                bind_port,
                want_extra,
                want_mark,
                socket_buffer,
                runtime_underlay(underlay, &device).gso_limits(),
                device.fec_gso_segments(),
            ) {
                Ok(new_socket) => {
                    // An ephemeral request must be reported as the port that
                    // was actually bound; the request itself stays `0` so a
                    // repeated `listen-port 0` is still visible.
                    let actual = new_socket.primary().local_addr().port();
                    device.note_bound_listen_port(want_epoch, actual);
                    bound_epoch = Some(want_epoch);
                    bound_extra = Some(want_extra);
                    bound_underlay = Some(want_underlay);
                    bound_mark = Some(want_mark);
                    socket = Some(new_socket);
                }
                Err(error) => {
                    log::error!("cannot bind UDP socket: {error}");
                    if socket.is_none() {
                        thread::sleep(Duration::from_millis(200));
                        continue;
                    }
                    rebind_after = now + Duration::from_secs(1);
                }
            }
        }
        let active = socket.as_ref().expect("socket is bound");
        let want_gso_limit = device.fec_gso_segments().unwrap_or(usize::MAX);
        if bound_gso_limit != want_gso_limit {
            for listener in active.all() {
                listener.limit_gso_segments(want_gso_limit);
            }
            bound_gso_limit = want_gso_limit;
        }
        if bound_mark != Some(want_mark) && apply_socket_mark(active, want_mark) {
            bound_mark = Some(want_mark);
        }
        device.for_each_peer(|peer| {
            let mut io = WorkerIo {
                socket: active,
                tun: &tun,
                rx: &mut rx,
                stats: None,
                device: Some(device.as_ref()),
            };
            let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut io);
            let _ = device.flush_control(peer, &mut context);
        });
        rekey.clear();
        let mut drained = BbrBatch::new();
        device.for_each_peer(|peer| {
            if device.bbr_drain_into(peer, now, MAX_BATCH_SIZE, &mut drained) == 0 {
                return;
            }
            let slices: Vec<&[u8]> = drained.iter().collect();
            send_run_inner(
                &device,
                active,
                &tun,
                &mut rng,
                now,
                &mut scratch,
                &mut tx_buffer,
                &mut batch_buffer,
                &mut batch,
                peer,
                &slices,
                &mut rekey,
                &mut rx,
            );
        });
        let mut busy = pump_tun_tx(
            &device,
            active,
            &mut tun,
            &mut rng,
            now,
            &mut scratch,
            &mut tx_buffer,
            &mut tx_plain,
            &mut batch_buffer,
            &mut batch,
            &mut rx,
            &mut tun_slices,
            &mut tun_sizes,
            &mut rekey,
        );

        if !batch.is_empty() {
            batch.flush_with(active, &batch_buffer, |peer, bytes| {
                device.on_send_drop(peer, bytes);
            });
        }
        for peer in &rekey {
            let mut io = WorkerIo {
                socket: active,
                tun: &tun,
                rx: &mut rx,
                stats: None,
                device: Some(device.as_ref()),
            };
            let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut io);
            if let Err(error) = device.after_batch_sent(peer, &mut context) {
                log::debug!("send timers failed: {error}");
            }
        }

        for listener in active.all() {
            loop {
                match listener.recv_batch(&mut recv_queue, &mut recv_slices) {
                    Ok(0) => break,
                    Ok(count) => {
                        busy = true;
                        log::debug!("rx batch of {count} datagrams");
                        let snapshot = device.incoming_snapshot();
                        for (index, buffer) in recv_slices.iter_mut().enumerate().take(count) {
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
                                rx: &mut rx,
                                stats: None,
                                device: Some(device.as_ref()),
                            };
                            let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut io);
                            match device.handle_incoming_with(
                                slice,
                                IncomingMeta::new(endpoint.dst(), gro_size),
                                &snapshot,
                                &mut context,
                            ) {
                                Ok(outcome) => {
                                    log::debug!("incoming {} bytes: {outcome:?}", meta.size)
                                }
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
        }

        rx.flush(&tun);

        let mut staged_error: Option<DeviceError> = None;
        device.for_each_peer(|peer| {
            let mut io = WorkerIo {
                socket: active,
                tun: &tun,
                rx: &mut rx,
                stats: None,
                device: Some(device.as_ref()),
            };
            let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut io);
            if let Err(error) = device.flush_staged(peer, &mut context) {
                staged_error = Some(error);
            }
        });
        if let Some(error) = staged_error {
            log::debug!("flush failed: {error}");
        }

        if device
            .next_deadline()
            .is_some_and(|deadline| deadline <= now)
        {
            let mut io = WorkerIo {
                socket: active,
                tun: &tun,
                rx: &mut rx,
                stats: None,
                device: Some(device.as_ref()),
            };
            let started = Instant::now();
            let mut context = IoContext::new(&mut rng, started, &mut scratch, &mut io);
            if let Err(error) = device.tick(&mut context) {
                log::debug!("timer tick failed: {error}");
            }
        }

        if !busy {
            let mut fds = Vec::with_capacity(active.all().len() + 1);
            poll_inputs(active, &tun, &mut fds);
            let timeout = poll_timeout_ms(Instant::now(), device.next_deadline());
            unsafe {
                libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout);
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
    let socket_buffer = socket_buffer_bytes(env::var("UMBRAWG_SOCKET_BUFFER").ok().as_deref())
        .map_err(io::Error::other)?;
    let underlay = Underlay::from_env().map_err(io::Error::other)?;

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

    let mut ext = ext_config_from_env().map_err(io::Error::other)?;
    let shard_cap = ext.max_shard_len;
    let fec_enabled = ext.fec != FecMode::Off;
    if fec_enabled {
        let derived = u16::try_from(fec_max_shard_len(underlay)).unwrap_or(u16::MAX);
        let limit = shard_cap.min(derived);
        if limit != ext.max_shard_len {
            log::info!(
                "FEC shard limit lowered from {} to {limit} bytes to fit the {}-byte underlay MTU",
                ext.max_shard_len,
                underlay.mtu()
            );
            ext.max_shard_len = limit;
        }
    }
    log::info!(
        "extension: bbr={} fec={} shard={} ack_interval={}",
        ext.bbr.as_str(),
        ext.fec.as_string(),
        ext.max_shard_len,
        ext.ack_interval
    );
    let device = Arc::new(Device::new(DeviceConfig {
        // The extension derives the FEC shard budget and the tunnel MTU from
        // the underlay MTU, so the device must know the configured value and
        // not fall back to the 1500-byte default.
        underlay_mtu: u16::try_from(underlay.mtu()).map_err(io::Error::other)?,
        ext,
        ..DeviceConfig::default()
    })?);
    apply_under_load_config(&device);
    log::info!("{underlay}");
    let tun_mtu = fec_tun_mtu(underlay, device.mtu(), device.obfuscation().s4, fec_enabled);
    if tun_mtu != device.mtu() {
        log::info!(
            "TUN MTU {} -> {tun_mtu} bytes for FEC over the {}-byte underlay",
            device.mtu(),
            underlay.mtu()
        );
    }
    let guard = Arc::new(MtuGuard::new(underlay));
    guard.check(tun_mtu, device.obfuscation().s4);
    device.up();

    if let Some(parallel) =
        parallel::ParallelConfig::from_env(available).map_err(io::Error::other)?
    {
        log::info!(
            "parallel rx enabled: {} crypto workers, sched={}, queue depth {} slots (~{} MiB per worker)",
            parallel.workers,
            parallel.sched.as_str(),
            parallel.queue_depth,
            parallel::queue_bytes(parallel.queue_depth).div_ceil(1024 * 1024)
        );
        return run_parallel(
            device,
            ifname,
            parallel,
            socket_buffer,
            underlay,
            guard,
            shard_cap,
        );
    }

    let requested = env::var("UMBRAWG_THREADS").ok();
    let workers = worker_count(requested.as_deref(), available);

    let config = TunConfig::new(ifname)
        .with_multi_queue(workers > 1)
        .with_offload(true)
        .with_vnet_hdr_size(VirtioNetHdr::LEN)
        .with_nonblocking(true)
        .with_mtu(u32::from(tun_mtu));
    let tun_set = match TunSet::open(&config, workers) {
        Ok(set) => set,
        Err(TunError::Unsupported(feature)) => {
            log::warn!("tun offload is unavailable ({feature}); falling back to packet mode");
            TunSet::open(&config.clone().with_offload(false), workers)?
        }
        Err(error) => return Err(error.into()),
    };

    let listener = UapiListener::bind(&socket_dir(), ifname)?;
    let server = listener.spawn(Arc::new(ConfigControl::new(
        Arc::clone(&device),
        Arc::clone(&guard),
        ifname,
        shard_cap,
    )))?;

    let mut handles = Vec::with_capacity(workers);
    for tun in tun_set.into_queues() {
        let device = Arc::clone(&device);
        let handle = thread::Builder::new()
            .name("umbrawg-worker".to_owned())
            .spawn(move || {
                if let Err(error) = worker_loop(device, tun, socket_buffer, underlay) {
                    log::error!("worker stopped: {error}");
                }
            })?;
        handles.push(handle);
    }

    while !shutdown_requested() {
        if handles.iter().any(|handle| handle.is_finished()) {
            log::error!("a worker thread exited unexpectedly; stopping the daemon");
            request_shutdown();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let joined = server.join();
    for handle in handles {
        let _ = handle.join();
    }
    joined?;

    Ok(())
}

fn ext_config_from_env() -> Result<ExtConfig, String> {
    let mut config = ExtConfig::default();
    if let Ok(value) = env::var("UMBRAWG_BBR") {
        config.bbr = BbrMode::parse(&value)
            .ok_or_else(|| format!("UMBRAWG_BBR: неизвестный режим {value:?}"))?;
    }
    if let Ok(value) = env::var("UMBRAWG_FEC") {
        config.fec = FecMode::parse(&value)
            .ok_or_else(|| format!("UMBRAWG_FEC: неизвестный режим {value:?}"))?;
        if config.fec != FecMode::Off && config.fec.config().is_none() {
            return Err(format!("UMBRAWG_FEC: недопустимые параметры {value:?}"));
        }
    }
    if let Ok(value) = env::var("UMBRAWG_FEC_SHARD") {
        config.max_shard_len = value
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|len| (MIN_MAX_SHARD_LEN..=DEFAULT_MAX_SHARD_LEN).contains(len))
            .ok_or_else(|| format!("UMBRAWG_FEC_SHARD: некорректно {value:?}"))?;
    }
    if let Ok(value) = env::var("UMBRAWG_ACK_INTERVAL") {
        config.ack_interval = value
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|interval| *interval > 0)
            .ok_or_else(|| format!("UMBRAWG_ACK_INTERVAL: некорректно {value:?}"))?;
    }
    Ok(config)
}

fn wait_for_shutdown(server: ServerHandle) -> Result<(), Box<dyn std::error::Error>> {
    while !shutdown_requested() {
        thread::sleep(Duration::from_millis(100));
    }
    server.join()?;
    Ok(())
}

fn run_parallel(
    device: Arc<Device>,
    ifname: &str,
    parallel: parallel::ParallelConfig,
    socket_buffer: usize,
    underlay: Underlay,
    guard: Arc<MtuGuard>,
    shard_cap: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let workers = parallel.workers;
    let tun_mtu = fec_tun_mtu(
        underlay,
        device.mtu(),
        device.obfuscation().s4,
        device.ext_config().fec != FecMode::Off,
    );
    let config = TunConfig::new(ifname)
        .with_multi_queue(workers > 1)
        .with_offload(true)
        .with_vnet_hdr_size(VirtioNetHdr::LEN)
        .with_nonblocking(true)
        .with_mtu(u32::from(tun_mtu));
    let tun_set = match TunSet::open(&config, workers) {
        Ok(set) => set,
        Err(TunError::Unsupported(feature)) => {
            log::warn!("tun offload is unavailable ({feature}); falling back to packet mode");
            TunSet::open(&config.clone().with_offload(false), workers)?
        }
        Err(error) => return Err(error.into()),
    };

    let listener = UapiListener::bind(&socket_dir(), ifname)?;
    let server = listener.spawn(Arc::new(ConfigControl::new(
        Arc::clone(&device),
        Arc::clone(&guard),
        ifname,
        shard_cap,
    )))?;
    let shared = Arc::new(parallel::SharedRx::new(
        workers,
        parallel.sched,
        parallel.queue_depth,
    )?);

    let rx_device = Arc::clone(&device);
    let rx_shared = Arc::clone(&shared);
    let rx_failure = Arc::clone(&shared);
    let rx_handle = thread::Builder::new()
        .name("umbrawg-rx".to_owned())
        .spawn(move || {
            if let Err(error) = parallel::rx_loop(rx_device, rx_shared, socket_buffer, underlay) {
                rx_failure.register_failure(format!("rx thread stopped: {error}"));
            }
        })?;

    let control_device = Arc::clone(&device);
    let control_shared = Arc::clone(&shared);
    let control_failure = Arc::clone(&shared);
    let control_handle = thread::Builder::new()
        .name("umbrawg-control".to_owned())
        .spawn(move || {
            if let Err(error) = parallel::control_loop(control_device, control_shared) {
                control_failure.register_failure(format!("control thread stopped: {error}"));
            }
        })?;

    let mut handles = Vec::with_capacity(workers);
    for (index, tun) in tun_set.into_queues().into_iter().enumerate() {
        let device = Arc::clone(&device);
        let worker_shared = Arc::clone(&shared);
        let worker_failure = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name(format!("umbrawg-crypto-{index}"))
            .spawn(move || {
                if let Err(error) = parallel::worker_loop(device, tun, worker_shared, index) {
                    worker_failure
                        .register_failure(format!("crypto worker {index} stopped: {error}"));
                }
            })?;
        handles.push(handle);
    }

    while !shutdown_requested() {
        let stopped = parallel::supervise(
            rx_handle.is_finished(),
            handles.iter().any(|handle| handle.is_finished()),
        )
        .or_else(|| {
            control_handle
                .is_finished()
                .then_some("control thread exited unexpectedly")
        });
        if let Some(reason) = stopped {
            shared.register_failure(reason.to_owned());
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    if shared.failure().is_none() {
        wait_for_shutdown(server)?;
    }
    if rx_handle.join().is_err() {
        shared.register_failure("rx thread panicked".to_owned());
    }
    if control_handle.join().is_err() {
        shared.register_failure("control thread panicked".to_owned());
    }
    let mut worker_panicked = false;
    for handle in handles {
        if handle.join().is_err() {
            worker_panicked = true;
        }
    }
    if worker_panicked {
        shared.register_failure("crypto worker panicked".to_owned());
    }
    if let Some(message) = shared.failure() {
        return Err(io::Error::other(message).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_batch_does_not_reuse_tun_batch_capacity() {
        let source = include_str!("lib.rs");
        let needle = concat!("TxBatch::new(", "TUN_BATCH)");
        assert!(!source.contains(needle));
        assert!(TxBatch::new(MAX_BATCH_SIZE).is_ok());
    }

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
    fn under_load_flag_defaults_to_enabled() {
        assert!(under_load_detection_enabled(None));
        assert!(under_load_detection_enabled(Some("1")));
        assert!(under_load_detection_enabled(Some("on")));
        assert!(!under_load_detection_enabled(Some("0")));
        assert!(!under_load_detection_enabled(Some("off")));
        assert!(!under_load_detection_enabled(Some("FALSE")));
    }

    #[test]
    fn under_load_threshold_uses_default_and_rejects_bad_values() {
        assert_eq!(under_load_threshold(None), DEFAULT_UNDER_LOAD_PPS);
        assert_eq!(under_load_threshold(Some("250")), 250);
        assert_eq!(under_load_threshold(Some(" 250 ")), 250);
        assert_eq!(under_load_threshold(Some("0")), DEFAULT_UNDER_LOAD_PPS);
        assert_eq!(under_load_threshold(Some("-5")), DEFAULT_UNDER_LOAD_PPS);
        assert_eq!(under_load_threshold(Some("abc")), DEFAULT_UNDER_LOAD_PPS);
    }

    #[test]
    fn shutdown_flag() {
        request_shutdown();
        assert!(shutdown_requested());
    }

    #[test]
    fn batch_flush_reserves_room_for_every_packet() {
        let record = 1676;
        let capacity = record * 128;
        assert!(!batch_flush_needed(0, 128, record, capacity));
        assert!(batch_flush_needed(0, 129, record, capacity));
        assert!(!batch_flush_needed(record * 127, 1, record, capacity));
        assert!(batch_flush_needed(record * 127 + 1, 1, record, capacity));
        assert!(batch_flush_needed(capacity, 1, record, capacity));
        assert!(batch_flush_needed(0, usize::MAX, record, capacity));
        assert!(batch_flush_needed(usize::MAX, 1, record, capacity));
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

    fn socket_buffer(fd: libc::c_int, name: libc::c_int) -> usize {
        read_socket_buffer(fd, name).expect("socket buffer is readable")
    }

    #[test]
    fn socket_buffer_defaults_to_8_mib() {
        assert_eq!(socket_buffer_bytes(None), Ok(SOCKET_BUFFER_BYTES));
        assert_eq!(SOCKET_BUFFER_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn rebind_tracks_port_epoch_and_extra_count() {
        let limits = Underlay::new(1500, 1).unwrap().gso_limits();
        let first = open_socket(0, 0, SOCKET_BUFFER_BYTES, limits).expect("first socket");
        let second = open_socket(0, 0, SOCKET_BUFFER_BYTES, limits).expect("second socket");
        let port = first.local_addr().port();
        let set = SocketSet::new(vec![first, second]).expect("socket set");

        assert!(rebind_needed(None, None, 0, None, None, 0, 1, 1500));
        assert!(!rebind_needed(
            Some(&set),
            Some(0),
            0,
            Some(1),
            Some(1500),
            0,
            1,
            1500
        ));
        assert!(!rebind_needed(
            Some(&set),
            Some(0),
            0,
            Some(1),
            Some(1500),
            port,
            1,
            1500
        ));
        assert!(rebind_needed(
            Some(&set),
            Some(0),
            0,
            Some(1),
            Some(1500),
            0,
            2,
            1500
        ));
        assert!(rebind_needed(
            Some(&set),
            Some(0),
            0,
            None,
            Some(1500),
            0,
            1,
            1500
        ));
        // A repeated `listen-port 0` bumps the epoch even though the value
        // stayed zero: the sockets must be rebound to a new ephemeral port.
        assert!(rebind_needed(
            Some(&set),
            Some(0),
            1,
            Some(1),
            Some(1500),
            0,
            1,
            1500
        ));
        // A runtime `underlay-mtu` change invalidates the GSO limits baked
        // into the sockets, so they must be recreated without a restart.
        assert!(rebind_needed(
            Some(&set),
            Some(0),
            0,
            Some(1),
            Some(1500),
            0,
            1,
            9000
        ));
        let other_port = if port == 1 { 2 } else { 1 };
        assert!(rebind_needed(
            Some(&set),
            Some(0),
            0,
            Some(1),
            Some(1500),
            other_port,
            1,
            1500
        ));
    }

    #[test]
    fn runtime_underlay_updates_the_gso_budget() {
        let device = Device::new(DeviceConfig::default()).expect("device");
        let base = Underlay::new(1500, 64).expect("underlay");
        assert_eq!(runtime_underlay(base, &device).max_segment(), 1472);

        device.set_underlay_mtu(9000).expect("underlay");
        let raised = runtime_underlay(base, &device);
        assert_eq!(raised.max_segment(), 8972);
        assert_eq!(raised.segments(), base.segments());

        device.set_underlay_mtu(1280).expect("underlay");
        assert_eq!(runtime_underlay(base, &device).max_segment(), 1252);
    }

    #[test]
    fn recreated_sockets_use_the_raised_gso_limits() {
        let base = Underlay::new(1500, 64).expect("underlay");
        let before = open_socket(0, 0, SOCKET_BUFFER_BYTES, base.gso_limits())
            .expect("1500-byte underlay socket");
        let raised = base.with_mtu(9000).expect("underlay");
        let after = open_socket(0, 0, SOCKET_BUFFER_BYTES, raised.gso_limits())
            .expect("9000-byte underlay socket");
        // A 1600-byte segment cannot be coalesced on the 1500-byte underlay
        // but fits once the runtime MTU is raised: this is exactly the GSO
        // decision made by `append_group`.
        let before_limits = tx::SegmentLimits::from_socket(&before);
        let after_limits = tx::SegmentLimits::from_socket(&after);
        assert!(
            before_limits.max_gso_size < 1600,
            "{}",
            before_limits.max_gso_size
        );
        assert!(
            after_limits.max_gso_size >= 1600,
            "{}",
            after_limits.max_gso_size
        );
        assert!(
            after_limits.max_gso_size > before_limits.max_gso_size,
            "{} -> {}",
            before_limits.max_gso_size,
            after_limits.max_gso_size
        );
    }

    #[test]
    fn rebind_port_keeps_an_established_ephemeral_port() {
        // A GSO/underlay rebind must not change the port peers already know.
        assert_eq!(rebind_port(0, Some(0), 0, Some(51820)), 51820);
        // A fresh `listen-port 0` request asks for a new ephemeral port.
        assert_eq!(rebind_port(0, Some(0), 1, Some(51820)), 0);
        // No current socket yet.
        assert_eq!(rebind_port(0, Some(0), 0, None), 0);
        // A fixed port always wins over the current one.
        assert_eq!(rebind_port(51821, Some(0), 0, Some(51820)), 51821);
    }

    #[test]
    fn configured_peer_deadline_reaches_the_poll_loop() {
        use umbrawg_crypto::{Key, PublicKey};
        use umbrawg_device::PeerConfig;

        let device = Device::new(DeviceConfig {
            private_key: Some(Key::from_bytes([0x55; 32])),
            ..DeviceConfig::default()
        })
        .expect("device");
        let mut config = PeerConfig::new(PublicKey::from_bytes([0x66; 32]));
        config.endpoint = Some("198.51.100.7:51820".parse().expect("endpoint"));
        device.add_peer(config).expect("peer");

        let now = Instant::now();
        let deadline = device
            .next_deadline()
            .expect("a restarted peer must want a handshake/revoke deadline");
        assert!(deadline <= now, "{deadline:?}");
        assert_eq!(poll_timeout_ms(now, Some(deadline)), 1);
        assert_eq!(earliest_deadline(Some(deadline), None), Some(deadline));
    }

    #[test]
    fn poll_timeout_follows_the_nearest_deadline() {
        let now = Instant::now();
        assert_eq!(poll_timeout_ms(now, None), IDLE_TIMEOUT_MS);
        assert_eq!(poll_timeout_ms(now, Some(now)), 1);
        assert_eq!(
            poll_timeout_ms(now, Some(now + Duration::from_micros(500))),
            1
        );
        assert_eq!(
            poll_timeout_ms(now, Some(now + Duration::from_millis(2))),
            2
        );
        assert_eq!(
            poll_timeout_ms(now, Some(now + Duration::from_millis(5))),
            5
        );
        assert_eq!(
            poll_timeout_ms(now, Some(now + Duration::from_secs(1))),
            IDLE_TIMEOUT_MS
        );
        assert_eq!(
            earliest_deadline(
                Some(now + Duration::from_millis(9)),
                Some(now + Duration::from_millis(1))
            ),
            Some(now + Duration::from_millis(1))
        );
        assert_eq!(earliest_deadline(None, Some(now)), Some(now));
        assert_eq!(earliest_deadline(Some(now), None), Some(now));
        assert_eq!(earliest_deadline(None, None), None);
    }

    #[test]
    fn socket_set_sends_over_all_sockets() {
        let limits = Underlay::new(1500, 1).unwrap().gso_limits();
        let first = open_socket(0, 0, SOCKET_BUFFER_BYTES, limits).expect("first socket");
        let second = open_socket(0, 0, SOCKET_BUFFER_BYTES, limits).expect("second socket");
        let first_port = first.local_addr().port();
        let second_port = second.local_addr().port();
        let set = SocketSet::new(vec![first, second]).expect("socket set");
        assert_eq!(set.len(), 2);
        assert_eq!(set.primary().local_addr().port(), first_port);
        let ports: Vec<u16> = (0..4).map(|_| set.next().local_addr().port()).collect();
        assert_eq!(
            ports,
            vec![first_port, second_port, first_port, second_port]
        );
    }

    #[test]
    fn socket_buffer_parses_valid_values_and_boundaries() {
        assert_eq!(socket_buffer_bytes(Some("8388608")), Ok(8 * 1024 * 1024));
        assert_eq!(
            socket_buffer_bytes(Some(" 217088 ")),
            Ok(SOCKET_BUFFER_MIN_BYTES)
        );
        assert_eq!(
            socket_buffer_bytes(Some("67108864")),
            Ok(SOCKET_BUFFER_MAX_BYTES)
        );
    }

    #[test]
    fn socket_buffer_rejects_invalid_values() {
        for value in [
            "",
            " ",
            "abc",
            "-1",
            "4MiB",
            "217087",
            "67108865",
            "999999999999999999999999",
        ] {
            let error = socket_buffer_bytes(Some(value)).expect_err(value);
            assert!(error.contains("UMBRAWG_SOCKET_BUFFER"), "{value}: {error}");
        }
    }

    #[test]
    fn buffer_shortfall_detects_kernel_clamp() {
        let requested = SOCKET_BUFFER_BYTES;
        assert_eq!(socket_buffer_shortfall(requested, requested * 2), None);
        assert_eq!(socket_buffer_shortfall(requested, 425_984), Some(212_992));
        assert_eq!(socket_buffer_shortfall(requested, 0), Some(0));
    }

    #[test]
    fn buffer_shortfall_allows_rounding_tolerance() {
        let requested = SOCKET_BUFFER_BYTES;
        let within = (requested - SOCKET_BUFFER_TOLERANCE_BYTES) * 2;
        assert_eq!(socket_buffer_shortfall(requested, within), None);
        let below = (requested - SOCKET_BUFFER_TOLERANCE_BYTES - 1) * 2;
        assert_eq!(
            socket_buffer_shortfall(requested, below),
            Some(requested - SOCKET_BUFFER_TOLERANCE_BYTES - 1)
        );
    }

    #[test]
    fn gso_limits_cover_obfuscated_segments() {
        let limits = Underlay::new(9000, mtu::DEFAULT_GSO_SEGMENTS)
            .unwrap()
            .gso_limits();
        assert_eq!(limits.max_segments(), mtu::DEFAULT_GSO_SEGMENTS);
        assert!(limits.max_gso_size() >= 1480);
        assert!(limits.max_gso_size() >= 1420 + 28 + 16 + 16);
    }

    #[test]
    fn gso_limits_leave_ether_underlay_plain() {
        let limits = Underlay::new(1500, mtu::DEFAULT_GSO_SEGMENTS)
            .unwrap()
            .gso_limits();
        assert_eq!(limits.max_gso_size(), 1472);
        assert!(limits.max_gso_size() < 1420 + 32 + 60);
    }

    #[test]
    fn open_socket_applies_gso_limits() {
        let limits = Underlay::new(9000, mtu::DEFAULT_GSO_SEGMENTS)
            .unwrap()
            .gso_limits();
        let socket = open_socket(0, 0, SOCKET_BUFFER_BYTES, limits).expect("socket is bound");
        assert_eq!(socket.gso_limits(), limits);
        assert!(socket.max_gso_size() >= 1480);
    }

    #[test]
    fn open_socket_requests_large_buffers() {
        let requested = 8 * 1024 * 1024;
        let limits = Underlay::new(1500, mtu::DEFAULT_GSO_SEGMENTS)
            .unwrap()
            .gso_limits();
        let socket = open_socket(0, 0, requested, limits).expect("socket is bound");
        let fd = socket.fd();
        let receive = socket_buffer(fd, libc::SO_RCVBUF);
        let send = socket_buffer(fd, libc::SO_SNDBUF);
        assert!(receive > 0);
        assert!(send > 0);
        assert!(effective_socket_buffer(receive) <= requested);
        assert!(effective_socket_buffer(send) <= requested);
    }

    #[test]
    fn open_socket_survives_small_kernel_limits() {
        let requested = SOCKET_BUFFER_MAX_BYTES;
        let limits = Underlay::new(1500, mtu::DEFAULT_GSO_SEGMENTS)
            .unwrap()
            .gso_limits();
        let socket = open_socket(0, 0, requested, limits).expect("socket is bound");
        let receive = effective_socket_buffer(socket_buffer(socket.fd(), libc::SO_RCVBUF));
        let send = effective_socket_buffer(socket_buffer(socket.fd(), libc::SO_SNDBUF));
        assert!(receive > 0);
        assert!(send > 0);
        assert!(receive <= requested);
        assert!(send <= requested);
    }
}
