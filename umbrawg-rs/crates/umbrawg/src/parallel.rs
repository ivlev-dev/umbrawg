//! Параллельный приём пакетов.
//!
//! Схема: один поток приёма делает `recvmmsg`, классификацию сообщения и поиск
//! сессии, после чего раскладывает сегменты по ограниченным SPSC-очередям
//! крипто-воркеров. Воркеры выполняют `keypair.open`, проверку повтора,
//! обработку таймеров и запись в собственную очередь TUN (с GSO-склейкой).
//!
//! Порядок пакетов между разными воркерами не гарантируется; внутри одной
//! дейтаграммы (в том числе GRO-суперпакета) порядок сохраняется, а отброшенный
//! сегмент не переставляет соседние.

use std::cell::UnsafeCell;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use umbrawg_crypto::random::BufferedRng;
use umbrawg_device::{
    DatagramSink, Device, IncomingOutcome, IoContext, PacketIo, Peer, PreparedIncoming,
    PreparedTransport,
};
use umbrawg_transport::{RecvQueue, Socket};
use umbrawg_tun::Tun;

use crate::ring::SpscRing;
use crate::rx::RxBatch;
use crate::tx::TxBatch;
use crate::{
    is_socket_would_block, open_socket, pump_tun_tx, shutdown_requested, IDLE_TIMEOUT_MS,
    MAX_PACKET, RECV_BATCH, TUN_BATCH, TUN_PACKET_MARGIN,
};

/// Максимальное число сегментов в одном задании.
pub(crate) const MAX_SEGMENTS: usize = 64;

/// Ёмкость очереди заданий и пула буферов на одного воркера.
const QUEUE_CAPACITY: usize = 64;

/// Верхняя граница числа крипто-воркеров: 8 потоков по 4 МиБ буферов.
const MAX_WORKERS: usize = 8;

/// Период вывода счётчиков при `UMBRAWG_RX_STATS=1`.
const STATS_INTERVAL: Duration = Duration::from_secs(5);

/// Настройки параллельного приёма.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParallelConfig {
    /// Число крипто-воркеров (потоков расшифровки и записи в TUN).
    pub workers: usize,
}

impl ParallelConfig {
    /// Читает конфигурацию из окружения. `None` означает обычный режим.
    pub fn from_env(available: usize) -> Option<Self> {
        let enabled = parallel_rx_enabled(std::env::var("UMBRAWG_PARALLEL_RX").ok().as_deref());
        if !enabled {
            return None;
        }
        let requested = std::env::var("UMBRAWG_RX_WORKERS").ok();
        Some(Self {
            workers: crypto_worker_count(requested.as_deref(), available),
        })
    }
}

/// Возвращает `true`, если параллельный приём включён значением переменной.
pub(crate) fn parallel_rx_enabled(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("1" | "true" | "yes" | "on" | "TRUE" | "YES" | "ON")
    )
}

/// Определяет число крипто-воркеров.
///
/// По умолчанию половина доступных ядер, но не больше четырёх: одно ядро
/// остаётся потоку приёма, остальные — сетевому стеку, UAPI и прочей работе.
pub(crate) fn crypto_worker_count(requested: Option<&str>, available: usize) -> usize {
    let available = available.clamp(1, MAX_WORKERS);
    let default = (available / 2).clamp(1, 4);
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

/// Счётчики потока приёма. Все поля — обычные атомики без блокировок.
#[derive(Default)]
pub(crate) struct RxStats {
    /// Принятых дейтаграмм.
    pub datagrams: AtomicU64,
    /// Сегментов, переданных воркерам.
    pub enqueued: AtomicU64,
    /// Управляющих пакетов, обработанных потоком приёма.
    pub controls: AtomicU64,
    /// Отброшено на классификации или поиске сессии.
    pub drops_detect: AtomicU64,
    /// Отброшено из-за переполнения очереди воркера.
    pub drops_queue: AtomicU64,
    /// Отброшено из-за слишком большого пакета или числа сегментов.
    pub drops_size: AtomicU64,
    /// Разбуженных воркеров.
    pub wakes: AtomicU64,
}

/// Задание воркеру: одна дейтаграмма с подготовленными сегментами.
pub(crate) struct Job {
    /// Индекс буфера в пуле воркера.
    pub slot: u32,
    /// Длина дейтаграммы в буфере.
    pub len: u32,
    /// Адрес отправителя.
    pub source: SocketAddr,
    /// Размер сегмента GRO, если дейтаграмма пришла суперпакетом.
    pub gro_size: Option<u32>,
    /// Подготовленные сегменты по порядковым номерам внутри дейтаграммы.
    pub prepared: [Option<PreparedTransport>; MAX_SEGMENTS],
}

struct BufferSlots {
    slots: Box<[UnsafeCell<Vec<u8>>]>,
    slot_len: usize,
}

// Безопасность: буфером владеет либо поток приёма (после `allocate`), либо
// воркер (после `pop`); владение передаётся через SPSC-очереди.
unsafe impl Sync for BufferSlots {}

impl BufferSlots {
    fn new(count: usize, slot_len: usize) -> Self {
        let slots = (0..count)
            .map(|_| UnsafeCell::new(vec![0u8; slot_len]))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { slots, slot_len }
    }

    fn write(&self, slot: u32, data: &[u8]) -> bool {
        if data.len() > self.slot_len {
            return false;
        }
        let buffer = unsafe { &mut *self.slots[slot as usize].get() };
        buffer[..data.len()].copy_from_slice(data);
        true
    }

    /// Возвращает буфер слота, которым в этот момент владеет воркер.
    #[allow(clippy::mut_from_ref)]
    fn get(&self, slot: u32) -> &mut [u8] {
        unsafe { &mut *self.slots[slot as usize].get() }
    }
}

struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    fn new() -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn notify(&self) {
        let value = 1u64.to_ne_bytes();
        let result = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                value.as_ptr().cast(),
                value.len() as libc::size_t,
            )
        };
        if result < 0 {
            log::trace!("eventfd write failed: {}", io::Error::last_os_error());
        }
    }

    fn drain(&self) {
        let mut value = [0u8; 8];
        let result = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                value.as_mut_ptr().cast(),
                value.len() as libc::size_t,
            )
        };
        if result < 0 {
            log::trace!("eventfd read failed: {}", io::Error::last_os_error());
        }
    }

    fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Очередь заданий и пул буферов одного воркера.
pub(crate) struct WorkerChannel {
    jobs: SpscRing<Job>,
    free: SpscRing<u32>,
    buffers: BufferSlots,
    event: EventFd,
    sleeping: AtomicBool,
}

impl WorkerChannel {
    fn new(slot_len: usize) -> io::Result<Self> {
        let free = SpscRing::new(QUEUE_CAPACITY);
        for slot in 0..QUEUE_CAPACITY as u32 {
            if free.push(slot).is_err() {
                return Err(io::Error::other("cannot seed buffer pool"));
            }
        }
        Ok(Self {
            jobs: SpscRing::new(QUEUE_CAPACITY),
            free,
            buffers: BufferSlots::new(QUEUE_CAPACITY, slot_len),
            event: EventFd::new()?,
            sleeping: AtomicBool::new(false),
        })
    }

    fn allocate(&self) -> Option<u32> {
        self.free.pop()
    }

    fn release(&self, slot: u32) {
        let _ = self.free.push(slot);
    }

    fn write(&self, slot: u32, data: &[u8]) -> bool {
        self.buffers.write(slot, data)
    }

    fn buffers(&self) -> &BufferSlots {
        &self.buffers
    }

    /// Публикует задание и будит воркер.
    ///
    /// Возвращает пару «опубликовано, разбужен». При переполнении буфер
    /// возвращается в пул, а задание отбрасывается вызывающим.
    fn publish(&self, job: Job) -> (bool, bool) {
        match self.jobs.push(job) {
            Ok(()) => {
                let woke = self.sleeping.swap(false, Ordering::AcqRel);
                if woke {
                    self.event.notify();
                }
                (true, woke)
            }
            Err(job) => {
                self.release(job.slot);
                (false, false)
            }
        }
    }

    fn pop(&self) -> Option<Job> {
        self.jobs.pop()
    }

    fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    fn wait(&self, tun_fd: RawFd) {
        self.sleeping.store(true, Ordering::SeqCst);
        if !self.jobs.is_empty() {
            self.sleeping.store(false, Ordering::SeqCst);
            return;
        }
        let mut fds = [
            libc::pollfd {
                fd: tun_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.event.fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        unsafe {
            libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, IDLE_TIMEOUT_MS);
        }
        self.sleeping.store(false, Ordering::SeqCst);
        if fds[1].revents != 0 {
            self.event.drain();
        }
    }
}

/// Общее состояние потока приёма и крипто-воркеров.
pub(crate) struct SharedRx {
    socket: RwLock<Option<Arc<Socket>>>,
    channels: Vec<WorkerChannel>,
    stats: RxStats,
}

impl SharedRx {
    pub fn new(workers: usize) -> io::Result<Self> {
        let mut channels = Vec::with_capacity(workers);
        for _ in 0..workers {
            channels.push(WorkerChannel::new(MAX_PACKET)?);
        }
        Ok(Self {
            socket: RwLock::new(None),
            channels,
            stats: RxStats::default(),
        })
    }

    fn set_socket(&self, socket: Option<Arc<Socket>>) {
        if let Ok(mut guard) = self.socket.write() {
            *guard = socket;
        }
    }

    fn socket(&self) -> Option<Arc<Socket>> {
        self.socket.read().ok().and_then(|guard| guard.clone())
    }
}

struct ControlIo<'a> {
    socket: &'a Socket,
}

impl DatagramSink for ControlIo<'_> {
    fn send_datagram(
        &mut self,
        endpoint: SocketAddr,
        _peer: Option<&Peer>,
        payload: &[u8],
        gso_size: Option<usize>,
    ) {
        let gso = gso_size.and_then(|size| umbrawg_transport::GsoSize::from_usize(size).ok());
        if let Err(error) =
            self.socket
                .send_to(umbrawg_transport::Endpoint::new(endpoint), payload, gso)
        {
            log::debug!("control send to {endpoint} failed: {error}");
        }
    }
}

impl PacketIo for ControlIo<'_> {
    fn deliver(&mut self, _peer: &Peer, _packet: &[u8]) {
        log::debug!("control packet delivery is ignored");
    }
}

/// Поток приёма: `recvmmsg`, классификация, раскладка по воркерам.
pub(crate) fn rx_loop(device: Arc<Device>, shared: Arc<SharedRx>) -> io::Result<()> {
    let mut rng = BufferedRng::new(OsRng);
    let mut scratch = vec![0u8; MAX_PACKET + 512];
    let mut recv_queue =
        RecvQueue::new(RECV_BATCH).map_err(|error| io::Error::other(error.to_string()))?;
    let mut recv_buffers: Vec<Vec<u8>> = (0..RECV_BATCH).map(|_| vec![0u8; MAX_PACKET]).collect();
    let mut recv_slices: Vec<&mut [u8]> = recv_buffers
        .iter_mut()
        .map(|buffer| buffer.as_mut_slice())
        .collect();
    let mut socket: Option<Arc<Socket>> = None;
    let mut cursor = 0usize;
    let mut stats_at = Instant::now();
    let stats_enabled = std::env::var("UMBRAWG_RX_STATS").is_ok_and(|value| value.trim() == "1");

    while !shutdown_requested() {
        let want_port = device.listen_port();
        let rebind = match socket.as_ref() {
            None => true,
            Some(current) => want_port != 0 && current.local_addr().port() != want_port,
        };
        if rebind {
            match open_socket(want_port, device.fwmark()) {
                Ok(new_socket) => {
                    log::info!("parallel rx listening on {}", new_socket.local_addr());
                    let new_socket = Arc::new(new_socket);
                    shared.set_socket(Some(Arc::clone(&new_socket)));
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
            match active.recv_batch(&mut recv_queue, &mut recv_slices) {
                Ok(0) => break,
                Ok(count) => {
                    busy = true;
                    let snapshot = device.incoming_snapshot();
                    let now = Instant::now();
                    for (index, buffer) in recv_slices.iter_mut().enumerate().take(count) {
                        let Some(meta) = recv_queue.meta(index) else {
                            continue;
                        };
                        let Some(endpoint) = meta.endpoint else {
                            continue;
                        };
                        if meta.truncated || meta.size == 0 {
                            shared.stats.drops_detect.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        shared.stats.datagrams.fetch_add(1, Ordering::Relaxed);
                        enqueue_segments(
                            &device,
                            &shared,
                            &mut cursor,
                            &snapshot,
                            now,
                            &mut rng,
                            &mut scratch,
                            active,
                            buffer,
                            meta.size,
                            meta.gro_size.map(|size| size.as_usize()),
                            endpoint.dst(),
                        );
                    }
                }
                Err(error) if is_socket_would_block(&error) => break,
                Err(error) => {
                    log::debug!("recv failed: {error}");
                    break;
                }
            }
        }

        if stats_enabled && stats_at.elapsed() >= STATS_INTERVAL {
            stats_at = Instant::now();
            log::info!(
                "rx stats: datagrams={} enqueued={} controls={} drops(detect={} queue={} size={}) wakes={}",
                shared.stats.datagrams.load(Ordering::Relaxed),
                shared.stats.enqueued.load(Ordering::Relaxed),
                shared.stats.controls.load(Ordering::Relaxed),
                shared.stats.drops_detect.load(Ordering::Relaxed),
                shared.stats.drops_queue.load(Ordering::Relaxed),
                shared.stats.drops_size.load(Ordering::Relaxed),
                shared.stats.wakes.load(Ordering::Relaxed),
            );
        }

        if !busy {
            let mut fds = [libc::pollfd {
                fd: active.fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            unsafe {
                libc::poll(fds.as_mut_ptr(), 1, IDLE_TIMEOUT_MS);
            }
        }
    }

    shared.set_socket(None);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn enqueue_segments(
    device: &Device,
    shared: &SharedRx,
    cursor: &mut usize,
    snapshot: &umbrawg_device::IncomingSnapshot,
    now: Instant,
    rng: &mut BufferedRng<OsRng>,
    scratch: &mut [u8],
    socket: &Socket,
    data: &mut [u8],
    len: usize,
    gro_size: Option<usize>,
    source: SocketAddr,
) {
    if gro_size.is_some_and(|size| size == 0 || size > len) {
        shared.stats.drops_detect.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut prepared: [Option<PreparedTransport>; MAX_SEGMENTS] = [const { None }; MAX_SEGMENTS];
    let mut ordinal = 0usize;
    let mut offset = 0usize;
    loop {
        if offset >= len {
            break;
        }
        if ordinal == MAX_SEGMENTS {
            shared.stats.drops_size.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let end = gro_size.map_or(len, |size| (offset + size).min(len));
        if end <= offset {
            break;
        }
        let segment = &mut data[offset..end];
        match device.prepare_incoming(segment, snapshot, now) {
            PreparedIncoming::Transport(entry) => {
                prepared[ordinal] = Some(entry);
            }
            PreparedIncoming::Control(detected) => {
                shared.stats.controls.fetch_add(1, Ordering::Relaxed);
                let mut control = ControlIo { socket };
                let mut context = IoContext::new(rng, now, scratch, &mut control);
                if let Err(error) = device.handle_prepared(
                    segment,
                    PreparedIncoming::Control(detected),
                    source,
                    snapshot,
                    &mut context,
                ) {
                    log::debug!("control packet failed: {error}");
                }
            }
            PreparedIncoming::Dropped => {
                shared.stats.drops_detect.fetch_add(1, Ordering::Relaxed);
            }
        }
        ordinal += 1;
        offset = end;
        if gro_size.is_none() {
            break;
        }
    }
    if ordinal == 0 {
        return;
    }
    let channels = shared.channels.len();
    let start = *cursor % channels;
    *cursor = cursor.wrapping_add(1);
    let mut target = start;
    let mut slot = None;
    for attempt in 0..channels {
        let candidate = (start + attempt) % channels;
        if let Some(free) = shared.channels[candidate].allocate() {
            target = candidate;
            slot = Some(free);
            break;
        }
    }
    let Some(slot) = slot else {
        shared.stats.drops_queue.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let channel = &shared.channels[target];
    if !channel.write(slot, &data[..len]) {
        channel.release(slot);
        shared.stats.drops_size.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let job = Job {
        slot,
        len: len as u32,
        source,
        gro_size: gro_size.map(|size| size as u32),
        prepared,
    };
    let (published, woke) = channel.publish(job);
    if woke {
        shared.stats.wakes.fetch_add(1, Ordering::Relaxed);
    }
    if !published {
        shared.stats.drops_queue.fetch_add(1, Ordering::Relaxed);
        return;
    }
    shared.stats.enqueued.fetch_add(1, Ordering::Relaxed);
}

#[allow(clippy::too_many_arguments)]
fn execute_job<R: RngCore>(
    device: &Device,
    channel: &WorkerChannel,
    job: &mut Job,
    snapshot: &umbrawg_device::IncomingSnapshot,
    now: Instant,
    rng: &mut R,
    scratch: &mut [u8],
    socket: &Socket,
    tun: &Tun,
    rx: &mut RxBatch,
) {
    let len = job.len as usize;
    let gro_size = job.gro_size.map(|size| size as usize);
    let data = channel.buffers().get(job.slot);
    let mut offset = 0usize;
    let mut ordinal = 0usize;
    while offset < len && ordinal < MAX_SEGMENTS {
        let end = gro_size.map_or(len, |size| (offset + size).min(len));
        if end <= offset {
            break;
        }
        if let Some(prepared) = job.prepared[ordinal].take() {
            let mut io = crate::WorkerIo { socket, tun, rx };
            let mut context = IoContext::new(rng, now, scratch, &mut io);
            match device.handle_prepared(
                &mut data[offset..end],
                PreparedIncoming::Transport(prepared),
                job.source,
                snapshot,
                &mut context,
            ) {
                Ok(IncomingOutcome::Delivered(_)) => {}
                Ok(_) => {}
                Err(error) => log::debug!("prepared packet failed: {error}"),
            }
        }
        offset = end;
        ordinal += 1;
    }
}

/// Крипто-воркер: расшифровка заданий, запись в TUN и передача из TUN.
pub(crate) fn worker_loop(
    device: Arc<Device>,
    mut tun: Tun,
    shared: Arc<SharedRx>,
    index: usize,
) -> io::Result<()> {
    let mut rng = BufferedRng::new(OsRng);
    let mut scratch = vec![0u8; MAX_PACKET + 512];
    let mut tx_buffer = vec![0u8; MAX_PACKET + 512];
    let slot = tun.mtu() as usize + TUN_PACKET_MARGIN;
    let mut tun_bufs: Vec<Vec<u8>> = (0..TUN_BATCH).map(|_| vec![0u8; slot]).collect();
    let mut tun_slices: Vec<&mut [u8]> = tun_bufs
        .iter_mut()
        .map(|buffer| buffer.as_mut_slice())
        .collect();
    let mut tun_sizes = [0usize; TUN_BATCH];
    let mut batch_buffer = vec![0u8; TUN_BATCH * slot];
    let mut batch = TxBatch::new(TUN_BATCH).map_err(|error| io::Error::other(error.to_string()))?;
    let mut rx = RxBatch::new(slot);
    let mut rekey: Vec<Arc<Peer>> = Vec::with_capacity(TUN_BATCH);
    let channel = &shared.channels[index];

    loop {
        if shutdown_requested() && channel.is_empty() {
            break;
        }
        let now = Instant::now();
        let socket = shared.socket();
        let mut busy = false;

        if let Some(active) = socket.as_deref() {
            rekey.clear();
            busy |= pump_tun_tx(
                &device,
                active,
                &mut tun,
                &mut rng,
                now,
                &mut scratch,
                &mut tx_buffer,
                &mut batch_buffer,
                &mut batch,
                &mut rx,
                &mut tun_slices,
                &mut tun_sizes,
                &mut rekey,
            );

            if !batch.is_empty() {
                batch.flush(active, &batch_buffer);
            }
            for peer in &rekey {
                let mut io = crate::WorkerIo {
                    socket: active,
                    tun: &tun,
                    rx: &mut rx,
                };
                let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut io);
                if let Err(error) = device.after_batch_sent(peer, &mut context) {
                    log::debug!("send timers failed: {error}");
                }
            }

            let snapshot = device.incoming_snapshot();
            loop {
                let Some(mut job) = channel.pop() else {
                    break;
                };
                busy = true;
                execute_job(
                    &device,
                    channel,
                    &mut job,
                    &snapshot,
                    now,
                    &mut rng,
                    &mut scratch,
                    active,
                    &tun,
                    &mut rx,
                );
                channel.release(job.slot);
            }
            rx.flush(&tun);
        }

        let mut staged_error = None;
        if let Some(active) = socket.as_deref() {
            device.for_each_peer(|peer| {
                let mut io = crate::WorkerIo {
                    socket: active,
                    tun: &tun,
                    rx: &mut rx,
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
                let mut io = crate::WorkerIo {
                    socket: active,
                    tun: &tun,
                    rx: &mut rx,
                };
                let started = Instant::now();
                let mut context = IoContext::new(&mut rng, started, &mut scratch, &mut io);
                if let Err(error) = device.tick(&mut context) {
                    log::debug!("timer tick failed: {error}");
                }
            }
        }

        if !busy {
            channel.wait(tun.fd());
        }
    }

    rx.flush(&tun);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_parallel_flag() {
        assert!(parallel_rx_enabled(Some("1")));
        assert!(parallel_rx_enabled(Some(" true ")));
        assert!(parallel_rx_enabled(Some("on")));
        assert!(!parallel_rx_enabled(Some("0")));
        assert!(!parallel_rx_enabled(Some("")));
        assert!(!parallel_rx_enabled(None));
    }

    #[test]
    fn worker_count_defaults_to_half_the_cores() {
        assert_eq!(crypto_worker_count(None, 6), 3);
        assert_eq!(crypto_worker_count(None, 12), 4);
        assert_eq!(crypto_worker_count(None, 2), 1);
        assert_eq!(crypto_worker_count(None, 1), 1);
    }

    #[test]
    fn worker_count_honours_override() {
        assert_eq!(crypto_worker_count(Some("2"), 6), 2);
        assert_eq!(crypto_worker_count(Some("0"), 6), 3);
        assert_eq!(crypto_worker_count(Some("99"), 6), 6);
        assert_eq!(crypto_worker_count(Some("99"), 64), MAX_WORKERS);
        assert_eq!(crypto_worker_count(Some("abc"), 6), 3);
    }

    fn job(slot: u32) -> Job {
        Job {
            slot,
            len: 0,
            source: "10.0.0.1:1000".parse().unwrap(),
            gro_size: None,
            prepared: [const { None }; MAX_SEGMENTS],
        }
    }

    #[test]
    fn channel_transfers_jobs_and_buffers() {
        let channel = WorkerChannel::new(128).unwrap();
        let slot = channel.allocate().unwrap();
        assert!(channel.write(slot, &[1, 2, 3]));
        assert!(channel.publish(job(slot)).0);
        let received = channel.pop().unwrap();
        assert_eq!(received.slot, slot);
        channel.release(received.slot);
        assert!(channel.allocate().is_some());
    }

    #[test]
    fn channel_reports_overflow_and_keeps_buffers() {
        let channel = WorkerChannel::new(128).unwrap();
        let mut published = 0;
        while let Some(slot) = channel.allocate() {
            if !channel.publish(job(slot)).0 {
                break;
            }
            published += 1;
        }
        assert_eq!(published, QUEUE_CAPACITY);
        assert!(channel.allocate().is_none());
        let received = channel.pop().unwrap();
        channel.release(received.slot);
        assert!(channel.allocate().is_some());
    }

    #[test]
    fn channel_distributes_jobs_across_workers() {
        let shared = SharedRx::new(3).unwrap();
        let mut cursor = 0usize;
        let mut counts = [0usize; 3];
        for _ in 0..30 {
            let worker = cursor % shared.channels.len();
            cursor = cursor.wrapping_add(1);
            counts[worker] += 1;
        }
        assert_eq!(counts, [10, 10, 10]);
    }

    #[test]
    fn shared_channels_survive_concurrent_shutdown() {
        let shared = Arc::new(SharedRx::new(2).unwrap());
        let producers: Vec<_> = (0..2)
            .map(|worker| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let channel = &shared.channels[worker];
                    let mut round = 0u32;
                    while round < 10_000 {
                        let Some(slot) = channel.allocate() else {
                            std::hint::spin_loop();
                            continue;
                        };
                        channel.write(slot, &round.to_le_bytes());
                        assert!(channel.publish(job(slot)).0);
                        round += 1;
                    }
                })
            })
            .collect();
        let consumers: Vec<_> = (0..2)
            .map(|worker| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let channel = &shared.channels[worker];
                    let mut received = 0u32;
                    while received < 10_000 {
                        if let Some(job) = channel.pop() {
                            channel.release(job.slot);
                            received += 1;
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                    received
                })
            })
            .collect();
        for producer in producers {
            producer.join().unwrap();
        }
        for consumer in consumers {
            assert_eq!(consumer.join().unwrap(), 10_000);
        }
    }

    #[test]
    fn waiting_worker_wakes_up_and_exits() {
        use std::sync::atomic::AtomicBool;

        let channel = Arc::new(WorkerChannel::new(64).unwrap());
        let idle = EventFd::new().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let consumer = {
            let channel = Arc::clone(&channel);
            let stop = Arc::clone(&stop);
            let idle_fd = idle.fd();
            std::thread::spawn(move || {
                let mut received = 0u32;
                while !stop.load(Ordering::Acquire) {
                    if let Some(job) = channel.pop() {
                        channel.release(job.slot);
                        received += 1;
                    } else {
                        channel.wait(idle_fd);
                    }
                }
                while let Some(job) = channel.pop() {
                    channel.release(job.slot);
                    received += 1;
                }
                received
            })
        };

        for _ in 0..100 {
            let mut slot = None;
            for _ in 0..10_000 {
                if let Some(free) = channel.allocate() {
                    slot = Some(free);
                    break;
                }
                std::hint::spin_loop();
            }
            let slot = slot.expect("buffer is available");
            let (published, _) = channel.publish(job(slot));
            assert!(published);
        }
        stop.store(true, Ordering::Release);
        assert_eq!(consumer.join().unwrap(), 100);
    }

    #[test]
    fn oversized_datagram_is_rejected() {
        let channel = WorkerChannel::new(16).unwrap();
        let slot = channel.allocate().unwrap();
        assert!(!channel.write(slot, &[0u8; 17]));
        assert!(channel.write(slot, &[0u8; 16]));
        channel.release(slot);
    }
}
