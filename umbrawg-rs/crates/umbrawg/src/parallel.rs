//! Параллельный приём пакетов.
//!
//! Схема: один поток приёма делает `recvmmsg`, классификацию сообщения и поиск
//! сессии, после чего раскладывает сегменты по ограниченным SPSC-очередям
//! крипто-воркеров. Воркеры выполняют `keypair.open`, проверку повтора,
//! обработку таймеров и запись в собственную очередь TUN (с GSO-склейкой).
//!
//! По умолчанию воркер выбирается по пиру (`UMBRAWG_RX_SCHED=peer`): все
//! транспортные сегменты одного пира попадают в один воркер, поэтому порядок
//! внутри пира сохраняется, а разные пиры распределяются по воркерам. Режим
//! `queue` раскладывает задания по наименее загруженной очереди и служит только
//! для замеров: он переставляет пакеты одного потока между воркерами.

use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use umbrawg_crypto::random::BufferedRng;
use umbrawg_device::{
    device::BbrBatch, DatagramSink, Device, IncomingOutcome, IoContext, PacketIo, Peer,
    PreparedIncoming, PreparedTransport,
};
use umbrawg_proto::obf::{DetectedPacket, MessageKind};
use umbrawg_transport::{RecvQueue, SocketSet, SocketSource, MAX_BATCH_SIZE};
use umbrawg_tun::Tun;

use crate::ring::SpscRing;
use crate::rx::RxBatch;
use crate::tx::TxBatch;
use crate::{
    is_socket_would_block, open_socket_set, pump_tun_tx, rebind_needed, shutdown_requested,
    IDLE_TIMEOUT_MS, MAX_PACKET, RECV_BATCH, TUN_BATCH, TUN_PACKET_MARGIN,
};

/// Максимальное число сегментов в одном задании.
pub(crate) const MAX_SEGMENTS: usize = 64;

/// Глубина очереди заданий и пула буферов по умолчанию: 64 слота по 64 КиБ.
///
/// Глубина задаёт запас на всплеск, а не пропускную способность: воркер
/// разбирает очередь на каждой итерации и уходит в `poll`, только когда она
/// пуста. На стенде с 50 пирами и 51 демоном каждый лишний слот — это 64 КиБ
/// анонимной памяти на воркер, поэтому дефолт выбран минимальным из
/// допустимых: 64 × 64 КиБ × 4 воркера = 16 МиБ на процесс вместо 64 МиБ.
/// Пул можно увеличить через `UMBRAWG_RX_QUEUE` (до 1024), если на стенде
/// есть запас памяти под всплески.
const DEFAULT_QUEUE_DEPTH: usize = MIN_QUEUE_DEPTH;

/// Минимальная глубина очереди воркера.
const MIN_QUEUE_DEPTH: usize = 64;

/// Максимальная глубина очереди воркера.
const MAX_QUEUE_DEPTH: usize = 1024;

/// Верхняя граница числа крипто-воркеров.
const MAX_WORKERS: usize = 8;

/// Период вывода счётчиков при `UMBRAWG_RX_STATS=1`.
const STATS_INTERVAL: Duration = Duration::from_secs(5);

const HOUSEKEEPING_INTERVAL: Duration = Duration::from_millis(5);

/// Ёмкость очереди управляющих пакетов, обрабатываемых отдельным потоком.
const CONTROL_QUEUE_CAPACITY: usize = 128;

/// Сколько управляющих пакетов поток обработки забирает за один проход.
const CONTROL_BATCH: usize = 32;

/// Настройки параллельного приёма.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParallelConfig {
    /// Число крипто-воркеров (потоков расшифровки и записи в TUN).
    pub workers: usize,
    /// Правило выбора воркера для дейтаграммы.
    pub sched: RxSchedule,
    /// Глубина очереди заданий и пула буферов каждого воркера.
    pub queue_depth: usize,
}

impl ParallelConfig {
    /// Читает конфигурацию из окружения. `None` означает обычный режим.
    ///
    /// Некорректная глубина очереди (`UMBRAWG_RX_QUEUE`) возвращается ошибкой.
    /// Число воркеров берётся из `UMBRAWG_RX_WORKERS`, а если он не задан или
    /// задан пустым/нечисловым — из `UMBRAWG_THREADS`: у параллельного приёма
    /// нет отдельного смысла игнорировать общую ручку числа потоков демона,
    /// а молча подставлять дефолт вместо явно заданного значения нельзя.
    pub fn from_env(available: usize) -> Result<Option<Self>, String> {
        let enabled = parallel_rx_enabled(std::env::var("UMBRAWG_PARALLEL_RX").ok().as_deref());
        if !enabled {
            return Ok(None);
        }
        let threads = std::env::var("UMBRAWG_THREADS")
            .ok()
            .filter(|value| worker_count_value(value).is_some());
        let requested = match std::env::var("UMBRAWG_RX_WORKERS").ok() {
            Some(value) if value.trim().is_empty() => threads,
            Some(value) => match worker_count_value(&value) {
                Some(_) => Some(value),
                None => {
                    log::warn!(
                        "UMBRAWG_RX_WORKERS={value:?} is not a worker count; \
                         falling back to UMBRAWG_THREADS/default"
                    );
                    threads
                }
            },
            None => threads,
        };
        let sched = RxSchedule::from_env(std::env::var("UMBRAWG_RX_SCHED").ok().as_deref());
        let queue_depth = queue_depth_from_env(std::env::var("UMBRAWG_RX_QUEUE").ok().as_deref())?;
        Ok(Some(Self {
            workers: crypto_worker_count(requested.as_deref(), available),
            sched,
            queue_depth,
        }))
    }
}

/// Возвращает число из значения переменной, если это корректный счётчик > 0.
fn worker_count_value(value: &str) -> Option<usize> {
    value
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|count| *count > 0)
}

/// Правило выбора воркера для задания.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum RxSchedule {
    /// Привязка по пиру: порядок пакетов внутри пира сохраняется.
    #[default]
    Peer,
    /// Наименее загруженная очередь: переставляет пакеты одного потока.
    Queue,
}

impl RxSchedule {
    /// Разбирает значение `UMBRAWG_RX_SCHED`; неизвестные значения дают `peer`.
    pub(crate) fn from_env(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(value) if value.eq_ignore_ascii_case("queue") => Self::Queue,
            _ => Self::Peer,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Queue => "queue",
        }
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
/// По умолчанию: половина доступных ядер, но не больше четырёх, а на
/// небольшом хосте (≤ 8 ГиБ RAM) — 2. Одно ядро остаётся потоку приёма,
/// остальные — сетевому стеку, UAPI и прочей работе.
///
/// Потоков у процесса при этом `N + 2`: N крипто-воркеров плюс поток приёма
/// и поток управления; ещё один поток держит UAPI. Память пула считается по
/// N, поэтому на стенде с малым объёмом RAM воркеры уменьшают через
/// `UMBRAWG_RX_WORKERS` (для 50 пиров на 4 ГБ это дефолтные 2).
pub(crate) fn crypto_worker_count(requested: Option<&str>, available: usize) -> usize {
    crypto_worker_count_for(requested, available, crate::mem_total())
}

/// Та же логика с явным объёмом RAM — для тестов и детерминированных вызовов.
pub(crate) fn crypto_worker_count_for(
    requested: Option<&str>,
    available: usize,
    mem_total: Option<u64>,
) -> usize {
    let available = available.clamp(1, MAX_WORKERS);
    let by_cpu = (available / 2).clamp(1, 4);
    let default = match mem_total {
        Some(total) if total < crate::SMALL_HOST_BYTES => by_cpu.min(2),
        _ => by_cpu,
    };
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

/// Проверяет, что глубина очереди — степень двойки из допустимого диапазона.
pub(crate) fn valid_queue_depth(depth: usize) -> bool {
    (MIN_QUEUE_DEPTH..=MAX_QUEUE_DEPTH).contains(&depth) && depth.is_power_of_two()
}

/// Разбирает `UMBRAWG_RX_QUEUE` — глубину очереди воркера.
///
/// Пустое значение означает значение по умолчанию. Число обязано быть степенью
/// двойки в диапазоне `MIN_QUEUE_DEPTH..=MAX_QUEUE_DEPTH`.
pub(crate) fn queue_depth_from_env(value: Option<&str>) -> Result<usize, String> {
    let Some(text) = value.map(str::trim) else {
        return Ok(DEFAULT_QUEUE_DEPTH);
    };
    if text.is_empty() {
        return Ok(DEFAULT_QUEUE_DEPTH);
    }
    let depth = text
        .parse::<usize>()
        .map_err(|_| format!("UMBRAWG_RX_QUEUE: ожидается целое число, получено {text:?}"))?;
    if !(MIN_QUEUE_DEPTH..=MAX_QUEUE_DEPTH).contains(&depth) {
        return Err(format!(
            "UMBRAWG_RX_QUEUE: глубина {depth} вне диапазона {MIN_QUEUE_DEPTH}..={MAX_QUEUE_DEPTH}"
        ));
    }
    if !depth.is_power_of_two() {
        return Err(format!(
            "UMBRAWG_RX_QUEUE: глубина {depth} должна быть степенью двойки: \
             64, 128, 256, 512, 1024"
        ));
    }
    Ok(depth)
}

/// Буферы, которые занимает пул воркера при глубине `depth`.
pub(crate) const fn queue_bytes(depth: usize) -> usize {
    depth * crate::MAX_PACKET
}

/// Верхняя граница памяти пула всех воркеров: `workers × depth × MAX_PACKET`.
///
/// Слоты растут лениво, поэтому это предел под нагрузкой, а не текущий RSS.
pub(crate) const fn pool_bytes(workers: usize, depth: usize) -> u64 {
    (workers as u64).saturating_mul(queue_bytes(depth) as u64)
}

/// Предупреждает, если верхняя граница пула больше четверти доступной памяти.
///
/// Слоты выделяются по требованию, но под нагрузкой пул может дорасти до
/// `pool_bytes`. На стенде с десятками демонов это чаще приводит к OOM-
/// киллеру, чем к понятной ошибке, поэтому предупреждаем заранее.
pub(crate) fn warn_pool_budget(workers: usize, depth: usize) {
    let Some(available) = mem_available() else {
        return;
    };
    let pool = pool_bytes(workers, depth);
    if !pool_over_budget(pool, available) {
        return;
    }
    log::warn!(
        "parallel rx pool can reach {} MiB ({} workers × {} slots × {} KiB), more than a \
         quarter of the {} MiB available: lower UMBRAWG_RX_QUEUE or UMBRAWG_RX_WORKERS",
        pool / (1024 * 1024),
        workers,
        depth,
        crate::MAX_PACKET / 1024,
        available / (1024 * 1024)
    );
}

/// Решение о предупреждении: пул больше четверти доступной памяти.
///
/// Сравнение через деление, а не `pool * 4`, чтобы не переполняться на
/// больших значениях и не терять предупреждение из-за saturating-умножения.
fn pool_over_budget(pool: u64, available: u64) -> bool {
    pool > available / 4
}

/// `MemAvailable` из `/proc/meminfo`, если он доступен.
fn mem_available() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// Счётчики потока приёма. Все поля — обычные атомики без блокировок.
#[derive(Default)]
pub(crate) struct RxStats {
    /// Принятых дейтаграмм.
    pub datagrams: AtomicU64,
    /// Сегментов, переданных воркерам.
    pub enqueued: AtomicU64,
    /// Управляющих пакетов, классифицированных потоком приёма.
    pub controls: AtomicU64,
    /// Управляющих пакетов, отброшенных из-за переполнения очереди.
    pub controls_dropped: AtomicU64,
    /// Отброшено на классификации или поиске сессии.
    pub drops_detect: AtomicU64,
    /// Отброшено из-за переполнения очереди воркера.
    pub drops_queue: AtomicU64,
    /// Отброшено из-за слишком большого пакета или числа сегментов.
    pub drops_size: AtomicU64,
    /// Разбуженных воркеров.
    pub wakes: AtomicU64,
    pub drops_prepared: AtomicU64,
    pub drops_endpoint: AtomicU64,
    pub drops_tun: AtomicU64,
    pub tx_drops: AtomicU64,
    pub pool_violations: AtomicU64,
    pub housekeeping: AtomicU64,
    pub segments: AtomicU64,
    pub gro_splits: AtomicU64,
    pub max_datagram_segments: AtomicU64,
    /// Дейтаграмм, в которых встретились сегменты разных пиров.
    pub mixed_peer_datagrams: AtomicU64,
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
    max_len: usize,
}

// Безопасность: буфером владеет либо поток приёма (после `allocate`), либо
// воркер (после `pop`); владение передаётся через SPSC-очереди.
unsafe impl Sync for BufferSlots {}

impl BufferSlots {
    /// Создаёт пул из `count` пустых слотов с пределом `max_len` байт.
    ///
    /// Слоты растут лениво, до длины фактического дейтаграммы: пул на 64–1024
    /// слота по 64 КиБ, выделенный заранее, — это десятки мегабайт анонимной
    /// памяти у каждого демона ещё до первого пакета. На стенде с 51 демоном
    /// такой стартовый всплеск упирается в OOM-киллер, хотя под нагрузкой
    /// одновременно занята лишь часть пула.
    ///
    /// Верхняя граница памяти пула — `count × max_len` (для 64 слотов это
    /// 4 МиБ), но фактически занято столько, сколько нужно самым длинным
    /// пакетам, попавшим в каждый слот: слот не сжимается, поэтому его длина
    /// равна максимуму длин дейтаграмм этого слота за всё время. Ёмкость
    /// `Vec` может быть чуть больше длины (аллокатор), но `reserve_exact`
    /// не удваивает её, как `reserve`.
    fn new(count: usize, max_len: usize) -> Self {
        let slots = (0..count)
            .map(|_| UnsafeCell::new(Vec::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { slots, max_len }
    }

    fn write(&self, slot: u32, data: &[u8]) -> bool {
        if data.len() > self.max_len {
            return false;
        }
        copy_packet(unsafe { &mut *self.slots[slot as usize].get() }, data);
        true
    }

    /// Возвращает буфер слота, которым в этот момент владеет воркер.
    ///
    /// `len` — длина дейтаграммы из задания: буфер не короче неё, иначе
    /// учёт пула сломан (это ловит `debug_assert`), а в release срез
    /// ограничивается фактической длиной, чтобы не читать за границей.
    #[allow(clippy::mut_from_ref)]
    fn get(&self, slot: u32, len: usize) -> &mut [u8] {
        let buffer = unsafe { &mut *self.slots[slot as usize].get() };
        debug_assert!(
            len <= buffer.len(),
            "job length {len} exceeds slot buffer {}",
            buffer.len()
        );
        let end = len.min(buffer.len());
        &mut buffer[..end]
    }
}

/// Копирует пакет в буфер, не сжимая его и не зануляя хвост.
///
/// `Vec::resize(len, 0)` сначала пишет нули во весь новый хвост (до 64 КиБ
/// на слот), которые тут же перезаписываются пакетом. Здесь память растёт
/// через `reserve_exact`, а инициализируется только скопированными байтами.
fn copy_packet(buffer: &mut Vec<u8>, data: &[u8]) {
    if buffer.len() < data.len() {
        buffer.reserve_exact(data.len() - buffer.len());
        // SAFETY: `reserve_exact` гарантирует capacity >= data.len(); первые
        // `data.len()` байт инициализируются копированием, `u8` не имеет Drop.
        unsafe {
            buffer
                .as_mut_ptr()
                .copy_from_nonoverlapping(data.as_ptr(), data.len());
            buffer.set_len(data.len());
        }
    } else {
        buffer[..data.len()].copy_from_slice(data);
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

struct ControlJob {
    buffer: Vec<u8>,
    len: usize,
    source: SocketAddr,
    detected: DetectedPacket,
}

struct ControlState {
    pending: VecDeque<ControlJob>,
    free: Vec<Vec<u8>>,
}

/// Ограниченная очередь управляющих пакетов для отдельного потока.
///
/// Поток приёма только копирует пакет и складывает его в очередь; он никогда
/// не ждёт обработки рукопожатия. При переполнении пакет отбрасывается, а
/// данные продолжают идти через очереди крипто-воркеров.
pub(crate) struct ControlQueue {
    state: Mutex<ControlState>,
    event: EventFd,
}

impl ControlQueue {
    fn new(capacity: usize) -> io::Result<Self> {
        // Буферы тоже растут лениво: рукопожатие — это 64–200 байт, а
        // фиксированные 128 × 64 КиБ = 8 МиБ на каждый из 51 демонов стоили
        // 400 МиБ RSS на стенде и ничего не давали.
        let free = (0..capacity).map(|_| Vec::new()).collect();
        Ok(Self {
            state: Mutex::new(ControlState {
                pending: VecDeque::with_capacity(capacity),
                free,
            }),
            event: EventFd::new()?,
        })
    }

    fn push(&self, data: &[u8], source: SocketAddr, detected: DetectedPacket) -> bool {
        if data.len() > MAX_PACKET {
            return false;
        }
        let mut state = lock(&self.state);
        let Some(mut buffer) = state.free.pop() else {
            return false;
        };
        copy_packet(&mut buffer, data);
        state.pending.push_back(ControlJob {
            buffer,
            len: data.len(),
            source,
            detected,
        });
        drop(state);
        self.event.notify();
        true
    }

    fn pop(&self) -> Option<ControlJob> {
        lock(&self.state).pending.pop_front()
    }

    /// Возвращает задание в начало очереди, не теряя его.
    ///
    /// Нужно, когда сокет ещё не привязан: выбросить initiation на старте —
    /// значит потерять рукопожатие до следующего ретрансмита.
    fn requeue_front(&self, job: ControlJob) {
        lock(&self.state).pending.push_front(job);
    }

    fn recycle(&self, job: ControlJob) {
        lock(&self.state).free.push(job.buffer);
    }

    /// Возвращает в пул все ожидающие задания одним проходом.
    ///
    /// Нужно на остановке, когда сокета уже нет: если отдавать по одному
    /// заданию за итерацию, между ними стоит `wait(IDLE_TIMEOUT_MS)`, и
    /// полная очередь 128 задерживает `join` на ~1.3 с вместо мгновенного
    /// дренажа.
    fn recycle_all(&self) {
        let mut state = lock(&self.state);
        let pending = std::mem::take(&mut state.pending);
        state.free.extend(pending.into_iter().map(|job| job.buffer));
    }

    #[cfg(test)]
    fn free(&self) -> usize {
        lock(&self.state).free.len()
    }

    fn is_empty(&self) -> bool {
        lock(&self.state).pending.is_empty()
    }

    fn wait(&self, timeout_ms: i32) {
        let mut fds = [libc::pollfd {
            fd: self.event.fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        unsafe {
            libc::poll(fds.as_mut_ptr(), 1, timeout_ms);
        }
        if fds[0].revents != 0 {
            self.event.drain();
        }
    }

    #[cfg(test)]
    fn pending(&self) -> usize {
        lock(&self.state).pending.len()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Очередь заданий и пул буферов одного воркера.
pub(crate) struct WorkerChannel {
    jobs: SpscRing<Job>,
    free: SpscRing<u32>,
    reclaim: SpscRing<u32>,
    buffers: BufferSlots,
    event: EventFd,
    sleeping: AtomicBool,
    depth: usize,
}

impl WorkerChannel {
    fn new(slot_len: usize, depth: usize) -> io::Result<Self> {
        if !valid_queue_depth(depth) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "rx queue depth {depth} must be a power of two in \
                     {MIN_QUEUE_DEPTH}..={MAX_QUEUE_DEPTH}"
                ),
            ));
        }
        let free = SpscRing::new(depth);
        for slot in 0..depth as u32 {
            if free.push(slot).is_err() {
                return Err(io::Error::other("cannot seed buffer pool"));
            }
        }
        Ok(Self {
            jobs: SpscRing::new(depth),
            free,
            reclaim: SpscRing::new(depth),
            buffers: BufferSlots::new(depth, slot_len),
            event: EventFd::new()?,
            sleeping: AtomicBool::new(false),
            depth,
        })
    }

    fn depth(&self) -> usize {
        self.depth
    }

    fn allocate(&self) -> Option<u32> {
        self.free.pop()
    }

    fn release(&self, slot: u32) -> bool {
        self.free.push(slot).is_ok()
    }

    /// Сколько слотов пула свободно (для строки статистики и тестов).
    ///
    /// Уменьшение до нуля означает, что пул выбран полностью: новые задания
    /// будут отброшены со счётчиком `drops(queue)`.
    fn available(&self) -> usize {
        self.free.len()
    }

    fn reject(&self, slot: u32) -> bool {
        self.reclaim.push(slot).is_ok()
    }

    fn drain_reclaimed(&self) -> (usize, usize) {
        let mut released = 0;
        let mut leaked = 0;
        while let Some(slot) = self.reclaim.pop() {
            if self.release(slot) {
                released += 1;
            } else {
                leaked += 1;
            }
        }
        (released, leaked)
    }

    fn write(&self, slot: u32, data: &[u8]) -> bool {
        self.buffers.write(slot, data)
    }

    fn buffers(&self) -> &BufferSlots {
        &self.buffers
    }

    /// Публикует задание и будит воркер.
    ///
    /// Возвращает пару «опубликовано, разбужен». Переполнение невозможно при
    /// целом пуле: слот выделяется только из свободных, поэтому очередь заданий
    /// не может быть полной. Слот возвращает исключительно воркер.
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
                debug_assert!(
                    false,
                    "job queue overflow means the buffer pool accounting is broken"
                );
                let _ = self.reject(job.slot);
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

    fn pending(&self) -> usize {
        self.jobs.len()
    }

    fn wait(&self, tun_fd: RawFd, timeout_ms: i32) {
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
            libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms);
        }
        self.sleeping.store(false, Ordering::SeqCst);
        if fds[1].revents != 0 {
            self.event.drain();
        }
    }
}

/// Общее состояние потока приёма и крипто-воркеров.
pub(crate) struct SharedRx {
    socket: RwLock<Option<Arc<SocketSet>>>,
    channels: Vec<WorkerChannel>,
    controls: ControlQueue,
    sched: RxSchedule,
    stats: RxStats,
    failure: Mutex<Option<String>>,
}

impl SharedRx {
    pub fn new(workers: usize, sched: RxSchedule, queue_depth: usize) -> io::Result<Self> {
        let mut channels = Vec::with_capacity(workers);
        for _ in 0..workers {
            channels.push(WorkerChannel::new(MAX_PACKET, queue_depth)?);
        }
        Ok(Self {
            socket: RwLock::new(None),
            channels,
            controls: ControlQueue::new(CONTROL_QUEUE_CAPACITY)?,
            sched,
            stats: RxStats::default(),
            failure: Mutex::new(None),
        })
    }

    pub fn register_failure(&self, message: String) {
        let mut guard = match self.failure.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_none() {
            *guard = Some(message.clone());
            log::error!("parallel rx failure: {message}");
        }
        drop(guard);
        crate::request_shutdown();
    }

    pub fn failure(&self) -> Option<String> {
        match self.failure.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn set_socket(&self, socket: Option<Arc<SocketSet>>) {
        if let Ok(mut guard) = self.socket.write() {
            *guard = socket;
        }
    }

    fn socket(&self) -> Option<Arc<SocketSet>> {
        self.socket.read().ok().and_then(|guard| guard.clone())
    }
}

struct ControlIo<'a> {
    socket: &'a dyn SocketSource,
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
                .next()
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
pub(crate) fn rx_loop(
    device: Arc<Device>,
    shared: Arc<SharedRx>,
    socket_buffer: usize,
    underlay: crate::mtu::Underlay,
) -> io::Result<()> {
    let mut rng = BufferedRng::new(OsRng);
    let mut scratch = vec![0u8; MAX_PACKET + 512];
    let mut recv_queue =
        RecvQueue::new(RECV_BATCH).map_err(|error| io::Error::other(error.to_string()))?;
    let mut recv_buffers: Vec<Vec<u8>> = (0..RECV_BATCH).map(|_| vec![0u8; MAX_PACKET]).collect();
    let mut recv_slices: Vec<&mut [u8]> = recv_buffers
        .iter_mut()
        .map(|buffer| buffer.as_mut_slice())
        .collect();
    let mut socket: Option<Arc<SocketSet>> = None;
    let mut bound_extra: Option<usize> = None;
    let mut bound_epoch: Option<u64> = None;
    let mut bound_underlay: Option<u16> = None;
    let mut bound_mark: Option<u32> = None;
    let mut rebind_after = Instant::now();
    let mut cursor = 0usize;
    let mut stats_at = Instant::now();
    let mut housekeeping_at = Instant::now();
    let stats_enabled = std::env::var("UMBRAWG_RX_STATS").is_ok_and(|value| value.trim() == "1");

    while !shutdown_requested() {
        let (want_port, want_epoch) = device.listen_port_request();
        let want_extra = usize::from(device.extra_ports());
        let want_mark = device.fwmark();
        let want_underlay = device.underlay_mtu();
        if Instant::now() >= rebind_after
            && rebind_needed(
                socket.as_deref(),
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
            let bind_port = crate::rebind_port(want_port, bound_epoch, want_epoch, current_port);
            match open_socket_set(
                bind_port,
                want_extra,
                want_mark,
                socket_buffer,
                crate::runtime_underlay(underlay, &device).gso_limits(),
            ) {
                Ok(new_socket) => {
                    let actual = new_socket.primary().local_addr().port();
                    device.note_bound_listen_port(want_epoch, actual);
                    log::info!(
                        "parallel rx listening on {} ({} sockets)",
                        new_socket.primary().local_addr(),
                        new_socket.len()
                    );
                    let new_socket = Arc::new(new_socket);
                    shared.set_socket(Some(Arc::clone(&new_socket)));
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
                    rebind_after = Instant::now() + Duration::from_secs(1);
                }
            }
        }
        let active = socket.as_ref().expect("socket is bound").as_ref();
        if bound_mark != Some(want_mark) && crate::apply_socket_mark(active, want_mark) {
            bound_mark = Some(want_mark);
        }
        let mut busy = false;

        for listener in active.all() {
            loop {
                match listener.recv_batch(&mut recv_queue, &mut recv_slices) {
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
                                shared.stats.drops_endpoint.fetch_add(1, Ordering::Relaxed);
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
        }

        if stats_enabled && stats_at.elapsed() >= STATS_INTERVAL {
            stats_at = Instant::now();
            let counters = device.incoming_drop_counters();
            let pool_free = shared
                .channels
                .iter()
                .map(WorkerChannel::available)
                .min()
                .unwrap_or(0);
            log::info!(
                "rx stats: sched={} datagrams={} enqueued={} controls={} control_drops={} under_load={} segments={} gro_splits={} max_datagram_segments={} mixed_peers={} housekeeping={} pool_free={} drops(detect={} prepared={} endpoint={} queue={} size={} open={} replay={} allowed={} tun={} tx={} pool={}) wakes={}",
                shared.sched.as_str(),
                shared.stats.datagrams.load(Ordering::Relaxed),
                shared.stats.enqueued.load(Ordering::Relaxed),
                shared.stats.controls.load(Ordering::Relaxed),
                shared.stats.controls_dropped.load(Ordering::Relaxed),
                u8::from(device.under_load()),
                shared.stats.segments.load(Ordering::Relaxed),
                shared.stats.gro_splits.load(Ordering::Relaxed),
                shared.stats.max_datagram_segments.load(Ordering::Relaxed),
                shared.stats.mixed_peer_datagrams.load(Ordering::Relaxed),
                shared.stats.housekeeping.load(Ordering::Relaxed),
                pool_free,
                shared.stats.drops_detect.load(Ordering::Relaxed),
                shared.stats.drops_prepared.load(Ordering::Relaxed),
                shared.stats.drops_endpoint.load(Ordering::Relaxed),
                shared.stats.drops_queue.load(Ordering::Relaxed),
                shared.stats.drops_size.load(Ordering::Relaxed),
                counters.open_failed(),
                counters.replay(),
                counters.allowed_ips(),
                shared.stats.drops_tun.load(Ordering::Relaxed),
                shared.stats.tx_drops.load(Ordering::Relaxed),
                shared.stats.pool_violations.load(Ordering::Relaxed),
                shared.stats.wakes.load(Ordering::Relaxed),
            );
        }

        let now = Instant::now();
        let deadline = device.next_deadline();
        if now >= housekeeping_at || deadline.is_some_and(|deadline| deadline <= now) {
            housekeeping_at = now + HOUSEKEEPING_INTERVAL;
            housekeeping(&device, active, now, &mut rng, &mut scratch);
            shared.stats.housekeeping.fetch_add(1, Ordering::Relaxed);
        }

        if !busy {
            let wakeup = crate::earliest_deadline(Some(housekeeping_at), device.next_deadline());
            let timeout = crate::poll_timeout_ms(Instant::now(), wakeup);
            let mut fds: Vec<libc::pollfd> = active
                .all()
                .iter()
                .map(|socket| libc::pollfd {
                    fd: socket.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            unsafe {
                libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout);
            }
        }
    }

    shared.set_socket(None);
    Ok(())
}

/// Поток обработки управляющих пакетов.
///
/// Рукопожатия, cookie и ответы обрабатываются здесь, а не в потоке приёма:
/// флуд инициаций занимает только эту очередь, пока данные продолжают идти
/// через крипто-воркеры.
pub(crate) fn control_loop(device: Arc<Device>, shared: Arc<SharedRx>) -> io::Result<()> {
    let mut rng = BufferedRng::new(OsRng);
    let mut scratch = vec![0u8; MAX_PACKET + 512];
    loop {
        if shutdown_requested() && shared.controls.is_empty() {
            break;
        }
        let mut processed = 0usize;
        while let Some(mut job) = shared.controls.pop() {
            let Some(socket) = shared.socket() else {
                // Сокет ещё не привязан потоком приёма: вернуть задание в
                // очередь, а не выбросить. Иначе initiation, пришедшая в это
                // окно, теряется до следующего ретрансмита (5 с).
                if !shutdown_requested() {
                    shared.controls.requeue_front(job);
                    break;
                }
                // Остановка: сокета уже не будет, обрабатывать задания
                // некуда. Дренаж всей очереди одним проходом, без `wait`
                // между заданиями, иначе полные 128 слотов задерживают
                // `join` на ~1.3 с.
                shared.controls.recycle(job);
                shared.controls.recycle_all();
                return Ok(());
            };
            let now = Instant::now();
            let snapshot = device.incoming_snapshot();
            let mut control = ControlIo {
                socket: socket.as_ref(),
            };
            let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut control);
            let prepared = PreparedIncoming::Control(job.detected);
            if let Err(error) = device.handle_prepared(
                &mut job.buffer[..job.len],
                prepared,
                job.source,
                &snapshot,
                &mut context,
            ) {
                log::debug!("control packet failed: {error}");
            }
            shared.controls.recycle(job);
            processed += 1;
            if processed >= CONTROL_BATCH {
                break;
            }
        }
        device.refresh_under_load(Instant::now());
        if shutdown_requested() && shared.controls.is_empty() {
            break;
        }
        if processed == 0 {
            shared.controls.wait(IDLE_TIMEOUT_MS);
        }
    }
    Ok(())
}

/// Выбирает воркера с наименьшей очередью, начиная обход с `start`.
pub(crate) fn select_worker(pending: &[usize], start: usize) -> usize {
    let mut best = start % pending.len();
    for attempt in 1..pending.len() {
        let candidate = (start + attempt) % pending.len();
        if pending[candidate] < pending[best] {
            best = candidate;
        }
    }
    best
}

/// Хеш FNV-1a: стабильный между запусками и независимый от порядка пиров.
fn peer_hash(bytes: &[u8; 32]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Привязывает пира к воркеру: `hash(public_key) % workers`.
pub(crate) fn peer_worker(public_key: &[u8; 32], workers: usize) -> usize {
    debug_assert!(workers > 0, "there is at least one worker");
    (peer_hash(public_key) % workers as u64) as usize
}

struct GroChunks {
    offset: usize,
    len: usize,
    gro_size: Option<usize>,
}

impl GroChunks {
    fn new(len: usize, gro_size: Option<usize>) -> Self {
        Self {
            offset: 0,
            len,
            gro_size,
        }
    }
}

impl Iterator for GroChunks {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.offset >= self.len {
            return None;
        }
        let end = match self.gro_size {
            Some(size) => (self.offset + size * MAX_SEGMENTS).min(self.len),
            None => self.len,
        };
        let start = self.offset;
        self.offset = end;
        Some((start, end))
    }
}

fn publish_job(
    shared: &SharedRx,
    cursor: &mut usize,
    data: &[u8],
    source: SocketAddr,
    gro_size: Option<usize>,
    prepared: [Option<PreparedTransport>; MAX_SEGMENTS],
    pinned: Option<usize>,
) {
    let channels = shared.channels.len();
    let (target, slot) = match shared.sched {
        RxSchedule::Peer => {
            let worker = match pinned {
                Some(worker) => worker % channels,
                None => {
                    let worker = *cursor % channels;
                    *cursor = cursor.wrapping_add(1);
                    worker
                }
            };
            match shared.channels[worker].allocate() {
                Some(slot) => (worker, slot),
                None => {
                    shared.stats.drops_queue.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
        RxSchedule::Queue => {
            let start = *cursor % channels;
            *cursor = cursor.wrapping_add(1);
            let mut pending = [0usize; MAX_WORKERS];
            for (slot, channel) in pending.iter_mut().zip(&shared.channels) {
                *slot = channel.pending();
            }
            let first = select_worker(&pending[..channels], start);
            let mut chosen = None;
            for attempt in 0..channels {
                let candidate = (first + attempt) % channels;
                if let Some(free) = shared.channels[candidate].allocate() {
                    chosen = Some((candidate, free));
                    break;
                }
            }
            match chosen {
                Some(pair) => pair,
                None => {
                    shared.stats.drops_queue.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
    };
    let channel = &shared.channels[target];
    debug_assert!(
        channel.pending() < channel.depth(),
        "a free slot was allocated while the job queue is full"
    );
    if !channel.write(slot, data) {
        shared.stats.pool_violations.fetch_add(1, Ordering::Relaxed);
        shared.stats.drops_size.fetch_add(1, Ordering::Relaxed);
        let _ = channel.reject(slot);
        return;
    }
    let job = Job {
        slot,
        len: data.len() as u32,
        source,
        gro_size: gro_size.map(|size| size as u32),
        prepared,
    };
    let (published, woke) = channel.publish(job);
    if woke {
        shared.stats.wakes.fetch_add(1, Ordering::Relaxed);
    }
    if !published {
        shared.stats.pool_violations.fetch_add(1, Ordering::Relaxed);
        shared.stats.drops_queue.fetch_add(1, Ordering::Relaxed);
        return;
    }
    shared.stats.enqueued.fetch_add(1, Ordering::Relaxed);
}

#[allow(clippy::too_many_arguments)]
fn enqueue_segments(
    device: &Device,
    shared: &SharedRx,
    cursor: &mut usize,
    snapshot: &umbrawg_device::IncomingSnapshot,
    now: Instant,
    data: &mut [u8],
    len: usize,
    gro_size: Option<usize>,
    source: SocketAddr,
) {
    if len > data.len() {
        shared.stats.drops_size.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if gro_size.is_some_and(|size| size == 0 || size > len) {
        shared.stats.drops_detect.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut total_segments = 0u64;
    let mut chunk_count = 0u64;
    let mut pinned: Option<usize> = None;
    let mut first_peer: Option<[u8; 32]> = None;
    let mut mixed = false;
    for (start, end) in GroChunks::new(len, gro_size) {
        let mut prepared: [Option<PreparedTransport>; MAX_SEGMENTS] =
            [const { None }; MAX_SEGMENTS];
        let mut ordinal = 0usize;
        let mut transports = 0usize;
        let mut offset = start;
        while offset < end && ordinal < MAX_SEGMENTS {
            let segment_end = gro_size.map_or(end, |size| (offset + size).min(end));
            if segment_end <= offset {
                break;
            }
            match device.prepare_incoming(&mut data[offset..segment_end], snapshot, now) {
                PreparedIncoming::Transport(entry) => {
                    let key = entry.peer_public_key().to_bytes();
                    match first_peer {
                        None => {
                            first_peer = Some(key);
                            if shared.sched == RxSchedule::Peer {
                                pinned = Some(peer_worker(&key, shared.channels.len()));
                            }
                        }
                        Some(expected) if expected != key && !mixed => {
                            mixed = true;
                            shared
                                .stats
                                .mixed_peer_datagrams
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Some(_) => {}
                    }
                    prepared[ordinal] = Some(entry);
                    transports += 1;
                }
                PreparedIncoming::Control(detected) => {
                    shared.stats.controls.fetch_add(1, Ordering::Relaxed);
                    let length = detected
                        .padding
                        .saturating_add(detected.body_len)
                        .min(segment_end - offset);
                    let queued =
                        shared
                            .controls
                            .push(&data[offset..offset + length], source, detected);
                    if !queued {
                        shared
                            .stats
                            .controls_dropped
                            .fetch_add(1, Ordering::Relaxed);
                        if detected.kind == MessageKind::Initiation {
                            device.note_initiation(now);
                        }
                    }
                }
                PreparedIncoming::Dropped => {
                    shared.stats.drops_prepared.fetch_add(1, Ordering::Relaxed);
                }
            }
            ordinal += 1;
            offset = segment_end;
        }
        if ordinal == 0 {
            continue;
        }
        total_segments += ordinal as u64;
        chunk_count += 1;
        if transports == 0 {
            // В куске только управляющие пакеты: они уже лежат в очереди
            // управления, а задание воркеру расшифровывать нечего. Публикация
            // такого задания занимает слот пула и будит воркера впустую —
            // на 50 одновременных initiation это половина пула.
            continue;
        }
        publish_job(
            shared,
            cursor,
            &data[start..end],
            source,
            gro_size,
            prepared,
            pinned,
        );
    }
    if total_segments > 0 {
        shared
            .stats
            .segments
            .fetch_add(total_segments, Ordering::Relaxed);
        shared
            .stats
            .max_datagram_segments
            .fetch_max(total_segments, Ordering::Relaxed);
    }
    if chunk_count > 1 {
        shared.stats.gro_splits.fetch_add(1, Ordering::Relaxed);
    }
}

fn housekeeping<R: RngCore>(
    device: &Device,
    socket: &dyn SocketSource,
    now: Instant,
    rng: &mut R,
    scratch: &mut [u8],
) {
    let mut control = ControlIo { socket };
    let mut staged_error = None;
    device.for_each_peer(|peer| {
        let mut context = IoContext::new(&mut *rng, now, scratch, &mut control);
        if let Err(error) = device.flush_staged(peer, &mut context) {
            staged_error = Some(error);
        }
    });
    if let Some(error) = staged_error {
        log::debug!("flush failed: {error}");
    }
    device.refresh_under_load(now);
    if device
        .next_deadline()
        .is_some_and(|deadline| deadline <= now)
    {
        let mut context = IoContext::new(rng, now, scratch, &mut control);
        if let Err(error) = device.tick(&mut context) {
            log::debug!("timer tick failed: {error}");
        }
    }
}

/// Дочитывает очередь канала и возвращает слоты в пул, когда сокета уже нет.
///
/// Возвращает число выброшенных заданий. Без этого `channel.is_empty()`
/// навсегда остаётся ложным: воркер не выходит из цикла, `run_parallel`
/// не дожидается `join`, и демон не завершается по SIGTERM (его приходится
/// убивать `kill -9`). Обрабатывать задания без сокета нельзя — доставлять
/// расшифрованное некуда, — поэтому они отбрасываются вместе со слотами.
fn drain_without_socket(channel: &WorkerChannel) -> usize {
    let mut drained = 0;
    while let Some(job) = channel.pop() {
        channel.release(job.slot);
        drained += 1;
    }
    drained
}

pub(crate) fn supervise(rx_finished: bool, worker_finished: bool) -> Option<&'static str> {
    if rx_finished {
        Some("rx thread exited unexpectedly")
    } else if worker_finished {
        Some("crypto worker exited unexpectedly")
    } else {
        None
    }
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
    socket: &dyn SocketSource,
    tun: &Tun,
    rx: &mut RxBatch,
    stats: &RxStats,
) {
    let len = job.len as usize;
    let gro_size = job.gro_size.map(|size| size as usize);
    let data = channel.buffers().get(job.slot, len);
    let mut offset = 0usize;
    let mut ordinal = 0usize;
    while offset < len && ordinal < MAX_SEGMENTS {
        let end = gro_size.map_or(len, |size| (offset + size).min(len));
        if end <= offset {
            break;
        }
        if let Some(prepared) = job.prepared[ordinal].take() {
            let mut io = crate::WorkerIo {
                socket,
                tun,
                rx,
                stats: Some(stats),
                device: Some(device),
            };
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
    let channel = &shared.channels[index];

    loop {
        if shutdown_requested() && channel.is_empty() {
            break;
        }
        let now = Instant::now();
        let socket = shared.socket();
        let mut busy = false;

        if let Some(active) = socket.as_deref() {
            device.for_each_peer(|peer| {
                let mut io = crate::WorkerIo {
                    socket: active,
                    tun: &tun,
                    rx: &mut rx,
                    stats: Some(&shared.stats),
                    device: Some(device.as_ref()),
                };
                let mut context = IoContext::new(&mut rng, now, &mut scratch, &mut io);
                let _ = device.flush_control(peer, &mut context);
            });
            rekey.clear();
            let mut drained = BbrBatch::new();
            device.for_each_peer(|peer| {
                if device.bbr_drain_into(peer, now, crate::MAX_BATCH_SIZE, &mut drained) == 0 {
                    return;
                }
                let slices: Vec<&[u8]> = drained.iter().collect();
                crate::send_run_inner(
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
            busy |= pump_tun_tx(
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
                let (_, dropped) = batch.flush_with(active, &batch_buffer, |peer, bytes| {
                    device.on_send_drop(peer, bytes);
                });
                if dropped > 0 {
                    shared
                        .stats
                        .tx_drops
                        .fetch_add(dropped as u64, Ordering::Relaxed);
                }
            }
            for peer in &rekey {
                let mut io = crate::WorkerIo {
                    socket: active,
                    tun: &tun,
                    rx: &mut rx,
                    stats: Some(&shared.stats),
                    device: Some(device.as_ref()),
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
                    &shared.stats,
                );
                channel.release(job.slot);
            }
            rx.flush(&tun);
            let errors = rx.take_errors();
            if errors > 0 {
                shared
                    .stats
                    .drops_tun
                    .fetch_add(errors as u64, Ordering::Relaxed);
            }
        } else {
            // Поток приёма уже снял сокет (остановка или его падение):
            // дочитать очередь и вернуть слоты в пул.
            let drained = drain_without_socket(channel);
            if drained > 0 {
                log::debug!(
                    "crypto worker {index} dropped {drained} queued jobs: the rx socket is gone"
                );
            }
        }

        let (released, leaked) = channel.drain_reclaimed();
        if leaked > 0 {
            shared
                .stats
                .pool_violations
                .fetch_add(leaked as u64, Ordering::Relaxed);
        }

        if !busy && released == 0 {
            let timeout = crate::poll_timeout_ms(Instant::now(), device.next_deadline());
            channel.wait(tun.fd(), timeout);
        }
    }

    rx.flush(&tun);
    let errors = rx.take_errors();
    if errors > 0 {
        shared
            .stats
            .drops_tun
            .fetch_add(errors as u64, Ordering::Relaxed);
    }
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

    fn control_packet() -> DetectedPacket {
        DetectedPacket {
            kind: MessageKind::Initiation,
            padding: 0,
            body_len: umbrawg_proto::messages::INITIATION_SIZE,
        }
    }

    #[test]
    fn control_queue_is_bounded_and_keeps_data_channels_free() {
        let shared = SharedRx::new(1, RxSchedule::Peer, DEFAULT_QUEUE_DEPTH).unwrap();
        let source: SocketAddr = "10.0.0.9:1234".parse().unwrap();
        let payload = vec![0x5a; 256];
        for _ in 0..CONTROL_QUEUE_CAPACITY {
            assert!(shared.controls.push(&payload, source, control_packet()));
        }
        assert_eq!(shared.controls.pending(), CONTROL_QUEUE_CAPACITY);
        assert!(!shared.controls.push(&payload, source, control_packet()));
        assert_eq!(shared.channels[0].available(), DEFAULT_QUEUE_DEPTH);

        let mut cursor = 0;
        publish(&shared, &mut cursor, None, 7u64);
        assert_eq!(drain(&shared), vec![vec![7u64]]);

        let job = shared.controls.pop().expect("queued control");
        assert_eq!(job.len, payload.len());
        assert_eq!(&job.buffer[..4], &payload[..4]);
        assert_eq!(job.source, source);
        assert_eq!(job.detected.kind, MessageKind::Initiation);
        shared.controls.recycle(job);
        assert_eq!(shared.controls.pending(), CONTROL_QUEUE_CAPACITY - 1);
        assert!(shared.controls.push(&payload, source, control_packet()));
    }

    #[test]
    fn oversized_control_packet_is_rejected() {
        let shared = SharedRx::new(1, RxSchedule::Peer, DEFAULT_QUEUE_DEPTH).unwrap();
        let payload = vec![0u8; MAX_PACKET + 1];
        let source: SocketAddr = "10.0.0.9:1234".parse().unwrap();
        assert!(!shared.controls.push(&payload, source, control_packet()));
        assert!(shared.controls.is_empty());
    }

    #[test]
    fn worker_count_defaults_to_half_the_cores() {
        // Большой хост — прежняя формула: половина ядер, не больше четырёх.
        assert_eq!(crypto_worker_count_for(None, 6, Some(64 << 30)), 3);
        assert_eq!(crypto_worker_count_for(None, 12, Some(64 << 30)), 4);
        assert_eq!(crypto_worker_count_for(None, 2, Some(64 << 30)), 1);
        assert_eq!(crypto_worker_count_for(None, 1, Some(64 << 30)), 1);
        // Небольшой хост (≤ 8 ГиБ) — 2: 51 демон на 4 ГБ иначе упирается в OOM.
        assert_eq!(crypto_worker_count_for(None, 6, Some(4 << 30)), 2);
        assert_eq!(crypto_worker_count_for(None, 12, Some(4 << 30)), 2);
        assert_eq!(crypto_worker_count_for(None, 2, Some(4 << 30)), 1);
        assert_eq!(crypto_worker_count_for(None, 3, Some(4 << 30)), 1);
        // Неизвестный объём RAM — как на большом хосте.
        assert_eq!(crypto_worker_count_for(None, 6, None), 3);
    }

    #[test]
    fn worker_count_honours_override() {
        assert_eq!(crypto_worker_count_for(Some("2"), 6, Some(4 << 30)), 2);
        assert_eq!(crypto_worker_count_for(Some("0"), 6, None), 3);
        assert_eq!(crypto_worker_count_for(Some("99"), 6, None), 6);
        assert_eq!(crypto_worker_count_for(Some("99"), 64, None), MAX_WORKERS);
        assert_eq!(crypto_worker_count_for(Some("abc"), 6, None), 3);
    }

    #[test]
    fn queue_depth_defaults_to_the_minimum() {
        // Дефолт — минимальная глубина: 51 демон на 50 пиров не должен
        // упираться в память пула (см. `DEFAULT_QUEUE_DEPTH`).
        assert_eq!(DEFAULT_QUEUE_DEPTH, MIN_QUEUE_DEPTH);
        assert_eq!(queue_depth_from_env(None), Ok(DEFAULT_QUEUE_DEPTH));
        assert_eq!(queue_depth_from_env(Some("")), Ok(DEFAULT_QUEUE_DEPTH));
        assert_eq!(queue_depth_from_env(Some("   ")), Ok(DEFAULT_QUEUE_DEPTH));
    }

    #[test]
    fn queue_depth_accepts_valid_powers_of_two() {
        for value in ["64", "128", "256", "512", "1024", " 256 ", "\t512\n"] {
            let depth = queue_depth_from_env(Some(value)).expect("valid depth");
            assert_eq!(depth, value.trim().parse::<usize>().unwrap());
            assert!(valid_queue_depth(depth));
        }
    }

    #[test]
    fn queue_depth_rejects_invalid_values() {
        for value in [
            "0",
            "1",
            "32",
            "63",
            "65",
            "100",
            "255",
            "2048",
            "4096",
            "-64",
            "64 KiB",
            "abc",
            "99999999999999999999999",
        ] {
            let error = queue_depth_from_env(Some(value)).expect_err("invalid depth");
            assert!(error.contains("UMBRAWG_RX_QUEUE"), "{value}: {error}");
        }
    }

    #[test]
    fn queue_depth_checks_range_boundaries() {
        assert_eq!(queue_depth_from_env(Some("64")), Ok(MIN_QUEUE_DEPTH));
        assert_eq!(queue_depth_from_env(Some("1024")), Ok(MAX_QUEUE_DEPTH));
        assert!(queue_depth_from_env(Some("32")).is_err());
        assert!(queue_depth_from_env(Some("2048")).is_err());
        assert!(valid_queue_depth(MIN_QUEUE_DEPTH));
        assert!(valid_queue_depth(MAX_QUEUE_DEPTH));
        assert!(!valid_queue_depth(MIN_QUEUE_DEPTH - 1));
        assert!(!valid_queue_depth(MAX_QUEUE_DEPTH * 2));
        assert!(!valid_queue_depth(100));
    }

    fn mib(bytes: usize) -> usize {
        bytes.div_ceil(1024 * 1024)
    }

    #[test]
    fn queue_memory_scales_with_depth() {
        assert_eq!(queue_bytes(MIN_QUEUE_DEPTH), 64 * MAX_PACKET);
        assert_eq!(mib(queue_bytes(64)), 4);
        assert_eq!(mib(queue_bytes(128)), 8);
        assert_eq!(mib(queue_bytes(256)), 16);
        assert_eq!(mib(queue_bytes(512)), 32);
        assert_eq!(mib(queue_bytes(1024)), 64);
        assert_eq!(mib(queue_bytes(DEFAULT_QUEUE_DEPTH)), 4);
        assert_eq!(mib(queue_bytes(DEFAULT_QUEUE_DEPTH) * 4), 16);
    }

    #[test]
    fn pool_bytes_is_the_upper_bound_for_all_workers() {
        assert_eq!(pool_bytes(1, MIN_QUEUE_DEPTH), 64 * MAX_PACKET as u64);
        assert_eq!(
            pool_bytes(4, DEFAULT_QUEUE_DEPTH),
            4 * 64 * MAX_PACKET as u64
        );
        assert_eq!(pool_bytes(0, DEFAULT_QUEUE_DEPTH), 0);
    }

    #[test]
    fn pool_budget_warns_above_a_quarter_of_available_memory() {
        let pool = pool_bytes(4, DEFAULT_QUEUE_DEPTH);
        assert!(!pool_over_budget(pool, pool * 4));
        assert!(pool_over_budget(pool, pool * 4 - 1));
        assert!(pool_over_budget(pool, pool));
        assert!(!pool_over_budget(0, 1));
        // Переполнение не паникует и не даёт ложного «влезает».
        assert!(pool_over_budget(u64::MAX, u64::MAX));
        assert!(!pool_over_budget(1, 4));
        assert!(pool_over_budget(2, 4));
    }

    #[test]
    fn parallel_config_reads_queue_depth_from_env() {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let names = [
            "UMBRAWG_PARALLEL_RX",
            "UMBRAWG_RX_WORKERS",
            "UMBRAWG_RX_SCHED",
            "UMBRAWG_RX_QUEUE",
            "UMBRAWG_THREADS",
        ];
        let saved: Vec<(&str, Option<String>)> = names
            .iter()
            .map(|name| (*name, std::env::var(name).ok()))
            .collect();
        std::env::set_var("UMBRAWG_PARALLEL_RX", "1");
        std::env::set_var("UMBRAWG_RX_WORKERS", "2");
        std::env::set_var("UMBRAWG_RX_SCHED", "peer");
        std::env::set_var("UMBRAWG_RX_QUEUE", "64");
        std::env::remove_var("UMBRAWG_THREADS");
        let config = ParallelConfig::from_env(8)
            .expect("valid env")
            .expect("parallel rx is enabled");
        assert_eq!(config.workers, 2);
        assert_eq!(config.sched, RxSchedule::Peer);
        assert_eq!(config.queue_depth, 64);
        // `UMBRAWG_RX_WORKERS` главнее общей ручки числа потоков.
        std::env::set_var("UMBRAWG_THREADS", "4");
        assert_eq!(ParallelConfig::from_env(8).unwrap().unwrap().workers, 2);
        // Без `UMBRAWG_RX_WORKERS` параллельный приём уважает `UMBRAWG_THREADS`.
        std::env::remove_var("UMBRAWG_RX_WORKERS");
        assert_eq!(ParallelConfig::from_env(8).unwrap().unwrap().workers, 4);
        // Пустой `UMBRAWG_RX_WORKERS` — тоже отсутствие значения.
        std::env::set_var("UMBRAWG_RX_WORKERS", "  ");
        assert_eq!(ParallelConfig::from_env(8).unwrap().unwrap().workers, 4);
        // Нечисловое значение не подменяется дефолтом молча: берётся
        // `UMBRAWG_THREADS`, о подмене пишется warn.
        std::env::set_var("UMBRAWG_RX_WORKERS", "abc");
        std::env::set_var("UMBRAWG_THREADS", "3");
        assert_eq!(ParallelConfig::from_env(8).unwrap().unwrap().workers, 3);
        // И без `UMBRAWG_THREADS` остаётся дефолт половины ядер.
        std::env::remove_var("UMBRAWG_THREADS");
        assert_eq!(ParallelConfig::from_env(8).unwrap().unwrap().workers, 4);
        std::env::set_var("UMBRAWG_THREADS", "4");
        std::env::set_var("UMBRAWG_RX_WORKERS", "2");
        std::env::set_var("UMBRAWG_RX_QUEUE", "100");
        let error = ParallelConfig::from_env(8).expect_err("invalid depth");
        assert!(error.contains("UMBRAWG_RX_QUEUE"));
        for (name, value) in saved {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
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
        let channel = WorkerChannel::new(128, MIN_QUEUE_DEPTH).unwrap();
        let slot = channel.allocate().unwrap();
        assert!(channel.write(slot, &[1, 2, 3]));
        assert!(channel.publish(job(slot)).0);
        let received = channel.pop().unwrap();
        assert_eq!(received.slot, slot);
        channel.release(received.slot);
        assert!(channel.allocate().is_some());
    }

    #[test]
    fn slot_buffers_are_allocated_lazily() {
        // Ни один слот не занимает 64 КиБ, пока в него не записали пакет.
        let channel = WorkerChannel::new(MAX_PACKET, MIN_QUEUE_DEPTH).unwrap();
        let slot = channel.allocate().unwrap();
        assert!(channel.buffers().get(slot, 0).is_empty());
        assert!(channel.write(slot, &[7u8; 3]));
        assert_eq!(channel.buffers().get(slot, 3).len(), 3);
        channel.release(slot);

        // Слот растёт до фактического размера.
        let capacity_after_first = channel.buffers().get(slot, 3).len();
        assert!(capacity_after_first <= 9_000);
        assert!(channel.write(slot, &[9u8; 9_000]));
        assert_eq!(channel.buffers().get(slot, 9_000).len(), 9_000);
        assert_eq!(&channel.buffers().get(slot, 3)[..3], &[9u8; 3]);

        // Повторная запись короткого пакета в тот же слот не сжимает буфер:
        // `get(slot, 9_000)` проходит `debug_assert` только если слота
        // по-прежнему хватает на 9 000 байт, а первые 4 байта — новые.
        assert!(channel.write(slot, &[1u8; 4]));
        let data = channel.buffers().get(slot, 9_000);
        assert_eq!(data.len(), 9_000, "слот не должен сжиматься");
        assert_eq!(&data[..4], &[1u8; 4]);
        assert_eq!(&data[4..9_000], &[9u8; 9_000 - 4]);
        channel.release(slot);

        // Верхняя граница всё ещё MAX_PACKET.
        assert!(!channel.write(slot, &[0u8; MAX_PACKET + 1]));
        assert!(channel.write(slot, &[0u8; MAX_PACKET]));
        assert_eq!(channel.buffers().get(slot, MAX_PACKET).len(), MAX_PACKET);
        channel.release(slot);
    }

    #[test]
    fn control_queue_keeps_a_requeued_job() {
        let shared = SharedRx::new(1, RxSchedule::Peer, DEFAULT_QUEUE_DEPTH).unwrap();
        let source: SocketAddr = "10.0.0.9:1234".parse().unwrap();
        let payload = vec![0x5a; 256];
        assert!(shared.controls.push(&payload, source, control_packet()));
        let job = shared.controls.pop().expect("queued control");
        shared.controls.requeue_front(job);
        assert_eq!(shared.controls.pending(), 1);
        let job = shared.controls.pop().expect("requeued control");
        assert_eq!(job.len, payload.len());
        assert_eq!(&job.buffer[..4], &payload[..4]);
        shared.controls.recycle(job);
        assert!(shared.controls.is_empty());
    }

    #[test]
    fn control_buffers_grow_to_the_packet_size() {
        let queue = ControlQueue::new(4).unwrap();
        let source: SocketAddr = "10.0.0.9:1234".parse().unwrap();
        assert!(queue.push(&[1u8; 200], source, control_packet()));
        let job = queue.pop().expect("control job");
        assert_eq!(job.buffer.len(), 200);
        assert!(job.buffer.capacity() < MAX_PACKET);
        queue.recycle(job);
    }

    #[test]
    fn control_queue_drains_in_one_pass() {
        let queue = ControlQueue::new(MIN_QUEUE_DEPTH).unwrap();
        let source: SocketAddr = "10.0.0.9:1234".parse().unwrap();
        for _ in 0..MIN_QUEUE_DEPTH {
            assert!(queue.push(&[7u8; 148], source, control_packet()));
        }
        // Один уже снятый job (как в `control_loop` на остановке) плюс
        // остаток очереди возвращаются в пул без ожиданий.
        let job = queue.pop().expect("first job");
        queue.recycle(job);
        queue.recycle_all();
        assert!(queue.is_empty());
        assert_eq!(queue.pending(), 0);
        assert_eq!(queue.free(), MIN_QUEUE_DEPTH);
        // Очередь снова принимает полный набор.
        for _ in 0..MIN_QUEUE_DEPTH {
            assert!(queue.push(&[7u8; 148], source, control_packet()));
        }
    }

    #[test]
    fn worker_drains_the_channel_without_a_socket() {
        let channel = WorkerChannel::new(MAX_PACKET, MIN_QUEUE_DEPTH).unwrap();
        for marker in 0..MIN_QUEUE_DEPTH as u64 {
            let slot = channel.allocate().expect("free slot");
            assert!(channel.write(slot, &marker.to_le_bytes()));
            assert!(channel.publish(job(slot)).0);
        }
        assert_eq!(channel.pending(), MIN_QUEUE_DEPTH);
        assert_eq!(channel.available(), 0);
        // Сокета уже нет: дочитываем одним проходом и возвращаем слоты.
        assert_eq!(drain_without_socket(&channel), MIN_QUEUE_DEPTH);
        assert!(channel.is_empty());
        assert_eq!(channel.available(), MIN_QUEUE_DEPTH);
        // Повторный вызов на пустом канале ничего не ломает.
        assert_eq!(drain_without_socket(&channel), 0);
        assert_eq!(channel.available(), MIN_QUEUE_DEPTH);
    }

    #[test]
    fn control_only_datagram_does_not_publish_a_job() {
        // Initiation с параметрами по умолчанию: type=1 (H1 = 1..=1) и ровно
        // INITIATION_SIZE байт. Классификация не требует ключей.
        let device =
            umbrawg_device::Device::new(umbrawg_device::DeviceConfig::default()).expect("device");
        let shared = SharedRx::new(2, RxSchedule::Peer, MIN_QUEUE_DEPTH).unwrap();
        let snapshot = device.incoming_snapshot();
        let mut packet = [0u8; umbrawg_proto::messages::INITIATION_SIZE];
        packet[..4].copy_from_slice(&1u32.to_le_bytes());
        let len = packet.len();
        let mut cursor = 0usize;
        enqueue_segments(
            &device,
            &shared,
            &mut cursor,
            &snapshot,
            Instant::now(),
            &mut packet,
            len,
            None,
            "10.0.0.9:1234".parse().unwrap(),
        );
        assert_eq!(shared.stats.controls.load(Ordering::Relaxed), 1);
        assert_eq!(shared.controls.pending(), 1);
        // Управляющий пакет уже в своей очереди: задание воркеру не нужно,
        // иначе он тратил бы слот пула и пробуждение на пустую расшифровку.
        assert_eq!(shared.stats.enqueued.load(Ordering::Relaxed), 0);
        assert!(shared.channels.iter().all(|channel| channel.pending() == 0));
        assert!(shared
            .channels
            .iter()
            .all(|channel| channel.available() == MIN_QUEUE_DEPTH));
    }

    #[test]
    fn channel_reports_overflow_and_keeps_buffers() {
        let channel = WorkerChannel::new(128, MIN_QUEUE_DEPTH).unwrap();
        let mut published = 0;
        while let Some(slot) = channel.allocate() {
            if !channel.publish(job(slot)).0 {
                break;
            }
            published += 1;
        }
        assert_eq!(published, MIN_QUEUE_DEPTH);
        assert!(channel.allocate().is_none());
        let received = channel.pop().unwrap();
        channel.release(received.slot);
        assert!(channel.allocate().is_some());
    }

    #[test]
    fn shared_rx_uses_configured_depth() {
        for depth in [MIN_QUEUE_DEPTH, 128, 512] {
            let shared = SharedRx::new(2, RxSchedule::Peer, depth).unwrap();
            for channel in &shared.channels {
                assert_eq!(channel.depth(), depth);
                assert_eq!(channel.available(), depth);
            }
            let key = peer_key(5);
            let worker = peer_worker(&key, shared.channels.len());
            let mut cursor = 0usize;
            for marker in 0..depth as u64 {
                publish(&shared, &mut cursor, Some(key), marker);
            }
            assert_eq!(shared.channels[worker].pending(), depth);
            assert_eq!(shared.channels[worker].available(), 0);
            assert_eq!(shared.stats.drops_queue.load(Ordering::Relaxed), 0);
            publish(&shared, &mut cursor, Some(key), 0);
            assert_eq!(shared.stats.drops_queue.load(Ordering::Relaxed), 1);
            assert_eq!(shared.channels[worker].pending(), depth);
            let drained = drain(&shared);
            assert_eq!(drained[worker].len(), depth);
            assert_eq!(shared.channels[worker].available(), depth);
            assert_eq!(shared.channels[worker].pending(), 0);
            assert_eq!(shared.channels[worker].drain_reclaimed(), (0, 0));
        }
    }

    #[test]
    fn pool_and_ring_follow_depth() {
        for depth in [MIN_QUEUE_DEPTH, 128, 256, MAX_QUEUE_DEPTH] {
            let channel = WorkerChannel::new(16, depth).unwrap();
            assert_eq!(channel.depth(), depth);
            assert_eq!(channel.available(), depth);
            let mut slots = Vec::new();
            while let Some(slot) = channel.allocate() {
                assert!(channel.write(slot, &[7u8; 16]));
                assert!(channel.publish(job(slot)).0);
                slots.push(slot);
            }
            assert_eq!(slots.len(), depth);
            assert_eq!(channel.pending(), depth);
            assert_eq!(channel.available(), 0);
            for _ in 0..depth {
                let received = channel.pop().expect("job is queued");
                assert!(channel.release(received.slot));
            }
            assert_eq!(channel.pending(), 0);
            assert_eq!(channel.available(), depth);
            assert_eq!(channel.drain_reclaimed(), (0, 0));
        }
    }

    #[test]
    fn invalid_depth_is_an_error_not_a_panic() {
        for depth in [0, 1, 32, 63, 65, 100, 2048, 4096] {
            assert!(SharedRx::new(1, RxSchedule::Peer, depth).is_err());
            assert!(WorkerChannel::new(64, depth).is_err());
        }
    }

    #[test]
    fn smallest_depth_serves_jobs() {
        let shared = SharedRx::new(1, RxSchedule::Peer, MIN_QUEUE_DEPTH).unwrap();
        let mut cursor = 0usize;
        for marker in 0..MIN_QUEUE_DEPTH as u64 {
            publish(&shared, &mut cursor, None, marker);
        }
        assert_eq!(shared.channels[0].pending(), MIN_QUEUE_DEPTH);
        let drained = drain(&shared);
        assert_eq!(drained[0].len(), MIN_QUEUE_DEPTH);
        assert_eq!(shared.channels[0].available(), MIN_QUEUE_DEPTH);
    }

    #[test]
    fn queue_mode_reports_drops_when_all_workers_are_full() {
        let depth = MIN_QUEUE_DEPTH;
        let shared = SharedRx::new(2, RxSchedule::Queue, depth).unwrap();
        let mut cursor = 0usize;
        for marker in 0..depth * 2 {
            publish(&shared, &mut cursor, None, marker as u64);
        }
        assert_eq!(shared.stats.drops_queue.load(Ordering::Relaxed), 0);
        assert!(shared
            .channels
            .iter()
            .all(|channel| channel.pending() == depth));
        publish(&shared, &mut cursor, None, 0);
        assert_eq!(shared.stats.drops_queue.load(Ordering::Relaxed), 1);
        assert_eq!(
            shared.stats.enqueued.load(Ordering::Relaxed),
            (depth * 2) as u64
        );
    }

    #[test]
    fn least_loaded_worker_is_preferred() {
        assert_eq!(super::select_worker(&[3, 0, 1], 0), 1);
        assert_eq!(super::select_worker(&[2, 1, 1], 0), 1);
        assert_eq!(super::select_worker(&[2, 2, 2], 1), 1);
        assert_eq!(super::select_worker(&[4, 4, 0], 2), 2);
    }

    #[test]
    fn rx_schedule_defaults_to_peer() {
        assert_eq!(RxSchedule::from_env(None), RxSchedule::Peer);
        assert_eq!(RxSchedule::from_env(Some("")), RxSchedule::Peer);
        assert_eq!(RxSchedule::from_env(Some("peer")), RxSchedule::Peer);
        assert_eq!(RxSchedule::from_env(Some(" PEER ")), RxSchedule::Peer);
        assert_eq!(RxSchedule::from_env(Some("unknown")), RxSchedule::Peer);
        assert_eq!(RxSchedule::from_env(Some("queue")), RxSchedule::Queue);
        assert_eq!(RxSchedule::from_env(Some(" Queue ")), RxSchedule::Queue);
        assert_eq!(RxSchedule::Peer.as_str(), "peer");
        assert_eq!(RxSchedule::Queue.as_str(), "queue");
        assert_eq!(RxSchedule::default(), RxSchedule::Peer);
    }

    fn peer_key(seed: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&seed.to_le_bytes());
        key[31] = 0x5a;
        key
    }

    fn keys_by_worker(workers: usize) -> Vec<[u8; 32]> {
        let mut keys: Vec<Option<[u8; 32]>> = vec![None; workers];
        let mut found = 0;
        for seed in 0..10_000u32 {
            let key = peer_key(seed);
            let worker = peer_worker(&key, workers);
            if keys[worker].is_none() {
                keys[worker] = Some(key);
                found += 1;
                if found == workers {
                    break;
                }
            }
        }
        assert_eq!(found, workers, "each worker has a peer key");
        keys.into_iter()
            .map(|key| key.expect("key found"))
            .collect()
    }

    fn publish(shared: &SharedRx, cursor: &mut usize, key: Option<[u8; 32]>, marker: u64) {
        let pinned = key.map(|key| peer_worker(&key, shared.channels.len()));
        let data = marker.to_le_bytes();
        publish_job(
            shared,
            cursor,
            &data,
            "10.0.0.1:1000".parse().unwrap(),
            None,
            [const { None }; MAX_SEGMENTS],
            pinned,
        );
    }

    fn drain(shared: &SharedRx) -> Vec<Vec<u64>> {
        shared
            .channels
            .iter()
            .map(|channel| {
                let mut markers = Vec::new();
                while let Some(job) = channel.pop() {
                    let len = job.len as usize;
                    let data = channel.buffers().get(job.slot, len);
                    let mut bytes = [0u8; 8];
                    bytes[..len].copy_from_slice(&data[..len]);
                    markers.push(u64::from_le_bytes(bytes));
                    channel.release(job.slot);
                }
                markers
            })
            .collect()
    }

    #[test]
    fn peer_worker_is_stable() {
        for workers in 1..=MAX_WORKERS {
            let key = peer_key(7);
            let worker = peer_worker(&key, workers);
            for _ in 0..100 {
                assert_eq!(peer_worker(&key, workers), worker);
            }
            assert!(worker < workers);
        }
    }

    #[test]
    fn peer_worker_spreads_distinct_peers() {
        for workers in 2..=MAX_WORKERS {
            let keys = keys_by_worker(workers);
            let mut used = vec![false; workers];
            for (expected, key) in keys.iter().enumerate() {
                let worker = peer_worker(key, workers);
                assert_eq!(worker, expected);
                used[worker] = true;
            }
            assert!(used.iter().all(|used| *used));
        }
    }

    #[test]
    fn peer_mode_keeps_one_worker_per_peer_in_order() {
        let shared = SharedRx::new(4, RxSchedule::Peer, DEFAULT_QUEUE_DEPTH).unwrap();
        let mut cursor = 0usize;
        let key = peer_key(11);
        let worker = peer_worker(&key, shared.channels.len());
        for marker in 0..25u64 {
            publish(&shared, &mut cursor, Some(key), marker);
        }
        let drained = drain(&shared);
        for (index, markers) in drained.iter().enumerate() {
            if index == worker {
                assert_eq!(*markers, (0..25u64).collect::<Vec<_>>());
            } else {
                assert!(markers.is_empty(), "worker {index} got foreign jobs");
            }
        }
        assert_eq!(shared.stats.enqueued.load(Ordering::Relaxed), 25);
        assert_eq!(shared.stats.drops_queue.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn peer_mode_spreads_peers_over_workers() {
        let workers = 4;
        let shared = SharedRx::new(workers, RxSchedule::Peer, DEFAULT_QUEUE_DEPTH).unwrap();
        let keys = keys_by_worker(workers);
        let mut cursor = 0usize;
        for round in 0..6u64 {
            for key in &keys {
                publish(&shared, &mut cursor, Some(*key), round);
            }
        }
        let drained = drain(&shared);
        assert_eq!(drained.len(), workers);
        for (worker, markers) in drained.iter().enumerate() {
            assert_eq!(*markers, (0..6u64).collect::<Vec<_>>(), "worker {worker}");
        }
    }

    #[test]
    fn queue_mode_distributes_jobs_across_workers() {
        let shared = SharedRx::new(2, RxSchedule::Queue, DEFAULT_QUEUE_DEPTH).unwrap();
        let mut cursor = 0usize;
        let key = peer_key(3);
        for marker in 0..10u64 {
            publish(&shared, &mut cursor, Some(key), marker);
        }
        let drained = drain(&shared);
        assert!(drained.iter().all(|markers| !markers.is_empty()));
        assert_eq!(drained.iter().map(Vec::len).sum::<usize>(), 10);
    }

    #[test]
    fn peer_mode_drops_on_backpressure_without_moving() {
        let workers = 3;
        let depth = MIN_QUEUE_DEPTH;
        let shared = SharedRx::new(workers, RxSchedule::Peer, depth).unwrap();
        let keys = keys_by_worker(workers);
        let mut cursor = 0usize;
        let busy = 0usize;
        let busy_key = keys[busy];
        let other_key = keys[1];
        for marker in 0..depth as u64 {
            publish(&shared, &mut cursor, Some(busy_key), marker);
        }
        assert_eq!(shared.channels[busy].pending(), depth);
        let before = shared.stats.enqueued.load(Ordering::Relaxed);
        publish(&shared, &mut cursor, Some(busy_key), 9_999);
        assert_eq!(shared.stats.drops_queue.load(Ordering::Relaxed), 1);
        assert_eq!(shared.stats.enqueued.load(Ordering::Relaxed), before);
        assert_eq!(shared.channels[busy].pending(), depth);
        assert_eq!(shared.channels[1].pending(), 0);
        publish(&shared, &mut cursor, Some(other_key), 1_000);
        assert_eq!(shared.channels[1].pending(), 1);
        assert_eq!(shared.stats.drops_queue.load(Ordering::Relaxed), 1);
        let drained = shared.channels[busy].pop().expect("job is queued");
        shared.channels[busy].release(drained.slot);
        publish(&shared, &mut cursor, Some(busy_key), 10_000);
        assert_eq!(shared.channels[busy].pending(), depth);
        assert_eq!(shared.stats.drops_queue.load(Ordering::Relaxed), 1);
        let markers = drain(&shared)[busy].clone();
        assert_eq!(markers.first(), Some(&1));
        assert_eq!(markers.last(), Some(&10_000));
    }

    #[test]
    fn shared_channels_survive_concurrent_shutdown() {
        let depth = MIN_QUEUE_DEPTH;
        let shared = Arc::new(SharedRx::new(2, RxSchedule::Peer, depth).unwrap());
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
                        assert!(channel.pending() < channel.depth());
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

        let channel = Arc::new(WorkerChannel::new(64, MIN_QUEUE_DEPTH).unwrap());
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
                        channel.wait(idle_fd, IDLE_TIMEOUT_MS);
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
            let deadline = Instant::now() + Duration::from_secs(10);
            let slot = loop {
                if let Some(free) = channel.allocate() {
                    break free;
                }
                assert!(Instant::now() < deadline, "buffer is available");
                std::thread::yield_now();
            };
            let (published, _) = channel.publish(job(slot));
            assert!(published);
        }
        stop.store(true, Ordering::Release);
        assert_eq!(consumer.join().unwrap(), 100);
    }

    #[test]
    fn oversized_datagram_is_rejected() {
        let channel = WorkerChannel::new(16, MIN_QUEUE_DEPTH).unwrap();
        let slot = channel.allocate().unwrap();
        assert!(!channel.write(slot, &[0u8; 17]));
        assert!(channel.write(slot, &[0u8; 16]));
        channel.release(slot);
    }

    #[test]
    fn rejected_slot_returns_through_worker() {
        let depth = MIN_QUEUE_DEPTH;
        let channel = WorkerChannel::new(128, depth).unwrap();
        let mut slots = Vec::new();
        while let Some(slot) = channel.allocate() {
            slots.push(slot);
        }
        assert_eq!(slots.len(), depth);
        for slot in &slots[..depth - 1] {
            assert!(channel.jobs.push(job(*slot)).is_ok());
        }
        let held = slots[depth - 1];
        assert!(channel.reject(held));
        assert_eq!(channel.available(), 0);
        assert_eq!(channel.drain_reclaimed(), (1, 0));
        assert_eq!(channel.available(), 1);
        assert_eq!(channel.allocate(), Some(held));
        assert!(channel.release(held));
        while let Some(received) = channel.pop() {
            assert!(channel.release(received.slot));
        }
        assert_eq!(channel.available(), depth);
        let mut seen = Vec::new();
        while let Some(slot) = channel.allocate() {
            seen.push(slot);
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..depth as u32).collect::<Vec<_>>());
    }

    #[test]
    fn pool_survives_rejection_cycles() {
        let channel = WorkerChannel::new(64, MIN_QUEUE_DEPTH).unwrap();
        for _ in 0..1_000 {
            let slot = channel.allocate().unwrap();
            assert!(channel.reject(slot));
            assert_eq!(channel.drain_reclaimed(), (1, 0));
            assert_eq!(channel.available(), MIN_QUEUE_DEPTH);
        }
    }

    #[test]
    fn pool_keeps_all_slots_after_publish_cycles() {
        let channel = WorkerChannel::new(64, MIN_QUEUE_DEPTH).unwrap();
        for round in 0..10_000u32 {
            let slot = channel.allocate().expect("slot is free");
            assert!(channel.write(slot, &round.to_le_bytes()));
            let (published, _) = channel.publish(job(slot));
            assert!(published);
            let received = channel.pop().expect("job is queued");
            assert_eq!(received.slot, slot);
            assert!(channel.release(received.slot));
        }
        assert_eq!(channel.available(), MIN_QUEUE_DEPTH);
    }

    #[test]
    fn gro_chunks_split_large_datagrams() {
        let bounds: Vec<(usize, usize)> = GroChunks::new(65 * 100, Some(100)).collect();
        assert_eq!(bounds, vec![(0, 6_400), (6_400, 6_500)]);
        let many: Vec<(usize, usize)> = GroChunks::new(512 * 100, Some(100)).collect();
        assert_eq!(many.len(), 8);
        assert_eq!(many[7], (44_800, 51_200));
    }

    #[test]
    fn gro_chunks_cover_every_byte_once() {
        for len in [1usize, 50, 6_400, 6_401, 32 * 100, 512 * 100, 2_000 * 28] {
            for size in [1usize, 28, 100, 512, 1_400] {
                let mut expected = 0;
                let mut count = 0;
                for (start, end) in GroChunks::new(len, Some(size)) {
                    assert_eq!(start, expected);
                    assert!(end > start);
                    assert!(end - start <= size * MAX_SEGMENTS);
                    expected = end;
                    count += 1;
                }
                assert_eq!(expected, len);
                assert_eq!(count, len.div_ceil(size * MAX_SEGMENTS));
            }
        }
        assert_eq!(
            GroChunks::new(100, None).collect::<Vec<_>>(),
            vec![(0, 100)]
        );
        assert_eq!(GroChunks::new(0, Some(10)).count(), 0);
    }

    #[test]
    fn tx_batch_uses_transport_limit() {
        let source = include_str!("parallel.rs");
        let needle = concat!("TxBatch::new(", "TUN_BATCH)");
        assert!(!source.contains(needle));
    }

    #[test]
    fn worker_loop_leaves_housekeeping_to_rx() {
        let source = include_str!("parallel.rs");
        let worker_start = source
            .find("pub(crate) fn worker_loop(")
            .expect("worker_loop is defined");
        let worker_tail = &source[worker_start..];
        let tests_start = worker_tail.find("#[cfg(test)]").expect("tests module");
        let worker_body = &worker_tail[..tests_start];
        // The worker may only use the deadline to size its wait; timers and
        // FEC/ACK housekeeping stay in the rx thread.
        assert!(worker_body.contains("poll_timeout_ms"));
        assert!(!worker_body.contains("housekeeping("));
        assert!(!worker_body.contains("device.tick("));
        let rx_start = source
            .find("pub(crate) fn rx_loop(")
            .expect("rx_loop is defined");
        assert!(source[rx_start..worker_start].contains("housekeeping("));
    }

    #[test]
    fn housekeeping_interval_is_bounded() {
        assert!(HOUSEKEEPING_INTERVAL >= Duration::from_millis(1));
        assert!(HOUSEKEEPING_INTERVAL <= Duration::from_millis(50));
    }

    #[test]
    fn failing_thread_requests_shutdown() {
        let shared = SharedRx::new(1, RxSchedule::Peer, MIN_QUEUE_DEPTH).unwrap();
        assert!(shared.failure().is_none());
        shared.register_failure("rx stop".to_owned());
        assert_eq!(shared.failure().as_deref(), Some("rx stop"));
        assert!(crate::shutdown_requested());
        shared.register_failure("worker stop".to_owned());
        assert_eq!(shared.failure().as_deref(), Some("rx stop"));
    }

    #[test]
    fn supervisor_detects_early_exit() {
        assert_eq!(
            supervise(true, false),
            Some("rx thread exited unexpectedly")
        );
        assert_eq!(
            supervise(false, true),
            Some("crypto worker exited unexpectedly")
        );
        assert_eq!(supervise(false, false), None);
    }
}
