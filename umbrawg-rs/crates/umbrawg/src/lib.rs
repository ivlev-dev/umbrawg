//! Каркас демона `umbrawg`.

use std::env;
use std::fs;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use umbrawg_transport::{AddressFamily, OpenOptions, Socket};
use umbrawg_tun::{TunConfig, TunSet};
use umbrawg_uapi::{UapiListener, socket_dir};
use umbrawg_uapi::{DeviceControl, DeviceSnapshot, SetRequest};
use umbrawg_uapi::UapiError;

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
            .unwrap_or(default),
        None => default,
    }
}

/// Запрашивает завершение работы.
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Проверяет, запрошено ли завершение.
pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Устанавливает обработчики сигналов.
pub fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
    }
}

extern "C" fn signal_handler(_signal: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Заглушка управления устройством.
pub struct StubDevice;

impl DeviceControl for StubDevice {
    fn snapshot(&self) -> DeviceSnapshot {
        // TODO: подключить реальное состояние umbrawg-device.
        DeviceSnapshot::default()
    }

    fn apply(&self, _request: SetRequest) -> Result<(), UapiError> {
        // TODO: делегировать umbrawg-device после его реализации.
        Err(UapiError::Internal("устройство не реализовано".to_owned()))
    }
}

/// Запускает демон.
pub fn run(ifname: &str, foreground: bool) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: согласовать имена переменных окружения с umbrawg-uapi (UWG_RUNTIME_DIR).
    if let Ok(value) = env::var("UMBRAWG_RUNTIME_DIR") {
        env::set_var("UWG_RUNTIME_DIR", value);
    }

    install_signal_handlers();

    if !foreground {
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                return Err(Box::new(std::io::Error::last_os_error()));
            }
            if pid > 0 {
                process::exit(0);
            }
            libc::setsid();
            let devnull = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")?;
            let fd = std::os::fd::AsRawFd::as_raw_fd(&devnull);
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }

    let available = thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    let requested = env::var("UMBRAWG_THREADS").ok();
    let workers = worker_count(requested.as_deref(), available);

    let config = TunConfig::new(ifname).with_multi_queue(true);
    let tun_set = TunSet::open(&config, workers)?;

    let mut handles = Vec::new();
    for tun in tun_set.into_queues() {
        let socket = Socket::open(OpenOptions::new(AddressFamily::Ipv4).reuse_port(true))?;
        let handle = thread::spawn(move || {
            let _tun = tun;
            let _socket = socket;
            while !shutdown_requested() {
                thread::sleep(Duration::from_millis(100));
            }
        });
        handles.push(handle);
    }

    let listener = UapiListener::bind(&socket_dir(), ifname)?;
    let device = std::sync::Arc::new(StubDevice);
    let server_handle = listener.spawn(device)?;

    while !shutdown_requested() {
        thread::sleep(Duration::from_millis(100));
    }

    server_handle.join()?;
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
        let args = parse_args(vec!["wg0".to_owned(), "--foreground".to_owned()]).unwrap();
        assert_eq!(args.ifname.as_deref(), Some("wg0"));
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
        assert_eq!(worker_count(None, 1), 1);
    }

    #[test]
    fn worker_count_override() {
        assert_eq!(worker_count(Some("3"), 8), 3);
        assert_eq!(worker_count(Some("bad"), 8), 4);
        assert_eq!(worker_count(Some("0"), 8), 4);
    }

    #[test]
    fn shutdown_flag() {
        // Сбрасываем глобальное состояние на всякий случай.
        SHUTDOWN.store(false, Ordering::SeqCst);
        assert!(!shutdown_requested());
        request_shutdown();
        assert!(shutdown_requested());
        SHUTDOWN.store(false, Ordering::SeqCst);
    }
}
