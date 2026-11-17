use std::process;

fn main() {
    let args = match umbrawg::parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("umbrawg: {error}");
            eprintln!("Использование: umbrawg [ПАРАМЕТРЫ] <интерфейс>");
            process::exit(2);
        }
    };

    if args.version {
        println!("umbrawg {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.help {
        print_help();
        return;
    }

    let ifname = args.ifname.expect("имя интерфейса проверено");

    env_logger::Builder::from_env(
        env_logger::Env::new()
            .filter("UMBRAWG_LOG_LEVEL")
            .default_filter_or("info"),
    )
    .init();

    if let Err(error) = umbrawg::run(&ifname, args.foreground) {
        eprintln!("umbrawg: {error}");
        process::exit(1);
    }
}

fn print_help() {
    println!("Использование: umbrawg [ПАРАМЕТРЫ] <интерфейс>");
    println!();
    println!("Параметры:");
    println!("  -f, --foreground   запуск на переднем плане");
    println!("  -v, --version      показать версию");
    println!("  -h, --help         показать эту справку");
    println!();
    println!("Переменные окружения:");
    println!("  UMBRAWG_THREADS       число рабочих потоков");
    println!("  UMBRAWG_SOCKET_BUFFER размер буферов UDP-сокета в байтах: 212 КиБ..64 МиБ (4 МиБ)");
    println!("  UMBRAWG_PARALLEL_RX   1 — параллельный приём (RX-поток + крипто-воркеры)");
    println!("  UMBRAWG_RX_WORKERS    число крипто-воркеров параллельного приёма");
    println!("  UMBRAWG_RX_SCHED      выбор воркера: peer (по умолчанию) или queue");
    println!("  UMBRAWG_RX_QUEUE      глубина очереди воркера: 64..1024, степень двойки (256)");
    println!("  UMBRAWG_RX_STATS      1 — выводить счётчики приёма раз в 5 секунд");
    println!("  UMBRAWG_LOG_LEVEL     уровень логирования");
    println!("  UMBRAWG_RUNTIME_DIR   каталог сокетов управления");
}
