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
    println!("  UMBRAWG_LOG_LEVEL     уровень логирования");
    println!("  UMBRAWG_RUNTIME_DIR   каталог сокетов управления");
}
