use crate::command::{CommandRunner, CommandSpec, SystemRunner};
use crate::config::QuickConfig;
use crate::dns;
use crate::error::{QuickError, QuickResult};
use crate::firewall;
use crate::mtu;
use crate::route;
use crate::save;
use crate::{
    DEFAULT_ROUTE_TABLE_START, DEFAULT_USERSPACE_IMPLEMENTATION, ENV_USERSPACE_IMPLEMENTATION,
    IP_PROGRAM, KERNEL_INTERFACE_TYPE, KERNEL_MODULE_PATH, RESOLVCONF_INTERFACE_ORDER,
    RESOLVCONF_RUN_DIR, UWG_PROGRAM,
};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const MAX_RULE_DELETIONS: usize = 1024;

/// `uwg setconf` reads the configuration from a file; `/dev/stdin` lets
/// `uwg-quick up` feed it through a pipe like the shell version's process
/// substitution does.
const CONFIGURATION_STDIN: &str = "/dev/stdin";

#[derive(Default)]
struct RunState {
    have_set_dns: bool,
    have_set_firewall: bool,
}

/// Entry point for the CLI.
pub fn run(subcommand: &str, config_argument: &str) -> QuickResult<()> {
    let config = QuickConfig::load(config_argument)?;
    let runner = SystemRunner;
    match subcommand {
        "up" => up(&config, &runner),
        "down" => down(&config, &runner),
        "save" => save_interface(&config, &runner),
        "strip" => {
            let output = config.strip_output();
            let mut stdout = io::stdout().lock();
            stdout.write_all(output.as_bytes())?;
            stdout.flush()?;
            Ok(())
        }
        other => Err(QuickError::die(format!("unknown subcommand `{other}'"))),
    }
}

pub fn up(config: &QuickConfig, runner: &dyn CommandRunner) -> QuickResult<()> {
    if interface_exists(&config.interface, runner) {
        return Err(QuickError::die(format!(
            "`{}' already exists",
            config.interface
        )));
    }
    let implementation = userspace_implementation();
    let mut state = RunState::default();
    let result = up_steps(config, runner, &implementation, &mut state);
    if result.is_err() {
        let _ = del_if(config, runner, &mut state);
    }
    result
}

fn up_steps(
    config: &QuickConfig,
    runner: &dyn CommandRunner,
    implementation: &str,
    state: &mut RunState,
) -> QuickResult<()> {
    add_if(config, runner, implementation)?;
    execute_hooks(&config.pre_up, config, runner)?;
    set_config(config, runner)?;
    for address in &config.addresses {
        add_address(config, address, runner)?;
    }
    set_mtu_up(config, runner)?;
    set_dns(config, runner, state)?;
    add_routes(config, runner, state)?;
    execute_hooks(&config.post_up, config, runner)
}

pub fn down(config: &QuickConfig, runner: &dyn CommandRunner) -> QuickResult<()> {
    ensure_wg_interface(config, runner)?;
    execute_hooks(&config.pre_down, config, runner)?;
    if config.save_config {
        save_config(config, runner)?;
    }
    let mut state = RunState::default();
    del_if(config, runner, &mut state)?;
    let _ = unset_dns(config, runner);
    let _ = remove_firewall(config, runner);
    execute_hooks(&config.post_down, config, runner)
}

pub fn save_interface(config: &QuickConfig, runner: &dyn CommandRunner) -> QuickResult<()> {
    ensure_wg_interface(config, runner)?;
    save_config(config, runner)
}

fn userspace_implementation() -> String {
    std::env::var(ENV_USERSPACE_IMPLEMENTATION)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_USERSPACE_IMPLEMENTATION.to_string())
}

fn interface_exists(interface: &str, runner: &dyn CommandRunner) -> bool {
    runner
        .capture(&quiet_capture(
            IP_PROGRAM,
            vec![
                "link".to_string(),
                "show".to_string(),
                "dev".to_string(),
                interface.to_string(),
            ],
        ))
        .map(|captured| !captured.stdout.is_empty())
        .unwrap_or(false)
}

fn ensure_wg_interface(config: &QuickConfig, runner: &dyn CommandRunner) -> QuickResult<()> {
    let output = runner
        .capture(
            &CommandSpec::new(UWG_PROGRAM).args(vec!["show".to_string(), "interfaces".to_string()]),
        )
        .map(|captured| captured.stdout_lossy())
        .unwrap_or_default();
    if output
        .split_ascii_whitespace()
        .any(|name| name == config.interface)
    {
        Ok(())
    } else {
        Err(QuickError::die(format!(
            "`{}' is not a WireGuard interface",
            config.interface
        )))
    }
}

fn add_if(
    config: &QuickConfig,
    runner: &dyn CommandRunner,
    implementation: &str,
) -> QuickResult<()> {
    add_if_with_module(
        config,
        runner,
        implementation,
        Path::new(KERNEL_MODULE_PATH).exists(),
    )
}

fn add_if_with_module(
    config: &QuickConfig,
    runner: &dyn CommandRunner,
    implementation: &str,
    kernel_module_present: bool,
) -> QuickResult<()> {
    let spec = echo_command(
        IP_PROGRAM,
        vec![
            "link".to_string(),
            "add".to_string(),
            config.interface.clone(),
            "type".to_string(),
            KERNEL_INTERFACE_TYPE.to_string(),
        ],
    );
    match runner.run_checked(&spec) {
        Ok(()) => Ok(()),
        Err(QuickError::Command { status, .. }) => {
            if kernel_module_present || !runner.command_exists(implementation) {
                return Err(QuickError::command(IP_PROGRAM, status));
            }
            eprintln!(
                "[!] Missing WireGuard (UmbraWG) kernel module. Falling back to slow userspace implementation."
            );
            let fallback = echo_command(implementation, vec![config.interface.clone()]);
            runner.run_checked(&fallback)
        }
        Err(error) => Err(error),
    }
}

fn set_config(config: &QuickConfig, runner: &dyn CommandRunner) -> QuickResult<()> {
    let mut data = config.wg_config.clone();
    data.push('\n');
    let spec = echo_command(
        UWG_PROGRAM,
        vec![
            "setconf".to_string(),
            config.interface.clone(),
            CONFIGURATION_STDIN.to_string(),
        ],
    )
    .stdin(data);
    runner.run_checked(&spec)
}

fn add_address(config: &QuickConfig, address: &str, runner: &dyn CommandRunner) -> QuickResult<()> {
    let spec = echo_command(
        IP_PROGRAM,
        vec![
            route::protocol_for(address).to_string(),
            "address".to_string(),
            "add".to_string(),
            address.to_string(),
            "dev".to_string(),
            config.interface.clone(),
        ],
    );
    runner.run_checked(&spec)
}

fn set_mtu_up(config: &QuickConfig, runner: &dyn CommandRunner) -> QuickResult<()> {
    if let Some(explicit) = &config.mtu {
        return set_link_mtu(config, runner, explicit);
    }

    let mut endpoint_mtus = Vec::new();
    if let Ok(endpoints) = runner.capture(&CommandSpec::new(UWG_PROGRAM).args(vec![
        "show".to_string(),
        config.interface.clone(),
        "endpoints".to_string(),
    ])) {
        for line in endpoints.stdout_lossy().lines() {
            let Some(host) = mtu::parse_endpoint(line) else {
                continue;
            };
            let route_output = runner
                .capture(&CommandSpec::new(IP_PROGRAM).args(vec![
                    "route".to_string(),
                    "get".to_string(),
                    host.to_string(),
                ]))
                .map(|captured| captured.stdout_lossy())
                .unwrap_or_default();
            if let Some(candidate) = route_mtu(&route_output, runner) {
                if candidate > 0 {
                    endpoint_mtus.push(candidate);
                }
            }
        }
    }

    let default_route_mtu = if endpoint_mtus.is_empty() {
        runner
            .capture(&CommandSpec::new(IP_PROGRAM).args(vec![
                "route".to_string(),
                "show".to_string(),
                "default".to_string(),
            ]))
            .ok()
            .and_then(|captured| {
                captured
                    .stdout_lossy()
                    .lines()
                    .next()
                    .map(ToOwned::to_owned)
            })
            .and_then(|line| route_mtu(&line, runner))
    } else {
        None
    };

    let value = mtu::auto_mtu(&endpoint_mtus, default_route_mtu);
    set_link_mtu(config, runner, &value.to_string())
}

fn route_mtu(output: &str, runner: &dyn CommandRunner) -> Option<u32> {
    if let Some(value) = mtu::extract_mtu(output) {
        return Some(value);
    }
    let device = mtu::extract_dev(output)?;
    let captured = runner
        .capture(&CommandSpec::new(IP_PROGRAM).args(vec![
            "link".to_string(),
            "show".to_string(),
            "dev".to_string(),
            device.to_string(),
        ]))
        .ok()?;
    mtu::extract_mtu(&captured.stdout_lossy())
}

fn set_link_mtu(config: &QuickConfig, runner: &dyn CommandRunner, value: &str) -> QuickResult<()> {
    let spec = echo_command(
        IP_PROGRAM,
        vec![
            "link".to_string(),
            "set".to_string(),
            "mtu".to_string(),
            value.to_string(),
            "up".to_string(),
            "dev".to_string(),
            config.interface.clone(),
        ],
    );
    runner.run_checked(&spec)
}

fn set_dns(
    config: &QuickConfig,
    runner: &dyn CommandRunner,
    state: &mut RunState,
) -> QuickResult<()> {
    set_dns_with(config, runner, state, dns::APPLY_ATTEMPTS, dns::APPLY_DELAY)
}

fn set_dns_with(
    config: &QuickConfig,
    runner: &dyn CommandRunner,
    state: &mut RunState,
    attempts: usize,
    delay: std::time::Duration,
) -> QuickResult<()> {
    if config.dns.is_empty() {
        return Ok(());
    }
    let payload = dns::payload(&config.dns, &config.dns_search);
    let spec = echo_command(
        "resolvconf",
        vec![
            "-a".to_string(),
            resolvconf_name(config),
            "-m".to_string(),
            "0".to_string(),
            "-x".to_string(),
        ],
    )
    .stdin(payload);
    dns::apply_with_retries(attempts, delay, || runner.run_checked(&spec))?;
    state.have_set_dns = true;
    Ok(())
}

fn unset_dns(config: &QuickConfig, runner: &dyn CommandRunner) -> QuickResult<()> {
    if config.dns.is_empty() {
        return Ok(());
    }
    let spec = echo_command(
        "resolvconf",
        vec!["-d".to_string(), resolvconf_name(config), "-f".to_string()],
    );
    runner.run_checked(&spec)
}

fn resolvconf_name(config: &QuickConfig) -> String {
    let prefix = fs::read_to_string(RESOLVCONF_INTERFACE_ORDER)
        .ok()
        .map(|contents| dns::interface_prefix(Some(&contents)))
        .unwrap_or_default();
    format!("{prefix}{}", config.interface)
}

fn add_routes(
    config: &QuickConfig,
    runner: &dyn CommandRunner,
    state: &mut RunState,
) -> QuickResult<()> {
    let captured = runner
        .capture(&CommandSpec::new(UWG_PROGRAM).args(vec![
            "show".to_string(),
            config.interface.clone(),
            "allowed-ips".to_string(),
        ]))
        .unwrap_or_default();
    let mut addresses = route::parse_allowed_ips(&captured.stdout_lossy());
    route::sort_allowed_ips(&mut addresses);
    for address in &addresses {
        add_route(config, address, runner, state)?;
    }
    Ok(())
}

fn add_route(
    config: &QuickConfig,
    address: &str,
    runner: &dyn CommandRunner,
    state: &mut RunState,
) -> QuickResult<()> {
    if config.table.as_deref() == Some("off") {
        return Ok(());
    }
    if let Some(table) = config
        .table
        .as_deref()
        .filter(|table| !table.is_empty() && *table != "auto")
    {
        let spec = echo_command(
            IP_PROGRAM,
            vec![
                route::protocol_for(address).to_string(),
                "route".to_string(),
                "add".to_string(),
                address.to_string(),
                "dev".to_string(),
                config.interface.clone(),
                "table".to_string(),
                table.to_string(),
            ],
        );
        return runner.run_checked(&spec);
    }
    if route::is_default_route(address) {
        return add_default(config, address, runner, state);
    }
    let lookup = quiet_capture(
        IP_PROGRAM,
        route::route_lookup_args(route::protocol_for(address), address, &config.interface),
    );
    let existing = runner
        .capture(&lookup)
        .map(|captured| captured.stdout)
        .unwrap_or_default();
    if existing.is_empty() {
        let spec = echo_command(
            IP_PROGRAM,
            route::route_add_args(route::protocol_for(address), address, &config.interface),
        );
        runner.run_checked(&spec)?;
    }
    Ok(())
}

fn add_default(
    config: &QuickConfig,
    address: &str,
    runner: &dyn CommandRunner,
    state: &mut RunState,
) -> QuickResult<()> {
    let table = match get_fwmark(&config.interface, runner) {
        Some(table) => table,
        None => {
            let table = allocate_table(runner)?;
            let spec = echo_command(
                UWG_PROGRAM,
                vec![
                    "set".to_string(),
                    config.interface.clone(),
                    "fwmark".to_string(),
                    table.to_string(),
                ],
            );
            runner.run_checked(&spec)?;
            table
        }
    };

    let protocol = route::protocol_for(address);
    for args in route::default_rule_args(protocol, table) {
        runner.run_checked(&echo_command(IP_PROGRAM, args))?;
    }
    runner.run_checked(&echo_command(
        IP_PROGRAM,
        route::default_route_args(protocol, address, &config.interface, table),
    ))?;

    let addresses_output = runner
        .capture(&quiet_capture(
            IP_PROGRAM,
            vec![
                "-o".to_string(),
                protocol.to_string(),
                "addr".to_string(),
                "show".to_string(),
                "dev".to_string(),
                config.interface.clone(),
            ],
        ))
        .map(|captured| captured.stdout_lossy())
        .unwrap_or_default();
    let addresses = firewall::parse_inet_addresses(&addresses_output);
    let marker = firewall::marker(&config.interface);

    if protocol == "-4" {
        runner.run_checked(&echo_command(
            "sysctl",
            vec![
                "-q".to_string(),
                "net.ipv4.conf.all.src_valid_mark=1".to_string(),
            ],
        ))?;
    }

    if runner.command_exists("nft") {
        let family = if protocol == "-6" { "ip6" } else { "ip" };
        let script = firewall::build_nft_commands(family, &config.interface, &addresses, table);
        runner.run_checked(&echo_command("nft", vec!["-f".to_string()]).stdin(script))?;
    } else {
        let script =
            firewall::build_iptables_restore(&marker, &config.interface, &addresses, table);
        let restore = if protocol == "-6" {
            "ip6tables-restore"
        } else {
            "iptables-restore"
        };
        runner.run_checked(&echo_command(restore, vec!["-n".to_string()]).stdin(script))?;
    }
    state.have_set_firewall = true;
    Ok(())
}

fn get_fwmark(interface: &str, runner: &dyn CommandRunner) -> Option<u32> {
    let captured = runner
        .capture(&CommandSpec::new(UWG_PROGRAM).args(vec![
            "show".to_string(),
            interface.to_string(),
            "fwmark".to_string(),
        ]))
        .ok()?;
    if !captured.success() {
        return None;
    }
    let output = captured.stdout_lossy();
    let value = output.trim();
    if value.is_empty() || value == "off" {
        return None;
    }
    parse_fwmark(value)
}

fn parse_fwmark(value: &str) -> Option<u32> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

fn allocate_table(runner: &dyn CommandRunner) -> QuickResult<u32> {
    let mut table = DEFAULT_ROUTE_TABLE_START;
    loop {
        let v4 = runner
            .capture(&quiet_capture(
                IP_PROGRAM,
                vec![
                    "-4".to_string(),
                    "route".to_string(),
                    "show".to_string(),
                    "table".to_string(),
                    table.to_string(),
                ],
            ))
            .map(|captured| captured.stdout)
            .unwrap_or_default();
        let v6 = runner
            .capture(&quiet_capture(
                IP_PROGRAM,
                vec![
                    "-6".to_string(),
                    "route".to_string(),
                    "show".to_string(),
                    "table".to_string(),
                    table.to_string(),
                ],
            ))
            .map(|captured| captured.stdout)
            .unwrap_or_default();
        if v4.is_empty() && v6.is_empty() {
            return Ok(table);
        }
        table = table
            .checked_add(1)
            .ok_or_else(|| QuickError::die("no free routing table"))?;
    }
}

fn del_if(
    config: &QuickConfig,
    runner: &dyn CommandRunner,
    state: &mut RunState,
) -> QuickResult<()> {
    if state.have_set_dns {
        unset_dns(config, runner)?;
    }
    if state.have_set_firewall {
        remove_firewall(config, runner)?;
    }

    let automatic_table = config
        .table
        .as_deref()
        .is_none_or(|table| table.is_empty() || table == "auto");
    if automatic_table {
        if let Some(table) = get_fwmark(&config.interface, runner) {
            let allowed_ips = runner
                .capture(&CommandSpec::new(UWG_PROGRAM).args(vec![
                    "show".to_string(),
                    config.interface.clone(),
                    "allowed-ips".to_string(),
                ]))
                .map(|captured| captured.stdout_lossy())
                .unwrap_or_default();
            if route::contains_default_route(&allowed_ips) {
                delete_rules(
                    runner,
                    "-4",
                    &format!("lookup {table}"),
                    route::rule_delete_args("-4", table),
                )?;
                delete_rules(
                    runner,
                    "-4",
                    "from all lookup main suppress_prefixlength 0",
                    route::suppress_rule_delete_args("-4"),
                )?;
                delete_rules(
                    runner,
                    "-6",
                    &format!("lookup {table}"),
                    route::rule_delete_args("-6", table),
                )?;
                delete_rules(
                    runner,
                    "-6",
                    "from all lookup main suppress_prefixlength 0",
                    route::suppress_rule_delete_args("-6"),
                )?;
            }
        }
    }

    runner.run_checked(&echo_command(
        IP_PROGRAM,
        vec![
            "link".to_string(),
            "delete".to_string(),
            "dev".to_string(),
            config.interface.clone(),
        ],
    ))
}

fn delete_rules(
    runner: &dyn CommandRunner,
    protocol: &str,
    needle: &str,
    delete_args: Vec<String>,
) -> QuickResult<()> {
    for _ in 0..MAX_RULE_DELETIONS {
        let output = runner
            .capture(&quiet_capture(
                IP_PROGRAM,
                vec![protocol.to_string(), "rule".to_string(), "show".to_string()],
            ))
            .map(|captured| captured.stdout_lossy())
            .unwrap_or_default();
        if !output.contains(needle) {
            return Ok(());
        }
        runner.run_checked(&echo_command(IP_PROGRAM, delete_args.clone()))?;
    }
    Err(QuickError::die("too many routing rules to delete"))
}

fn remove_firewall(config: &QuickConfig, runner: &dyn CommandRunner) -> QuickResult<()> {
    if runner.command_exists("nft") {
        let output = runner
            .capture(&quiet_capture(
                "nft",
                vec!["list".to_string(), "tables".to_string()],
            ))
            .map(|captured| captured.stdout_lossy())
            .unwrap_or_default();
        let script = firewall::nft_delete_script(&output, &config.interface);
        if !script.is_empty() {
            runner.run_checked(&echo_command("nft", vec!["-f".to_string()]).stdin(script))?;
        }
    }
    if runner.command_exists("iptables") {
        for program in ["iptables", "ip6tables"] {
            let save_program = format!("{program}-save");
            let output = runner
                .capture(&quiet_capture(&save_program, Vec::new()))
                .map(|captured| captured.stdout_lossy())
                .unwrap_or_default();
            let (script, found) = firewall::iptables_delete_script(&output, &config.interface);
            if found {
                let restore_program = format!("{program}-restore");
                runner.run_checked(
                    &echo_command(&restore_program, vec!["-n".to_string()]).stdin(script),
                )?;
            }
        }
    }
    Ok(())
}

fn save_config(config: &QuickConfig, runner: &dyn CommandRunner) -> QuickResult<()> {
    let brief = runner
        .capture(&CommandSpec::new(IP_PROGRAM).args(vec![
            "-all".to_string(),
            "-brief".to_string(),
            "address".to_string(),
            "show".to_string(),
            "dev".to_string(),
            config.interface.clone(),
        ]))
        .map(|captured| captured.stdout_lossy())
        .unwrap_or_default();
    let addresses = save::parse_brief_addresses(&brief, &config.interface);

    let resolv_name = resolvconf_name(config);
    let resolv_output = runner.capture(
        &CommandSpec::new("resolvconf")
            .args(vec!["-l".to_string(), resolv_name.clone()])
            .stderr_null(),
    );
    let resolv_text = match resolv_output {
        Ok(captured) if captured.success() => captured.stdout_lossy(),
        _ => fs::read_to_string(format!("{RESOLVCONF_RUN_DIR}/{resolv_name}")).unwrap_or_default(),
    };
    let servers = dns::parse_nameservers(&resolv_text);

    let current_mtu = if config.mtu.is_some() {
        runner
            .capture(&CommandSpec::new(IP_PROGRAM).args(vec![
                "link".to_string(),
                "show".to_string(),
                "dev".to_string(),
                config.interface.clone(),
            ]))
            .ok()
            .and_then(|captured| {
                mtu::extract_mtu(&captured.stdout_lossy()).map(|value| value.to_string())
            })
    } else {
        None
    };

    let inputs = save::SaveInputs {
        addresses: &addresses,
        dns: &servers,
        mtu: current_mtu.as_deref(),
        table: config.table.as_deref(),
        save_config: config.save_config,
        pre_up: &config.pre_up,
        post_up: &config.post_up,
        pre_down: &config.pre_down,
        post_down: &config.post_down,
    };
    let quick_block = save::build_saved_config(&inputs);

    let showconf = runner.capture(&echo_command(
        UWG_PROGRAM,
        vec!["showconf".to_string(), config.interface.clone()],
    ))?;
    if !showconf.success() {
        return Err(QuickError::command(UWG_PROGRAM, showconf.status));
    }
    let showconf_text = showconf.stdout_lossy();
    let trimmed = showconf_text.trim_end_matches('\n');
    let mut merged = save::apply_saved_config(trimmed, &quick_block);
    merged.push('\n');
    write_config_file(&config.config_file, merged.as_bytes())
}

fn write_config_file(path: &Path, data: &[u8]) -> QuickResult<()> {
    let temporary = temporary_path(path);
    let _umask = UmaskGuard::new(0o077);
    let write_result = write_temporary(&temporary, data);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(QuickError::die("Could not move configuration file"));
    }
    Ok(())
}

fn write_temporary(path: &Path, data: &[u8]) -> QuickResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let write_error = || QuickError::die("Could not write configuration file");
    let mut file = fs::File::create(path).map_err(|_| write_error())?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| write_error())?;
    file.write_all(data).map_err(|_| write_error())?;
    file.sync_all().map_err(|_| write_error())?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

struct UmaskGuard(u32);

impl UmaskGuard {
    fn new(mask: u32) -> Self {
        let previous = unsafe { libc::umask(mask as libc::mode_t) };
        Self(previous as u32)
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.0 as libc::mode_t);
        }
    }
}

fn execute_hooks(
    hooks: &[String],
    config: &QuickConfig,
    runner: &dyn CommandRunner,
) -> QuickResult<()> {
    for hook in hooks {
        let expanded = hook.replace("%i", &config.interface);
        eprintln!("[#] {expanded}");
        let shell = if runner.command_exists("bash") {
            "bash"
        } else {
            "sh"
        };
        let config_file = config.config_file.to_string_lossy().into_owned();
        let spec = CommandSpec::new(shell)
            .args(["-c", expanded.as_str()])
            .env("INTERFACE", config.interface.clone())
            .env("CONFIG_FILE", config_file);
        runner.run_checked(&spec)?;
    }
    Ok(())
}

fn echo_command(program: &str, args: Vec<String>) -> CommandSpec {
    CommandSpec::new(program).args(args).echo()
}

fn quiet_capture(program: &str, args: Vec<String>) -> CommandSpec {
    CommandSpec::new(program).args(args).stderr_null()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::testing::MockRunner;
    use crate::command::Captured;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    fn mock_from<F>(handler: F) -> MockRunner
    where
        F: Fn(&str, usize) -> (i32, String) + 'static,
    {
        let counts: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
        MockRunner::new(move |spec| {
            let command = spec.display();
            let count = {
                let mut counts = counts.borrow_mut();
                let value = counts.entry(command.clone()).or_insert(0);
                *value += 1;
                *value
            };
            let (status, stdout) = handler(&command, count);
            Ok(Captured {
                status,
                stdout: stdout.into_bytes(),
            })
        })
    }

    fn config_with(directory: &Path, name: &str, body: &str) -> QuickConfig {
        let path = directory.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        QuickConfig::load(path.to_str().unwrap()).unwrap()
    }

    #[test]
    fn up_builds_routes_rules_and_firewall_in_shell_order() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.2/24\n",
        );
        let runner = mock_from(|command, _| match command {
            "ip link show dev wg0" => (1, String::new()),
            "ip route show default" => (
                0,
                "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.2 metric 100\n"
                    .to_string(),
            ),
            "ip link show dev eth0" => (
                0,
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                    .to_string(),
            ),
            "uwg show wg0 allowed-ips" => (0, "peer\t10.0.0.0/24 0.0.0.0/0\n".to_string()),
            "uwg show wg0 fwmark" => (0, "off\n".to_string()),
            "ip -o -4 addr show dev wg0" => (
                0,
                "4: wg0    inet 10.0.0.2/24 scope global wg0\n".to_string(),
            ),
            "ip -4 route show dev wg0 match 10.0.0.0/24" => (1, String::new()),
            _ => (0, String::new()),
        })
        .with_available(["nft"]);

        up(&config, &runner).unwrap();

        let expected = [
            "ip link show dev wg0",
            "ip link add wg0 type umbrawg",
            "uwg setconf wg0 /dev/stdin",
            "ip -4 address add 10.0.0.2/24 dev wg0",
            "uwg show wg0 endpoints",
            "ip route show default",
            "ip link show dev eth0",
            "ip link set mtu 1420 up dev wg0",
            "uwg show wg0 allowed-ips",
            "ip -4 route show dev wg0 match 10.0.0.0/24",
            "ip -4 route add 10.0.0.0/24 dev wg0",
            "uwg show wg0 fwmark",
            "ip -4 route show table 51820",
            "ip -6 route show table 51820",
            "uwg set wg0 fwmark 51820",
            "ip -4 rule add not fwmark 51820 table 51820",
            "ip -4 rule add table main suppress_prefixlength 0",
            "ip -4 route add 0.0.0.0/0 dev wg0 table 51820",
            "ip -o -4 addr show dev wg0",
            "sysctl -q net.ipv4.conf.all.src_valid_mark=1",
            "nft -f",
        ];
        assert_eq!(runner.call_strings(), expected);
    }

    #[test]
    fn set_config_passes_the_configuration_as_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.2/24\n",
        );
        let runner = MockRunner::empty();

        set_config(&config, &runner).unwrap();

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "uwg");
        assert_eq!(calls[0].args, ["setconf", "wg0", "/dev/stdin"]);
        assert_eq!(
            calls[0].stdin.as_deref(),
            Some(format!("{}\n", config.wg_config).as_bytes())
        );
    }

    #[test]
    fn auto_mtu_uses_largest_endpoint_route() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\n",
        );
        let runner = mock_from(|command, _| match command {
            "uwg show wg0 endpoints" => (
                0,
                "peer\t192.0.2.1:51820\npeer2\t[2001:db8::1]:51820\n".to_string(),
            ),
            "ip route get 192.0.2.1" => (
                0,
                "192.0.2.1 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 0\n    cache mtu 1400\n"
                    .to_string(),
            ),
            "ip route get 2001:db8::1" => (
                0,
                "2001:db8::1 via fe80::1 dev eth0 src fe80::2 uid 0\n    cache mtu 9000\n"
                    .to_string(),
            ),
            _ => (0, String::new()),
        });

        set_mtu_up(&config, &runner).unwrap();

        assert_eq!(
            runner.call_strings(),
            [
                "uwg show wg0 endpoints",
                "ip route get 192.0.2.1",
                "ip route get 2001:db8::1",
                "ip link set mtu 8920 up dev wg0",
            ]
        );
    }

    #[test]
    fn explicit_mtu_and_table_off_skip_auto_routing() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.2/24\nMTU = 1280\nTable = off\n",
        );
        let runner = mock_from(|command, _| match command {
            "ip link show dev wg0" => (1, String::new()),
            "uwg show wg0 allowed-ips" => (0, "peer\t10.0.0.0/24 0.0.0.0/0\n".to_string()),
            _ => (0, String::new()),
        });

        up(&config, &runner).unwrap();

        let calls = runner.call_strings();
        assert!(calls.contains(&"ip link set mtu 1280 up dev wg0".to_string()));
        assert!(!calls.iter().any(|call| call.starts_with("ip -4 route add")));
        assert!(!calls.iter().any(|call| call == "uwg show wg0 endpoints"));
    }

    #[test]
    fn up_cleans_up_interface_after_failure() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\n",
        );
        let runner = mock_from(|command, _| match command {
            "ip link show dev wg0" => (1, String::new()),
            "uwg setconf wg0 /dev/stdin" => (1, String::new()),
            "uwg show wg0 fwmark" => (1, String::new()),
            _ => (0, String::new()),
        });

        let error = up(&config, &runner).unwrap_err();
        assert_eq!(error.exit_code(), 1);
        assert!(runner
            .call_strings()
            .contains(&"ip link delete dev wg0".to_string()));
    }

    #[test]
    fn falls_back_to_userspace_implementation() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\n",
        );
        let runner = mock_from(|command, _| match command {
            "ip link add wg0 type umbrawg" => (1, String::new()),
            _ => (0, String::new()),
        })
        .with_available(["umbrawg"]);

        add_if_with_module(&config, &runner, "umbrawg", false).unwrap();
        assert_eq!(
            runner.call_strings(),
            ["ip link add wg0 type umbrawg", "umbrawg wg0"]
        );
    }

    #[test]
    fn does_not_fall_back_when_kernel_module_is_present() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\n",
        );
        let runner = mock_from(|command, _| match command {
            "ip link add wg0 type umbrawg" => (1, String::new()),
            _ => (0, String::new()),
        })
        .with_available(["umbrawg"]);

        let error = add_if_with_module(&config, &runner, "umbrawg", true).unwrap_err();
        assert_eq!(error.exit_code(), 1);
    }

    #[test]
    fn down_removes_rules_dns_and_link() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\nDNS = 1.1.1.1\nTable = auto\nSaveConfig = false\n",
        );
        let v4_output = |count: usize| {
            match count {
            1 => "0: from all lookup local\n32765: not from all fwmark 0xca6c lookup 51820\n32766: from all lookup main suppress_prefixlength 0\n".to_string(),
            2 | 3 => "32766: from all lookup main suppress_prefixlength 0\n".to_string(),
            _ => String::new(),
        }
        };
        let runner = mock_from(move |command, count| match command {
            "uwg show interfaces" => (0, "lo wg0\n".to_string()),
            "uwg show wg0 fwmark" => (0, "51820\n".to_string()),
            "uwg show wg0 allowed-ips" => (0, "peer\t0.0.0.0/0\n".to_string()),
            "ip -4 rule show" => (0, v4_output(count)),
            "ip -6 rule show" => (0, String::new()),
            _ => (0, String::new()),
        });

        down(&config, &runner).unwrap();

        let expected = [
            "uwg show interfaces",
            "uwg show wg0 fwmark",
            "uwg show wg0 allowed-ips",
            "ip -4 rule show",
            "ip -4 rule delete table 51820",
            "ip -4 rule show",
            "ip -4 rule show",
            "ip -4 rule delete table main suppress_prefixlength 0",
            "ip -4 rule show",
            "ip -6 rule show",
            "ip -6 rule show",
            "ip link delete dev wg0",
        ];
        let calls = runner.call_strings();
        let last = calls.last().expect("resolvconf call");
        assert!(last.starts_with("resolvconf -d "));
        assert!(last.ends_with(" -f"));
        assert_eq!(&calls[..calls.len() - 1], expected);
    }

    #[test]
    fn down_rejects_non_wireguard_interface() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\n",
        );
        let runner = mock_from(|_, _| (0, "lo\n".to_string()));
        let error = down(&config, &runner).unwrap_err();
        assert_eq!(error.to_string(), "`wg0' is not a WireGuard interface");
    }

    #[test]
    fn save_writes_current_state_back_to_config() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "\
[Interface]
PrivateKey = abc=
Address = 10.0.0.2/24
DNS = 1.1.1.1
MTU = 1400
Table = 100
SaveConfig = true
PreUp = echo up
PostUp = echo post
PreDown = echo down
PostDown = echo postdown

[Peer]
PublicKey = xyz=
",
        );
        let showconf = "\
[Interface]
PrivateKey=abc=
ListenPort=51820

[Peer]
PublicKey=xyz=
AdvancedSecurity=on
AllowedIPs=10.0.0.0/24
";
        let runner = mock_from(move |command, _| {
            match command {
            "uwg show interfaces" => (0, "wg0\n".to_string()),
            "ip -all -brief address show dev wg0" => {
                (0, "wg0              UNKNOWN        10.0.0.2/24 fd00::2/64\n".to_string())
            }
            "ip link show dev wg0" => (
                0,
                "4: wg0: <POINTOPOINT,UP,LOWER_UP> mtu 1400 qdisc noqueue state UNKNOWN\n"
                    .to_string(),
            ),
            "uwg showconf wg0" => (0, showconf.to_string()),
            command if command.starts_with("resolvconf -l ") => (
                0,
                "# resolv.conf from wg0\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch example.com\n"
                    .to_string(),
            ),
            _ => (0, String::new()),
        }
        });

        save_interface(&config, &runner).unwrap();

        let expected = "\
[Interface]
Address = 10.0.0.2/24
Address = fd00::2/64
DNS = 1.1.1.1
DNS = 8.8.8.8
MTU = 1400
Table = 100
SaveConfig = true
PreUp = echo up
PostUp = echo post
PreDown = echo down
PostDown = echo postdown
PrivateKey=abc=
ListenPort=51820

[Peer]
PublicKey=xyz=
AdvancedSecurity=on
AllowedIPs=10.0.0.0/24
";
        assert_eq!(fs::read_to_string(&config.config_file).unwrap(), expected);
        let mode = fs::metadata(&config.config_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
        assert!(!temporary_path(&config.config_file).exists());
    }

    #[test]
    fn parses_fwmark_formats() {
        assert_eq!(parse_fwmark("51820"), Some(51820));
        assert_eq!(parse_fwmark("0xca6c"), Some(51820));
        assert_eq!(parse_fwmark("off"), None);
    }

    #[test]
    fn dns_retries_until_resolvconf_succeeds() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\nDNS = 1.1.1.1\n",
        );
        let runner = mock_from(|command, count| match command {
            "resolvconf -a wg0 -m 0 -x" if count < 3 => (1, String::new()),
            _ => (0, String::new()),
        });
        let mut state = RunState::default();

        set_dns_with(&config, &runner, &mut state, 3, std::time::Duration::ZERO).unwrap();

        assert!(state.have_set_dns);
        assert_eq!(
            runner
                .call_strings()
                .iter()
                .filter(|call| call.starts_with("resolvconf -a "))
                .count(),
            3
        );
    }

    #[test]
    fn dns_reports_a_clear_error_after_all_attempts() {
        let directory = tempfile::tempdir().unwrap();
        let config = config_with(
            directory.path(),
            "wg0.conf",
            "[Interface]\nPrivateKey = abc=\nDNS = 1.1.1.1\n",
        );
        let runner = mock_from(|command, _| match command {
            "resolvconf -a wg0 -m 0 -x" => (2, String::new()),
            _ => (0, String::new()),
        });
        let mut state = RunState::default();

        let error = set_dns_with(&config, &runner, &mut state, 3, std::time::Duration::ZERO)
            .expect_err("resolvconf keeps failing");

        assert_eq!(
            error.to_string(),
            "Failed to apply DNS settings after 3 attempts: command `resolvconf` failed with status 2"
        );
        assert!(!state.have_set_dns);
    }
}
