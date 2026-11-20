use std::fmt::Write as _;
use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

use umbrawg_config::{format_endpoint, Key, U16Range, U32Range};
use umbrawg_ctl::{BbrStats, Device, FecStats, Peer, TimeSpec};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const FG_GREEN: &str = "\x1b[32m";
const FG_YELLOW: &str = "\x1b[33m";
const FG_CYAN: &str = "\x1b[36m";
const FG_RED: &str = "\x1b[31m";

pub fn color_enabled() -> bool {
    match std::env::var("WG_COLOR_MODE").as_deref() {
        Ok("always") => true,
        Ok("never") => false,
        _ => std::io::stdout().is_terminal(),
    }
}

pub fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

struct Style {
    color: bool,
}

impl Style {
    fn wrap(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("{code}{text}{RESET}")
        } else {
            text.to_owned()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.wrap(BOLD, text)
    }

    fn green(&self, text: &str) -> String {
        self.wrap(FG_GREEN, text)
    }

    fn green_bold(&self, text: &str) -> String {
        self.wrap(&format!("{FG_GREEN}{BOLD}"), text)
    }

    fn yellow(&self, text: &str) -> String {
        self.wrap(FG_YELLOW, text)
    }

    fn yellow_bold(&self, text: &str) -> String {
        self.wrap(&format!("{FG_YELLOW}{BOLD}"), text)
    }

    fn cyan(&self, text: &str) -> String {
        self.wrap(FG_CYAN, text)
    }

    fn red(&self, text: &str) -> String {
        self.wrap(FG_RED, text)
    }
}

pub fn pretty(device: &Device, color: bool) -> String {
    pretty_at(device, color, now_seconds())
}

pub fn pretty_at(device: &Device, color: bool, now: i64) -> String {
    let style = Style { color };
    let mut output = String::new();
    if color {
        output.push_str(RESET);
    }
    let _ = writeln!(
        output,
        "{}: {}",
        style.green_bold("interface"),
        style.green(&device.name)
    );
    if let Some(key) = &device.public_key {
        let _ = writeln!(
            output,
            "  {}: {}",
            style.bold("public key"),
            key.to_base64()
        );
    }
    if let Some(key) = &device.private_key {
        let _ = writeln!(
            output,
            "  {}: {}",
            style.bold("private key"),
            masked_key(key)
        );
    }
    if device.listen_port != 0 {
        let _ = writeln!(
            output,
            "  {}: {}",
            style.bold("listening port"),
            device.listen_port
        );
    }
    if device.fwmark != 0 {
        let _ = writeln!(output, "  {}: 0x{:x}", style.bold("fwmark"), device.fwmark);
    }
    if let Some(extra_ports) = device.extra_ports.filter(|ports| *ports != 0) {
        let _ = writeln!(output, "  {}: {extra_ports}", style.bold("extra udp ports"));
    }
    if let Some(underlay_mtu) = device.underlay_mtu {
        let _ = writeln!(output, "  {}: {underlay_mtu}", style.bold("underlay mtu"));
    }
    if let Some(bbr) = &device.bbr {
        let _ = writeln!(output, "  {}: {bbr}", style.bold("bbr"));
    }
    if let Some(fec) = &device.fec {
        let _ = writeln!(output, "  {}: {fec}", style.bold("fec"));
    }
    let obfuscation = &device.obfuscation;
    for (name, value) in [
        ("jc", obfuscation.jc),
        ("jmin", obfuscation.jmin),
        ("jmax", obfuscation.jmax),
        ("s1", obfuscation.s1),
        ("s2", obfuscation.s2),
        ("s3", obfuscation.s3),
        ("s4", obfuscation.s4),
    ] {
        if let Some(value) = value {
            if value != 0 {
                let _ = writeln!(output, "  {}: {}", style.bold(name), value);
            }
        }
    }
    for (index, value) in [
        obfuscation.h1,
        obfuscation.h2,
        obfuscation.h3,
        obfuscation.h4,
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(value) = value {
            if value != U32Range::single(index as u32 + 1) {
                let _ = writeln!(
                    output,
                    "  {}: {}",
                    style.bold(&format!("h{}", index + 1)),
                    value
                );
            }
        }
    }
    for (index, value) in [
        &obfuscation.i1,
        &obfuscation.i2,
        &obfuscation.i3,
        &obfuscation.i4,
        &obfuscation.i5,
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(value) = value {
            let _ = writeln!(
                output,
                "  {}: {}",
                style.bold(&format!("i{}", index + 1)),
                value
            );
        }
    }
    if let Some(key) = &obfuscation.header_protection_key {
        let _ = writeln!(
            output,
            "  {}: {}",
            style.bold("header protection key"),
            key.to_base64()
        );
    }
    for (name, value) in [
        (
            "content padding addition",
            obfuscation.content_padding_addition,
        ),
        ("rekey after time", obfuscation.rekey_after_time),
        ("rekey timeout", obfuscation.rekey_timeout),
        ("reject after time", obfuscation.reject_after_time),
        ("keepalive timeout", obfuscation.keepalive_timeout),
        ("max handshake attempts", obfuscation.max_handshake_attempts),
    ] {
        if let Some(value) = value {
            if !value.is_zero() {
                let _ = writeln!(output, "  {}: {}", style.bold(name), value);
            }
        }
    }
    if let Some(value) = obfuscation.random_trailers {
        let _ = writeln!(
            output,
            "  {}: {}",
            style.bold("random trailers"),
            bool_text(value)
        );
    }
    if let Some(value) = obfuscation.disable_cookies {
        let _ = writeln!(
            output,
            "  {}: {}",
            style.bold("disable cookies"),
            bool_text(value)
        );
    }
    match &device.bbr_stats {
        Some(stats) => {
            let _ = writeln!(output, "  {}:", style.bold("bbr stats"));
            output.push_str(&bbr_stats_text(stats, "    "));
        }
        None => {
            let _ = writeln!(output, "  {}: (none)", style.bold("bbr stats"));
        }
    }
    match &device.fec_stats {
        Some(stats) => {
            let _ = writeln!(output, "  {}:", style.bold("fec stats"));
            output.push_str(&fec_stats_text(stats, "    "));
        }
        None => {
            let _ = writeln!(output, "  {}: (none)", style.bold("fec stats"));
        }
    }

    let peers = sorted_peers(device);
    if !peers.is_empty() {
        output.push('\n');
    }
    for (index, peer) in peers.iter().enumerate() {
        let _ = writeln!(
            output,
            "{}: {}",
            style.yellow_bold("peer"),
            style.yellow(&peer.public_key.to_base64())
        );
        if let Some(key) = &peer.preshared_key {
            let _ = writeln!(
                output,
                "  {}: {}",
                style.bold("preshared key"),
                masked_key(key)
            );
        }
        if let Some(endpoint) = &peer.endpoint {
            let _ = writeln!(
                output,
                "  {}: {}",
                style.bold("endpoint"),
                format_endpoint(endpoint)
            );
        }
        let _ = write!(output, "  {}: ", style.bold("allowed ips"));
        if peer.allowed_ips.is_empty() {
            output.push_str("(none)\n");
        } else {
            for (allowed_index, allowed_ip) in peer.allowed_ips.iter().enumerate() {
                if allowed_index + 1 < peer.allowed_ips.len() {
                    let _ = write!(
                        output,
                        "{}{}{}, ",
                        allowed_ip.address,
                        style.cyan("/"),
                        allowed_ip.cidr
                    );
                } else {
                    let _ = writeln!(
                        output,
                        "{}{}{}",
                        allowed_ip.address,
                        style.cyan("/"),
                        allowed_ip.cidr
                    );
                }
            }
        }
        if peer.last_handshake_time.seconds != 0 {
            let _ = writeln!(
                output,
                "  {}: {}",
                style.bold("latest handshake"),
                ago(&peer.last_handshake_time, now, color)
            );
        }
        if peer.rx_bytes != 0 || peer.tx_bytes != 0 {
            let _ = writeln!(
                output,
                "  {}: {} received, {} sent",
                style.bold("transfer"),
                bytes(peer.rx_bytes, color),
                bytes(peer.tx_bytes, color)
            );
        }
        if !peer.persistent_keepalive.is_zero() {
            let _ = writeln!(
                output,
                "  {}: {}",
                style.bold("persistent keepalive"),
                peer.persistent_keepalive
            );
        }
        if let Some(cipher) = peer.cipher {
            if cipher != umbrawg_config::Cipher::ChaCha20Poly1305 {
                let _ = writeln!(output, "  {}: {}", style.bold("cipher"), cipher);
            }
        }
        let _ = writeln!(
            output,
            "  {}: {}",
            style.bold("advanced security"),
            advanced_security_text(peer)
        );
        if index + 1 < peers.len() {
            output.push('\n');
        }
    }
    output
}

pub fn dump(device: &Device, with_interface: bool) -> String {
    let mut output = String::new();
    if with_interface {
        output.push_str(&device.name);
        output.push('\t');
    }
    for value in [
        maybe_key(device.private_key.as_ref()),
        maybe_key(device.public_key.as_ref()),
        device.listen_port.to_string(),
        u16_text(device.obfuscation.jc),
        u16_text(device.obfuscation.jmin),
        u16_text(device.obfuscation.jmax),
        u16_text(device.obfuscation.s1),
        u16_text(device.obfuscation.s2),
        u16_text(device.obfuscation.s3),
        u16_text(device.obfuscation.s4),
        u32_range_text(device.obfuscation.h1),
        u32_range_text(device.obfuscation.h2),
        u32_range_text(device.obfuscation.h3),
        u32_range_text(device.obfuscation.h4),
        option_text(&device.obfuscation.i1, "(null)"),
        option_text(&device.obfuscation.i2, "(null)"),
        option_text(&device.obfuscation.i3, "(null)"),
        option_text(&device.obfuscation.i4, "(null)"),
        option_text(&device.obfuscation.i5, "(null)"),
        maybe_key(device.obfuscation.header_protection_key.as_ref()),
        u16_range_text(device.obfuscation.content_padding_addition),
        u16_range_text(device.obfuscation.rekey_after_time),
        u16_range_text(device.obfuscation.rekey_timeout),
        u16_range_text(device.obfuscation.reject_after_time),
        u16_range_text(device.obfuscation.keepalive_timeout),
        u16_range_text(device.obfuscation.max_handshake_attempts),
        bool_text(device.obfuscation.random_trailers.unwrap_or(false)).to_owned(),
        bool_text(device.obfuscation.disable_cookies.unwrap_or(false)).to_owned(),
    ] {
        let _ = write!(output, "{value}\t");
    }
    if device.fwmark != 0 {
        let _ = writeln!(output, "0x{:x}", device.fwmark);
    } else {
        output.push_str("off\n");
    }
    for peer in &device.peers {
        let prefix = if with_interface {
            format!("{}\t", device.name)
        } else {
            String::new()
        };
        let endpoint = peer
            .endpoint
            .as_ref()
            .map(format_endpoint)
            .unwrap_or_else(|| "(none)".to_owned());
        let allowed_ips = if peer.allowed_ips.is_empty() {
            "(none)".to_owned()
        } else {
            peer.allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        let keepalive = if peer.persistent_keepalive.is_zero() {
            "off".to_owned()
        } else {
            peer.persistent_keepalive.to_string()
        };
        let _ = writeln!(
            output,
            "{prefix}{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            peer.public_key.to_base64(),
            maybe_key(peer.preshared_key.as_ref()),
            endpoint,
            allowed_ips,
            peer.last_handshake_time.seconds,
            peer.rx_bytes,
            peer.tx_bytes,
            keepalive
        );
    }
    output
}

pub fn ugly(device: &Device, parameter: &str, with_interface: bool) -> Result<String, String> {
    let mut output = String::new();
    let prefix = if with_interface {
        format!("{}\t", device.name)
    } else {
        String::new()
    };
    match parameter {
        "public-key" => {
            let _ = writeln!(output, "{prefix}{}", maybe_key(device.public_key.as_ref()));
        }
        "private-key" => {
            let _ = writeln!(output, "{prefix}{}", maybe_key(device.private_key.as_ref()));
        }
        "listen-port" => {
            let _ = writeln!(output, "{prefix}{}", device.listen_port);
        }
        "extra-ports" => {
            let _ = writeln!(output, "{prefix}{}", device.extra_ports.unwrap_or(0));
        }
        "fwmark" => {
            if device.fwmark != 0 {
                let _ = writeln!(output, "{prefix}0x{:x}", device.fwmark);
            } else {
                let _ = writeln!(output, "{prefix}off");
            }
        }
        "bbr" => {
            let _ = writeln!(output, "{prefix}{}", option_text(&device.bbr, "(none)"));
        }
        "fec" => {
            let _ = writeln!(output, "{prefix}{}", option_text(&device.fec, "(none)"));
        }
        "underlay-mtu" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                device
                    .underlay_mtu
                    .map(|mtu| mtu.to_string())
                    .unwrap_or_else(|| "(none)".to_owned())
            );
        }
        "bbr-stats" => match &device.bbr_stats {
            Some(stats) => output.push_str(&bbr_stats_text(stats, &prefix)),
            None => {
                let _ = writeln!(output, "{prefix}(none)");
            }
        },
        "fec-stats" => match &device.fec_stats {
            Some(stats) => output.push_str(&fec_stats_text(stats, &prefix)),
            None => {
                let _ = writeln!(output, "{prefix}(none)");
            }
        },
        "jc" => {
            let _ = writeln!(output, "{prefix}{}", u16_text(device.obfuscation.jc));
        }
        "jmin" => {
            let _ = writeln!(output, "{prefix}{}", u16_text(device.obfuscation.jmin));
        }
        "jmax" => {
            let _ = writeln!(output, "{prefix}{}", u16_text(device.obfuscation.jmax));
        }
        "s1" => {
            let _ = writeln!(output, "{prefix}{}", u16_text(device.obfuscation.s1));
        }
        "s2" => {
            let _ = writeln!(output, "{prefix}{}", u16_text(device.obfuscation.s2));
        }
        "s3" => {
            let _ = writeln!(output, "{prefix}{}", u16_text(device.obfuscation.s3));
        }
        "s4" => {
            let _ = writeln!(output, "{prefix}{}", u16_text(device.obfuscation.s4));
        }
        "h1" => {
            let _ = writeln!(output, "{prefix}{}", u32_range_text(device.obfuscation.h1));
        }
        "h2" => {
            let _ = writeln!(output, "{prefix}{}", u32_range_text(device.obfuscation.h2));
        }
        "h3" => {
            let _ = writeln!(output, "{prefix}{}", u32_range_text(device.obfuscation.h3));
        }
        "h4" => {
            let _ = writeln!(output, "{prefix}{}", u32_range_text(device.obfuscation.h4));
        }
        "i1" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                option_text(&device.obfuscation.i1, "(null)")
            );
        }
        "i2" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                option_text(&device.obfuscation.i2, "(null)")
            );
        }
        "i3" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                option_text(&device.obfuscation.i3, "(null)")
            );
        }
        "i4" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                option_text(&device.obfuscation.i4, "(null)")
            );
        }
        "i5" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                option_text(&device.obfuscation.i5, "(null)")
            );
        }
        "header-protection-key" => {
            let key = device
                .obfuscation
                .header_protection_key
                .as_ref()
                .map(Key::to_base64)
                .unwrap_or_else(|| Key::zero().to_base64());
            let _ = writeln!(output, "{prefix}{key}");
        }
        "content-padding-addition" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                u16_range_text(device.obfuscation.content_padding_addition)
            );
        }
        "rekey-after-time" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                u16_range_text(device.obfuscation.rekey_after_time)
            );
        }
        "rekey-timeout" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                u16_range_text(device.obfuscation.rekey_timeout)
            );
        }
        "reject-after-time" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                u16_range_text(device.obfuscation.reject_after_time)
            );
        }
        "keepalive-timeout" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                u16_range_text(device.obfuscation.keepalive_timeout)
            );
        }
        "max-handshake-attempts" | "max-handshake-attemps" | "max_handshake_attempts" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                u16_range_text(device.obfuscation.max_handshake_attempts)
            );
        }
        "random-trailers" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                bool_text(device.obfuscation.random_trailers.unwrap_or(false))
            );
        }
        "disable-cookies" => {
            let _ = writeln!(
                output,
                "{prefix}{}",
                bool_text(device.obfuscation.disable_cookies.unwrap_or(false))
            );
        }
        "endpoints" => {
            for peer in &device.peers {
                let endpoint = peer
                    .endpoint
                    .as_ref()
                    .map(format_endpoint)
                    .unwrap_or_else(|| "(none)".to_owned());
                let _ = writeln!(
                    output,
                    "{prefix}{}\t{endpoint}",
                    peer.public_key.to_base64()
                );
            }
        }
        "allowed-ips" => {
            for peer in &device.peers {
                let allowed_ips = if peer.allowed_ips.is_empty() {
                    "(none)".to_owned()
                } else {
                    peer.allowed_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                let _ = writeln!(
                    output,
                    "{prefix}{}\t{allowed_ips}",
                    peer.public_key.to_base64()
                );
            }
        }
        "latest-handshakes" => {
            for peer in &device.peers {
                let _ = writeln!(
                    output,
                    "{prefix}{}\t{}",
                    peer.public_key.to_base64(),
                    peer.last_handshake_time.seconds
                );
            }
        }
        "transfer" => {
            for peer in &device.peers {
                let _ = writeln!(
                    output,
                    "{prefix}{}\t{}\t{}",
                    peer.public_key.to_base64(),
                    peer.rx_bytes,
                    peer.tx_bytes
                );
            }
        }
        "persistent-keepalive" => {
            for peer in &device.peers {
                if peer.persistent_keepalive.is_zero() {
                    let _ = writeln!(output, "{prefix}{}\toff", peer.public_key.to_base64());
                } else {
                    let _ = writeln!(
                        output,
                        "{prefix}{}\t{}",
                        peer.public_key.to_base64(),
                        peer.persistent_keepalive
                    );
                }
            }
        }
        "advanced-security" => {
            for peer in &device.peers {
                let _ = writeln!(
                    output,
                    "{prefix}{}\t{}",
                    peer.public_key.to_base64(),
                    advanced_security_text(peer)
                );
            }
        }
        "preshared-keys" => {
            for peer in &device.peers {
                let key = maybe_key(peer.preshared_key.as_ref());
                let _ = writeln!(output, "{prefix}{}\t{key}", peer.public_key.to_base64());
            }
        }
        "peers" => {
            for peer in &device.peers {
                let _ = writeln!(output, "{prefix}{}", peer.public_key.to_base64());
            }
        }
        "dump" => output = dump(device, with_interface),
        _ => return Err(format!("Invalid parameter: `{parameter}'")),
    }
    Ok(output)
}

pub fn showconf(device: &Device) -> String {
    let mut config = device.to_config();
    config.device.extra_ports = device.extra_ports.filter(|ports| *ports != 0);
    config.to_ini(false)
}

fn sorted_peers(device: &Device) -> Vec<&Peer> {
    let mut peers: Vec<&Peer> = device.peers.iter().collect();
    peers.sort_by(|left, right| compare_peers(left, right));
    peers
}

fn compare_peers(left: &Peer, right: &Peer) -> std::cmp::Ordering {
    let left_zero = left.last_handshake_time.is_zero();
    let right_zero = right.last_handshake_time.is_zero();
    match (left_zero, right_zero) {
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
        _ => right
            .last_handshake_time
            .seconds
            .cmp(&left.last_handshake_time.seconds)
            .then_with(|| {
                right
                    .last_handshake_time
                    .nanoseconds
                    .cmp(&left.last_handshake_time.nanoseconds)
            }),
    }
}

fn masked_key(key: &Key) -> String {
    match std::env::var("WG_HIDE_KEYS").as_deref() {
        Ok("never") => key.to_base64(),
        _ => "(hidden)".to_owned(),
    }
}

fn maybe_key(key: Option<&Key>) -> String {
    key.map(Key::to_base64)
        .unwrap_or_else(|| "(none)".to_owned())
}

fn u16_text(value: Option<u16>) -> String {
    value.unwrap_or(0).to_string()
}

fn u16_range_text(value: Option<U16Range>) -> String {
    value.unwrap_or_default().to_string()
}

fn u32_range_text(value: Option<U32Range>) -> String {
    value.unwrap_or_default().to_string()
}

fn bbr_mode_text(mode: u8) -> &'static str {
    match mode {
        0 => "off",
        1 => "monitor",
        2 => "on",
        _ => "unknown",
    }
}

fn bbr_stats_text(stats: &BbrStats, prefix: &str) -> String {
    let mut output = String::new();
    for (name, value) in [
        ("mode", bbr_mode_text(stats.mode).to_owned()),
        ("cwnd", stats.cwnd.to_string()),
        ("inflight", stats.inflight.to_string()),
        ("pacing_rate", stats.pacing_rate.to_string()),
        ("btl_bw", stats.btl_bw.to_string()),
        ("min_rtt_ns", stats.min_rtt_ns.to_string()),
        ("round_lost", stats.round_lost.to_string()),
        ("peers", stats.peers.to_string()),
    ] {
        let _ = writeln!(output, "{prefix}{name}={value}");
    }
    output
}

fn fec_stats_text(stats: &FecStats, prefix: &str) -> String {
    let mut output = String::new();
    for (name, value) in [
        ("blocks_encoded", stats.blocks_encoded),
        ("shards_sent", stats.shards_sent),
        ("blocks_decoded", stats.blocks_decoded),
        ("packets_recovered", stats.packets_recovered),
        ("decode_fail", stats.decode_fail),
        ("dropped_bounds", stats.dropped_bounds),
        ("dropped_disabled", stats.dropped_disabled),
    ] {
        let _ = writeln!(output, "{prefix}{name}={value}");
    }
    output
}

fn option_text(value: &Option<String>, missing: &str) -> String {
    value.clone().unwrap_or_else(|| missing.to_owned())
}

fn bool_text(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

fn advanced_security_text(peer: &Peer) -> &'static str {
    match peer.advanced_security {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unsupported",
    }
}

fn bytes(value: u64, color: bool) -> String {
    let style = Style { color };
    if value < 1024 {
        format!("{value} {}", style.cyan("B"))
    } else if value < 1024 * 1024 {
        format!("{:.2} {}", value as f64 / 1024.0, style.cyan("KiB"))
    } else if value < 1024 * 1024 * 1024 {
        format!(
            "{:.2} {}",
            value as f64 / (1024.0 * 1024.0),
            style.cyan("MiB")
        )
    } else if value < 1024 * 1024 * 1024 * 1024 {
        format!(
            "{:.2} {}",
            value as f64 / (1024.0 * 1024.0 * 1024.0),
            style.cyan("GiB")
        )
    } else {
        format!(
            "{:.2} {}",
            value as f64 / (1024.0 * 1024.0 * 1024.0 * 1024.0),
            style.cyan("TiB")
        )
    }
}

fn ago(time: &TimeSpec, now: i64, color: bool) -> String {
    let style = Style { color };
    if now == time.seconds {
        return "Now".to_owned();
    }
    if now < time.seconds {
        return format!(
            "({})",
            style.red("System clock wound backward; connection problems may ensue.")
        );
    }
    let elapsed = (now - time.seconds) as u64;
    let pretty = pretty_time(elapsed, color);
    format!("{pretty} ago")
}

fn pretty_time(mut left: u64, color: bool) -> String {
    let style = Style { color };
    let years = left / (365 * 24 * 60 * 60);
    left %= 365 * 24 * 60 * 60;
    let days = left / (24 * 60 * 60);
    left %= 24 * 60 * 60;
    let hours = left / (60 * 60);
    left %= 60 * 60;
    let minutes = left / 60;
    let seconds = left % 60;
    let mut parts = Vec::new();
    for (value, name) in [
        (years, "year"),
        (days, "day"),
        (hours, "hour"),
        (minutes, "minute"),
        (seconds, "second"),
    ] {
        if value != 0 {
            let suffix = if value == 1 { "" } else { "s" };
            parts.push(format!(
                "{value} {}",
                style.cyan(&format!("{name}{suffix}"))
            ));
        }
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbrawg_config::AllowedIp;
    use umbrawg_ctl::Peer;

    fn sample_device() -> Device {
        let mut device = Device::new("uwg0");
        device.ifindex = Some(3);
        device.private_key = Some(Key::from_hex(&"11".repeat(32)).expect("valid"));
        device.public_key = Some(Key::from_hex(&"22".repeat(32)).expect("valid"));
        device.listen_port = 51820;
        device.extra_ports = Some(4);
        device.fwmark = 0x1234;
        device.bbr = Some("monitor".to_owned());
        device.fec = Some("8:2".to_owned());
        device.underlay_mtu = Some(9000);
        device.bbr_stats = Some(BbrStats {
            mode: 2,
            cwnd: 131_072,
            inflight: 4096,
            pacing_rate: 1_000_000,
            btl_bw: 2_000_000,
            min_rtt_ns: 12_345,
            round_lost: 8,
            peers: 1,
        });
        device.fec_stats = Some(FecStats {
            blocks_encoded: 10,
            shards_sent: 12,
            blocks_decoded: 9,
            packets_recovered: 1,
            decode_fail: 2,
            dropped_bounds: 3,
            dropped_disabled: 4,
        });
        device.obfuscation.jc = Some(4);
        device.obfuscation.jmin = Some(40);
        device.obfuscation.jmax = Some(70);
        device.obfuscation.h1 = Some(U32Range::new(10, 20));
        device.obfuscation.i1 = Some("<b 0x1><c>".to_owned());
        device.obfuscation.random_trailers = Some(true);
        device.peers.push(Peer {
            public_key: Key::from_hex(&"33".repeat(32)).expect("valid"),
            preshared_key: Some(Key::from_hex(&"44".repeat(32)).expect("valid")),
            endpoint: Some("192.0.2.1:51820".parse().expect("valid")),
            persistent_keepalive: U16Range::single(25),
            last_handshake_time: TimeSpec::new(1_700_000_000, 0),
            rx_bytes: 2048,
            tx_bytes: 10,
            allowed_ips: vec!["10.0.0.0/8".parse::<AllowedIp>().expect("valid")],
            advanced_security: Some(true),
            cipher: None,
        });
        device
    }

    #[test]
    fn shows_bbr_and_fec_state() {
        let device = sample_device();
        assert_eq!(ugly(&device, "bbr", false).expect("valid"), "monitor\n");
        assert_eq!(ugly(&device, "fec", false).expect("valid"), "8:2\n");

        let mut device = sample_device();
        device.bbr = None;
        device.fec = None;
        assert_eq!(ugly(&device, "bbr", false).expect("valid"), "(none)\n");
        assert_eq!(ugly(&device, "fec", false).expect("valid"), "(none)\n");
        let output = showconf(&device);
        assert!(!output.contains("BBR"), "{output}");
        assert!(!output.contains("FEC"), "{output}");
    }

    #[test]
    fn shows_underlay_mtu() {
        let device = sample_device();
        assert_eq!(
            ugly(&device, "underlay-mtu", false).expect("valid"),
            "9000\n"
        );
        assert_eq!(
            ugly(&device, "underlay-mtu", true).expect("valid"),
            "uwg0\t9000\n"
        );
        let rendered = pretty(&device, false);
        assert!(rendered.contains("underlay mtu: 9000"), "{rendered}");

        let mut device = sample_device();
        device.underlay_mtu = None;
        assert_eq!(
            ugly(&device, "underlay-mtu", false).expect("valid"),
            "(none)\n"
        );
        assert!(!pretty(&device, false).contains("underlay mtu"));
    }

    #[test]
    fn shows_bbr_and_fec_stats() {
        let device = sample_device();
        assert_eq!(
            ugly(&device, "bbr-stats", false).expect("valid"),
            "mode=on\ncwnd=131072\ninflight=4096\npacing_rate=1000000\nbtl_bw=2000000\nmin_rtt_ns=12345\nround_lost=8\npeers=1\n"
        );
        assert_eq!(
            ugly(&device, "fec-stats", false).expect("valid"),
            "blocks_encoded=10\nshards_sent=12\nblocks_decoded=9\npackets_recovered=1\ndecode_fail=2\ndropped_bounds=3\ndropped_disabled=4\n"
        );
        assert_eq!(
            ugly(&device, "fec-stats", true).expect("valid"),
            "uwg0\tblocks_encoded=10\nuwg0\tshards_sent=12\nuwg0\tblocks_decoded=9\nuwg0\tpackets_recovered=1\nuwg0\tdecode_fail=2\nuwg0\tdropped_bounds=3\nuwg0\tdropped_disabled=4\n"
        );

        let mut device = sample_device();
        device.bbr_stats = None;
        device.fec_stats = None;
        assert_eq!(
            ugly(&device, "bbr-stats", false).expect("valid"),
            "(none)\n"
        );
        assert_eq!(
            ugly(&device, "fec-stats", false).expect("valid"),
            "(none)\n"
        );
        let output = pretty_at(&device, false, 1_700_000_060);
        assert!(output.contains("  bbr stats: (none)\n"), "{output}");
        assert!(output.contains("  fec stats: (none)\n"), "{output}");
    }

    #[test]
    fn bbr_stats_mode_names() {
        assert_eq!(bbr_mode_text(0), "off");
        assert_eq!(bbr_mode_text(1), "monitor");
        assert_eq!(bbr_mode_text(2), "on");
        assert_eq!(bbr_mode_text(3), "unknown");
    }

    #[test]
    fn pretty_shows_bbr_and_fec_modes() {
        let output = pretty_at(&sample_device(), false, 1_700_000_060);
        assert!(output.contains("  bbr: monitor\n"), "{output}");
        assert!(output.contains("  fec: 8:2\n"), "{output}");

        let mut device = sample_device();
        device.bbr = None;
        device.fec = None;
        let output = pretty_at(&device, false, 1_700_000_060);
        assert!(!output.contains("  bbr:"), "{output}");
        assert!(!output.contains("  fec:"), "{output}");
    }

    #[test]
    fn pretty_output_contains_fields() {
        let output = pretty_at(&sample_device(), false, 1_700_000_060);
        assert!(output.starts_with("interface: uwg0\n"));
        assert!(output.contains("  public key: "));
        assert!(output.contains("  private key: (hidden)\n"));
        assert!(output.contains("  listening port: 51820\n"));
        assert!(output.contains("  fwmark: 0x1234\n"));
        assert!(output.contains("  jc: 4\n"));
        assert!(output.contains("  h1: 10-20\n"));
        assert!(output.contains("  i1: <b 0x1><c>\n"));
        assert!(output.contains("peer: "));
        assert!(output.contains("  allowed ips: 10.0.0.0/8\n"));
        assert!(output.contains("  latest handshake: 1 minute ago\n"));
        assert!(output.contains("  transfer: 2.00 KiB received, 10 B sent\n"));
        assert!(output.contains("  persistent keepalive: 25\n"));
        assert!(output.contains("  bbr stats:\n    mode=on\n    cwnd=131072\n"));
        assert!(output.contains("  fec stats:\n    blocks_encoded=10\n"));
    }

    #[test]
    fn dump_output_has_expected_columns() {
        let output = dump(&sample_device(), true);
        let mut lines = output.lines();
        let interface: Vec<&str> = lines.next().expect("interface").split('\t').collect();
        assert_eq!(interface.len(), 30);
        assert_eq!(interface[0], "uwg0");
        assert_eq!(
            interface[1],
            sample_device().private_key.expect("key").to_base64()
        );
        assert_eq!(
            interface[2],
            sample_device().public_key.expect("key").to_base64()
        );
        let peer: Vec<&str> = lines.next().expect("peer").split('\t').collect();
        assert_eq!(peer[0], "uwg0");
        assert_eq!(peer[1], sample_device().peers[0].public_key.to_base64());
        assert_eq!(peer[3], "192.0.2.1:51820");
        assert_eq!(peer[4], "10.0.0.0/8");
        assert_eq!(peer[5], "1700000000");
        assert_eq!(peer[8], "25");
    }

    #[test]
    fn ugly_parameters() {
        let device = sample_device();
        assert!(ugly(&device, "public-key", false)
            .expect("valid")
            .starts_with(&device.public_key.clone().expect("key").to_base64()));
        assert_eq!(ugly(&device, "fwmark", false).expect("valid"), "0x1234\n");
        assert_eq!(ugly(&device, "extra-ports", false).expect("valid"), "4\n");
        assert_eq!(ugly(&device, "bbr", false).expect("valid"), "monitor\n");
        assert_eq!(ugly(&device, "fec", false).expect("valid"), "8:2\n");
        assert_eq!(ugly(&device, "jc", false).expect("valid"), "4\n");
        assert_eq!(ugly(&device, "h1", false).expect("valid"), "10-20\n");
        assert_eq!(ugly(&device, "i1", false).expect("valid"), "<b 0x1><c>\n");
        assert_eq!(
            ugly(&device, "endpoints", false).expect("valid"),
            format!(
                "{}\t192.0.2.1:51820\n",
                device.peers[0].public_key.to_base64()
            )
        );
        assert_eq!(
            ugly(&device, "allowed-ips", false).expect("valid"),
            format!("{}\t10.0.0.0/8\n", device.peers[0].public_key.to_base64())
        );
        assert_eq!(
            ugly(&device, "peers", true).expect("valid"),
            format!("uwg0\t{}\n", device.peers[0].public_key.to_base64())
        );
        assert!(ugly(&device, "bogus", false).is_err());
    }

    #[test]
    fn accepts_every_max_handshake_attempts_spelling() {
        let mut device = sample_device();
        device.obfuscation.max_handshake_attempts = Some(U16Range::new(2, 5));
        for parameter in [
            "max-handshake-attempts",
            "max-handshake-attemps",
            "max_handshake_attempts",
        ] {
            assert_eq!(
                ugly(&device, parameter, false).expect("valid"),
                "2-5\n",
                "{parameter}"
            );
        }
    }

    #[test]
    fn shows_advanced_security_state() {
        let mut device = sample_device();
        assert!(pretty_at(&device, false, 1_700_000_060).contains("  advanced security: yes\n"));
        assert_eq!(
            ugly(&device, "advanced-security", false).expect("valid"),
            format!("{}\tyes\n", device.peers[0].public_key.to_base64())
        );
        device.peers[0].advanced_security = Some(false);
        assert!(pretty_at(&device, false, 1_700_000_060).contains("  advanced security: no\n"));
        device.peers[0].advanced_security = None;
        assert!(
            pretty_at(&device, false, 1_700_000_060).contains("  advanced security: unsupported\n")
        );
        assert_eq!(
            ugly(&device, "advanced-security", false).expect("valid"),
            format!("{}\tunsupported\n", device.peers[0].public_key.to_base64())
        );
    }

    #[test]
    fn showconf_prints_advanced_security_states() {
        let mut device = sample_device();
        device.peers[0].advanced_security = Some(false);
        assert!(showconf(&device).contains("AdvancedSecurity = off\n"));
        device.peers[0].advanced_security = None;
        assert!(!showconf(&device).contains("AdvancedSecurity"));
    }

    #[test]
    fn showconf_contains_obfuscation() {
        let output = showconf(&sample_device());
        assert!(output.starts_with("[Interface]\n"));
        assert!(output.contains("ListenPort = 51820\n"));
        assert!(output.contains("ExtraPorts = 4\n"));
        assert!(output.contains("FwMark = 0x1234\n"));
        assert!(output.contains("BBR = monitor\n"));
        assert!(output.contains("FEC = 8:2\n"));
        assert!(output.contains("H1 = 10-20\n"));
        assert!(output.contains("I1 = <b 0x1><c>\n"));
        assert!(output.contains("RandomTrailers = on\n"));
        assert!(output.contains("[Peer]\nPublicKey = "));
        assert!(output.contains("AllowedIPs = 10.0.0.0/8\n"));
        assert!(output.contains("PersistentKeepalive = 25\n"));
        assert!(output.contains("AdvancedSecurity = on\n"));
        let reparsed = umbrawg_config::Config::parse(&output).expect("showconf parses");
        assert_eq!(reparsed, sample_device().to_config());
    }

    #[test]
    fn showconf_prints_extra_ports() {
        let mut device = sample_device();
        device.extra_ports = Some(0);
        assert!(!showconf(&device).contains("ExtraPorts"));
        device.extra_ports = Some(8);
        assert!(showconf(&device).contains("ExtraPorts = 8\n"));
    }

    #[test]
    fn time_and_byte_formatting() {
        assert_eq!(pretty_time(0, false), "");
        assert_eq!(pretty_time(60, false), "1 minute");
        assert_eq!(pretty_time(3661, false), "1 hour, 1 minute, 1 second");
        assert_eq!(pretty_time(2 * 365 * 24 * 60 * 60, false), "2 years");
        assert_eq!(ago(&TimeSpec::new(100, 0), 100, false), "Now");
        assert_eq!(
            ago(&TimeSpec::new(101, 0), 100, false),
            "(System clock wound backward; connection problems may ensue.)"
        );
        assert_eq!(bytes(0, false), "0 B");
        assert_eq!(bytes(1024, false), "1.00 KiB");
        assert_eq!(bytes(1024 * 1024, false), "1.00 MiB");
        assert_eq!(bytes(1024 * 1024 * 1024, false), "1.00 GiB");
        assert_eq!(bytes(1024 * 1024 * 1024 * 1024, false), "1.00 TiB");
    }

    #[test]
    fn color_mode_adds_escape_codes() {
        let output = pretty_at(&sample_device(), true, 1_700_000_060);
        assert!(output.starts_with(RESET));
        assert!(output.contains(FG_GREEN));
        assert!(output.contains(FG_YELLOW));
    }
}
