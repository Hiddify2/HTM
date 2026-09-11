//! Working out what a remote host is.
//!
//! Everything is collected by one uploaded shell script that prints
//! `key=value` lines, so the whole probe costs a single command round trip and
//! the parsing has no quoting hazards.

use crate::error::Result;
use crate::model::{PackageManager, ServerFacts};
use crate::ssh::{PrivMode, SshClient};
use crate::util;

/// The probe script. Every value is optional; a missing tool yields an empty
/// field rather than a failure, and the caller decides what is fatal.
const PROBE: &str = r#"#!/bin/sh
# HTM host probe. Prints key=value lines; never fails the whole run.

emit() { printf '%s=%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1 && echo 1 || echo 0; }

OS_ID=""; OS_PRETTY=""; OS_VERSION=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release 2>/dev/null
  OS_ID="${ID:-}"
  OS_PRETTY="${PRETTY_NAME:-}"
  OS_VERSION="${VERSION_ID:-}"
fi
emit os_id "$OS_ID"
emit os_pretty "$OS_PRETTY"
emit os_version "$OS_VERSION"

emit kernel "$(uname -r 2>/dev/null)"
emit arch "$(uname -m 2>/dev/null)"
emit login_user "$(id -un 2>/dev/null)"
emit uid "$(id -u 2>/dev/null)"

CORES="$(nproc 2>/dev/null)"
if [ -z "$CORES" ]; then
  CORES="$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
fi
emit cpu_cores "$CORES"

CPU="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^[[:space:]]*//')"
if [ -z "$CPU" ]; then
  CPU="$(grep -m1 'Model' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^[[:space:]]*//')"
fi
emit cpu_model "$CPU"

emit mem_total_kb "$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo 2>/dev/null)"
emit uptime_secs "$(awk '{ print int($1) }' /proc/uptime 2>/dev/null)"
emit root_free_kb "$(df -Pk / 2>/dev/null | awk 'NR == 2 { print $4 }')"

# Interface carrying the default route, then its address and MTU.
IFACE="$(ip -4 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i+1); exit } }')"
if [ -z "$IFACE" ]; then
  IFACE="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i+1); exit } }')"
fi
emit iface "$IFACE"

LOCAL_IP=""
if [ -n "$IFACE" ]; then
  LOCAL_IP="$(ip -4 -o addr show dev "$IFACE" scope global 2>/dev/null | awk '{ print $4 }' | cut -d/ -f1 | head -n 1)"
  emit iface_mtu "$(cat "/sys/class/net/$IFACE/mtu" 2>/dev/null)"
else
  emit iface_mtu ""
fi
if [ -z "$LOCAL_IP" ]; then
  LOCAL_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i+1); exit } }')"
fi
emit local_ip "$LOCAL_IP"

# systemd has to be PID 1, not merely installed.
HAS_SYSTEMCTL="$(have systemctl)"
IS_SYSTEMD=0
if [ -d /run/systemd/system ]; then IS_SYSTEMD=1; fi
emit has_systemd "$HAS_SYSTEMCTL"
emit systemd_running "$IS_SYSTEMD"

TUN=0
if [ -c /dev/net/tun ]; then TUN=1; fi
emit has_tun "$TUN"

emit has_iptables "$(have iptables)"
emit has_iperf3 "$(have iperf3)"
emit has_python3 "$(have python3)"
emit has_curl "$(have curl)"
emit has_wget "$(have wget)"
emit has_ip "$(have ip)"
emit has_ping "$(have ping)"
emit has_cargo "$(have cargo)"
emit has_git "$(have git)"

PKG=unknown
if   command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf     >/dev/null 2>&1; then PKG=dnf
elif command -v yum     >/dev/null 2>&1; then PKG=yum
elif command -v pacman  >/dev/null 2>&1; then PKG=pacman
elif command -v apk     >/dev/null 2>&1; then PKG=apk
elif command -v zypper  >/dev/null 2>&1; then PKG=zypper
fi
emit pkg "$PKG"

emit virt "$(systemd-detect-virt 2>/dev/null || echo unknown)"
exit 0
"#;

/// Services asked, in order, for the address the internet sees. Each one is
/// given a short timeout so an unreachable service costs little.
const PUBLIC_IP_SCRIPT: &str = r#"#!/bin/sh
for url in \
  "https://api.ipify.org" \
  "https://ipv4.icanhazip.com" \
  "https://ifconfig.me/ip" \
  "https://checkip.amazonaws.com"
do
  if command -v curl >/dev/null 2>&1; then
    ip="$(curl -4 -fsS --max-time 6 "$url" 2>/dev/null | tr -d '[:space:]')"
  elif command -v wget >/dev/null 2>&1; then
    ip="$(wget -4 -qO- --timeout=6 "$url" 2>/dev/null | tr -d '[:space:]')"
  else
    ip=""
  fi
  case "$ip" in
    *[!0-9.]*|"") : ;;
    *) printf '%s\n' "$ip"; exit 0 ;;
  esac
done
exit 1
"#;

/// Probe a host. `discover_public_ip` costs an outbound HTTPS request from the
/// server, so it can be skipped on a network where that would hang.
pub fn gather(client: &SshClient, discover_public_ip: bool) -> Result<ServerFacts> {
    let out = client.run_script(PROBE, false)?;
    // A non-zero status here still leaves usable output, so parse first and
    // only complain if nothing came back at all.
    let map = parse_kv(&out.stdout);
    if map.is_empty() {
        return Err(crate::error::Error::Parse {
            what: "host probe output".to_string(),
            detail: format!(
                "the probe produced nothing. stderr was: {}",
                util::truncate(out.stderr.trim(), 300)
            ),
        });
    }

    let get = |k: &str| map.get(k).cloned().unwrap_or_default();
    let num = |k: &str| get(k).parse::<u64>().unwrap_or(0);
    let flag = |k: &str| get(k) == "1";

    let priv_mode = client.priv_mode();
    let mut facts = ServerFacts {
        os_id: get("os_id"),
        os_pretty: get("os_pretty"),
        os_version: get("os_version"),
        kernel: get("kernel"),
        arch: normalize_arch(&get("arch")),

        cpu_model: get("cpu_model"),
        cpu_cores: num("cpu_cores") as u32,
        mem_total_kb: num("mem_total_kb"),

        login_user: get("login_user"),
        is_root: get("uid") == "0",
        passwordless_sudo: priv_mode == PrivMode::SudoNoPassword,
        can_escalate: priv_mode.can_escalate(),

        package_manager: parse_package_manager(&get("pkg")),
        has_systemd: flag("has_systemd") && flag("systemd_running"),

        default_iface: get("iface"),
        local_ipv4: get("local_ip"),
        public_ipv4: String::new(),
        iface_mtu: num("iface_mtu") as u32,

        has_tun: flag("has_tun"),
        has_iptables: flag("has_iptables"),
        has_iperf3: flag("has_iperf3"),
        has_python3: flag("has_python3"),
        has_curl: flag("has_curl"),
        root_free_kb: num("root_free_kb"),
        uptime_secs: num("uptime_secs"),
    };

    if facts.os_pretty.is_empty() && !facts.os_id.is_empty() {
        facts.os_pretty = format!("{} {}", facts.os_id, facts.os_version)
            .trim()
            .to_string();
    }

    if discover_public_ip {
        facts.public_ipv4 = discover_public_ipv4(client).unwrap_or_default();
    }
    if facts.public_ipv4.is_empty() {
        // Falling back to the interface address is right for the common case
        // of a directly addressed VPS.
        facts.public_ipv4 = facts.local_ipv4.clone();
    }

    Ok(facts)
}

/// Ask the host what address the internet sees it as.
pub fn discover_public_ipv4(client: &SshClient) -> Option<String> {
    let out = client.run_script(PUBLIC_IP_SCRIPT, false).ok()?;
    let candidate = out.first_line().to_string();
    if crate::model::is_ipv4(&candidate) {
        Some(candidate)
    } else {
        None
    }
}

/// Whether the kernel can give us a TUN device, loading the module if needed.
pub fn ensure_tun_available(client: &SshClient) -> Result<bool> {
    if client.path_exists("/dev/net/tun")? {
        return Ok(true);
    }
    // Loading the module needs root; a container without the device simply
    // cannot run a tunnel and the caller reports that.
    let _ = client.exec_priv("modprobe tun 2>/dev/null || true");
    client.path_exists("/dev/net/tun")
}

/// Parse `key=value` lines, keeping the last occurrence of a repeated key.
fn parse_kv(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            if !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                map.insert(k.to_string(), v.trim().to_string());
            }
        }
    }
    map
}

fn parse_package_manager(raw: &str) -> PackageManager {
    match raw {
        "apt" => PackageManager::Apt,
        "dnf" => PackageManager::Dnf,
        "yum" => PackageManager::Yum,
        "pacman" => PackageManager::Pacman,
        "apk" => PackageManager::Apk,
        "zypper" => PackageManager::Zypper,
        _ => PackageManager::Unknown,
    }
}

/// Map the many spellings `uname -m` produces onto the names release assets
/// use.
pub fn normalize_arch(raw: &str) -> String {
    match raw.trim() {
        "x86_64" | "amd64" => "x86_64".to_string(),
        "aarch64" | "arm64" => "aarch64".to_string(),
        "armv7l" | "armv7" | "armhf" => "armv7".to_string(),
        "i386" | "i486" | "i586" | "i686" => "i686".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_values_are_parsed() {
        let map = parse_kv("a=1\nb=hello world\n\nnot a pair\nc=\n");
        assert_eq!(map.get("a").map(String::as_str), Some("1"));
        assert_eq!(map.get("b").map(String::as_str), Some("hello world"));
        assert_eq!(map.get("c").map(String::as_str), Some(""));
        assert!(!map.contains_key("not a pair"));
    }

    #[test]
    fn values_containing_equals_survive() {
        let map = parse_kv("cpu_model=Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n");
        assert!(map.get("cpu_model").unwrap().contains("2.40GHz"));
    }

    #[test]
    fn architectures_are_normalised() {
        assert_eq!(normalize_arch("amd64"), "x86_64");
        assert_eq!(normalize_arch("arm64"), "aarch64");
        assert_eq!(normalize_arch("riscv64"), "riscv64");
    }
}
