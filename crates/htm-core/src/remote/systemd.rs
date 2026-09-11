//! Driving systemd on the remote hosts.
//!
//! Status is read with `systemctl show`, whose `Key=Value` output is stable
//! and machine-oriented, rather than by scraping `systemctl status`. Logs are
//! read with journal cursors so each poll returns only what is new, which is
//! what makes the live log view cheap enough to run continuously.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::model::{IfaceStats, ServiceStatus};
use crate::ssh::SshClient;
use crate::util::sh_quote;

/// Directory unit files are written to.
pub const UNIT_DIR: &str = "/etc/systemd/system";

/// Install a unit file and reload the daemon.
pub fn write_unit(client: &SshClient, unit_name: &str, content: &str) -> Result<()> {
    let path = format!("{UNIT_DIR}/{unit_name}");
    client.write_file_priv(&path, content, "0644")?;
    daemon_reload(client)
}

/// Whether a unit file already exists on disk.
pub fn unit_exists(client: &SshClient, unit_name: &str) -> Result<bool> {
    client.path_exists(&format!("{UNIT_DIR}/{unit_name}"))
}

pub fn daemon_reload(client: &SshClient) -> Result<()> {
    client.exec_priv_ok("systemctl daemon-reload").map(|_| ())
}

/// Remove a unit file, stopping and disabling it first.
pub fn remove_unit(client: &SshClient, unit_name: &str) -> Result<()> {
    let script = format!(
        r#"#!/bin/sh
systemctl stop {unit} >/dev/null 2>&1 || true
systemctl disable {unit} >/dev/null 2>&1 || true
rm -f {path}
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed {unit} >/dev/null 2>&1 || true
exit 0
"#,
        unit = sh_quote(unit_name),
        path = sh_quote(&format!("{UNIT_DIR}/{unit_name}")),
    );
    client.run_script(&script, true)?;
    Ok(())
}

/// Run one `systemctl` verb against a unit.
///
/// `reset-failed` is issued before starting so a unit that previously hit its
/// restart limit can start again without the user having to know that.
pub fn control(client: &SshClient, unit: &str, verb: &str) -> Result<()> {
    let quoted = sh_quote(unit);
    let command = match verb {
        "start" | "restart" => format!(
            "systemctl reset-failed {quoted} >/dev/null 2>&1 || true; systemctl {verb} {quoted}"
        ),
        _ => format!("systemctl {verb} {quoted}"),
    };
    let out = client.exec_priv(&command)?;
    if out.ok() {
        return Ok(());
    }
    Err(Error::Remote {
        command,
        status: out.status,
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

/// Query one unit plus, optionally, the TUN interface it manages.
pub fn status(client: &SshClient, unit: &str, iface: Option<&str>) -> Result<ServiceStatus> {
    let script = format!(
        r#"#!/bin/sh
UNIT={unit}
systemctl show "$UNIT" --no-pager \
  --property=LoadState \
  --property=ActiveState \
  --property=SubState \
  --property=UnitFileState \
  --property=MainPID \
  --property=MemoryCurrent \
  --property=NRestarts \
  --property=ExecMainStatus \
  --property=Result \
  --property=ActiveEnterTimestampMonotonic 2>/dev/null
printf 'BootUptime=%s\n' "$(awk '{{ print int($1) }}' /proc/uptime 2>/dev/null)"
printf 'EnabledState=%s\n' "$(systemctl is-enabled "$UNIT" 2>/dev/null)"

IFACE={iface}
if [ -n "$IFACE" ] && [ -d "/sys/class/net/$IFACE" ]; then
  printf 'IfaceName=%s\n' "$IFACE"
  printf 'IfacePresent=1\n'
  printf 'IfaceOperState=%s\n' "$(cat "/sys/class/net/$IFACE/operstate" 2>/dev/null)"
  printf 'IfaceMtu=%s\n'       "$(cat "/sys/class/net/$IFACE/mtu" 2>/dev/null)"
  printf 'RxBytes=%s\n'        "$(cat "/sys/class/net/$IFACE/statistics/rx_bytes" 2>/dev/null)"
  printf 'TxBytes=%s\n'        "$(cat "/sys/class/net/$IFACE/statistics/tx_bytes" 2>/dev/null)"
  printf 'RxPackets=%s\n'      "$(cat "/sys/class/net/$IFACE/statistics/rx_packets" 2>/dev/null)"
  printf 'TxPackets=%s\n'      "$(cat "/sys/class/net/$IFACE/statistics/tx_packets" 2>/dev/null)"
  printf 'RxErrors=%s\n'       "$(cat "/sys/class/net/$IFACE/statistics/rx_errors" 2>/dev/null)"
  printf 'TxErrors=%s\n'       "$(cat "/sys/class/net/$IFACE/statistics/tx_errors" 2>/dev/null)"
else
  printf 'IfacePresent=0\n'
fi
exit 0
"#,
        unit = sh_quote(unit),
        iface = sh_quote(iface.unwrap_or("")),
    );

    let out = client.run_script(&script, false)?;
    let map = parse_properties(&out.stdout);
    Ok(build_status(&map))
}

/// Status for several units in one round trip.
///
/// `units` pairs a unit name with the TUN interface belonging to it.
pub fn status_many(
    client: &SshClient,
    units: &[(String, Option<String>)],
) -> Result<Vec<ServiceStatus>> {
    let mut out = Vec::with_capacity(units.len());
    for (unit, iface) in units {
        match status(client, unit, iface.as_deref()) {
            Ok(s) => out.push(s),
            Err(e) => out.push(ServiceStatus {
                query_error: Some(e.to_string()),
                ..Default::default()
            }),
        }
    }
    Ok(out)
}

fn build_status(map: &BTreeMap<String, String>) -> ServiceStatus {
    let get = |k: &str| map.get(k).cloned().unwrap_or_default();
    let num = |k: &str| -> Option<u64> {
        let raw = get(k);
        // systemd writes `[not set]` or a huge sentinel for unset values.
        if raw.is_empty() || raw.starts_with('[') {
            return None;
        }
        raw.parse::<u64>().ok().filter(|v| *v != u64::MAX)
    };

    let pid = num("MainPID").filter(|p| *p != 0).map(|p| p as u32);
    let memory = num("MemoryCurrent");

    // `ActiveEnterTimestampMonotonic` is microseconds since boot, so the age of
    // the unit is uptime minus that.
    let since_secs = match (num("ActiveEnterTimestampMonotonic"), num("BootUptime")) {
        (Some(enter_us), Some(uptime_s)) if enter_us > 0 => {
            let enter_s = enter_us / 1_000_000;
            uptime_s.checked_sub(enter_s)
        }
        _ => None,
    };

    let iface = if get("IfacePresent") == "1" {
        Some(IfaceStats {
            name: get("IfaceName"),
            up: matches!(get("IfaceOperState").as_str(), "up" | "unknown"),
            rx_bytes: num("RxBytes").unwrap_or(0),
            tx_bytes: num("TxBytes").unwrap_or(0),
            rx_packets: num("RxPackets").unwrap_or(0),
            tx_packets: num("TxPackets").unwrap_or(0),
            rx_errors: num("RxErrors").unwrap_or(0),
            tx_errors: num("TxErrors").unwrap_or(0),
            mtu: num("IfaceMtu").unwrap_or(0) as u32,
        })
    } else {
        None
    };

    let exit_code = {
        let raw = get("ExecMainStatus");
        raw.parse::<i32>().ok().filter(|c| *c != 0)
    };

    ServiceStatus {
        load_state: get("LoadState"),
        active_state: get("ActiveState"),
        sub_state: get("SubState"),
        enabled: matches!(
            get("EnabledState").as_str(),
            "enabled" | "enabled-runtime" | "static" | "indirect"
        ) || get("UnitFileState") == "enabled",
        pid,
        memory_bytes: memory,
        since_secs,
        restarts: num("NRestarts").map(|v| v as u32),
        exit_code,
        iface,
        query_error: None,
    }
}

/// Journal lines and the cursor to continue from.
#[derive(Debug, Clone, Default)]
pub struct JournalChunk {
    pub lines: Vec<String>,
    pub cursor: Option<String>,
}

/// Read a unit's journal.
///
/// Pass the cursor from the previous call to get only what is new. Without a
/// cursor the last `lines` entries are returned.
pub fn journal(
    client: &SshClient,
    unit: &str,
    lines: u32,
    after_cursor: Option<&str>,
) -> Result<JournalChunk> {
    let selector = match after_cursor {
        Some(cursor) if !cursor.is_empty() => {
            format!("--after-cursor {} --lines {}", sh_quote(cursor), lines.max(1))
        }
        _ => format!("--lines {}", lines.max(1)),
    };

    let command = format!(
        "journalctl --unit {unit} --no-pager --output=short-iso --show-cursor {selector} 2>&1",
        unit = sh_quote(unit),
    );

    // The journal is normally root-only, so read it with privileges when we
    // have them and fall back to an unprivileged read otherwise.
    let out = if client.priv_mode().can_escalate() {
        client.exec_priv(&command)?
    } else {
        client.exec(&command)?
    };

    let mut chunk = JournalChunk::default();
    for line in out.stdout.lines() {
        let trimmed = line.trim_end_matches('\r');
        if let Some(cursor) = trimmed.strip_prefix("-- cursor: ") {
            chunk.cursor = Some(cursor.trim().to_string());
            continue;
        }
        // journalctl's own notices are noise in a log pane.
        if trimmed.starts_with("-- No entries")
            || trimmed.starts_with("-- Logs begin")
            || trimmed.starts_with("-- Journal begins")
            || trimmed.starts_with("-- Reboot --")
            || trimmed.trim().is_empty()
        {
            continue;
        }
        chunk.lines.push(trimmed.to_string());
    }

    // Keep the previous cursor when this poll returned nothing new, otherwise
    // the next poll would re-read the whole tail.
    if chunk.cursor.is_none() {
        chunk.cursor = after_cursor.map(|c| c.to_string());
    }

    Ok(chunk)
}

/// Read TUN interface counters on their own, without a unit query.
pub fn iface_stats(client: &SshClient, iface: &str) -> Result<Option<IfaceStats>> {
    if iface.is_empty() {
        return Ok(None);
    }
    let script = format!(
        r#"#!/bin/sh
IFACE={iface}
[ -d "/sys/class/net/$IFACE" ] || exit 0
printf 'IfaceName=%s\n'      "$IFACE"
printf 'IfacePresent=1\n'
printf 'IfaceOperState=%s\n' "$(cat "/sys/class/net/$IFACE/operstate" 2>/dev/null)"
printf 'IfaceMtu=%s\n'       "$(cat "/sys/class/net/$IFACE/mtu" 2>/dev/null)"
printf 'RxBytes=%s\n'        "$(cat "/sys/class/net/$IFACE/statistics/rx_bytes" 2>/dev/null)"
printf 'TxBytes=%s\n'        "$(cat "/sys/class/net/$IFACE/statistics/tx_bytes" 2>/dev/null)"
printf 'RxPackets=%s\n'      "$(cat "/sys/class/net/$IFACE/statistics/rx_packets" 2>/dev/null)"
printf 'TxPackets=%s\n'      "$(cat "/sys/class/net/$IFACE/statistics/tx_packets" 2>/dev/null)"
printf 'RxErrors=%s\n'       "$(cat "/sys/class/net/$IFACE/statistics/rx_errors" 2>/dev/null)"
printf 'TxErrors=%s\n'       "$(cat "/sys/class/net/$IFACE/statistics/tx_errors" 2>/dev/null)"
exit 0
"#,
        iface = sh_quote(iface),
    );
    let out = client.run_script(&script, false)?;
    let map = parse_properties(&out.stdout);
    Ok(build_status(&map).iface)
}

/// Parse `Key=Value` lines. Values may contain `=`; keys may not.
fn parse_properties(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_built_from_systemctl_show_output() {
        let text = "\
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
MainPID=4242
MemoryCurrent=10485760
NRestarts=2
ExecMainStatus=0
Result=success
ActiveEnterTimestampMonotonic=60000000
BootUptime=300
EnabledState=enabled
IfacePresent=1
IfaceName=candy0
IfaceOperState=unknown
IfaceMtu=1380
RxBytes=1000
TxBytes=2000
RxPackets=10
TxPackets=20
RxErrors=0
TxErrors=0
";
        let s = build_status(&parse_properties(text));
        assert!(s.is_active());
        assert!(s.exists());
        assert!(s.enabled);
        assert_eq!(s.pid, Some(4242));
        assert_eq!(s.memory_bytes, Some(10_485_760));
        assert_eq!(s.restarts, Some(2));
        assert_eq!(s.exit_code, None);
        // 300s uptime, entered active 60s after boot.
        assert_eq!(s.since_secs, Some(240));
        let iface = s.iface.expect("interface stats");
        assert_eq!(iface.name, "candy0");
        assert!(iface.up);
        assert_eq!(iface.tx_bytes, 2000);
    }

    #[test]
    fn unset_systemd_values_become_none() {
        let text = "\
LoadState=not-found
ActiveState=inactive
SubState=dead
MainPID=0
MemoryCurrent=[not set]
ExecMainStatus=1
IfacePresent=0
";
        let s = build_status(&parse_properties(text));
        assert!(!s.exists());
        assert!(!s.is_active());
        assert_eq!(s.pid, None);
        assert_eq!(s.memory_bytes, None);
        assert_eq!(s.exit_code, Some(1));
        assert!(s.iface.is_none());
    }
}
