//! Network measurement: latency, throughput and jitter across a live tunnel.
//!
//! Two measurement backends are supported and produce the same
//! [`ThroughputSample`]:
//!
//! * **iperf3**, when it is installed or can be installed. It is the tool
//!   everyone compares numbers against.
//! * **A bundled Python probe** ([`PROBE_SOURCE`]), uploaded by HTM. It needs
//!   nothing but `python3` and exists so benchmarking still works on hosts
//!   where installing packages is impossible.
//!
//! In both cases the figure HTM keeps is the **receiver's** byte count, since
//! that is what actually crossed the tunnel.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::ssh::SshClient;
use crate::util::{first_f64, sh_quote};

/// The Python probe, embedded at compile time so there is exactly one copy.
pub const PROBE_SOURCE: &str = include_str!("probe.py");

/// Where the probe and its result file live on a remote host.
pub const PROBE_PATH: &str = "/opt/htm/htm-probe.py";
pub const PROBE_RESULT: &str = "/tmp/htm-probe-result.json";

// ── Latency ──────────────────────────────────────────────────────────────────

/// Parsed output of `ping`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PingSample {
    pub transmitted: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
    /// Mean deviation. `ping` from busybox does not report it; then it is 0.
    pub mdev_ms: f64,
}

impl PingSample {
    pub fn is_usable(&self) -> bool {
        self.received > 0 && self.avg_ms > 0.0
    }
}

/// Ping `target` from `client`.
///
/// `-n` keeps `ping` from doing reverse DNS on every reply, which would
/// otherwise add seconds on hosts with no resolver.
pub fn ping(
    client: &SshClient,
    target: &str,
    count: u32,
    interval_ms: u32,
    source_ip: Option<&str>,
) -> Result<PingSample> {
    let count = count.clamp(1, 500);
    let interval = (interval_ms.clamp(20, 5000) as f64) / 1000.0;
    // Allow the whole run plus generous slack for the final timeouts.
    let budget = ((count as f64 * interval) + 15.0).ceil() as u64;

    let source = match source_ip {
        Some(ip) if !ip.is_empty() => format!("-I {} ", sh_quote(ip)),
        _ => String::new(),
    };

    // `-i` below 0.2s needs root on most systems, which HTM has.
    let command = format!(
        "ping -n -q -c {count} -i {interval:.3} -W 2 {source}{target} 2>&1",
        target = sh_quote(target),
    );

    client.set_command_timeout(budget + 20);
    let out = if client.priv_mode().can_escalate() {
        client.exec_priv(&command)
    } else {
        client.exec(&command)
    };
    client.reset_command_timeout();
    let out = out?;

    let sample = parse_ping(&out.combined());
    if sample.transmitted == 0 {
        return Err(Error::Parse {
            what: "ping output".to_string(),
            detail: crate::util::truncate(&out.combined(), 400),
        });
    }
    Ok(sample)
}

/// Parse the summary block from iputils or busybox `ping`.
pub fn parse_ping(text: &str) -> PingSample {
    let mut sample = PingSample::default();

    for line in text.lines() {
        let line = line.trim();

        // "20 packets transmitted, 20 received, 0% packet loss, time 3805ms"
        // busybox: "20 packets transmitted, 20 packets received, 0% packet loss"
        if line.contains("packets transmitted") {
            let parts: Vec<&str> = line.split(',').collect();
            for part in &parts {
                let part = part.trim();
                if part.contains("transmitted") {
                    if let Some(v) = first_f64(part) {
                        sample.transmitted = v as u32;
                    }
                } else if part.contains("received") {
                    if let Some(v) = first_f64(part) {
                        sample.received = v as u32;
                    }
                } else if part.contains("packet loss") {
                    if let Some(v) = first_f64(part) {
                        sample.loss_pct = v;
                    }
                }
            }
        }

        // "rtt min/avg/max/mdev = 0.234/0.312/0.456/0.045 ms"
        // busybox: "round-trip min/avg/max = 0.234/0.312/0.456 ms"
        if (line.starts_with("rtt ") || line.starts_with("round-trip "))
            && line.contains('=')
        {
            if let Some((_, values)) = line.split_once('=') {
                let values = values.trim().trim_end_matches(" ms").trim();
                let nums: Vec<f64> = values
                    .split('/')
                    .filter_map(|v| v.trim().parse::<f64>().ok())
                    .collect();
                if nums.len() >= 3 {
                    sample.min_ms = nums[0];
                    sample.avg_ms = nums[1];
                    sample.max_ms = nums[2];
                }
                if nums.len() >= 4 {
                    sample.mdev_ms = nums[3];
                }
            }
        }
    }

    // Derive loss when the line did not carry it explicitly.
    if sample.transmitted > 0 && sample.loss_pct == 0.0 && sample.received < sample.transmitted {
        let lost = sample.transmitted - sample.received;
        sample.loss_pct = lost as f64 * 100.0 / sample.transmitted as f64;
    }
    sample
}

/// A single reachability check, used for tunnel readiness polling.
pub fn ping_once(client: &SshClient, target: &str, timeout_secs: u32) -> Result<bool> {
    let command = format!(
        "ping -n -q -c 1 -W {timeout} {target} >/dev/null 2>&1 && echo up || echo down",
        timeout = timeout_secs.clamp(1, 30),
        target = sh_quote(target),
    );
    client.set_command_timeout((timeout_secs as u64) + 15);
    let out = if client.priv_mode().can_escalate() {
        client.exec_priv(&command)
    } else {
        client.exec(&command)
    };
    client.reset_command_timeout();
    Ok(out?.first_line() == "up")
}

// ── Throughput ───────────────────────────────────────────────────────────────

/// One throughput measurement, whichever tool produced it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ThroughputSample {
    pub bits_per_second: f64,
    pub bytes: u64,
    pub seconds: f64,
    /// TCP retransmissions, when the tool reports them.
    pub retransmits: u64,
    /// UDP only.
    pub jitter_ms: f64,
    /// UDP only.
    pub lost_percent: f64,
    /// Which tool produced this: `iperf3` or `probe`.
    pub tool: String,
}

/// Which measurement backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Iperf3,
    Probe,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Backend::Iperf3 => "iperf3",
            Backend::Probe => "probe",
        }
    }
}

/// A running measurement server on the exit host, stopped on drop by the
/// caller via [`stop_server`].
#[derive(Debug, Clone)]
pub struct ServerHandle {
    pub backend: Backend,
    pub port: u16,
    pub result_path: String,
}

/// Upload the bundled probe to a host, if it is not already current.
pub fn ensure_probe_installed(client: &SshClient) -> Result<()> {
    // A content hash avoids re-uploading on every benchmark variant.
    let expected = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(PROBE_SOURCE.as_bytes());
        crate::util::hex_colon(&digest[..8]).replace(':', "")
    };
    let marker = format!("{PROBE_PATH}.sha");

    if let Ok(existing) = client.read_file(&marker) {
        if existing.trim() == expected && client.path_exists(PROBE_PATH)? {
            return Ok(());
        }
    }

    client.write_file_priv(PROBE_PATH, PROBE_SOURCE, "0755")?;
    client.write_file_priv(&marker, &format!("{expected}\n"), "0644")?;
    Ok(())
}

/// Start the measurement server on the exit host.
///
/// The process is detached with `setsid` and `nohup` so it survives the SSH
/// channel closing, and it terminates by itself once the test finishes or its
/// timeout expires — a benchmark that is cancelled mid-run therefore does not
/// leave listeners behind.
pub fn start_server(
    client: &SshClient,
    backend: Backend,
    bind_ip: &str,
    port: u16,
    udp: bool,
    seconds: u32,
    streams: u32,
    datagram_size: u32,
) -> Result<ServerHandle> {
    // Clear any previous result so a stale file cannot be mistaken for this run.
    let result_path = format!("{PROBE_RESULT}.{port}");
    let _ = client.exec(&format!("rm -f {}", sh_quote(&result_path)));

    let command = match backend {
        Backend::Iperf3 => {
            // `-1` makes the daemon exit after one client, and the overall
            // `timeout` is a backstop if no client ever arrives.
            format!(
                "timeout {budget} iperf3 --server --one-off --bind {bind} --port {port} \
                 --json --logfile {log} >/dev/null 2>&1",
                budget = seconds as u64 + 60,
                bind = sh_quote(bind_ip),
                port = port,
                log = sh_quote(&result_path),
            )
        }
        Backend::Probe => format!(
            "timeout {budget} python3 {probe} serve --bind {bind} --port {port} --mode {mode} \
             --seconds {seconds} --streams {streams} --datagram-size {dgram} --out {out} \
             >/dev/null 2>&1",
            budget = seconds as u64 + 75,
            probe = sh_quote(PROBE_PATH),
            bind = sh_quote(bind_ip),
            port = port,
            mode = if udp { "udp" } else { "tcp" },
            seconds = seconds,
            streams = streams.max(1),
            dgram = datagram_size,
            out = sh_quote(&result_path),
        ),
    };

    // setsid detaches from the session so closing the SSH channel does not
    // deliver SIGHUP to the listener.
    let launch = format!("setsid nohup sh -c {} >/dev/null 2>&1 &", sh_quote(&command));
    client.exec_priv(&launch)?;

    Ok(ServerHandle {
        backend,
        port,
        result_path,
    })
}

/// Kill whatever is still listening on the measurement port.
pub fn stop_server(client: &SshClient, handle: &ServerHandle) {
    let pattern = match handle.backend {
        Backend::Iperf3 => format!("iperf3 --server --one-off .*--port {}", handle.port),
        Backend::Probe => format!("htm-probe.py serve .*--port {}", handle.port),
    };
    let _ = client.exec_priv(&format!(
        "pkill -f {} >/dev/null 2>&1 || true",
        sh_quote(&pattern)
    ));
}

/// Run the client side of a TCP throughput test and return the measurement.
///
/// `reverse` measures the exit-to-relay direction.
#[allow(clippy::too_many_arguments)]
pub fn run_tcp_client(
    client: &SshClient,
    backend: Backend,
    server_ip: &str,
    port: u16,
    seconds: u32,
    streams: u32,
    reverse: bool,
    bind_ip: Option<&str>,
    cancel: &Arc<AtomicBool>,
) -> Result<ThroughputSample> {
    let budget = Duration::from_secs(seconds as u64 + 90);

    let command = match backend {
        Backend::Iperf3 => {
            let bind = match bind_ip {
                Some(ip) if !ip.is_empty() => format!("--bind {} ", sh_quote(ip)),
                _ => String::new(),
            };
            format!(
                "iperf3 --client {server} --port {port} --time {seconds} --parallel {streams} \
                 --connect-timeout 15000 {bind}{reverse}--json",
                server = sh_quote(server_ip),
                port = port,
                seconds = seconds,
                streams = streams.max(1),
                reverse = if reverse { "--reverse " } else { "" },
            )
        }
        Backend::Probe => format!(
            "python3 {probe} client --host {server} --port {port} --mode tcp --seconds {seconds} \
             --streams {streams} {reverse}",
            probe = sh_quote(PROBE_PATH),
            server = sh_quote(server_ip),
            port = port,
            seconds = seconds,
            streams = streams.max(1),
            reverse = if reverse { "--reverse" } else { "" },
        ),
    };

    let mut captured = String::new();
    let status = client.run_script_stream(
        &format!("#!/bin/sh\n{command}\n"),
        true,
        cancel,
        budget,
        |line| {
            captured.push_str(line);
            captured.push('\n');
        },
    )?;

    match backend {
        Backend::Iperf3 => parse_iperf3_tcp(&captured, reverse).ok_or_else(|| Error::Parse {
            what: "iperf3 output".to_string(),
            detail: describe_failure(status, &captured),
        }),
        Backend::Probe => parse_probe(&captured).ok_or_else(|| Error::Parse {
            what: "probe output".to_string(),
            detail: describe_failure(status, &captured),
        }),
    }
}

/// Run the client side of a UDP jitter and loss test.
#[allow(clippy::too_many_arguments)]
pub fn run_udp_client(
    client: &SshClient,
    backend: Backend,
    server_ip: &str,
    port: u16,
    seconds: u32,
    mbits: u32,
    datagram_size: u32,
    bind_ip: Option<&str>,
    cancel: &Arc<AtomicBool>,
) -> Result<ThroughputSample> {
    let budget = Duration::from_secs(seconds as u64 + 90);

    let command = match backend {
        Backend::Iperf3 => {
            let bind = match bind_ip {
                Some(ip) if !ip.is_empty() => format!("--bind {} ", sh_quote(ip)),
                _ => String::new(),
            };
            format!(
                "iperf3 --client {server} --port {port} --udp --bitrate {mbits}M \
                 --time {seconds} --length {dgram} --connect-timeout 15000 {bind}--json",
                server = sh_quote(server_ip),
                port = port,
                mbits = mbits.max(1),
                seconds = seconds,
                dgram = datagram_size,
            )
        }
        Backend::Probe => format!(
            "python3 {probe} client --host {server} --port {port} --mode udp --seconds {seconds} \
             --mbits {mbits} --datagram-size {dgram}",
            probe = sh_quote(PROBE_PATH),
            server = sh_quote(server_ip),
            port = port,
            seconds = seconds,
            mbits = mbits.max(1),
            dgram = datagram_size,
        ),
    };

    let mut captured = String::new();
    let status = client.run_script_stream(
        &format!("#!/bin/sh\n{command}\n"),
        true,
        cancel,
        budget,
        |line| {
            captured.push_str(line);
            captured.push('\n');
        },
    )?;

    match backend {
        Backend::Iperf3 => parse_iperf3_udp(&captured).ok_or_else(|| Error::Parse {
            what: "iperf3 UDP output".to_string(),
            detail: describe_failure(status, &captured),
        }),
        // The client only knows what it sent; loss and jitter come from the
        // server's result file, merged in by the caller.
        Backend::Probe => parse_probe(&captured).ok_or_else(|| Error::Parse {
            what: "probe UDP output".to_string(),
            detail: describe_failure(status, &captured),
        }),
    }
}

/// Read the measurement server's own result file.
///
/// For an uplink test this is the authoritative number, and for a UDP test it
/// is the only place loss and jitter are known.
pub fn read_server_result(
    client: &SshClient,
    handle: &ServerHandle,
    udp: bool,
) -> Option<ThroughputSample> {
    // The server writes its file as it exits; give it a moment.
    for attempt in 0..12 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(400));
        }
        let Ok(text) = client.read_file(&handle.result_path) else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        let parsed = match handle.backend {
            Backend::Iperf3 => {
                if udp {
                    parse_iperf3_udp(&text)
                } else {
                    // The server log records the same session; the receiver
                    // figure is `sum_received`.
                    parse_iperf3_tcp(&text, false)
                }
            }
            Backend::Probe => parse_probe(&text),
        };
        if parsed.is_some() {
            return parsed;
        }
    }
    None
}

/// Turn a failed measurement into a message worth showing.
fn describe_failure(status: i32, output: &str) -> String {
    let trimmed = crate::util::tail_lines(output.trim(), 8);
    if trimmed.is_empty() {
        format!("the command exited with status {status} and produced no output")
    } else {
        format!("exit status {status}: {}", crate::util::truncate(&trimmed, 500))
    }
}

/// Pull the first JSON object out of a blob that may also contain log noise.
fn extract_json(text: &str) -> Option<Value> {
    // The common case: the whole thing is JSON.
    if let Ok(v) = serde_json::from_str::<Value>(text.trim()) {
        return Some(v);
    }
    // Otherwise find the outermost braces and try that span.
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str::<Value>(&text[start..=end]).ok()
}

/// Parse an iperf3 TCP result.
///
/// `end.sum_received` is the receiver's view and is what HTM keeps.
pub fn parse_iperf3_tcp(text: &str, _reverse: bool) -> Option<ThroughputSample> {
    let v = extract_json(text)?;
    if let Some(err) = v.get("error").and_then(Value::as_str) {
        log::debug!("iperf3 reported an error: {err}");
        return None;
    }
    let end = v.get("end")?;

    let received = end.get("sum_received");
    let sent = end.get("sum_sent");

    let bits = received
        .and_then(|s| s.get("bits_per_second"))
        .and_then(Value::as_f64)
        .or_else(|| {
            sent.and_then(|s| s.get("bits_per_second"))
                .and_then(Value::as_f64)
        })?;

    let bytes = received
        .and_then(|s| s.get("bytes"))
        .and_then(Value::as_u64)
        .or_else(|| sent.and_then(|s| s.get("bytes")).and_then(Value::as_u64))
        .unwrap_or(0);

    let seconds = received
        .and_then(|s| s.get("seconds"))
        .and_then(Value::as_f64)
        .unwrap_or(0.0);

    let retransmits = sent
        .and_then(|s| s.get("retransmits"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    Some(ThroughputSample {
        bits_per_second: bits,
        bytes,
        seconds,
        retransmits,
        jitter_ms: 0.0,
        lost_percent: 0.0,
        tool: "iperf3".to_string(),
    })
}

/// Parse an iperf3 UDP result.
pub fn parse_iperf3_udp(text: &str) -> Option<ThroughputSample> {
    let v = extract_json(text)?;
    if v.get("error").is_some() {
        return None;
    }
    let end = v.get("end")?;
    // iperf3 puts the UDP summary under `sum`, and under `sum_received` on
    // some versions when the server side is reporting.
    let sum = end.get("sum").or_else(|| end.get("sum_received"))?;

    Some(ThroughputSample {
        bits_per_second: sum
            .get("bits_per_second")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        bytes: sum.get("bytes").and_then(Value::as_u64).unwrap_or(0),
        seconds: sum.get("seconds").and_then(Value::as_f64).unwrap_or(0.0),
        retransmits: 0,
        jitter_ms: sum.get("jitter_ms").and_then(Value::as_f64).unwrap_or(0.0),
        lost_percent: sum
            .get("lost_percent")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        tool: "iperf3".to_string(),
    })
}

/// Parse the bundled probe's JSON, for either mode.
pub fn parse_probe(text: &str) -> Option<ThroughputSample> {
    let v = extract_json(text)?;
    if v.get("error").is_some() && v.get("bits_per_second").is_none() {
        return None;
    }
    Some(ThroughputSample {
        bits_per_second: v
            .get("bits_per_second")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        bytes: v.get("bytes").and_then(Value::as_u64).unwrap_or(0),
        seconds: v.get("seconds").and_then(Value::as_f64).unwrap_or(0.0),
        retransmits: 0,
        jitter_ms: v.get("jitter_ms").and_then(Value::as_f64).unwrap_or(0.0),
        lost_percent: v
            .get("lost_percent")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        tool: "probe".to_string(),
    })
}

/// Free a TCP/UDP port on a host, in case a previous run left something behind.
pub fn free_port(client: &SshClient, port: u16) {
    let _ = client.exec_priv(&format!(
        "fuser -k {port}/tcp >/dev/null 2>&1; fuser -k {port}/udp >/dev/null 2>&1; true"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iputils_ping() {
        let text = "\
PING 10.77.0.1 (10.77.0.1) 56(84) bytes of data.

--- 10.77.0.1 ping statistics ---
20 packets transmitted, 20 received, 0% packet loss, time 3805ms
rtt min/avg/max/mdev = 0.234/0.312/0.456/0.045 ms
";
        let s = parse_ping(text);
        assert_eq!(s.transmitted, 20);
        assert_eq!(s.received, 20);
        assert_eq!(s.loss_pct, 0.0);
        assert_eq!(s.min_ms, 0.234);
        assert_eq!(s.avg_ms, 0.312);
        assert_eq!(s.max_ms, 0.456);
        assert_eq!(s.mdev_ms, 0.045);
        assert!(s.is_usable());
    }

    #[test]
    fn parses_busybox_ping_without_mdev() {
        let text = "\
--- 10.77.0.1 ping statistics ---
10 packets transmitted, 8 packets received, 20% packet loss
round-trip min/avg/max = 1.1/2.2/3.3 ms
";
        let s = parse_ping(text);
        assert_eq!(s.transmitted, 10);
        assert_eq!(s.received, 8);
        assert_eq!(s.loss_pct, 20.0);
        assert_eq!(s.avg_ms, 2.2);
        assert_eq!(s.mdev_ms, 0.0);
    }

    #[test]
    fn derives_loss_when_the_line_omits_it() {
        let text = "\
4 packets transmitted, 1 received, time 3000ms
rtt min/avg/max/mdev = 1.0/1.0/1.0/0.0 ms
";
        let s = parse_ping(text);
        assert!((s.loss_pct - 75.0).abs() < 0.001);
    }

    #[test]
    fn total_loss_is_not_usable() {
        let text = "\
5 packets transmitted, 0 received, 100% packet loss, time 4102ms
";
        let s = parse_ping(text);
        assert_eq!(s.received, 0);
        assert_eq!(s.loss_pct, 100.0);
        assert!(!s.is_usable());
    }

    #[test]
    fn parses_iperf3_tcp_json() {
        let json = r#"{
          "end": {
            "sum_sent":     { "bytes": 1000, "bits_per_second": 800.0, "retransmits": 3, "seconds": 10.0 },
            "sum_received": { "bytes":  990, "bits_per_second": 792.0, "seconds": 10.0 }
          }
        }"#;
        let s = parse_iperf3_tcp(json, false).expect("parsed");
        assert_eq!(s.bits_per_second, 792.0);
        assert_eq!(s.bytes, 990);
        assert_eq!(s.retransmits, 3);
        assert_eq!(s.tool, "iperf3");
    }

    #[test]
    fn falls_back_to_sender_figures() {
        let json = r#"{ "end": { "sum_sent": { "bytes": 500, "bits_per_second": 400.0 } } }"#;
        let s = parse_iperf3_tcp(json, false).expect("parsed");
        assert_eq!(s.bits_per_second, 400.0);
        assert_eq!(s.bytes, 500);
    }

    #[test]
    fn iperf3_errors_are_not_treated_as_results() {
        let json = r#"{ "error": "unable to connect to server: Connection refused" }"#;
        assert!(parse_iperf3_tcp(json, false).is_none());
        assert!(parse_iperf3_udp(json).is_none());
    }

    #[test]
    fn parses_iperf3_udp_json() {
        let json = r#"{
          "end": { "sum": { "bytes": 100, "bits_per_second": 80.0, "seconds": 10.0,
                            "jitter_ms": 0.42, "lost_percent": 1.25 } }
        }"#;
        let s = parse_iperf3_udp(json).expect("parsed");
        assert_eq!(s.jitter_ms, 0.42);
        assert_eq!(s.lost_percent, 1.25);
    }

    #[test]
    fn parses_probe_json_with_surrounding_noise() {
        let text = "warning: something\n{\"bits_per_second\": 123.5, \"bytes\": 10, \
                    \"seconds\": 1.0, \"jitter_ms\": 0.1, \"lost_percent\": 0.5}\n";
        let s = parse_probe(text).expect("parsed");
        assert_eq!(s.bits_per_second, 123.5);
        assert_eq!(s.lost_percent, 0.5);
        assert_eq!(s.tool, "probe");
    }

    #[test]
    fn probe_error_output_is_rejected() {
        assert!(parse_probe(r#"{"error": "connection refused"}"#).is_none());
    }
}
