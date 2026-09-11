//! Small helpers shared across the crate: shell quoting, formatting, ID and
//! secret generation, and a handful of text parsers.

use rand::Rng;

/// Quote a string so it survives POSIX `sh` word splitting verbatim.
///
/// Every remote command HTM builds goes through this for any value that came
/// from user input or from a config file. The empty string becomes `''`.
pub fn sh_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    // Fast path: nothing that the shell treats specially.
    let plain = s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b',' | b'+' | b'=')
    });
    if plain {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            // Close the quote, emit an escaped quote, reopen.
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Quote each argument and join them with spaces.
pub fn sh_join<I, S>(args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .map(|a| sh_quote(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A lowercase hex string of `bytes` random bytes.
pub fn random_hex(bytes: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(bytes * 2);
    for _ in 0..bytes {
        let b: u8 = rng.gen();
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A short, URL- and filename-safe unique identifier.
pub fn new_id(prefix: &str) -> String {
    let ts = chrono::Utc::now().timestamp_millis();
    format!("{prefix}-{ts:x}-{}", random_hex(4))
}

/// Sanitise a user-supplied name into something usable as a systemd instance
/// name and a filename. Returns `None` if nothing usable remains.
pub fn sanitize_instance_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Collapse runs of dashes so "my  tunnel" does not become "my--tunnel".
    let mut collapsed = String::with_capacity(cleaned.len());
    let mut last_dash = false;
    for c in cleaned.chars() {
        if c == '-' {
            if !last_dash {
                collapsed.push(c);
            }
            last_dash = true;
        } else {
            collapsed.push(c);
            last_dash = false;
        }
    }
    let trimmed = collapsed.trim_matches('-');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() > 48 {
        return Some(trimmed[..48].trim_end_matches('-').to_string());
    }
    Some(trimmed.to_string())
}

/// Format a byte count with binary units.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut idx = 0usize;
    while value >= 1024.0 && idx + 1 < UNITS.len() {
        value /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[idx])
    }
}

/// Format a bits-per-second figure using decimal SI units, the convention for
/// network throughput.
pub fn human_bits_per_sec(bps: f64) -> String {
    const UNITS: [&str; 5] = ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
    if !bps.is_finite() || bps <= 0.0 {
        return "-".to_string();
    }
    let mut value = bps;
    let mut idx = 0usize;
    while value >= 1000.0 && idx + 1 < UNITS.len() {
        value /= 1000.0;
        idx += 1;
    }
    format!("{value:.2} {}", UNITS[idx])
}

/// Format a millisecond figure for display.
pub fn human_ms(ms: f64) -> String {
    if !ms.is_finite() || ms < 0.0 {
        return "-".to_string();
    }
    if ms < 10.0 {
        format!("{ms:.2} ms")
    } else if ms < 1000.0 {
        format!("{ms:.1} ms")
    } else {
        format!("{:.2} s", ms / 1000.0)
    }
}

/// Format a duration in seconds as `1d 2h 3m` / `4m 5s` / `6s`.
pub fn human_duration_secs(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Parse the first floating point number appearing in `s`.
pub fn first_f64(s: &str) -> Option<f64> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        let starts_number = c.is_ascii_digit()
            || (c == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit());
        if starts_number {
            let start = i;
            if c == b'-' {
                i += 1;
            }
            let mut seen_dot = false;
            while i < bytes.len() {
                let c = bytes[i];
                if c.is_ascii_digit() {
                    i += 1;
                } else if c == b'.' && !seen_dot {
                    seen_dot = true;
                    i += 1;
                } else {
                    break;
                }
            }
            return s[start..i].trim_end_matches('.').parse::<f64>().ok();
        }
        i += 1;
    }
    None
}

/// Clamp a float into `[lo, hi]`, mapping NaN to `lo`.
pub fn clamp_f64(v: f64, lo: f64, hi: f64) -> f64 {
    if v.is_nan() {
        lo
    } else if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

/// Truncate a string to `max` characters, appending an ellipsis if cut.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}...")
    }
}

/// Keep only the final `max_lines` lines of a potentially huge log blob.
pub fn tail_lines(s: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() <= max_lines {
        return s.to_string();
    }
    lines[lines.len() - max_lines..].join("\n")
}

/// Render a SHA-256 digest as the OpenSSH-style base64 fingerprint (no padding).
pub fn ssh_fingerprint_sha256(digest: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
}

/// Render a digest as colon-separated lowercase hex, the MD5 fingerprint style.
pub fn hex_colon(digest: &[u8]) -> String {
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Generate a pre-shared key suitable for a tunnel: 32 random bytes as hex.
pub fn generate_psk() -> String {
    random_hex(32)
}

/// Parse a comma/space separated list of ports, rejecting anything invalid.
///
/// Accepts plain ports (`443`) and inclusive ranges (`8000-8010`).
pub fn parse_port_list(raw: &str) -> std::result::Result<Vec<u16>, String> {
    let mut out: Vec<u16> = Vec::new();
    for token in raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
    {
        if let Some((a, b)) = token.split_once('-') {
            let lo: u32 = a
                .trim()
                .parse()
                .map_err(|_| format!("'{a}' is not a port number"))?;
            let hi: u32 = b
                .trim()
                .parse()
                .map_err(|_| format!("'{b}' is not a port number"))?;
            if lo == 0 || hi == 0 || lo > 65535 || hi > 65535 {
                return Err(format!("port range '{token}' is outside 1-65535"));
            }
            if lo > hi {
                return Err(format!("port range '{token}' is reversed"));
            }
            if hi - lo > 1024 {
                return Err(format!(
                    "port range '{token}' spans {} ports; keep ranges under 1024",
                    hi - lo + 1
                ));
            }
            for p in lo..=hi {
                out.push(p as u16);
            }
        } else {
            let p: u32 = token
                .parse()
                .map_err(|_| format!("'{token}' is not a port number"))?;
            if p == 0 || p > 65535 {
                return Err(format!("port {p} is outside 1-65535"));
            }
            out.push(p as u16);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Render a port list back into the compact form the user typed.
pub fn format_port_list(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::new();
    }
    let mut sorted = ports.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut parts: Vec<String> = Vec::new();
    let mut start = sorted[0];
    let mut prev = sorted[0];
    for &p in &sorted[1..] {
        if p == prev + 1 {
            prev = p;
            continue;
        }
        parts.push(if start == prev {
            start.to_string()
        } else {
            format!("{start}-{prev}")
        });
        start = p;
        prev = p;
    }
    parts.push(if start == prev {
        start.to_string()
    } else {
        format!("{start}-{prev}")
    });
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_are_escaped() {
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("plain"), "plain");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
        assert_eq!(sh_quote("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn port_lists_round_trip() {
        let parsed = parse_port_list("443, 80 8000-8003").unwrap();
        assert_eq!(parsed, vec![80, 443, 8000, 8001, 8002, 8003]);
        assert_eq!(format_port_list(&parsed), "80, 443, 8000-8003");
        assert!(parse_port_list("0").is_err());
        assert!(parse_port_list("70000").is_err());
        assert!(parse_port_list("9-8").is_err());
    }

    #[test]
    fn numbers_are_extracted() {
        assert_eq!(first_f64("rtt = 12.5 ms"), Some(12.5));
        assert_eq!(first_f64("no digits"), None);
        assert_eq!(first_f64("-3.25 loss"), Some(-3.25));
    }

    #[test]
    fn instance_names_are_sanitised() {
        assert_eq!(
            sanitize_instance_name(" my tunnel! "),
            Some("my-tunnel".into())
        );
        assert_eq!(sanitize_instance_name("---"), None);
    }
}
