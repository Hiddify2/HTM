//! Opening the TCP connection that SSH will run over, optionally through a
//! proxy.
//!
//! The proxy clients are implemented here rather than pulled from a crate so
//! that HTM controls the timeouts, the error messages and the exact bytes on
//! the wire. All three protocols are small and completely specified:
//!
//! * SOCKS5 — RFC 1928, with username/password auth from RFC 1929.
//! * SOCKS4a — the domain-name extension to the original SOCKS4 protocol.
//! * HTTP `CONNECT` — RFC 7231 §4.3.6, with RFC 7617 Basic auth.
//!
//! The returned stream is left blocking with no socket-level read or write
//! timeout, because libssh2 drives its own deadlines through
//! `libssh2_session_set_timeout` and a socket timeout underneath it would
//! surface as a spurious error.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::model::{ProxyConfig, ProxyKind};

/// Connect to `host:port`, going through `proxy` when one is configured.
pub fn dial(
    host: &str,
    port: u16,
    proxy: &ProxyConfig,
    proxy_password: &str,
    timeout: Duration,
) -> Result<TcpStream> {
    let stream = match proxy.kind {
        ProxyKind::None => connect_direct(host, port, timeout)?,
        ProxyKind::Socks5 => {
            let s = connect_direct(&proxy.host, proxy.port, timeout)?;
            socks5_handshake(s, host, port, &proxy.username, proxy_password, proxy, timeout)?
        }
        ProxyKind::Socks4 => {
            let s = connect_direct(&proxy.host, proxy.port, timeout)?;
            socks4a_handshake(s, host, port, &proxy.username, proxy, timeout)?
        }
        ProxyKind::Http => {
            let s = connect_direct(&proxy.host, proxy.port, timeout)?;
            http_connect(s, host, port, &proxy.username, proxy_password, proxy, timeout)?
        }
    };

    // Hand a clean, blocking socket to libssh2.
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Resolve and connect straight to a host, trying every resolved address.
fn connect_direct(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let target = format!("{host}:{port}");

    // A literal address needs no resolver round trip.
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        return TcpStream::connect_timeout(&addr, timeout).map_err(|e| Error::Connect {
            target,
            reason: e.to_string(),
        });
    }

    let addrs: Vec<SocketAddr> = target
        .to_socket_addrs()
        .map_err(|e| Error::Connect {
            target: target.clone(),
            reason: format!("name lookup failed: {e}"),
        })?
        .collect();

    if addrs.is_empty() {
        return Err(Error::Connect {
            target,
            reason: "name resolved to no addresses".to_string(),
        });
    }

    // Prefer IPv4: a VPS that publishes an AAAA record the operator cannot
    // actually reach is a common and confusing failure.
    let mut ordered = addrs.clone();
    ordered.sort_by_key(|a| u8::from(a.is_ipv6()));

    let mut last: Option<String> = None;
    for addr in ordered {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(format!("{addr}: {e}")),
        }
    }
    Err(Error::Connect {
        target,
        reason: last.unwrap_or_else(|| "no address could be reached".to_string()),
    })
}

/// Read exactly `buf.len()` bytes, honouring an overall deadline.
fn read_exact_deadline(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| Error::Timeout {
                what: "proxy response".to_string(),
                seconds: 0,
            })?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "proxy closed the connection",
                )))
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(())
}

fn write_all_deadline(stream: &mut TcpStream, buf: &[u8], deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| Error::Timeout {
            what: "proxy request".to_string(),
            seconds: 0,
        })?;
    stream.set_write_timeout(Some(remaining))?;
    stream.write_all(buf)?;
    stream.flush()?;
    Ok(())
}

// ── SOCKS5 ───────────────────────────────────────────────────────────────────

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_AUTH_USERPASS: u8 = 0x02;
const SOCKS5_AUTH_UNACCEPTABLE: u8 = 0xFF;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

fn socks5_handshake(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    proxy: &ProxyConfig,
    timeout: Duration,
) -> Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let fail = |reason: String| Error::Proxy {
        proxy: proxy.endpoint(),
        reason,
    };

    // Greeting: offer no-auth, plus username/password when we have credentials.
    let offer_userpass = !username.is_empty() || !password.is_empty();
    let mut greeting: Vec<u8> = vec![SOCKS5_VERSION];
    if offer_userpass {
        greeting.push(2);
        greeting.push(SOCKS5_AUTH_NONE);
        greeting.push(SOCKS5_AUTH_USERPASS);
    } else {
        greeting.push(1);
        greeting.push(SOCKS5_AUTH_NONE);
    }
    write_all_deadline(&mut stream, &greeting, deadline)?;

    let mut reply = [0u8; 2];
    read_exact_deadline(&mut stream, &mut reply, deadline)?;
    if reply[0] != SOCKS5_VERSION {
        return Err(fail(format!(
            "expected a SOCKS5 reply but the server answered with version {}",
            reply[0]
        )));
    }
    match reply[1] {
        SOCKS5_AUTH_NONE => {}
        SOCKS5_AUTH_USERPASS => {
            if !offer_userpass {
                return Err(fail(
                    "proxy demands username/password authentication but none was configured"
                        .to_string(),
                ));
            }
            socks5_userpass(&mut stream, username, password, deadline, proxy)?;
        }
        SOCKS5_AUTH_UNACCEPTABLE => {
            return Err(fail(
                "proxy rejected every authentication method offered".to_string(),
            ))
        }
        other => {
            return Err(fail(format!(
                "proxy selected authentication method {other:#04x}, which HTM does not implement"
            )))
        }
    }

    // CONNECT request.
    let mut req: Vec<u8> = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            req.push(SOCKS5_ATYP_IPV4);
            req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            req.push(SOCKS5_ATYP_IPV6);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let bytes = host.as_bytes();
            if bytes.len() > 255 {
                return Err(fail("host name is longer than SOCKS5 allows".to_string()));
            }
            req.push(SOCKS5_ATYP_DOMAIN);
            req.push(bytes.len() as u8);
            req.extend_from_slice(bytes);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    write_all_deadline(&mut stream, &req, deadline)?;

    let mut head = [0u8; 4];
    read_exact_deadline(&mut stream, &mut head, deadline)?;
    if head[0] != SOCKS5_VERSION {
        return Err(fail(format!(
            "malformed CONNECT reply (version byte {})",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(fail(format!(
            "proxy refused CONNECT to {host}:{port}: {}",
            socks5_reply_text(head[1])
        )));
    }

    // Drain the bound address so the stream is positioned at the tunnel payload.
    match head[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut rest = [0u8; 4 + 2];
            read_exact_deadline(&mut stream, &mut rest, deadline)?;
        }
        SOCKS5_ATYP_IPV6 => {
            let mut rest = [0u8; 16 + 2];
            read_exact_deadline(&mut stream, &mut rest, deadline)?;
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact_deadline(&mut stream, &mut len, deadline)?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            read_exact_deadline(&mut stream, &mut rest, deadline)?;
        }
        other => {
            return Err(fail(format!(
                "proxy returned an unknown address type {other:#04x}"
            )))
        }
    }

    Ok(stream)
}

fn socks5_userpass(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
    deadline: Instant,
    proxy: &ProxyConfig,
) -> Result<()> {
    let fail = |reason: String| Error::Proxy {
        proxy: proxy.endpoint(),
        reason,
    };
    if username.len() > 255 || password.len() > 255 {
        return Err(fail(
            "SOCKS5 username and password must each be at most 255 bytes".to_string(),
        ));
    }
    let mut msg: Vec<u8> = vec![0x01];
    msg.push(username.len() as u8);
    msg.extend_from_slice(username.as_bytes());
    msg.push(password.len() as u8);
    msg.extend_from_slice(password.as_bytes());
    write_all_deadline(stream, &msg, deadline)?;

    let mut reply = [0u8; 2];
    read_exact_deadline(stream, &mut reply, deadline)?;
    if reply[1] != 0x00 {
        return Err(fail(
            "proxy rejected the username and password".to_string(),
        ));
    }
    Ok(())
}

fn socks5_reply_text(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown failure code",
    }
}

// ── SOCKS4a ──────────────────────────────────────────────────────────────────

fn socks4a_handshake(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    user_id: &str,
    proxy: &ProxyConfig,
    timeout: Duration,
) -> Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let fail = |reason: String| Error::Proxy {
        proxy: proxy.endpoint(),
        reason,
    };

    let mut req: Vec<u8> = vec![0x04, 0x01];
    req.extend_from_slice(&port.to_be_bytes());

    let mut trailing_host: Option<&str> = None;
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => req.extend_from_slice(&v4.octets()),
        Ok(IpAddr::V6(_)) => {
            return Err(fail(
                "SOCKS4a cannot carry IPv6 destinations; use SOCKS5 instead".to_string(),
            ))
        }
        Err(_) => {
            // SOCKS4a marker: an address of 0.0.0.x with x != 0 means the host
            // name follows the user id.
            req.extend_from_slice(&[0, 0, 0, 1]);
            trailing_host = Some(host);
        }
    }

    req.extend_from_slice(user_id.as_bytes());
    req.push(0x00);
    if let Some(h) = trailing_host {
        if h.as_bytes().contains(&0) {
            return Err(fail("host name contains a NUL byte".to_string()));
        }
        req.extend_from_slice(h.as_bytes());
        req.push(0x00);
    }
    write_all_deadline(&mut stream, &req, deadline)?;

    let mut reply = [0u8; 8];
    read_exact_deadline(&mut stream, &mut reply, deadline)?;
    if reply[0] != 0x00 {
        return Err(fail(format!(
            "malformed SOCKS4 reply (first byte {})",
            reply[0]
        )));
    }
    match reply[1] {
        0x5A => Ok(stream),
        0x5B => Err(fail(format!("request rejected or failed for {host}:{port}"))),
        0x5C => Err(fail(
            "request rejected: proxy could not reach an identd on this machine".to_string(),
        )),
        0x5D => Err(fail(
            "request rejected: identd reported a different user id".to_string(),
        )),
        other => Err(fail(format!("unknown SOCKS4 status {other:#04x}"))),
    }
}

// ── HTTP CONNECT ─────────────────────────────────────────────────────────────

fn http_connect(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    proxy: &ProxyConfig,
    timeout: Duration,
) -> Result<TcpStream> {
    use base64::Engine as _;

    let deadline = Instant::now() + timeout;
    let fail = |reason: String| Error::Proxy {
        proxy: proxy.endpoint(),
        reason,
    };

    // An IPv6 literal has to be bracketed in the request target.
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if !username.is_empty() || !password.is_empty() {
        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    write_all_deadline(&mut stream, req.as_bytes(), deadline)?;

    // Read until the end of the header block. Headers are small; cap the read
    // so a hostile or broken proxy cannot make us allocate without bound.
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if buf.len() > 16 * 1024 {
            return Err(fail(
                "proxy sent more than 16 KiB of headers without completing the response"
                    .to_string(),
            ));
        }
        read_exact_deadline(&mut stream, &mut byte, deadline)?;
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        // Tolerate proxies that terminate with bare LFs.
        if buf.len() >= 2 && &buf[buf.len() - 2..] == b"\n\n" {
            break;
        }
    }

    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or_default().trim().to_string();
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| fail(format!("could not parse the status line '{status_line}'")))?;

    if code == 407 {
        return Err(fail(
            "proxy requires authentication (407); check the proxy username and password"
                .to_string(),
        ));
    }
    if !(200..300).contains(&code) {
        return Err(fail(format!(
            "proxy refused CONNECT to {host}:{port}: {status_line}"
        )));
    }

    Ok(stream)
}
