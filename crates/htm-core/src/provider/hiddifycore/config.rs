//! Hiddify Core's settings and the pair of sing-box JSON configs it runs.
//!
//! Hiddify Core is a sing-box build: `hiddify-core -D <workdir> run -c <cfg>`
//! takes an ordinary sing-box configuration. HTM uses it to join the relay and
//! the exit with one of several proxy protocols, which is where the breadth of
//! tunnelling comes from — Shadowsocks, VMess, VLESS, Trojan, Hysteria2, TUIC
//! and SOCKS.
//!
//! The exit runs the protocol **server** (an inbound) with a `direct` outbound,
//! so decrypted traffic leaves to the internet. The relay runs the protocol
//! **client** (an outbound) and captures traffic through one of two inbounds:
//!
//! * `mixed` — a local SOCKS5/HTTP proxy on the relay, for apps to point at;
//! * `tun`   — a TUN device with `auto_route`, which forwards all of the relay's
//!   IPv4 traffic through the tunnel (full IP forwarding).
//!
//! There is no point-to-point TUN link between the two hosts to ping, so this is
//! a [`SocksProxy`](crate::provider::TunnelModel) model: readiness is the
//! relay's inbound and the exit's protocol port actually listening.
//!
//! See <https://github.com/hiddify/hiddify-core>.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::model::{
    OptValue, OptionKind, OptionMap, OptionMapExt, OptionSpace, OptionSpec, TunnelPlan, TunnelSide,
};

pub const INSTALL_DIR: &str = "/opt/htm-hiddifycore";
pub const BINARY_PATH: &str = "/opt/htm-hiddifycore/hiddify-core";
pub const CONFIG_DIR: &str = "/etc/htm-hiddifycore";
pub const WORKDIR_BASE: &str = "/var/lib/htm-hiddifycore";
pub const VERSION_FILE: &str = "/opt/htm-hiddifycore/VERSION";
pub const SERVICE_PREFIX: &str = "htm-hiddifycore";
pub const UNIT_TEMPLATE: &str = "htm-hiddifycore@.service";

// ── Option keys ──────────────────────────────────────────────────────────────

pub mod keys {
    /// The proxy protocol carried between the relay and the exit.
    pub const PROTOCOL: &str = "protocol";
    /// How the relay captures traffic: `mixed` (local proxy) or `tun` (IP fwd).
    pub const INBOUND_MODE: &str = "inbound_mode";
    /// Local SOCKS5/HTTP port for the `mixed` inbound.
    pub const SOCKS_PORT: &str = "socks_port";
    /// TLS SNI presented by the TLS-bearing protocols.
    pub const SNI: &str = "sni";
}

/// The proxy protocols HTM drives through Hiddify Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Hysteria2,
    Tuic,
    Socks,
}

impl Protocol {
    pub fn id(self) -> &'static str {
        match self {
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Vmess => "vmess",
            Protocol::Vless => "vless",
            Protocol::Trojan => "trojan",
            Protocol::Hysteria2 => "hysteria2",
            Protocol::Tuic => "tuic",
            Protocol::Socks => "socks",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Some(match id {
            "shadowsocks" => Protocol::Shadowsocks,
            "vmess" => Protocol::Vmess,
            "vless" => Protocol::Vless,
            "trojan" => Protocol::Trojan,
            "hysteria2" => Protocol::Hysteria2,
            "tuic" => Protocol::Tuic,
            "socks" => Protocol::Socks,
            _ => return None,
        })
    }

    /// Does the protocol require a TLS certificate on the exit?
    pub fn needs_tls(self) -> bool {
        matches!(
            self,
            Protocol::Trojan | Protocol::Hysteria2 | Protocol::Tuic
        )
    }

    /// Is the protocol carried over UDP on the wire (so a listening check must
    /// probe the UDP socket, not a TCP one)?
    pub fn is_udp(self) -> bool {
        matches!(self, Protocol::Hysteria2 | Protocol::Tuic)
    }

    pub const ALL: [Protocol; 7] = [
        Protocol::Shadowsocks,
        Protocol::Vmess,
        Protocol::Vless,
        Protocol::Trojan,
        Protocol::Hysteria2,
        Protocol::Tuic,
        Protocol::Socks,
    ];
}

/// Shadowsocks cipher used for every Shadowsocks tunnel. A password-based AEAD
/// method, so the pre-shared key can be used directly with no key-length rules.
pub const SS_METHOD: &str = "chacha20-ietf-poly1305";

pub fn protocol_of(options: &OptionMap) -> Protocol {
    Protocol::from_id(&options.str_or(keys::PROTOCOL, "shadowsocks"))
        .unwrap_or(Protocol::Shadowsocks)
}

pub fn inbound_mode(options: &OptionMap) -> String {
    let mode = options.str_or(keys::INBOUND_MODE, "mixed");
    if mode == "tun" {
        "tun".to_string()
    } else {
        "mixed".to_string()
    }
}

pub fn socks_port(plan: &TunnelPlan) -> u16 {
    normalize(&plan.options)
        .int_or(keys::SOCKS_PORT, 2080)
        .clamp(1, 65_535) as u16
}

// ── Credential derivation ──────────────────────────────────────────────────

/// A deterministic UUID derived from the pre-shared key, for the protocols that
/// identify a user by UUID (VMess, VLESS, TUIC). Both sides derive the same one
/// from the shared key, so nothing extra has to be exchanged.
pub fn derive_uuid(psk: &str) -> String {
    let digest = Sha256::digest(psk.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    // Set the version (5) and RFC 4122 variant bits so it is a well-formed UUID.
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// The password material for the password-based protocols: the shared key
/// itself, which already carries enough entropy.
pub fn derive_password(psk: &str) -> String {
    psk.to_string()
}

pub fn cert_path(instance: &str) -> String {
    format!("{CONFIG_DIR}/{instance}-cert.pem")
}

pub fn key_path(instance: &str) -> String {
    format!("{CONFIG_DIR}/{instance}-key.pem")
}

pub fn workdir(instance: &str) -> String {
    format!("{WORKDIR_BASE}/{instance}")
}

pub fn service_name(instance: &str) -> String {
    format!("{SERVICE_PREFIX}@{instance}.service")
}

pub fn config_path(instance: &str) -> String {
    format!("{CONFIG_DIR}/{instance}.json")
}

// ── Option space ────────────────────────────────────────────────────────────

pub fn option_space() -> OptionSpace {
    let protocol_choices: Vec<(String, String)> = vec![
        (
            "shadowsocks".into(),
            "Shadowsocks — AEAD, no TLS, simplest and robust".into(),
        ),
        (
            "vmess".into(),
            "VMess — UUID auth over TCP, no certificate".into(),
        ),
        (
            "vless".into(),
            "VLESS — lightweight UUID auth over TCP, no certificate".into(),
        ),
        (
            "trojan".into(),
            "Trojan — password over TLS (self-signed on the exit)".into(),
        ),
        (
            "hysteria2".into(),
            "Hysteria2 — password over QUIC/TLS, UDP (self-signed)".into(),
        ),
        (
            "tuic".into(),
            "TUIC — UUID+password over QUIC/TLS, UDP (self-signed)".into(),
        ),
        (
            "socks".into(),
            "SOCKS5 — username/password, no encryption (debug/LAN)".into(),
        ),
    ];

    let mut specs = Vec::new();
    specs.push(OptionSpec {
        key: keys::PROTOCOL.into(),
        label: "Tunnel protocol".into(),
        help: "Which proxy protocol carries traffic between the relay and the exit. Shadowsocks, \
               VMess, VLESS and SOCKS need no certificate; Trojan, Hysteria2 and TUIC run over TLS \
               and HTM generates a self-signed certificate on the exit for them."
            .into(),
        group: "Protocol".into(),
        kind: OptionKind::Choice {
            choices: protocol_choices,
        },
        default: OptValue::Choice("shadowsocks".into()),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::INBOUND_MODE.into(),
        label: "Relay capture mode".into(),
        help: "How the relay takes in traffic. 'mixed' exposes a local SOCKS5/HTTP proxy for apps \
               on the relay to use; 'tun' creates a TUN device and forwards all of the relay's \
               IPv4 traffic through the tunnel (needs /dev/net/tun)."
            .into(),
        group: "Relay".into(),
        kind: OptionKind::Choice {
            choices: vec![
                ("mixed".into(), "Local SOCKS5/HTTP proxy".into()),
                ("tun".into(), "TUN — forward all IP traffic".into()),
            ],
        },
        default: OptValue::Choice("mixed".into()),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::SOCKS_PORT.into(),
        label: "Local proxy port".into(),
        help: "Port the relay's SOCKS5/HTTP proxy listens on, in 'mixed' mode. Bound to localhost."
            .into(),
        group: "Relay".into(),
        kind: OptionKind::Int {
            min: 1,
            max: 65_535,
        },
        default: OptValue::Int(2080),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::SNI.into(),
        label: "TLS SNI".into(),
        help: "Server name the TLS protocols present and the relay expects. Used only by Trojan, \
               Hysteria2 and TUIC; the relay skips certificate verification, since the two servers \
               are your own."
            .into(),
        group: "Protocol".into(),
        kind: OptionKind::Text,
        default: OptValue::Text("www.bing.com".into()),
        benchmarkable: false,
        bench_values: Vec::new(),
    });

    OptionSpace { specs }
}

pub fn normalize(options: &OptionMap) -> OptionMap {
    let mut out = option_space().normalize(options);
    if Protocol::from_id(&out.str_or(keys::PROTOCOL, "shadowsocks")).is_none() {
        out.insert(
            keys::PROTOCOL.into(),
            OptValue::Choice("shadowsocks".into()),
        );
    }
    let mode = inbound_mode(&out);
    out.insert(keys::INBOUND_MODE.into(), OptValue::Choice(mode));
    out
}

pub fn validate(options: &OptionMap) -> Result<(), String> {
    if Protocol::from_id(&options.str_or(keys::PROTOCOL, "shadowsocks")).is_none() {
        return Err(format!(
            "'{}' is not a protocol HTM supports through Hiddify Core.",
            options.str_or(keys::PROTOCOL, "")
        ));
    }
    let port = options.int_or(keys::SOCKS_PORT, 2080);
    if !(1..=65_535).contains(&port) {
        return Err("The local proxy port must be between 1 and 65535.".into());
    }
    Ok(())
}

pub fn validate_plan(plan: &TunnelPlan) -> Result<(), String> {
    plan.validate()?;
    validate(&normalize(&plan.options))?;
    Ok(())
}

/// True when this configuration needs a TLS certificate generated on the exit.
pub fn needs_certificate(plan: &TunnelPlan) -> bool {
    protocol_of(&normalize(&plan.options)).needs_tls()
}

pub fn describe(options: &OptionMap) -> String {
    let p = protocol_of(options);
    let mode = inbound_mode(options);
    format!("{} · {}", p.id(), mode)
}

// ── sing-box rendering ─────────────────────────────────────────────────────

fn sni_of(plan: &TunnelPlan) -> String {
    normalize(&plan.options).str_or(keys::SNI, "www.bing.com")
}

/// The server-side inbound (on the exit) for the chosen protocol.
fn server_inbound(plan: &TunnelPlan) -> Value {
    let p = protocol_of(&normalize(&plan.options));
    let port = plan.data_port;
    let pw = derive_password(&plan.pre_shared_key);
    let uuid = derive_uuid(&plan.pre_shared_key);
    let tls = json!({
        "enabled": true,
        "server_name": sni_of(plan),
        "certificate_path": cert_path(&plan.instance),
        "key_path": key_path(&plan.instance),
    });

    match p {
        Protocol::Shadowsocks => json!({
            "type": "shadowsocks", "tag": "in", "listen": "::", "listen_port": port,
            "method": SS_METHOD, "password": pw,
        }),
        Protocol::Vmess => json!({
            "type": "vmess", "tag": "in", "listen": "::", "listen_port": port,
            "users": [{ "uuid": uuid, "alterId": 0 }],
        }),
        Protocol::Vless => json!({
            "type": "vless", "tag": "in", "listen": "::", "listen_port": port,
            "users": [{ "uuid": uuid }],
        }),
        Protocol::Trojan => json!({
            "type": "trojan", "tag": "in", "listen": "::", "listen_port": port,
            "users": [{ "password": pw }], "tls": tls,
        }),
        Protocol::Hysteria2 => json!({
            "type": "hysteria2", "tag": "in", "listen": "::", "listen_port": port,
            "users": [{ "password": pw }], "tls": tls,
        }),
        Protocol::Tuic => json!({
            "type": "tuic", "tag": "in", "listen": "::", "listen_port": port,
            "users": [{ "uuid": uuid, "password": pw }],
            "congestion_control": "bbr", "tls": tls,
        }),
        Protocol::Socks => json!({
            "type": "socks", "tag": "in", "listen": "::", "listen_port": port,
            "users": [{ "username": "htm", "password": pw }],
        }),
    }
}

/// The client-side outbound (on the relay) dialling the exit.
fn client_outbound(plan: &TunnelPlan) -> Value {
    let p = protocol_of(&normalize(&plan.options));
    let server = plan.server.peer_target();
    let port = plan.data_port;
    let pw = derive_password(&plan.pre_shared_key);
    let uuid = derive_uuid(&plan.pre_shared_key);
    let tls = json!({
        "enabled": true,
        "insecure": true,
        "server_name": sni_of(plan),
    });

    match p {
        Protocol::Shadowsocks => json!({
            "type": "shadowsocks", "tag": "proxy", "server": server, "server_port": port,
            "method": SS_METHOD, "password": pw,
        }),
        Protocol::Vmess => json!({
            "type": "vmess", "tag": "proxy", "server": server, "server_port": port,
            "uuid": uuid, "security": "auto",
        }),
        Protocol::Vless => json!({
            "type": "vless", "tag": "proxy", "server": server, "server_port": port,
            "uuid": uuid,
        }),
        Protocol::Trojan => json!({
            "type": "trojan", "tag": "proxy", "server": server, "server_port": port,
            "password": pw, "tls": tls,
        }),
        Protocol::Hysteria2 => json!({
            "type": "hysteria2", "tag": "proxy", "server": server, "server_port": port,
            "password": pw, "tls": tls,
        }),
        Protocol::Tuic => json!({
            "type": "tuic", "tag": "proxy", "server": server, "server_port": port,
            "uuid": uuid, "password": pw, "congestion_control": "bbr", "tls": tls,
        }),
        Protocol::Socks => json!({
            "type": "socks", "tag": "proxy", "server": server, "server_port": port,
            "version": "5", "username": "htm", "password": pw,
        }),
    }
}

/// The relay's inbound, per capture mode.
fn client_inbound(plan: &TunnelPlan) -> Value {
    let options = normalize(&plan.options);
    if inbound_mode(&options) == "tun" {
        json!({
            "type": "tun",
            "tag": "in",
            "address": ["172.19.0.1/30"],
            "mtu": plan.tun_mtu.min(plan.mtu),
            "auto_route": true,
            "strict_route": true,
            "stack": "system",
        })
    } else {
        json!({
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": options.int_or(keys::SOCKS_PORT, 2080),
        })
    }
}

/// Render the exit's sing-box config: accept the protocol, exit to the internet.
pub fn render_server(plan: &TunnelPlan) -> String {
    let cfg = json!({
        "log": { "level": plan.log_level, "timestamp": true },
        "dns": { "servers": [{ "address": "tls://8.8.8.8" }] },
        "inbounds": [server_inbound(plan)],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "dns", "tag": "dns-out" },
        ],
        "route": {
            "rules": [{ "port": 53, "outbound": "dns-out" }],
            "final": "direct",
        },
    });
    serde_json::to_string_pretty(&cfg).unwrap_or_else(|_| "{}".into())
}

/// Render the relay's sing-box config: capture traffic and send it to the exit.
pub fn render_client(plan: &TunnelPlan) -> String {
    let exit = plan.server.peer_target();
    let cfg = json!({
        "log": { "level": plan.log_level, "timestamp": true },
        "dns": { "servers": [{ "address": "tls://8.8.8.8" }] },
        "inbounds": [client_inbound(plan)],
        "outbounds": [
            client_outbound(plan),
            { "type": "direct", "tag": "direct" },
            { "type": "dns", "tag": "dns-out" },
        ],
        "route": {
            "rules": [
                { "port": 53, "outbound": "dns-out" },
                // Reach the exit itself directly, or the tunnel would loop.
                { "ip_cidr": [format!("{exit}/32")], "outbound": "direct" },
            ],
            "final": "proxy",
            "auto_detect_interface": true,
        },
    });
    serde_json::to_string_pretty(&cfg).unwrap_or_else(|_| "{}".into())
}

/// Render one side's config.
pub fn render_side(plan: &TunnelPlan, side: TunnelSide) -> String {
    match side {
        TunnelSide::Server => render_server(plan),
        TunnelSide::Client => render_client(plan),
    }
}

/// The systemd template unit HTM installs.
pub fn unit_template() -> String {
    format!(
        "[Unit]\n\
         Description=HTM Hiddify Core instance %i\n\
         Documentation=https://github.com/hiddify/hiddify-core\n\
         After=network-online.target nss-lookup.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=60\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=root\n\
         ExecStartPre=/bin/mkdir -p {workdir_base}/%i\n\
         ExecStart={binary} -D {workdir_base}/%i run -c {config_dir}/%i.json\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier={prefix}-%i\n\
         AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n\
         NoNewPrivileges=false\n\
         LimitNOFILE=infinity\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        workdir_base = WORKDIR_BASE,
        binary = BINARY_PATH,
        config_dir = CONFIG_DIR,
        prefix = SERVICE_PREFIX,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EndpointPlan, SpoofPlan};

    fn plan_with(protocol: &str, mode: &str) -> TunnelPlan {
        let mut p = TunnelPlan {
            instance: "demo".into(),
            provider_id: "hiddifycore".into(),
            client: EndpointPlan {
                side: TunnelSide::Client,
                iface: "eth0".into(),
                real_ip: "198.51.100.1".into(),
                public_ip: "198.51.100.1".into(),
                tun_ip: "10.66.0.2".into(),
                spoofed_ip: "198.51.100.1".into(),
            },
            server: EndpointPlan {
                side: TunnelSide::Server,
                iface: "ens3".into(),
                real_ip: "203.0.113.9".into(),
                public_ip: "203.0.113.9".into(),
                tun_ip: "10.66.0.1".into(),
                spoofed_ip: "203.0.113.9".into(),
            },
            tun_netmask: "255.255.255.252".into(),
            tun_name: "hcore0".into(),
            data_port: 8443,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![],
            mtu: 1400,
            tun_mtu: 1400,
            log_level: "info".into(),
            spoofing: SpoofPlan::default(),
            options: option_space().defaults(),
        };
        p.options
            .insert(keys::PROTOCOL.into(), OptValue::Choice(protocol.into()));
        p.options
            .insert(keys::INBOUND_MODE.into(), OptValue::Choice(mode.into()));
        p
    }

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).expect("valid JSON")
    }

    #[test]
    fn derived_uuid_is_well_formed_and_stable() {
        let a = derive_uuid("mysecretkey-1234567890");
        let b = derive_uuid("mysecretkey-1234567890");
        assert_eq!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(a.as_bytes()[14], b'5', "version nibble");
        assert!(matches!(a.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }

    #[test]
    fn shadowsocks_server_and_client_share_method_and_password() {
        let p = plan_with("shadowsocks", "mixed");
        let server = parse(&render_server(&p));
        assert_eq!(server["inbounds"][0]["type"], "shadowsocks");
        assert_eq!(server["inbounds"][0]["method"], SS_METHOD);
        let client = parse(&render_client(&p));
        assert_eq!(client["outbounds"][0]["type"], "shadowsocks");
        assert_eq!(
            client["outbounds"][0]["password"],
            server["inbounds"][0]["password"]
        );
        assert_eq!(client["outbounds"][0]["server"], "203.0.113.9");
        assert_eq!(client["outbounds"][0]["server_port"], 8443);
    }

    #[test]
    fn uuid_protocols_use_the_same_uuid_on_both_sides() {
        for proto in ["vmess", "vless", "tuic"] {
            let p = plan_with(proto, "mixed");
            let server = parse(&render_server(&p));
            let client = parse(&render_client(&p));
            let want = derive_uuid(&p.pre_shared_key);
            assert_eq!(server["inbounds"][0]["users"][0]["uuid"], want, "{proto}");
            assert_eq!(client["outbounds"][0]["uuid"], want, "{proto}");
        }
    }

    #[test]
    fn tls_protocols_point_at_the_exit_certificate_and_skip_verification() {
        for proto in ["trojan", "hysteria2", "tuic"] {
            let p = plan_with(proto, "mixed");
            assert!(needs_certificate(&p), "{proto} should need a cert");
            let server = parse(&render_server(&p));
            assert_eq!(
                server["inbounds"][0]["tls"]["certificate_path"],
                cert_path("demo")
            );
            let client = parse(&render_client(&p));
            assert_eq!(client["outbounds"][0]["tls"]["insecure"], true);
            assert_eq!(client["outbounds"][0]["tls"]["server_name"], "www.bing.com");
        }
    }

    #[test]
    fn non_tls_protocols_need_no_certificate() {
        for proto in ["shadowsocks", "vmess", "vless", "socks"] {
            assert!(!needs_certificate(&plan_with(proto, "mixed")), "{proto}");
        }
    }

    #[test]
    fn mixed_mode_opens_a_local_proxy_port() {
        let p = plan_with("vless", "mixed");
        let client = parse(&render_client(&p));
        assert_eq!(client["inbounds"][0]["type"], "mixed");
        assert_eq!(client["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(client["inbounds"][0]["listen_port"], 2080);
    }

    #[test]
    fn tun_mode_creates_an_auto_routed_tun_for_full_ip_forwarding() {
        let p = plan_with("vless", "tun");
        let client = parse(&render_client(&p));
        assert_eq!(client["inbounds"][0]["type"], "tun");
        assert_eq!(client["inbounds"][0]["auto_route"], true);
    }

    #[test]
    fn the_relay_reaches_the_exit_directly_to_avoid_a_loop() {
        let p = plan_with("vmess", "tun");
        let client = parse(&render_client(&p));
        let rules = client["route"]["rules"].as_array().unwrap();
        assert!(rules
            .iter()
            .any(|r| r["ip_cidr"][0] == "203.0.113.9/32" && r["outbound"] == "direct"));
        assert_eq!(client["route"]["final"], "proxy");
    }

    #[test]
    fn the_exit_exits_to_the_internet_directly() {
        let server = parse(&render_server(&plan_with("vmess", "mixed")));
        assert_eq!(server["route"]["final"], "direct");
    }

    #[test]
    fn defaults_validate_and_normalise() {
        let defaults = option_space().defaults();
        assert!(validate(&defaults).is_ok());
        assert_eq!(normalize(&defaults), normalize(&normalize(&defaults)));
        assert_eq!(protocol_of(&normalize(&defaults)), Protocol::Shadowsocks);
    }

    #[test]
    fn an_unknown_protocol_is_rejected_and_normalised_away() {
        let mut opts = option_space().defaults();
        opts.insert(
            keys::PROTOCOL.into(),
            OptValue::Choice("wireguard-xyz".into()),
        );
        assert!(validate(&opts).is_err());
        assert_eq!(protocol_of(&normalize(&opts)), Protocol::Shadowsocks);
    }

    #[test]
    fn the_unit_runs_hiddify_core_with_the_instance_config() {
        let unit = unit_template();
        assert!(unit.contains("/opt/htm-hiddifycore/hiddify-core -D"));
        assert!(unit.contains("run -c /etc/htm-hiddifycore/%i.json"));
    }

    #[test]
    fn udp_and_tls_flags_match_the_protocol() {
        assert!(Protocol::Hysteria2.is_udp());
        assert!(Protocol::Tuic.is_udp());
        assert!(!Protocol::Vmess.is_udp());
        assert!(Protocol::Trojan.needs_tls());
        assert!(!Protocol::Shadowsocks.needs_tls());
    }
}
