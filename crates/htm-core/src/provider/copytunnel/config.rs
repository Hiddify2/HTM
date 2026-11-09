//! CopyTunnel's settings, validation, and the pair of TOML files it reads.
//!
//! CopyTunnel is a point-to-point encrypted TUN tunnel: the relay captures
//! IPv4 TCP/UDP through a TUN device, encrypts every packet with one of six
//! wire ciphers, and relays it to the exit over UDP, where the kernel routes
//! and NATs it to the real destination. The option keys here match
//! CopyTunnel's own config keys one for one, so the generated file reads
//! against the upstream documentation without translation.
//!
//! HTM drives only CopyTunnel's **TUN** mode. The transparent-proxy mode needs
//! sing-box plus iptables TPROXY on the relay and exposes no TUN link to ping,
//! so it belongs to a different tunnel model than the one this provider serves.
//!
//! See <https://github.com/Hiddify2/CopyTunnel>.

use crate::model::{
    is_ipv4, OptValue, OptionKind, OptionMap, OptionMapExt, OptionSpace, OptionSpec, FakeMode,
    TunnelPlan, TunnelSide,
};

/// HTM-owned install and config locations. Namespaced away from upstream's
/// `/opt/copytunnel` source tree and `/etc/copytunnel/{tun,proxy}.toml`, so an
/// installation managed by CopyTunnel's own `copytunnel-menu` keeps working
/// untouched alongside HTM's.
pub const INSTALL_DIR: &str = "/opt/htm-copytunnel";
pub const CONFIG_DIR: &str = "/etc/htm-copytunnel";
pub const BINARY_PATH: &str = "/opt/htm-copytunnel/copytunnel";
pub const VERSION_FILE: &str = "/opt/htm-copytunnel/VERSION";
pub const SERVICE_PREFIX: &str = "htm-copytunnel";
pub const UNIT_TEMPLATE: &str = "htm-copytunnel@.service";

// ── Option keys ──────────────────────────────────────────────────────────────

pub mod keys {
    pub const CIPHER: &str = "encryption";
    pub const OBFUSCATE: &str = "obfuscate";
    pub const FORWARD_PROTOCOLS: &str = "forward_protocols";
    pub const AUTO_NAT: &str = "auto_nat";
    pub const KEEPALIVE: &str = "keepalive_secs";
    pub const WORKERS: &str = "worker_threads";
}

/// Every wire cipher CopyTunnel ships, in the order the UI should offer them.
/// The second element is the one-line trade-off shown as hover help.
pub const CIPHERS: [(&str, &str); 6] = [
    (
        "chacha20poly1305",
        "AEAD, fast and constant-time on any CPU with no AES hardware. The safe default.",
    ),
    (
        "xchacha20poly1305",
        "AEAD with a 192-bit nonce, for extremely high packet rates where nonce reuse is a concern.",
    ),
    (
        "aes256gcm",
        "AEAD, the throughput winner on a modern CPU with AES-NI; slower in pure software.",
    ),
    (
        "aes128gcm",
        "AEAD with a 128-bit key, marginally faster AES, still strong.",
    ),
    (
        "xor",
        "Obfuscation only — NOT confidential and NOT authenticated. DPI shape-breaking or raw throughput tests.",
    ),
    (
        "none",
        "Plaintext passthrough. Debugging only; packets travel in the clear.",
    ),
];

/// The ciphers that provide real confidentiality and integrity.
pub const AEAD_CIPHERS: [&str; 4] = [
    "chacha20poly1305",
    "xchacha20poly1305",
    "aes256gcm",
    "aes128gcm",
];

/// Build the full option space.
pub fn option_space() -> OptionSpace {
    let cipher_choices: Vec<(String, String)> = CIPHERS
        .iter()
        .map(|(id, help)| (id.to_string(), format!("{id} — {help}")))
        .collect();

    let mut specs = Vec::new();

    // ── Encryption ──────────────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::CIPHER.into(),
        label: "Wire cipher".into(),
        help: "How every packet is sealed on the link. The four AEAD ciphers are confidential \
               and authenticated; 'xor' and 'none' are obfuscation and debugging only. Must \
               match on both sides, which HTM guarantees by rendering them together."
            .into(),
        group: "Encryption".into(),
        kind: OptionKind::Choice {
            choices: cipher_choices,
        },
        default: OptValue::Choice("chacha20poly1305".into()),
        benchmarkable: true,
        bench_values: CIPHERS
            .iter()
            .map(|(id, _)| OptValue::Choice((*id).to_string()))
            .collect(),
    });
    specs.push(OptionSpec {
        key: keys::OBFUSCATE.into(),
        label: "Whole-frame obfuscation".into(),
        help: "Run a PSK-derived XOR mask over the entire sealed frame so it has no fixed \
               structure a trivial classifier could key on. Adds no cryptographic strength — \
               the AEAD already provides that — and must match on both sides."
            .into(),
        group: "Encryption".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(false),
        benchmarkable: true,
        bench_values: Vec::new(),
    });

    // ── Packet selection ────────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::FORWARD_PROTOCOLS.into(),
        label: "Protocols to tunnel".into(),
        help: "Which IP protocols are captured and relayed. Packets of other protocols are \
               dropped at the TUN device. CopyTunnel forwards IPv4 only."
            .into(),
        group: "Packet selection".into(),
        kind: OptionKind::Choice {
            choices: vec![
                ("both".into(), "TCP and UDP".into()),
                ("tcp".into(), "TCP only".into()),
                ("udp".into(), "UDP only".into()),
            ],
        },
        default: OptValue::Choice("both".into()),
        benchmarkable: false,
        bench_values: Vec::new(),
    });

    // ── Networking ──────────────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::AUTO_NAT.into(),
        label: "Automatic NAT on the exit".into(),
        help: "Let CopyTunnel enable IPv4 forwarding and install the MASQUERADE rule on the \
               exit, and remove them when it stops. Turn off only if you manage NAT yourself."
            .into(),
        group: "Networking".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(true),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::KEEPALIVE.into(),
        label: "Keepalive interval (s)".into(),
        help: "How often the relay sends a keepalive so the exit always knows where to send \
               replies. Zero disables it."
            .into(),
        group: "Networking".into(),
        kind: OptionKind::Int { min: 0, max: 120 },
        default: OptValue::Int(15),
        benchmarkable: false,
        bench_values: Vec::new(),
    });

    // ── Performance ─────────────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::WORKERS.into(),
        label: "Worker threads".into(),
        help: "Tokio runtime threads. Zero lets CopyTunnel use one per CPU core.".into(),
        group: "Performance".into(),
        kind: OptionKind::Int { min: 0, max: 64 },
        default: OptValue::Int(0),
        benchmarkable: false,
        bench_values: Vec::new(),
    });

    OptionSpace { specs }
}

/// Fold an option map into canonical form. CopyTunnel has few interdependent
/// settings, so this mostly fills defaults and clamps the cipher to a known
/// value, which keeps the benchmark de-duplicator honest.
pub fn normalize(options: &OptionMap) -> OptionMap {
    let space = option_space();
    let mut out = space.normalize(options);

    let cipher = out.str_or(keys::CIPHER, "chacha20poly1305");
    if !CIPHERS.iter().any(|(id, _)| *id == cipher) {
        out.insert(
            keys::CIPHER.into(),
            OptValue::Choice("chacha20poly1305".into()),
        );
    }

    let protos = out.str_or(keys::FORWARD_PROTOCOLS, "both");
    if !matches!(protos.as_str(), "both" | "tcp" | "udp") {
        out.insert(
            keys::FORWARD_PROTOCOLS.into(),
            OptValue::Choice("both".into()),
        );
    }

    out
}

/// Reject combinations CopyTunnel will refuse to run.
pub fn validate(options: &OptionMap) -> Result<(), String> {
    let cipher = options.str_or(keys::CIPHER, "chacha20poly1305");
    if !CIPHERS.iter().any(|(id, _)| *id == cipher) {
        return Err(format!("'{cipher}' is not a cipher CopyTunnel supports."));
    }
    let protos = options.str_or(keys::FORWARD_PROTOCOLS, "both");
    if !matches!(protos.as_str(), "both" | "tcp" | "udp") {
        return Err(format!("'{protos}' is not a valid protocol selection."));
    }
    Ok(())
}

/// Whether the chosen cipher actually protects the traffic.
pub fn cipher_is_secure(cipher: &str) -> bool {
    AEAD_CIPHERS.contains(&cipher)
}

/// A short label describing what makes a variant distinct.
pub fn describe(options: &OptionMap) -> String {
    let mut parts = vec![options.str_or(keys::CIPHER, "chacha20poly1305")];
    if options.bool_or(keys::OBFUSCATE, false) {
        parts.push("obfs".into());
    }
    let protos = options.str_or(keys::FORWARD_PROTOCOLS, "both");
    if protos != "both" {
        parts.push(protos);
    }
    parts.join(" · ")
}

/// A sentence-form explanation of a variant.
pub fn explain(options: &OptionMap) -> String {
    let cipher = options.str_or(keys::CIPHER, "chacha20poly1305");
    let mut out = format!("{cipher} cipher");
    if !cipher_is_secure(&cipher) {
        out.push_str(" (obfuscation/debug only, not confidential)");
    }
    if options.bool_or(keys::OBFUSCATE, false) {
        out.push_str(", whole-frame obfuscation on");
    }
    let protos = options.str_or(keys::FORWARD_PROTOCOLS, "both");
    out.push_str(match protos.as_str() {
        "tcp" => ", TCP only",
        "udp" => ", UDP only",
        _ => ", TCP and UDP",
    });
    out.push('.');
    out
}

/// The forward-protocols option as the TOML array CopyTunnel expects.
fn forward_protocols_array(selection: &str) -> &'static str {
    match selection {
        "tcp" => r#"["tcp"]"#,
        "udp" => r#"["udp"]"#,
        _ => r#"["tcp", "udp"]"#,
    }
}

// ── TOML rendering ───────────────────────────────────────────────────────────

fn toml_bool(v: bool) -> &'static str {
    if v {
        "true"
    } else {
        "false"
    }
}

fn toml_string(v: &str) -> String {
    let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn toml_int_array(values: &[u16]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }
    let items: Vec<String> = values.iter().map(|v| v.to_string()).collect();
    format!("[{}]", items.join(", "))
}

/// Render one side's config TOML.
///
/// The two sides differ in `role`, in whether `mode`/`server_addr` (client) or
/// `listen_addr`/`auto_nat` (server) are present, in the swapped TUN addresses,
/// and in the forwarded ports, which only the relay captures.
pub fn render_toml(plan: &TunnelPlan, side: TunnelSide) -> String {
    let options = normalize(&plan.options);
    let me = plan.endpoint(side);
    let peer = plan.endpoint(side.peer());
    let tun_mtu = plan.tun_mtu.min(plan.mtu);
    let generated = chrono::Utc::now().to_rfc3339();

    let mut s = String::with_capacity(2048);
    s.push_str(&format!(
        "# CopyTunnel configuration generated by HTM (Hiddify Tunnel Manager)\n\
         # Instance : {instance}\n\
         # Role     : {role}\n\
         # Generated: {generated}\n\
         #\n\
         # Do not edit by hand: HTM rewrites this file whenever the tunnel is\n\
         # redeployed. Change the settings in HTM instead.\n\n",
        instance = plan.instance,
        role = side.as_str(),
        generated = generated,
    ));

    s.push_str(&format!("role = {}\n", toml_string(side.as_str())));
    if side == TunnelSide::Client {
        // HTM drives only the layer-3 TUN mode.
        s.push_str("mode = \"tun\"\n");
    }
    s.push('\n');

    s.push_str("# ── Transport ─────────────────────────────────────────────────\n");
    match side {
        TunnelSide::Client => {
            s.push_str(&format!(
                "server_addr = {}\n",
                toml_string(&format!("{}:{}", peer.peer_target(), plan.data_port))
            ));
        }
        TunnelSide::Server => {
            s.push_str(&format!(
                "listen_addr = {}\n",
                toml_string(&format!("0.0.0.0:{}", plan.data_port))
            ));
            // HTM serves TUN clients only; the transparent-proxy listener stays
            // off so this unit never doubles as a sing-box backend.
            s.push_str("proxy_listen = \"\"\n");
        }
    }
    s.push('\n');

    s.push_str("# ── Security (must match on both sides) ───────────────────────\n");
    s.push_str(&format!(
        "pre_shared_key = {}\n",
        toml_string(&plan.pre_shared_key)
    ));
    s.push_str(&format!(
        "encryption = {}\n",
        toml_string(&options.str_or(keys::CIPHER, "chacha20poly1305"))
    ));
    s.push_str(&format!(
        "obfuscate = {}\n\n",
        toml_bool(options.bool_or(keys::OBFUSCATE, false))
    ));

    s.push_str("# ── Packet selection ──────────────────────────────────────────\n");
    s.push_str(&format!(
        "forward_protocols = {}\n",
        forward_protocols_array(&options.str_or(keys::FORWARD_PROTOCOLS, "both"))
    ));
    // Only the relay captures traffic, so only it filters ports.
    let forward_ports = if side == TunnelSide::Client {
        toml_int_array(&plan.forward_ports)
    } else {
        "[]".to_string()
    };
    s.push_str(&format!("forward_ports = {forward_ports}\n\n"));

    s.push_str("# ── TUN interface ─────────────────────────────────────────────\n");
    s.push_str(&format!("tun_name    = {}\n", toml_string(&plan.tun_name)));
    s.push_str(&format!("tun_ip      = {}\n", toml_string(&me.tun_ip)));
    s.push_str(&format!("tun_peer_ip = {}\n", toml_string(&peer.tun_ip)));
    s.push_str(&format!(
        "tun_netmask = {}\n",
        toml_string(&plan.tun_netmask)
    ));
    s.push_str(&format!("mtu         = {tun_mtu}\n\n"));

    s.push_str("# ── Networking ────────────────────────────────────────────────\n");
    s.push_str(&format!("interface = {}\n", toml_string(&me.iface)));
    match side {
        TunnelSide::Server => {
            s.push_str(&format!(
                "auto_nat  = {}\n",
                toml_bool(options.bool_or(keys::AUTO_NAT, true))
            ));
        }
        TunnelSide::Client => {
            // NAT is a server concern; keep it off on the relay.
            s.push_str("auto_nat  = false\n");
            s.push_str(&format!(
                "keepalive_secs = {}\n",
                options.int_or(keys::KEEPALIVE, 15)
            ));
        }
    }
    s.push('\n');

    s.push_str("# ── Runtime ───────────────────────────────────────────────────\n");
    s.push_str(&format!(
        "worker_threads = {}\n",
        options.int_or(keys::WORKERS, 0)
    ));
    s.push_str(&format!(
        "log_level      = {}\n",
        toml_string(&plan.log_level)
    ));

    s
}

/// The systemd template unit HTM installs.
pub fn unit_template() -> String {
    format!(
        "[Unit]\n\
         Description=HTM CopyTunnel instance %i\n\
         Documentation=https://github.com/Hiddify2/CopyTunnel\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=60\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=root\n\
         ExecStart={binary} --config {config_dir}/%i.toml\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier={prefix}-%i\n\
         AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n\
         NoNewPrivileges=false\n\
         LimitNOFILE=65536\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        binary = BINARY_PATH,
        config_dir = CONFIG_DIR,
        prefix = SERVICE_PREFIX,
    )
}

/// Sanity-check a rendered plan before anything is uploaded.
pub fn validate_plan(plan: &TunnelPlan) -> Result<(), String> {
    plan.validate()?;
    validate(&normalize(&plan.options))?;

    // CopyTunnel sends from each host's real address and has no field for a
    // forged source, so the forged-address mode cannot be honoured here.
    if plan.faking.mode == FakeMode::Forged {
        return Err(
            "CopyTunnel sends from each server's own address and cannot forge source addresses. \
             Use the normal source-address mode, or pick a provider that supports forging."
                .into(),
        );
    }

    if plan.tun_name.len() > 15 {
        return Err(format!(
            "The TUN interface name '{}' is longer than the 15 characters Linux allows.",
            plan.tun_name
        ));
    }
    if !is_ipv4(&plan.client.tun_ip) || !is_ipv4(&plan.server.tun_ip) {
        return Err("The TUN addresses are not valid IPv4 addresses.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EndpointPlan, FakePlan};

    fn plan() -> TunnelPlan {
        TunnelPlan {
            instance: "demo".into(),
            provider_id: "copytunnel".into(),
            client: EndpointPlan {
                side: TunnelSide::Client,
                iface: "eth0".into(),
                real_ip: "192.0.2.10".into(),
                public_ip: "192.0.2.10".into(),
                tun_ip: "10.66.0.2".into(),
                faked_ip: "192.0.2.10".into(),
            },
            server: EndpointPlan {
                side: TunnelSide::Server,
                iface: "ens3".into(),
                real_ip: "198.51.100.5".into(),
                public_ip: "198.51.100.5".into(),
                tun_ip: "10.66.0.1".into(),
                faked_ip: "198.51.100.5".into(),
            },
            tun_netmask: "255.255.255.252".into(),
            tun_name: "copy0".into(),
            data_port: 51822,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![443, 80],
            mtu: 1380,
            tun_mtu: 1380,
            log_level: "info".into(),
            faking: FakePlan::default(),
            options: option_space().defaults(),
        }
    }

    #[test]
    fn both_sides_render_their_role_and_share_the_secret() {
        let p = plan();
        let client = render_toml(&p, TunnelSide::Client);
        let server = render_toml(&p, TunnelSide::Server);
        assert!(client.contains("role = \"client\""));
        assert!(client.contains("mode = \"tun\""));
        assert!(server.contains("role = \"server\""));
        assert!(!server.contains("mode ="), "server has no client mode");
        assert!(client.contains("pre_shared_key = \"0123456789abcdef0123456789abcdef\""));
        assert!(server.contains("pre_shared_key = \"0123456789abcdef0123456789abcdef\""));
    }

    #[test]
    fn the_client_dials_the_exit_and_the_server_listens() {
        let p = plan();
        let client = render_toml(&p, TunnelSide::Client);
        assert!(client.contains("server_addr = \"198.51.100.5:51822\""));
        let server = render_toml(&p, TunnelSide::Server);
        assert!(server.contains("listen_addr = \"0.0.0.0:51822\""));
        assert!(server.contains("proxy_listen = \"\""));
    }

    #[test]
    fn tun_addresses_are_swapped_between_sides() {
        let p = plan();
        let client = render_toml(&p, TunnelSide::Client);
        let server = render_toml(&p, TunnelSide::Server);
        assert!(client.contains("tun_ip      = \"10.66.0.2\""));
        assert!(client.contains("tun_peer_ip = \"10.66.0.1\""));
        assert!(server.contains("tun_ip      = \"10.66.0.1\""));
        assert!(server.contains("tun_peer_ip = \"10.66.0.2\""));
    }

    #[test]
    fn only_the_relay_forwards_ports_and_runs_without_nat() {
        let p = plan();
        let client = render_toml(&p, TunnelSide::Client);
        let server = render_toml(&p, TunnelSide::Server);
        assert!(client.contains("forward_ports = [443, 80]"));
        assert!(client.contains("auto_nat  = false"));
        assert!(server.contains("forward_ports = []"));
        assert!(server.contains("auto_nat  = true"));
    }

    #[test]
    fn the_cipher_and_obfuscation_render_on_both_sides() {
        let mut p = plan();
        p.options
            .insert(keys::CIPHER.into(), OptValue::Choice("aes256gcm".into()));
        p.options
            .insert(keys::OBFUSCATE.into(), OptValue::Bool(true));
        for side in [TunnelSide::Client, TunnelSide::Server] {
            let r = render_toml(&p, side);
            assert!(r.contains("encryption = \"aes256gcm\""), "{side:?}");
            assert!(r.contains("obfuscate = true"), "{side:?}");
        }
    }

    #[test]
    fn protocol_selection_renders_the_right_array() {
        let mut p = plan();
        p.options.insert(
            keys::FORWARD_PROTOCOLS.into(),
            OptValue::Choice("udp".into()),
        );
        assert!(render_toml(&p, TunnelSide::Client).contains("forward_protocols = [\"udp\"]"));
    }

    #[test]
    fn defaults_are_valid_and_already_normalised() {
        let defaults = option_space().defaults();
        assert!(validate(&defaults).is_ok());
        assert_eq!(normalize(&defaults), defaults);
    }

    #[test]
    fn an_unknown_cipher_is_rejected_and_normalised_away() {
        let mut opts = option_space().defaults();
        opts.insert(keys::CIPHER.into(), OptValue::Choice("rot13".into()));
        assert!(validate(&opts).is_err());
        assert!(validate(&normalize(&opts)).is_ok());
    }

    #[test]
    fn forged_source_addresses_are_refused() {
        let mut p = plan();
        p.faking = FakePlan::from_list(&["8.8.8.8".into(), "1.1.1.1".into()]);
        p.client.faked_ip = "8.8.8.8".into();
        p.server.faked_ip = "1.1.1.1".into();
        assert!(validate_plan(&p).is_err());
    }

    #[test]
    fn aead_ciphers_are_flagged_secure_and_the_rest_are_not() {
        assert!(cipher_is_secure("chacha20poly1305"));
        assert!(cipher_is_secure("aes128gcm"));
        assert!(!cipher_is_secure("xor"));
        assert!(!cipher_is_secure("none"));
    }

    #[test]
    fn the_unit_runs_the_unified_binary_with_net_capabilities() {
        let unit = unit_template();
        assert!(unit.contains("/opt/htm-copytunnel/copytunnel --config"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW"));
    }
}
