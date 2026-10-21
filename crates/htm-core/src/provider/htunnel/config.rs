//! HTunnel's settings and the pair of JSON config files it reads.
//!
//! HTunnel is an asymmetric UDP tunnel rather than a TUN tunnel. The relay
//! exposes a local **SOCKS5** proxy; the uplink (relay → exit) rides an
//! upstream SOCKS5 proxy, and the downlink (exit → relay) is fake-source UDP
//! from a pool of addresses. There is no TUN device and no point-to-point
//! link, so HTM treats it as a [`SocksProxy`](crate::provider::TunnelModel)
//! model: readiness is the SOCKS5 port actually listening, not an ICMP echo.
//!
//! The exit's fake downlink source maps onto HTM's source-address modes: in
//! forged mode the exit's half of the address list becomes `faked_ip_pool`; in
//! the normal mode the exit simply sends from its own address, which is what
//! works on a provider that filters forged sources.
//!
//! See <https://github.com/Hiddify2/HTunnel>.

use serde_json::json;

use crate::model::{
    OptValue, OptionKind, OptionMap, OptionMapExt, OptionSpace, OptionSpec, TunnelPlan, TunnelSide,
};

/// HTM-owned install and config locations, namespaced away from a manual
/// `/etc/htunnel` install set up by upstream's `setup.sh`.
pub const INSTALL_DIR: &str = "/opt/htm-htunnel";
pub const CONFIG_DIR: &str = "/etc/htm-htunnel";
pub const BINARY_CLIENT: &str = "/opt/htm-htunnel/htunnel-client";
pub const BINARY_SERVER: &str = "/opt/htm-htunnel/htunnel-server";
pub const VERSION_FILE: &str = "/opt/htm-htunnel/VERSION";
pub const SERVICE_PREFIX: &str = "htm-htunnel";

// ── Option keys ──────────────────────────────────────────────────────────────

pub mod keys {
    /// Local SOCKS5 port the relay exposes to applications.
    pub const SOCKS_PORT: &str = "socks_port";
    /// Upstream SOCKS5 proxy the relay's uplink rides, as `host:port`. Empty
    /// means none, in which case the relay dials the exit directly.
    pub const UPLINK_PROXY: &str = "uplink_proxy";
    /// Parallel tunnels.
    pub const TUNNEL_COUNT: &str = "tunnel_count";
    /// Initial congestion window.
    pub const INITIAL_CWND: &str = "initial_cwnd";
}

/// Build the full option space.
pub fn option_space() -> OptionSpace {
    let mut specs = Vec::new();

    specs.push(OptionSpec {
        key: keys::SOCKS_PORT.into(),
        label: "Local SOCKS5 port".into(),
        help: "The port the relay's SOCKS5 proxy listens on, for applications on the relay to \
               point at. Bound to localhost."
            .into(),
        group: "Proxy".into(),
        kind: OptionKind::Int {
            min: 1,
            max: 65_535,
        },
        default: OptValue::Int(9234),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::UPLINK_PROXY.into(),
        label: "Upstream SOCKS5 proxy".into(),
        help: "The relay sends its uplink through this upstream SOCKS5 proxy (host:port), which \
               is what makes the upload look like ordinary SOCKS traffic. Leave empty to dial the \
               exit directly. HTM does not set this proxy up for you — point it at an existing \
               one (a 3x-ui SOCKS inbound, Dante, …)."
            .into(),
        group: "Proxy".into(),
        kind: OptionKind::Text,
        default: OptValue::Text(String::new()),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::TUNNEL_COUNT.into(),
        label: "Parallel tunnels".into(),
        help: "Independent streams run side by side; more can raise throughput on a high-latency \
               route at the cost of memory and CPU."
            .into(),
        group: "Performance".into(),
        kind: OptionKind::Int { min: 1, max: 32 },
        default: OptValue::Int(4),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::INITIAL_CWND.into(),
        label: "Initial congestion window".into(),
        help: "How many packets the sender puts in flight before waiting for acknowledgements. \
               Larger ramps up faster on a fast link; smaller is gentler on a lossy one."
            .into(),
        group: "Performance".into(),
        kind: OptionKind::Int { min: 1, max: 1_000 },
        default: OptValue::Int(10),
        benchmarkable: false,
        bench_values: Vec::new(),
    });

    OptionSpace { specs }
}

/// Fill defaults and clamp; nothing here is interdependent.
pub fn normalize(options: &OptionMap) -> OptionMap {
    option_space().normalize(options)
}

/// Reject combinations HTunnel will refuse to run.
pub fn validate(options: &OptionMap) -> Result<(), String> {
    let port = options.int_or(keys::SOCKS_PORT, 9234);
    if !(1..=65_535).contains(&port) {
        return Err("The local SOCKS5 port must be between 1 and 65535.".into());
    }
    let proxy = options.str_or(keys::UPLINK_PROXY, "");
    if !proxy.is_empty() && !proxy.contains(':') {
        return Err(
            "The upstream SOCKS5 proxy must be given as host:port, for example 127.0.0.1:1081."
                .into(),
        );
    }
    if options.int_or(keys::TUNNEL_COUNT, 4) < 1 {
        return Err("At least one parallel tunnel is required.".into());
    }
    Ok(())
}

/// The SOCKS5 port the relay listens on for a plan.
pub fn socks_port(plan: &TunnelPlan) -> u16 {
    normalize(&plan.options)
        .int_or(keys::SOCKS_PORT, 9234)
        .clamp(1, 65_535) as u16
}

/// The exit's fake downlink source address and its rotation pool.
///
/// In forged mode this is the exit's half of the user's address list; in the
/// normal mode the exit sends from its own address, which keeps the tunnel
/// working on a provider that filters forged sources.
fn exit_fake_pool(plan: &TunnelPlan) -> Vec<String> {
    if plan.spoofing.is_forged() {
        let pool = plan.spoofing.pool_for(TunnelSide::Server);
        if !pool.is_empty() {
            return pool.to_vec();
        }
    }
    vec![plan.server.real_ip.clone()]
}

/// A short label describing a configuration.
pub fn describe(options: &OptionMap) -> String {
    let mut parts = vec![format!("x{}", options.int_or(keys::TUNNEL_COUNT, 4))];
    let proxy = options.str_or(keys::UPLINK_PROXY, "");
    parts.push(if proxy.is_empty() {
        "direct-uplink".into()
    } else {
        "proxied-uplink".into()
    });
    parts.join(" · ")
}

// ── Benchmark matrix ─────────────────────────────────────────────────────────
//
// HTunnel is measured through its SOCKS5 proxy; the sweep varies the parallel
// tunnel count, which is what most affects its throughput.

use crate::model::{BenchVariant, MatrixSelection};

pub fn variant_id(options: &OptionMap) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for (key, value) in options {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.short_display().as_bytes());
        hasher.update(b";");
    }
    let digest = hasher.finalize();
    digest[..6].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn expand(selection: &MatrixSelection) -> Vec<BenchVariant> {
    let base = option_space().defaults();
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for combo in selection.expand(&base) {
        let normalized = normalize(&combo);
        if validate(&normalized).is_err() {
            continue;
        }
        let id = variant_id(&normalized);
        if !seen.insert(id.clone()) {
            continue;
        }
        let count = normalized.int_or(keys::TUNNEL_COUNT, 4);
        out.push(BenchVariant {
            id,
            label: format!("{count} tunnel(s)"),
            description: format!("HTunnel with {count} parallel tunnel(s)"),
            options: normalized,
        });
    }
    out
}

pub fn default_matrix() -> MatrixSelection {
    let mut s = MatrixSelection::default();
    s.dimensions.insert(
        keys::TUNNEL_COUNT.to_string(),
        vec![
            OptValue::Int(1),
            OptValue::Int(2),
            OptValue::Int(4),
            OptValue::Int(8),
        ],
    );
    s
}

/// Render one side's JSON config.
pub fn render_json(plan: &TunnelPlan, side: TunnelSide) -> String {
    let options = normalize(&plan.options);
    let me = plan.endpoint(side);
    let peer = plan.endpoint(side.peer());
    let tunnel_count = options.int_or(keys::TUNNEL_COUNT, 4).max(1);
    let cwnd = options.int_or(keys::INITIAL_CWND, 10).max(1) as f64;
    let mtu = plan.tun_mtu.min(plan.mtu);
    let fake_pool = exit_fake_pool(plan);
    let fake_primary = fake_pool
        .first()
        .cloned()
        .unwrap_or_else(|| plan.server.real_ip.clone());

    let value = match side {
        TunnelSide::Client => {
            let proxy = options.str_or(keys::UPLINK_PROXY, "");
            // The relay must accept the exit's downlink, which arrives from the
            // fake source pool — so every fake address is trusted explicitly.
            let allowed: Vec<String> = fake_pool.clone();
            json!({
                "listen": format!("127.0.0.1:{}", options.int_or(keys::SOCKS_PORT, 9234)),
                "interface": me.iface,
                "real_ip": me.real_ip,
                "peer_real_ip": peer.peer_target(),
                "peer_fake_ip": fake_primary,
                "data_port": plan.data_port,
                "allowed_peers": allowed,
                "tunnel_count": tunnel_count,
                "mtu": mtu,
                "initial_cwnd": cwnd,
                "uplink_proxy": if proxy.is_empty() { serde_json::Value::Null } else { json!(proxy) },
            })
        }
        TunnelSide::Server => {
            // The exit's uplink arrives from the relay, or from the relay's
            // upstream SOCKS proxy; the relay's own address is trusted, and the
            // operator can add a proxy's address to allowed_peers by hand.
            let allowed: Vec<String> = vec![peer.real_ip.clone()];
            json!({
                "listen": format!("0.0.0.0:{}", plan.data_port),
                "interface": me.iface,
                "real_ip": me.real_ip,
                "peer_real_ip": peer.peer_target(),
                "faked_ip": fake_primary,
                "faked_ip_pool": fake_pool,
                "data_port": plan.data_port,
                "allowed_peers": allowed,
                "tunnel_count": tunnel_count,
                "mtu": mtu,
                "initial_cwnd": cwnd,
                "uplink_proxy": serde_json::Value::Null,
            })
        }
    };

    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

/// The systemd unit for one side. HTunnel ships two binaries rather than one
/// role-switching binary, so the relay runs the client and the exit runs the
/// server; the unit's name is the same on both, its `ExecStart` is not.
pub fn unit_file(plan: &TunnelPlan, side: TunnelSide) -> String {
    let binary = match side {
        TunnelSide::Client => BINARY_CLIENT,
        TunnelSide::Server => BINARY_SERVER,
    };
    let role = match side {
        TunnelSide::Client => "relay (SOCKS5 client)",
        TunnelSide::Server => "exit (server)",
    };
    format!(
        "[Unit]\n\
         Description=HTM HTunnel {role} — instance {instance}\n\
         Documentation=https://github.com/Hiddify2/HTunnel\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=60\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=root\n\
         ExecStart={binary} --config {config}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier={prefix}-{instance}\n\
         AmbientCapabilities=CAP_NET_RAW\n\
         NoNewPrivileges=false\n\
         LimitNOFILE=65536\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        role = role,
        instance = plan.instance,
        binary = binary,
        config = config_path(&plan.instance),
        prefix = SERVICE_PREFIX,
    )
}

/// systemd unit name for an instance.
pub fn service_name(instance: &str) -> String {
    format!("{SERVICE_PREFIX}-{instance}.service")
}

/// Config file path for an instance.
pub fn config_path(instance: &str) -> String {
    format!("{CONFIG_DIR}/{instance}.json")
}

/// Sanity-check a plan before anything is uploaded.
pub fn validate_plan(plan: &TunnelPlan) -> Result<(), String> {
    plan.validate()?;
    validate(&normalize(&plan.options))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{is_ipv4, EndpointPlan, SpoofPlan};

    fn plan() -> TunnelPlan {
        TunnelPlan {
            instance: "demo".into(),
            provider_id: "htunnel".into(),
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
                real_ip: "203.0.113.1".into(),
                public_ip: "203.0.113.1".into(),
                tun_ip: "10.66.0.1".into(),
                spoofed_ip: "203.0.113.1".into(),
            },
            tun_netmask: "255.255.255.252".into(),
            tun_name: "htun0".into(),
            data_port: 51820,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![],
            mtu: 1380,
            tun_mtu: 1380,
            log_level: "info".into(),
            spoofing: SpoofPlan::default(),
            options: option_space().defaults(),
        }
    }

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("valid JSON")
    }

    #[test]
    fn the_client_exposes_a_socks_port_and_names_the_exit() {
        let v = parse(&render_json(&plan(), TunnelSide::Client));
        assert_eq!(v["listen"], "127.0.0.1:9234");
        assert_eq!(v["peer_real_ip"], "203.0.113.1");
        assert_eq!(v["real_ip"], "198.51.100.1");
        // No upstream proxy by default → null, not a string.
        assert!(v["uplink_proxy"].is_null());
    }

    #[test]
    fn the_server_listens_on_the_data_port_and_fakes_its_own_address_by_default() {
        let v = parse(&render_json(&plan(), TunnelSide::Server));
        assert_eq!(v["listen"], "0.0.0.0:51820");
        // Normal (non-forged) mode: the exit sends from its own address.
        assert_eq!(v["faked_ip"], "203.0.113.1");
        assert_eq!(v["faked_ip_pool"][0], "203.0.113.1");
        assert!(v["uplink_proxy"].is_null());
    }

    #[test]
    fn forged_mode_fills_the_fake_pool_from_the_exits_half() {
        let mut p = plan();
        p.spoofing = SpoofPlan::from_list(&[
            "8.8.8.8".into(),
            "1.1.1.1".into(),
            "9.9.9.9".into(),
            "208.67.222.222".into(),
        ]);
        p.server.spoofed_ip = p.spoofing.server_pool[0].clone();
        let server = parse(&render_json(&p, TunnelSide::Server));
        // Exit's half is entries 1 and 3.
        assert_eq!(server["faked_ip"], "1.1.1.1");
        assert_eq!(server["faked_ip_pool"][0], "1.1.1.1");
        assert_eq!(server["faked_ip_pool"][1], "208.67.222.222");
        // The relay must accept every fake the exit might send from.
        let client = parse(&render_json(&p, TunnelSide::Client));
        assert_eq!(client["peer_fake_ip"], "1.1.1.1");
        assert_eq!(client["allowed_peers"][0], "1.1.1.1");
    }

    #[test]
    fn an_upstream_proxy_renders_as_a_string_on_the_client_only() {
        let mut p = plan();
        p.options.insert(
            keys::UPLINK_PROXY.into(),
            OptValue::Text("127.0.0.1:1081".into()),
        );
        let client = parse(&render_json(&p, TunnelSide::Client));
        assert_eq!(client["uplink_proxy"], "127.0.0.1:1081");
        let server = parse(&render_json(&p, TunnelSide::Server));
        assert!(server["uplink_proxy"].is_null());
    }

    #[test]
    fn the_congestion_window_is_a_json_number() {
        let v = parse(&render_json(&plan(), TunnelSide::Client));
        assert!(v["initial_cwnd"].is_number());
        assert_eq!(v["initial_cwnd"].as_f64(), Some(10.0));
    }

    #[test]
    fn a_custom_socks_port_moves_the_listener() {
        let mut p = plan();
        p.options
            .insert(keys::SOCKS_PORT.into(), OptValue::Int(1080));
        assert_eq!(socks_port(&p), 1080);
        let v = parse(&render_json(&p, TunnelSide::Client));
        assert_eq!(v["listen"], "127.0.0.1:1080");
    }

    #[test]
    fn units_are_side_specific_and_share_a_name() {
        let p = plan();
        assert_eq!(service_name("demo"), "htm-htunnel-demo.service");
        assert!(unit_file(&p, TunnelSide::Client).contains("htunnel-client --config"));
        assert!(unit_file(&p, TunnelSide::Server).contains("htunnel-server --config"));
    }

    #[test]
    fn defaults_validate_and_a_bad_proxy_is_caught() {
        assert!(validate(&option_space().defaults()).is_ok());
        let mut opts = option_space().defaults();
        opts.insert(keys::UPLINK_PROXY.into(), OptValue::Text("no-port".into()));
        assert!(validate(&opts).is_err());
    }

    #[test]
    fn rendered_configs_are_valid_json_with_ipv4_fields() {
        let v = parse(&render_json(&plan(), TunnelSide::Server));
        assert!(is_ipv4(v["real_ip"].as_str().unwrap()));
        assert!(is_ipv4(v["faked_ip"].as_str().unwrap()));
    }
}
