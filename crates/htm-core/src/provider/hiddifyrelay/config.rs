//! The Hiddify Relay Builder methods, as HTM configuration.
//!
//! The Hiddify Relay Builder is a relay — not a point-to-point tunnel. The
//! relay server listens on a set of ports (443/80 by default) and forwards each
//! one to an upstream "main server", so clients connect to the relay while the
//! real service runs elsewhere. HTM maps the relay onto the client/relay side
//! and the upstream onto the exit's public address, and installs the forwarder
//! as a per-instance systemd unit.
//!
//! Six methods are offered, matching the Builder's own menu:
//!
//! | Method      | Mechanism                                             | Far end |
//! |-------------|-------------------------------------------------------|---------|
//! | `iptables`  | NAT DNAT/MASQUERADE of the ports to the upstream       | unmanaged |
//! | `gost`      | `gost -L` TCP+UDP forwarders, one per port             | unmanaged |
//! | `dokodemo`  | Xray dokodemo-door inbounds, one per port (tcp,udp)    | unmanaged |
//! | `haproxy`   | HAProxy TCP frontend→backend, one per port             | unmanaged |
//! | `socat`     | `socat` TCP relays, one process per port               | unmanaged |
//! | `wst`       | wstunnel websocket forward; the upstream runs a server | managed |
//!
//! Only `wst` configures the far end (the upstream runs a wstunnel server); the
//! other five leave it an unchanged destination, so for them HTM manages the
//! relay alone.
//!
//! This is a [`RelayForward`](crate::provider::TunnelModel) model: there is no
//! TUN link and no throughput benchmark; readiness is the forwarder listening
//! on its ports.
//!
//! See the Hiddify Relay Builder: <https://github.com/hiddify/hiddify-relay>.

use crate::model::{
    OptValue, OptionKind, OptionMap, OptionMapExt, OptionSpace, OptionSpec, TunnelPlan, TunnelSide,
};

pub const BASE_DIR: &str = "/etc/htm-hiddifyrelay";
pub const SERVICE_PREFIX: &str = "htm-hiddifyrelay";

pub const GOST_BIN: &str = "/usr/local/bin/gost";
pub const XRAY_BIN: &str = "/usr/local/bin/xray";
pub const WSTUNNEL_BIN: &str = "/usr/local/bin/wstunnel";
pub const HAPROXY_BIN: &str = "/usr/sbin/haproxy";
pub const SOCAT_BIN: &str = "/usr/bin/socat";

// ── Option keys ──────────────────────────────────────────────────────────────

pub mod keys {
    pub const METHOD: &str = "method";
    /// Websocket port the wstunnel server listens on and the relay dials.
    pub const WS_PORT: &str = "ws_port";
}

/// Which forwarding mechanism a relay instance uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMethod {
    Iptables,
    Gost,
    Dokodemo,
    Haproxy,
    Socat,
    Wst,
}

impl RelayMethod {
    pub fn id(self) -> &'static str {
        match self {
            RelayMethod::Iptables => "iptables",
            RelayMethod::Gost => "gost",
            RelayMethod::Dokodemo => "dokodemo",
            RelayMethod::Haproxy => "haproxy",
            RelayMethod::Socat => "socat",
            RelayMethod::Wst => "wst",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Some(match id {
            "iptables" => RelayMethod::Iptables,
            "gost" => RelayMethod::Gost,
            "dokodemo" => RelayMethod::Dokodemo,
            "haproxy" => RelayMethod::Haproxy,
            "socat" => RelayMethod::Socat,
            "wst" => RelayMethod::Wst,
            _ => return None,
        })
    }

    /// Does this method also configure the upstream (exit) host?
    pub fn manages_upstream(self) -> bool {
        matches!(self, RelayMethod::Wst)
    }

    /// All methods in menu order.
    pub const ALL: [RelayMethod; 6] = [
        RelayMethod::Iptables,
        RelayMethod::Gost,
        RelayMethod::Dokodemo,
        RelayMethod::Haproxy,
        RelayMethod::Socat,
        RelayMethod::Wst,
    ];
}

/// The method of a plan, falling back to the default rather than erroring.
pub fn method_of(options: &OptionMap) -> RelayMethod {
    RelayMethod::from_id(&options.str_or(keys::METHOD, "gost")).unwrap_or(RelayMethod::Gost)
}

/// The ports the relay forwards. Empty on the plan means the Builder's own
/// default of the web ports.
pub fn forward_ports(plan: &TunnelPlan) -> Vec<u16> {
    if plan.forward_ports.is_empty() {
        vec![80, 443]
    } else {
        let mut ports = plan.forward_ports.clone();
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

/// The websocket port for the `wst` method.
pub fn ws_port(plan: &TunnelPlan) -> u16 {
    normalize(&plan.options)
        .int_or(keys::WS_PORT, 8080)
        .clamp(1, 65_535) as u16
}

/// The upstream (main server) address the relay forwards to.
pub fn upstream_addr(plan: &TunnelPlan) -> String {
    plan.server.peer_target().to_string()
}

pub fn option_space() -> OptionSpace {
    let method_choices: Vec<(String, String)> = vec![
        (
            "iptables".into(),
            "IP-Tables — kernel NAT DNAT of the ports to the upstream".into(),
        ),
        (
            "gost".into(),
            "GOST — userspace TCP+UDP port forwarder".into(),
        ),
        (
            "dokodemo".into(),
            "Dokodemo-Door — Xray dokodemo inbound per port (tcp+udp)".into(),
        ),
        (
            "haproxy".into(),
            "HAProxy — TCP frontend/backend per port".into(),
        ),
        (
            "socat".into(),
            "Socat — one TCP relay process per port".into(),
        ),
        (
            "wst".into(),
            "WST — wstunnel websocket forward (also sets up the upstream)".into(),
        ),
    ];

    let mut specs = Vec::new();
    specs.push(OptionSpec {
        key: keys::METHOD.into(),
        label: "Relay method".into(),
        help: "How the relay forwards its ports to the upstream server. GOST, Dokodemo, HAProxy \
               and Socat are userspace forwarders that listen on each port; IP-Tables forwards in \
               the kernel with no listener; WST tunnels over websockets and also configures the \
               upstream."
            .into(),
        group: "Relay".into(),
        kind: OptionKind::Choice {
            choices: method_choices,
        },
        default: OptValue::Choice("gost".into()),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::WS_PORT.into(),
        label: "Websocket port (WST)".into(),
        help: "The port the wstunnel server listens on, and that the relay dials over ws://. \
               Used only by the WST method."
            .into(),
        group: "Relay".into(),
        kind: OptionKind::Int {
            min: 1,
            max: 65_535,
        },
        default: OptValue::Int(8080),
        benchmarkable: false,
        bench_values: Vec::new(),
    });

    OptionSpace { specs }
}

pub fn normalize(options: &OptionMap) -> OptionMap {
    let mut out = option_space().normalize(options);
    let method = out.str_or(keys::METHOD, "gost");
    if RelayMethod::from_id(&method).is_none() {
        out.insert(keys::METHOD.into(), OptValue::Choice("gost".into()));
    }
    out
}

pub fn validate(options: &OptionMap) -> Result<(), String> {
    if RelayMethod::from_id(&options.str_or(keys::METHOD, "gost")).is_none() {
        return Err(format!(
            "'{}' is not a relay method HTM knows.",
            options.str_or(keys::METHOD, "")
        ));
    }
    let ws = options.int_or(keys::WS_PORT, 8080);
    if !(1..=65_535).contains(&ws) {
        return Err("The websocket port must be between 1 and 65535.".into());
    }
    Ok(())
}

pub fn validate_plan(plan: &TunnelPlan) -> Result<(), String> {
    plan.validate()?;
    validate(&normalize(&plan.options))?;
    let ports = forward_ports(plan);
    if ports.is_empty() {
        return Err("A relay needs at least one port to forward.".into());
    }
    // The wstunnel port must not clash with a forwarded port on the relay.
    if method_of(&normalize(&plan.options)) == RelayMethod::Wst && ports.contains(&ws_port(plan)) {
        return Err(format!(
            "The websocket port {} is also in the forwarded-port list; give WST a port of its own.",
            ws_port(plan)
        ));
    }
    Ok(())
}

pub fn describe(options: &OptionMap) -> String {
    method_of(options).id().to_string()
}

pub fn config_dir(instance: &str) -> String {
    format!("{BASE_DIR}/{instance}")
}

pub fn service_name(instance: &str) -> String {
    format!("{SERVICE_PREFIX}-{instance}.service")
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// One file HTM writes for a relay instance, relative work done by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderFile {
    pub path: String,
    pub content: String,
    pub mode: String,
    pub description: String,
}

/// A systemd unit wrapping an ExecStart line, shared by the long-running
/// methods. `oneshot` marks the kernel-NAT method, which applies rules on start
/// and removes them on stop rather than running a daemon.
fn unit(
    plan: &TunnelPlan,
    method: RelayMethod,
    exec_start: &str,
    exec_stop: Option<&str>,
    needs_net_admin: bool,
) -> String {
    let caps = if needs_net_admin {
        "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n"
    } else {
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
    };
    let (ty, extra) = if let Some(stop) = exec_stop {
        ("oneshot", format!("RemainAfterExit=yes\nExecStop={stop}\n"))
    } else {
        ("simple", "Restart=on-failure\nRestartSec=5\n".to_string())
    };
    format!(
        "[Unit]\n\
         Description=HTM Hiddify Relay ({method}) — instance {instance}\n\
         Documentation=https://github.com/hiddify/hiddify-relay\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=60\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         Type={ty}\n\
         User=root\n\
         ExecStart={exec_start}\n\
         {extra}\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier={prefix}-{instance}\n\
         {caps}\
         NoNewPrivileges=false\n\
         LimitNOFILE=65536\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        method = method.id(),
        instance = plan.instance,
        ty = ty,
        exec_start = exec_start,
        extra = extra,
        prefix = SERVICE_PREFIX,
        caps = caps,
    )
}

/// Render every file for one side of a relay plan.
///
/// The relay (client) side always produces a forwarder; the upstream (server)
/// side produces files only for the `wst` method, which runs a wstunnel server
/// there. Any other method leaves the upstream untouched and returns nothing.
pub fn render_side(plan: &TunnelPlan, side: TunnelSide) -> Vec<RenderFile> {
    let options = normalize(&plan.options);
    let method = method_of(&options);
    let dir = config_dir(&plan.instance);
    let unit_path = format!("/etc/systemd/system/{}", service_name(&plan.instance));

    if side == TunnelSide::Server {
        // Only wstunnel configures the far end.
        if method != RelayMethod::Wst {
            return Vec::new();
        }
        let exec = format!(
            "{bin} --server ws://0.0.0.0:{ws}",
            bin = WSTUNNEL_BIN,
            ws = ws_port(plan),
        );
        return vec![RenderFile {
            path: unit_path,
            content: unit(plan, method, &exec, None, false),
            mode: "0644".into(),
            description: "wstunnel server unit".into(),
        }];
    }

    // ── Relay (client) side ──────────────────────────────────────────────────
    let ports = forward_ports(plan);
    let upstream = upstream_addr(plan);

    match method {
        RelayMethod::Iptables => {
            let up = iptables_script(&ports, &upstream, true);
            let down = iptables_script(&ports, &upstream, false);
            let up_path = format!("{dir}/up.sh");
            let down_path = format!("{dir}/down.sh");
            let exec = format!("/bin/sh {}", up_path);
            let stop = format!("/bin/sh {}", down_path);
            vec![
                RenderFile {
                    path: up_path,
                    content: up,
                    mode: "0755".into(),
                    description: "iptables apply script".into(),
                },
                RenderFile {
                    path: down_path,
                    content: down,
                    mode: "0755".into(),
                    description: "iptables teardown script".into(),
                },
                RenderFile {
                    path: unit_path,
                    content: unit(plan, method, &exec, Some(&stop), true),
                    mode: "0644".into(),
                    description: "iptables relay unit".into(),
                },
            ]
        }
        RelayMethod::Gost => {
            // One -L forwarder per port, for both TCP and UDP.
            let mut args = String::new();
            for p in &ports {
                args.push_str(&format!(" -L=tcp://:{p}/{upstream}:{p}"));
                args.push_str(&format!(" -L=udp://:{p}/{upstream}:{p}"));
            }
            let exec = format!("{GOST_BIN}{args}");
            vec![RenderFile {
                path: unit_path,
                content: unit(plan, method, &exec, None, true),
                mode: "0644".into(),
                description: "gost relay unit".into(),
            }]
        }
        RelayMethod::Dokodemo => {
            let cfg_path = format!("{dir}/xray.json");
            let exec = format!("{XRAY_BIN} run -c {cfg_path}");
            vec![
                RenderFile {
                    path: cfg_path,
                    content: xray_config(&ports, &upstream),
                    mode: "0644".into(),
                    description: "Xray dokodemo-door config".into(),
                },
                RenderFile {
                    path: unit_path,
                    content: unit(plan, method, &exec, None, true),
                    mode: "0644".into(),
                    description: "Xray relay unit".into(),
                },
            ]
        }
        RelayMethod::Haproxy => {
            let cfg_path = format!("{dir}/haproxy.cfg");
            let exec = format!("{HAPROXY_BIN} -f {cfg_path} -db");
            vec![
                RenderFile {
                    path: cfg_path,
                    content: haproxy_config(&ports, &upstream),
                    mode: "0644".into(),
                    description: "HAProxy config".into(),
                },
                RenderFile {
                    path: unit_path,
                    content: unit(plan, method, &exec, None, true),
                    mode: "0644".into(),
                    description: "HAProxy relay unit".into(),
                },
            ]
        }
        RelayMethod::Socat => {
            let run_path = format!("{dir}/run.sh");
            let exec = format!("/bin/sh {run_path}");
            vec![
                RenderFile {
                    path: run_path,
                    content: socat_script(&ports, &upstream),
                    mode: "0755".into(),
                    description: "socat relay script".into(),
                },
                RenderFile {
                    path: unit_path,
                    content: unit(plan, method, &exec, None, true),
                    mode: "0644".into(),
                    description: "socat relay unit".into(),
                },
            ]
        }
        RelayMethod::Wst => {
            // The relay forwards each port over a websocket to the upstream's
            // wstunnel server.
            let ws = ws_port(plan);
            let mut args = String::new();
            for p in &ports {
                args.push_str(&format!(" -L 0.0.0.0:{p}:localhost:{p}"));
            }
            let exec = format!("{WSTUNNEL_BIN}{args} ws://{upstream}:{ws}");
            vec![RenderFile {
                path: unit_path,
                content: unit(plan, method, &exec, None, true),
                mode: "0644".into(),
                description: "wstunnel relay unit".into(),
            }]
        }
    }
}

/// The readiness ports for one side: the listeners a working relay opens.
pub fn readiness_ports(plan: &TunnelPlan, side: TunnelSide) -> Vec<(u16, bool)> {
    let method = method_of(&normalize(&plan.options));
    match side {
        TunnelSide::Client => {
            // iptables forwards in the kernel and opens no listening socket, so
            // there is nothing to probe — the unit being active is the signal.
            if method == RelayMethod::Iptables {
                Vec::new()
            } else {
                forward_ports(plan).into_iter().map(|p| (p, true)).collect()
            }
        }
        TunnelSide::Server => {
            if method == RelayMethod::Wst {
                vec![(ws_port(plan), true)]
            } else {
                Vec::new()
            }
        }
    }
}

fn iptables_script(ports: &[u16], upstream: &str, apply: bool) -> String {
    // `-A` to add on start, `-D` to delete the identical rule on stop. A comment
    // tag makes the rules recognisable, and deleting by the same spec is exact.
    let op = if apply { "-A" } else { "-D" };
    let mut body = String::new();
    body.push_str("#!/bin/sh\n");
    if apply {
        body.push_str("set -e\n");
        body.push_str("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true\n");
    } else {
        // On teardown, a missing rule must not abort the rest.
        body.push_str("set +e\n");
    }
    for p in ports {
        for proto in ["tcp", "udp"] {
            body.push_str(&format!(
                "iptables -t nat {op} PREROUTING -p {proto} --dport {p} -j DNAT \
                 --to-destination {upstream}\n"
            ));
            body.push_str(&format!(
                "iptables -t nat {op} POSTROUTING -p {proto} -d {upstream} --dport {p} -j MASQUERADE\n"
            ));
        }
    }
    body.push_str("exit 0\n");
    body
}

fn xray_config(ports: &[u16], upstream: &str) -> String {
    let inbounds: Vec<serde_json::Value> = ports
        .iter()
        .map(|p| {
            serde_json::json!({
                "listen": null,
                "port": p,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": upstream,
                    "followRedirect": false,
                    "network": "tcp,udp",
                    "port": p,
                },
                "tag": format!("inbound-{p}"),
            })
        })
        .collect();
    let cfg = serde_json::json!({
        "log": { "loglevel": "warning" },
        "inbounds": inbounds,
        "outbounds": [
            { "protocol": "freedom" },
            { "protocol": "blackhole", "tag": "blocked" }
        ],
    });
    serde_json::to_string_pretty(&cfg).unwrap_or_else(|_| "{}".into())
}

fn haproxy_config(ports: &[u16], upstream: &str) -> String {
    let mut s = String::new();
    s.push_str(
        "global\n    daemon\n    maxconn 20000\n\n\
         defaults\n    mode tcp\n    timeout connect 5s\n    timeout client 50s\n    timeout server 50s\n\n",
    );
    for p in ports {
        s.push_str(&format!(
            "frontend tunnel-{p}\n    bind :::{p} v4v6\n    mode tcp\n    default_backend backend-{p}\n\n\
             backend backend-{p}\n    mode tcp\n    server upstream {upstream}:{p}\n\n"
        ));
    }
    s
}

fn socat_script(ports: &[u16], upstream: &str) -> String {
    let mut s = String::new();
    s.push_str("#!/bin/sh\n# One socat TCP relay per forwarded port.\npids=\"\"\n");
    for p in ports {
        s.push_str(&format!(
            "{bin} TCP-LISTEN:{p},reuseaddr,fork TCP:{up}:{p} &\npids=\"$pids $!\"\n",
            bin = SOCAT_BIN,
            up = upstream,
        ));
    }
    s.push_str("trap 'kill $pids 2>/dev/null' TERM INT\nwait\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EndpointPlan, OptValue, SpoofPlan};

    fn plan() -> TunnelPlan {
        TunnelPlan {
            instance: "demo".into(),
            provider_id: "hiddifyrelay".into(),
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
            tun_name: "rel0".into(),
            data_port: 443,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![443, 80],
            mtu: 1380,
            tun_mtu: 1380,
            log_level: "info".into(),
            spoofing: SpoofPlan::default(),
            options: option_space().defaults(),
        }
    }

    fn with_method(method: &str) -> TunnelPlan {
        let mut p = plan();
        p.options
            .insert(keys::METHOD.into(), OptValue::Choice(method.into()));
        p
    }

    fn relay_unit(files: &[RenderFile]) -> &RenderFile {
        files
            .iter()
            .find(|f| f.path.contains("/etc/systemd/system/"))
            .expect("a unit file")
    }

    #[test]
    fn default_ports_fall_back_to_the_web_ports() {
        let mut p = plan();
        p.forward_ports = vec![];
        assert_eq!(forward_ports(&p), vec![80, 443]);
    }

    #[test]
    fn gost_forwards_each_port_tcp_and_udp_to_the_upstream() {
        let files = render_side(&with_method("gost"), TunnelSide::Client);
        let unit = relay_unit(&files);
        assert!(unit.content.contains("-L=tcp://:443/203.0.113.9:443"));
        assert!(unit.content.contains("-L=udp://:80/203.0.113.9:80"));
        // Only the relay is managed for gost.
        assert!(render_side(&with_method("gost"), TunnelSide::Server).is_empty());
    }

    #[test]
    fn iptables_applies_and_tears_down_dnat_rules() {
        let files = render_side(&with_method("iptables"), TunnelSide::Client);
        let up = files.iter().find(|f| f.path.ends_with("up.sh")).unwrap();
        let down = files.iter().find(|f| f.path.ends_with("down.sh")).unwrap();
        assert!(up
            .content
            .contains("-A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 203.0.113.9"));
        assert!(down
            .content
            .contains("-D PREROUTING -p tcp --dport 443 -j DNAT --to-destination 203.0.113.9"));
        // It is a oneshot unit with an ExecStop.
        let unit = relay_unit(&files);
        assert!(unit.content.contains("Type=oneshot"));
        assert!(unit.content.contains("ExecStop=/bin/sh"));
    }

    #[test]
    fn dokodemo_writes_an_xray_config_with_one_inbound_per_port() {
        let files = render_side(&with_method("dokodemo"), TunnelSide::Client);
        let cfg = files
            .iter()
            .find(|f| f.path.ends_with("xray.json"))
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&cfg.content).unwrap();
        assert_eq!(v["inbounds"].as_array().unwrap().len(), 2);
        assert_eq!(v["inbounds"][0]["protocol"], "dokodemo-door");
        assert_eq!(v["inbounds"][0]["settings"]["address"], "203.0.113.9");
    }

    #[test]
    fn haproxy_makes_a_tcp_frontend_and_backend_per_port() {
        let files = render_side(&with_method("haproxy"), TunnelSide::Client);
        let cfg = files
            .iter()
            .find(|f| f.path.ends_with("haproxy.cfg"))
            .unwrap();
        assert!(cfg.content.contains("frontend tunnel-443"));
        assert!(cfg.content.contains("server upstream 203.0.113.9:443"));
    }

    #[test]
    fn socat_launches_one_relay_per_port() {
        let files = render_side(&with_method("socat"), TunnelSide::Client);
        let run = files.iter().find(|f| f.path.ends_with("run.sh")).unwrap();
        assert!(run
            .content
            .contains("TCP-LISTEN:443,reuseaddr,fork TCP:203.0.113.9:443"));
        assert!(run
            .content
            .contains("TCP-LISTEN:80,reuseaddr,fork TCP:203.0.113.9:80"));
    }

    #[test]
    fn wst_forwards_over_websocket_and_sets_up_the_upstream_server() {
        let mut p = with_method("wst");
        p.options.insert(keys::WS_PORT.into(), OptValue::Int(8080));
        let relay = render_side(&p, TunnelSide::Client);
        assert!(relay_unit(&relay)
            .content
            .contains("-L 0.0.0.0:443:localhost:443"));
        assert!(relay_unit(&relay).content.contains("ws://203.0.113.9:8080"));
        // WST manages the upstream too.
        let server = render_side(&p, TunnelSide::Server);
        assert!(!server.is_empty());
        assert!(relay_unit(&server)
            .content
            .contains("--server ws://0.0.0.0:8080"));
    }

    #[test]
    fn readiness_probes_the_forwarded_ports_except_for_kernel_nat() {
        assert_eq!(
            readiness_ports(&with_method("gost"), TunnelSide::Client),
            vec![(80, true), (443, true)]
        );
        // iptables opens no socket.
        assert!(readiness_ports(&with_method("iptables"), TunnelSide::Client).is_empty());
        // wst probes the upstream's websocket port.
        let mut p = with_method("wst");
        p.options.insert(keys::WS_PORT.into(), OptValue::Int(8080));
        assert_eq!(readiness_ports(&p, TunnelSide::Server), vec![(8080, true)]);
    }

    #[test]
    fn wst_rejects_a_websocket_port_that_clashes_with_a_forwarded_port() {
        let mut p = with_method("wst");
        p.options.insert(keys::WS_PORT.into(), OptValue::Int(443));
        assert!(validate_plan(&p).is_err());
    }

    #[test]
    fn only_wst_manages_the_upstream() {
        assert!(RelayMethod::Wst.manages_upstream());
        for m in [
            RelayMethod::Iptables,
            RelayMethod::Gost,
            RelayMethod::Dokodemo,
            RelayMethod::Haproxy,
            RelayMethod::Socat,
        ] {
            assert!(!m.manages_upstream(), "{}", m.id());
        }
    }

    #[test]
    fn an_unknown_method_normalises_to_the_default() {
        let mut opts = option_space().defaults();
        opts.insert(keys::METHOD.into(), OptValue::Choice("bogus".into()));
        assert!(validate(&opts).is_err());
        assert_eq!(method_of(&normalize(&opts)), RelayMethod::Gost);
    }

    #[test]
    fn the_upstream_is_the_exits_public_address() {
        assert_eq!(upstream_addr(&plan()), "203.0.113.9");
    }
}
