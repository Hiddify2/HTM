//! Working out *why* a tunnel is not passing traffic.
//!
//! "The tunnel did not carry traffic" is a useless thing to tell someone. This
//! module collects the handful of facts that actually distinguish the causes,
//! from both servers, and turns them into a sentence naming the most likely
//! one.
//!
//! The decisive figures are the TUN interface counters:
//!
//! | relay tx | relay rx | what it means |
//! |----------|----------|---------------|
//! | 0        | 0        | nothing reached the TUN — routing, or the device is not up |
//! | > 0      | 0        | the relay is sending and getting nothing back — the wire path is broken |
//! | > 0      | > 0      | packets are crossing; the problem is elsewhere |

use std::collections::BTreeMap;

use crate::error::Result;
use crate::model::TunnelSide;
use crate::ssh::SshClient;
use crate::util::sh_quote;

/// What one server reports about a tunnel that is not working.
#[derive(Debug, Clone, Default)]
pub struct HostDiagnostics {
    pub label: String,
    /// `net.ipv4.ip_forward`.
    pub ip_forward: Option<u8>,
    pub rp_filter_all: Option<u8>,
    pub rp_filter_tun: Option<u8>,

    pub tun_present: bool,
    pub tun_state: String,
    pub tun_address: String,
    pub tun_mtu: Option<u32>,
    pub tun_rx_packets: Option<u64>,
    pub tun_tx_packets: Option<u64>,

    /// First line of `ip route get <peer tun ip>`.
    pub route_to_peer: String,
    /// Number of running `candy-tunnel` processes.
    pub processes: Option<u32>,
    /// Whether the other server answers an ordinary ping on its public address.
    pub peer_reachable: Option<bool>,

    pub firewall: Vec<String>,
    /// Anything the script printed that was not understood.
    pub raw: String,
}

impl HostDiagnostics {
    /// A compact block for a failure message.
    pub fn render(&self) -> String {
        let yes_no = |v: Option<bool>| match v {
            Some(true) => "yes".to_string(),
            Some(false) => "no".to_string(),
            None => "unknown".to_string(),
        };
        let num = |v: Option<u64>| match v {
            Some(n) => n.to_string(),
            None => "unknown".to_string(),
        };

        let mut out = format!("[{}]\n", self.label);
        if !self.tun_present {
            out.push_str("  TUN device      : NOT PRESENT\n");
        } else {
            out.push_str(&format!(
                "  TUN device      : {} {} mtu {}\n",
                self.tun_state,
                if self.tun_address.is_empty() {
                    "(no address)"
                } else {
                    &self.tun_address
                },
                self.tun_mtu.map(|m| m.to_string()).unwrap_or_default(),
            ));
            out.push_str(&format!(
                "  TUN packets     : {} in / {} out\n",
                num(self.tun_rx_packets),
                num(self.tun_tx_packets),
            ));
        }
        out.push_str(&format!(
            "  ip_forward      : {}\n",
            self.ip_forward
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".into())
        ));
        out.push_str(&format!(
            "  rp_filter       : all={} tun={}\n",
            self.rp_filter_all
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
            self.rp_filter_tun
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
        ));
        out.push_str(&format!(
            "  tunnel process  : {}\n",
            self.processes
                .map(|n| format!("{n} running"))
                .unwrap_or_else(|| "unknown".into())
        ));
        out.push_str(&format!(
            "  peer pingable   : {}\n",
            yes_no(self.peer_reachable)
        ));
        if !self.route_to_peer.is_empty() {
            out.push_str(&format!("  route to peer   : {}\n", self.route_to_peer));
        }
        for line in &self.firewall {
            out.push_str(&format!("  firewall        : {line}\n"));
        }
        out
    }
}

/// Collect diagnostics from one host.
pub fn collect(
    client: &SshClient,
    label: &str,
    tun_name: &str,
    peer_tun_ip: &str,
    peer_wire_ip: &str,
) -> Result<HostDiagnostics> {
    // Deliberately free of shell braces, so it can go through `format!` without
    // escaping, and free of awk, so it runs on a busybox userland.
    let script = format!(
        r#"#!/bin/sh
TUN={tun}
PEER={peer_tun}
PEER_WIRE={peer_wire}

echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
echo "rp_filter_all=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null)"

if [ -d "/sys/class/net/$TUN" ]; then
  echo "tun_present=1"
  echo "rp_filter_tun=$(cat /proc/sys/net/ipv4/conf/$TUN/rp_filter 2>/dev/null)"
  echo "tun_state=$(cat /sys/class/net/$TUN/operstate 2>/dev/null)"
  echo "tun_mtu=$(cat /sys/class/net/$TUN/mtu 2>/dev/null)"
  echo "tun_rx_packets=$(cat /sys/class/net/$TUN/statistics/rx_packets 2>/dev/null)"
  echo "tun_tx_packets=$(cat /sys/class/net/$TUN/statistics/tx_packets 2>/dev/null)"
  echo "tun_address=$(ip -4 -o addr show dev "$TUN" 2>/dev/null | tr -s ' ' | cut -d' ' -f4)"
else
  echo "tun_present=0"
fi

echo "route_to_peer=$(ip -4 route get "$PEER" 2>&1 | head -n 1)"
echo "processes=$(pgrep -c -f candy-tunnel 2>/dev/null)"
echo "peer_reachable=$(ping -n -q -c 2 -W 3 "$PEER_WIRE" >/dev/null 2>&1 && echo yes || echo no)"

POLICY=$(iptables -S INPUT 2>/dev/null | head -n 1)
if [ -n "$POLICY" ]; then
  echo "firewall=iptables INPUT $POLICY"
fi
DROPS=$(iptables -S 2>/dev/null | grep -c -- "-j DROP")
if [ -n "$DROPS" ]; then
  echo "firewall=iptables DROP rules: $DROPS"
fi
if command -v ufw >/dev/null 2>&1; then
  echo "firewall=ufw $(ufw status 2>/dev/null | head -n 1)"
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  echo "firewall=firewalld $(firewall-cmd --state 2>/dev/null)"
fi
exit 0
"#,
        tun = sh_quote(tun_name),
        peer_tun = sh_quote(peer_tun_ip),
        peer_wire = sh_quote(peer_wire_ip),
    );

    let out = client.run_script(&script, true)?;
    Ok(parse(label, &out.stdout))
}

fn parse(label: &str, text: &str) -> HostDiagnostics {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut firewall = Vec::new();
    let mut unknown = String::new();

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        match line.split_once('=') {
            Some(("firewall", value)) => firewall.push(value.trim().to_string()),
            Some((key, value)) if !key.is_empty() => {
                map.insert(key.trim().to_string(), value.trim().to_string());
            }
            _ => {
                if !line.trim().is_empty() {
                    unknown.push_str(line);
                    unknown.push('\n');
                }
            }
        }
    }

    let get = |k: &str| map.get(k).cloned().unwrap_or_default();
    let u8_of = |k: &str| get(k).parse::<u8>().ok();
    let u32_of = |k: &str| get(k).parse::<u32>().ok();
    let u64_of = |k: &str| get(k).parse::<u64>().ok();

    HostDiagnostics {
        label: label.to_string(),
        ip_forward: u8_of("ip_forward"),
        rp_filter_all: u8_of("rp_filter_all"),
        rp_filter_tun: u8_of("rp_filter_tun"),
        tun_present: get("tun_present") == "1",
        tun_state: get("tun_state"),
        tun_address: get("tun_address"),
        tun_mtu: u32_of("tun_mtu"),
        tun_rx_packets: u64_of("tun_rx_packets"),
        tun_tx_packets: u64_of("tun_tx_packets"),
        route_to_peer: get("route_to_peer"),
        processes: u32_of("processes"),
        peer_reachable: match get("peer_reachable").as_str() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        },
        firewall,
        raw: unknown,
    }
}

/// Name the most likely cause, given what both sides reported.
///
/// Ordered so the first matching rule is the one worth acting on: there is no
/// point telling someone about reverse-path filtering when the TUN device was
/// never created.
pub fn explain(relay: &HostDiagnostics, exit: &HostDiagnostics, wire_port: u16) -> String {
    if !relay.tun_present || !exit.tun_present {
        let which = if !relay.tun_present {
            &relay.label
        } else {
            &exit.label
        };
        return format!(
            "The TUN device was never created on {which}. The tunnel process is running but \
             failed to set the interface up — check that /dev/net/tun exists and that the \
             process has CAP_NET_ADMIN."
        );
    }

    if relay.processes == Some(0) || exit.processes == Some(0) {
        return "The tunnel process is not running on one of the servers, even though systemd \
                reports the unit as active. It is most likely crashing and being restarted."
            .to_string();
    }

    if relay.peer_reachable == Some(false) {
        return format!(
            "{} cannot even ping {} on its public address. The two servers have no path to each \
             other, so no tunnel transport will work until that is fixed.",
            relay.label, exit.label
        );
    }

    let relay_tx = relay.tun_tx_packets.unwrap_or(0);
    let relay_rx = relay.tun_rx_packets.unwrap_or(0);
    let exit_tx = exit.tun_tx_packets.unwrap_or(0);
    let exit_rx = exit.tun_rx_packets.unwrap_or(0);

    if relay_tx == 0 {
        return format!(
            "Nothing was written into the tunnel on {}: its TUN device sent zero packets. The \
             ping never reached the interface, which points at the routing for the tunnel \
             subnet rather than at the link itself.",
            relay.label
        );
    }

    if relay_rx == 0 && exit_rx == 0 {
        return format!(
            "{} sent {relay_tx} packets into the tunnel and {} received none of them, so the \
             wire path is blocked in that direction. The usual cause is the exit server's \
             firewall dropping inbound traffic on port {wire_port}; the next most likely is a \
             provider filtering the transport itself.",
            relay.label, exit.label
        );
    }

    if relay_rx == 0 && exit_rx > 0 {
        return format!(
            "{} received {exit_rx} packets and replied ({exit_tx} sent), but {} received none of \
             the replies. Traffic is getting through in one direction only — check the relay's \
             firewall for inbound rules on port {wire_port}, and reverse-path filtering if the \
             servers use asymmetric routing.",
            exit.label, relay.label
        );
    }

    format!(
        "Packets are crossing the link in both directions ({} out / {} in on the relay), so the \
         transport itself works. The handshake is being rejected instead — most often because \
         the two sides disagree on a setting that has to match, such as the pre-shared key or \
         the encryption flag.",
        relay_tx, relay_rx
    )
}

/// Collect from both servers and produce a report.
pub fn report(
    relay_client: &SshClient,
    exit_client: &SshClient,
    relay_label: &str,
    exit_label: &str,
    tun_name: &str,
    relay_tun_ip: &str,
    exit_tun_ip: &str,
    relay_wire_ip: &str,
    exit_wire_ip: &str,
    wire_port: u16,
) -> String {
    let relay = collect(relay_client, relay_label, tun_name, exit_tun_ip, exit_wire_ip)
        .unwrap_or_else(|e| HostDiagnostics {
            label: relay_label.to_string(),
            raw: format!("diagnostics could not be collected: {e}"),
            ..Default::default()
        });
    let exit = collect(exit_client, exit_label, tun_name, relay_tun_ip, relay_wire_ip)
        .unwrap_or_else(|e| HostDiagnostics {
            label: exit_label.to_string(),
            raw: format!("diagnostics could not be collected: {e}"),
            ..Default::default()
        });

    format!(
        "\nMost likely cause:\n  {}\n\n{}\n{}",
        explain(&relay, &exit, wire_port),
        relay.render(),
        exit.render(),
    )
}

/// Which side a set of diagnostics came from, for callers that keep both.
pub fn label_for(side: TunnelSide) -> &'static str {
    match side {
        TunnelSide::Client => "relay",
        TunnelSide::Server => "exit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(label: &str, tx: u64, rx: u64) -> HostDiagnostics {
        HostDiagnostics {
            label: label.to_string(),
            tun_present: true,
            processes: Some(1),
            peer_reachable: Some(true),
            tun_tx_packets: Some(tx),
            tun_rx_packets: Some(rx),
            ..Default::default()
        }
    }

    #[test]
    fn key_values_are_parsed_including_repeated_firewall_lines() {
        let text = "\
ip_forward=1
rp_filter_all=2
tun_present=1
tun_state=unknown
tun_rx_packets=0
tun_tx_packets=17
firewall=ufw Status: active
firewall=iptables DROP rules: 3
";
        let d = parse("relay", text);
        assert_eq!(d.ip_forward, Some(1));
        assert_eq!(d.rp_filter_all, Some(2));
        assert!(d.tun_present);
        assert_eq!(d.tun_tx_packets, Some(17));
        assert_eq!(d.tun_rx_packets, Some(0));
        assert_eq!(d.firewall.len(), 2);
    }

    #[test]
    fn a_missing_tun_device_outranks_everything_else() {
        let mut relay = host("relay", 0, 0);
        relay.tun_present = false;
        let message = explain(&relay, &host("exit", 0, 0), 8472);
        assert!(message.contains("TUN device was never created"), "{message}");
    }

    #[test]
    fn unreachable_servers_are_reported_before_packet_counts() {
        let mut relay = host("relay", 0, 0);
        relay.peer_reachable = Some(false);
        let message = explain(&relay, &host("exit", 0, 0), 8472);
        assert!(message.contains("no path to each other"), "{message}");
    }

    #[test]
    fn sending_with_nothing_arriving_blames_the_exit_firewall() {
        let message = explain(&host("relay", 40, 0), &host("exit", 0, 0), 8472);
        assert!(message.contains("firewall"), "{message}");
        assert!(message.contains("8472"), "{message}");
    }

    #[test]
    fn a_one_way_path_is_distinguished_from_no_path() {
        let message = explain(&host("relay", 40, 0), &host("exit", 12, 40), 8472);
        assert!(message.contains("one direction only"), "{message}");
    }

    #[test]
    fn traffic_in_both_directions_points_at_the_handshake() {
        let message = explain(&host("relay", 40, 38), &host("exit", 38, 40), 8472);
        assert!(message.contains("handshake"), "{message}");
    }

    #[test]
    fn nothing_leaving_the_relay_points_at_routing() {
        let message = explain(&host("relay", 0, 0), &host("exit", 0, 0), 8472);
        assert!(message.contains("routing"), "{message}");
    }
}
