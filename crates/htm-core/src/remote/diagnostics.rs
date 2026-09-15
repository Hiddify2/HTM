//! Working out *why* a tunnel is not passing traffic.
//!
//! "The tunnel did not carry traffic" is a useless thing to tell someone. This
//! module collects the handful of facts that actually distinguish the causes,
//! from both servers, and turns them into a sentence naming the most likely
//! one.
//!
//! Two measurements carry most of the weight. The first is the TUN interface
//! counters:
//!
//! | relay tx | exit rx | what it means |
//! |----------|---------|---------------|
//! | 0        | 0       | nothing reached the TUN — routing, or the device is not up |
//! | > 0      | 0       | the relay is sending but nothing comes out the far end |
//! | > 0      | > 0     | packets are crossing; the problem is elsewhere |
//!
//! The middle row has two causes that need opposite fixes, so [`wire_arrival`]
//! separates them by counting tunnel packets as they arrive at the exit, below
//! the tunnel software. None arriving means the path is blocked — a firewall or
//! the network. Some arriving, with nothing delivered, means the path is fine
//! and the two ends disagree about a setting that has to match.

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

/// The iptables match for one transport, used to count arriving packets.
fn transport_match(transport: &str, port: u16) -> String {
    match transport {
        "tcp" => format!("-p tcp --dport {port}"),
        "icmp" => "-p icmp".to_string(),
        "proto58" => "-p 58".to_string(),
        "gre" => "-p 47".to_string(),
        "ipip" => "-p 4".to_string(),
        // udp, quic, and anything unrecognised.
        _ => format!("-p udp --dport {port}"),
    }
}

/// Count how many tunnel packets actually reach the exit host.
///
/// This is the measurement that separates the two very different causes of a
/// silent exit: packets never arriving (a firewall or the network) from packets
/// arriving and being rejected (the two sides disagreeing about the pre-shared
/// key, the cipher, or which addresses to trust).
///
/// It works by inserting a *counting* rule — an iptables rule with no target,
/// which tallies matches and falls through — then provoking traffic and reading
/// the tally. Nothing about the firewall's behaviour changes, and the rule is
/// removed afterwards.
///
/// Returns `None` when the count could not be taken at all.
pub fn wire_arrival(
    relay: &SshClient,
    exit: &SshClient,
    transport: &str,
    port: u16,
    peer_tun_ip: &str,
) -> Option<u64> {
    let rule = transport_match(transport, port);

    // Insert the counter and read its starting value in one go, so a stale rule
    // from an interrupted run cannot be mistaken for this one.
    let insert = format!(
        r#"#!/bin/sh
iptables -w -D INPUT {rule} 2>/dev/null
iptables -w -I INPUT {rule} 2>/dev/null || exit 1
exit 0
"#
    );
    if !exit.run_script(&insert, true).ok()?.ok() {
        return None;
    }

    // Provoke the tunnel into sending: pinging the peer's TUN address makes the
    // relay encapsulate and transmit, whether or not anything comes back.
    let _ = relay.exec_priv(&format!(
        "ping -n -q -c 5 -i 0.3 -W 1 {} >/dev/null 2>&1 || true",
        sh_quote(peer_tun_ip)
    ));

    let read = format!(
        r#"#!/bin/sh
COUNT=$(iptables -w -L INPUT -v -n -x 2>/dev/null | sed -n '3p' | tr -s ' ' | sed 's/^ *//' | cut -d' ' -f1)
iptables -w -D INPUT {rule} 2>/dev/null
echo "arrived=$COUNT"
exit 0
"#
    );
    let out = exit.run_script(&read, true).ok()?;
    out.stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("arrived="))
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Name the most likely cause, given what both sides reported.
///
/// Ordered so the first matching rule is the one worth acting on: there is no
/// point telling someone about reverse-path filtering when the TUN device was
/// never created.
pub fn explain(
    relay: &HostDiagnostics,
    exit: &HostDiagnostics,
    wire_port: u16,
    arrived: Option<u64>,
) -> String {
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
        // Nothing came out of the tunnel at the far end. That has two very
        // different causes, and `arrived` is what tells them apart.
        return match arrived {
            Some(0) => format!(
                "{} sent {relay_tx} packets into the tunnel, and not one of them reached {} — \
                 counted at the network layer, before the tunnel software sees them. The path \
                 itself is blocked. Check the exit server's firewall for inbound traffic on \
                 port {wire_port}, and whether the provider filters this transport.",
                relay.label, exit.label
            ),
            Some(n) => format!(
                "{n} tunnel packets DID reach {}, but it discarded every one rather than \
                 delivering them, so the network path is fine and the two sides disagree about \
                 something they must agree on. In order of likelihood: the pre-shared key \
                 differs, the encryption setting differs, or the exit does not recognise the \
                 address the relay is sending from. The journals below usually name it.",
                exit.label
            ),
            None => format!(
                "{} sent {relay_tx} packets into the tunnel and {} delivered none of them. HTM \
                 could not count arrivals at the exit (iptables was unavailable), so this is \
                 either a blocked path or packets being rejected on arrival.",
                relay.label, exit.label
            ),
        };
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
#[allow(clippy::too_many_arguments)]
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
    transport: &str,
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

    // Only worth provoking traffic when both devices exist; if one is missing
    // there is nothing to count and the cause is already known.
    let arrived = if relay.tun_present && exit.tun_present {
        wire_arrival(relay_client, exit_client, transport, wire_port, exit_tun_ip)
    } else {
        None
    };

    let mut out = format!(
        "\nMost likely cause:\n  {}\n\n{}\n{}",
        explain(&relay, &exit, wire_port, arrived),
        relay.render(),
        exit.render(),
    );
    if let Some(n) = arrived {
        out.push_str(&format!(
            "\n  {n} tunnel packets reached {exit_label} at the network layer during the check.\n"
        ));
    }
    out
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
        let message = explain(&relay, &host("exit", 0, 0), 8472, None);
        assert!(message.contains("TUN device was never created"), "{message}");
    }

    #[test]
    fn unreachable_servers_are_reported_before_packet_counts() {
        let mut relay = host("relay", 0, 0);
        relay.peer_reachable = Some(false);
        let message = explain(&relay, &host("exit", 0, 0), 8472, None);
        assert!(message.contains("no path to each other"), "{message}");
    }

    #[test]
    fn nothing_arriving_blames_the_path() {
        let message = explain(&host("relay", 40, 0), &host("exit", 0, 0), 8472, Some(0));
        assert!(message.contains("not one of them reached"), "{message}");
        assert!(message.contains("firewall"), "{message}");
        assert!(message.contains("8472"), "{message}");
    }

    #[test]
    fn packets_arriving_but_discarded_blames_a_mismatched_setting() {
        // The decisive distinction: the path works, so the fix is a setting
        // rather than a firewall rule.
        let message = explain(&host("relay", 40, 0), &host("exit", 0, 0), 8472, Some(37));
        assert!(message.contains("DID reach"), "{message}");
        assert!(message.contains("pre-shared key"), "{message}");
        assert!(!message.contains("firewall"), "{message}");
    }

    #[test]
    fn an_uncountable_arrival_is_admitted_rather_than_guessed() {
        let message = explain(&host("relay", 40, 0), &host("exit", 0, 0), 8472, None);
        assert!(message.contains("could not count"), "{message}");
    }

    #[test]
    fn transport_matches_cover_the_portless_protocols() {
        assert_eq!(transport_match("udp", 8472), "-p udp --dport 8472");
        assert_eq!(transport_match("tcp", 443), "-p tcp --dport 443");
        assert_eq!(transport_match("icmp", 8472), "-p icmp");
        assert_eq!(transport_match("gre", 8472), "-p 47");
        assert_eq!(transport_match("ipip", 8472), "-p 4");
        assert_eq!(transport_match("proto58", 8472), "-p 58");
        // QUIC rides on UDP.
        assert_eq!(transport_match("quic", 8472), "-p udp --dport 8472");
    }

    #[test]
    fn a_one_way_path_is_distinguished_from_no_path() {
        let message = explain(&host("relay", 40, 0), &host("exit", 12, 40), 8472, None);
        assert!(message.contains("one direction only"), "{message}");
    }

    #[test]
    fn traffic_in_both_directions_points_at_the_handshake() {
        let message = explain(&host("relay", 40, 38), &host("exit", 38, 40), 8472, None);
        assert!(message.contains("handshake"), "{message}");
    }

    #[test]
    fn nothing_leaving_the_relay_points_at_routing() {
        let message = explain(&host("relay", 0, 0), &host("exit", 0, 0), 8472, None);
        assert!(message.contains("routing"), "{message}");
    }
}
