//! CandyTunnel's settings: what they are, which combinations are legal, and
//! how a [`TunnelPlan`] becomes the pair of TOML files the binary reads.
//!
//! The option keys here match CandyTunnel's own config keys one for one, so
//! the generated file can be read against the upstream documentation without
//! translation.

use crate::model::{
    is_ipv4, OptValue, OptionKind, OptionMap, OptionMapExt, OptionSpace, OptionSpec, TunnelPlan,
    TunnelSide,
};

/// Installation paths, matching what upstream's own manager script uses so an
/// existing installation is recognised rather than duplicated.
pub const INSTALL_DIR: &str = "/opt/candytunnel";
pub const CONFIG_DIR: &str = "/etc/candytunnel";
pub const BINARY_PATH: &str = "/opt/candytunnel/candy-tunnel";
pub const VERSION_FILE: &str = "/opt/candytunnel/VERSION";
/// HTM uses its own unit prefix so it never disturbs instances created by
/// upstream's `candy-manager.sh`.
pub const SERVICE_PREFIX: &str = "htm-candytunnel";
pub const UNIT_TEMPLATE: &str = "htm-candytunnel@.service";

// ── Option keys ──────────────────────────────────────────────────────────────

pub mod keys {
    pub const UPLINK: &str = "uplink_protocol";
    pub const DOWNLINK: &str = "downlink_protocol";
    pub const SHUFFLE_PORT: &str = "shuffle_data_port";
    pub const SHUFFLE_MIN: &str = "shuffle_port_min";
    pub const SHUFFLE_MAX: &str = "shuffle_port_max";
    pub const ICMP_ID: &str = "icmp_id";
    pub const RANDOM_ICMP_ID: &str = "random_icmp_id";

    pub const MULTIPLEX: &str = "enable_multiplex";
    pub const MULTIPLEX_FLUSH_MS: &str = "multiplex_flush_ms";
    pub const MULTIPLEX_MAX_PAYLOAD: &str = "multiplex_max_payload";
    pub const FEC: &str = "enable_fec";
    pub const FEC_GROUP: &str = "fec_group_size";

    pub const XOR: &str = "enable_xor";

    pub const PADDING: &str = "packet_padding";
    pub const PADDING_MAX: &str = "packet_padding_max";
    pub const TTL_JITTER: &str = "ttl_jitter";
    pub const FAKE_TLS: &str = "fake_tls_header";
    pub const RANDOM_DSCP: &str = "random_dscp";

    pub const PERF_MODE: &str = "perf_mode";
    pub const AUTO_TUNE: &str = "auto_tune";
    pub const TUNNEL_COUNT: &str = "tunnel_count";
    pub const CHANNEL_CAPACITY: &str = "channel_capacity";
    pub const IO_CHANNEL_CAPACITY: &str = "io_channel_capacity";
    pub const WORKER_THREADS: &str = "runtime_worker_threads";

    pub const QUIC_SERVER_NAME: &str = "quic_server_name";
    pub const QUIC_ALPN: &str = "quic_alpn";
    pub const QUIC_IDLE_MS: &str = "quic_idle_timeout_ms";
    pub const QUIC_MAX_DATA: &str = "quic_max_data";
    pub const QUIC_MAX_STREAM_DATA: &str = "quic_max_stream_data";
    pub const QUIC_MAX_STREAMS: &str = "quic_max_streams_bidi";
}

/// Every transport CandyTunnel implements.
pub const PROTOCOLS: [(&str, &str); 7] = [
    ("udp", "UDP — most compatible, supports multiplexing and FEC"),
    ("icmp", "ICMP echo — blends in with ping traffic"),
    ("proto58", "IP protocol 58 — no L4 header, mimics IPv6 neighbour discovery"),
    ("tcp", "TCP — looks like HTTP/HTTPS, no multiplexing or FEC"),
    ("quic", "QUIC — real TLS 1.3 handshake, both directions must be QUIC"),
    ("ipip", "IP-in-IP (RFC 2003) — looks like a plain IPIP tunnel"),
    ("gre", "GRE (RFC 2784) — looks like a standard GRE VPN"),
];

/// Transports that can carry multiplexed and FEC-protected frames.
///
/// Taken from CandyTunnel's own dispatch in `app.rs`, not just its README.
pub const MUX_CAPABLE: [&str; 5] = ["udp", "icmp", "proto58", "ipip", "gre"];

/// Transports that have a real L4 port, and so can shuffle it.
pub const PORT_BEARING: [&str; 2] = ["udp", "tcp"];

/// Build the full option space.
pub fn option_space() -> OptionSpace {
    let protocol_choices: Vec<(String, String)> = PROTOCOLS
        .iter()
        .map(|(id, help)| (id.to_string(), format!("{id} — {}", help.split(" — ").nth(1).unwrap_or(help))))
        .collect();

    let mut specs = Vec::new();

    // ── Transport ───────────────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::UPLINK.into(),
        label: "Uplink transport".into(),
        help: "How packets travel from the relay to the exit. HTM configures \
               the exit to listen for exactly this."
            .into(),
        group: "Transport".into(),
        kind: OptionKind::Choice {
            choices: protocol_choices.clone(),
        },
        default: OptValue::Choice("udp".into()),
        benchmarkable: true,
        bench_values: PROTOCOLS
            .iter()
            .map(|(id, _)| OptValue::Choice((*id).to_string()))
            .collect(),
    });
    specs.push(OptionSpec {
        key: keys::DOWNLINK.into(),
        label: "Downlink transport".into(),
        help: "How packets travel back from the exit to the relay. Normally the \
               same as the uplink; sweeping only the uplink keeps the two in \
               step. When they differ, HTM mirrors the pair onto the exit so \
               that each side listens for what the other sends."
            .into(),
        group: "Transport".into(),
        kind: OptionKind::Choice {
            choices: protocol_choices,
        },
        default: OptValue::Choice("udp".into()),
        benchmarkable: true,
        bench_values: PROTOCOLS
            .iter()
            .map(|(id, _)| OptValue::Choice((*id).to_string()))
            .collect(),
    });
    specs.push(OptionSpec {
        key: keys::SHUFFLE_PORT.into(),
        label: "Shuffle the data port".into(),
        help: "Pick a different UDP/TCP port for every packet, from a pool both \
               sides derive from the shared key. Defeats simple port blocking; \
               not available with QUIC."
            .into(),
        group: "Transport".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(false),
        benchmarkable: true,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::SHUFFLE_MIN.into(),
        label: "Shuffle range, lowest port".into(),
        help: "Bottom of the port range used when shuffling.".into(),
        group: "Transport".into(),
        kind: OptionKind::Int {
            min: 1,
            max: 65_535,
        },
        default: OptValue::Int(49_152),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::SHUFFLE_MAX.into(),
        label: "Shuffle range, highest port".into(),
        help: "Top of the port range used when shuffling.".into(),
        group: "Transport".into(),
        kind: OptionKind::Int {
            min: 1,
            max: 65_535,
        },
        default: OptValue::Int(65_535),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::ICMP_ID.into(),
        label: "ICMP echo identifier".into(),
        help: "Distinguishes tunnel pings from ordinary ones. Must match on \
               both sides. Only used by the ICMP transport."
            .into(),
        group: "Transport".into(),
        kind: OptionKind::Int {
            min: 1,
            max: 65_535,
        },
        default: OptValue::Int(0x4321),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::RANDOM_ICMP_ID.into(),
        label: "Randomise the ICMP identifier".into(),
        help: "Use a fresh echo identifier per packet instead of a fixed one.".into(),
        group: "Transport".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(false),
        benchmarkable: true,
        bench_values: Vec::new(),
    });

    // ── Multiplexing and FEC ────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::MULTIPLEX.into(),
        label: "Multiplexing".into(),
        help: "Batch several tunnel packets into one wire frame. Raises \
               throughput and lowers packet rate; adds up to the flush delay of \
               latency. UDP, ICMP, proto58, IPIP and GRE only."
            .into(),
        group: "Multiplexing & FEC".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(true),
        benchmarkable: true,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::MULTIPLEX_FLUSH_MS.into(),
        label: "Multiplex flush delay (ms)".into(),
        help: "How long a partly filled batch waits for company. Larger values \
               trade latency for throughput."
            .into(),
        group: "Multiplexing & FEC".into(),
        kind: OptionKind::Int { min: 0, max: 100 },
        default: OptValue::Int(1),
        benchmarkable: true,
        bench_values: vec![OptValue::Int(1), OptValue::Int(5)],
    });
    specs.push(OptionSpec {
        key: keys::MULTIPLEX_MAX_PAYLOAD.into(),
        label: "Multiplex frame payload (bytes)".into(),
        help: "Largest wire frame a batch may produce. Keep it under the path \
               MTU or the frames will fragment."
            .into(),
        group: "Multiplexing & FEC".into(),
        kind: OptionKind::Int {
            min: 256,
            max: 9_000,
        },
        default: OptValue::Int(1_380),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::FEC.into(),
        label: "Forward error correction".into(),
        help: "Send an XOR parity frame per group so a single lost frame can be \
               rebuilt without retransmission. Costs bandwidth; pays off on \
               lossy links."
            .into(),
        group: "Multiplexing & FEC".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(false),
        benchmarkable: true,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::FEC_GROUP.into(),
        label: "FEC group size".into(),
        help: "Data frames per parity frame. Smaller recovers more loss but \
               wastes more bandwidth."
            .into(),
        group: "Multiplexing & FEC".into(),
        kind: OptionKind::Int { min: 2, max: 16 },
        default: OptValue::Int(4),
        benchmarkable: true,
        bench_values: vec![OptValue::Int(2), OptValue::Int(4), OptValue::Int(8)],
    });

    // ── Encryption ──────────────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::XOR.into(),
        label: "ChaCha20 wire encryption".into(),
        help: "Encrypt every frame with ChaCha20, keyed from the pre-shared \
               key. Leave this on unless you are measuring its cost."
            .into(),
        group: "Encryption".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(true),
        benchmarkable: true,
        bench_values: Vec::new(),
    });

    // ── Obfuscation ─────────────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::PADDING.into(),
        label: "Random packet padding".into(),
        help: "Append random bytes so packet lengths vary and cannot be \
               fingerprinted by size alone. Costs a little bandwidth."
            .into(),
        group: "Obfuscation".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(false),
        benchmarkable: true,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::PADDING_MAX.into(),
        label: "Maximum padding (bytes)".into(),
        help: "Upper bound on the random padding added per frame.".into(),
        group: "Obfuscation".into(),
        kind: OptionKind::Int { min: 1, max: 255 },
        default: OptValue::Int(64),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::TTL_JITTER.into(),
        label: "TTL jitter".into(),
        help: "Vary the IPv4 TTL across values real operating systems use, \
               instead of always sending the same one."
            .into(),
        group: "Obfuscation".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(false),
        benchmarkable: true,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::FAKE_TLS.into(),
        label: "Fake TLS record header".into(),
        help: "Prefix TCP payloads with a five-byte TLS application-data header \
               so shallow inspection sees TLS. TCP transport only."
            .into(),
        group: "Obfuscation".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(false),
        benchmarkable: true,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::RANDOM_DSCP.into(),
        label: "Random DSCP marking".into(),
        help: "Set a plausible traffic class instead of leaving it at zero, \
               which is itself unusual."
            .into(),
        group: "Obfuscation".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(false),
        benchmarkable: true,
        bench_values: Vec::new(),
    });

    // ── Performance ─────────────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::PERF_MODE.into(),
        label: "Performance profile".into(),
        help: "Biases internal buffer and batching choices.".into(),
        group: "Performance".into(),
        kind: OptionKind::Choice {
            choices: vec![
                ("balanced".into(), "Balanced".into()),
                ("throughput".into(), "Throughput".into()),
                ("latency".into(), "Latency".into()),
            ],
        },
        default: OptValue::Choice("balanced".into()),
        benchmarkable: true,
        bench_values: vec![
            OptValue::Choice("balanced".into()),
            OptValue::Choice("throughput".into()),
            OptValue::Choice("latency".into()),
        ],
    });
    specs.push(OptionSpec {
        key: keys::AUTO_TUNE.into(),
        label: "Auto-tune".into(),
        help: "Let CandyTunnel size its queues and worker threads from the \
               detected CPU, memory and NIC."
            .into(),
        group: "Performance".into(),
        kind: OptionKind::Toggle,
        default: OptValue::Bool(true),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::TUNNEL_COUNT.into(),
        label: "Parallel tunnels".into(),
        help: "Independent streams run side by side. More can raise throughput \
               on high-latency links, at the cost of memory and CPU."
            .into(),
        group: "Performance".into(),
        kind: OptionKind::Int { min: 1, max: 32 },
        default: OptValue::Int(4),
        benchmarkable: true,
        bench_values: vec![
            OptValue::Int(1),
            OptValue::Int(2),
            OptValue::Int(4),
            OptValue::Int(8),
        ],
    });
    specs.push(OptionSpec {
        key: keys::CHANNEL_CAPACITY.into(),
        label: "Per-tunnel queue depth".into(),
        help: "Packets buffered per tunnel before back pressure applies.".into(),
        group: "Performance".into(),
        kind: OptionKind::Int {
            min: 256,
            max: 262_144,
        },
        default: OptValue::Int(8_192),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::IO_CHANNEL_CAPACITY.into(),
        label: "Raw I/O queue depth".into(),
        help: "Packets buffered in the raw socket and multiplexer queues.".into(),
        group: "Performance".into(),
        kind: OptionKind::Int {
            min: 256,
            max: 262_144,
        },
        default: OptValue::Int(16_384),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::WORKER_THREADS.into(),
        label: "Worker threads".into(),
        help: "Async runtime threads. Zero lets CandyTunnel decide.".into(),
        group: "Performance".into(),
        kind: OptionKind::Int { min: 0, max: 64 },
        default: OptValue::Int(0),
        benchmarkable: false,
        bench_values: Vec::new(),
    });

    // ── QUIC ────────────────────────────────────────────────────────────────
    specs.push(OptionSpec {
        key: keys::QUIC_SERVER_NAME.into(),
        label: "QUIC server name (SNI)".into(),
        help: "Name the client presents in the TLS handshake.".into(),
        group: "QUIC".into(),
        kind: OptionKind::Text,
        default: OptValue::Text("CandyTunnel".into()),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::QUIC_ALPN.into(),
        label: "QUIC ALPN".into(),
        help: "Application protocol label. 'h3' makes the session look like \
               HTTP/3."
            .into(),
        group: "QUIC".into(),
        kind: OptionKind::Text,
        default: OptValue::Text("h3".into()),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::QUIC_IDLE_MS.into(),
        label: "QUIC idle timeout (ms)".into(),
        help: "How long an idle QUIC connection survives.".into(),
        group: "QUIC".into(),
        kind: OptionKind::Int {
            min: 1_000,
            max: 600_000,
        },
        default: OptValue::Int(30_000),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::QUIC_MAX_DATA.into(),
        label: "QUIC connection window (bytes)".into(),
        help: "Connection-wide flow control limit.".into(),
        group: "QUIC".into(),
        kind: OptionKind::Int {
            min: 1_048_576,
            max: 4_294_967_296,
        },
        default: OptValue::Int(134_217_728),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::QUIC_MAX_STREAM_DATA.into(),
        label: "QUIC stream window (bytes)".into(),
        help: "Per-stream flow control limit.".into(),
        group: "QUIC".into(),
        kind: OptionKind::Int {
            min: 65_536,
            max: 1_073_741_824,
        },
        default: OptValue::Int(16_777_216),
        benchmarkable: false,
        bench_values: Vec::new(),
    });
    specs.push(OptionSpec {
        key: keys::QUIC_MAX_STREAMS.into(),
        label: "QUIC concurrent streams".into(),
        help: "Maximum bidirectional streams in flight.".into(),
        group: "QUIC".into(),
        kind: OptionKind::Int { min: 1, max: 4_096 },
        default: OptValue::Int(256),
        benchmarkable: false,
        bench_values: Vec::new(),
    });

    OptionSpace { specs }
}

/// Whether a transport supports multiplexing and FEC.
pub fn supports_mux(protocol: &str) -> bool {
    MUX_CAPABLE.contains(&protocol)
}

/// Whether a transport uses an L4 port that can be shuffled.
pub fn supports_port_shuffle(protocol: &str) -> bool {
    PORT_BEARING.contains(&protocol)
}

/// Fold an option map into its canonical form.
///
/// Settings a transport ignores are forced to their inert value. That is what
/// stops the benchmark matrix from producing pairs of variants that differ
/// only in a field the binary never reads — they would measure identically and
/// waste minutes each.
pub fn normalize(options: &OptionMap) -> OptionMap {
    let space = option_space();
    let mut out = space.normalize(options);

    let uplink = out.str_or(keys::UPLINK, "udp");
    let downlink = out.str_or(keys::DOWNLINK, &uplink);

    // QUIC is all or nothing in CandyTunnel, so a half-QUIC selection is
    // promoted rather than rejected.
    if uplink == "quic" || downlink == "quic" {
        out.insert(keys::UPLINK.into(), OptValue::Choice("quic".into()));
        out.insert(keys::DOWNLINK.into(), OptValue::Choice("quic".into()));
    }

    let uplink = out.str_or(keys::UPLINK, "udp");
    let downlink = out.str_or(keys::DOWNLINK, "udp");

    // Multiplexing and FEC exist only on the frame-batching transports, and
    // only if *both* directions can carry them.
    if !supports_mux(&uplink) || !supports_mux(&downlink) {
        out.insert(keys::MULTIPLEX.into(), OptValue::Bool(false));
        out.insert(keys::FEC.into(), OptValue::Bool(false));
    }
    // The group size is meaningless without FEC.
    if !out.bool_or(keys::FEC, false) {
        out.insert(keys::FEC_GROUP.into(), OptValue::Int(4));
    }
    // The flush delay is meaningless without multiplexing.
    if !out.bool_or(keys::MULTIPLEX, false) {
        out.insert(keys::MULTIPLEX_FLUSH_MS.into(), OptValue::Int(1));
    }

    // Port shuffling needs a real L4 port. Because the pair is mirrored between
    // the two sides, a transport with no ports in *either* direction makes the
    // setting meaningless for the pair as a whole.
    if !supports_port_shuffle(&uplink) || !supports_port_shuffle(&downlink) || uplink == "quic" {
        out.insert(keys::SHUFFLE_PORT.into(), OptValue::Bool(false));
    }

    // The fake TLS header is only written on TCP payloads.
    if uplink != "tcp" && downlink != "tcp" {
        out.insert(keys::FAKE_TLS.into(), OptValue::Bool(false));
    }

    // The echo identifier only exists on ICMP.
    if uplink != "icmp" && downlink != "icmp" {
        out.insert(keys::RANDOM_ICMP_ID.into(), OptValue::Bool(false));
    }

    // Keep the shuffle range sane.
    let lo = out.int_or(keys::SHUFFLE_MIN, 49_152).clamp(1, 65_535);
    let hi = out.int_or(keys::SHUFFLE_MAX, 65_535).clamp(1, 65_535);
    let (lo, hi) = if lo > hi { (hi, lo) } else { (lo, hi) };
    out.insert(keys::SHUFFLE_MIN.into(), OptValue::Int(lo));
    out.insert(keys::SHUFFLE_MAX.into(), OptValue::Int(hi));

    out
}

/// Reject combinations CandyTunnel will refuse to start with.
pub fn validate(options: &OptionMap) -> Result<(), String> {
    let uplink = options.str_or(keys::UPLINK, "udp");
    let downlink = options.str_or(keys::DOWNLINK, "udp");

    let known: Vec<&str> = PROTOCOLS.iter().map(|(id, _)| *id).collect();
    if !known.contains(&uplink.as_str()) {
        return Err(format!("'{uplink}' is not a transport CandyTunnel supports."));
    }
    if !known.contains(&downlink.as_str()) {
        return Err(format!(
            "'{downlink}' is not a transport CandyTunnel supports."
        ));
    }

    if (uplink == "quic") != (downlink == "quic") {
        return Err(
            "QUIC has to be used in both directions. Set the uplink and downlink transports \
             both to QUIC, or neither."
                .into(),
        );
    }
    if uplink == "quic" && options.bool_or(keys::SHUFFLE_PORT, false) {
        return Err("Port shuffling cannot be combined with the QUIC transport.".into());
    }

    let tunnel_count = options.int_or(keys::TUNNEL_COUNT, 4);
    if tunnel_count < 1 {
        return Err("At least one parallel tunnel is required.".into());
    }
    if options.int_or(keys::CHANNEL_CAPACITY, 8_192) < 1 {
        return Err("The per-tunnel queue depth must be at least 1.".into());
    }
    let group = options.int_or(keys::FEC_GROUP, 4);
    if options.bool_or(keys::FEC, false) && group < 2 {
        return Err("The FEC group size must be 2 or more.".into());
    }

    let lo = options.int_or(keys::SHUFFLE_MIN, 49_152);
    let hi = options.int_or(keys::SHUFFLE_MAX, 65_535);
    if options.bool_or(keys::SHUFFLE_PORT, false) && lo > hi {
        return Err("The shuffle port range starts above where it ends.".into());
    }

    Ok(())
}

/// True when this configuration needs a QUIC certificate on the exit host.
pub fn needs_quic_certificate(options: &OptionMap) -> bool {
    options.str_or(keys::UPLINK, "udp") == "quic"
        || options.str_or(keys::DOWNLINK, "udp") == "quic"
}

/// Path of the QUIC certificate for an instance.
pub fn quic_cert_path(instance: &str) -> String {
    format!("{CONFIG_DIR}/{instance}-quic-cert.pem")
}

/// Path of the QUIC private key for an instance.
pub fn quic_key_path(instance: &str) -> String {
    format!("{CONFIG_DIR}/{instance}-quic-key.pem")
}

/// A short label describing what makes a variant distinct.
pub fn describe(options: &OptionMap) -> String {
    let uplink = options.str_or(keys::UPLINK, "udp");
    let downlink = options.str_or(keys::DOWNLINK, "udp");

    let mut parts: Vec<String> = Vec::new();
    if uplink == downlink {
        parts.push(uplink.clone());
    } else {
        parts.push(format!("{uplink}>{downlink}"));
    }

    if options.bool_or(keys::MULTIPLEX, false) {
        let flush = options.int_or(keys::MULTIPLEX_FLUSH_MS, 1);
        parts.push(if flush == 1 {
            "mux".to_string()
        } else {
            format!("mux{flush}ms")
        });
    }
    if options.bool_or(keys::FEC, false) {
        parts.push(format!("fec{}", options.int_or(keys::FEC_GROUP, 4)));
    }
    if options.bool_or(keys::XOR, true) {
        parts.push("xor".into());
    } else {
        parts.push("plain".into());
    }
    if options.bool_or(keys::SHUFFLE_PORT, false) {
        parts.push("shuffle".into());
    }

    let mut obfs: Vec<&str> = Vec::new();
    if options.bool_or(keys::PADDING, false) {
        obfs.push("pad");
    }
    if options.bool_or(keys::TTL_JITTER, false) {
        obfs.push("ttl");
    }
    if options.bool_or(keys::FAKE_TLS, false) {
        obfs.push("tls");
    }
    if options.bool_or(keys::RANDOM_DSCP, false) {
        obfs.push("dscp");
    }
    if !obfs.is_empty() {
        parts.push(obfs.join("+"));
    }

    let perf = options.str_or(keys::PERF_MODE, "balanced");
    if perf != "balanced" {
        parts.push(perf);
    }
    let count = options.int_or(keys::TUNNEL_COUNT, 4);
    if count != 4 {
        parts.push(format!("x{count}"));
    }

    parts.join(" · ")
}

/// A longer, sentence-form explanation of a variant.
pub fn explain(options: &OptionMap) -> String {
    let uplink = options.str_or(keys::UPLINK, "udp");
    let downlink = options.str_or(keys::DOWNLINK, "udp");
    let mut out = if uplink == downlink {
        format!("{uplink} in both directions")
    } else {
        format!("{uplink} outbound, {downlink} inbound")
    };

    out.push_str(&format!(
        ", {} parallel tunnel(s), {} profile",
        options.int_or(keys::TUNNEL_COUNT, 4),
        options.str_or(keys::PERF_MODE, "balanced")
    ));

    if options.bool_or(keys::MULTIPLEX, false) {
        out.push_str(&format!(
            ". Multiplexing on with a {} ms flush",
            options.int_or(keys::MULTIPLEX_FLUSH_MS, 1)
        ));
    } else {
        out.push_str(". Multiplexing off");
    }
    if options.bool_or(keys::FEC, false) {
        out.push_str(&format!(
            ", FEC on with groups of {}",
            options.int_or(keys::FEC_GROUP, 4)
        ));
    }
    out.push_str(if options.bool_or(keys::XOR, true) {
        ". ChaCha20 encryption on"
    } else {
        ". Encryption off"
    });

    let mut obfs: Vec<&str> = Vec::new();
    if options.bool_or(keys::PADDING, false) {
        obfs.push("packet padding");
    }
    if options.bool_or(keys::TTL_JITTER, false) {
        obfs.push("TTL jitter");
    }
    if options.bool_or(keys::FAKE_TLS, false) {
        obfs.push("fake TLS header");
    }
    if options.bool_or(keys::RANDOM_DSCP, false) {
        obfs.push("random DSCP");
    }
    if options.bool_or(keys::SHUFFLE_PORT, false) {
        obfs.push("port shuffling");
    }
    if obfs.is_empty() {
        out.push_str(", no extra obfuscation.");
    } else {
        out.push_str(&format!(", plus {}.", obfs.join(", ")));
    }
    out
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
    // CandyTunnel's values are addresses, identifiers and short labels, so a
    // basic escape of quotes and backslashes is exactly right.
    let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn toml_str_array(values: &[String]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }
    let items: Vec<String> = values.iter().map(|v| toml_string(v)).collect();
    format!("[{}]", items.join(", "))
}

fn toml_int_array(values: &[u16]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }
    let items: Vec<String> = values.iter().map(|v| v.to_string()).collect();
    format!("[{}]", items.join(", "))
}

/// Render one side's `config.toml`.
///
/// The two sides differ in `role`, in which endpoint is "this" and which is
/// "the peer", in the swapped TUN addresses, and in the forwarded ports, which
/// only the relay has.
pub fn render_toml(plan: &TunnelPlan, side: TunnelSide) -> String {
    let options = normalize(&plan.options);
    let me = plan.endpoint(side);
    let peer = plan.endpoint(side.peer());

    let forward_ports = if side == TunnelSide::Client {
        toml_int_array(&plan.forward_ports)
    } else {
        "[]".to_string()
    };

    // Each side rotates through its own half of the address list, and must
    // accept every address the *other* side was given — otherwise a packet
    // sent from a rotated address arrives from somewhere the receiver does not
    // recognise and is dropped.
    let (spoof_pool, allowed_peers) = if plan.spoofing.is_forged() {
        let own = plan.spoofing.pool_for(side);
        let peer_pool = plan.spoofing.pool_for(side.peer());
        (
            // A single address needs no rotation list, and leaving it empty
            // keeps the generated file readable.
            if own.len() > 1 {
                toml_str_array(own)
            } else {
                "[]".to_string()
            },
            toml_str_array(peer_pool),
        )
    } else {
        ("[]".to_string(), "[]".to_string())
    };

    let tun_mtu = plan.tun_mtu.min(plan.mtu);
    let generated = chrono::Utc::now().to_rfc3339();

    let mut s = String::with_capacity(4096);

    s.push_str(&format!(
        "# CandyTunnel configuration generated by HTM (Hiddify Tunnel Manager)\n\
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

    s.push_str(&format!("role = {}\n\n", toml_string(side.as_str())));

    s.push_str("# ── Addressing ────────────────────────────────────────────────\n");
    s.push_str(&format!("real_ip      = {}\n", toml_string(&me.real_ip)));
    s.push_str(&format!(
        "peer_real_ip = {}\n",
        toml_string(peer.peer_target())
    ));
    s.push_str(&format!(
        "spoofed_ip      = {}\n",
        toml_string(&me.spoofed_ip)
    ));
    s.push_str(&format!(
        "peer_spoofed_ip = {}\n",
        toml_string(&peer.spoofed_ip)
    ));
    s.push_str(&format!("spoofed_ip_pool = {spoof_pool}\n"));
    // CandyTunnel trusts the peer's real address and its primary spoofed
    // address implicitly. This list adds the rest of the peer's rotation pool.
    s.push_str(&format!("allowed_peers = {allowed_peers}\n\n"));

    // A node *sends* with `uplink_protocol` and *listens* with
    // `downlink_protocol`: `tunnel.rs` picks the outgoing transport from the
    // uplink, while `app.rs` spawns the receiver from the downlink. For the two
    // ends to meet, each side's uplink has to be the other side's downlink, so
    // the pair is mirrored onto the exit rather than copied to it.
    //
    // The plan states the pair from the relay's point of view: `uplink` means
    // relay to exit. When both name the same transport — which is every variant
    // the default benchmark matrix produces — mirroring is a no-op.
    let plan_uplink = options.str_or(keys::UPLINK, "udp");
    let plan_downlink = options.str_or(keys::DOWNLINK, "udp");
    let (uplink, downlink) = match side {
        TunnelSide::Client => (plan_uplink.as_str(), plan_downlink.as_str()),
        TunnelSide::Server => (plan_downlink.as_str(), plan_uplink.as_str()),
    };

    s.push_str("# ── Transport ─────────────────────────────────────────────────\n");
    s.push_str(&format!("uplink_protocol   = {}\n", toml_string(uplink)));
    s.push_str(&format!("downlink_protocol = {}\n", toml_string(downlink)));
    s.push_str(&format!("data_port         = {}\n", plan.data_port));
    s.push_str(&format!(
        "shuffle_data_port = {}\n",
        toml_bool(options.bool_or(keys::SHUFFLE_PORT, false))
    ));
    s.push_str(&format!(
        "shuffle_port_min  = {}\n",
        options.int_or(keys::SHUFFLE_MIN, 49_152)
    ));
    s.push_str(&format!(
        "shuffle_port_max  = {}\n",
        options.int_or(keys::SHUFFLE_MAX, 65_535)
    ));
    s.push_str(&format!(
        "icmp_id        = {}\n",
        options.int_or(keys::ICMP_ID, 0x4321)
    ));
    s.push_str(&format!(
        "random_icmp_id = {}\n\n",
        toml_bool(options.bool_or(keys::RANDOM_ICMP_ID, false))
    ));

    s.push_str("# ── Multiplexing & FEC ────────────────────────────────────────\n");
    s.push_str(&format!(
        "enable_multiplex      = {}\n",
        toml_bool(options.bool_or(keys::MULTIPLEX, true))
    ));
    s.push_str(&format!(
        "multiplex_flush_ms    = {}\n",
        options.int_or(keys::MULTIPLEX_FLUSH_MS, 1)
    ));
    s.push_str(&format!(
        "multiplex_max_payload = {}\n",
        options
            .int_or(keys::MULTIPLEX_MAX_PAYLOAD, 1_380)
            .min(plan.mtu as i64)
    ));
    s.push_str(&format!(
        "enable_fec            = {}\n",
        toml_bool(options.bool_or(keys::FEC, false))
    ));
    s.push_str(&format!(
        "fec_group_size        = {}\n\n",
        options.int_or(keys::FEC_GROUP, 4)
    ));

    s.push_str("# ── QUIC ──────────────────────────────────────────────────────\n");
    s.push_str(&format!(
        "quic_server_name      = {}\n",
        toml_string(&options.str_or(keys::QUIC_SERVER_NAME, "CandyTunnel"))
    ));
    s.push_str(&format!(
        "quic_cert             = {}\n",
        toml_string(&quic_cert_path(&plan.instance))
    ));
    s.push_str(&format!(
        "quic_key              = {}\n",
        toml_string(&quic_key_path(&plan.instance))
    ));
    s.push_str(&format!(
        "quic_alpn             = {}\n",
        toml_string(&options.str_or(keys::QUIC_ALPN, "h3"))
    ));
    s.push_str(&format!(
        "quic_idle_timeout_ms  = {}\n",
        options.int_or(keys::QUIC_IDLE_MS, 30_000)
    ));
    s.push_str(&format!(
        "quic_max_data         = {}\n",
        options.int_or(keys::QUIC_MAX_DATA, 134_217_728)
    ));
    s.push_str(&format!(
        "quic_max_stream_data  = {}\n",
        options.int_or(keys::QUIC_MAX_STREAM_DATA, 16_777_216)
    ));
    s.push_str(&format!(
        "quic_max_streams_bidi = {}\n\n",
        options.int_or(keys::QUIC_MAX_STREAMS, 256)
    ));

    s.push_str("# ── Security ──────────────────────────────────────────────────\n");
    s.push_str(&format!(
        "pre_shared_key = {}\n",
        toml_string(&plan.pre_shared_key)
    ));
    s.push_str(&format!(
        "enable_xor     = {}\n",
        toml_bool(options.bool_or(keys::XOR, true))
    ));
    s.push_str("# xor_key is left unset so it is derived from pre_shared_key.\n\n");

    s.push_str("# ── Obfuscation (must match on both sides) ────────────────────\n");
    s.push_str(&format!(
        "packet_padding     = {}\n",
        toml_bool(options.bool_or(keys::PADDING, false))
    ));
    s.push_str(&format!(
        "packet_padding_max = {}\n",
        options.int_or(keys::PADDING_MAX, 64)
    ));
    s.push_str(&format!(
        "ttl_jitter         = {}\n",
        toml_bool(options.bool_or(keys::TTL_JITTER, false))
    ));
    s.push_str(&format!(
        "fake_tls_header    = {}\n",
        toml_bool(options.bool_or(keys::FAKE_TLS, false))
    ));
    s.push_str(&format!(
        "random_dscp        = {}\n\n",
        toml_bool(options.bool_or(keys::RANDOM_DSCP, false))
    ));

    s.push_str("# ── TUN interface ─────────────────────────────────────────────\n");
    s.push_str(&format!("tun_name    = {}\n", toml_string(&plan.tun_name)));
    s.push_str(&format!("tun_ip      = {}\n", toml_string(&me.tun_ip)));
    s.push_str(&format!("tun_peer_ip = {}\n", toml_string(&peer.tun_ip)));
    s.push_str(&format!(
        "tun_netmask = {}\n",
        toml_string(&plan.tun_netmask)
    ));
    s.push_str(&format!("tun_mtu     = {tun_mtu}\n"));
    s.push_str(&format!("interface   = {}\n", toml_string(&me.iface)));
    s.push_str(&format!("forward_ports = {forward_ports}\n\n"));

    s.push_str("# ── Performance ───────────────────────────────────────────────\n");
    s.push_str(&format!(
        "perf_mode              = {}\n",
        toml_string(&options.str_or(keys::PERF_MODE, "balanced"))
    ));
    s.push_str(&format!(
        "auto_tune              = {}\n",
        toml_bool(options.bool_or(keys::AUTO_TUNE, true))
    ));
    s.push_str(&format!(
        "tunnel_count           = {}\n",
        options.int_or(keys::TUNNEL_COUNT, 4)
    ));
    s.push_str(&format!("mtu                    = {}\n", plan.mtu));
    s.push_str(&format!(
        "channel_capacity       = {}\n",
        options.int_or(keys::CHANNEL_CAPACITY, 8_192)
    ));
    s.push_str(&format!(
        "io_channel_capacity    = {}\n",
        options.int_or(keys::IO_CHANNEL_CAPACITY, 16_384)
    ));
    s.push_str(&format!(
        "runtime_worker_threads = {}\n\n",
        options.int_or(keys::WORKER_THREADS, 0)
    ));

    s.push_str("# ── Logging ───────────────────────────────────────────────────\n");
    s.push_str(&format!("log_level = {}\n", toml_string(&plan.log_level)));

    s
}

/// The systemd template unit HTM installs.
pub fn unit_template() -> String {
    format!(
        "[Unit]\n\
         Description=HTM CandyTunnel instance %i\n\
         Documentation=https://github.com/AmiRCandy/CandyTunnel\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=60\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=root\n\
         # The unified binary is used deliberately: the separate 'server'\n\
         # binary prompts for a license password on stdin and cannot run\n\
         # unattended under systemd.\n\
         ExecStart={binary} --config {config_dir}/%i.toml\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier={prefix}-%i\n\
         AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN\n\
         CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\n\
         NoNewPrivileges=false\n\
         LimitNOFILE=65536\n\
         LimitMEMLOCK=infinity\n\
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
    use crate::model::{EndpointPlan, SpoofPlan};

    fn plan() -> TunnelPlan {
        TunnelPlan {
            instance: "demo".into(),
            provider_id: "candytunnel".into(),
            client: EndpointPlan {
                side: TunnelSide::Client,
                iface: "eth0".into(),
                real_ip: "192.0.2.10".into(),
                public_ip: "192.0.2.10".into(),
                tun_ip: "10.77.0.2".into(),
                spoofed_ip: "192.0.2.10".into(),
            },
            server: EndpointPlan {
                side: TunnelSide::Server,
                iface: "ens3".into(),
                real_ip: "198.51.100.5".into(),
                public_ip: "198.51.100.5".into(),
                tun_ip: "10.77.0.1".into(),
                spoofed_ip: "198.51.100.5".into(),
            },
            tun_netmask: "255.255.255.252".into(),
            tun_name: "candy0".into(),
            data_port: 8443,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![443, 8443],
            mtu: 1380,
            tun_mtu: 1380,
            log_level: "info".into(),
            spoofing: SpoofPlan::default(),
            options: option_space().defaults(),
        }
    }

    #[test]
    fn both_sides_render_and_agree_on_the_secret() {
        let p = plan();
        let client = render_toml(&p, TunnelSide::Client);
        let server = render_toml(&p, TunnelSide::Server);

        assert!(client.contains("role = \"client\""));
        assert!(server.contains("role = \"server\""));
        assert!(client.contains("pre_shared_key = \"0123456789abcdef0123456789abcdef\""));
        assert!(server.contains("pre_shared_key = \"0123456789abcdef0123456789abcdef\""));
    }

    #[test]
    fn tun_addresses_are_swapped_between_sides() {
        let p = plan();
        let client = render_toml(&p, TunnelSide::Client);
        let server = render_toml(&p, TunnelSide::Server);
        assert!(client.contains("tun_ip      = \"10.77.0.2\""));
        assert!(client.contains("tun_peer_ip = \"10.77.0.1\""));
        assert!(server.contains("tun_ip      = \"10.77.0.1\""));
        assert!(server.contains("tun_peer_ip = \"10.77.0.2\""));
    }

    #[test]
    fn only_the_relay_forwards_ports() {
        let p = plan();
        assert!(render_toml(&p, TunnelSide::Client).contains("forward_ports = [443, 8443]"));
        assert!(render_toml(&p, TunnelSide::Server).contains("forward_ports = []"));
    }

    #[test]
    fn each_side_gets_the_peers_public_address() {
        let p = plan();
        let client = render_toml(&p, TunnelSide::Client);
        assert!(client.contains("peer_real_ip = \"198.51.100.5\""));
        let server = render_toml(&p, TunnelSide::Server);
        assert!(server.contains("peer_real_ip = \"192.0.2.10\""));
    }

    #[test]
    fn half_quic_is_promoted_to_full_quic() {
        let mut opts = option_space().defaults();
        opts.insert(keys::UPLINK.into(), OptValue::Choice("quic".into()));
        let norm = normalize(&opts);
        assert_eq!(norm.str_or(keys::DOWNLINK, ""), "quic");
        assert!(validate(&norm).is_ok());
    }

    #[test]
    fn mux_is_forced_off_on_transports_that_ignore_it() {
        for proto in ["tcp", "quic"] {
            let mut opts = option_space().defaults();
            opts.insert(keys::UPLINK.into(), OptValue::Choice(proto.into()));
            opts.insert(keys::DOWNLINK.into(), OptValue::Choice(proto.into()));
            opts.insert(keys::MULTIPLEX.into(), OptValue::Bool(true));
            opts.insert(keys::FEC.into(), OptValue::Bool(true));
            let norm = normalize(&opts);
            assert!(!norm.bool_or(keys::MULTIPLEX, true), "{proto}");
            assert!(!norm.bool_or(keys::FEC, true), "{proto}");
        }
    }

    #[test]
    fn port_shuffling_is_dropped_where_there_is_no_port() {
        let mut opts = option_space().defaults();
        opts.insert(keys::UPLINK.into(), OptValue::Choice("icmp".into()));
        opts.insert(keys::DOWNLINK.into(), OptValue::Choice("icmp".into()));
        opts.insert(keys::SHUFFLE_PORT.into(), OptValue::Bool(true));
        assert!(!normalize(&opts).bool_or(keys::SHUFFLE_PORT, true));
    }

    #[test]
    fn quic_with_shuffling_is_rejected_before_normalisation() {
        let mut opts = option_space().defaults();
        opts.insert(keys::UPLINK.into(), OptValue::Choice("quic".into()));
        opts.insert(keys::DOWNLINK.into(), OptValue::Choice("quic".into()));
        opts.insert(keys::SHUFFLE_PORT.into(), OptValue::Bool(true));
        assert!(validate(&opts).is_err());
        // Normalisation resolves it rather than leaving it broken.
        assert!(validate(&normalize(&opts)).is_ok());
    }

    #[test]
    fn mismatched_quic_is_rejected() {
        let mut opts = option_space().defaults();
        opts.insert(keys::UPLINK.into(), OptValue::Choice("quic".into()));
        opts.insert(keys::DOWNLINK.into(), OptValue::Choice("udp".into()));
        assert!(validate(&opts).is_err());
    }

    #[test]
    fn labels_are_stable_and_readable() {
        let opts = normalize(&option_space().defaults());
        let label = describe(&opts);
        assert!(label.starts_with("udp"));
        assert!(label.contains("mux"));
        assert!(label.contains("xor"));
    }

    #[test]
    fn an_asymmetric_transport_pair_is_mirrored_on_the_exit() {
        // CandyTunnel sends with `uplink_protocol` and listens with
        // `downlink_protocol`, so each side's uplink has to be the other's
        // downlink. Copying the pair verbatim would leave the relay shouting
        // over ICMP at an exit listening for UDP.
        let mut p = plan();
        p.options
            .insert(keys::UPLINK.into(), OptValue::Choice("icmp".into()));
        p.options
            .insert(keys::DOWNLINK.into(), OptValue::Choice("udp".into()));

        let client = render_toml(&p, TunnelSide::Client);
        let server = render_toml(&p, TunnelSide::Server);

        assert!(client.contains("uplink_protocol   = \"icmp\""));
        assert!(client.contains("downlink_protocol = \"udp\""));
        // Mirrored, not copied.
        assert!(server.contains("uplink_protocol   = \"udp\""));
        assert!(server.contains("downlink_protocol = \"icmp\""));
    }

    #[test]
    fn a_symmetric_transport_pair_is_unchanged_by_mirroring() {
        // Every variant the default matrix produces is symmetric, so mirroring
        // has to be a no-op for them.
        let mut p = plan();
        p.options
            .insert(keys::UPLINK.into(), OptValue::Choice("gre".into()));
        p.options
            .insert(keys::DOWNLINK.into(), OptValue::Choice("gre".into()));

        for side in [TunnelSide::Client, TunnelSide::Server] {
            let rendered = render_toml(&p, side);
            assert!(rendered.contains("uplink_protocol   = \"gre\""));
            assert!(rendered.contains("downlink_protocol = \"gre\""));
        }
    }

    #[test]
    fn original_mode_uses_each_servers_own_address() {
        let p = plan();
        assert!(!p.spoofing.is_forged());
        let client = render_toml(&p, TunnelSide::Client);
        let server = render_toml(&p, TunnelSide::Server);

        assert!(client.contains("spoofed_ip      = \"192.0.2.10\""));
        assert!(client.contains("peer_spoofed_ip = \"198.51.100.5\""));
        assert!(server.contains("spoofed_ip      = \"198.51.100.5\""));
        assert!(server.contains("peer_spoofed_ip = \"192.0.2.10\""));
        // Nothing to rotate and nothing extra to trust.
        assert!(client.contains("spoofed_ip_pool = []"));
        assert!(client.contains("allowed_peers = []"));
    }

    #[test]
    fn forged_mode_gives_each_side_its_own_addresses() {
        use crate::model::SpoofPlan;

        let mut p = plan();
        p.spoofing = SpoofPlan::from_list(&[
            "8.8.8.8".to_string(),
            "1.1.1.1".to_string(),
            "9.9.9.9".to_string(),
            "208.67.222.222".to_string(),
        ]);
        // build_plan normally does this; do it by hand for the unit test.
        p.client.spoofed_ip = p.spoofing.client_pool[0].clone();
        p.server.spoofed_ip = p.spoofing.server_pool[0].clone();
        assert!(validate_plan(&p).is_ok());

        let client = render_toml(&p, TunnelSide::Client);
        let server = render_toml(&p, TunnelSide::Server);

        // Alternating split: relay gets entries 0 and 2, exit gets 1 and 3.
        assert!(client.contains("spoofed_ip      = \"8.8.8.8\""));
        assert!(client.contains("peer_spoofed_ip = \"1.1.1.1\""));
        assert!(client.contains(r#"spoofed_ip_pool = ["8.8.8.8", "9.9.9.9"]"#));
        // The relay must accept everything the exit might send from.
        assert!(client.contains(r#"allowed_peers = ["1.1.1.1", "208.67.222.222"]"#));

        assert!(server.contains("spoofed_ip      = \"1.1.1.1\""));
        assert!(server.contains("peer_spoofed_ip = \"8.8.8.8\""));
        assert!(server.contains(r#"allowed_peers = ["8.8.8.8", "9.9.9.9"]"#));
    }

    #[test]
    fn a_single_forged_address_per_side_needs_no_rotation_list() {
        use crate::model::SpoofPlan;

        let mut p = plan();
        p.spoofing = SpoofPlan::from_list(&["8.8.8.8".to_string(), "1.1.1.1".to_string()]);
        p.client.spoofed_ip = "8.8.8.8".into();
        p.server.spoofed_ip = "1.1.1.1".into();

        let client = render_toml(&p, TunnelSide::Client);
        assert!(client.contains("spoofed_ip_pool = []"));
        assert!(client.contains(r#"allowed_peers = ["1.1.1.1"]"#));
    }

    #[test]
    fn forged_mode_rejects_one_address_and_duplicates() {
        use crate::model::{SpoofMode, SpoofPlan};

        // One address leaves a side with nothing to send from.
        assert!(SpoofPlan::from_list(&["8.8.8.8".to_string()])
            .validate()
            .is_err());

        // The same address on both sides makes the two indistinguishable.
        let clashing = SpoofPlan {
            mode: SpoofMode::Forged,
            client_pool: vec!["8.8.8.8".to_string()],
            server_pool: vec!["8.8.8.8".to_string()],
        };
        assert!(clashing.validate().is_err());

        assert!(SpoofPlan::from_list(&["8.8.8.8".to_string(), "not-an-ip".to_string()])
            .validate()
            .is_err());
    }

    #[test]
    fn strings_are_escaped_in_toml() {
        assert_eq!(toml_string(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn the_unit_uses_the_unified_binary() {
        let unit = unit_template();
        assert!(unit.contains("/opt/candytunnel/candy-tunnel --config"));
        assert!(!unit.contains("/opt/candytunnel/server"));
        assert!(unit.contains("CAP_NET_RAW"));
    }

    #[test]
    fn plans_are_validated() {
        let mut p = plan();
        assert!(validate_plan(&p).is_ok());
        p.tun_name = "a-very-long-interface-name".into();
        assert!(validate_plan(&p).is_err());
    }
}
