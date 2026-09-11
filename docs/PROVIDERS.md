# Adding a tunnel implementation

HTM ships with CandyTunnel, but nothing outside
`crates/htm-core/src/provider/candytunnel/` names it. Adding a second
implementation means writing one module and adding one line to the registry.
The GUI, the benchmark engine, the deployment flow and the systemd controls all
work off the trait and need no changes.

---

## The three pieces

### 1. A module implementing `TunnelProvider`

```
crates/htm-core/src/provider/yourtunnel/
├── mod.rs        the trait impl
├── config.rs     the option space, validation, and file rendering
├── install.rs    getting the software onto a host
└── profiles.rs   turning a matrix selection into variants
```

That split is a suggestion, not a requirement — it is simply where CandyTunnel's
roughly two thousand lines naturally fell apart.

### 2. One line in the registry

```rust
// provider/registry.rs
pub fn all() -> Vec<ProviderRef> {
    vec![
        Arc::new(CandyTunnelProvider::new()) as ProviderRef,
        Arc::new(YourTunnelProvider::new()) as ProviderRef,   // <- this
    ]
}
```

### 3. Nothing else

The provider combo box, the matrix builder, the results table, the tunnel
wizard and the tunnel cards are all written against the trait.

---

## Declaring your settings

This is the part that makes everything else work. Each setting gets an
`OptionSpec`:

```rust
OptionSpec {
    key: "enable_multiplex".into(),
    label: "Multiplexing".into(),
    help: "Batch several tunnel packets into one wire frame. Raises throughput \
           and lowers packet rate; adds up to the flush delay of latency."
        .into(),
    group: "Multiplexing & FEC".into(),
    kind: OptionKind::Toggle,
    default: OptValue::Bool(true),
    benchmarkable: true,
    bench_values: Vec::new(),   // empty: both booleans
}
```

- **`group`** becomes a heading in both the matrix builder and the settings
  editor, in first-appearance order.
- **`help`** becomes the hover text. Write the trade-off, not a restatement of
  the label. "Enables multiplexing" tells the reader nothing they could not
  guess; the text above tells them when to turn it on.
- **`benchmarkable`** decides whether the matrix builder offers the setting as a
  dimension to sweep. Mark the ones that change the answer; leave buffer sizes
  and log levels off.
- **`bench_values`** narrows what a sweep tries. An `Int { min: 1, max: 32 }`
  would otherwise sweep only its two endpoints, which is rarely what you want —
  give it `[1, 2, 4, 8]` instead.

Settings travel through the rest of HTM as an `OptionMap`, a
`BTreeMap<String, OptValue>`. Read them with `OptionMapExt`:

```rust
let protocol = options.str_or("uplink_protocol", "udp");
let tunnels  = options.int_or("tunnel_count", 4);
let mux      = options.bool_or("enable_multiplex", true);
```

Those helpers fall back to a default rather than erroring, so you can add,
rename or remove a setting later without breaking tunnels the user already
saved.

---

## Normalising combinations

Implement a `normalize` function and run every option map through it before you
render, validate or compare. Force the inert value for any setting the current
configuration ignores:

```rust
// Multiplexing only exists on the frame-batching transports.
if !supports_mux(&uplink) || !supports_mux(&downlink) {
    out.insert("enable_multiplex".into(), OptValue::Bool(false));
    out.insert("enable_fec".into(), OptValue::Bool(false));
}
// The group size is meaningless without FEC.
if !out.bool_or("enable_fec", false) {
    out.insert("fec_group_size".into(), OptValue::Int(4));
}
```

Then de-duplicate by hashing the normalised map. Two selections the binary would
treat identically collapse into one measurement instead of costing a minute
each, and the results table never shows two rows that are secretly the same.

---

## Rendering and deploying

`render` turns a `TunnelPlan` into files, without touching the network — the
wizard's preview pane calls it, so it must be pure:

```rust
fn render(&self, plan: &TunnelPlan, side: TunnelSide) -> Result<RenderedSide> {
    Ok(RenderedSide {
        side,
        files: vec![RemoteFile {
            path: self.config_path(&plan.instance),
            content: render_config(plan, side),
            mode: "0600".into(),   // it holds the shared key
            description: "configuration".into(),
        }],
        service: self.service_name(&plan.instance),
    })
}
```

`deploy` writes them. Do any host-side preparation there — CandyTunnel generates
a self-signed certificate on the exit node when the QUIC transport is selected.

The plan gives you both endpoints. `real_ip` is the address on the interface,
which is what a raw socket binds to; `peer_target()` is the address the peer
must send to, which differs when a host is behind NAT. TUN addresses come from
the plan already allocated and are swapped per side.

---

## Readiness

Tell the orchestrator what a working tunnel looks like:

```rust
fn readiness(&self) -> Readiness {
    Readiness {
        ready_markers: vec!["tunnels established".into()],
        fatal_markers: vec![
            "handshake timed out".into(),
            "Address already in use".into(),
            "Operation not permitted".into(),
        ],
    }
}
```

The authoritative readiness test is an ICMP echo across the TUN link, which HTM
does for you. The fatal markers are what let a hopeless configuration fail in
seconds instead of burning the full timeout — during a benchmark, that is the
difference between a run that takes twenty minutes and one that takes two hours.

---

## Symmetric settings

List the settings both ends must agree on:

```rust
fn symmetric_option_keys(&self) -> Vec<&'static str> {
    vec!["uplink_protocol", "downlink_protocol", "enable_xor", "packet_padding"]
}
```

HTM renders both sides from one plan, so they cannot drift apart on their own.
This list is what lets the UI explain *why* a setting is not editable per side.

---

## A checklist

- [ ] `id()` is stable — it is written into `state.json`.
- [ ] `default_options()` returns something already normalised, so
      `normalize(defaults) == defaults`.
- [ ] Every `benchmarkable` spec returns a non-empty `sweep_values()`.
- [ ] `validate_options` rejects combinations the software refuses to start
      with, and says what to do about it rather than just what is wrong.
- [ ] Config files holding a shared secret are mode `0600`.
- [ ] `service_name` is namespaced, so HTM does not collide with units the
      upstream project's own installer created.
- [ ] `remove_instance` deletes everything `deploy` created, including anything
      generated on the host.
- [ ] Unit tests cover rendering both sides, normalisation, and matrix
      expansion. Those are the parts where being wrong is silent.

CandyTunnel's implementation is the worked example for all of it.
