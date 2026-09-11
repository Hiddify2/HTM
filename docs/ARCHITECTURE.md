# Architecture

HTM is two crates. `htm-core` does everything; `htm-gui` draws it.

```
crates/
├── htm-core/          no UI, no egui, fully testable
│   ├── model/         plain data: servers, plans, benchmark results, options
│   ├── ssh/           dial (+proxy) → host key → authenticated session
│   ├── remote/        facts, packages, systemd, network measurement
│   ├── provider/      the TunnelProvider trait + CandyTunnel
│   ├── orchestrator/  the operations the app performs, incl. the bench engine
│   ├── jobs.rs        background work and how it reports back
│   ├── store.rs       state.json
│   ├── crypto.rs      the encrypted credential vault
│   └── util.rs        shell quoting, formatting, parsers
└── htm-gui/
    ├── app.rs         state, the job pump, action dispatch
    ├── state.rs       UI-only state
    ├── theme.rs       palette and type scale
    ├── widgets.rs     reusable pieces
    └── views/         one module per tab, plus the shell, wizard and modals
```

The dependency direction is strictly one way. `htm-core` does not know egui
exists, and `htm-gui` contains no SSH, no shell commands and no measurement
logic.

---

## Threading

Every remote operation blocks: an SSH round trip, an `apt-get install`, a
ten-second throughput test. None of it can run on the UI thread.

`jobs::spawn` starts a worker thread and hands back a `JobHandle`. The worker
talks back through an `mpsc` channel of `JobEvent`s — log lines, stage names,
progress, typed payloads, and a final outcome. The UI drains every handle once
per frame in `HtmApp::pump_jobs` and asks for a repaint while anything is in
flight.

Cancellation is cooperative. Each worker holds an `Arc<AtomicBool>` and checks
it between steps and inside its read loops, so *Cancel* takes effect in about a
second rather than at the next natural boundary. The benchmark engine treats
cleanup as unconditional: a cancelled run still tears its measurement instance
off both servers.

`ssh2::Session` is `Send + Sync` and internally mutex-guarded, so a session can
be shared, but calls serialise — a blocking read on one channel stalls every
other channel on that session. Anything long-running therefore gets its own
connection.

---

## Actions, not method calls

Views never do work. They push an `Action` onto `app.actions`, which is drained
after the frame is drawn:

```rust
if widgets::primary_button(ui, &palette, "Install on both servers", ready).clicked() {
    app.push(Action::InstallProvider);
}
```

Two reasons. First, it keeps each view a pure function of state plus a list of
intents, which makes them easy to read. Second, it avoids the borrow conflicts
that come from mutating the app while drawing part of it — a real and constant
problem in immediate-mode UI.

---

## The SSH layer

Three steps, each in its own module:

**`ssh/dial.rs`** opens the TCP connection. SOCKS5 (RFC 1928/1929), SOCKS4a and
HTTP `CONNECT` are implemented directly rather than pulled from a crate, so HTM
controls the timeouts, the error messages and the exact bytes on the wire. The
stream handed to libssh2 is left blocking with no socket-level timeout, because
libssh2 drives its own deadlines and a socket timeout underneath it surfaces as
a spurious error.

**`ssh/hostkey.rs`** is trust-on-first-use with an explicit decision. An unknown
key returns `Error::HostKeyUnknown`, which the GUI turns into a dialog; the
retry then carries `HostKeyPolicy::Trust { sha256 }`. A key that *changed* is
never accepted by any policy except an explicit approval of the new
fingerprint.

**`ssh/session.rs`** authenticates and runs commands. Three decisions worth
knowing:

- **Files go over an exec channel, not SFTP.** `cat > file` works wherever a
  shell works, including hosts that do not enable the SFTP subsystem, and it is
  binary safe.
- **Privilege escalation is decided once,** at connect time, by probing `id -u`
  and then `sudo -n true`. No later command has to guess.
- **Non-trivial commands are uploaded as scripts.** An `awk` program full of
  `$1` and braces survives being written to a file; it does not survive being
  interpolated into a command line. Every shell value that came from user input
  still goes through `util::sh_quote`.

---

## Providers

A provider is the only thing that knows what a particular tunnel implementation
wants. It publishes:

- an **`OptionSpace`** — a list of settings, each with a label, help text, a
  widget kind, a default, and whether the benchmark should sweep it;
- **`expand_variants`**, which turns a matrix selection into the configurations
  actually worth measuring;
- **`render`** and **`deploy`**, which turn a `TunnelPlan` into files on a host;
- **`readiness`**, which says what a working tunnel looks like in the journal.

Settings travel everywhere else as `OptionMap`, a `BTreeMap<String, OptValue>`.
The GUI draws controls from the `OptionSpace`; the benchmark engine crosses
values it never interprets; the store serialises them without knowing what they
mean. That is what makes a second provider a self-contained addition.

### Normalisation

`expand_variants` folds each combination into canonical form before
de-duplicating. Multiplexing is meaningless on TCP, the fake TLS header is only
written on TCP payloads, port shuffling needs a port, and QUIC is all-or-nothing
— so those settings are forced to their inert values for transports that ignore
them.

Without this, "all seven transports × multiplexing on and off" would be fourteen
measurements, two of which measure the same thing twice. With it, it is twelve.
At roughly fifty seconds each, that is two minutes of the user's time saved by
a few lines of code, and it means the results table never shows two rows that
are secretly identical.

---

## The benchmark engine

Strictly sequential. Measuring two configurations at once would have them
compete for the same link and produce numbers that mean nothing.

For each variant:

1. Render and upload both configurations under a dedicated instance name on a
   reserved TUN slot, so a benchmark can never disturb a deployed tunnel.
2. Start the exit unit, then the relay unit.
3. Wait until the link actually carries traffic.
4. Let it settle, then measure: ICMP, TCP up, TCP down, UDP.
5. Stop both units and move on.

After the run, remove the measurement instance from both hosts — including
after a cancellation or a failure.

### Readiness

A unit being `active` is not enough. CandyTunnel reports active while its
handshake is still in progress, and a misconfigured pair can stay active forever
without passing a packet. The authoritative test is an ICMP echo across the TUN
link. While waiting, HTM also watches both units for the failed state and scans
the relay's journal for the provider's fatal markers, so a hopeless
configuration fails in seconds instead of burning the whole timeout.

### Which number counts

The **receiver's** byte count, always — that is what crossed the tunnel.

iperf3 reports both directions in its client JSON, so its client output is
authoritative on its own. The bundled probe only knows its own side, so for an
uplink test HTM reads the result file the exit node wrote. For UDP, only the
receiver can know how much arrived and how evenly, so loss and jitter always
come from the server side.

### Scoring

Each dimension is min-max normalised across the completed results, then combined
with user-adjustable weights. Relative, not absolute: with a single completed
result every dimension normalises to 1.0 and the score is 100, which is correct,
because there is nothing to compare it against. Changing the weights re-scores
results already on screen.

---

## The measurement probe

`remote/probe.py` is a dependency-free stand-in for iperf3, embedded with
`include_str!` and uploaded when iperf3 is unavailable. Python 3.6 syntax,
standard library only.

It exists because a benchmark that cannot run is worse than one that is slightly
less precise, and "install iperf3 first" is exactly the kind of obstacle this
application is supposed to remove. The server side runs one measurement, writes
JSON and exits; the client prints JSON to stdout. TCP streams carry a 16-byte
header saying which direction is being measured; UDP datagrams carry a sequence
number and a monotonic timestamp, from which the receiver computes RFC 3550
interarrival jitter and loss.

---

## Error handling

`Error` is a single enum with variants the UI reacts to differently.
`HostKeyUnknown` and `HostKeyMismatch` drive dialogs rather than error
messages. `Cancelled` becomes a neutral outcome, not a failure. `Remote`
carries the command, the exit status and both output streams, so a failure can
say what actually happened rather than "command failed".

Long failures open a dialog the user can read and copy from; short ones get a
toast. A benchmark variant that fails records the tail of the relay's journal
alongside the reason, because that is where the answer usually is.

---

## Testing

`cargo test` covers the parts where being wrong is silent: shell quoting, port
list parsing, `ping` output from both iputils and busybox, iperf3 JSON in both
its shapes, TUN slot allocation, benchmark scoring, matrix expansion and
de-duplication, config rendering for both sides of a plan, vault round-trips
including tamper detection, and `systemctl show` parsing.

What is not covered by unit tests is anything that needs two real servers.
Those paths are instead written to fail loudly and specifically.
