# Using HTM

A walk through a first run, start to finish.

---

## Before you start

You need two Linux servers with root or sudo access, in different places — the
whole point is to route traffic through the second one. A typical arrangement
is a relay somewhere with good local connectivity and an exit node somewhere
unfiltered.

Have ready, for each:

- its address and SSH port
- a username, and a password or a private key file
- a proxy, if your own connection to that host is filtered

---

## Step 1 — Servers

Two cards, side by side. The left one is the **exit** server; the right one is
the **relay**.

> The exit is on the left because everything happens in that order: it is
> brought up first, torn down last, and the relay's handshake needs something
> to reach.

Fill both in and press **Test both connections**.

### Trusting the host key

The first time HTM connects to a server it shows the SSH host key fingerprint
and asks. Check it against something you did not get through the same
connection — your provider's control panel, or by running this on the server:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Once approved, the key is pinned. If it ever changes, HTM stops and says so
loudly. A changed key means the server was rebuilt — or that something is
sitting between you and it.

### Reading the result

A successful test fills in a panel of facts, plus two kinds of message:

- **Red** blocks deployment. No root, no systemd, no TUN device, no supported
  package manager.
- **Amber** is worth knowing but not fatal. The most common is NAT: the
  interface holds one address while the internet sees another. HTM handles it
  — it writes the interface address where the raw socket binds and the public
  address where the peer has to dial — but it says so, because it changes what
  you should expect.

If a detected value is wrong, open **Advanced** and override the interface or
either address. What you type there goes straight into the tunnel
configuration.

---

## Step 2 — Install

Pick the tunnel software (CandyTunnel is the only one built in so far), choose
an install method, and press **Install on both servers**.

**Automatic** is right almost always: the published binary on x86_64, a source
build anywhere else. A source build needs Rust, CMake and Go, and takes ten
minutes or more on a small instance — HTM warns you before starting one.

Leave *Also install iperf3 and python3* ticked unless you have a reason not to.
If iperf3 cannot be installed, HTM falls back to a measurement script it uploads
itself, which needs only python3.

Watch progress in the bar at the bottom of the window. The full output of every
command goes to the **Logs** tab.

---

## Step 3 — Benchmark

### Just press Run

The default matrix — *Transports × multiplexing* — measures every transport
with frame multiplexing both on and off. Twelve configurations, about ten
minutes. That is usually enough to find out which protocols your route allows
at all, which is the first thing you want to know.

The estimate above the button is honest: it accounts for startup, the settle
time, every test you have enabled, and repeats.

### While it runs

Rows fill in as each configuration finishes. You can sort by any column at any
point, and you can stop the run — HTM still removes the measurement instance
from both servers before it exits.

### Reading the table

| Column | Meaning |
|--------|---------|
| **Score** | 0–100, relative to the other completed rows, using your weights |
| **Up** | TCP throughput, relay → exit |
| **Down** | TCP throughput, exit → relay |
| **Latency** | Mean ICMP round trip across the tunnel |
| **Jitter** | UDP interarrival jitter, or ping's mean deviation when UDP was not measured |
| **Loss** | The worse of the ICMP and UDP figures |
| **Startup** | How long the tunnel took to carry traffic — a decent proxy for reliability |

Click a row for the details: every measurement, every setting, and — if it
failed — the reason plus the tail of the relay's journal.

### Tuning what "best" means

Open **Measurement settings** and use the weight sliders, or one of the three
presets. *Favour latency* is right for interactive traffic and gaming; *favour
throughput* for bulk transfer. Changing the weights re-scores the table
immediately, without re-measuring anything.

### Going deeper

Once you know which transport works, run **Parallelism & profile** to tune it,
or **Error correction** if the link shows loss. The **Matrix** section lets you
cross any settings you like; HTM folds away combinations the software would
ignore, so the count shown is what will actually be measured.

---

## Step 4 — Create the tunnel

Press **Create a tunnel with this** on the row you want.

### The fields

**Name** — used for the systemd unit and the config file names.

**Forward ports** — the ports on the **relay** that get pushed through the
tunnel. `443, 8443, 2052-2060`. These are the ports your users connect to.

> Leaving this empty forwards *every* TCP and UDP port. It works, but it also
> captures the relay's own traffic — including, potentially, your SSH session
> to it. Name the ports you actually serve.

**Wire port** — the port the tunnel itself uses between the two servers. Change
it only if something else is already using it.

**Source addresses** — the two modes, covered in the
[README](../README.md#the-two-source-address-modes). The short version: use the
servers' own addresses unless you have confirmed both providers allow forged
ones.

**Shared key** — generated for you, written into both configurations.
Regenerate it if you like; there is no reason to type one by hand.

### Before you commit

**Preview the configuration** renders both files exactly as they will be
written. Worth a look the first time, if only to see what HTM is doing on your
behalf.

Then **Create and start**. HTM writes both files, installs the units, starts the
exit and then the relay, and waits until the link answers. If it does not come
up, the error carries both journals.

---

## Step 5 — Running it

The **Tunnels** tab shows each tunnel with live throughput, a sparkline, both
units' status, interface counters and round-trip time. It refreshes on its own
every fifteen seconds; change or disable that in Settings.

- **Start / Restart / Stop** — in the right order, automatically
- **Enable at boot** — so it survives a reboot
- **More** — the full configuration, and a button to view either rendered file
- **Remove** — stops it, deletes the units and configs from both servers, and
  forgets it here

### Watching logs

The **Logs** tab has HTM's own activity on top and either server's journal
below. Pick a tunnel, pick a side, tick **Follow**. HTM reads with a journal
cursor, so each poll fetches only what is new.

Lines are coloured by what they say — errors red, warnings amber, "established"
and "ready" green — which makes a failing tunnel obvious without reading every
line.

---

## Settings worth knowing

**Status refresh** — how often the Tunnels tab polls. Set it to 0 if you would
rather refresh by hand.

**Ask before stopping or removing** — on by default. Turn it off once the
novelty wears off.

**Master password** — set one. Until you do, your SSH passwords are protected
only by a key file that lives next to them, and the Settings tab says so in
those words.

---

## Answers to things that go wrong

See the [Troubleshooting section of the README](../README.md#troubleshooting).

The general rule: HTM's own log says what it tried, and the server journal says
what happened. Both are one click away in the Logs tab, which is the point of
having them there.
