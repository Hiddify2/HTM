//! Installing the forwarder each Hiddify Relay method needs.
//!
//! The method is chosen per tunnel, not at install time, so the provider's
//! install step only lays down the common relay prerequisites; [`deploy`] then
//! calls [`ensure_method_installed`] to put the specific forwarder in place for
//! whichever method the user picked. That keeps "Install" light and means a
//! method the user switches to later is installed on demand.
//!
//! [`deploy`]: super::HiddifyRelayProvider

use std::time::Duration;

use super::config::{RelayMethod, BASE_DIR, GOST_BIN, SERVICE_PREFIX, WSTUNNEL_BIN, XRAY_BIN};
use crate::error::{Error, Result};
use crate::provider::{HostCtx, InstallMethod, InstalledVersion};
use crate::remote::pkg;
use crate::util::sh_quote;

/// wstunnel version whose CLI matches the Builder's service templates
/// (`-L host:port:...` and `--server ws://...`). x86_64 Linux only.
const WSTUNNEL_URL: &str =
    "https://github.com/erebe/wstunnel/releases/download/v5.0/wstunnel-linux-x64";

/// Lay down the common relay prerequisites. The per-method forwarder is
/// installed at deploy time, when the chosen method is known.
pub fn install(ctx: &HostCtx<'_>, _method: InstallMethod) -> Result<InstalledVersion> {
    ctx.info("Preparing relay prerequisites.");
    ctx.client
        .exec_priv_ok(&format!("mkdir -p {}", sh_quote(BASE_DIR)))?;

    let _ = pkg::install(
        ctx.client,
        ctx.facts.package_manager,
        &[
            pkg::logical::CURL,
            pkg::logical::CA_CERTS,
            pkg::logical::IPROUTE2,
        ],
        ctx.scope,
        ctx.reporter,
        ctx.cancel,
    )?;

    ctx.success("Relay prerequisites ready.");
    Ok(InstalledVersion {
        version: "ready".to_string(),
        binary_path: BASE_DIR.to_string(),
        origin: "relay host prepared".to_string(),
    })
}

/// Nothing persistent identifies a relay install at the provider level, so the
/// install step always runs; the method tooling is detected per method at
/// deploy time.
pub fn detect(_ctx: &HostCtx<'_>) -> Result<Option<InstalledVersion>> {
    Ok(None)
}

/// Make sure the forwarder for `method` is present on this host.
///
/// Called from `deploy` on the side being configured: the relay for every
/// method, and additionally the upstream for `wst`, which needs the wstunnel
/// binary to run its server.
pub fn ensure_method_installed(ctx: &HostCtx<'_>, method: RelayMethod) -> Result<()> {
    match method {
        RelayMethod::Iptables => ensure_package(ctx, &[pkg::logical::IPTABLES]),
        RelayMethod::Socat => ensure_package(ctx, &[pkg::logical::SOCAT]),
        RelayMethod::Haproxy => ensure_package(ctx, &[pkg::logical::HAPROXY]),
        RelayMethod::Gost => ensure_gost(ctx),
        RelayMethod::Dokodemo => ensure_xray(ctx),
        RelayMethod::Wst => ensure_wstunnel(ctx),
    }
}

fn ensure_package(ctx: &HostCtx<'_>, logical: &[&str]) -> Result<()> {
    let report = pkg::install(
        ctx.client,
        ctx.facts.package_manager,
        logical,
        ctx.scope,
        ctx.reporter,
        ctx.cancel,
    )?;
    if !report.is_ok() {
        let names: Vec<String> = report.failed.iter().map(|(p, _)| p.clone()).collect();
        return Err(Error::Provider {
            provider: "Hiddify Relay".to_string(),
            detail: format!("could not install: {}.", names.join(", ")),
        });
    }
    Ok(())
}

fn ensure_gost(ctx: &HostCtx<'_>) -> Result<()> {
    if ctx.client.path_exists(GOST_BIN)? {
        ctx.debug("gost already installed.");
        return Ok(());
    }
    ctx.info("Installing gost.");
    let script = format!(
        r#"#!/bin/sh
set -e
if ! command -v curl >/dev/null 2>&1; then
  echo "HTM-ERROR: curl is required to install gost."; exit 3
fi
curl -fsSL https://github.com/go-gost/gost/raw/master/install.sh | bash -s -- --install
[ -x {bin} ] || command -v gost >/dev/null 2>&1 || {{ echo "HTM-ERROR: gost did not install."; exit 4; }}
echo "gost installed."
"#,
        bin = GOST_BIN,
    );
    run(ctx, &script, "gost")
}

fn ensure_xray(ctx: &HostCtx<'_>) -> Result<()> {
    if ctx.client.path_exists(XRAY_BIN)? {
        ctx.debug("Xray already installed.");
        return Ok(());
    }
    ctx.info("Installing Xray.");
    // The official installer drops the binary at /usr/local/bin/xray. HTM runs
    // its own per-instance unit, so the installer's own service is irrelevant.
    let script = r#"#!/bin/sh
set -e
if ! command -v curl >/dev/null 2>&1; then
  echo "HTM-ERROR: curl is required to install Xray."; exit 3
fi
bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1 || true
if [ ! -x /usr/local/bin/xray ]; then echo "HTM-ERROR: Xray did not install."; exit 4; fi
echo "Xray installed."
"#;
    run(ctx, script, "Xray")
}

fn ensure_wstunnel(ctx: &HostCtx<'_>) -> Result<()> {
    if ctx.client.path_exists(WSTUNNEL_BIN)? {
        ctx.debug("wstunnel already installed.");
        return Ok(());
    }
    if ctx.facts.arch != "x86_64" {
        return Err(Error::Unsupported {
            detail: format!(
                "The WST method installs the x86_64 wstunnel binary, but {} is {}. Pick another \
                 relay method on this host.",
                ctx.scope, ctx.facts.arch
            ),
        });
    }
    ctx.info("Installing wstunnel.");
    let script = format!(
        r#"#!/bin/sh
set -e
if ! command -v curl >/dev/null 2>&1; then
  echo "HTM-ERROR: curl is required to install wstunnel."; exit 3
fi
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 300 -o "$TMP" {url}
[ -s "$TMP" ] || {{ echo "HTM-ERROR: wstunnel downloaded empty."; exit 4; }}
install -m 0755 -o root -g root "$TMP" {bin}
echo "wstunnel installed."
"#,
        url = WSTUNNEL_URL,
        bin = WSTUNNEL_BIN,
    );
    run(ctx, &script, "wstunnel")
}

fn run(ctx: &HostCtx<'_>, script: &str, what: &str) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();
    let status = ctx.client.run_script_stream(
        script,
        true,
        ctx.cancel,
        Duration::from_secs(900),
        |line| {
            let line = line.trim();
            if line.is_empty() {
                return;
            }
            if let Some(e) = line.strip_prefix("HTM-ERROR:") {
                errors.push(e.trim().to_string());
                return;
            }
            ctx.debug(line);
        },
    )?;
    if status != 0 {
        return Err(Error::Provider {
            provider: "Hiddify Relay".to_string(),
            detail: if errors.is_empty() {
                format!("installing {what} failed with exit status {status}")
            } else {
                errors.join(" ")
            },
        });
    }
    ctx.success(&format!("{what} ready."));
    Ok(())
}

/// Remove everything HTM put on the host for the relay provider. The forwarder
/// binaries (gost, xray, wstunnel, haproxy, socat) are shared system software
/// and are left in place; only HTM's own units and config are removed.
pub fn uninstall(ctx: &HostCtx<'_>) -> Result<()> {
    let script = format!(
        r#"#!/bin/sh
for unit in $(systemctl list-units --all --plain --no-legend '{prefix}-*' 2>/dev/null | awk '{{ print $1 }}'); do
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/{prefix}-*.service
rm -rf {base}
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Removed HTM relay units."
exit 0
"#,
        prefix = SERVICE_PREFIX,
        base = BASE_DIR,
    );
    let out = ctx.client.run_script(&script, true)?;
    if !out.ok() {
        return Err(Error::Provider {
            provider: "Hiddify Relay".to_string(),
            detail: format!(
                "uninstall failed: {}",
                crate::util::truncate(&out.combined(), 300)
            ),
        });
    }
    ctx.success("Hiddify Relay units removed.");
    Ok(())
}
