//! Getting HTunnel onto a server, and off it again.
//!
//! HTunnel ships two separate binaries — `client` and `server` — rather than
//! one role-switching binary, and publishes them for x86_64 Linux only. HTM
//! installs **both** on every managed host (the relay runs the client, the
//! exit the server) so a single unit name can refer to the right binary on
//! each side. A source build is the fallback on any other architecture.

use std::time::Duration;

use super::config::{BINARY_CLIENT, BINARY_SERVER, CONFIG_DIR, INSTALL_DIR, VERSION_FILE};
use crate::error::{Error, Result};
use crate::provider::{HostCtx, InstallMethod, InstalledVersion};
use crate::remote::pkg;
use crate::util::sh_quote;

pub const REPO_OWNER: &str = "Hiddify2";
pub const REPO_NAME: &str = "HTunnel";
pub const RELEASE_ARCH: &str = "x86_64";
pub const CLIENT_ASSET: &str = "HTunnel-client-linux-x86_64";
pub const SERVER_ASSET: &str = "HTunnel-server-linux-x86_64";

/// Is HTunnel already installed by HTM?
pub fn detect(ctx: &HostCtx<'_>) -> Result<Option<InstalledVersion>> {
    // Both binaries must be present; the exit needs the server and the relay
    // needs the client, and HTM installs them together.
    if !ctx.client.path_exists(BINARY_CLIENT)? || !ctx.client.path_exists(BINARY_SERVER)? {
        return Ok(None);
    }
    let runs = ctx
        .client
        .exec(&format!(
            "{c} --help >/dev/null 2>&1 && {s} --help >/dev/null 2>&1 && echo ok || echo no",
            c = sh_quote(BINARY_CLIENT),
            s = sh_quote(BINARY_SERVER),
        ))?
        .first_line()
        == "ok";
    if !runs {
        ctx.warn("HTunnel binaries are present but will not execute. They will be reinstalled.");
        return Ok(None);
    }

    let version = ctx
        .client
        .read_file(VERSION_FILE)
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let (version, origin) = if version.is_empty() {
        ("unknown".to_string(), "already present".to_string())
    } else if let Some(rest) = version.strip_prefix("source-") {
        (rest.to_string(), "built from source".to_string())
    } else {
        (version.clone(), format!("release binaries {version}"))
    };

    Ok(Some(InstalledVersion {
        version,
        binary_path: BINARY_CLIENT.to_string(),
        origin,
    }))
}

pub fn resolve_method(method: InstallMethod, arch: &str) -> InstallMethod {
    match method {
        InstallMethod::Auto => {
            if arch == RELEASE_ARCH {
                InstallMethod::PrebuiltBinary
            } else {
                InstallMethod::BuildFromSource
            }
        }
        other => other,
    }
}

pub fn install(ctx: &HostCtx<'_>, method: InstallMethod) -> Result<InstalledVersion> {
    let resolved = resolve_method(method, &ctx.facts.arch);
    if resolved == InstallMethod::PrebuiltBinary && ctx.facts.arch != RELEASE_ARCH {
        return Err(Error::Unsupported {
            detail: format!(
                "This host is {}, but HTunnel publishes {RELEASE_ARCH} Linux binaries only. \
                 Choose 'Build from source' instead.",
                ctx.facts.arch
            ),
        });
    }

    ctx.info(&format!(
        "Installing HTunnel via {}.",
        match resolved {
            InstallMethod::PrebuiltBinary => "the published release binaries",
            InstallMethod::BuildFromSource => "a source build",
            InstallMethod::Auto => "the automatic choice",
        }
    ));

    ctx.client.exec_priv_ok(&format!(
        "mkdir -p {install} {config} && chmod 0755 {install} && chmod 0750 {config}",
        install = sh_quote(INSTALL_DIR),
        config = sh_quote(CONFIG_DIR),
    ))?;

    match resolved {
        InstallMethod::BuildFromSource => install_from_source(ctx),
        _ => install_prebuilt(ctx),
    }
}

fn install_prebuilt(ctx: &HostCtx<'_>) -> Result<InstalledVersion> {
    let script = format!(
        r#"#!/bin/sh
set -e

BASE="https://github.com/{owner}/{repo}/releases/latest/download"

if ! command -v curl >/dev/null 2>&1; then
  echo "HTM-ERROR: curl is not installed, so the release cannot be downloaded."
  exit 3
fi

fetch() {{
  url="$1"; dest="$2"
  tmp="$(mktemp)"
  if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 600 -o "$tmp" "$url"; then
    rm -f "$tmp"
    echo "HTM-ERROR: could not download $url. The server may have no outbound HTTPS, or GitHub"
    echo "HTM-ERROR: may be blocked. Try 'Build from source'."
    exit 4
  fi
  if [ ! -s "$tmp" ]; then rm -f "$tmp"; echo "HTM-ERROR: $url downloaded empty."; exit 5; fi
  chmod 0755 "$tmp"
  if ! "$tmp" --help >/dev/null 2>&1; then
    rm -f "$tmp"
    echo "HTM-ERROR: $dest does not run on this host (likely a newer glibc). Try 'Build from source'."
    exit 6
  fi
  install -m 0755 -o root -g root "$tmp" "$dest"
  rm -f "$tmp"
}}

echo "Downloading the HTunnel client and server."
fetch "$BASE/{client_asset}" {client_bin}
fetch "$BASE/{server_asset}" {server_bin}

# The release tag, best effort, for the version record.
TAG="$(curl -fsSL --connect-timeout 20 --max-time 60 \
        -H 'Accept: application/vnd.github+json' \
        -H 'User-Agent: HTM-Hiddify-Tunnel-Manager' \
        "https://api.github.com/repos/{owner}/{repo}/releases/latest" 2>/dev/null \
        | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 \
        | sed 's/.*"\([^"]*\)"$/\1/')"
printf '%s\n' "${{TAG:-unknown}}" > {version_file}
chmod 0644 {version_file}

echo "HTM-VERSION: ${{TAG:-unknown}}"
echo "Installed the HTunnel client and server."
"#,
        owner = REPO_OWNER,
        repo = REPO_NAME,
        client_asset = CLIENT_ASSET,
        server_asset = SERVER_ASSET,
        client_bin = BINARY_CLIENT,
        server_bin = BINARY_SERVER,
        version_file = VERSION_FILE,
    );

    run_install_script(ctx, &script, Duration::from_secs(900), "release binaries")
}

fn install_from_source(ctx: &HostCtx<'_>) -> Result<InstalledVersion> {
    ctx.info("Installing build dependencies (git and a C toolchain).");
    ctx.check()?;
    let report = pkg::install(
        ctx.client,
        ctx.facts.package_manager,
        &[
            pkg::logical::GIT,
            pkg::logical::TOOLCHAIN_C,
            pkg::logical::PKGCONFIG,
        ],
        ctx.scope,
        ctx.reporter,
        ctx.cancel,
    )?;
    if !report.is_ok() {
        let names: Vec<String> = report.failed.iter().map(|(p, _)| p.clone()).collect();
        return Err(Error::Provider {
            provider: "HTunnel".to_string(),
            detail: format!(
                "these build dependencies could not be installed: {}.",
                names.join(", ")
            ),
        });
    }

    ctx.check()?;
    ctx.info("Preparing the Rust toolchain.");
    let toolchain = pkg::install_rust_toolchain(ctx.client, ctx.scope, ctx.reporter, ctx.cancel)?;
    ctx.info(&format!("Using {toolchain}."));

    ctx.check()?;
    ctx.info("Cloning and compiling HTunnel.");
    let script = format!(
        r#"#!/bin/sh
set -e

SRC={install_dir}/src
CARGO={cargo_bin}
if [ ! -x "$CARGO" ]; then
  if command -v cargo >/dev/null 2>&1; then CARGO="$(command -v cargo)";
  else echo "HTM-ERROR: no cargo executable found."; exit 3; fi
fi
export CARGO_HOME={cargo_home}
export RUSTUP_HOME={rustup_home}
export CARGO_TERM_COLOR=never

rm -rf "$SRC"; mkdir -p "$SRC"
git clone --depth 1 https://github.com/{owner}/{repo}.git "$SRC"
cd "$SRC"
VER="$(grep -m 1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')"
echo "Source version ${{VER:-unknown}}"

"$CARGO" build --release --bin client --bin server
for b in client server; do
  if [ ! -f "target/release/$b" ]; then
    echo "HTM-ERROR: the build finished but target/release/$b is missing."; exit 4
  fi
done
install -m 0755 -o root -g root target/release/client {client_bin}
install -m 0755 -o root -g root target/release/server {server_bin}
printf 'source-%s\n' "${{VER:-unknown}}" > {version_file}
chmod 0644 {version_file}
echo "HTM-VERSION: ${{VER:-unknown}}"
"#,
        install_dir = INSTALL_DIR,
        cargo_bin = pkg::CARGO_BIN,
        cargo_home = pkg::CARGO_HOME,
        rustup_home = pkg::RUSTUP_HOME,
        owner = REPO_OWNER,
        repo = REPO_NAME,
        client_bin = BINARY_CLIENT,
        server_bin = BINARY_SERVER,
        version_file = VERSION_FILE,
    );

    run_install_script(ctx, &script, Duration::from_secs(2400), "built from source")
}

fn run_install_script(
    ctx: &HostCtx<'_>,
    script: &str,
    timeout: Duration,
    origin: &str,
) -> Result<InstalledVersion> {
    let mut version = String::new();
    let mut errors: Vec<String> = Vec::new();
    let status = ctx
        .client
        .run_script_stream(script, true, ctx.cancel, timeout, |line| {
            let line = line.trim();
            if line.is_empty() {
                return;
            }
            if let Some(v) = line.strip_prefix("HTM-VERSION:") {
                version = v.trim().to_string();
                return;
            }
            if let Some(e) = line.strip_prefix("HTM-ERROR:") {
                errors.push(e.trim().to_string());
                return;
            }
            ctx.debug(line);
        })?;
    if status != 0 {
        return Err(Error::Provider {
            provider: "HTunnel".to_string(),
            detail: if errors.is_empty() {
                format!("the install script failed with exit status {status}")
            } else {
                errors.join(" ")
            },
        });
    }
    let version = if version.is_empty() {
        "unknown".to_string()
    } else {
        version
    };
    ctx.success(&format!("HTunnel {version} installed."));
    Ok(InstalledVersion {
        version: version.clone(),
        binary_path: BINARY_CLIENT.to_string(),
        origin: if origin == "built from source" {
            origin.to_string()
        } else {
            format!("{origin} {version}")
        },
    })
}

/// Remove HTunnel and everything HTM put on the host for it.
pub fn uninstall(ctx: &HostCtx<'_>) -> Result<()> {
    let script = format!(
        r#"#!/bin/sh
for unit in $(systemctl list-units --all --plain --no-legend '{prefix}-*' 2>/dev/null | awk '{{ print $1 }}'); do
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/{prefix}-*.service
rm -rf {install_dir}
rm -rf {config_dir}
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Removed HTunnel."
exit 0
"#,
        prefix = super::config::SERVICE_PREFIX,
        install_dir = INSTALL_DIR,
        config_dir = CONFIG_DIR,
    );
    let out = ctx.client.run_script(&script, true)?;
    if !out.ok() {
        return Err(Error::Provider {
            provider: "HTunnel".to_string(),
            detail: format!(
                "uninstall failed: {}",
                crate::util::truncate(&out.combined(), 300)
            ),
        });
    }
    ctx.success("HTunnel removed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prebuilt_only_on_x86_64() {
        assert_eq!(
            resolve_method(InstallMethod::Auto, "x86_64"),
            InstallMethod::PrebuiltBinary
        );
        assert_eq!(
            resolve_method(InstallMethod::Auto, "aarch64"),
            InstallMethod::BuildFromSource
        );
    }
}
