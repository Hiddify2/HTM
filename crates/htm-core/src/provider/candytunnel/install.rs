//! Getting CandyTunnel onto a server, and off it again.
//!
//! Two routes are supported. The released `CandyTunnel-linux-x86_64` binary is
//! preferred: it takes seconds and needs no toolchain. A source build is the
//! fallback for non-x86_64 hosts and for anyone who wants to track `main`; it
//! needs CMake and Go as well as Rust, because the QUIC transport pulls in
//! BoringSSL.
//!
//! Only the unified `candy-tunnel` binary is ever installed. The separate
//! `server` binary in the same repository prompts for a license password on
//! stdin and cannot run unattended under systemd.

use std::time::Duration;

use super::config::{BINARY_PATH, CONFIG_DIR, INSTALL_DIR, VERSION_FILE};
use crate::error::{Error, Result};
use crate::provider::{HostCtx, InstallMethod, InstalledVersion};
use crate::remote::pkg;
use crate::util::sh_quote;

/// Upstream repository, used for both the release API and source checkouts.
pub const REPO_OWNER: &str = "AmiRCandy";
pub const REPO_NAME: &str = "CandyTunnel";
/// The release asset holding the unified binary.
pub const RELEASE_ASSET: &str = "CandyTunnel-linux-x86_64";

/// Architecture the published binaries are built for.
pub const RELEASE_ARCH: &str = "x86_64";

/// Is CandyTunnel already installed, and at what version?
pub fn detect(ctx: &HostCtx<'_>) -> Result<Option<InstalledVersion>> {
    if !ctx.client.path_exists(BINARY_PATH)? {
        return Ok(None);
    }

    // A file that exists but will not run is worse than one that is absent,
    // because the unit would fail cryptically. Check it executes.
    let runs = ctx
        .client
        .exec(&format!(
            "{bin} --help >/dev/null 2>&1 && echo ok || echo no",
            bin = sh_quote(BINARY_PATH)
        ))?
        .first_line()
        == "ok";

    if !runs {
        ctx.warn(
            "A CandyTunnel binary is present but will not execute. It will be reinstalled.",
        );
        return Ok(None);
    }

    let version = ctx
        .client
        .read_file(VERSION_FILE)
        .map(|v| v.trim().to_string())
        .unwrap_or_default();

    let (version, origin) = if version.is_empty() {
        (
            "unknown".to_string(),
            "already present, not installed by HTM".to_string(),
        )
    } else if let Some(rest) = version.strip_prefix("source-") {
        (rest.to_string(), "built from source".to_string())
    } else {
        (version.clone(), format!("release binary {version}"))
    };

    Ok(Some(InstalledVersion {
        version,
        binary_path: BINARY_PATH.to_string(),
        origin,
    }))
}

/// Which route [`InstallMethod::Auto`] resolves to on this host.
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

/// Install or update CandyTunnel.
pub fn install(ctx: &HostCtx<'_>, method: InstallMethod) -> Result<InstalledVersion> {
    let resolved = resolve_method(method, &ctx.facts.arch);

    if resolved == InstallMethod::PrebuiltBinary && ctx.facts.arch != RELEASE_ARCH {
        return Err(Error::Unsupported {
            detail: format!(
                "This host is {}, but CandyTunnel only publishes {RELEASE_ARCH} Linux binaries. \
                 Choose 'Build from source' instead.",
                ctx.facts.arch
            ),
        });
    }

    ctx.info(&format!(
        "Installing CandyTunnel via {}.",
        match resolved {
            InstallMethod::PrebuiltBinary => "the published release binary",
            InstallMethod::BuildFromSource => "a source build",
            InstallMethod::Auto => "the automatic choice",
        }
    ));

    prepare_directories(ctx)?;

    match resolved {
        InstallMethod::BuildFromSource => install_from_source(ctx),
        _ => install_prebuilt(ctx),
    }
}

fn prepare_directories(ctx: &HostCtx<'_>) -> Result<()> {
    ctx.client.exec_priv_ok(&format!(
        "mkdir -p {install} {config} /var/log/candytunnel && chmod 0755 {install} && chmod 0750 {config}",
        install = sh_quote(INSTALL_DIR),
        config = sh_quote(CONFIG_DIR),
    ))?;
    Ok(())
}

/// Download the published binary.
fn install_prebuilt(ctx: &HostCtx<'_>) -> Result<InstalledVersion> {
    let script = format!(
        r#"#!/bin/sh
set -e

API="https://api.github.com/repos/{owner}/{repo}/releases/latest"
ASSET="{asset}"

if ! command -v curl >/dev/null 2>&1; then
  echo "HTM-ERROR: curl is not installed, so the release cannot be downloaded."
  exit 3
fi

echo "Querying the latest release."
JSON="$(curl -fsSL --connect-timeout 20 --max-time 60 \
          -H 'Accept: application/vnd.github+json' \
          -H 'User-Agent: HTM-Hiddify-Tunnel-Manager' "$API" 2>/dev/null)" || {{
  echo "HTM-ERROR: could not reach the GitHub release API. The server may have no outbound"
  echo "HTM-ERROR: HTTPS access, or GitHub may be blocked from it. Try 'Build from source',"
  echo "HTM-ERROR: or place the binary at {binary} manually."
  exit 4
}}

TAG="$(printf '%s' "$JSON" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/')"
URL="$(printf '%s' "$JSON" | grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | sed 's/.*"\(https[^"]*\)"$/\1/' | grep -E "/${{ASSET}}$" | head -n 1)"

if [ -z "$URL" ]; then
  echo "HTM-ERROR: release ${{TAG:-unknown}} has no asset named $ASSET."
  exit 5
fi

echo "Release ${{TAG:-unknown}}"
echo "Downloading $URL"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 600 -o "$TMP" "$URL"

if [ ! -s "$TMP" ]; then
  echo "HTM-ERROR: the downloaded file is empty."
  exit 6
fi

chmod 0755 "$TMP"
if ! "$TMP" --help >/dev/null 2>&1; then
  echo "HTM-ERROR: the downloaded binary does not run on this host. It may have been built"
  echo "HTM-ERROR: against a newer glibc than this distribution provides. Try 'Build from source'."
  exit 7
fi

install -m 0755 -o root -g root "$TMP" {binary}
printf '%s\n' "${{TAG:-unknown}}" > {version_file}
chmod 0644 {version_file}
ln -sf {binary} /usr/local/bin/candy-tunnel 2>/dev/null || true

echo "HTM-VERSION: ${{TAG:-unknown}}"
echo "Installed {binary}"
"#,
        owner = REPO_OWNER,
        repo = REPO_NAME,
        asset = RELEASE_ASSET,
        binary = BINARY_PATH,
        version_file = VERSION_FILE,
    );

    let mut version = String::new();
    let mut errors: Vec<String> = Vec::new();

    let status = ctx.client.run_script_stream(
        &script,
        true,
        ctx.cancel,
        Duration::from_secs(900),
        |line| {
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
        },
    )?;

    if status != 0 {
        return Err(Error::Provider {
            provider: "CandyTunnel".to_string(),
            detail: if errors.is_empty() {
                format!("the download script failed with exit status {status}")
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
    ctx.success(&format!("CandyTunnel {version} installed."));

    Ok(InstalledVersion {
        version: version.clone(),
        binary_path: BINARY_PATH.to_string(),
        origin: format!("release binary {version}"),
    })
}

/// Clone and compile.
fn install_from_source(ctx: &HostCtx<'_>) -> Result<InstalledVersion> {
    ctx.info("Installing build dependencies. CandyTunnel's QUIC transport needs CMake and Go as well as a C toolchain.");
    ctx.check()?;

    let report = pkg::install(
        ctx.client,
        ctx.facts.package_manager,
        pkg::BUILD_PACKAGES,
        ctx.scope,
        ctx.reporter,
        ctx.cancel,
    )?;
    if !report.is_ok() {
        let names: Vec<String> = report.failed.iter().map(|(p, _)| p.clone()).collect();
        return Err(Error::Provider {
            provider: "CandyTunnel".to_string(),
            detail: format!(
                "these build dependencies could not be installed: {}. A source build cannot \
                 proceed without them.",
                names.join(", ")
            ),
        });
    }

    ctx.check()?;
    ctx.info("Preparing the Rust toolchain.");
    let toolchain = pkg::install_rust_toolchain(ctx.client, ctx.scope, ctx.reporter, ctx.cancel)?;
    ctx.info(&format!("Using {toolchain}."));

    ctx.check()?;
    ctx.info("Cloning and compiling. On a small VPS this takes ten minutes or more.");

    let script = format!(
        r#"#!/bin/sh
set -e

SRC={install_dir}/src
CARGO={cargo_bin}

if [ ! -x "$CARGO" ]; then
  if command -v cargo >/dev/null 2>&1; then
    CARGO="$(command -v cargo)"
  else
    echo "HTM-ERROR: no cargo executable could be found after installing the toolchain."
    exit 3
  fi
fi

export CARGO_HOME={cargo_home}
export RUSTUP_HOME={rustup_home}
export CARGO_TERM_COLOR=never

rm -rf "$SRC"
mkdir -p "$SRC"
git clone --depth 1 https://github.com/{owner}/{repo}.git "$SRC"
cd "$SRC"

VER="$(grep -m 1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')"
echo "Source version ${{VER:-unknown}}"

# Only the unified binary is built. The separate client and server binaries are
# deliberately skipped: the server one prompts for a license password on stdin.
"$CARGO" build --release --bin candy-tunnel

if [ ! -f target/release/candy-tunnel ]; then
  echo "HTM-ERROR: the build finished but target/release/candy-tunnel is missing."
  exit 4
fi

install -m 0755 -o root -g root target/release/candy-tunnel {binary}
printf 'source-%s\n' "${{VER:-unknown}}" > {version_file}
chmod 0644 {version_file}
ln -sf {binary} /usr/local/bin/candy-tunnel 2>/dev/null || true

if ! {binary} --help >/dev/null 2>&1; then
  echo "HTM-ERROR: the freshly built binary does not run."
  exit 5
fi

echo "HTM-VERSION: ${{VER:-unknown}}"
"#,
        install_dir = INSTALL_DIR,
        cargo_bin = pkg::CARGO_BIN,
        cargo_home = pkg::CARGO_HOME,
        rustup_home = pkg::RUSTUP_HOME,
        owner = REPO_OWNER,
        repo = REPO_NAME,
        binary = BINARY_PATH,
        version_file = VERSION_FILE,
    );

    let mut version = String::new();
    let mut errors: Vec<String> = Vec::new();

    // A cold build of quiche and BoringSSL on one shared vCPU is slow; allow
    // an hour before giving up.
    let status = ctx.client.run_script_stream(
        &script,
        true,
        ctx.cancel,
        Duration::from_secs(3600),
        |line| {
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
        },
    )?;

    if status != 0 {
        return Err(Error::Provider {
            provider: "CandyTunnel".to_string(),
            detail: if errors.is_empty() {
                format!(
                    "the source build failed with exit status {status}. The log above has the \
                     compiler output; running out of memory during linking is the usual cause on \
                     small instances."
                )
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
    ctx.success(&format!("CandyTunnel {version} built and installed."));

    Ok(InstalledVersion {
        version: version.clone(),
        binary_path: BINARY_PATH.to_string(),
        origin: "built from source".to_string(),
    })
}

/// Generate the self-signed certificate the QUIC transport needs.
///
/// CandyTunnel's client does not validate the certificate chain — it is there
/// so the handshake looks like real TLS 1.3 on the wire — so a self-signed
/// certificate is the right thing here.
pub fn ensure_quic_certificate(
    ctx: &HostCtx<'_>,
    cert_path: &str,
    key_path: &str,
    server_name: &str,
) -> Result<()> {
    let exists = ctx.client.path_exists(cert_path)? && ctx.client.path_exists(key_path)?;
    if exists {
        ctx.debug("QUIC certificate already present.");
        return Ok(());
    }

    if !ctx.client.has_command("openssl")? {
        ctx.info("Installing openssl to generate the QUIC certificate.");
        let report = pkg::install(
            ctx.client,
            ctx.facts.package_manager,
            &[pkg::logical::OPENSSL],
            ctx.scope,
            ctx.reporter,
            ctx.cancel,
        )?;
        if !report.is_ok() {
            return Err(Error::Provider {
                provider: "CandyTunnel".to_string(),
                detail: "openssl could not be installed, so the QUIC certificate cannot be \
                         generated. Choose a transport other than QUIC, or install openssl by \
                         hand."
                    .to_string(),
            });
        }
    }

    let script = format!(
        r#"#!/bin/sh
set -e
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout {key} -out {cert} -subj "/CN={cn}" >/dev/null 2>&1
chmod 0600 {key}
chmod 0644 {cert}
chown root:root {key} {cert}
echo "Generated a 10 year self-signed certificate for {cn}."
"#,
        key = sh_quote(key_path),
        cert = sh_quote(cert_path),
        cn = server_name.replace('"', ""),
    );

    let out = ctx.client.run_script(&script, true)?;
    if !out.ok() {
        return Err(Error::Provider {
            provider: "CandyTunnel".to_string(),
            detail: format!(
                "the QUIC certificate could not be generated: {}",
                crate::util::truncate(&out.combined(), 300)
            ),
        });
    }
    ctx.success("QUIC certificate ready.");
    Ok(())
}

/// Remove CandyTunnel and everything HTM put on the host for it.
pub fn uninstall(ctx: &HostCtx<'_>) -> Result<()> {
    let script = format!(
        r#"#!/bin/sh
# Stop and forget every HTM-managed instance before deleting anything.
for unit in $(systemctl list-units --all --plain --no-legend '{prefix}@*' 2>/dev/null | awk '{{ print $1 }}'); do
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
done

rm -f /etc/systemd/system/{template}
rm -rf {install_dir}
rm -rf {config_dir}
rm -f /usr/local/bin/candy-tunnel
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Removed CandyTunnel."
exit 0
"#,
        prefix = super::config::SERVICE_PREFIX,
        template = super::config::UNIT_TEMPLATE,
        install_dir = INSTALL_DIR,
        config_dir = CONFIG_DIR,
    );

    let out = ctx.client.run_script(&script, true)?;
    if !out.ok() {
        return Err(Error::Provider {
            provider: "CandyTunnel".to_string(),
            detail: format!(
                "uninstall failed: {}",
                crate::util::truncate(&out.combined(), 300)
            ),
        });
    }
    ctx.success("CandyTunnel removed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_prefers_the_release_binary_on_x86_64() {
        assert_eq!(
            resolve_method(InstallMethod::Auto, "x86_64"),
            InstallMethod::PrebuiltBinary
        );
    }

    #[test]
    fn auto_falls_back_to_source_elsewhere() {
        assert_eq!(
            resolve_method(InstallMethod::Auto, "aarch64"),
            InstallMethod::BuildFromSource
        );
    }

    #[test]
    fn an_explicit_choice_is_respected() {
        assert_eq!(
            resolve_method(InstallMethod::BuildFromSource, "x86_64"),
            InstallMethod::BuildFromSource
        );
    }
}
