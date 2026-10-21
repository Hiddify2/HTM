//! Getting CopyTunnel onto a server, and off it again.
//!
//! The published `copytunnel-<target>` binary is preferred and exists for both
//! x86_64 and aarch64 Linux, so a prebuilt install works on most hosts. A
//! source build is the fallback for any other architecture and for anyone
//! tracking `main`; CopyTunnel's ciphers are pure-Rust RustCrypto crates, so a
//! build needs only Rust, git and a C toolchain — no CMake or Go.

use std::time::Duration;

use super::config::{BINARY_PATH, CONFIG_DIR, INSTALL_DIR, VERSION_FILE};
use crate::error::{Error, Result};
use crate::provider::{HostCtx, InstallMethod, InstalledVersion};
use crate::remote::pkg;
use crate::util::sh_quote;

pub const REPO_OWNER: &str = "Hiddify2";
pub const REPO_NAME: &str = "CopyTunnel";

/// Architectures CopyTunnel publishes a prebuilt binary for, with the release
/// asset's target-triple suffix.
pub fn release_triple(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("x86_64-unknown-linux-gnu"),
        "aarch64" | "arm64" => Some("aarch64-unknown-linux-gnu"),
        _ => None,
    }
}

/// Is CopyTunnel already installed by HTM, and at what version?
pub fn detect(ctx: &HostCtx<'_>) -> Result<Option<InstalledVersion>> {
    if !ctx.client.path_exists(BINARY_PATH)? {
        return Ok(None);
    }

    let runs = ctx
        .client
        .exec(&format!(
            "{bin} --help >/dev/null 2>&1 && echo ok || echo no",
            bin = sh_quote(BINARY_PATH)
        ))?
        .first_line()
        == "ok";
    if !runs {
        ctx.warn("A CopyTunnel binary is present but will not execute. It will be reinstalled.");
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
            if release_triple(arch).is_some() {
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

    if resolved == InstallMethod::PrebuiltBinary && release_triple(&ctx.facts.arch).is_none() {
        return Err(Error::Unsupported {
            detail: format!(
                "This host is {}, which CopyTunnel publishes no prebuilt binary for. Choose \
                 'Build from source' instead.",
                ctx.facts.arch
            ),
        });
    }

    ctx.info(&format!(
        "Installing CopyTunnel via {}.",
        match resolved {
            InstallMethod::PrebuiltBinary => "the published release binary",
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
    let triple = release_triple(&ctx.facts.arch).ok_or_else(|| Error::Unsupported {
        detail: format!("No CopyTunnel binary is published for {}.", ctx.facts.arch),
    })?;

    let script = format!(
        r#"#!/bin/sh
set -e

API="https://api.github.com/repos/{owner}/{repo}/releases/latest"
ASSET="copytunnel-{triple}"

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
  # Fall back to the stable latest-download path when the asset list is odd.
  URL="https://github.com/{owner}/{repo}/releases/latest/download/${{ASSET}}"
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

echo "HTM-VERSION: ${{TAG:-unknown}}"
echo "Installed {binary}"
"#,
        owner = REPO_OWNER,
        repo = REPO_NAME,
        triple = triple,
        binary = BINARY_PATH,
        version_file = VERSION_FILE,
    );

    run_install_script(ctx, &script, Duration::from_secs(900), |v| {
        InstalledVersion {
            version: v.clone(),
            binary_path: BINARY_PATH.to_string(),
            origin: format!("release binary {v}"),
        }
    })
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
            provider: "CopyTunnel".to_string(),
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
    ctx.info("Cloning and compiling CopyTunnel.");

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

"$CARGO" build --release --bin copytunnel

if [ ! -f target/release/copytunnel ]; then
  echo "HTM-ERROR: the build finished but target/release/copytunnel is missing."
  exit 4
fi

install -m 0755 -o root -g root target/release/copytunnel {binary}
printf 'source-%s\n' "${{VER:-unknown}}" > {version_file}
chmod 0644 {version_file}

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

    run_install_script(ctx, &script, Duration::from_secs(2400), |v| {
        InstalledVersion {
            version: v.clone(),
            binary_path: BINARY_PATH.to_string(),
            origin: "built from source".to_string(),
        }
    })
}

/// Run an install script, collecting the `HTM-VERSION`/`HTM-ERROR` markers and
/// turning a non-zero exit into a provider error.
fn run_install_script(
    ctx: &HostCtx<'_>,
    script: &str,
    timeout: Duration,
    make: impl Fn(&String) -> InstalledVersion,
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
            provider: "CopyTunnel".to_string(),
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
    ctx.success(&format!("CopyTunnel {version} installed."));
    Ok(make(&version))
}

/// Remove CopyTunnel and everything HTM put on the host for it.
pub fn uninstall(ctx: &HostCtx<'_>) -> Result<()> {
    let script = format!(
        r#"#!/bin/sh
for unit in $(systemctl list-units --all --plain --no-legend '{prefix}@*' 2>/dev/null | awk '{{ print $1 }}'); do
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
done

rm -f /etc/systemd/system/{template}
rm -rf {install_dir}
rm -rf {config_dir}
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Removed CopyTunnel."
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
            provider: "CopyTunnel".to_string(),
            detail: format!(
                "uninstall failed: {}",
                crate::util::truncate(&out.combined(), 300)
            ),
        });
    }
    ctx.success("CopyTunnel removed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prebuilt_is_available_for_x86_64_and_aarch64() {
        assert!(release_triple("x86_64").is_some());
        assert!(release_triple("aarch64").is_some());
        assert!(release_triple("armv7l").is_none());
    }

    #[test]
    fn auto_prefers_the_binary_where_one_is_published() {
        assert_eq!(
            resolve_method(InstallMethod::Auto, "x86_64"),
            InstallMethod::PrebuiltBinary
        );
        assert_eq!(
            resolve_method(InstallMethod::Auto, "aarch64"),
            InstallMethod::PrebuiltBinary
        );
        assert_eq!(
            resolve_method(InstallMethod::Auto, "armv7l"),
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
