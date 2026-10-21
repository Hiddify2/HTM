//! Getting Hiddify Core onto a server, and off it again.
//!
//! Hiddify Core publishes a tarball per architecture and libc, named like
//! `hiddify-core-linux-<arch>[-glibc|-musl].tar.gz`, holding one executable.
//! HTM downloads it and installs the binary into its own namespaced location so
//! it never disturbs an install set up by upstream's own `installer.sh`. A
//! source build is not offered: the upstream build is a large CGo/sing-box
//! toolchain, and prebuilt binaries cover every architecture HTM targets.

use std::time::Duration;

use super::config::{BINARY_PATH, CONFIG_DIR, INSTALL_DIR, VERSION_FILE, WORKDIR_BASE};
use crate::error::{Error, Result};
use crate::provider::{HostCtx, InstallMethod, InstalledVersion};
use crate::remote::pkg;
use crate::util::sh_quote;

pub const REPO_OWNER: &str = "hiddify";
pub const REPO_NAME: &str = "hiddify-core";

/// Map HTM's `uname -m` architecture to the release tarball's arch token, or
/// `None` when no prebuilt binary is published for it.
pub fn release_arch(arch: &str) -> Option<&'static str> {
    Some(match arch {
        "x86_64" => "amd64",
        "aarch64" | "arm64" => "arm64",
        "armv7l" | "armv7" => "armv7",
        "armv6l" | "armv6" => "armv6",
        "i686" | "i386" => "386",
        "riscv64" => "riscv64",
        "s390x" => "s390x",
        "ppc64le" => "ppc64le",
        _ => return None,
    })
}

pub fn detect(ctx: &HostCtx<'_>) -> Result<Option<InstalledVersion>> {
    if !ctx.client.path_exists(BINARY_PATH)? {
        return Ok(None);
    }
    let runs = ctx
        .client
        .exec(&format!(
            "{bin} version >/dev/null 2>&1 || {bin} --help >/dev/null 2>&1 && echo ok || echo no",
            bin = sh_quote(BINARY_PATH)
        ))?
        .first_line()
        == "ok";
    if !runs {
        ctx.warn("A Hiddify Core binary is present but will not execute. It will be reinstalled.");
        return Ok(None);
    }
    let version = ctx
        .client
        .read_file(VERSION_FILE)
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let (version, origin) = if version.is_empty() {
        ("unknown".to_string(), "already present".to_string())
    } else {
        (version.clone(), format!("release {version}"))
    };
    Ok(Some(InstalledVersion {
        version,
        binary_path: BINARY_PATH.to_string(),
        origin,
    }))
}

pub fn install(ctx: &HostCtx<'_>, _method: InstallMethod) -> Result<InstalledVersion> {
    let arch = release_arch(&ctx.facts.arch).ok_or_else(|| Error::Unsupported {
        detail: format!(
            "Hiddify Core publishes no binary for {}. Use a supported architecture.",
            ctx.facts.arch
        ),
    })?;

    ctx.info("Installing Hiddify Core.");
    ctx.client.exec_priv_ok(&format!(
        "mkdir -p {install} {config} {work} && chmod 0755 {install} && chmod 0750 {config}",
        install = sh_quote(INSTALL_DIR),
        config = sh_quote(CONFIG_DIR),
        work = sh_quote(WORKDIR_BASE),
    ))?;

    // `tar` is needed to unpack the release; make sure it is present.
    let _ = pkg::install(
        ctx.client,
        ctx.facts.package_manager,
        &[
            pkg::logical::CURL,
            pkg::logical::TAR,
            pkg::logical::CA_CERTS,
        ],
        ctx.scope,
        ctx.reporter,
        ctx.cancel,
    )?;

    let script = format!(
        r#"#!/bin/sh
set -e

REPO="{owner}/{repo}"
ARCH="{arch}"

if ! command -v curl >/dev/null 2>&1; then
  echo "HTM-ERROR: curl is required to download Hiddify Core."; exit 3
fi

# glibc vs musl, matching upstream's installer.
LIBC=""
if ldd --version 2>&1 | grep -iq musl; then LIBC="-musl";
elif ldd --version 2>&1 | grep -iq glibc; then LIBC="-glibc"; fi

TAG="$(curl -fsSL --connect-timeout 20 --max-time 60 \
        -H 'Accept: application/vnd.github+json' \
        -H 'User-Agent: HTM-Hiddify-Tunnel-Manager' \
        "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -n 1)"
if [ -z "$TAG" ]; then
  echo "HTM-ERROR: could not reach the GitHub release API. The server may have no outbound HTTPS."
  exit 4
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

download() {{
  art="hiddify-core-linux-${{ARCH}}$1.tar.gz"
  url="https://github.com/$REPO/releases/download/$TAG/$art"
  echo "Trying $art"
  curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 600 -o "$WORK/core.tar.gz" "$url"
}}

# Prefer the libc-specific artifact, then the generic one.
if ! {{ [ -n "$LIBC" ] && download "$LIBC"; }}; then
  download "" || {{ echo "HTM-ERROR: no matching Hiddify Core artifact for $ARCH."; exit 5; }}
fi

tar -zxf "$WORK/core.tar.gz" -C "$WORK"
BIN="$(find "$WORK" -type f -name 'hiddify*' -perm -u+x | head -n 1)"
[ -n "$BIN" ] || BIN="$(find "$WORK" -type f -name 'hiddify*' | head -n 1)"
if [ -z "$BIN" ]; then echo "HTM-ERROR: no hiddify binary inside the tarball."; exit 6; fi

install -m 0755 -o root -g root "$BIN" {binary}
printf '%s\n' "$TAG" > {version_file}
chmod 0644 {version_file}

if ! {{ {binary} version >/dev/null 2>&1 || {binary} --help >/dev/null 2>&1; }}; then
  echo "HTM-ERROR: the installed Hiddify Core binary does not run on this host."; exit 7
fi

echo "HTM-VERSION: $TAG"
echo "Installed Hiddify Core $TAG."
"#,
        owner = REPO_OWNER,
        repo = REPO_NAME,
        arch = arch,
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
            provider: "Hiddify Core".to_string(),
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
    ctx.success(&format!("Hiddify Core {version} installed."));
    Ok(InstalledVersion {
        version: version.clone(),
        binary_path: BINARY_PATH.to_string(),
        origin: format!("release {version}"),
    })
}

/// Generate the self-signed certificate the TLS protocols need on the exit.
pub fn ensure_certificate(
    ctx: &HostCtx<'_>,
    cert_path: &str,
    key_path: &str,
    server_name: &str,
) -> Result<()> {
    if ctx.client.path_exists(cert_path)? && ctx.client.path_exists(key_path)? {
        ctx.debug("TLS certificate already present.");
        return Ok(());
    }
    if !ctx.client.has_command("openssl")? {
        ctx.info("Installing openssl to generate the TLS certificate.");
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
                provider: "Hiddify Core".to_string(),
                detail:
                    "openssl could not be installed, so the TLS certificate cannot be \
                         generated. Choose a non-TLS protocol (Shadowsocks, VMess, VLESS or SOCKS)."
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
            provider: "Hiddify Core".to_string(),
            detail: format!(
                "the TLS certificate could not be generated: {}",
                crate::util::truncate(&out.combined(), 300)
            ),
        });
    }
    ctx.success("TLS certificate ready.");
    Ok(())
}

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
rm -rf {workdir}
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Removed Hiddify Core."
exit 0
"#,
        prefix = super::config::SERVICE_PREFIX,
        template = super::config::UNIT_TEMPLATE,
        install_dir = INSTALL_DIR,
        config_dir = CONFIG_DIR,
        workdir = WORKDIR_BASE,
    );
    let out = ctx.client.run_script(&script, true)?;
    if !out.ok() {
        return Err(Error::Provider {
            provider: "Hiddify Core".to_string(),
            detail: format!(
                "uninstall failed: {}",
                crate::util::truncate(&out.combined(), 300)
            ),
        });
    }
    ctx.success("Hiddify Core removed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architectures_map_to_release_tokens() {
        assert_eq!(release_arch("x86_64"), Some("amd64"));
        assert_eq!(release_arch("aarch64"), Some("arm64"));
        assert_eq!(release_arch("armv7l"), Some("armv7"));
        assert_eq!(release_arch("sparc"), None);
    }
}
