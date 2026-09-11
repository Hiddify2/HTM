//! Installing distribution packages.
//!
//! HTM names packages logically ("ping", "iproute2", "toolchain-c") and this
//! module maps each one onto what the host's package manager actually calls
//! it. A package that genuinely does not exist on a distribution maps to
//! nothing and is skipped rather than failing the install.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::jobs::{LogLevel, Reporter};
use crate::model::PackageManager;
use crate::ssh::SshClient;
use crate::util::sh_join;

/// Logical package names HTM knows how to install.
pub mod logical {
    /// Fetch files over HTTPS.
    pub const CURL: &str = "curl";
    /// `ip`, needed for interface and route inspection.
    pub const IPROUTE2: &str = "iproute2";
    /// Client-side port forwarding rules.
    pub const IPTABLES: &str = "iptables";
    /// `ping`, used for latency measurement and readiness checks.
    pub const PING: &str = "ping";
    /// Root certificates, without which HTTPS downloads fail on minimal images.
    pub const CA_CERTS: &str = "ca-certificates";
    /// The throughput benchmark tool.
    pub const IPERF3: &str = "iperf3";
    /// Interpreter for HTM's bundled throughput probe.
    pub const PYTHON3: &str = "python3";
    /// Source checkout.
    pub const GIT: &str = "git";
    /// C compiler and make, needed by several Rust crates' build scripts.
    pub const TOOLCHAIN_C: &str = "toolchain-c";
    /// CMake, required to build BoringSSL for the QUIC transport.
    pub const CMAKE: &str = "cmake";
    /// Go, also required by BoringSSL's build.
    pub const GOLANG: &str = "golang";
    /// pkg-config, used by several `-sys` crates.
    pub const PKGCONFIG: &str = "pkg-config";
    /// Perl, used by OpenSSL-style build scripts.
    pub const PERL: &str = "perl";
    /// Archive tools used when unpacking toolchains.
    pub const TAR: &str = "tar";
    /// The `openssl` command, used to generate the QUIC transport's
    /// self-signed certificate.
    pub const OPENSSL: &str = "openssl";
}

/// What every host needs before a tunnel can run.
pub const RUNTIME_PACKAGES: &[&str] = &[
    logical::CURL,
    logical::CA_CERTS,
    logical::IPROUTE2,
    logical::IPTABLES,
    logical::PING,
];

/// What the benchmark engine needs on top of that.
pub const BENCHMARK_PACKAGES: &[&str] = &[logical::IPERF3, logical::PYTHON3];

/// What a source build needs. This is a lot, because CandyTunnel's QUIC
/// transport pulls in BoringSSL, whose build requires both CMake and Go.
pub const BUILD_PACKAGES: &[&str] = &[
    logical::GIT,
    logical::TOOLCHAIN_C,
    logical::CMAKE,
    logical::GOLANG,
    logical::PKGCONFIG,
    logical::PERL,
    logical::TAR,
];

/// Translate a logical name into the concrete package(s) for a distribution.
///
/// Returns an empty vector when the distribution has no such package, which
/// means "nothing to do" rather than an error.
pub fn concrete_packages(logical_name: &str, manager: PackageManager) -> Vec<&'static str> {
    use PackageManager as P;
    match logical_name {
        logical::CURL => vec!["curl"],
        logical::CA_CERTS => match manager {
            P::Pacman => vec!["ca-certificates"],
            P::Apk => vec!["ca-certificates"],
            _ => vec!["ca-certificates"],
        },
        logical::IPROUTE2 => match manager {
            P::Dnf | P::Yum => vec!["iproute"],
            _ => vec!["iproute2"],
        },
        logical::IPTABLES => match manager {
            P::Dnf | P::Yum => vec!["iptables-nft"],
            _ => vec!["iptables"],
        },
        logical::PING => match manager {
            P::Apt => vec!["iputils-ping"],
            P::Dnf | P::Yum | P::Zypper => vec!["iputils"],
            P::Pacman => vec!["iputils"],
            P::Apk => vec!["iputils-ping"],
            P::Unknown => vec![],
        },
        logical::IPERF3 => vec!["iperf3"],
        logical::PYTHON3 => match manager {
            P::Pacman => vec!["python"],
            _ => vec!["python3"],
        },
        logical::GIT => vec!["git"],
        logical::TOOLCHAIN_C => match manager {
            P::Apt => vec!["build-essential"],
            P::Dnf | P::Yum => vec!["gcc", "gcc-c++", "make"],
            P::Pacman => vec!["base-devel"],
            P::Apk => vec!["build-base"],
            P::Zypper => vec!["gcc", "gcc-c++", "make"],
            P::Unknown => vec![],
        },
        logical::CMAKE => vec!["cmake"],
        logical::GOLANG => match manager {
            P::Apt => vec!["golang-go"],
            P::Dnf | P::Yum => vec!["golang"],
            P::Pacman => vec!["go"],
            P::Apk => vec!["go"],
            P::Zypper => vec!["go"],
            P::Unknown => vec![],
        },
        logical::PKGCONFIG => match manager {
            P::Apt => vec!["pkg-config"],
            P::Apk => vec!["pkgconf"],
            _ => vec!["pkgconf"],
        },
        logical::PERL => vec!["perl"],
        logical::TAR => vec!["tar"],
        logical::OPENSSL => vec!["openssl"],
        _ => vec![],
    }
}

/// The shell command that installs `packages` without prompting.
fn install_command(manager: PackageManager, packages: &[String]) -> Option<String> {
    if packages.is_empty() {
        return None;
    }
    let list = sh_join(packages);
    Some(match manager {
        PackageManager::Apt => format!(
            "export DEBIAN_FRONTEND=noninteractive; apt-get install -y --no-install-recommends {list}"
        ),
        PackageManager::Dnf => format!("dnf install -y {list}"),
        PackageManager::Yum => format!("yum install -y {list}"),
        PackageManager::Pacman => format!("pacman -S --needed --noconfirm {list}"),
        PackageManager::Apk => format!("apk add --no-cache {list}"),
        PackageManager::Zypper => {
            format!("zypper --non-interactive install --no-recommends {list}")
        }
        PackageManager::Unknown => return None,
    })
}

/// The command that refreshes the package index, when the manager needs one.
fn refresh_command(manager: PackageManager) -> Option<&'static str> {
    match manager {
        PackageManager::Apt => {
            Some("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq")
        }
        PackageManager::Pacman => Some("pacman -Sy --noconfirm"),
        PackageManager::Apk => Some("apk update"),
        PackageManager::Zypper => Some("zypper --non-interactive refresh"),
        // dnf and yum refresh their metadata as part of install.
        PackageManager::Dnf | PackageManager::Yum | PackageManager::Unknown => None,
    }
}

/// Result of an install attempt.
#[derive(Debug, Clone, Default)]
pub struct InstallReport {
    /// Packages that are now present.
    pub installed: Vec<String>,
    /// Logical names the distribution has no package for.
    pub unavailable: Vec<String>,
    /// Packages the manager refused to install, with its message.
    pub failed: Vec<(String, String)>,
}

impl InstallReport {
    pub fn is_ok(&self) -> bool {
        self.failed.is_empty()
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.installed.is_empty() {
            parts.push(format!("{} installed", self.installed.len()));
        }
        if !self.unavailable.is_empty() {
            parts.push(format!("{} unavailable", self.unavailable.len()));
        }
        if !self.failed.is_empty() {
            parts.push(format!("{} failed", self.failed.len()));
        }
        if parts.is_empty() {
            "nothing to do".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Install the given logical packages, skipping any already present.
///
/// The bulk install is attempted first; only if that fails does HTM retry one
/// package at a time, so the common case stays fast while a single broken
/// package still gets named precisely.
pub fn install(
    client: &SshClient,
    manager: PackageManager,
    logical_names: &[&str],
    scope: &str,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<InstallReport> {
    let mut report = InstallReport::default();

    if manager == PackageManager::Unknown {
        return Err(Error::Unsupported {
            detail: "no supported package manager was found (apt, dnf, yum, pacman, apk or zypper)"
                .to_string(),
        });
    }

    // Resolve names and drop what is already installed.
    let mut wanted: Vec<String> = Vec::new();
    for name in logical_names {
        let concrete = concrete_packages(name, manager);
        if concrete.is_empty() {
            report.unavailable.push((*name).to_string());
            continue;
        }
        for c in concrete {
            if !wanted.iter().any(|w| w == c) {
                wanted.push(c.to_string());
            }
        }
    }

    if wanted.is_empty() {
        return Ok(report);
    }

    reporter.log_line(
        LogLevel::Info,
        Some(scope),
        &format!("Ensuring packages: {}", wanted.join(", ")),
    );

    if let Some(refresh) = refresh_command(manager) {
        reporter.check()?;
        reporter.log_line(
            LogLevel::Debug,
            Some(scope),
            "Refreshing the package index",
        );
        // A stale index is common and not always fatal, so a refresh failure is
        // a warning; the install below will surface anything that matters.
        client.set_command_timeout(300);
        let refreshed = client.exec_priv(refresh);
        client.reset_command_timeout();
        match refreshed {
            Ok(out) if !out.ok() => reporter.log_line(
                LogLevel::Warn,
                Some(scope),
                &format!(
                    "Package index refresh reported a problem; continuing anyway. {}",
                    crate::util::truncate(&out.combined(), 300)
                ),
            ),
            Err(e) => reporter.log_line(
                LogLevel::Warn,
                Some(scope),
                &format!("Package index refresh failed ({e}); continuing anyway."),
            ),
            _ => {}
        }
    }

    reporter.check()?;
    let Some(bulk) = install_command(manager, &wanted) else {
        return Ok(report);
    };

    let mut tail: Vec<String> = Vec::new();
    let status = client.run_script_stream(
        &format!("#!/bin/sh\nset -e\n{bulk}\n"),
        true,
        cancel,
        Duration::from_secs(900),
        |line| {
            let line = line.trim();
            if line.is_empty() {
                return;
            }
            reporter.log_line(LogLevel::Debug, Some(scope), line);
            tail.push(line.to_string());
            if tail.len() > 40 {
                tail.remove(0);
            }
        },
    )?;

    if status == 0 {
        report.installed = wanted;
        reporter.log_line(
            LogLevel::Success,
            Some(scope),
            &format!("{} package(s) ready", report.installed.len()),
        );
        return Ok(report);
    }

    // Retry individually so the user learns exactly which package is the
    // problem instead of staring at a wall of apt output.
    reporter.log_line(
        LogLevel::Warn,
        Some(scope),
        "Bulk install failed; retrying one package at a time to find the cause.",
    );

    for pkg in wanted {
        reporter.check()?;
        let Some(cmd) = install_command(manager, std::slice::from_ref(&pkg)) else {
            continue;
        };
        client.set_command_timeout(600);
        let out = client.exec_priv(&format!("{cmd} 2>&1"));
        client.reset_command_timeout();
        match out {
            Ok(o) if o.ok() => report.installed.push(pkg),
            Ok(o) => report
                .failed
                .push((pkg, crate::util::tail_lines(&o.combined(), 6))),
            Err(e) => report.failed.push((pkg, e.to_string())),
        }
    }

    for (pkg, why) in &report.failed {
        reporter.log_line(
            LogLevel::Error,
            Some(scope),
            &format!("Could not install '{pkg}': {why}"),
        );
    }

    Ok(report)
}

/// Root of the Rust toolchain HTM installs for source builds.
///
/// A fixed, root-owned location rather than `~/.cargo`, because the build runs
/// with elevated privileges and `$HOME` is not consistent across `sudo`
/// configurations. Putting it somewhere predictable means the build script can
/// always find `cargo`.
pub const CARGO_HOME: &str = "/opt/htm/cargo";
pub const RUSTUP_HOME: &str = "/opt/htm/rustup";
/// Absolute path to the `cargo` HTM installs.
pub const CARGO_BIN: &str = "/opt/htm/cargo/bin/cargo";

/// Install a Rust toolchain via rustup, for source builds.
///
/// rustup is used rather than the distribution's Rust because CandyTunnel needs
/// edition 2021 and Rust 1.75 or newer, which several long-term-support
/// distributions still do not ship.
///
/// Returns the `cargo --version` line of whichever toolchain will be used.
pub fn install_rust_toolchain(
    client: &SshClient,
    scope: &str,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<String> {
    let script = format!(
        r#"#!/bin/sh
set -e

CARGO_HOME={cargo_home}
RUSTUP_HOME={rustup_home}
export CARGO_HOME RUSTUP_HOME

if [ -x "$CARGO_HOME/bin/cargo" ]; then
  echo "Toolchain already present: $("$CARGO_HOME/bin/cargo" --version)"
  exit 0
fi

# A system Rust is fine if it is new enough; CandyTunnel needs 1.75.
if command -v cargo >/dev/null 2>&1; then
  SYS_VER="$(cargo --version 2>/dev/null | awk '{{ print $2 }}')"
  MAJOR="$(printf '%s' "$SYS_VER" | cut -d. -f1)"
  MINOR="$(printf '%s' "$SYS_VER" | cut -d. -f2)"
  if [ -n "$MAJOR" ] && [ -n "$MINOR" ] && [ "$MAJOR" -ge 1 ] && [ "$MINOR" -ge 75 ]; then
    echo "Using the system toolchain: $(cargo --version)"
    mkdir -p "$CARGO_HOME/bin"
    ln -sf "$(command -v cargo)" "$CARGO_HOME/bin/cargo"
    exit 0
  fi
  echo "System cargo is $SYS_VER, which is older than the required 1.75; installing rustup."
fi

echo "Installing the Rust toolchain with rustup. This usually takes a few minutes."
mkdir -p "$CARGO_HOME" "$RUSTUP_HOME"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path

"$CARGO_HOME/bin/cargo" --version
"#,
        cargo_home = crate::util::sh_quote(CARGO_HOME),
        rustup_home = crate::util::sh_quote(RUSTUP_HOME),
    );

    let mut last = String::new();
    let status = client.run_script_stream(
        &script,
        true,
        cancel,
        Duration::from_secs(2400),
        |line| {
            let line = line.trim();
            if line.is_empty() {
                return;
            }
            reporter.log_line(LogLevel::Debug, Some(scope), line);
            last = line.to_string();
        },
    )?;

    if status != 0 {
        return Err(Error::Remote {
            command: "install rust toolchain".to_string(),
            status,
            stdout: last,
            stderr: String::new(),
        });
    }

    let version = client
        .exec_priv(&format!("{CARGO_BIN} --version 2>/dev/null || true"))
        .map(|o| o.first_line().to_string())
        .unwrap_or_default();
    Ok(if version.is_empty() {
        "cargo (version unknown)".to_string()
    } else {
        version
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_is_named_differently_per_distro() {
        assert_eq!(
            concrete_packages(logical::PING, PackageManager::Apt),
            vec!["iputils-ping"]
        );
        assert_eq!(
            concrete_packages(logical::PING, PackageManager::Dnf),
            vec!["iputils"]
        );
        assert!(concrete_packages(logical::PING, PackageManager::Unknown).is_empty());
    }

    #[test]
    fn c_toolchain_expands_to_several_packages_on_rpm() {
        let pkgs = concrete_packages(logical::TOOLCHAIN_C, PackageManager::Dnf);
        assert!(pkgs.contains(&"gcc"));
        assert!(pkgs.contains(&"make"));
    }

    #[test]
    fn install_commands_are_non_interactive() {
        let cmd =
            install_command(PackageManager::Apt, &["curl".to_string()]).expect("a command");
        assert!(cmd.contains("noninteractive"));
        assert!(cmd.contains("-y"));
        assert!(install_command(PackageManager::Unknown, &["curl".into()]).is_none());
        assert!(install_command(PackageManager::Apt, &[]).is_none());
    }

    #[test]
    fn package_names_are_shell_quoted() {
        let cmd = install_command(PackageManager::Apk, &["a b".to_string()]).unwrap();
        assert!(cmd.contains("'a b'"));
    }
}
