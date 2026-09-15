//! The CandyTunnel provider.
//!
//! CandyTunnel is an IP-spoofing tunnel for heavily filtered networks. It
//! forges source addresses in both directions and offers seven transports,
//! ChaCha20 encryption, frame multiplexing, XOR forward error correction and
//! several inspection-evasion tricks.
//!
//! Two things about the upstream project shape this integration:
//!
//! * **Only the unified `candy-tunnel` binary is usable unattended.** The
//!   separate `server` binary prompts for a license password on stdin and
//!   verifies it against a remote service, which cannot work under systemd.
//!   HTM installs and runs only the unified binary, exactly as upstream's own
//!   systemd unit does.
//! * **Source builds are heavy.** The QUIC transport depends on quiche, which
//!   builds BoringSSL, which needs CMake and Go on top of a C toolchain and
//!   Rust 1.75. The published x86_64 binary avoids all of that and is the
//!   default wherever it fits.
//!
//! See <https://github.com/AmiRCandy/CandyTunnel>.

pub mod config;
pub mod install;
pub mod profiles;

use crate::error::{Error, Result};
use crate::model::{
    BenchVariant, MatrixSelection, OptionMap, OptionSpace, PackageManager, TunnelPlan, TunnelSide,
};
use crate::provider::{
    HostCtx, InstallMethod, InstalledVersion, MatrixPreset, Readiness, RemoteFile, RenderedSide,
    TunnelProvider,
};
use crate::remote::{pkg, systemd};
use crate::util::sh_quote;

use config::{keys, CONFIG_DIR, SERVICE_PREFIX, UNIT_TEMPLATE};

/// The provider implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct CandyTunnelProvider;

impl CandyTunnelProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TunnelProvider for CandyTunnelProvider {
    fn id(&self) -> &'static str {
        "candytunnel"
    }

    fn name(&self) -> &'static str {
        "CandyTunnel"
    }

    fn description(&self) -> &'static str {
        "Bidirectional IP-spoofing tunnel with seven transports, ChaCha20 encryption, frame \
         multiplexing, XOR error correction and inspection-evasion options."
    }

    fn homepage(&self) -> &'static str {
        "https://github.com/AmiRCandy/CandyTunnel"
    }

    fn option_space(&self) -> OptionSpace {
        config::option_space()
    }

    fn default_options(&self) -> OptionMap {
        config::normalize(&config::option_space().defaults())
    }

    fn validate_options(&self, options: &OptionMap) -> std::result::Result<(), String> {
        config::validate(options)
    }

    fn expand_variants(&self, selection: &MatrixSelection) -> Vec<BenchVariant> {
        profiles::expand(selection)
    }

    fn default_matrix(&self) -> MatrixSelection {
        profiles::default_matrix()
    }

    fn matrix_presets(&self) -> Vec<MatrixPreset> {
        profiles::presets()
    }

    fn required_packages(&self, _manager: PackageManager) -> Vec<String> {
        pkg::RUNTIME_PACKAGES
            .iter()
            .map(|p| (*p).to_string())
            .collect()
    }

    fn detect(&self, ctx: &HostCtx<'_>) -> Result<Option<InstalledVersion>> {
        install::detect(ctx)
    }

    fn install(&self, ctx: &HostCtx<'_>, method: InstallMethod) -> Result<InstalledVersion> {
        install::install(ctx, method)
    }

    fn uninstall(&self, ctx: &HostCtx<'_>) -> Result<()> {
        install::uninstall(ctx)
    }

    fn render(&self, plan: &TunnelPlan, side: TunnelSide) -> Result<RenderedSide> {
        config::validate_plan(plan).map_err(|detail| Error::Provider {
            provider: "CandyTunnel".to_string(),
            detail,
        })?;

        let toml = config::render_toml(plan, side);
        let mut files = vec![RemoteFile {
            path: self.config_path(&plan.instance),
            content: toml,
            // The file carries the pre-shared key, so it is root-only.
            mode: "0600".to_string(),
            description: format!("CandyTunnel {} configuration", side.as_str()),
        }];

        files.push(RemoteFile {
            path: format!("{}/{}", systemd::UNIT_DIR, UNIT_TEMPLATE),
            content: config::unit_template(),
            mode: "0644".to_string(),
            description: "systemd template unit".to_string(),
        });

        Ok(RenderedSide {
            side,
            files,
            service: self.service_name(&plan.instance),
        })
    }

    fn deploy(&self, ctx: &HostCtx<'_>, plan: &TunnelPlan) -> Result<RenderedSide> {
        let rendered = self.render(plan, ctx.side)?;
        ctx.check()?;

        // The config directory holds secrets, so keep it off-limits to other
        // users on the box.
        ctx.client.exec_priv_ok(&format!(
            "mkdir -p {dir} && chown root:root {dir} && chmod 0750 {dir}",
            dir = sh_quote(CONFIG_DIR)
        ))?;

        // QUIC needs a certificate, and only the exit side presents one.
        let options = config::normalize(&plan.options);
        if config::needs_quic_certificate(&options) && ctx.side == TunnelSide::Server {
            ctx.check()?;
            install::ensure_quic_certificate(
                ctx,
                &config::quic_cert_path(&plan.instance),
                &config::quic_key_path(&plan.instance),
                &options.get(keys::QUIC_SERVER_NAME).and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "CandyTunnel".to_string()),
            )?;
        }

        for file in &rendered.files {
            ctx.check()?;
            ctx.debug(&format!("Writing {}", file.path));
            ctx.client
                .write_file_priv(&file.path, &file.content, &file.mode)?;
        }

        systemd::daemon_reload(ctx.client)?;
        ctx.success(&format!(
            "Deployed instance '{}' as {}.",
            plan.instance, rendered.service
        ));
        Ok(rendered)
    }

    fn remove_instance(&self, ctx: &HostCtx<'_>, instance: &str) -> Result<()> {
        let unit = self.service_name(instance);
        systemd::remove_unit(ctx.client, &unit)?;

        let script = format!(
            r#"#!/bin/sh
rm -f {config}
rm -f {quic_cert} {quic_key}
exit 0
"#,
            config = sh_quote(&self.config_path(instance)),
            quic_cert = sh_quote(&config::quic_cert_path(instance)),
            quic_key = sh_quote(&config::quic_key_path(instance)),
        );
        ctx.client.run_script(&script, true)?;
        ctx.success(&format!("Removed instance '{instance}'."));
        Ok(())
    }

    fn service_name(&self, instance: &str) -> String {
        format!("{SERVICE_PREFIX}@{instance}.service")
    }

    fn config_path(&self, instance: &str) -> String {
        format!("{CONFIG_DIR}/{instance}.toml")
    }

    fn list_instances(&self, ctx: &HostCtx<'_>) -> Result<Vec<String>> {
        let out = ctx.client.exec(&format!(
            "ls -1 {dir}/*.toml 2>/dev/null || true",
            dir = sh_quote(CONFIG_DIR)
        ))?;
        let mut names: Vec<String> = out
            .stdout
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let file = line.rsplit('/').next()?;
                file.strip_suffix(".toml").map(|s| s.to_string())
            })
            .filter(|n| !n.is_empty())
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn readiness(&self) -> Readiness {
        Readiness {
            // Emitted by `run_tun_client` once every tunnel has handshaken, and
            // by `run_server` as each tunnel is accepted.
            ready_markers: vec![
                "tunnels established".to_string(),
                "tunnel ready".to_string(),
                " ready".to_string(),
                "TUN ".to_string(),
            ],
            // Conditions CandyTunnel bails out on, where waiting is pointless.
            fatal_markers: vec![
                "handshake timed out".to_string(),
                "quic requires both".to_string(),
                "shuffle_data_port is not supported".to_string(),
                "channel_capacity must be".to_string(),
                "tunnel_count must be".to_string(),
                "Cannot read config".to_string(),
                "Invalid config".to_string(),
                "Permission denied".to_string(),
                "Operation not permitted".to_string(),
                "Address already in use".to_string(),
                "No such device".to_string(),
            ],
        }
    }

    fn symmetric_option_keys(&self) -> Vec<&'static str> {
        // CandyTunnel refuses to interoperate, or silently drops frames, when
        // these differ between the two sides.
        vec![
            keys::UPLINK,
            keys::DOWNLINK,
            keys::XOR,
            keys::ICMP_ID,
            keys::PADDING,
            keys::PADDING_MAX,
            keys::TTL_JITTER,
            keys::FAKE_TLS,
            keys::RANDOM_DSCP,
            keys::MULTIPLEX,
            keys::FEC,
            keys::FEC_GROUP,
            keys::SHUFFLE_PORT,
        ]
    }
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
                tun_ip: "10.54.21.2".into(),
                spoofed_ip: "192.0.2.10".into(),
            },
            server: EndpointPlan {
                side: TunnelSide::Server,
                iface: "ens3".into(),
                real_ip: "198.51.100.5".into(),
                public_ip: "198.51.100.5".into(),
                tun_ip: "10.54.21.1".into(),
                spoofed_ip: "198.51.100.5".into(),
            },
            tun_netmask: "255.255.255.252".into(),
            tun_name: "candy0".into(),
            data_port: 8443,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![443],
            mtu: 1380,
            tun_mtu: 1380,
            log_level: "info".into(),
            spoofing: SpoofPlan::default(),
            options: config::option_space().defaults(),
        }
    }

    #[test]
    fn unit_and_config_paths_are_namespaced_to_htm() {
        let p = CandyTunnelProvider::new();
        assert_eq!(
            p.service_name("demo"),
            "htm-candytunnel@demo.service"
        );
        assert_eq!(p.config_path("demo"), "/etc/candytunnel/demo.toml");
    }

    #[test]
    fn rendering_produces_a_config_and_a_unit() {
        let p = CandyTunnelProvider::new();
        let rendered = p.render(&plan(), TunnelSide::Client).expect("rendered");
        assert_eq!(rendered.files.len(), 2);
        let cfg = &rendered.files[0];
        assert_eq!(cfg.mode, "0600", "the key must not be world readable");
        assert!(cfg.content.contains("role = \"client\""));
        assert!(rendered.files[1].path.ends_with("htm-candytunnel@.service"));
    }

    #[test]
    fn a_broken_plan_is_refused_before_anything_is_uploaded() {
        let p = CandyTunnelProvider::new();
        let mut bad = plan();
        bad.pre_shared_key = "short".into();
        assert!(p.render(&bad, TunnelSide::Client).is_err());
    }

    #[test]
    fn defaults_are_already_normalised() {
        let p = CandyTunnelProvider::new();
        let defaults = p.default_options();
        assert!(p.validate_options(&defaults).is_ok());
        assert_eq!(config::normalize(&defaults), defaults);
    }

    #[test]
    fn symmetric_keys_all_exist_in_the_option_space() {
        let p = CandyTunnelProvider::new();
        let space = p.option_space();
        for key in p.symmetric_option_keys() {
            assert!(space.get(key).is_some(), "unknown option key '{key}'");
        }
    }

    #[test]
    fn every_benchmarkable_option_offers_values_to_sweep() {
        let space = CandyTunnelProvider::new().option_space();
        for spec in space.benchmarkable() {
            assert!(
                !spec.sweep_values().is_empty(),
                "{} has nothing to sweep",
                spec.key
            );
        }
    }
}
