//! The CopyTunnel provider.
//!
//! CopyTunnel is a point-to-point encrypted TUN tunnel: the relay captures
//! IPv4 TCP/UDP through a TUN device, seals each packet with one of six wire
//! ciphers, and relays it to the exit over UDP, where the kernel routes and
//! NATs it onward. That is HTM's native shape, so CopyTunnel slots in beside
//! CandyTunnel as a [`TunnelModel::PointToPointTun`] provider: the same deploy
//! flow, the same ICMP-across-the-TUN readiness test, and the same throughput
//! benchmark all apply unchanged.
//!
//! Only CopyTunnel's TUN mode is driven here. Its transparent-proxy mode needs
//! sing-box and iptables TPROXY and exposes no TUN link, so it is out of scope
//! for this provider.
//!
//! See <https://github.com/Hiddify2/CopyTunnel>.

pub mod config;
pub mod install;
pub mod profiles;

use crate::error::{Error, Result};
use crate::model::{
    BenchVariant, MatrixSelection, OptionMap, OptionSpace, PackageManager, TunnelPlan, TunnelSide,
};
use crate::provider::{
    HostCtx, InstallMethod, InstalledVersion, MatrixPreset, Readiness, RemoteFile, RenderedSide,
    TunnelModel, TunnelProvider,
};
use crate::remote::{pkg, systemd};
use crate::util::sh_quote;

use config::{keys, CONFIG_DIR, SERVICE_PREFIX, UNIT_TEMPLATE};

#[derive(Debug, Default, Clone, Copy)]
pub struct CopyTunnelProvider;

impl CopyTunnelProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TunnelProvider for CopyTunnelProvider {
    fn id(&self) -> &'static str {
        "copytunnel"
    }

    fn name(&self) -> &'static str {
        "CopyTunnel"
    }

    fn description(&self) -> &'static str {
        "Point-to-point encrypted layer-3 TUN tunnel over UDP, with six selectable wire ciphers \
         (ChaCha20-Poly1305, AES-GCM and more) and an optional whole-frame obfuscation layer."
    }

    fn homepage(&self) -> &'static str {
        "https://github.com/Hiddify2/CopyTunnel"
    }

    fn model(&self) -> TunnelModel {
        TunnelModel::PointToPointTun
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
            provider: "CopyTunnel".to_string(),
            detail,
        })?;

        let toml = config::render_toml(plan, side);
        let files = vec![
            RemoteFile {
                path: self.config_path(&plan.instance),
                content: toml,
                mode: "0600".to_string(),
                description: format!("CopyTunnel {} configuration", side.as_str()),
            },
            RemoteFile {
                path: format!("{}/{}", systemd::UNIT_DIR, UNIT_TEMPLATE),
                content: config::unit_template(),
                mode: "0644".to_string(),
                description: "systemd template unit".to_string(),
            },
        ];

        Ok(RenderedSide {
            side,
            files,
            service: self.service_name(&plan.instance),
        })
    }

    fn deploy(&self, ctx: &HostCtx<'_>, plan: &TunnelPlan) -> Result<RenderedSide> {
        let rendered = self.render(plan, ctx.side)?;
        ctx.check()?;

        ctx.client.exec_priv_ok(&format!(
            "mkdir -p {dir} && chown root:root {dir} && chmod 0750 {dir}",
            dir = sh_quote(CONFIG_DIR)
        ))?;

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
        ctx.client.run_script(
            &format!(
                "#!/bin/sh\nrm -f {config}\nexit 0\n",
                config = sh_quote(&self.config_path(instance))
            ),
            true,
        )?;
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
                let file = line.trim().rsplit('/').next()?;
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
            ready_markers: vec![
                "TUN interface".to_string(),
                "is up".to_string(),
                "listening for clients".to_string(),
                "relaying to server".to_string(),
            ],
            fatal_markers: vec![
                "Cannot read config".to_string(),
                "invalid config".to_string(),
                "Permission denied".to_string(),
                "Operation not permitted".to_string(),
                "Address already in use".to_string(),
                "No such device".to_string(),
                "failed to open TUN".to_string(),
            ],
        }
    }

    fn symmetric_option_keys(&self) -> Vec<&'static str> {
        // The two sides must agree on the cipher and the obfuscation layer, or
        // every frame fails to authenticate and the tunnel looks silent. HTM
        // renders both sides from one plan, so they cannot drift.
        vec![keys::CIPHER, keys::OBFUSCATE, keys::FORWARD_PROTOCOLS]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EndpointPlan, OptionMapExt, FakePlan};
    use crate::provider::TunnelModel;

    fn plan() -> TunnelPlan {
        TunnelPlan {
            instance: "demo".into(),
            provider_id: "copytunnel".into(),
            client: EndpointPlan {
                side: TunnelSide::Client,
                iface: "eth0".into(),
                real_ip: "192.0.2.10".into(),
                public_ip: "192.0.2.10".into(),
                tun_ip: "10.66.0.2".into(),
                faked_ip: "192.0.2.10".into(),
            },
            server: EndpointPlan {
                side: TunnelSide::Server,
                iface: "ens3".into(),
                real_ip: "198.51.100.5".into(),
                public_ip: "198.51.100.5".into(),
                tun_ip: "10.66.0.1".into(),
                faked_ip: "198.51.100.5".into(),
            },
            tun_netmask: "255.255.255.252".into(),
            tun_name: "copy0".into(),
            data_port: 51822,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![443],
            mtu: 1380,
            tun_mtu: 1380,
            log_level: "info".into(),
            faking: FakePlan::default(),
            options: config::option_space().defaults(),
        }
    }

    #[test]
    fn it_is_a_point_to_point_tun_provider_managing_both_sides() {
        let p = CopyTunnelProvider::new();
        assert_eq!(p.model(), TunnelModel::PointToPointTun);
        assert_eq!(p.managed_sides(&p.default_options()).len(), 2);
        assert!(p.readiness_probes(&plan()).is_empty());
    }

    #[test]
    fn units_and_config_paths_are_namespaced_to_htm() {
        let p = CopyTunnelProvider::new();
        assert_eq!(p.service_name("demo"), "htm-copytunnel@demo.service");
        assert_eq!(p.config_path("demo"), "/etc/htm-copytunnel/demo.toml");
    }

    #[test]
    fn rendering_produces_a_config_and_a_unit() {
        let p = CopyTunnelProvider::new();
        let rendered = p.render(&plan(), TunnelSide::Client).expect("rendered");
        assert_eq!(rendered.files.len(), 2);
        assert_eq!(
            rendered.files[0].mode, "0600",
            "the key must not be world readable"
        );
        assert!(rendered.files[0].content.contains("role = \"client\""));
        assert!(rendered.files[1].path.ends_with("htm-copytunnel@.service"));
    }

    #[test]
    fn defaults_are_valid_and_normalised() {
        let p = CopyTunnelProvider::new();
        let defaults = p.default_options();
        assert!(p.validate_options(&defaults).is_ok());
        assert_eq!(config::normalize(&defaults), defaults);
        assert_eq!(defaults.str_or(keys::CIPHER, ""), "chacha20poly1305");
    }

    #[test]
    fn symmetric_keys_all_exist_in_the_option_space() {
        let p = CopyTunnelProvider::new();
        let space = p.option_space();
        for key in p.symmetric_option_keys() {
            assert!(space.get(key).is_some(), "unknown option key '{key}'");
        }
    }

    #[test]
    fn every_benchmarkable_option_offers_values_to_sweep() {
        let space = CopyTunnelProvider::new().option_space();
        for spec in space.benchmarkable() {
            assert!(
                !spec.sweep_values().is_empty(),
                "{} has nothing to sweep",
                spec.key
            );
        }
    }

    #[test]
    fn a_forged_plan_is_refused_before_anything_is_uploaded() {
        let p = CopyTunnelProvider::new();
        let mut bad = plan();
        bad.faking = FakePlan::from_list(&["8.8.8.8".into(), "1.1.1.1".into()]);
        bad.client.faked_ip = "8.8.8.8".into();
        bad.server.faked_ip = "1.1.1.1".into();
        assert!(p.render(&bad, TunnelSide::Client).is_err());
    }

    #[test]
    fn a_short_key_is_refused() {
        let p = CopyTunnelProvider::new();
        let mut bad = plan();
        bad.pre_shared_key = "short".into();
        assert!(p.render(&bad, TunnelSide::Client).is_err());
    }
}
