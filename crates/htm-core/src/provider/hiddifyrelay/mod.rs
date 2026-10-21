//! The Hiddify Relay provider.
//!
//! This wraps the Hiddify Relay Builder's six methods — IP-Tables, GOST,
//! Dokodemo-Door (Xray), HAProxy, Socat and WST (wstunnel) — as HTM tunnels.
//! A relay listens on a set of ports and forwards each to an upstream "main
//! server"; HTM maps the relay onto the client/relay side and the upstream onto
//! the exit's public address.
//!
//! It is a [`TunnelModel::RelayForward`] provider: there is no TUN link, so the
//! throughput benchmark does not apply, and readiness is the forwarder's ports
//! actually listening (except kernel NAT, which opens no socket). Only the WST
//! method configures the upstream; the other five manage the relay alone.
//!
//! See the Hiddify Relay Builder: <https://github.com/hiddify/hiddify-relay>.

pub mod config;
pub mod install;

use crate::error::{Error, Result};
use crate::model::{
    BenchVariant, MatrixSelection, OptionMap, OptionSpace, PackageManager, TunnelPlan, TunnelSide,
};
use crate::provider::{
    HostCtx, InstallMethod, InstalledVersion, Readiness, ReadinessProbe, RemoteFile, RenderedSide,
    TunnelModel, TunnelProvider,
};
use crate::remote::systemd;
use crate::util::sh_quote;

use config::{method_of, BASE_DIR};

#[derive(Debug, Default, Clone, Copy)]
pub struct HiddifyRelayProvider;

impl HiddifyRelayProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TunnelProvider for HiddifyRelayProvider {
    fn id(&self) -> &'static str {
        "hiddifyrelay"
    }

    fn name(&self) -> &'static str {
        "Hiddify Relay"
    }

    fn description(&self) -> &'static str {
        "Relay a set of ports to an upstream main server using one of the Hiddify Relay Builder's \
         six methods: IP-Tables, GOST, Dokodemo-Door, HAProxy, Socat or WST (wstunnel)."
    }

    fn homepage(&self) -> &'static str {
        "https://github.com/hiddify/hiddify-relay"
    }

    fn model(&self) -> TunnelModel {
        TunnelModel::RelayForward
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
        config::expand(selection)
    }

    fn default_matrix(&self) -> MatrixSelection {
        config::default_matrix()
    }

    fn matrix_presets(&self) -> Vec<crate::provider::MatrixPreset> {
        config::presets()
    }

    fn bench_access(&self, _plan: &TunnelPlan) -> crate::provider::BenchAccess {
        // Every method forwards the measurement port to the exit, so the
        // relay→exit path is measured to the relay's local forwarded port.
        // (IP-Tables is excluded from the default sweep; its kernel DNAT cannot
        // be measured from the relay itself, so a hand-built iptables variant
        // would simply fail to measure.)
        crate::provider::BenchAccess::LocalForward
    }

    fn required_packages(&self, _manager: PackageManager) -> Vec<String> {
        // Base relay prerequisites; the per-method forwarder is installed at
        // deploy time once the method is known.
        vec![
            crate::remote::pkg::logical::CURL.to_string(),
            crate::remote::pkg::logical::CA_CERTS.to_string(),
            crate::remote::pkg::logical::IPROUTE2.to_string(),
        ]
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
            provider: "Hiddify Relay".to_string(),
            detail,
        })?;

        let files = config::render_side(plan, side)
            .into_iter()
            .map(|f| RemoteFile {
                path: f.path,
                content: f.content,
                mode: f.mode,
                description: f.description,
            })
            .collect();

        Ok(RenderedSide {
            side,
            files,
            service: self.service_name(&plan.instance),
        })
    }

    fn deploy(&self, ctx: &HostCtx<'_>, plan: &TunnelPlan) -> Result<RenderedSide> {
        let rendered = self.render(plan, ctx.side)?;

        // The upstream side is only touched by the WST method; for every other
        // method there is nothing to write there, so skip it cleanly.
        if rendered.files.is_empty() {
            ctx.debug("This method does not configure the upstream; nothing to deploy here.");
            return Ok(rendered);
        }

        let method = method_of(&config::normalize(&plan.options));
        ctx.check()?;
        install::ensure_method_installed(ctx, method)?;

        ctx.check()?;
        ctx.client.exec_priv_ok(&format!(
            "mkdir -p {dir} && chmod 0750 {dir}",
            dir = sh_quote(&config::config_dir(&plan.instance))
        ))?;

        for file in &rendered.files {
            ctx.check()?;
            ctx.debug(&format!("Writing {}", file.path));
            ctx.client
                .write_file_priv(&file.path, &file.content, &file.mode)?;
        }

        systemd::daemon_reload(ctx.client)?;
        ctx.success(&format!(
            "Deployed relay instance '{}' ({}) as {}.",
            plan.instance,
            method.id(),
            rendered.service
        ));
        Ok(rendered)
    }

    fn remove_instance(&self, ctx: &HostCtx<'_>, instance: &str) -> Result<()> {
        let unit = self.service_name(instance);
        systemd::remove_unit(ctx.client, &unit)?;
        ctx.client.run_script(
            &format!(
                "#!/bin/sh\nrm -rf {dir}\nexit 0\n",
                dir = sh_quote(&config::config_dir(instance))
            ),
            true,
        )?;
        ctx.success(&format!("Removed relay instance '{instance}'."));
        Ok(())
    }

    fn service_name(&self, instance: &str) -> String {
        config::service_name(instance)
    }

    fn config_path(&self, instance: &str) -> String {
        config::config_dir(instance)
    }

    fn list_instances(&self, ctx: &HostCtx<'_>) -> Result<Vec<String>> {
        let out = ctx.client.exec(&format!(
            "ls -1 {base} 2>/dev/null || true",
            base = sh_quote(BASE_DIR)
        ))?;
        let mut names: Vec<String> = out
            .stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn managed_sides(&self, options: &OptionMap) -> Vec<TunnelSide> {
        if method_of(&config::normalize(options)).manages_upstream() {
            vec![TunnelSide::Server, TunnelSide::Client]
        } else {
            // Relay only; the upstream is an unchanged destination.
            vec![TunnelSide::Client]
        }
    }

    fn readiness_probes(&self, plan: &TunnelPlan) -> Vec<ReadinessProbe> {
        let mut out = Vec::new();
        for side in [TunnelSide::Client, TunnelSide::Server] {
            for (port, tcp) in config::readiness_ports(plan, side) {
                out.push(if tcp {
                    ReadinessProbe::TcpPort { side, port }
                } else {
                    ReadinessProbe::UdpPort { side, port }
                });
            }
        }
        out
    }

    fn readiness(&self) -> Readiness {
        Readiness {
            ready_markers: vec!["listening".to_string(), "started".to_string()],
            fatal_markers: vec![
                "Address already in use".to_string(),
                "Permission denied".to_string(),
                "Operation not permitted".to_string(),
                "cannot bind".to_string(),
                "command not found".to_string(),
                "No such file or directory".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EndpointPlan, OptValue, SpoofPlan};
    use crate::provider::hiddifyrelay::config::RelayMethod;
    use crate::provider::{ReadinessProbe, TunnelModel};

    fn plan_with(method: &str) -> TunnelPlan {
        let mut p = TunnelPlan {
            instance: "demo".into(),
            provider_id: "hiddifyrelay".into(),
            client: EndpointPlan {
                side: TunnelSide::Client,
                iface: "eth0".into(),
                real_ip: "198.51.100.1".into(),
                public_ip: "198.51.100.1".into(),
                tun_ip: "10.66.0.2".into(),
                spoofed_ip: "198.51.100.1".into(),
            },
            server: EndpointPlan {
                side: TunnelSide::Server,
                iface: "ens3".into(),
                real_ip: "203.0.113.9".into(),
                public_ip: "203.0.113.9".into(),
                tun_ip: "10.66.0.1".into(),
                spoofed_ip: "203.0.113.9".into(),
            },
            tun_netmask: "255.255.255.252".into(),
            tun_name: "rel0".into(),
            data_port: 443,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![443, 80],
            mtu: 1380,
            tun_mtu: 1380,
            log_level: "info".into(),
            spoofing: SpoofPlan::default(),
            options: config::option_space().defaults(),
        };
        p.options
            .insert(config::keys::METHOD.into(), OptValue::Choice(method.into()));
        p
    }

    #[test]
    fn it_is_a_relay_forward_provider_that_sweeps_userspace_methods() {
        let p = HiddifyRelayProvider::new();
        assert_eq!(p.model(), TunnelModel::RelayForward);
        // The default benchmark sweeps the four userspace forwarders.
        assert_eq!(p.expand_variants(&p.default_matrix()).len(), 4);
        assert_eq!(
            p.bench_access(&plan_with("gost")),
            crate::provider::BenchAccess::LocalForward
        );
    }

    #[test]
    fn most_methods_manage_the_relay_only() {
        let p = HiddifyRelayProvider::new();
        let gost = plan_with("gost");
        assert_eq!(p.managed_sides(&gost.options), vec![TunnelSide::Client]);
    }

    #[test]
    fn wst_manages_both_sides() {
        let p = HiddifyRelayProvider::new();
        let wst = plan_with("wst");
        assert_eq!(
            p.managed_sides(&wst.options),
            vec![TunnelSide::Server, TunnelSide::Client]
        );
    }

    #[test]
    fn render_gives_the_relay_a_unit_and_the_upstream_nothing_for_gost() {
        let p = HiddifyRelayProvider::new();
        let relay = p.render(&plan_with("gost"), TunnelSide::Client).unwrap();
        assert!(!relay.files.is_empty());
        let upstream = p.render(&plan_with("gost"), TunnelSide::Server).unwrap();
        assert!(
            upstream.files.is_empty(),
            "gost leaves the upstream untouched"
        );
    }

    #[test]
    fn readiness_probes_the_forwarded_ports() {
        let p = HiddifyRelayProvider::new();
        let probes = p.readiness_probes(&plan_with("gost"));
        assert!(probes.contains(&ReadinessProbe::TcpPort {
            side: TunnelSide::Client,
            port: 443
        }));
        // iptables has no listening socket to probe.
        assert!(p.readiness_probes(&plan_with("iptables")).is_empty());
    }

    #[test]
    fn service_name_and_config_dir_are_namespaced() {
        let p = HiddifyRelayProvider::new();
        assert_eq!(p.service_name("demo"), "htm-hiddifyrelay-demo.service");
        assert_eq!(p.config_path("demo"), "/etc/htm-hiddifyrelay/demo");
    }

    #[test]
    fn every_method_renders_a_relay_unit() {
        let p = HiddifyRelayProvider::new();
        for m in RelayMethod::ALL {
            let rendered = p.render(&plan_with(m.id()), TunnelSide::Client).unwrap();
            assert!(
                rendered
                    .files
                    .iter()
                    .any(|f| f.path.contains("/etc/systemd/system/")),
                "{} produced no unit",
                m.id()
            );
        }
    }

    #[test]
    fn defaults_validate() {
        let p = HiddifyRelayProvider::new();
        assert!(p.validate_options(&p.default_options()).is_ok());
    }
}
