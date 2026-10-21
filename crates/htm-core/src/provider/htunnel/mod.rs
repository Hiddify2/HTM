//! The HTunnel provider.
//!
//! HTunnel is an asymmetric UDP tunnel for heavily censored networks: the relay
//! exposes a local SOCKS5 proxy, its uplink rides an upstream SOCKS5 proxy, and
//! the exit's downlink is fake-source UDP from a pool of addresses. There is no
//! TUN device, so HTM runs it as a [`TunnelModel::SocksProxy`] provider — the
//! readiness test is the relay's SOCKS5 port actually listening, not an ICMP
//! echo across a link that does not exist, and the TUN-based throughput
//! benchmark does not apply.
//!
//! HTunnel's uplink needs an upstream SOCKS5 proxy to ride (a 3x-ui SOCKS
//! inbound, Dante, …). HTM does not stand that proxy up; set `uplink_proxy` to
//! point at an existing one, or leave it empty to have the relay dial the exit
//! directly.
//!
//! See <https://github.com/Hiddify2/HTunnel>.

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
use crate::remote::{pkg, systemd};
use crate::util::sh_quote;

use config::CONFIG_DIR;

#[derive(Debug, Default, Clone, Copy)]
pub struct HTunnelProvider;

impl HTunnelProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TunnelProvider for HTunnelProvider {
    fn id(&self) -> &'static str {
        "htunnel"
    }

    fn name(&self) -> &'static str {
        "HTunnel"
    }

    fn description(&self) -> &'static str {
        "Asymmetric UDP tunnel: the relay exposes a local SOCKS5 proxy, the uplink rides an \
         upstream SOCKS5 proxy, and the exit's downlink is fake-source UDP from an address pool. \
         No TUN device."
    }

    fn homepage(&self) -> &'static str {
        "https://github.com/Hiddify2/HTunnel"
    }

    fn model(&self) -> TunnelModel {
        TunnelModel::SocksProxy
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

    fn required_packages(&self, _manager: PackageManager) -> Vec<String> {
        // The relay's uplink and the readiness probe need `curl`/`ss` and
        // `ip`; no iptables or TUN is required.
        vec![
            pkg::logical::CURL.to_string(),
            pkg::logical::CA_CERTS.to_string(),
            pkg::logical::IPROUTE2.to_string(),
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
            provider: "HTunnel".to_string(),
            detail,
        })?;

        let files = vec![
            RemoteFile {
                path: self.config_path(&plan.instance),
                content: config::render_json(plan, side),
                mode: "0600".to_string(),
                description: format!("HTunnel {} configuration", side.as_str()),
            },
            RemoteFile {
                path: format!(
                    "{}/{}",
                    systemd::UNIT_DIR,
                    config::service_name(&plan.instance)
                ),
                content: config::unit_file(plan, side),
                mode: "0644".to_string(),
                description: "systemd unit".to_string(),
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
        config::service_name(instance)
    }

    fn config_path(&self, instance: &str) -> String {
        config::config_path(instance)
    }

    fn list_instances(&self, ctx: &HostCtx<'_>) -> Result<Vec<String>> {
        let out = ctx.client.exec(&format!(
            "ls -1 {dir}/*.json 2>/dev/null || true",
            dir = sh_quote(CONFIG_DIR)
        ))?;
        let mut names: Vec<String> = out
            .stdout
            .lines()
            .filter_map(|line| {
                let file = line.trim().rsplit('/').next()?;
                file.strip_suffix(".json").map(|s| s.to_string())
            })
            .filter(|n| !n.is_empty())
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn managed_sides(&self, _options: &OptionMap) -> Vec<TunnelSide> {
        // Both ends run HTunnel software: the relay the client, the exit the
        // server.
        vec![TunnelSide::Server, TunnelSide::Client]
    }

    fn readiness_probes(&self, plan: &TunnelPlan) -> Vec<ReadinessProbe> {
        // The one externally observable sign the tunnel is up is the relay's
        // SOCKS5 listener accepting connections.
        vec![ReadinessProbe::TcpPort {
            side: TunnelSide::Client,
            port: config::socks_port(plan),
        }]
    }

    fn bench_access(&self, plan: &TunnelPlan) -> crate::provider::BenchAccess {
        // Measured through the relay's SOCKS5 proxy to a probe server on the
        // exit's loopback.
        crate::provider::BenchAccess::Socks {
            socks_port: config::socks_port(plan),
        }
    }

    fn readiness(&self) -> Readiness {
        Readiness {
            ready_markers: vec![
                "SOCKS5 proxy listening".to_string(),
                "tunnel".to_string(),
                "established".to_string(),
            ],
            fatal_markers: vec![
                "Permission denied".to_string(),
                "Operation not permitted".to_string(),
                "Address already in use".to_string(),
                "No such device".to_string(),
                "failed to parse config".to_string(),
                "invalid config".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EndpointPlan, SpoofPlan};
    use crate::provider::{ReadinessProbe, TunnelModel};

    fn plan() -> TunnelPlan {
        TunnelPlan {
            instance: "demo".into(),
            provider_id: "htunnel".into(),
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
                real_ip: "203.0.113.1".into(),
                public_ip: "203.0.113.1".into(),
                tun_ip: "10.66.0.1".into(),
                spoofed_ip: "203.0.113.1".into(),
            },
            tun_netmask: "255.255.255.252".into(),
            tun_name: "htun0".into(),
            data_port: 51820,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![],
            mtu: 1380,
            tun_mtu: 1380,
            log_level: "info".into(),
            spoofing: SpoofPlan::default(),
            options: config::option_space().defaults(),
        }
    }

    #[test]
    fn it_is_a_socks_proxy_provider_that_probes_the_relay_socks_port() {
        let p = HTunnelProvider::new();
        assert_eq!(p.model(), TunnelModel::SocksProxy);
        assert_eq!(
            p.readiness_probes(&plan()),
            vec![ReadinessProbe::TcpPort {
                side: TunnelSide::Client,
                port: 9234
            }]
        );
    }

    #[test]
    fn it_sweeps_tunnel_counts_and_measures_over_socks() {
        let p = HTunnelProvider::new();
        assert!(!p.expand_variants(&p.default_matrix()).is_empty());
        assert_eq!(
            p.bench_access(&plan()),
            crate::provider::BenchAccess::Socks { socks_port: 9234 }
        );
    }

    #[test]
    fn render_produces_a_config_and_a_side_specific_unit() {
        let p = HTunnelProvider::new();
        let client = p.render(&plan(), TunnelSide::Client).expect("client");
        assert_eq!(client.files.len(), 2);
        assert_eq!(client.files[0].mode, "0600");
        assert!(client.files[1].content.contains("htunnel-client --config"));
        let server = p.render(&plan(), TunnelSide::Server).expect("server");
        assert!(server.files[1].content.contains("htunnel-server --config"));
    }

    #[test]
    fn units_and_config_paths_are_namespaced() {
        let p = HTunnelProvider::new();
        assert_eq!(p.service_name("demo"), "htm-htunnel-demo.service");
        assert_eq!(p.config_path("demo"), "/etc/htm-htunnel/demo.json");
    }

    #[test]
    fn defaults_validate() {
        let p = HTunnelProvider::new();
        assert!(p.validate_options(&p.default_options()).is_ok());
    }
}
