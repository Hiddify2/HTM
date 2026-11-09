//! The Hiddify Core provider.
//!
//! Hiddify Core is a sing-box build, so this provider turns HTM's relay/exit
//! pair into a sing-box proxy tunnel and brings a whole family of protocols with
//! it: Shadowsocks, VMess, VLESS, Trojan, Hysteria2, TUIC and SOCKS. The exit
//! runs the protocol server; the relay runs the protocol client and captures
//! traffic either through a local SOCKS5/HTTP proxy (`mixed`) or a TUN device
//! that forwards all of its IPv4 traffic (`tun`).
//!
//! There is no point-to-point TUN link between the hosts to ping, so it is a
//! [`TunnelModel::SocksProxy`] provider: readiness is the relay's inbound and
//! the exit's protocol port listening, and the TUN-based throughput benchmark
//! does not apply. Build these tunnels from the wizard.
//!
//! See <https://github.com/hiddify/hiddify-core>.

pub mod config;
pub mod install;

use crate::error::{Error, Result};
use crate::model::{
    BenchVariant, MatrixSelection, OptionMap, OptionMapExt, OptionSpace, PackageManager,
    TunnelPlan, TunnelSide,
};
use crate::provider::{
    HostCtx, InstallMethod, InstalledVersion, Readiness, ReadinessProbe, RemoteFile, RenderedSide,
    TunnelModel, TunnelProvider,
};
use crate::remote::{pkg, systemd};
use crate::util::sh_quote;

use config::{protocol_of, CONFIG_DIR, UNIT_TEMPLATE};

#[derive(Debug, Default, Clone, Copy)]
pub struct HiddifyCoreProvider;

impl HiddifyCoreProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TunnelProvider for HiddifyCoreProvider {
    fn id(&self) -> &'static str {
        "hiddifycore"
    }

    fn name(&self) -> &'static str {
        "Hiddify Core"
    }

    fn description(&self) -> &'static str {
        "sing-box multi-protocol tunnel: carry traffic between relay and exit over Shadowsocks, \
         VMess, VLESS, Trojan, Hysteria2, TUIC or SOCKS, with a local proxy or full TUN IP \
         forwarding on the relay."
    }

    fn homepage(&self) -> &'static str {
        "https://github.com/hiddify/hiddify-core"
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

    fn matrix_presets(&self) -> Vec<crate::provider::MatrixPreset> {
        config::presets()
    }

    fn required_packages(&self, _manager: PackageManager) -> Vec<String> {
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
            provider: "Hiddify Core".to_string(),
            detail,
        })?;

        let files = vec![
            RemoteFile {
                path: self.config_path(&plan.instance),
                content: config::render_side(plan, side),
                mode: "0600".to_string(),
                description: format!("Hiddify Core {} configuration", side.as_str()),
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

        // TLS protocols present a certificate on the exit.
        if ctx.side == TunnelSide::Server && config::needs_certificate(plan) {
            ctx.check()?;
            install::ensure_certificate(
                ctx,
                &config::cert_path(&plan.instance),
                &config::key_path(&plan.instance),
                &config::normalize(&plan.options).str_or(config::keys::SNI, "www.bing.com"),
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
            "Deployed instance '{}' ({}) as {}.",
            plan.instance,
            protocol_of(&config::normalize(&plan.options)).id(),
            rendered.service
        ));
        Ok(rendered)
    }

    fn remove_instance(&self, ctx: &HostCtx<'_>, instance: &str) -> Result<()> {
        let unit = self.service_name(instance);
        systemd::remove_unit(ctx.client, &unit)?;
        let script = format!(
            "#!/bin/sh\nrm -f {config} {cert} {key}\nrm -rf {work}\nexit 0\n",
            config = sh_quote(&self.config_path(instance)),
            cert = sh_quote(&config::cert_path(instance)),
            key = sh_quote(&config::key_path(instance)),
            work = sh_quote(&config::workdir(instance)),
        );
        ctx.client.run_script(&script, true)?;
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

    fn readiness_probes(&self, plan: &TunnelPlan) -> Vec<ReadinessProbe> {
        let options = config::normalize(&plan.options);
        let proto = protocol_of(&options);
        let mut out = Vec::new();

        // The exit's protocol port: a UDP socket for the QUIC-based protocols,
        // a TCP listener for the rest.
        out.push(if proto.is_udp() {
            ReadinessProbe::UdpPort {
                side: TunnelSide::Server,
                port: plan.data_port,
            }
        } else {
            ReadinessProbe::TcpPort {
                side: TunnelSide::Server,
                port: plan.data_port,
            }
        });

        // The relay's listeners depend on the access mode: a SOCKS port, the
        // forwarded ports, or nothing at all for TUN.
        match config::access_mode(&options).as_str() {
            "socks" => out.push(ReadinessProbe::TcpPort {
                side: TunnelSide::Client,
                port: config::socks_port(plan),
            }),
            "forward" => {
                for p in config::forward_ports(plan) {
                    out.push(ReadinessProbe::TcpPort {
                        side: TunnelSide::Client,
                        port: p,
                    });
                }
            }
            _ => {}
        }
        out
    }

    fn bench_access(&self, _plan: &TunnelPlan) -> crate::provider::BenchAccess {
        // Benchmarking forces port-forward mode (see bench_plan_options), so the
        // relay→exit path is measured to the relay's local forwarded port.
        crate::provider::BenchAccess::LocalForward
    }

    fn bench_plan_options(&self, options: &OptionMap) -> OptionMap {
        // Measure protocols over a port forward regardless of the user's chosen
        // access mode, so there is always a measurable relay→exit path.
        let mut out = options.clone();
        out.insert(
            config::keys::ACCESS_MODE.to_string(),
            crate::model::OptValue::Choice("forward".to_string()),
        );
        out
    }

    fn readiness(&self) -> Readiness {
        Readiness {
            ready_markers: vec![
                "sing-box started".to_string(),
                "started".to_string(),
                "inbound/".to_string(),
            ],
            fatal_markers: vec![
                "FATAL".to_string(),
                "Address already in use".to_string(),
                "Permission denied".to_string(),
                "Operation not permitted".to_string(),
                "decode config".to_string(),
                "parse config".to_string(),
                "missing".to_string(),
            ],
        }
    }

    fn symmetric_option_keys(&self) -> Vec<&'static str> {
        // Both sides must agree on the protocol (and, for the TLS protocols, the
        // SNI); HTM renders them from one plan, so they cannot drift.
        vec![config::keys::PROTOCOL, config::keys::SNI]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EndpointPlan, OptValue, FakePlan};
    use crate::provider::{ReadinessProbe, TunnelModel};

    fn plan_with(protocol: &str, mode: &str) -> TunnelPlan {
        let mut p = TunnelPlan {
            instance: "demo".into(),
            provider_id: "hiddifycore".into(),
            client: EndpointPlan {
                side: TunnelSide::Client,
                iface: "eth0".into(),
                real_ip: "198.51.100.1".into(),
                public_ip: "198.51.100.1".into(),
                tun_ip: "10.66.0.2".into(),
                faked_ip: "198.51.100.1".into(),
            },
            server: EndpointPlan {
                side: TunnelSide::Server,
                iface: "ens3".into(),
                real_ip: "203.0.113.9".into(),
                public_ip: "203.0.113.9".into(),
                tun_ip: "10.66.0.1".into(),
                faked_ip: "203.0.113.9".into(),
            },
            tun_netmask: "255.255.255.252".into(),
            tun_name: "hcore0".into(),
            data_port: 8443,
            pre_shared_key: "0123456789abcdef0123456789abcdef".into(),
            forward_ports: vec![],
            mtu: 1400,
            tun_mtu: 1400,
            log_level: "info".into(),
            faking: FakePlan::default(),
            options: config::option_space().defaults(),
        };
        p.options.insert(
            config::keys::PROTOCOL.into(),
            OptValue::Choice(protocol.into()),
        );
        p.options.insert(
            config::keys::ACCESS_MODE.into(),
            OptValue::Choice(mode.into()),
        );
        p
    }

    #[test]
    fn it_is_a_socks_proxy_provider_that_sweeps_protocols() {
        let p = HiddifyCoreProvider::new();
        assert_eq!(p.model(), TunnelModel::SocksProxy);
        // Every protocol becomes one benchmark variant.
        assert_eq!(
            p.expand_variants(&p.default_matrix()).len(),
            config::Protocol::ALL.len()
        );
        assert_eq!(p.managed_sides(&p.default_options()).len(), 2);
        // Benchmarking forces a measurable port-forward path.
        assert_eq!(
            p.bench_access(&plan_with("shadowsocks", "socks")),
            crate::provider::BenchAccess::LocalForward
        );
        // ...and rewrites the access mode to forward for the measurement.
        let benched = p.bench_plan_options(&plan_with("vmess", "socks").options);
        assert_eq!(config::access_mode(&benched), "forward");
    }

    #[test]
    fn units_and_config_paths_are_namespaced() {
        let p = HiddifyCoreProvider::new();
        assert_eq!(p.service_name("demo"), "htm-hiddifycore@demo.service");
        assert_eq!(p.config_path("demo"), "/etc/htm-hiddifycore/demo.json");
    }

    #[test]
    fn render_produces_a_config_and_the_template_unit() {
        let p = HiddifyCoreProvider::new();
        let rendered = p
            .render(&plan_with("shadowsocks", "socks"), TunnelSide::Server)
            .unwrap();
        assert_eq!(rendered.files.len(), 2);
        assert_eq!(rendered.files[0].mode, "0600");
        assert!(rendered.files[1].path.ends_with("htm-hiddifycore@.service"));
    }

    #[test]
    fn socks_mode_probes_the_exit_port_and_the_relay_proxy() {
        let p = HiddifyCoreProvider::new();
        let probes = p.readiness_probes(&plan_with("vmess", "socks"));
        assert!(probes.contains(&ReadinessProbe::TcpPort {
            side: TunnelSide::Server,
            port: 8443
        }));
        assert!(probes.contains(&ReadinessProbe::TcpPort {
            side: TunnelSide::Client,
            port: 2080
        }));
    }

    #[test]
    fn udp_protocols_probe_the_exit_as_udp_and_tun_mode_has_no_relay_listener() {
        let p = HiddifyCoreProvider::new();
        let probes = p.readiness_probes(&plan_with("hysteria2", "tun"));
        assert_eq!(
            probes,
            vec![ReadinessProbe::UdpPort {
                side: TunnelSide::Server,
                port: 8443
            }]
        );
    }

    #[test]
    fn symmetric_keys_exist_in_the_option_space() {
        let p = HiddifyCoreProvider::new();
        let space = p.option_space();
        for key in p.symmetric_option_keys() {
            assert!(space.get(key).is_some(), "unknown key {key}");
        }
    }

    #[test]
    fn defaults_validate() {
        let p = HiddifyCoreProvider::new();
        assert!(p.validate_options(&p.default_options()).is_ok());
    }
}
