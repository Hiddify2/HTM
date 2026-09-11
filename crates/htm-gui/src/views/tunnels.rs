//! Step 4: the tunnels themselves — creating, watching and controlling them.

use egui::{RichText, Ui};

use htm_core::jobs::{JobKind, LogLevel};
use htm_core::model::{Health, ServiceAction, ServiceStatus, TunnelInstance, TunnelSide};
use htm_core::util;

use crate::app::{Action, HtmApp};
use crate::state::{ConfirmedAction, Modal, Tab};
use crate::theme::{Palette, SPACE_M, SPACE_S, SPACE_XS};
use crate::widgets;

const LABEL_W: f32 = 132.0;

pub fn show(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let ready = app.both_servers_ready();
    let busy = app.busy_with(JobKind::CreateTunnel)
        || app.busy_with(JobKind::ControlTunnel)
        || app.busy_with(JobKind::RemoveTunnel);

    ui.horizontal(|ui| {
        if widgets::primary_button(ui, &palette, "New tunnel", ready && !busy).clicked() {
            app.push(Action::OpenWizard { from_variant: None });
        }
        if widgets::ghost_button(
            ui,
            &palette,
            "Refresh now",
            ready && !app.busy_with(JobKind::RefreshStatus),
        )
        .clicked()
        {
            app.push(Action::RefreshStatuses);
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            match app.tunnels_ui.last_refresh {
                Some(at) => widgets::hint(
                    ui,
                    &palette,
                    &format!("Updated {:.0}s ago", at.elapsed().as_secs_f32()),
                ),
                None => widgets::hint(ui, &palette, "Not checked yet"),
            }
            if app.busy_with(JobKind::RefreshStatus) {
                ui.add(egui::Spinner::new().size(12.0).color(palette.accent));
            }
        });
    });

    if !ready {
        ui.add_space(SPACE_S);
        widgets::notice(
            ui,
            &palette,
            LogLevel::Warn,
            "Both servers must pass a connection test before a tunnel can be created or \
             controlled.",
        );
        ui.add_space(SPACE_S);
        if widgets::ghost_button(ui, &palette, "← Back to servers", true).clicked() {
            app.push(Action::SwitchTab(Tab::Servers));
        }
    }

    if let Some(error) = app.tunnels_ui.last_error.clone() {
        ui.add_space(SPACE_S);
        widgets::notice(ui, &palette, LogLevel::Error, &error);
    }

    ui.add_space(SPACE_M);

    if app.state.tunnels.is_empty() {
        widgets::card(ui, &palette, |ui| {
            widgets::empty_state(
                ui,
                &palette,
                "No tunnels yet",
                "Press New tunnel, or pick a configuration from the benchmark results.",
            );
        });
        return;
    }

    let tunnels = app.state.tunnels.clone();
    for instance in &tunnels {
        tunnel_card(app, ui, instance, busy);
        ui.add_space(SPACE_M);
    }

    if let Some((instance_id, side, text)) = app.tunnels_ui.preview.clone() {
        preview_card(app, ui, &instance_id, side, &text);
    }
}

fn tunnel_card(app: &mut HtmApp, ui: &mut Ui, instance: &TunnelInstance, busy: bool) {
    let palette = app.palette;
    let status = app.tunnels_ui.statuses.get(&instance.id).cloned();
    let health = status.as_ref().map(|s| s.health()).unwrap_or(Health::Unknown);
    let expanded = app.tunnels_ui.expanded.as_deref() == Some(instance.id.as_str());
    let confirm = app.state.settings.confirm_destructive;

    let mut requested: Option<Action> = None;
    let mut modal: Option<Modal> = None;
    let mut toggle_expand = false;

    widgets::card(ui, &palette, |ui| {
        // ── Header ──────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            widgets::dot(ui, widgets::health_color(&palette, health));
            ui.label(
                RichText::new(instance.plan.instance.as_str())
                    .font(crate::theme::title_font())
                    .color(palette.text),
            );
            widgets::pill(
                ui,
                &palette,
                health.label(),
                widgets::health_color(&palette, health),
            );
            if let Some(source) = &instance.source_variant {
                widgets::pill(ui, &palette, source.as_str(), palette.info);
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if expanded { "Less" } else { "More" };
                if widgets::ghost_button(ui, &palette, label, true).clicked() {
                    toggle_expand = true;
                }
            });
        });

        widgets::hint(
            ui,
            &palette,
            &format!(
                "{} · {} on the relay · {} link",
                instance.plan.provider_id,
                if instance.plan.forward_ports.is_empty() {
                    "all ports forwarded".to_string()
                } else {
                    format!(
                        "ports {}",
                        util::format_port_list(&instance.plan.forward_ports)
                    )
                },
                instance.plan.tun_name
            ),
        );

        ui.add_space(SPACE_S);

        // ── Live figures ────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            let history = app.tunnels_ui.traffic.get(&instance.id).cloned();
            let rate = history.as_ref().map(|h| h.latest()).unwrap_or(0.0);

            widgets::metric(
                ui,
                &palette,
                "THROUGHPUT",
                &util::human_bits_per_sec(rate),
                Some("across both interfaces"),
            );
            ui.add_space(SPACE_M);

            let rtt = status
                .as_ref()
                .and_then(|s| s.link_rtt_ms)
                .map(util::human_ms)
                .unwrap_or_else(|| "—".to_string());
            widgets::metric(
                ui,
                &palette,
                "ROUND TRIP",
                &rtt,
                instance
                    .expected_latency_ms
                    .map(|e| format!("measured {}", util::human_ms(e)))
                    .as_deref(),
            );
            ui.add_space(SPACE_M);

            let (rx, tx) = status
                .as_ref()
                .map(|s| s.total_bytes())
                .unwrap_or((0, 0));
            widgets::metric(
                ui,
                &palette,
                "TRANSFERRED",
                &util::human_bytes(rx.saturating_add(tx)),
                Some(&format!(
                    "{} in · {} out",
                    util::human_bytes(rx),
                    util::human_bytes(tx)
                )),
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let samples = history.map(|h| h.samples).unwrap_or_default();
                widgets::sparkline(
                    ui,
                    &palette,
                    &samples,
                    palette.series[0],
                    egui::vec2(200.0, 44.0),
                );
            });
        });

        ui.add_space(SPACE_S);

        // ── Per-side status ─────────────────────────────────────────────────
        ui.columns(2, |cols| {
            for (column, side) in [(0usize, TunnelSide::Server), (1usize, TunnelSide::Client)] {
                let ui = &mut cols[column];
                let label = app
                    .state
                    .server(side)
                    .map(|p| p.label.clone())
                    .unwrap_or_else(|| side.display_name().to_string());
                let unit_status = status.as_ref().map(|s| s.side(side));
                side_status(ui, &palette, &label, unit_status);
            }
        });

        // ── Details ─────────────────────────────────────────────────────────
        if expanded {
            widgets::divider(ui, &palette);
            details(ui, &palette, instance);

            ui.add_space(SPACE_S);
            ui.horizontal(|ui| {
                if widgets::ghost_button(ui, &palette, "Show relay configuration", true).clicked()
                {
                    requested = Some(Action::PreviewTunnelConfig {
                        instance_id: instance.id.clone(),
                        side: TunnelSide::Client,
                    });
                }
                if widgets::ghost_button(ui, &palette, "Show exit configuration", true).clicked() {
                    requested = Some(Action::PreviewTunnelConfig {
                        instance_id: instance.id.clone(),
                        side: TunnelSide::Server,
                    });
                }
            });
        }

        widgets::divider(ui, &palette);

        // ── Controls ────────────────────────────────────────────────────────
        ui.horizontal_wrapped(|ui| {
            let running = health == Health::Up || health == Health::Partial;

            if widgets::primary_button(ui, &palette, "Start", !busy && !running).clicked() {
                requested = Some(Action::ControlTunnel {
                    instance_id: instance.id.clone(),
                    action: ServiceAction::Start,
                });
            }
            if widgets::ghost_button(ui, &palette, "Restart", !busy).clicked() {
                requested = Some(Action::ControlTunnel {
                    instance_id: instance.id.clone(),
                    action: ServiceAction::Restart,
                });
            }
            if widgets::danger_button(ui, &palette, "Stop", !busy && running).clicked() {
                if confirm {
                    modal = Some(Modal::Confirm {
                        title: format!("Stop '{}'?", instance.plan.instance),
                        body: "Traffic through this tunnel stops immediately. The configuration \
                               and the systemd units stay in place, so it can be started again."
                            .to_string(),
                        confirm_label: "Stop it".to_string(),
                        action: Box::new(ConfirmedAction::StopTunnel(instance.id.clone())),
                    });
                } else {
                    requested = Some(Action::ControlTunnel {
                        instance_id: instance.id.clone(),
                        action: ServiceAction::Stop,
                    });
                }
            }

            ui.add_space(SPACE_S);

            let enabled_at_boot = status
                .as_ref()
                .map(|s| s.client.enabled && s.server.enabled)
                .unwrap_or(instance.start_on_boot);
            let (boot_label, boot_action) = if enabled_at_boot {
                ("Disable at boot", ServiceAction::Disable)
            } else {
                ("Enable at boot", ServiceAction::Enable)
            };
            if widgets::ghost_button(ui, &palette, boot_label, !busy).clicked() {
                requested = Some(Action::ControlTunnel {
                    instance_id: instance.id.clone(),
                    action: boot_action,
                });
            }

            if widgets::ghost_button(ui, &palette, "View logs", true).clicked() {
                requested = Some(Action::SwitchTab(Tab::Logs));
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::danger_button(ui, &palette, "Remove", !busy).clicked() {
                    modal = Some(Modal::Confirm {
                        title: format!("Remove '{}'?", instance.plan.instance),
                        body: format!(
                            "This stops the tunnel, deletes its systemd units and its \
                             configuration from both servers, and forgets it here. The {} \
                             software itself stays installed.",
                            app.provider.name()
                        ),
                        confirm_label: "Remove it".to_string(),
                        action: Box::new(ConfirmedAction::RemoveTunnel(instance.id.clone())),
                    });
                }
            });
        });
    });

    if toggle_expand {
        app.tunnels_ui.expanded = if expanded {
            None
        } else {
            Some(instance.id.clone())
        };
    }
    if let Some(modal) = modal {
        app.modal = Some(modal);
    }
    if let Some(action) = requested {
        // Selecting the log view should also point it at this tunnel.
        if matches!(action, Action::SwitchTab(Tab::Logs)) {
            app.logs_ui.remote_instance = Some(instance.id.clone());
            app.logs_ui.follow_remote = true;
        }
        app.push(action);
    }
}

fn side_status(ui: &mut Ui, palette: &Palette, label: &str, status: Option<&ServiceStatus>) {
    widgets::inset(ui, palette, |ui| {
        ui.horizontal(|ui| {
            let color = match status {
                Some(s) if s.is_active() => palette.success,
                Some(s) if s.is_failed() => palette.error,
                Some(s) if s.exists() => palette.text_faint,
                _ => palette.text_muted,
            };
            widgets::dot(ui, color);
            ui.label(RichText::new(label).color(palette.text).strong());
        });

        match status {
            None => widgets::hint(ui, palette, "Status unknown"),
            Some(s) => {
                if let Some(error) = &s.query_error {
                    widgets::hint(ui, palette, &util::truncate(error, 120));
                    return;
                }
                widgets::kv(
                    ui,
                    palette,
                    "UNIT",
                    &format!("{} ({})", s.active_state, s.sub_state),
                    LABEL_W,
                );
                if let Some(secs) = s.since_secs {
                    widgets::kv(
                        ui,
                        palette,
                        "UP FOR",
                        &util::human_duration_secs(secs),
                        LABEL_W,
                    );
                }
                if let Some(pid) = s.pid {
                    widgets::kv(
                        ui,
                        palette,
                        "PROCESS",
                        &format!(
                            "pid {pid}{}",
                            s.memory_bytes
                                .map(|m| format!(" · {}", util::human_bytes(m)))
                                .unwrap_or_default()
                        ),
                        LABEL_W,
                    );
                }
                if let Some(restarts) = s.restarts.filter(|r| *r > 0) {
                    widgets::kv(ui, palette, "RESTARTS", &restarts.to_string(), LABEL_W);
                }
                if let Some(code) = s.exit_code {
                    widgets::kv(ui, palette, "LAST EXIT", &code.to_string(), LABEL_W);
                }
                match &s.iface {
                    Some(iface) => widgets::kv_mono(
                        ui,
                        palette,
                        "INTERFACE",
                        &format!(
                            "{} · {} · MTU {}",
                            iface.name,
                            if iface.up { "up" } else { "down" },
                            iface.mtu
                        ),
                        LABEL_W,
                    ),
                    None => widgets::kv(ui, palette, "INTERFACE", "not present", LABEL_W),
                }
                if s.enabled {
                    widgets::hint(ui, palette, "Starts automatically at boot.");
                }
            }
        }
    });
}

fn details(ui: &mut Ui, palette: &Palette, instance: &TunnelInstance) {
    widgets::section_title(ui, palette, "Configuration");

    ui.columns(2, |cols| {
        let ui = &mut cols[0];
        widgets::kv_mono(
            ui,
            palette,
            "RELAY",
            &format!(
                "{} → tun {}",
                instance.plan.client.peer_target(),
                instance.plan.client.tun_ip
            ),
            LABEL_W,
        );
        widgets::kv_mono(
            ui,
            palette,
            "EXIT",
            &format!(
                "{} → tun {}",
                instance.plan.server.peer_target(),
                instance.plan.server.tun_ip
            ),
            LABEL_W,
        );
        widgets::kv_mono(
            ui,
            palette,
            "WIRE PORT",
            &instance.plan.data_port.to_string(),
            LABEL_W,
        );
        widgets::kv_mono(
            ui,
            palette,
            "MTU",
            &format!("{} wire · {} tun", instance.plan.mtu, instance.plan.tun_mtu),
            LABEL_W,
        );

        let ui = &mut cols[1];
        widgets::kv(
            ui,
            palette,
            "FORWARDED",
            &if instance.plan.forward_ports.is_empty() {
                "every TCP and UDP port".to_string()
            } else {
                util::format_port_list(&instance.plan.forward_ports)
            },
            LABEL_W,
        );
        widgets::kv(
            ui,
            palette,
            "SOURCE ADDRESSES",
            &if instance.plan.spoofing.is_forged() {
                format!(
                    "forged · relay {} · exit {}",
                    instance.plan.client.spoofed_ip, instance.plan.server.spoofed_ip
                )
            } else {
                "the servers' own".to_string()
            },
            LABEL_W,
        );
        widgets::kv(
            ui,
            palette,
            "CREATED",
            &instance
                .created_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string(),
            LABEL_W,
        );
        if let (Some(up), Some(down)) =
            (instance.expected_uplink_bps, instance.expected_downlink_bps)
        {
            widgets::kv(
                ui,
                palette,
                "MEASURED AT",
                &format!(
                    "{} up · {} down",
                    util::human_bits_per_sec(up),
                    util::human_bits_per_sec(down)
                ),
                LABEL_W,
            );
        }
    });

    ui.add_space(SPACE_XS);
    widgets::hint(
        ui,
        palette,
        "The pre-shared key is stored in the configuration on both servers and is not shown \
         here.",
    );
}

fn preview_card(
    app: &mut HtmApp,
    ui: &mut Ui,
    instance_id: &str,
    side: TunnelSide,
    text: &str,
) {
    let palette = app.palette;
    let name = app
        .state
        .tunnel(instance_id)
        .map(|t| t.plan.instance.clone())
        .unwrap_or_default();
    let mut close = false;

    widgets::card(ui, &palette, |ui| {
        ui.horizontal(|ui| {
            widgets::section_title(
                ui,
                &palette,
                &format!("{name} · {} configuration", side.as_str()),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::ghost_button(ui, &palette, "Close", true).clicked() {
                    close = true;
                }
            });
        });
        widgets::hint(
            ui,
            &palette,
            "This is exactly what HTM writes to the server, rendered from the saved plan.",
        );
        ui.add_space(SPACE_S);
        widgets::code_block(ui, &palette, text, 420.0);
    });

    if close {
        app.push(Action::ClosePreview);
    }
}
