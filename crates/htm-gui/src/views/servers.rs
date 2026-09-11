//! Step 1: the two VPS hosts.
//!
//! Both servers are shown side by side because almost every mistake here is a
//! mix-up between them — the exit node's address typed into the relay, a
//! password pasted into the wrong card. Keeping them adjacent, labelled by
//! role rather than by number, makes that mix-up visible.

use egui::{RichText, Ui};

use htm_core::jobs::{JobKind, LogLevel};
use htm_core::model::{
    AuthKind, ProxyKind, ServerFacts, ServerProfile, ServerSecrets, TunnelSide,
};
use htm_core::util;

use crate::app::{Action, HtmApp};
use crate::state::ServersUi;
use crate::theme::{Palette, SPACE_M, SPACE_S};
use crate::widgets;

/// Width of the label column inside the server forms.
const LABEL_W: f32 = 104.0;
/// Width of the input controls.
const FIELD_W: f32 = 210.0;

pub fn show(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let testing = app.busy_with(JobKind::TestConnection);

    ui.horizontal(|ui| {
        let ready = app.both_servers_ready();
        if widgets::primary_button(ui, &palette, "Test both connections", !testing).clicked() {
            ui.ctx().request_repaint();
            app.push(Action::TestBothConnections);
        }
        if ready {
            ui.add_space(SPACE_S);
            widgets::pill(ui, &palette, "Both servers are ready", palette.success);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if widgets::ghost_button(ui, &palette, "Continue to install →", ready).clicked() {
                app.push(Action::SwitchTab(crate::state::Tab::Install));
            }
        });
    });

    ui.add_space(SPACE_M);

    let mut changed = false;
    ui.columns(2, |columns| {
        // The exit node first: it is the one that has to exist before the
        // relay has anything to connect to.
        for (column, side) in [
            (0usize, TunnelSide::Server),
            (1usize, TunnelSide::Client),
        ] {
            let ui = &mut columns[column];
            let Some(index) = app.state.servers.iter().position(|s| s.side == side) else {
                continue;
            };
            let id = app.state.servers[index].id.clone();

            // Disjoint field borrows: the profile lives in `state`, the
            // secrets and the expander flags in `servers_ui`, the queue in
            // `actions`.
            let profile = &mut app.state.servers[index];
            let secrets = app.servers_ui.secrets.entry(id.clone()).or_default();
            let show_proxy = *ServersUi::flag(&mut app.servers_ui.show_proxy, &id);
            let show_advanced = *ServersUi::flag(&mut app.servers_ui.show_advanced, &id);
            let error = app.servers_ui.last_error.get(&id).cloned();

            let outcome = server_card(
                ui,
                &palette,
                profile,
                secrets,
                show_proxy,
                show_advanced,
                error.as_deref(),
                testing,
            );

            changed |= outcome.changed;
            if outcome.toggle_proxy {
                let flag = ServersUi::flag(&mut app.servers_ui.show_proxy, &id);
                *flag = !*flag;
            }
            if outcome.toggle_advanced {
                let flag = ServersUi::flag(&mut app.servers_ui.show_advanced, &id);
                *flag = !*flag;
            }
            if outcome.test {
                app.actions.push(Action::TestConnection(side));
            }
            if let Some((host, port)) = outcome.forget_host_key {
                app.actions.push(Action::ForgetHostKey { host, port });
            }
        }
    });

    if changed {
        app.mark_dirty();
    }

    ui.add_space(SPACE_M);
    guidance(app, ui);
}

/// What the user did inside one card.
#[derive(Default)]
struct CardOutcome {
    changed: bool,
    test: bool,
    toggle_proxy: bool,
    toggle_advanced: bool,
    forget_host_key: Option<(String, u16)>,
}

#[allow(clippy::too_many_arguments)]
fn server_card(
    ui: &mut Ui,
    palette: &Palette,
    profile: &mut ServerProfile,
    secrets: &mut ServerSecrets,
    show_proxy: bool,
    show_advanced: bool,
    error: Option<&str>,
    testing: bool,
) -> CardOutcome {
    let mut out = CardOutcome::default();
    // Stable per-card suffix for widget ids and reveal toggles, taken once so
    // no widget has to borrow the profile just to identify itself.
    let card_id = profile.id.clone();

    widgets::card(ui, palette, |ui| {
        // ── Header ──────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            let color = match profile.side {
                TunnelSide::Server => palette.series[1],
                TunnelSide::Client => palette.series[0],
            };
            widgets::dot(ui, color);
            ui.label(
                RichText::new(profile.side.display_name())
                    .font(crate::theme::title_font())
                    .color(palette.text),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                match &profile.facts {
                    Some(f) if f.blockers().is_empty() => {
                        widgets::pill(ui, palette, "Ready", palette.success);
                    }
                    Some(_) => {
                        widgets::pill(ui, palette, "Needs attention", palette.warn);
                    }
                    None => {
                        widgets::pill(ui, palette, "Not tested", palette.text_faint);
                    }
                }
            });
        });
        widgets::hint(
            ui,
            palette,
            match profile.side {
                TunnelSide::Server => {
                    "The far end. Traffic leaves the tunnel here and reaches the internet."
                }
                TunnelSide::Client => {
                    "The near end. Your users connect to this host, and the ports you forward \
                     are opened on it."
                }
            },
        );

        ui.add_space(SPACE_S);

        // ── Identity ────────────────────────────────────────────────────────
        out.changed |= widgets::form_row(ui, palette, "NAME", LABEL_W, |ui| {
            widgets::text_field(ui, &mut profile.label, FIELD_W, "A name you will recognise")
                .changed()
        });

        out.changed |= widgets::form_row(ui, palette, "HOST", LABEL_W, |ui| {
            widgets::text_field(
                ui,
                &mut profile.host,
                FIELD_W,
                "IP address or hostname",
            )
            .changed()
        });

        out.changed |= widgets::form_row(ui, palette, "SSH PORT", LABEL_W, |ui| {
            ui.add(
                egui::DragValue::new(&mut profile.port)
                    .range(1..=65535)
                    .speed(1.0),
            )
            .changed()
        });

        out.changed |= widgets::form_row(ui, palette, "USERNAME", LABEL_W, |ui| {
            widgets::text_field(ui, &mut profile.username, FIELD_W, "root").changed()
        });

        // ── Authentication ──────────────────────────────────────────────────
        out.changed |= widgets::form_row(ui, palette, "SIGN IN WITH", LABEL_W, |ui| {
            let mut changed = false;
            egui::ComboBox::from_id_source(("auth", &card_id))
                .selected_text(profile.auth_kind.display_name())
                .width(FIELD_W)
                .show_ui(ui, |ui| {
                    for kind in AuthKind::ALL {
                        changed |= ui
                            .selectable_value(&mut profile.auth_kind, kind, kind.display_name())
                            .changed();
                    }
                });
            changed
        });

        match profile.auth_kind {
            AuthKind::Password => {
                out.changed |= widgets::form_row(ui, palette, "PASSWORD", LABEL_W, |ui| {
                    widgets::password_field(
                        ui,
                        &mut secrets.password,
                        FIELD_W,
                        "SSH password",
                        &format!("pw-{card_id}"),
                    )
                    .changed()
                });
            }
            AuthKind::PrivateKey => {
                out.changed |= widgets::form_row(ui, palette, "KEY FILE", LABEL_W, |ui| {
                    widgets::text_field(
                        ui,
                        &mut profile.private_key_path,
                        FIELD_W,
                        "C:\\Users\\you\\.ssh\\id_ed25519",
                    )
                    .changed()
                });
                out.changed |= widgets::form_row(ui, palette, "PASSPHRASE", LABEL_W, |ui| {
                    widgets::password_field(
                        ui,
                        &mut secrets.key_passphrase,
                        FIELD_W,
                        "Leave blank if the key has none",
                        &format!("kp-{card_id}"),
                    )
                    .changed()
                });
            }
            AuthKind::Agent => {
                widgets::hint(
                    ui,
                    palette,
                    "HTM will offer every identity your SSH agent holds.",
                );
            }
        }

        // A sudo password is only meaningful for a non-root login.
        if profile.username.trim() != "root" && !profile.username.trim().is_empty() {
            out.changed |= widgets::form_row(ui, palette, "SUDO PASSWORD", LABEL_W, |ui| {
                widgets::password_field(
                    ui,
                    &mut secrets.sudo_password,
                    FIELD_W,
                    "Blank = same as the login password",
                    &format!("sudo-{card_id}"),
                )
                .changed()
            });
            widgets::hint(
                ui,
                palette,
                "HTM needs root to install software, write systemd units and open raw sockets.",
            );
        }

        ui.add_space(SPACE_S);

        // ── Proxy ───────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            let label = if show_proxy {
                "▾ Proxy"
            } else {
                "▸ Proxy"
            };
            if widgets::ghost_button(ui, palette, label, true).clicked() {
                out.toggle_proxy = true;
            }
            if profile.proxy.kind.is_enabled() {
                widgets::pill(
                    ui,
                    palette,
                    profile.proxy.kind.display_name(),
                    palette.info,
                );
            }
        });

        if show_proxy {
            ui.add_space(SPACE_S);
            widgets::hint(
                ui,
                palette,
                "Use a proxy when your own connection to the server is filtered. It carries only \
                 HTM's SSH session, not the tunnel itself.",
            );
            ui.add_space(SPACE_S);

            out.changed |= widgets::form_row(ui, palette, "TYPE", LABEL_W, |ui| {
                let mut changed = false;
                egui::ComboBox::from_id_source(("proxy", &card_id))
                    .selected_text(profile.proxy.kind.display_name())
                    .width(FIELD_W)
                    .show_ui(ui, |ui| {
                        for kind in ProxyKind::ALL {
                            changed |= ui
                                .selectable_value(
                                    &mut profile.proxy.kind,
                                    kind,
                                    kind.display_name(),
                                )
                                .changed();
                        }
                    });
                changed
            });

            if profile.proxy.kind.is_enabled() {
                out.changed |= widgets::form_row(ui, palette, "PROXY HOST", LABEL_W, |ui| {
                    widgets::text_field(ui, &mut profile.proxy.host, FIELD_W, "127.0.0.1")
                        .changed()
                });
                out.changed |= widgets::form_row(ui, palette, "PROXY PORT", LABEL_W, |ui| {
                    ui.add(
                        egui::DragValue::new(&mut profile.proxy.port)
                            .range(1..=65535)
                            .speed(1.0),
                    )
                    .changed()
                });
                if profile.proxy.kind != ProxyKind::Socks4 {
                    out.changed |= widgets::form_row(ui, palette, "PROXY USER", LABEL_W, |ui| {
                        widgets::text_field(
                            ui,
                            &mut profile.proxy.username,
                            FIELD_W,
                            "Optional",
                        )
                        .changed()
                    });
                    out.changed |=
                        widgets::form_row(ui, palette, "PROXY PASSWORD", LABEL_W, |ui| {
                            widgets::password_field(
                                ui,
                                &mut secrets.proxy_password,
                                FIELD_W,
                                "Optional",
                                &format!("px-{card_id}"),
                            )
                            .changed()
                        });
                } else {
                    out.changed |= widgets::form_row(ui, palette, "USER ID", LABEL_W, |ui| {
                        widgets::text_field(
                            ui,
                            &mut profile.proxy.username,
                            FIELD_W,
                            "Optional SOCKS4 user id",
                        )
                        .changed()
                    });
                }
            }
        }

        // ── Advanced ────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            let label = if show_advanced {
                "▾ Advanced"
            } else {
                "▸ Advanced"
            };
            if widgets::ghost_button(ui, palette, label, true).clicked() {
                out.toggle_advanced = true;
            }
            let overrides = !profile.iface_override.is_empty()
                || !profile.local_ip_override.is_empty()
                || !profile.public_ip_override.is_empty();
            if overrides {
                widgets::pill(ui, palette, "Overridden", palette.warn);
            }
        });

        if show_advanced {
            ui.add_space(SPACE_S);
            widgets::hint(
                ui,
                palette,
                "Leave these empty unless HTM detected the wrong values. They are written \
                 straight into the tunnel configuration.",
            );
            ui.add_space(SPACE_S);

            out.changed |= widgets::form_row(ui, palette, "INTERFACE", LABEL_W, |ui| {
                widgets::text_field(
                    ui,
                    &mut profile.iface_override,
                    FIELD_W,
                    &detected(profile.facts.as_ref(), |f| f.default_iface.clone()),
                )
                .changed()
            });
            out.changed |= widgets::form_row(ui, palette, "LOCAL IPv4", LABEL_W, |ui| {
                widgets::text_field(
                    ui,
                    &mut profile.local_ip_override,
                    FIELD_W,
                    &detected(profile.facts.as_ref(), |f| f.local_ipv4.clone()),
                )
                .changed()
            });
            out.changed |= widgets::form_row(ui, palette, "PUBLIC IPv4", LABEL_W, |ui| {
                widgets::text_field(
                    ui,
                    &mut profile.public_ip_override,
                    FIELD_W,
                    &detected(profile.facts.as_ref(), |f| f.public_ipv4.clone()),
                )
                .changed()
            });
            out.changed |= widgets::form_row(ui, palette, "CONNECT (s)", LABEL_W, |ui| {
                ui.add(
                    egui::DragValue::new(&mut profile.connect_timeout_secs)
                        .range(5..=600)
                        .speed(1.0),
                )
                .changed()
            });
            out.changed |= widgets::form_row(ui, palette, "COMMAND (s)", LABEL_W, |ui| {
                ui.add(
                    egui::DragValue::new(&mut profile.command_timeout_secs)
                        .range(10..=3600)
                        .speed(5.0),
                )
                .changed()
            });
        }

        widgets::divider(ui, palette);

        // ── Actions ─────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            if widgets::primary_button(ui, palette, "Test connection", !testing).clicked() {
                out.test = true;
            }
            if !profile.host.trim().is_empty()
                && widgets::ghost_button(ui, palette, "Forget host key", true)
                    .on_hover_text(
                        "Remove the pinned SSH host key so the next connection asks again.",
                    )
                    .clicked()
            {
                out.forget_host_key = Some((profile.host.trim().to_string(), profile.port));
            }
        });

        if testing {
            ui.add_space(SPACE_S);
            widgets::busy(ui, palette, "Connecting…");
        }

        if let Some(error) = error {
            ui.add_space(SPACE_S);
            widgets::notice(ui, palette, LogLevel::Error, error);
        }

        // ── What we found ───────────────────────────────────────────────────
        if let Some(facts) = profile.facts.clone() {
            ui.add_space(SPACE_M);
            facts_panel(ui, palette, &facts, profile);
        }
    });

    out
}

fn detected(facts: Option<&ServerFacts>, get: impl Fn(&ServerFacts) -> String) -> String {
    match facts.map(get) {
        Some(value) if !value.is_empty() => format!("Detected: {value}"),
        _ => "Not detected yet".to_string(),
    }
}

fn facts_panel(ui: &mut Ui, palette: &Palette, facts: &ServerFacts, profile: &ServerProfile) {
    widgets::section_title(ui, palette, "What HTM found");

    widgets::inset(ui, palette, |ui| {
        widgets::kv(ui, palette, "SYSTEM", &facts.os_pretty, LABEL_W);
        widgets::kv(
            ui,
            palette,
            "KERNEL",
            &format!("{} ({})", facts.kernel, facts.arch),
            LABEL_W,
        );
        widgets::kv(
            ui,
            palette,
            "HARDWARE",
            &format!(
                "{} cores · {} RAM · {} free on /",
                facts.cpu_cores,
                util::human_bytes(facts.mem_total_kb.saturating_mul(1024)),
                util::human_bytes(facts.root_free_kb.saturating_mul(1024)),
            ),
            LABEL_W,
        );
        widgets::kv_mono(
            ui,
            palette,
            "INTERFACE",
            &format!("{} · MTU {}", facts.default_iface, facts.iface_mtu),
            LABEL_W,
        );
        widgets::kv_mono(ui, palette, "LOCAL IPv4", &facts.local_ipv4, LABEL_W);
        widgets::kv_mono(ui, palette, "PUBLIC IPv4", &facts.public_ipv4, LABEL_W);
        widgets::kv(
            ui,
            palette,
            "ACCESS",
            if facts.is_root {
                "root"
            } else if facts.passwordless_sudo {
                "sudo, no password needed"
            } else if facts.can_escalate {
                "sudo with a password"
            } else {
                "no root access"
            },
            LABEL_W,
        );
        widgets::kv(
            ui,
            palette,
            "UPTIME",
            &util::human_duration_secs(facts.uptime_secs),
            LABEL_W,
        );

        ui.add_space(SPACE_S);
        ui.horizontal_wrapped(|ui| {
            capability(ui, palette, "systemd", facts.has_systemd);
            capability(ui, palette, "/dev/net/tun", facts.has_tun);
            capability(ui, palette, "iptables", facts.has_iptables);
            capability(ui, palette, "curl", facts.has_curl);
            capability(ui, palette, "iperf3", facts.has_iperf3);
            capability(ui, palette, "python3", facts.has_python3);
            widgets::pill(
                ui,
                palette,
                facts.package_manager.display_name(),
                palette.info,
            );
        });
    });

    for blocker in facts.blockers() {
        ui.add_space(SPACE_S);
        widgets::notice(ui, palette, LogLevel::Error, &blocker);
    }
    for warning in facts.warnings() {
        ui.add_space(SPACE_S);
        widgets::notice(ui, palette, LogLevel::Warn, &warning);
    }

    if let Some(checked) = profile.last_checked {
        ui.add_space(SPACE_S);
        widgets::hint(
            ui,
            palette,
            &format!(
                "Checked {}",
                checked
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S")
            ),
        );
    }
}

/// A pill that is green when a capability is present and muted when it is not.
///
/// Missing capabilities are not coloured red here: several of them are merely
/// nice to have, and the blockers list below says which ones actually matter.
fn capability(ui: &mut Ui, palette: &Palette, name: &str, present: bool) {
    let (text, color) = if present {
        (name.to_string(), palette.success)
    } else {
        (format!("no {name}"), palette.text_faint)
    };
    widgets::pill(ui, palette, &text, color);
}

fn guidance(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "How HTM uses these servers");
        widgets::hint(
            ui,
            &palette,
            "The exit server terminates the tunnel and reaches the internet on your behalf. The \
             relay server is the one your users point their clients at; the ports you choose \
             later are opened on it and pushed down the tunnel.",
        );
        ui.add_space(SPACE_S);
        widgets::hint(
            ui,
            &palette,
            "Nothing is written to either server until you press Install. Testing a connection \
             only reads: it looks at /etc/os-release, the routing table, the interface list and \
             whether a few commands exist.",
        );
        ui.add_space(SPACE_S);
        widgets::hint(
            ui,
            &palette,
            "Passwords are kept on this machine only, in an encrypted file. They are never \
             written into any configuration that lands on a server.",
        );
    });
}
