//! Step 2: putting the tunnel software on both servers.

use egui::{RichText, Ui};

use htm_core::jobs::{JobKind, LogLevel};
use htm_core::model::TunnelSide;
use htm_core::provider::{registry, InstallMethod};

use crate::app::{Action, HtmApp};
use crate::state::{ConfirmedAction, Modal, Tab};
use crate::theme::{SPACE_M, SPACE_S, SPACE_XS};
use crate::widgets;

const LABEL_W: f32 = 150.0;

pub fn show(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;

    if !app.both_servers_ready() {
        widgets::notice(
            ui,
            &palette,
            LogLevel::Warn,
            "Both servers need to pass a connection test before anything can be installed.",
        );
        ui.add_space(SPACE_S);
        if widgets::ghost_button(ui, &palette, "← Back to servers", true).clicked() {
            app.push(Action::SwitchTab(Tab::Servers));
        }
        ui.add_space(SPACE_M);
    }

    provider_card(app, ui);
    ui.add_space(SPACE_M);
    method_card(app, ui);
    ui.add_space(SPACE_M);
    status_card(app, ui);
}

fn provider_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let providers = registry::all();
    let mut selected = app.provider.id().to_string();

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "Tunnel software");

        widgets::form_row(ui, &palette, "PROVIDER", LABEL_W, |ui| {
            egui::ComboBox::from_id_source("htm-provider")
                .selected_text(app.provider.name())
                .width(260.0)
                .show_ui(ui, |ui| {
                    for provider in &providers {
                        ui.selectable_value(
                            &mut selected,
                            provider.id().to_string(),
                            provider.name(),
                        );
                    }
                });
        });

        ui.add_space(SPACE_S);
        widgets::hint(ui, &palette, app.provider.description());
        ui.add_space(SPACE_XS);
        ui.hyperlink_to(
            RichText::new(app.provider.homepage()).color(palette.accent),
            app.provider.homepage(),
        );

        if providers.len() == 1 {
            ui.add_space(SPACE_S);
            widgets::hint(
                ui,
                &palette,
                "Only one provider is built in so far. HTM's provider layer is generic, so \
                 others can be added without changing any of the screens you are looking at.",
            );
        }
    });

    if selected != app.provider.id() {
        app.provider = registry::get_or_default(&selected);
        app.state.settings.provider_id = selected;
        // A different provider has a different option space, so anything
        // carried over from the old one would be meaningless.
        let matrix = app.provider.default_matrix();
        let options = app.provider.default_options();
        app.bench_ui.selection = matrix;
        app.bench_ui.invalidate_preview();
        app.wizard.options = options;
        app.install_ui.versions.clear();
        app.mark_dirty();
    }
}

fn method_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let busy = app.busy_with(JobKind::Install) || app.busy_with(JobKind::Uninstall);
    let ready = app.both_servers_ready();

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "How to install it");

        let mut method = app.state.settings.install_method;
        let changed = widgets::form_row(ui, &palette, "METHOD", LABEL_W, |ui| {
            let mut changed = false;
            egui::ComboBox::from_id_source("htm-install-method")
                .selected_text(method.display_name())
                .width(260.0)
                .show_ui(ui, |ui| {
                    for option in InstallMethod::ALL {
                        changed |= ui
                            .selectable_value(&mut method, option, option.display_name())
                            .changed();
                    }
                });
            changed
        });
        if changed {
            app.state.settings.install_method = method;
            app.mark_dirty();
        }

        ui.add_space(SPACE_XS);
        widgets::hint(ui, &palette, method.help());

        // Say plainly when the automatic choice will pick the slow route.
        if method != InstallMethod::PrebuiltBinary {
            let non_x86: Vec<String> = TunnelSide::ORDERED
                .iter()
                .filter_map(|side| {
                    let profile = app.state.server(*side)?;
                    let facts = profile.facts.as_ref()?;
                    (facts.arch != "x86_64")
                        .then(|| format!("{} is {}", profile.label, facts.arch))
                })
                .collect();
            if !non_x86.is_empty() && method == InstallMethod::Auto {
                ui.add_space(SPACE_S);
                widgets::notice(
                    ui,
                    &palette,
                    LogLevel::Warn,
                    &format!(
                        "{}. Those hosts will be compiled from source, which needs Rust, CMake \
                         and Go and typically takes ten minutes or more.",
                        non_x86.join(" and ")
                    ),
                );
            }
        }

        ui.add_space(SPACE_S);
        let mut with_tools = app.install_ui.with_benchmark_tools;
        if ui
            .checkbox(
                &mut with_tools,
                "Also install iperf3 and python3, used for benchmarking",
            )
            .changed()
        {
            app.install_ui.with_benchmark_tools = with_tools;
        }
        widgets::hint(
            ui,
            &palette,
            "If iperf3 cannot be installed, HTM falls back to a small measurement script it \
             uploads itself, which needs only python3.",
        );

        widgets::divider(ui, &palette);

        ui.horizontal(|ui| {
            if widgets::primary_button(
                ui,
                &palette,
                "Install on both servers",
                ready && !busy,
            )
            .clicked()
            {
                app.push(Action::InstallProvider);
            }

            if widgets::danger_button(ui, &palette, "Uninstall from both", ready && !busy)
                .clicked()
            {
                app.modal = Some(Modal::Confirm {
                    title: "Remove the tunnel software?".to_string(),
                    body: format!(
                        "This stops and deletes every tunnel HTM created, removes {} from both \
                         servers and deletes its configuration directory. Tunnels created \
                         outside HTM are left alone.",
                        app.provider.name()
                    ),
                    confirm_label: "Remove it".to_string(),
                    action: Box::new(ConfirmedAction::UninstallProvider),
                });
            }
        });

        if busy {
            ui.add_space(SPACE_S);
            widgets::busy(ui, &palette, "Working on the servers. The log tab has the detail.");
        }
    });
}

fn status_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "Installed");

        if app.install_ui.versions.is_empty() {
            widgets::empty_state(
                ui,
                &palette,
                "Nothing installed yet",
                "Press Install and HTM will report what it put on each server.",
            );
        } else {
            for side in TunnelSide::ORDERED {
                let label = app
                    .state
                    .server(side)
                    .map(|p| p.label.clone())
                    .unwrap_or_else(|| side.display_name().to_string());

                ui.horizontal(|ui| {
                    match app.install_ui.versions.get(&side) {
                        Some(version) => {
                            widgets::dot(ui, palette.success);
                            ui.label(RichText::new(label.as_str()).color(palette.text).strong());
                            ui.label(
                                RichText::new(version.summary()).color(palette.text_muted),
                            );
                        }
                        None => {
                            widgets::dot(ui, palette.text_faint);
                            ui.label(RichText::new(label.as_str()).color(palette.text_muted));
                            ui.label(RichText::new("not installed").color(palette.text_faint));
                        }
                    }
                });
                if let Some(version) = app.install_ui.versions.get(&side) {
                    widgets::kv_mono(ui, &palette, "BINARY", &version.binary_path, LABEL_W);
                }
                ui.add_space(SPACE_XS);
            }
        }

        if let Some(error) = app.install_ui.last_error.clone() {
            ui.add_space(SPACE_S);
            widgets::notice(ui, &palette, LogLevel::Error, &error);
        }

        if app.provider_installed() {
            widgets::divider(ui, &palette);
            ui.horizontal(|ui| {
                if widgets::primary_button(ui, &palette, "Continue to benchmark →", true)
                    .clicked()
                {
                    app.push(Action::SwitchTab(Tab::Benchmark));
                }
                widgets::hint(
                    ui,
                    &palette,
                    "Or skip straight to Tunnels if you already know the configuration you want.",
                );
            });
        }
    });

    ui.add_space(SPACE_M);

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "What installing does");
        widgets::hint(
            ui,
            &palette,
            "HTM installs the packages the tunnel needs (iproute2, iptables, ping, curl), makes \
             sure /dev/net/tun exists, places the tunnel binary in /opt, and writes a systemd \
             template unit. Nothing is started: units are only created when you make a tunnel.",
        );
        ui.add_space(SPACE_S);
        widgets::hint(
            ui,
            &palette,
            "HTM uses its own unit prefix, so an existing CandyTunnel installation managed by \
             the upstream script keeps working untouched alongside it.",
        );
    });
}
