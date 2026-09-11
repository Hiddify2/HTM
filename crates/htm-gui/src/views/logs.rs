//! Two logs: what HTM did, and what the servers said.
//!
//! They are side by side deliberately. When a tunnel will not start, the
//! answer is almost always in the remote journal, and having to go looking for
//! it in a terminal is exactly the friction this app exists to remove.

use egui::{RichText, Ui};

use htm_core::jobs::LogLevel;
use htm_core::model::TunnelSide;

use crate::app::{Action, HtmApp};
use crate::theme::{SPACE_M, SPACE_S};
use crate::widgets;

pub fn show(app: &mut HtmApp, ui: &mut Ui) {
    app_log_card(app, ui);
    ui.add_space(SPACE_M);
    remote_log_card(app, ui);
}

fn app_log_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;

    let levels = [
        (0u8, "Everything"),
        (1, "Info and above"),
        (2, "Warnings and errors"),
        (3, "Errors only"),
    ];

    // Filter before rendering so the scroll area only lays out what is shown.
    let min_level = app.logs_ui.min_level;
    let filter = app.logs_ui.filter.to_lowercase();
    let lines: Vec<String> = app
        .log
        .iter()
        .filter(|line| severity_rank(line.level) >= min_level)
        .filter(|line| {
            filter.is_empty()
                || line.text.to_lowercase().contains(&filter)
                || line
                    .scope
                    .as_ref()
                    .map(|s| s.to_lowercase().contains(&filter))
                    .unwrap_or(false)
        })
        .map(|line| line.render())
        .collect();

    let total = app.log.len();
    let joined = lines.join("\n");

    widgets::card(ui, &palette, |ui| {
        ui.horizontal(|ui| {
            widgets::section_title(ui, &palette, "HTM activity");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::ghost_button(ui, &palette, "Clear", !app.log.is_empty()).clicked() {
                    app.log.clear();
                }
                widgets::copy_button(ui, &palette, &joined);
                let mut autoscroll = app.logs_ui.autoscroll;
                if ui.checkbox(&mut autoscroll, "Follow").changed() {
                    app.logs_ui.autoscroll = autoscroll;
                }
            });
        });

        ui.horizontal(|ui| {
            let current = levels
                .iter()
                .find(|(rank, _)| *rank == app.logs_ui.min_level)
                .map(|(_, label)| *label)
                .unwrap_or("Everything");
            egui::ComboBox::from_id_source("htm-log-level")
                .selected_text(current)
                .width(190.0)
                .show_ui(ui, |ui| {
                    for (rank, label) in levels {
                        ui.selectable_value(&mut app.logs_ui.min_level, rank, label);
                    }
                });
            widgets::text_field(ui, &mut app.logs_ui.filter, 280.0, "Filter…");
            widgets::hint(
                ui,
                &palette,
                &format!("{} of {total} lines", lines.len()),
            );
        });

        ui.add_space(SPACE_S);

        if lines.is_empty() {
            widgets::empty_state(
                ui,
                &palette,
                "Nothing logged yet",
                "Actions you take are recorded here, including every command HTM runs on the \
                 servers.",
            );
            return;
        }

        widgets::inset(ui, &palette, |ui| {
            egui::ScrollArea::vertical()
                .max_height(320.0)
                .auto_shrink([false, false])
                .stick_to_bottom(app.logs_ui.autoscroll)
                .show(ui, |ui| {
                    for line in app.log.iter() {
                        if severity_rank(line.level) < min_level {
                            continue;
                        }
                        if !filter.is_empty()
                            && !line.text.to_lowercase().contains(&filter)
                            && !line
                                .scope
                                .as_ref()
                                .map(|s| s.to_lowercase().contains(&filter))
                                .unwrap_or(false)
                        {
                            continue;
                        }
                        ui.label(
                            RichText::new(line.render())
                                .font(crate::theme::mono_small_font())
                                .color(widgets::level_color(&palette, line.level)),
                        );
                    }
                });
        });
    });
}

fn severity_rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Trace | LogLevel::Debug => 0,
        LogLevel::Info | LogLevel::Success => 1,
        LogLevel::Warn => 2,
        LogLevel::Error => 3,
    }
}

fn remote_log_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let tunnels: Vec<(String, String)> = app
        .state
        .tunnels
        .iter()
        .map(|t| (t.id.clone(), t.plan.instance.clone()))
        .collect();

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "Server journal");

        if tunnels.is_empty() {
            widgets::empty_state(
                ui,
                &palette,
                "No tunnels to read logs from",
                "Create a tunnel first; its systemd journal will be readable here.",
            );
            return;
        }

        ui.horizontal(|ui| {
            let selected_name = app
                .logs_ui
                .remote_instance
                .as_ref()
                .and_then(|id| tunnels.iter().find(|(tid, _)| tid == id))
                .map(|(_, name)| name.clone())
                .unwrap_or_else(|| "Choose a tunnel".to_string());

            egui::ComboBox::from_id_source("htm-remote-log-tunnel")
                .selected_text(selected_name)
                .width(220.0)
                .show_ui(ui, |ui| {
                    for (id, name) in &tunnels {
                        if ui
                            .selectable_label(
                                app.logs_ui.remote_instance.as_deref() == Some(id.as_str()),
                                name,
                            )
                            .clicked()
                        {
                            app.logs_ui.remote_instance = Some(id.clone());
                        }
                    }
                });

            for side in [TunnelSide::Client, TunnelSide::Server] {
                let label = match side {
                    TunnelSide::Client => "Relay",
                    TunnelSide::Server => "Exit",
                };
                let selected = app.logs_ui.remote_side == side;
                if ui.selectable_label(selected, label).clicked() {
                    app.logs_ui.remote_side = side;
                }
            }

            let mut follow = app.logs_ui.follow_remote;
            if ui.checkbox(&mut follow, "Follow").changed() {
                app.logs_ui.follow_remote = follow;
            }

            if widgets::ghost_button(
                ui,
                &palette,
                "Fetch now",
                app.logs_ui.remote_instance.is_some(),
            )
            .clicked()
            {
                app.actions.push(Action::PollRemoteLogs);
            }
        });

        widgets::hint(
            ui,
            &palette,
            "HTM reads the journal with a cursor, so each refresh fetches only what is new \
             rather than the whole log again.",
        );

        ui.add_space(SPACE_S);

        let Some(instance_id) = app.logs_ui.remote_instance.clone() else {
            widgets::empty_state(
                ui,
                &palette,
                "No tunnel selected",
                "Pick one above to read its journal from the server.",
            );
            return;
        };

        let key = (instance_id.clone(), app.logs_ui.remote_side);
        let lines = app.logs_ui.remote_lines.get(&key).cloned().unwrap_or_default();

        if lines.is_empty() {
            widgets::empty_state(
                ui,
                &palette,
                "Nothing fetched yet",
                "Press Fetch now, or tick Follow to poll every couple of seconds.",
            );
            return;
        }

        ui.horizontal(|ui| {
            widgets::hint(ui, &palette, &format!("{} lines", lines.len()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                widgets::copy_button(ui, &palette, &lines.join("\n"));
                if widgets::ghost_button(ui, &palette, "Clear view", true).clicked() {
                    app.logs_ui.remote_lines.remove(&key);
                    app.logs_ui.remote_cursor.remove(&key);
                }
            });
        });

        widgets::inset(ui, &palette, |ui| {
            egui::ScrollArea::vertical()
                .max_height(380.0)
                .auto_shrink([false, false])
                .stick_to_bottom(app.logs_ui.follow_remote)
                .show(ui, |ui| {
                    for line in &lines {
                        ui.label(
                            RichText::new(line)
                                .font(crate::theme::mono_small_font())
                                .color(journal_color(&palette, line)),
                        );
                    }
                });
        });
    });
}

/// Colour a journal line by the severity words the tunnel software uses.
///
/// The journal is plain text, so this is a heuristic — but it is the
/// difference between scanning a wall of grey and spotting the one red line.
fn journal_color(palette: &crate::theme::Palette, line: &str) -> egui::Color32 {
    let lower = line.to_lowercase();
    if lower.contains("error") || lower.contains("panic") || lower.contains("failed") {
        palette.error
    } else if lower.contains("warn") {
        palette.warn
    } else if lower.contains("established") || lower.contains("ready") || lower.contains(" up ") {
        palette.success
    } else if lower.contains("debug") || lower.contains("trace") {
        palette.text_faint
    } else {
        palette.text_muted
    }
}
