//! The new-tunnel dialog.
//!
//! This is where the benchmark result becomes a real tunnel. The settings that
//! came from the chosen configuration are shown read-only by default, because
//! editing them silently would make the measured numbers a lie; the advanced
//! section unlocks them for anyone who knows what they are doing.

use egui::{Context, RichText, Ui};

use htm_core::jobs::{JobKind, LogLevel};
use htm_core::model::{OptValue, OptionKind, SpoofMode};
use htm_core::util;

use crate::app::{Action, HtmApp};
use crate::theme::{SPACE_M, SPACE_S, SPACE_XS};
use crate::widgets;

const LABEL_W: f32 = 168.0;

pub fn show(app: &mut HtmApp, ctx: &Context) {
    if !app.wizard.open {
        return;
    }
    let palette = app.palette;
    let mut open = true;
    let mut close = false;

    egui::Window::new("New tunnel")
        .order(egui::Order::Foreground)
        .collapsible(false)
        .resizable(true)
        .open(&mut open)
        .default_width(760.0)
        .default_height(620.0)
        .max_height(ctx.screen_rect().height() - 80.0)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .frame(
            egui::Frame::none()
                .fill(palette.surface)
                .stroke(egui::Stroke::new(1.0, palette.border_strong))
                .rounding(egui::Rounding::same(crate::theme::R_CARD))
                .inner_margin(egui::Margin::same(16.0)),
        )
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    body(app, ui, &mut close);
                });
        });

    if !open || close {
        app.push(Action::CloseWizard);
    }
}

fn body(app: &mut HtmApp, ui: &mut Ui, close: &mut bool) {
    let palette = app.palette;
    let creating = app.busy_with(JobKind::CreateTunnel);

    if let Some(source) = app.wizard.source_variant.clone() {
        widgets::accent_card(ui, &palette, palette.success, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("From your benchmark:")
                        .color(palette.success)
                        .strong(),
                );
                ui.label(RichText::new(source).color(palette.text));
            });
            if let (Some(up), Some(down), Some(latency)) = (
                app.wizard.expected_up,
                app.wizard.expected_down,
                app.wizard.expected_latency,
            ) {
                widgets::hint(
                    ui,
                    &palette,
                    &format!(
                        "It measured {} up, {} down, {} round trip. Changing the settings below \
                         will change those numbers.",
                        util::human_bits_per_sec(up),
                        util::human_bits_per_sec(down),
                        util::human_ms(latency)
                    ),
                );
            }
        });
        ui.add_space(SPACE_M);
    }

    // ── Identity and ports ──────────────────────────────────────────────────
    widgets::section_title(ui, &palette, "Tunnel");

    widgets::form_row(ui, &palette, "NAME", LABEL_W, |ui| {
        widgets::text_field(ui, &mut app.wizard.name, 260.0, "main");
    });
    widgets::hint(
        ui,
        &palette,
        "Used for the systemd unit and the configuration file names. Letters, digits, dashes \
         and underscores only.",
    );

    ui.add_space(SPACE_S);

    widgets::form_row(ui, &palette, "FORWARD PORTS", LABEL_W, |ui| {
        widgets::text_field(
            ui,
            &mut app.wizard.forward_ports_text,
            260.0,
            "443, 8443, 2052-2060",
        );
    });

    match util::parse_port_list(&app.wizard.forward_ports_text) {
        Ok(ports) if ports.is_empty() => {
            widgets::notice(
                ui,
                &palette,
                LogLevel::Warn,
                "With no ports listed, every TCP and UDP port arriving at the relay is pushed \
                 through the tunnel. That works, but it also captures the relay's own traffic; \
                 naming the ports you actually serve is safer.",
            );
        }
        Ok(ports) => {
            widgets::hint(
                ui,
                &palette,
                &format!(
                    "{} port(s) on the relay will be forwarded to the exit: {}",
                    ports.len(),
                    util::format_port_list(&ports)
                ),
            );
        }
        Err(problem) => {
            widgets::notice(ui, &palette, LogLevel::Error, &problem);
        }
    }

    ui.add_space(SPACE_S);

    ui.columns(2, |cols| {
        let ui = &mut cols[0];
        widgets::form_row(ui, &palette, "WIRE PORT", LABEL_W, |ui| {
            ui.add(
                egui::DragValue::new(&mut app.wizard.data_port)
                    .range(1..=65535)
                    .speed(1.0),
            );
        });
        widgets::form_row(ui, &palette, "MTU", LABEL_W, |ui| {
            ui.add(
                egui::DragValue::new(&mut app.wizard.mtu)
                    .range(576..=9000)
                    .speed(10.0),
            );
        });

        let ui = &mut cols[1];
        widgets::form_row(ui, &palette, "LOG LEVEL", LABEL_W, |ui| {
            egui::ComboBox::from_id_source("htm-wizard-log")
                .selected_text(app.wizard.log_level.clone())
                .width(150.0)
                .show_ui(ui, |ui| {
                    for level in ["error", "warn", "info", "debug", "trace"] {
                        ui.selectable_value(
                            &mut app.wizard.log_level,
                            level.to_string(),
                            level,
                        );
                    }
                });
        });
        let mut boot = app.wizard.start_on_boot;
        if ui.checkbox(&mut boot, "Start automatically at boot").changed() {
            app.wizard.start_on_boot = boot;
        }
    });

    ui.add_space(SPACE_S);

    ui.horizontal(|ui| {
        widgets::field_label(ui, &palette, "SHARED KEY", LABEL_W);
        ui.label(
            RichText::new(util::truncate(&app.wizard.pre_shared_key, 24))
                .font(crate::theme::mono_font())
                .color(palette.text_muted),
        );
        if widgets::ghost_button(ui, &palette, "Regenerate", true).clicked() {
            app.wizard.pre_shared_key = util::generate_psk();
        }
    });
    widgets::hint(
        ui,
        &palette,
        "Generated for you and written into both configurations. It authenticates every packet \
         and derives the encryption key.",
    );

    widgets::divider(ui, &palette);

    // ── Source addresses ────────────────────────────────────────────────────
    source_addresses(app, ui);

    // ── Provider settings ───────────────────────────────────────────────────
    ui.horizontal(|ui| {
        widgets::section_title(
            ui,
            &palette,
            &format!("{} settings", app.provider.name()),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let label = if app.wizard.show_advanced {
                "Lock settings"
            } else {
                "Edit settings"
            };
            if widgets::ghost_button(ui, &palette, label, true).clicked() {
                app.wizard.show_advanced = !app.wizard.show_advanced;
            }
        });
    });

    if app.wizard.show_advanced {
        options_editor(app, ui);
    } else {
        options_summary(app, ui);
    }

    if let Err(problem) = app.provider.validate_options(&app.wizard.options) {
        ui.add_space(SPACE_S);
        widgets::notice(ui, &palette, LogLevel::Error, &problem);
    }

    widgets::divider(ui, &palette);

    // ── Preview and create ──────────────────────────────────────────────────
    ui.horizontal(|ui| {
        if widgets::primary_button(ui, &palette, "Create and start", !creating).clicked() {
            app.push(Action::CreateTunnel);
        }
        if widgets::ghost_button(ui, &palette, "Preview the configuration", !creating).clicked()
        {
            app.push(Action::PreviewWizardConfig);
        }
        if widgets::ghost_button(ui, &palette, "Cancel", !creating).clicked() {
            *close = true;
        }
    });

    if creating {
        ui.add_space(SPACE_S);
        widgets::busy(
            ui,
            &palette,
            "Writing the configuration, starting both units and waiting for the link to answer…",
        );
    }

    if let Some(error) = app.wizard.error.clone() {
        ui.add_space(SPACE_S);
        widgets::notice(ui, &palette, LogLevel::Error, &error);
    }

    if let Some((relay, exit)) = app.wizard.preview.clone() {
        ui.add_space(SPACE_M);
        widgets::section_title(ui, &palette, "Relay configuration");
        widgets::code_block(ui, &palette, &relay, 260.0);
        ui.add_space(SPACE_S);
        widgets::section_title(ui, &palette, "Exit configuration");
        widgets::code_block(ui, &palette, &exit, 260.0);
    }
}

/// The two ways a tunnel can fill in the source address of its packets.
///
/// Presented as two labelled cards rather than a checkbox, because they are a
/// genuine either-or with very different consequences, and because a checkbox
/// called "spoof" tells a reader nothing about which one they want.
fn source_addresses(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let current = app.wizard.spoofing.mode;
    let mut chosen = current;

    widgets::section_title(ui, &palette, "Source addresses");
    widgets::hint(
        ui,
        &palette,
        "What each server writes as the sender of the packets it puts on the wire.",
    );
    ui.add_space(SPACE_S);

    ui.columns(2, |cols| {
        for (index, mode) in SpoofMode::ALL.into_iter().enumerate() {
            let ui = &mut cols[index];
            let selected = current == mode;
            let accent = if selected {
                palette.accent
            } else {
                palette.border
            };

            let response = egui::Frame::none()
                .fill(if selected {
                    crate::theme::lerp_color(palette.surface, palette.accent, 0.12)
                } else {
                    palette.inset
                })
                .stroke(egui::Stroke::new(if selected { 1.5 } else { 1.0 }, accent))
                .rounding(egui::Rounding::same(crate::theme::R_CONTROL))
                .inner_margin(egui::Margin::same(12.0))
                .show(ui, |ui| {
                    ui.set_min_height(104.0);
                    ui.horizontal(|ui| {
                        widgets::dot(
                            ui,
                            if selected {
                                palette.accent
                            } else {
                                palette.text_faint
                            },
                        );
                        ui.label(
                            RichText::new(mode.display_name())
                                .color(palette.text)
                                .strong(),
                        );
                        if mode == SpoofMode::Original {
                            widgets::pill(ui, &palette, "recommended", palette.success);
                        }
                    });
                    ui.add_space(SPACE_XS);
                    widgets::hint(ui, &palette, mode.help());
                })
                .response
                .interact(egui::Sense::click());

            if response.clicked() {
                chosen = mode;
            }
        }
    });

    if chosen != current {
        app.wizard.spoofing.mode = chosen;
    }

    if app.wizard.spoofing.is_forged() {
        ui.add_space(SPACE_S);
        widgets::form_row(ui, &palette, "ADDRESS LIST", LABEL_W, |ui| {
            widgets::text_field(
                ui,
                &mut app.wizard.spoof_pool_text,
                340.0,
                "8.8.8.8, 1.1.1.1, 9.9.9.9, 208.67.222.222",
            );
        });

        // Show the split immediately: which address each server will claim is
        // the thing most likely to surprise someone, so it should never have to
        // be guessed.
        let addresses = crate::app::parse_address_list(&app.wizard.spoof_pool_text);
        if addresses.is_empty() {
            widgets::hint(
                ui,
                &palette,
                "Enter at least two addresses, separated by commas or spaces. Each server needs \
                 its own; extra addresses are rotated between sessions.",
            );
        } else {
            let plan = htm_core::model::SpoofPlan::from_list(&addresses);
            match plan.validate() {
                Ok(()) => {
                    widgets::inset(ui, &palette, |ui| {
                        widgets::kv_mono(
                            ui,
                            &palette,
                            "RELAY SENDS AS",
                            &plan.client_pool.join(", "),
                            LABEL_W,
                        );
                        widgets::kv_mono(
                            ui,
                            &palette,
                            "EXIT SENDS AS",
                            &plan.server_pool.join(", "),
                            LABEL_W,
                        );
                    });
                    ui.add_space(SPACE_XS);
                    widgets::hint(
                        ui,
                        &palette,
                        "Addresses alternate between the two servers. Each one also accepts \
                         every address the other was given, so rotation cannot break the link.",
                    );
                }
                Err(problem) => {
                    widgets::notice(ui, &palette, LogLevel::Error, &problem);
                }
            }
        }

        ui.add_space(SPACE_S);
        widgets::notice(
            ui,
            &palette,
            LogLevel::Warn,
            "Most hosting providers drop packets whose source address is not one of yours. If \
             either provider does that, the tunnel will not carry any traffic at all. Benchmark \
             this mode before relying on it.",
        );
    }

    widgets::divider(ui, &palette);
}

/// Read-only view of the settings, which is what most people should see.
fn options_summary(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let space = app.provider.option_space();

    widgets::inset(ui, &palette, |ui| {
        egui::Grid::new("htm-wizard-options-summary")
            .num_columns(4)
            .spacing(egui::vec2(16.0, 4.0))
            .show(ui, |ui| {
                let mut column = 0;
                for spec in &space.specs {
                    let Some(value) = app.wizard.options.get(&spec.key) else {
                        continue;
                    };
                    // Only the settings that differ from the provider default
                    // are worth the reader's attention.
                    if value == &spec.default {
                        continue;
                    }
                    ui.label(
                        RichText::new(spec.label.as_str())
                            .font(crate::theme::label_font())
                            .color(palette.text_muted),
                    );
                    ui.label(
                        RichText::new(spec.label_for(value))
                            .font(crate::theme::mono_small_font())
                            .color(palette.text),
                    );
                    column += 1;
                    if column % 2 == 0 {
                        ui.end_row();
                    }
                }
                if column % 2 != 0 {
                    ui.label("");
                    ui.label("");
                    ui.end_row();
                }
                if column == 0 {
                    ui.label(
                        RichText::new("Everything is at its default.")
                            .color(palette.text_faint),
                    );
                    ui.end_row();
                }
            });
    });
}

/// The full editor, one row per setting, grouped as the provider declared.
fn options_editor(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let space = app.provider.option_space();

    widgets::notice(
        ui,
        &palette,
        LogLevel::Warn,
        "Changing these moves you away from the configuration that was measured. Settings both \
         sides must agree on are written identically to each server, so they cannot drift apart.",
    );
    ui.add_space(SPACE_S);

    for group in space.groups() {
        ui.label(
            RichText::new(group.as_str())
                .font(crate::theme::label_font())
                .color(palette.accent),
        );
        ui.add_space(SPACE_XS);

        for spec in space.specs.iter().filter(|s| s.group == group) {
            let current = app
                .wizard
                .options
                .get(&spec.key)
                .cloned()
                .unwrap_or_else(|| spec.default.clone());

            let response = ui
                .horizontal(|ui| {
                    widgets::field_label(ui, &palette, &spec.label.to_uppercase(), 200.0);
                    match &spec.kind {
                        OptionKind::Toggle => {
                            let mut value = current.as_bool().unwrap_or(false);
                            if ui.checkbox(&mut value, "").changed() {
                                app.wizard
                                    .options
                                    .insert(spec.key.clone(), OptValue::Bool(value));
                            }
                        }
                        OptionKind::Int { min, max } => {
                            let mut value = current.as_int().unwrap_or(*min);
                            if ui
                                .add(egui::DragValue::new(&mut value).range(*min..=*max))
                                .changed()
                            {
                                app.wizard
                                    .options
                                    .insert(spec.key.clone(), OptValue::Int(value));
                            }
                        }
                        OptionKind::Text => {
                            let mut value =
                                current.as_str().unwrap_or_default().to_string();
                            if widgets::text_field(ui, &mut value, 240.0, "").changed() {
                                app.wizard
                                    .options
                                    .insert(spec.key.clone(), OptValue::Text(value));
                            }
                        }
                        OptionKind::Choice { choices } => {
                            let current_value =
                                current.as_str().unwrap_or_default().to_string();
                            let shown = choices
                                .iter()
                                .find(|(v, _)| v == &current_value)
                                .map(|(_, label)| label.clone())
                                .unwrap_or_else(|| current_value.clone());
                            egui::ComboBox::from_id_source(("htm-wizard-opt", &spec.key))
                                .selected_text(shown)
                                .width(260.0)
                                .show_ui(ui, |ui| {
                                    for (value, label) in choices {
                                        if ui
                                            .selectable_label(value == &current_value, label)
                                            .clicked()
                                        {
                                            app.wizard.options.insert(
                                                spec.key.clone(),
                                                OptValue::Choice(value.clone()),
                                            );
                                        }
                                    }
                                });
                        }
                    }
                })
                .response;
            response.on_hover_text(&spec.help);
        }
        ui.add_space(SPACE_S);
    }

    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, &palette, "Reset to defaults", true).clicked() {
            let defaults = app.provider.default_options();
            app.wizard.options = defaults;
        }
        widgets::hint(
            ui,
            &palette,
            "Settings a transport ignores are folded away before the configuration is written.",
        );
    });
}
