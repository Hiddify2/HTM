//! The window chrome: title bar, step navigation, activity bar, toasts and the
//! modal layer.

use egui::{Align2, Color32, Context, Id, LayerId, Order, RichText, Rounding, Sense, Stroke, Vec2};

use htm_core::jobs::LogLevel;

use crate::app::{Action, HtmApp};
use crate::state::Tab;
use crate::theme::{self, R_CARD, R_CONTROL, SPACE_M, SPACE_S};
use crate::views;
use crate::widgets;

pub fn show(app: &mut HtmApp, ctx: &Context) {
    title_bar(app, ctx);
    tab_bar(app, ctx);
    activity_bar(app, ctx);

    let modal_open = app.modal.is_some() || app.wizard.open;
    let palette = app.palette;

    egui::CentralPanel::default()
        .frame(
            egui::Frame::none()
                .fill(palette.ground)
                .inner_margin(egui::Margin::symmetric(SPACE_M, SPACE_M)),
        )
        .show(ctx, |ui| {
            ui.add_enabled_ui(!modal_open, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let tab = app.tab;
                        widgets::page_header(ui, &palette, tab.title(), tab.subtitle());

                        if let Some(note) = app.startup_note.clone() {
                            widgets::notice(ui, &palette, LogLevel::Warn, &note);
                            ui.add_space(SPACE_S);
                            if widgets::ghost_button(ui, &palette, "Dismiss", true).clicked() {
                                app.startup_note = None;
                            }
                            ui.add_space(SPACE_S);
                        }

                        match tab {
                            Tab::Servers => views::servers::show(app, ui),
                            Tab::Install => views::install::show(app, ui),
                            Tab::Benchmark => views::benchmark::show(app, ui),
                            Tab::Tunnels => views::tunnels::show(app, ui),
                            Tab::Logs => views::logs::show(app, ui),
                            Tab::Settings => views::settings::show(app, ui),
                        }

                        // Room to scroll past the last card.
                        ui.add_space(40.0);
                    });
            });
        });

    if modal_open {
        dim(ctx, &palette);
    }
    views::wizard::show(app, ctx);
    views::modals::show(app, ctx);
    toasts(app, ctx);
}

/// Paint a translucent cover over the interface behind a modal.
fn dim(ctx: &Context, palette: &theme::Palette) {
    let painter = ctx.layer_painter(LayerId::new(Order::Middle, Id::new("htm-modal-dim")));
    let shade = if palette.is_dark {
        Color32::from_black_alpha(150)
    } else {
        Color32::from_black_alpha(90)
    };
    painter.rect_filled(ctx.screen_rect(), Rounding::ZERO, shade);
}

fn title_bar(app: &mut HtmApp, ctx: &Context) {
    let palette = app.palette;
    egui::TopBottomPanel::top("htm-title")
        .exact_height(54.0)
        .frame(
            egui::Frame::none()
                .fill(palette.panel)
                .inner_margin(egui::Margin::symmetric(SPACE_M, SPACE_S)),
        )
        .show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                mark(ui, &palette);
                ui.add_space(SPACE_S);
                ui.vertical(|ui| {
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("Hiddify Tunnel Manager")
                            .font(theme::title_font())
                            .color(palette.text),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} · v{}",
                            app.provider.name(),
                            htm_core::VERSION
                        ))
                        .font(theme::label_font())
                        .color(palette.text_muted),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let icon = if app.state.settings.dark_mode {
                        "Light theme"
                    } else {
                        "Dark theme"
                    };
                    if widgets::ghost_button(ui, &palette, icon, true).clicked() {
                        app.state.settings.dark_mode = !app.state.settings.dark_mode;
                        app.mark_dirty();
                    }

                    if widgets::ghost_button(ui, &palette, "Save now", true).clicked() {
                        app.push(Action::SaveNow);
                    }

                    // A quiet indicator rather than a nag: people should be
                    // able to see at a glance that nothing is pending.
                    let (text, color) = if app.any_foreground_job() {
                        ("Working", palette.accent)
                    } else {
                        ("Idle", palette.text_faint)
                    };
                    widgets::pill(ui, &palette, text, color);
                });
            });
        });
}

/// The HTM monogram: a small tunnel drawn as two nested rounded rectangles.
fn mark(ui: &mut egui::Ui, palette: &theme::Palette) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(32.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(
        rect,
        Rounding::same(9.0),
        theme::lerp_color(palette.surface, palette.accent, 0.25),
    );
    painter.rect_stroke(
        rect,
        Rounding::same(9.0),
        Stroke::new(1.0, palette.accent.gamma_multiply(0.8)),
    );
    painter.text(
        rect.center(),
        Align2::CENTER_CENTER,
        "H",
        egui::FontId::new(16.0, egui::FontFamily::Proportional),
        palette.accent,
    );
}

fn tab_bar(app: &mut HtmApp, ctx: &Context) {
    let palette = app.palette;
    egui::TopBottomPanel::top("htm-tabs")
        .exact_height(42.0)
        .frame(
            egui::Frame::none()
                .fill(palette.ground)
                .inner_margin(egui::Margin::symmetric(SPACE_M, 6.0)),
        )
        .show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                for tab in Tab::ALL {
                    let selected = app.tab == tab;
                    let label = match tab.step_number() {
                        Some(n) => format!("{n}. {}", tab.title()),
                        None => tab.title().to_string(),
                    };

                    let text_color = if selected {
                        palette.text
                    } else {
                        palette.text_muted
                    };
                    let button = egui::Button::new(RichText::new(label).color(text_color))
                        .fill(if selected {
                            palette.surface
                        } else {
                            Color32::TRANSPARENT
                        })
                        .stroke(if selected {
                            Stroke::new(1.0, palette.border_strong)
                        } else {
                            Stroke::NONE
                        })
                        .rounding(Rounding::same(R_CONTROL));

                    if ui.add(button).clicked() {
                        app.push(Action::SwitchTab(tab));
                    }

                    // A dot marks tabs that are not ready to be used yet, so
                    // the order of operations is visible without a wizard.
                    if !selected {
                        if let Some(blocker) = blocker_for(app, tab) {
                            ui.add_space(-4.0);
                            widgets::dot(ui, palette.text_faint);
                            ui.add_space(2.0);
                            let _ = blocker;
                        }
                    }
                }
            });
        });
}

/// Why a tab cannot be used yet, or `None` when it is ready.
fn blocker_for(app: &HtmApp, tab: Tab) -> Option<&'static str> {
    match tab {
        Tab::Install => (!app.both_servers_ready()).then_some("Test both servers first"),
        Tab::Benchmark => (!app.both_servers_ready()).then_some("Test both servers first"),
        Tab::Tunnels => (!app.both_servers_ready()).then_some("Test both servers first"),
        _ => None,
    }
}

fn activity_bar(app: &mut HtmApp, ctx: &Context) {
    let palette = app.palette;
    let active: Vec<(u64, String, String, Option<(u32, u32)>, bool)> = app
        .jobs
        .iter()
        .filter(|j| !j.is_finished() && !j.kind.is_background())
        .map(|j| {
            (
                j.id,
                j.label.clone(),
                j.stage.clone(),
                j.progress,
                j.is_cancelling(),
            )
        })
        .collect();

    if active.is_empty() {
        return;
    }

    egui::TopBottomPanel::bottom("htm-activity")
        .frame(
            egui::Frame::none()
                .fill(palette.panel)
                .stroke(Stroke::new(1.0, palette.border))
                .inner_margin(egui::Margin::symmetric(SPACE_M, SPACE_S)),
        )
        .show(ctx, |ui| {
            for (id, label, stage, progress, cancelling) in active {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(13.0).color(palette.accent));
                    ui.label(RichText::new(label.as_str()).color(palette.text).strong());
                    if !stage.is_empty() {
                        ui.label(
                            RichText::new(format!("· {stage}")).color(palette.text_muted),
                        );
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let label = if cancelling { "Stopping…" } else { "Cancel" };
                        if widgets::danger_button(ui, &palette, label, !cancelling).clicked() {
                            app.push(Action::CancelJob(id));
                        }
                        if let Some((done, total)) = progress {
                            if total > 0 {
                                ui.add_space(SPACE_S);
                                ui.add(
                                    egui::ProgressBar::new(done as f32 / total as f32)
                                        .desired_width(180.0)
                                        .rounding(Rounding::same(R_CONTROL))
                                        .fill(palette.accent)
                                        .text(format!("{done}/{total}")),
                                );
                            }
                        }
                    });
                });
            }
        });
}

fn toasts(app: &mut HtmApp, ctx: &Context) {
    if app.toasts.is_empty() {
        return;
    }
    let palette = app.palette;
    let toasts = app.toasts.clone();

    egui::Area::new(Id::new("htm-toasts"))
        .order(Order::Foreground)
        .anchor(Align2::RIGHT_BOTTOM, Vec2::new(-16.0, -16.0))
        .show(ctx, |ui| {
            ui.vertical(|ui| {
                // Newest at the bottom, nearest the pointer.
                for toast in toasts.iter().rev().take(4).collect::<Vec<_>>().into_iter().rev() {
                    let color = widgets::level_color(&palette, toast.level);
                    // Fade out over the last second of the toast's life.
                    let remaining = crate::state::Toast::LIFETIME
                        .saturating_sub(toast.created.elapsed())
                        .as_secs_f32();
                    let alpha = remaining.clamp(0.0, 1.0);

                    egui::Frame::none()
                        .fill(theme::lerp_color(palette.surface, color, 0.14)
                            .gamma_multiply(0.85 + 0.15 * alpha))
                        .stroke(Stroke::new(1.0, color.gamma_multiply(0.6 * alpha.max(0.3))))
                        .rounding(Rounding::same(R_CARD))
                        .inner_margin(egui::Margin::symmetric(12.0, 9.0))
                        .show(ui, |ui| {
                            ui.set_max_width(420.0);
                            ui.horizontal_wrapped(|ui| {
                                widgets::dot(ui, color);
                                ui.label(RichText::new(toast.text.as_str()).color(palette.text));
                            });
                        });
                    ui.add_space(6.0);
                }
            });
        });
}
