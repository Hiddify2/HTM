//! Step 3: measuring real configurations, and choosing one.
//!
//! The results table is the centre of the app. It is deliberately dense —
//! comparing a dozen configurations is the whole point — but every column is
//! sortable and the best row is always obvious, because score is a single
//! number and the bar behind it is coloured.

use egui::{RichText, Ui};

use htm_core::jobs::{JobKind, LogLevel};
use htm_core::model::{
    BenchOutcome, BenchResult, BenchRun, OptValue, ScoreWeights, ThroughputTool,
};
use htm_core::util;

use crate::app::{Action, HtmApp};
use crate::state::{BenchSort, Tab};
use crate::theme::{Palette, SPACE_M, SPACE_S, SPACE_XS};
use crate::widgets;

const LABEL_W: f32 = 168.0;

pub fn show(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;

    if !app.both_servers_ready() {
        widgets::notice(
            ui,
            &palette,
            LogLevel::Warn,
            "Benchmarking brings tunnels up and down on both servers, so both need to pass a \
             connection test first.",
        );
        ui.add_space(SPACE_S);
        if widgets::ghost_button(ui, &palette, "← Back to servers", true).clicked() {
            app.push(Action::SwitchTab(Tab::Servers));
        }
        ui.add_space(SPACE_M);
    }

    // Keep the variant preview in step with the matrix.
    let provider = app.provider.clone();
    app.bench_ui.refresh_preview(&provider);

    control_card(app, ui);
    ui.add_space(SPACE_M);

    if app.bench_ui.show_matrix {
        matrix_card(app, ui);
        ui.add_space(SPACE_M);
    }
    if app.bench_ui.show_settings {
        settings_card(app, ui);
        ui.add_space(SPACE_M);
    }

    results_card(app, ui);
}

fn control_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let running = app.busy_with(JobKind::Benchmark);
    let ready = app.both_servers_ready();
    let count = app.bench_ui.preview_variants.len();
    let per_variant = app.state.settings.bench.seconds_per_variant();
    let estimate = util::human_duration_secs((per_variant * count as f64) as u64);

    let presets = app.provider.matrix_presets();
    let mut apply_preset: Option<String> = None;
    let mut toggle_matrix = false;
    let mut toggle_settings = false;
    let mut run = false;
    let mut cancel = false;

    widgets::card(ui, &palette, |ui| {
        ui.horizontal(|ui| {
            widgets::section_title(ui, &palette, "What to measure");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if running {
                    if widgets::danger_button(ui, &palette, "Stop", true).clicked() {
                        cancel = true;
                    }
                } else if widgets::primary_button(
                    ui,
                    &palette,
                    "Run benchmark",
                    ready && count > 0,
                )
                .clicked()
                {
                    run = true;
                }
            });
        });

        let current_preset = app.bench_ui.preset_id.clone();
        let preset_name = presets
            .iter()
            .find(|p| p.id == current_preset)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "Custom".to_string());

        widgets::form_row(ui, &palette, "PRESET", LABEL_W, |ui| {
            egui::ComboBox::from_id_source("htm-bench-preset")
                .selected_text(&preset_name)
                .width(280.0)
                .show_ui(ui, |ui| {
                    for preset in &presets {
                        if ui
                            .selectable_label(preset.id == current_preset, &preset.name)
                            .clicked()
                        {
                            apply_preset = Some(preset.id.clone());
                        }
                    }
                });
        });

        if let Some(preset) = presets.iter().find(|p| p.id == current_preset) {
            ui.add_space(SPACE_XS);
            widgets::hint(ui, &palette, &preset.description);
        }

        ui.add_space(SPACE_S);
        ui.horizontal(|ui| {
            widgets::metric(
                ui,
                &palette,
                "CONFIGURATIONS",
                &count.to_string(),
                Some("after removing duplicates"),
            );
            ui.add_space(SPACE_M);
            widgets::metric(
                ui,
                &palette,
                "ESTIMATED TIME",
                &estimate,
                Some(&format!("about {per_variant:.0}s each")),
            );
            ui.add_space(SPACE_M);
            widgets::metric(
                ui,
                &palette,
                "MEASURED WITH",
                app.state.settings.bench.tool.display_name(),
                None,
            );
        });

        if count == 0 {
            ui.add_space(SPACE_S);
            widgets::notice(
                ui,
                &palette,
                LogLevel::Warn,
                "Nothing is selected to vary, so there is nothing to compare. Pick a preset or \
                 choose values in the matrix below.",
            );
        } else if count > 40 {
            ui.add_space(SPACE_S);
            widgets::notice(
                ui,
                &palette,
                LogLevel::Warn,
                &format!(
                    "{count} configurations will take roughly {estimate}. Each one brings the \
                     tunnel up and down on both servers, so the link is unusable for other \
                     traffic while this runs."
                ),
            );
        }

        widgets::divider(ui, &palette);
        ui.horizontal(|ui| {
            let matrix_label = if app.bench_ui.show_matrix {
                "▾ Matrix"
            } else {
                "▸ Matrix"
            };
            if widgets::ghost_button(ui, &palette, matrix_label, true).clicked() {
                toggle_matrix = true;
            }
            let settings_label = if app.bench_ui.show_settings {
                "▾ Measurement settings"
            } else {
                "▸ Measurement settings"
            };
            if widgets::ghost_button(ui, &palette, settings_label, true).clicked() {
                toggle_settings = true;
            }
        });
    });

    if let Some(id) = apply_preset {
        app.push(Action::ApplyBenchPreset(id));
    }
    if toggle_matrix {
        app.bench_ui.show_matrix = !app.bench_ui.show_matrix;
    }
    if toggle_settings {
        app.bench_ui.show_settings = !app.bench_ui.show_settings;
    }
    if run {
        app.push(Action::RunBenchmark);
    }
    if cancel {
        app.push(Action::CancelAllJobs);
    }
}

fn matrix_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let space = app.provider.option_space();
    let mut changed = false;

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "Matrix");
        widgets::hint(
            ui,
            &palette,
            "Pick the values to try for each setting. Everything you leave untouched stays at \
             its default. Combinations a transport would ignore are folded together, so the \
             count above is what will actually be measured.",
        );
        ui.add_space(SPACE_S);

        for group in space.groups() {
            let specs: Vec<_> = space
                .specs
                .iter()
                .filter(|s| s.benchmarkable && s.group == group)
                .collect();
            if specs.is_empty() {
                continue;
            }

            ui.label(
                RichText::new(group.as_str())
                    .font(crate::theme::label_font())
                    .color(palette.accent),
            );
            ui.add_space(SPACE_XS);

            for spec in specs {
                ui.horizontal_wrapped(|ui| {
                    widgets::field_label(ui, &palette, &spec.label.to_uppercase(), LABEL_W);

                    let values = spec.sweep_values();
                    let selected = app.bench_ui.selection.dimensions.get(&spec.key).cloned();

                    for value in values {
                        let is_on = selected
                            .as_ref()
                            .map(|v| v.contains(&value))
                            .unwrap_or(false);
                        let text = spec.label_for(&value);
                        let button = egui::Button::new(
                            RichText::new(text).color(if is_on {
                                palette.accent_text
                            } else {
                                palette.text_muted
                            }),
                        )
                        .fill(if is_on {
                            palette.accent
                        } else {
                            palette.surface_raised
                        })
                        .rounding(egui::Rounding::same(crate::theme::R_CONTROL))
                        .small();

                        if ui.add(button).clicked() {
                            toggle_value(app, &spec.key, value);
                            changed = true;
                        }
                    }
                })
                .response
                .on_hover_text(&spec.help);
                ui.add_space(SPACE_XS);
            }
            ui.add_space(SPACE_S);
        }

        widgets::divider(ui, &palette);
        ui.horizontal(|ui| {
            if widgets::ghost_button(ui, &palette, "Clear the matrix", true).clicked() {
                app.bench_ui.selection.dimensions.clear();
                changed = true;
            }
            widgets::hint(
                ui,
                &palette,
                "Selecting a setting here overrides the preset; the preset name becomes Custom.",
            );
        });
    });

    if changed {
        app.bench_ui.preset_id = "custom".to_string();
        let provider = app.provider.clone();
        app.bench_ui.refresh_preview(&provider);
    }
}

/// Add or remove one value from a swept dimension.
fn toggle_value(app: &mut HtmApp, key: &str, value: OptValue) {
    let entry = app
        .bench_ui
        .selection
        .dimensions
        .entry(key.to_string())
        .or_default();
    if let Some(index) = entry.iter().position(|v| v == &value) {
        entry.remove(index);
    } else {
        entry.push(value);
    }
    // An empty list means "do not vary this", which is cleaner expressed by
    // the key being absent.
    if entry.is_empty() {
        app.bench_ui.selection.dimensions.remove(key);
    }
}

fn settings_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let mut settings = app.state.settings.bench.clone();
    let mut changed = false;

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "Measurement settings");
        widgets::hint(
            ui,
            &palette,
            "Longer runs give steadier numbers and take proportionally longer. Eight seconds per \
             direction is usually enough to tell configurations apart.",
        );
        ui.add_space(SPACE_S);

        ui.columns(2, |cols| {
            let ui = &mut cols[0];
            changed |= widgets::form_row(ui, &palette, "SECONDS PER TEST", LABEL_W, |ui| {
                ui.add(
                    egui::DragValue::new(&mut settings.throughput_secs)
                        .range(1..=120)
                        .suffix(" s"),
                )
                .changed()
            });
            changed |= widgets::form_row(ui, &palette, "PARALLEL STREAMS", LABEL_W, |ui| {
                ui.add(egui::DragValue::new(&mut settings.parallel_streams).range(1..=64))
                    .changed()
            });
            changed |= widgets::form_row(ui, &palette, "PING COUNT", LABEL_W, |ui| {
                ui.add(egui::DragValue::new(&mut settings.ping_count).range(1..=500))
                    .changed()
            });
            changed |= widgets::form_row(ui, &palette, "PING INTERVAL", LABEL_W, |ui| {
                ui.add(
                    egui::DragValue::new(&mut settings.ping_interval_ms)
                        .range(20..=5000)
                        .suffix(" ms"),
                )
                .changed()
            });
            changed |= widgets::form_row(ui, &palette, "REPEAT EACH", LABEL_W, |ui| {
                ui.add(egui::DragValue::new(&mut settings.repeats).range(1..=10))
                    .changed()
            });

            let ui = &mut cols[1];
            changed |= widgets::form_row(ui, &palette, "STARTUP TIMEOUT", LABEL_W, |ui| {
                ui.add(
                    egui::DragValue::new(&mut settings.handshake_timeout_secs)
                        .range(5..=600)
                        .suffix(" s"),
                )
                .changed()
            });
            changed |= widgets::form_row(ui, &palette, "SETTLE", LABEL_W, |ui| {
                ui.add(
                    egui::DragValue::new(&mut settings.settle_secs)
                        .range(0..=30)
                        .suffix(" s"),
                )
                .changed()
            });
            changed |= widgets::form_row(ui, &palette, "UDP RATE", LABEL_W, |ui| {
                ui.add(
                    egui::DragValue::new(&mut settings.udp_target_mbits)
                        .range(1..=10_000)
                        .suffix(" Mbit/s"),
                )
                .changed()
            });
            changed |= widgets::form_row(ui, &palette, "STOP AFTER", LABEL_W, |ui| {
                let response = ui.add(
                    egui::DragValue::new(&mut settings.abort_after_failures)
                        .range(0..=50)
                        .suffix(" failures"),
                );
                response.on_hover_text("0 means never give up early.").changed()
            });
            changed |= widgets::form_row(ui, &palette, "TOOL", LABEL_W, |ui| {
                let mut changed = false;
                egui::ComboBox::from_id_source("htm-bench-tool")
                    .selected_text(settings.tool.display_name())
                    .width(240.0)
                    .show_ui(ui, |ui| {
                        for tool in ThroughputTool::ALL {
                            changed |= ui
                                .selectable_value(&mut settings.tool, tool, tool.display_name())
                                .changed();
                        }
                    });
                changed
            });
        });

        ui.add_space(SPACE_S);
        changed |= ui
            .checkbox(
                &mut settings.test_downlink,
                "Measure the exit-to-relay direction as well",
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut settings.test_udp,
                "Measure UDP jitter and packet loss",
            )
            .changed();

        widgets::divider(ui, &palette);

        widgets::section_title(ui, &palette, "What matters to you");
        widgets::hint(
            ui,
            &palette,
            "These weights decide the score. Only their ratios matter, and changing them \
             re-scores results you have already measured.",
        );
        ui.add_space(SPACE_S);

        ui.horizontal(|ui| {
            if widgets::ghost_button(ui, &palette, "Balanced", true).clicked() {
                settings.weights = ScoreWeights::default();
                changed = true;
            }
            if widgets::ghost_button(ui, &palette, "Favour throughput", true).clicked() {
                settings.weights = ScoreWeights::throughput();
                changed = true;
            }
            if widgets::ghost_button(ui, &palette, "Favour latency", true).clicked() {
                settings.weights = ScoreWeights::latency();
                changed = true;
            }
        });
        ui.add_space(SPACE_S);

        let weight = |ui: &mut Ui, label: &str, value: &mut f32| {
            widgets::form_row(ui, &palette, label, LABEL_W, |ui| {
                ui.add(egui::Slider::new(value, 0.0..=10.0).show_value(true))
                    .changed()
            })
        };
        changed |= weight(ui, "UPLINK", &mut settings.weights.uplink);
        changed |= weight(ui, "DOWNLINK", &mut settings.weights.downlink);
        changed |= weight(ui, "LATENCY", &mut settings.weights.latency);
        changed |= weight(ui, "JITTER", &mut settings.weights.jitter);
        changed |= weight(ui, "PACKET LOSS", &mut settings.weights.loss);
        changed |= weight(ui, "FAST STARTUP", &mut settings.weights.handshake);

        if let Err(problem) = settings.validate() {
            ui.add_space(SPACE_S);
            widgets::notice(ui, &palette, LogLevel::Error, &problem);
        }
    });

    if changed {
        app.state.settings.bench = settings;
        app.mark_dirty();
        // Re-score whatever is on screen so the weights feel live.
        if let Some(run) = app.bench_ui.current.as_mut() {
            htm_core::model::score_results(
                &mut run.results,
                &app.state.settings.bench.weights,
            );
        }
    }
}

fn results_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let run = app.bench_ui.current.clone();
    let history: Vec<(usize, String)> = app
        .state
        .bench_runs
        .iter()
        .enumerate()
        .map(|(i, r)| {
            (
                i,
                format!(
                    "{} · {} configurations",
                    r.started_at
                        .with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M"),
                    r.results.len()
                ),
            )
        })
        .rev()
        .collect();

    widgets::card(ui, &palette, |ui| {
        ui.horizontal(|ui| {
            widgets::section_title(ui, &palette, "Results");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !history.is_empty() {
                    let selected = match app.bench_ui.history_index {
                        Some(i) => history
                            .iter()
                            .find(|(idx, _)| *idx == i)
                            .map(|(_, label)| label.clone())
                            .unwrap_or_else(|| "Latest".to_string()),
                        None => "Latest run".to_string(),
                    };
                    egui::ComboBox::from_id_source("htm-bench-history")
                        .selected_text(selected)
                        .width(260.0)
                        .show_ui(ui, |ui| {
                            if ui.selectable_label(false, "Latest run").clicked() {
                                app.actions.push(Action::ShowBenchRun(None));
                            }
                            for (index, label) in &history {
                                if ui.selectable_label(false, label).clicked() {
                                    app.actions.push(Action::ShowBenchRun(Some(*index)));
                                }
                            }
                        });
                }
                let mut hide = app.bench_ui.hide_failed;
                if ui.checkbox(&mut hide, "Hide failures").changed() {
                    app.bench_ui.hide_failed = hide;
                }
            });
        });

        let Some(run) = run else {
            widgets::empty_state(
                ui,
                &palette,
                "No measurements yet",
                "Choose a preset above and press Run benchmark. Results appear here as each \
                 configuration finishes.",
            );
            return;
        };

        summary_row(ui, &palette, &run);
        ui.add_space(SPACE_S);
        table(app, ui, &run);

        if let Some(reason) = &run.aborted_reason {
            ui.add_space(SPACE_S);
            widgets::notice(ui, &palette, LogLevel::Warn, reason);
        }
    });

    // The detail pane sits outside the table card so it can be as tall as it
    // needs without pushing the table around.
    if let (Some(run), Some(variant_id)) = (
        app.bench_ui.current.clone(),
        app.bench_ui.selected_variant.clone(),
    ) {
        if let Some(result) = run.results.iter().find(|r| r.variant.id == variant_id) {
            ui.add_space(SPACE_M);
            detail_card(app, ui, result);
        }
    }
}

fn summary_row(ui: &mut Ui, palette: &Palette, run: &BenchRun) {
    let (done, total) = run.progress();
    let completed = run.completed().count();

    ui.horizontal(|ui| {
        widgets::metric(
            ui,
            palette,
            "PROGRESS",
            &format!("{done}/{total}"),
            Some(&format!("{completed} usable")),
        );
        ui.add_space(SPACE_M);

        if let Some(best) = run.best() {
            if let Some(metrics) = best.outcome.metrics() {
                widgets::metric(
                    ui,
                    palette,
                    "BEST CONFIGURATION",
                    &best.variant.label,
                    Some(&format!(
                        "{} up · {} down · {}",
                        util::human_bits_per_sec(metrics.uplink_bps),
                        util::human_bits_per_sec(metrics.downlink_bps),
                        util::human_ms(metrics.latency_avg_ms)
                    )),
                );
            }
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if done < total {
                ui.add(
                    egui::ProgressBar::new(done as f32 / total.max(1) as f32)
                        .desired_width(200.0)
                        .fill(palette.accent)
                        .rounding(egui::Rounding::same(crate::theme::R_CONTROL)),
                );
            }
        });
    });
}

fn table(app: &mut HtmApp, ui: &mut Ui, run: &BenchRun) {
    let palette = app.palette;

    // Order the rows the way the user asked for.
    let mut rows: Vec<&BenchResult> = run
        .results
        .iter()
        .filter(|r| !app.bench_ui.hide_failed || r.outcome.is_completed())
        .collect();
    sort_rows(&mut rows, app.bench_ui.sort, app.bench_ui.sort_descending);

    // Scale the bars against the best value present, not an absolute maximum.
    let max_total = run
        .completed()
        .filter_map(|r| r.outcome.metrics())
        .map(|m| m.total_bps())
        .fold(0.0f64, f64::max)
        .max(1.0);

    let mut clicked_header: Option<BenchSort> = None;
    let mut clicked_row: Option<String> = None;

    egui::ScrollArea::horizontal()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("htm-bench-table")
                .num_columns(9)
                .striped(true)
                .spacing(egui::vec2(14.0, 6.0))
                .min_col_width(56.0)
                .show(ui, |ui| {
                    // ── Header ──────────────────────────────────────────────
                    for sort in BenchSort::ALL {
                        let active = app.bench_ui.sort == sort;
                        let arrow = if !active {
                            ""
                        } else if app.bench_ui.sort_descending {
                            " ↓"
                        } else {
                            " ↑"
                        };
                        let text = RichText::new(format!("{}{arrow}", sort.title()))
                            .font(crate::theme::label_font())
                            .color(if active { palette.accent } else { palette.text_muted });
                        if ui.add(egui::Button::new(text).frame(false)).clicked() {
                            clicked_header = Some(sort);
                        }
                    }
                    ui.label(
                        RichText::new("STATUS")
                            .font(crate::theme::label_font())
                            .color(palette.text_muted),
                    );
                    ui.end_row();

                    // ── Rows ────────────────────────────────────────────────
                    for result in rows {
                        let selected =
                            app.bench_ui.selected_variant.as_deref() == Some(&result.variant.id);
                        let metrics = result.outcome.metrics();

                        // Score
                        match result.score {
                            Some(score) => {
                                widgets::score_bar(ui, &palette, score, 62.0);
                            }
                            None => {
                                ui.label(RichText::new("—").color(palette.text_faint));
                            }
                        }

                        // Throughput columns, with a bar behind the number so
                        // the comparison is visible without reading digits.
                        cell_rate(ui, &palette, metrics.map(|m| m.uplink_bps), max_total);
                        cell_rate(
                            ui,
                            &palette,
                            metrics.filter(|m| m.downlink_tested).map(|m| m.downlink_bps),
                            max_total,
                        );

                        cell_value(
                            ui,
                            &palette,
                            metrics.map(|m| util::human_ms(m.latency_avg_ms)),
                        );
                        cell_value(
                            ui,
                            &palette,
                            metrics.map(|m| util::human_ms(m.effective_jitter_ms())),
                        );
                        cell_value(
                            ui,
                            &palette,
                            metrics.map(|m| format!("{:.2}%", m.effective_loss_pct())),
                        );
                        cell_value(
                            ui,
                            &palette,
                            metrics.map(|m| format!("{:.1}s", m.handshake_secs)),
                        );

                        // Configuration label, clickable.
                        let label = RichText::new(result.variant.label.as_str()).color(if selected {
                            palette.accent
                        } else {
                            palette.text
                        });
                        if ui
                            .add(egui::Button::new(label).frame(selected))
                            .on_hover_text(&result.variant.description)
                            .clicked()
                        {
                            clicked_row = Some(result.variant.id.clone());
                        }

                        // Status
                        let (text, color) = match &result.outcome {
                            BenchOutcome::Completed(_) => ("measured", palette.success),
                            BenchOutcome::Running => ("running", palette.accent),
                            BenchOutcome::Pending => ("queued", palette.text_faint),
                            BenchOutcome::Failed { .. } => ("failed", palette.error),
                            BenchOutcome::Skipped { .. } => ("skipped", palette.warn),
                            BenchOutcome::Cancelled => ("cancelled", palette.text_faint),
                        };
                        widgets::pill(ui, &palette, text, color);

                        ui.end_row();
                    }
                });
        });

    if let Some(sort) = clicked_header {
        if app.bench_ui.sort == sort {
            app.bench_ui.sort_descending = !app.bench_ui.sort_descending;
        } else {
            app.bench_ui.sort = sort;
            app.bench_ui.sort_descending = sort.higher_is_better();
        }
    }
    if let Some(id) = clicked_row {
        app.bench_ui.selected_variant = if app.bench_ui.selected_variant.as_deref() == Some(&id) {
            None
        } else {
            Some(id)
        };
    }
}

fn cell_rate(ui: &mut Ui, palette: &Palette, value: Option<f64>, max: f64) {
    match value {
        Some(bps) if bps > 0.0 => {
            widgets::bar(
                ui,
                palette,
                (bps / max) as f32,
                palette.series[0],
                &util::human_bits_per_sec(bps),
                118.0,
            );
        }
        _ => {
            ui.label(RichText::new("—").color(palette.text_faint));
        }
    }
}

fn cell_value(ui: &mut Ui, palette: &Palette, value: Option<String>) {
    match value {
        Some(text) => {
            ui.label(
                RichText::new(text)
                    .font(crate::theme::mono_small_font())
                    .color(palette.text),
            );
        }
        None => {
            ui.label(RichText::new("—").color(palette.text_faint));
        }
    }
}

fn sort_rows(rows: &mut [&BenchResult], sort: BenchSort, descending: bool) {
    // Incomplete rows always sink to the bottom: they have nothing to compare.
    rows.sort_by(|a, b| {
        let a_done = a.outcome.is_completed();
        let b_done = b.outcome.is_completed();
        if a_done != b_done {
            return b_done.cmp(&a_done);
        }
        if sort == BenchSort::Label {
            let ordering = a.variant.label.cmp(&b.variant.label);
            return if descending { ordering.reverse() } else { ordering };
        }

        let key = |r: &BenchResult| -> f64 {
            let m = r.outcome.metrics();
            match sort {
                BenchSort::Score => r.score.unwrap_or(f64::MIN),
                BenchSort::Uplink => m.map(|m| m.uplink_bps).unwrap_or(f64::MIN),
                BenchSort::Downlink => m.map(|m| m.downlink_bps).unwrap_or(f64::MIN),
                BenchSort::Latency => m.map(|m| m.latency_avg_ms).unwrap_or(f64::MAX),
                BenchSort::Jitter => m.map(|m| m.effective_jitter_ms()).unwrap_or(f64::MAX),
                BenchSort::Loss => m.map(|m| m.effective_loss_pct()).unwrap_or(f64::MAX),
                BenchSort::Handshake => m.map(|m| m.handshake_secs).unwrap_or(f64::MAX),
                BenchSort::Label => 0.0,
            }
        };
        let ordering = key(a)
            .partial_cmp(&key(b))
            .unwrap_or(std::cmp::Ordering::Equal);
        if descending {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

fn detail_card(app: &mut HtmApp, ui: &mut Ui, result: &BenchResult) {
    let palette = app.palette;
    let space = app.provider.option_space();
    let mut create = false;

    widgets::card(ui, &palette, |ui| {
        ui.horizontal(|ui| {
            widgets::section_title(ui, &palette, &result.variant.label);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::primary_button(
                    ui,
                    &palette,
                    "Create a tunnel with this",
                    result.outcome.is_completed(),
                )
                .clicked()
                {
                    create = true;
                }
            });
        });

        widgets::hint(ui, &palette, &result.variant.description);
        ui.add_space(SPACE_S);

        match &result.outcome {
            BenchOutcome::Completed(m) => {
                ui.horizontal_wrapped(|ui| {
                    widgets::metric(
                        ui,
                        &palette,
                        "UPLINK",
                        &util::human_bits_per_sec(m.uplink_bps),
                        Some("relay → exit"),
                    );
                    ui.add_space(SPACE_M);
                    widgets::metric(
                        ui,
                        &palette,
                        "DOWNLINK",
                        &if m.downlink_tested {
                            util::human_bits_per_sec(m.downlink_bps)
                        } else {
                            "not measured".to_string()
                        },
                        Some("exit → relay"),
                    );
                    ui.add_space(SPACE_M);
                    widgets::metric(
                        ui,
                        &palette,
                        "LATENCY",
                        &util::human_ms(m.latency_avg_ms),
                        Some(&format!(
                            "{} min · {} max",
                            util::human_ms(m.latency_min_ms),
                            util::human_ms(m.latency_max_ms)
                        )),
                    );
                    ui.add_space(SPACE_M);
                    widgets::metric(
                        ui,
                        &palette,
                        "JITTER",
                        &util::human_ms(m.effective_jitter_ms()),
                        Some(if m.udp_tested { "from UDP" } else { "from ICMP" }),
                    );
                    ui.add_space(SPACE_M);
                    widgets::metric(
                        ui,
                        &palette,
                        "LOSS",
                        &format!("{:.2}%", m.effective_loss_pct()),
                        Some(&format!("{:.2}% ICMP", m.icmp_loss_pct)),
                    );
                    ui.add_space(SPACE_M);
                    widgets::metric(
                        ui,
                        &palette,
                        "STARTUP",
                        &format!("{:.1}s", m.handshake_secs),
                        Some(&format!("{} retransmits", m.retransmits)),
                    );
                });
            }
            BenchOutcome::Failed {
                reason,
                log_excerpt,
            } => {
                widgets::notice(ui, &palette, LogLevel::Error, reason);
                if !log_excerpt.trim().is_empty() {
                    ui.add_space(SPACE_S);
                    widgets::hint(ui, &palette, "The relay's journal at the time:");
                    widgets::code_block(ui, &palette, log_excerpt, 220.0);
                }
            }
            other => {
                widgets::hint(ui, &palette, &format!("This configuration was {}.", other.label().to_lowercase()));
            }
        }

        widgets::divider(ui, &palette);
        widgets::section_title(ui, &palette, "Settings");

        egui::Grid::new("htm-variant-options")
            .num_columns(2)
            .spacing(egui::vec2(18.0, 4.0))
            .show(ui, |ui| {
                for (key, value) in &result.variant.options {
                    let (label, rendered) = match space.get(key) {
                        Some(spec) => (spec.label.clone(), spec.label_for(value)),
                        None => (key.clone(), value.short_display()),
                    };
                    ui.label(
                        RichText::new(label)
                            .font(crate::theme::label_font())
                            .color(palette.text_muted),
                    );
                    ui.label(
                        RichText::new(rendered)
                            .font(crate::theme::mono_small_font())
                            .color(palette.text),
                    );
                    ui.end_row();
                }
            });
    });

    if create {
        app.push(Action::OpenWizard {
            from_variant: Some(result.variant.id.clone()),
        });
    }
}

