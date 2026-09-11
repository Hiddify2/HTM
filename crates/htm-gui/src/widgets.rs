//! Reusable pieces of the interface.
//!
//! Everything here takes the [`Palette`] explicitly rather than reading it from
//! the context, so a widget can never accidentally use a colour from the wrong
//! theme, and so each helper stays a plain function that is easy to reason
//! about.

use egui::{Align2, Color32, FontId, Rect, Response, RichText, Rounding, Sense, Stroke, Ui, Vec2};

use htm_core::jobs::LogLevel;
use htm_core::model::Health;

use crate::theme::{self, Palette, R_CARD, R_CONTROL, R_PILL, SPACE_S, SPACE_XS};

/// A raised, bordered surface. The basic unit of layout in HTM.
pub fn card<R>(ui: &mut Ui, palette: &Palette, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::none()
        .fill(palette.surface)
        .stroke(Stroke::new(1.0, palette.border))
        .rounding(Rounding::same(R_CARD))
        .inner_margin(egui::Margin::same(14.0))
        .show(ui, add)
        .inner
}

/// A card that draws attention to itself, used for warnings and prompts.
pub fn accent_card<R>(
    ui: &mut Ui,
    palette: &Palette,
    accent: Color32,
    add: impl FnOnce(&mut Ui) -> R,
) -> R {
    egui::Frame::none()
        .fill(theme::lerp_color(palette.surface, accent, 0.10))
        .stroke(Stroke::new(1.0, accent.gamma_multiply(0.7)))
        .rounding(Rounding::same(R_CARD))
        .inner_margin(egui::Margin::same(14.0))
        .show(ui, add)
        .inner
}

/// An inset surface: log panes, config previews, read-only text.
pub fn inset<R>(ui: &mut Ui, palette: &Palette, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::none()
        .fill(palette.inset)
        .stroke(Stroke::new(1.0, palette.border))
        .rounding(Rounding::same(R_CONTROL))
        .inner_margin(egui::Margin::same(9.0))
        .show(ui, add)
        .inner
}

/// A page heading with an explanatory line beneath it.
pub fn page_header(ui: &mut Ui, palette: &Palette, title: &str, subtitle: &str) {
    ui.label(
        RichText::new(title)
            .font(theme::heading_font())
            .color(palette.text),
    );
    if !subtitle.is_empty() {
        ui.add_space(2.0);
        ui.label(RichText::new(subtitle).color(palette.text_muted));
    }
    ui.add_space(SPACE_S);
}

/// A heading inside a card.
pub fn section_title(ui: &mut Ui, palette: &Palette, title: &str) {
    ui.label(
        RichText::new(title)
            .font(theme::title_font())
            .color(palette.text),
    );
    ui.add_space(SPACE_XS);
}

/// Small muted explanatory text.
pub fn hint(ui: &mut Ui, palette: &Palette, text: &str) {
    ui.label(
        RichText::new(text)
            .font(theme::label_font())
            .color(palette.text_muted),
    );
}

/// An uppercase field label, sized so form rows line up.
pub fn field_label(ui: &mut Ui, palette: &Palette, text: &str, width: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 22.0), Sense::hover());
    ui.painter().text(
        rect.left_center(),
        Align2::LEFT_CENTER,
        text,
        theme::label_font(),
        palette.text_muted,
    );
}

/// A labelled form row: label on the left at a fixed width, control on the
/// right. Keeping the label column fixed is what makes a column of fields read
/// as a form rather than a pile of controls.
pub fn form_row<R>(
    ui: &mut Ui,
    palette: &Palette,
    label: &str,
    label_width: f32,
    add: impl FnOnce(&mut Ui) -> R,
) -> R {
    ui.horizontal(|ui| {
        field_label(ui, palette, label, label_width);
        add(ui)
    })
    .inner
}

/// A key and its value, for read-only detail lists.
pub fn kv(ui: &mut Ui, palette: &Palette, key: &str, value: &str, label_width: f32) {
    ui.horizontal(|ui| {
        field_label(ui, palette, key, label_width);
        ui.label(RichText::new(value).color(palette.text));
    });
}

/// A key and a monospaced value, for addresses and fingerprints.
pub fn kv_mono(ui: &mut Ui, palette: &Palette, key: &str, value: &str, label_width: f32) {
    ui.horizontal(|ui| {
        field_label(ui, palette, key, label_width);
        ui.label(
            RichText::new(value)
                .font(theme::mono_font())
                .color(palette.text),
        );
    });
}

/// A rounded status chip.
pub fn pill(ui: &mut Ui, palette: &Palette, text: &str, color: Color32) -> Response {
    let font = theme::label_font();
    let galley = ui.painter().layout_no_wrap(
        text.to_string(),
        font.clone(),
        color,
    );
    let padding = Vec2::new(9.0, 3.0);
    let size = galley.size() + padding * 2.0;
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());

    let bg = theme::lerp_color(palette.surface, color, if palette.is_dark { 0.22 } else { 0.16 });
    ui.painter()
        .rect_filled(rect, Rounding::same(R_PILL), bg);
    ui.painter().rect_stroke(
        rect,
        Rounding::same(R_PILL),
        Stroke::new(1.0, color.gamma_multiply(0.8)),
    );
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        text,
        font,
        color,
    );
    response
}

/// A small filled circle, used as a status dot next to a label.
pub fn dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
    ui.painter()
        .circle_filled(rect.center(), 4.0, color);
}

/// The colour that means this health state.
pub fn health_color(palette: &Palette, health: Health) -> Color32 {
    match health {
        Health::Up => palette.success,
        Health::Partial => palette.warn,
        Health::Down => palette.text_faint,
        Health::Failed => palette.error,
        Health::Unknown => palette.text_muted,
    }
}

/// The colour that means this log severity.
pub fn level_color(palette: &Palette, level: LogLevel) -> Color32 {
    match level {
        LogLevel::Trace | LogLevel::Debug => palette.text_faint,
        LogLevel::Info => palette.text_muted,
        LogLevel::Success => palette.success,
        LogLevel::Warn => palette.warn,
        LogLevel::Error => palette.error,
    }
}

/// A large number with a caption: the headline figures on a results row.
pub fn metric(ui: &mut Ui, palette: &Palette, label: &str, value: &str, sub: Option<&str>) {
    ui.vertical(|ui| {
        ui.label(
            RichText::new(label)
                .font(theme::label_font())
                .color(palette.text_muted),
        );
        ui.label(
            RichText::new(value)
                .font(FontId::new(17.0, egui::FontFamily::Proportional))
                .color(palette.text),
        );
        if let Some(sub) = sub {
            ui.label(
                RichText::new(sub)
                    .font(theme::label_font())
                    .color(palette.text_faint),
            );
        }
    });
}

/// A horizontal bar showing `value` against `max`, with the value written
/// inside. Used to compare benchmark results at a glance.
pub fn bar(
    ui: &mut Ui,
    palette: &Palette,
    fraction: f32,
    color: Color32,
    text: &str,
    width: f32,
) -> Response {
    let height = 18.0;
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());

    ui.painter()
        .rect_filled(rect, Rounding::same(R_CONTROL), palette.inset);

    let fraction = fraction.clamp(0.0, 1.0);
    if fraction > 0.0 {
        let filled = Rect::from_min_size(
            rect.min,
            Vec2::new((rect.width() * fraction).max(2.0), rect.height()),
        );
        ui.painter().rect_filled(
            filled,
            Rounding::same(R_CONTROL),
            color.gamma_multiply(0.55),
        );
    }
    ui.painter().rect_stroke(
        rect,
        Rounding::same(R_CONTROL),
        Stroke::new(1.0, palette.border),
    );

    if !text.is_empty() {
        ui.painter().text(
            rect.left_center() + Vec2::new(7.0, 0.0),
            Align2::LEFT_CENTER,
            text,
            theme::mono_small_font(),
            palette.text,
        );
    }
    response
}

/// A 0-100 score rendered as a coloured bar with the number on it.
pub fn score_bar(ui: &mut Ui, palette: &Palette, score: f64, width: f32) -> Response {
    let color = palette.score_color(score);
    bar(
        ui,
        palette,
        (score / 100.0) as f32,
        color,
        &format!("{score:.0}"),
        width,
    )
}

/// A sparkline over a series of values, drawn without any plotting library.
///
/// Used for the live traffic history on a tunnel card, where the shape matters
/// far more than exact values.
pub fn sparkline(
    ui: &mut Ui,
    palette: &Palette,
    values: &[f64],
    color: Color32,
    size: Vec2,
) -> Response {
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter()
        .rect_filled(rect, Rounding::same(R_CONTROL), palette.inset);

    if values.len() < 2 {
        ui.painter().text(
            rect.center(),
            Align2::CENTER_CENTER,
            "collecting…",
            theme::label_font(),
            palette.text_faint,
        );
        return response;
    }

    let max = values.iter().cloned().fold(0.0f64, f64::max).max(1.0);
    let step = rect.width() / (values.len() - 1) as f32;

    let points: Vec<egui::Pos2> = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = rect.left() + step * i as f32;
            let t = (v / max).clamp(0.0, 1.0) as f32;
            // Inset by two pixels so the peak is not clipped by the border.
            let y = rect.bottom() - 2.0 - t * (rect.height() - 4.0);
            egui::pos2(x, y)
        })
        .collect();

    // A filled area under the line reads better at small sizes than a bare
    // stroke does.
    for pair in points.windows(2) {
        let quad = vec![
            pair[0],
            pair[1],
            egui::pos2(pair[1].x, rect.bottom()),
            egui::pos2(pair[0].x, rect.bottom()),
        ];
        ui.painter().add(egui::Shape::convex_polygon(
            quad,
            color.gamma_multiply(0.18),
            Stroke::NONE,
        ));
    }
    ui.painter()
        .add(egui::Shape::line(points, Stroke::new(1.6, color)));

    ui.painter().rect_stroke(
        rect,
        Rounding::same(R_CONTROL),
        Stroke::new(1.0, palette.border),
    );
    response
}

/// The main call to action. There should be at most one per view.
pub fn primary_button(ui: &mut Ui, palette: &Palette, text: &str, enabled: bool) -> Response {
    let button = egui::Button::new(
        RichText::new(text).color(if enabled {
            palette.accent_text
        } else {
            palette.text_faint
        }),
    )
    .fill(if enabled {
        palette.accent
    } else {
        palette.surface_raised
    })
    .rounding(Rounding::same(R_CONTROL))
    .min_size(Vec2::new(0.0, 28.0));

    ui.add_enabled(enabled, button)
}

/// A destructive action: stopping, removing, uninstalling.
pub fn danger_button(ui: &mut Ui, palette: &Palette, text: &str, enabled: bool) -> Response {
    let button = egui::Button::new(RichText::new(text).color(palette.error))
        .fill(theme::lerp_color(palette.surface_raised, palette.error, 0.12))
        .stroke(Stroke::new(1.0, palette.error.gamma_multiply(0.5)))
        .rounding(Rounding::same(R_CONTROL));
    ui.add_enabled(enabled, button)
}

/// A quiet button for secondary actions.
pub fn ghost_button(ui: &mut Ui, palette: &Palette, text: &str, enabled: bool) -> Response {
    let button = egui::Button::new(RichText::new(text).color(palette.text))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0, palette.border))
        .rounding(Rounding::same(R_CONTROL));
    ui.add_enabled(enabled, button)
}

/// A button that copies text to the clipboard and says so.
pub fn copy_button(ui: &mut Ui, palette: &Palette, value: &str) {
    let response = ghost_button(ui, palette, "Copy", !value.is_empty());
    if response.clicked() {
        ui.ctx().copy_text(value.to_string());
    }
    response.on_hover_text("Copy to the clipboard");
}

/// A single-line text field with a consistent width.
pub fn text_field(ui: &mut Ui, value: &mut String, width: f32, hint_text: &str) -> Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .desired_width(width)
            .hint_text(hint_text),
    )
}

/// A password field with a reveal toggle. The toggle is per call site, stored
/// in egui's temporary memory under `id`.
pub fn password_field(
    ui: &mut Ui,
    value: &mut String,
    width: f32,
    hint_text: &str,
    id: &str,
) -> Response {
    let reveal_id = egui::Id::new(("htm-reveal", id));
    let mut revealed = ui.data(|d| d.get_temp::<bool>(reveal_id).unwrap_or(false));

    let response = ui.add(
        egui::TextEdit::singleline(value)
            .desired_width(width - 34.0)
            .password(!revealed)
            .hint_text(hint_text),
    );

    let toggle = ui.add(
        egui::Button::new(if revealed { "hide" } else { "show" })
            .small()
            .frame(false),
    );
    if toggle.clicked() {
        revealed = !revealed;
        ui.data_mut(|d| d.insert_temp(reveal_id, revealed));
    }

    response
}

/// A read-only monospaced block with a copy button, for config previews.
pub fn code_block(ui: &mut Ui, palette: &Palette, text: &str, max_height: f32) {
    ui.horizontal(|ui| {
        ui.add_space(ui.available_width() - 60.0);
        copy_button(ui, palette, text);
    });
    inset(ui, palette, |ui| {
        egui::ScrollArea::both()
            .max_height(max_height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // A non-editable TextEdit keeps selection and copying working,
                // which a plain label does not.
                let mut shown = text.to_string();
                ui.add(
                    egui::TextEdit::multiline(&mut shown)
                        .font(theme::mono_font())
                        .desired_width(f32::INFINITY)
                        .interactive(false)
                        .frame(false),
                );
            });
    });
}

/// A horizontal rule with breathing room around it.
pub fn divider(ui: &mut Ui, palette: &Palette) {
    ui.add_space(SPACE_S);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter()
        .rect_filled(rect, Rounding::ZERO, palette.border);
    ui.add_space(SPACE_S);
}

/// An inline notice: an explanation the user needs where they are looking.
pub fn notice(ui: &mut Ui, palette: &Palette, level: LogLevel, text: &str) {
    let color = level_color(palette, level);
    accent_card(ui, palette, color, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(match level {
                    LogLevel::Error => "Problem",
                    LogLevel::Warn => "Careful",
                    LogLevel::Success => "Done",
                    _ => "Note",
                })
                .color(color)
                .strong(),
            );
            ui.label(RichText::new(text).color(palette.text));
        });
    });
}

/// An empty-state message, shown where a list has nothing in it yet.
pub fn empty_state(ui: &mut Ui, palette: &Palette, title: &str, detail: &str) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new(title)
                .font(theme::title_font())
                .color(palette.text_muted),
        );
        ui.add_space(SPACE_XS);
        ui.label(
            RichText::new(detail)
                .color(palette.text_faint)
                .font(theme::label_font()),
        );
    });
    ui.add_space(24.0);
}

/// A spinner with a caption, for work in progress.
pub fn busy(ui: &mut Ui, palette: &Palette, text: &str) {
    ui.horizontal(|ui| {
        ui.add(egui::Spinner::new().size(14.0).color(palette.accent));
        ui.label(RichText::new(text).color(palette.text_muted));
    });
}
