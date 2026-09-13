//! HTM's visual language.
//!
//! The app spends most of its time showing dense, technical information —
//! tables of measurements, log streams, status pills — so the palette is built
//! around a deep neutral ground with a small number of saturated accents that
//! only ever carry meaning. Nothing is coloured decoratively: a green pill
//! always means running, amber always means attention, red always means
//! failure.

use egui::{Color32, Context, FontFamily, FontId, Rounding, Stroke, TextStyle, Visuals};

/// Every colour the app uses, resolved for one theme.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub is_dark: bool,

    /// Window background, behind everything.
    pub ground: Color32,
    /// Side and top panels.
    pub panel: Color32,
    /// Raised surfaces: cards, table rows, popups.
    pub surface: Color32,
    /// A surface that is one step further forward, e.g. a selected row.
    pub surface_raised: Color32,
    /// Inset surfaces: text fields, log panes.
    pub inset: Color32,

    pub border: Color32,
    pub border_strong: Color32,

    pub text: Color32,
    pub text_muted: Color32,
    pub text_faint: Color32,

    /// Primary accent, used for focus, selection and the main call to action.
    pub accent: Color32,
    pub accent_hover: Color32,
    pub accent_text: Color32,

    pub success: Color32,
    pub warn: Color32,
    pub error: Color32,
    pub info: Color32,

    /// Series colours for charts and the benchmark bars.
    pub series: [Color32; 6],
}

impl Palette {
    pub const DARK: Palette = Palette {
        is_dark: true,
        ground: Color32::from_rgb(0x0E, 0x10, 0x15),
        panel: Color32::from_rgb(0x14, 0x18, 0x1F),
        surface: Color32::from_rgb(0x1A, 0x20, 0x29),
        surface_raised: Color32::from_rgb(0x22, 0x2A, 0x36),
        inset: Color32::from_rgb(0x10, 0x14, 0x1A),

        border: Color32::from_rgb(0x27, 0x2F, 0x3C),
        border_strong: Color32::from_rgb(0x38, 0x44, 0x55),

        text: Color32::from_rgb(0xE4, 0xE9, 0xF1),
        text_muted: Color32::from_rgb(0x94, 0x9F, 0xB2),
        text_faint: Color32::from_rgb(0x62, 0x6C, 0x7C),

        accent: Color32::from_rgb(0x4C, 0xA6, 0xFF),
        accent_hover: Color32::from_rgb(0x6E, 0xB9, 0xFF),
        accent_text: Color32::from_rgb(0x08, 0x0C, 0x12),

        success: Color32::from_rgb(0x3D, 0xD6, 0x8C),
        warn: Color32::from_rgb(0xF0, 0xB4, 0x29),
        error: Color32::from_rgb(0xFF, 0x6B, 0x6B),
        info: Color32::from_rgb(0x7C, 0x8C, 0xFF),

        series: [
            Color32::from_rgb(0x4C, 0xA6, 0xFF),
            Color32::from_rgb(0x3D, 0xD6, 0x8C),
            Color32::from_rgb(0xC7, 0x7D, 0xFF),
            Color32::from_rgb(0xF0, 0xB4, 0x29),
            Color32::from_rgb(0xFF, 0x8A, 0x65),
            Color32::from_rgb(0x4D, 0xD0, 0xE1),
        ],
    };

    pub const LIGHT: Palette = Palette {
        is_dark: false,
        ground: Color32::from_rgb(0xF4, 0xF6, 0xF9),
        panel: Color32::from_rgb(0xEC, 0xEF, 0xF4),
        surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
        surface_raised: Color32::from_rgb(0xE8, 0xED, 0xF5),
        inset: Color32::from_rgb(0xF7, 0xF9, 0xFC),

        border: Color32::from_rgb(0xD5, 0xDB, 0xE4),
        border_strong: Color32::from_rgb(0xB3, 0xBD, 0xCC),

        text: Color32::from_rgb(0x17, 0x1C, 0x24),
        text_muted: Color32::from_rgb(0x54, 0x5F, 0x70),
        text_faint: Color32::from_rgb(0x86, 0x91, 0xA2),

        accent: Color32::from_rgb(0x14, 0x6E, 0xD6),
        accent_hover: Color32::from_rgb(0x0F, 0x5C, 0xB8),
        accent_text: Color32::from_rgb(0xFF, 0xFF, 0xFF),

        success: Color32::from_rgb(0x12, 0x8A, 0x54),
        warn: Color32::from_rgb(0xA9, 0x70, 0x00),
        error: Color32::from_rgb(0xC6, 0x30, 0x30),
        info: Color32::from_rgb(0x45, 0x50, 0xC7),

        series: [
            Color32::from_rgb(0x14, 0x6E, 0xD6),
            Color32::from_rgb(0x12, 0x8A, 0x54),
            Color32::from_rgb(0x7B, 0x3F, 0xC4),
            Color32::from_rgb(0xA9, 0x70, 0x00),
            Color32::from_rgb(0xC2, 0x52, 0x2B),
            Color32::from_rgb(0x0E, 0x7A, 0x8C),
        ],
    };

    pub fn for_theme(dark: bool) -> Self {
        if dark {
            Self::DARK
        } else {
            Self::LIGHT
        }
    }

    /// A colour for a 0-100 benchmark score: red through amber to green.
    pub fn score_color(&self, score: f64) -> Color32 {
        let t = (score / 100.0).clamp(0.0, 1.0) as f32;
        if t < 0.5 {
            lerp_color(self.error, self.warn, t * 2.0)
        } else {
            lerp_color(self.warn, self.success, (t - 0.5) * 2.0)
        }
    }
}

/// Blend two colours.
pub fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round().clamp(0.0, 255.0) as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

/// Corner radii used across the app. Cards are softer than controls so they
/// read as surfaces rather than buttons.
pub const R_CARD: f32 = 10.0;
pub const R_CONTROL: f32 = 6.0;
pub const R_PILL: f32 = 999.0;

/// Standard spacing steps. Sticking to these keeps the layout rhythm even.
pub const SPACE_XS: f32 = 4.0;
pub const SPACE_S: f32 = 8.0;
pub const SPACE_M: f32 = 14.0;
pub const SPACE_L: f32 = 22.0;

/// Install the palette, type scale and widget styling into the context.
pub fn apply(ctx: &Context, palette: &Palette) {
    let mut visuals = if palette.is_dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };

    visuals.override_text_color = Some(palette.text);
    visuals.panel_fill = palette.panel;
    visuals.window_fill = palette.surface;
    visuals.extreme_bg_color = palette.inset;
    visuals.faint_bg_color = palette.surface_raised;
    visuals.code_bg_color = palette.inset;

    visuals.window_stroke = Stroke::new(1.0_f32, palette.border);
    visuals.window_rounding = Rounding::same(R_CARD);
    visuals.menu_rounding = Rounding::same(R_CONTROL);

    visuals.hyperlink_color = palette.accent;
    visuals.warn_fg_color = palette.warn;
    visuals.error_fg_color = palette.error;

    visuals.selection.bg_fill = palette.accent.gamma_multiply(0.35);
    visuals.selection.stroke = Stroke::new(1.0_f32, palette.accent);

    // Resting controls sit flush with the surface; interaction is what lifts
    // them, so the interface stays calm until the pointer moves.
    visuals.widgets.noninteractive.bg_fill = palette.surface;
    visuals.widgets.noninteractive.weak_bg_fill = palette.surface;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, palette.border);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, palette.text_muted);
    visuals.widgets.noninteractive.rounding = Rounding::same(R_CONTROL);

    visuals.widgets.inactive.bg_fill = palette.surface_raised;
    visuals.widgets.inactive.weak_bg_fill = palette.surface_raised;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, palette.border);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, palette.text);
    visuals.widgets.inactive.rounding = Rounding::same(R_CONTROL);

    visuals.widgets.hovered.bg_fill = lerp_color(palette.surface_raised, palette.accent, 0.18);
    visuals.widgets.hovered.weak_bg_fill =
        lerp_color(palette.surface_raised, palette.accent, 0.18);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, palette.border_strong);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, palette.text);
    visuals.widgets.hovered.rounding = Rounding::same(R_CONTROL);

    visuals.widgets.active.bg_fill = lerp_color(palette.surface_raised, palette.accent, 0.34);
    visuals.widgets.active.weak_bg_fill =
        lerp_color(palette.surface_raised, palette.accent, 0.34);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, palette.accent);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, palette.text);
    visuals.widgets.active.rounding = Rounding::same(R_CONTROL);

    visuals.widgets.open.bg_fill = palette.surface_raised;
    visuals.widgets.open.weak_bg_fill = palette.surface_raised;
    visuals.widgets.open.bg_stroke = Stroke::new(1.0_f32, palette.border_strong);
    visuals.widgets.open.fg_stroke = Stroke::new(1.0_f32, palette.text);
    visuals.widgets.open.rounding = Rounding::same(R_CONTROL);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();

    // A type scale with clear steps. Monospace is reserved for values the user
    // may need to compare character by character: addresses, fingerprints,
    // config text and logs.
    style.text_styles = [
        (TextStyle::Heading, FontId::new(19.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(12.5, FontFamily::Monospace)),
    ]
    .into();

    style.spacing.item_spacing = egui::vec2(SPACE_S, SPACE_S);
    style.spacing.button_padding = egui::vec2(11.0, 6.0);
    style.spacing.menu_margin = egui::Margin::same(6.0);
    style.spacing.indent = 18.0;
    style.spacing.interact_size.y = 26.0;
    style.spacing.slider_width = 180.0;
    style.spacing.combo_width = 180.0;
    style.spacing.scroll.bar_width = 9.0;

    style.visuals.striped = true;

    ctx.set_style(style);
}

/// Named text styles used by [`crate::widgets`].
pub fn heading_font() -> FontId {
    FontId::new(19.0, FontFamily::Proportional)
}

pub fn title_font() -> FontId {
    FontId::new(15.0, FontFamily::Proportional)
}

pub fn label_font() -> FontId {
    FontId::new(11.5, FontFamily::Proportional)
}

pub fn mono_font() -> FontId {
    FontId::new(12.5, FontFamily::Monospace)
}

pub fn mono_small_font() -> FontId {
    FontId::new(11.5, FontFamily::Monospace)
}
