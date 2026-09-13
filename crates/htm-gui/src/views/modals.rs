//! Dialogs that need an answer before anything else can happen.
//!
//! The host key dialog is the important one. It is the only place in HTM where
//! a wrong click has a security consequence, so it shows the fingerprint in
//! full, in monospace, and never pre-selects the accepting button.

use egui::{Context, RichText, Ui};

use htm_core::jobs::LogLevel;

use crate::app::{Action, HtmApp};
use crate::state::Modal;
use crate::theme::{Palette, R_CARD, SPACE_M, SPACE_S};
use crate::widgets;

pub fn show(app: &mut HtmApp, ctx: &Context) {
    let Some(modal) = app.modal.clone() else {
        return;
    };
    let palette = app.palette;

    let (title, width) = match &modal {
        Modal::HostKey { .. } => ("Confirm the server's identity", 620.0),
        Modal::Confirm { title, .. } => (title.as_str(), 520.0),
        Modal::Error { title, .. } => (title.as_str(), 640.0),
        Modal::Unlock { .. } => ("Unlock your stored credentials", 460.0),
    };

    egui::Window::new(title)
        .order(egui::Order::Foreground)
        .collapsible(false)
        .resizable(false)
        .title_bar(true)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .default_width(width)
        .max_width(width)
        .frame(
            egui::Frame::none()
                .fill(palette.surface)
                .stroke(egui::Stroke::new(1.0_f32, palette.border_strong))
                .rounding(egui::Rounding::same(R_CARD))
                .inner_margin(egui::Margin::same(16.0)),
        )
        .show(ctx, |ui| match &modal {
            Modal::HostKey {
                server_id,
                host,
                port,
                key_type,
                sha256,
                md5,
                previous_sha256,
            } => host_key(
                app,
                ui,
                &palette,
                server_id,
                host,
                *port,
                key_type,
                sha256,
                md5,
                previous_sha256.as_deref(),
            ),
            Modal::Confirm {
                body,
                confirm_label,
                action,
                ..
            } => confirm(app, ui, &palette, body, confirm_label, action),
            Modal::Error { body, .. } => error(app, ui, &palette, body),
            Modal::Unlock { .. } => unlock(app, ui, &palette),
        });
}

#[allow(clippy::too_many_arguments)]
fn host_key(
    app: &mut HtmApp,
    ui: &mut Ui,
    palette: &Palette,
    server_id: &str,
    host: &str,
    port: u16,
    key_type: &str,
    sha256: &str,
    md5: &str,
    previous: Option<&str>,
) {
    let changed = previous.is_some();

    if changed {
        widgets::notice(
            ui,
            palette,
            LogLevel::Error,
            "This server is presenting a different key from the one HTM pinned. That happens \
             when a server is rebuilt or reinstalled — and it is also exactly what an \
             interception attack looks like. Do not continue unless you know why the key \
             changed.",
        );
    } else {
        widgets::hint(
            ui,
            palette,
            "HTM has not seen this server before. Check the fingerprint against one you got \
             from your provider's control panel, or by running `ssh-keygen -lf \
             /etc/ssh/ssh_host_ed25519_key.pub` on the server itself.",
        );
    }

    ui.add_space(SPACE_M);
    widgets::inset(ui, palette, |ui| {
        widgets::kv_mono(ui, palette, "SERVER", &format!("{host}:{port}"), 110.0);
        if !key_type.is_empty() {
            widgets::kv_mono(ui, palette, "KEY TYPE", key_type, 110.0);
        }
        ui.add_space(SPACE_S);
        ui.label(
            RichText::new("SHA256 fingerprint")
                .font(crate::theme::label_font())
                .color(palette.text_muted),
        );
        ui.label(
            RichText::new(format!("SHA256:{sha256}"))
                .font(crate::theme::mono_font())
                .color(if changed { palette.error } else { palette.text }),
        );
        if !md5.is_empty() {
            ui.add_space(SPACE_S);
            ui.label(
                RichText::new("MD5 fingerprint (legacy)")
                    .font(crate::theme::label_font())
                    .color(palette.text_muted),
            );
            ui.label(
                RichText::new(format!("MD5:{md5}"))
                    .font(crate::theme::mono_small_font())
                    .color(palette.text_muted),
            );
        }
        if let Some(previous) = previous {
            ui.add_space(SPACE_S);
            ui.label(
                RichText::new("Previously pinned")
                    .font(crate::theme::label_font())
                    .color(palette.text_muted),
            );
            ui.label(
                RichText::new(format!("SHA256:{previous}"))
                    .font(crate::theme::mono_small_font())
                    .color(palette.warn),
            );
        }
    });

    ui.add_space(SPACE_M);
    ui.horizontal(|ui| {
        // Rejecting is the leftmost, default-looking action on purpose.
        if widgets::ghost_button(ui, palette, "Cancel", true).clicked() {
            app.push(Action::DismissModal);
        }
        widgets::copy_button(ui, palette, &format!("SHA256:{sha256}"));

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let label = if changed {
                "I know why it changed — trust it"
            } else {
                "Trust this server"
            };
            let button = if changed {
                widgets::danger_button(ui, palette, label, true)
            } else {
                widgets::primary_button(ui, palette, label, true)
            };
            if button.clicked() {
                app.push(Action::TrustHostKey {
                    server_id: server_id.to_string(),
                    sha256: sha256.to_string(),
                });
            }
        });
    });
}

fn confirm(
    app: &mut HtmApp,
    ui: &mut Ui,
    palette: &Palette,
    body: &str,
    confirm_label: &str,
    action: &crate::state::ConfirmedAction,
) {
    ui.label(RichText::new(body).color(palette.text));
    ui.add_space(SPACE_M);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, palette, "Cancel", true).clicked() {
            app.push(Action::DismissModal);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if widgets::danger_button(ui, palette, confirm_label, true).clicked() {
                app.push(Action::Confirm(Box::new(action.clone())));
            }
        });
    });
}

fn error(app: &mut HtmApp, ui: &mut Ui, palette: &Palette, body: &str) {
    widgets::code_block(ui, palette, body, 340.0);
    ui.add_space(SPACE_M);
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if widgets::primary_button(ui, palette, "Close", true).clicked() {
                app.push(Action::DismissModal);
            }
        });
    });
}

/// Shown when the vault is locked. The unlock flow itself runs in `main`
/// before the app starts, so this exists for the case where the key source is
/// changed while running and the vault has to be re-opened.
fn unlock(app: &mut HtmApp, ui: &mut Ui, palette: &Palette) {
    widgets::hint(
        ui,
        palette,
        "Your stored SSH credentials are encrypted with a master password.",
    );
    ui.add_space(SPACE_M);

    let mut password = match &app.modal {
        Some(Modal::Unlock { password, .. }) => password.clone(),
        _ => String::new(),
    };
    let error = match &app.modal {
        Some(Modal::Unlock { error, .. }) => error.clone(),
        _ => None,
    };

    let response = widgets::password_field(
        ui,
        &mut password,
        320.0,
        "Master password",
        "unlock-modal",
    );
    if response.changed() {
        if let Some(Modal::Unlock { password: stored, .. }) = app.modal.as_mut() {
            *stored = password.clone();
        }
    }

    if let Some(error) = error {
        ui.add_space(SPACE_S);
        widgets::notice(ui, palette, LogLevel::Error, &error);
    }

    ui.add_space(SPACE_M);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, palette, "Continue without them", true).clicked() {
            app.push(Action::DismissModal);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if widgets::primary_button(ui, palette, "Unlock", !password.is_empty()).clicked() {
                app.push(Action::UnlockVault(password.clone()));
            }
        });
    });
}
