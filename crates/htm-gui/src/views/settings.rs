//! Preferences, credential storage and pinned host keys.

use egui::{RichText, Ui};

use htm_core::jobs::LogLevel;
use htm_core::ssh::KnownHosts;

use crate::app::{Action, HtmApp};
use crate::state::{ConfirmedAction, Modal};
use crate::theme::{SPACE_M, SPACE_S, SPACE_XS};
use crate::widgets;

const LABEL_W: f32 = 200.0;

pub fn show(app: &mut HtmApp, ui: &mut Ui) {
    preferences_card(app, ui);
    ui.add_space(SPACE_M);
    vault_card(app, ui);
    ui.add_space(SPACE_M);
    host_keys_card(app, ui);
    ui.add_space(SPACE_M);
    about_card(app, ui);
}

fn preferences_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let mut changed = false;

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "Preferences");

        changed |= widgets::form_row(ui, &palette, "THEME", LABEL_W, |ui| {
            let mut dark = app.state.settings.dark_mode;
            let changed = ui
                .selectable_value(&mut dark, true, "Dark")
                .clicked()
                | ui.selectable_value(&mut dark, false, "Light").clicked();
            if changed {
                app.state.settings.dark_mode = dark;
            }
            changed
        });

        changed |= widgets::form_row(ui, &palette, "STATUS REFRESH", LABEL_W, |ui| {
            ui.add(
                egui::DragValue::new(&mut app.state.settings.auto_refresh_secs)
                    .range(0..=600)
                    .suffix(" s"),
            )
            .on_hover_text("0 turns automatic refreshing off.")
            .changed()
        });

        changed |= widgets::form_row(ui, &palette, "JOURNAL LINES", LABEL_W, |ui| {
            ui.add(
                egui::DragValue::new(&mut app.state.settings.log_lines)
                    .range(50..=2000)
                    .speed(10.0),
            )
            .on_hover_text("How many journal lines each poll asks for.")
            .changed()
        });

        changed |= widgets::form_row(ui, &palette, "BENCHMARKS KEPT", LABEL_W, |ui| {
            let mut keep = app.state.settings.keep_bench_runs as u32;
            let response = ui.add(egui::DragValue::new(&mut keep).range(1..=200));
            if response.changed() {
                app.state.settings.keep_bench_runs = keep as usize;
            }
            response.changed()
        });

        ui.add_space(SPACE_S);
        let mut confirm = app.state.settings.confirm_destructive;
        if ui
            .checkbox(
                &mut confirm,
                "Ask before stopping or removing a tunnel",
            )
            .changed()
        {
            app.state.settings.confirm_destructive = confirm;
            changed = true;
        }
    });

    if changed {
        app.mark_dirty();
    }
}

fn vault_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let uses_password = app.key_source.is_master_password();
    let mut set_password: Option<String> = None;
    let mut remove_password = false;
    let mut clear = false;

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "Stored credentials");

        if app.vault_locked {
            widgets::notice(
                ui,
                &palette,
                LogLevel::Error,
                "The credential file on disk could not be opened, so HTM is running without it. \
                 Nothing will be written over it: your stored passwords are still there. Enter \
                 the master password below to unlock them, or set a new one to start a fresh \
                 file.",
            );
            ui.add_space(SPACE_S);
        } else if uses_password {
            widgets::notice(
                ui,
                &palette,
                LogLevel::Success,
                "Your SSH passwords are encrypted with a master password. Without it the file is \
                 unreadable, including by anyone who copies it.",
            );
        } else {
            widgets::notice(
                ui,
                &palette,
                LogLevel::Warn,
                "Your SSH passwords are encrypted with a key file stored next to them. That \
                 stops the file being useful on another machine, but anyone who can read your \
                 user profile can read both. Set a master password for real protection.",
            );
        }

        ui.add_space(SPACE_S);
        widgets::kv_mono(
            ui,
            &palette,
            "LOCATION",
            &app.paths.secrets().display().to_string(),
            LABEL_W,
        );
        widgets::kv(
            ui,
            &palette,
            "ENCRYPTION",
            "AES-256-GCM, key stretched with Argon2id",
            LABEL_W,
        );

        widgets::divider(ui, &palette);

        widgets::form_row(ui, &palette, "MASTER PASSWORD", LABEL_W, |ui| {
            widgets::password_field(
                ui,
                &mut app.settings_ui.new_master_password,
                260.0,
                "At least 8 characters",
                "master-1",
            );
        });
        widgets::form_row(ui, &palette, "CONFIRM", LABEL_W, |ui| {
            widgets::password_field(
                ui,
                &mut app.settings_ui.confirm_master_password,
                260.0,
                "Type it again",
                "master-2",
            );
        });

        let typed = app.settings_ui.new_master_password.clone();
        let confirmed = app.settings_ui.confirm_master_password.clone();
        let matching = !typed.is_empty() && typed == confirmed;

        if !typed.is_empty() && !matching {
            widgets::hint(ui, &palette, "The two entries do not match yet.");
        }

        ui.add_space(SPACE_S);
        ui.horizontal(|ui| {
            let label = if uses_password {
                "Change the master password"
            } else {
                "Set a master password"
            };
            if widgets::primary_button(ui, &palette, label, matching).clicked() {
                set_password = Some(typed.clone());
            }
            if uses_password
                && widgets::ghost_button(ui, &palette, "Remove the master password", true)
                    .clicked()
            {
                remove_password = true;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::danger_button(ui, &palette, "Forget all credentials", true).clicked()
                {
                    clear = true;
                }
            });
        });

        if let Some(message) = app.settings_ui.vault_message.clone() {
            ui.add_space(SPACE_S);
            widgets::notice(ui, &palette, LogLevel::Success, &message);
        }
        if let Some(error) = app.settings_ui.vault_error.clone() {
            ui.add_space(SPACE_S);
            widgets::notice(ui, &palette, LogLevel::Error, &error);
        }
    });

    if let Some(password) = set_password {
        app.push(Action::SetMasterPassword(password));
    }
    if remove_password {
        app.push(Action::RemoveMasterPassword);
    }
    if clear {
        app.modal = Some(Modal::Confirm {
            title: "Forget every stored credential?".to_string(),
            body: "All SSH passwords, key passphrases, sudo passwords and proxy passwords are \
                   deleted from this machine. Your servers and tunnels are untouched, but you \
                   will have to type the passwords again before HTM can reach them."
                .to_string(),
            confirm_label: "Forget them".to_string(),
            action: Box::new(ConfirmedAction::ClearVault),
        });
    }
}

fn host_keys_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;
    let path = app.known_hosts_path();
    let known = KnownHosts::load(&path).ok();
    let mut forget: Option<(String, u16)> = None;

    widgets::card(ui, &palette, |ui| {
        ui.horizontal(|ui| {
            widgets::section_title(ui, &palette, "Pinned host keys");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let count = known.as_ref().map(|k| k.len()).unwrap_or(0);
                widgets::pill(ui, &palette, &format!("{count} pinned"), palette.info);
            });
        });
        widgets::hint(
            ui,
            &palette,
            "HTM keeps its own list rather than touching your OpenSSH known_hosts. The first \
             time you connect to a server it asks you to confirm the fingerprint; after that, a \
             key that changes stops the connection until you approve it.",
        );
        ui.add_space(SPACE_S);
        widgets::kv_mono(
            ui,
            &palette,
            "FILE",
            &path.display().to_string(),
            LABEL_W,
        );

        ui.add_space(SPACE_S);

        match &known {
            None => widgets::notice(
                ui,
                &palette,
                LogLevel::Error,
                "The pin file could not be read.",
            ),
            Some(known) if known.is_empty() => widgets::empty_state(
                ui,
                &palette,
                "Nothing pinned yet",
                "Keys are pinned the first time you approve a server's fingerprint.",
            ),
            Some(known) => {
                for record in known.all() {
                    widgets::inset(ui, &palette, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{}:{}", record.host, record.port))
                                    .font(crate::theme::mono_font())
                                    .color(palette.text),
                            );
                            widgets::pill(ui, &palette, &record.key_type, palette.info);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if widgets::danger_button(ui, &palette, "Forget", true)
                                        .clicked()
                                    {
                                        forget = Some((record.host.clone(), record.port));
                                    }
                                },
                            );
                        });
                        ui.label(
                            RichText::new(format!("SHA256:{}", record.sha256))
                                .font(crate::theme::mono_small_font())
                                .color(palette.text_muted),
                        );
                        widgets::hint(
                            ui,
                            &palette,
                            &format!(
                                "First seen {}",
                                record
                                    .first_seen
                                    .with_timezone(&chrono::Local)
                                    .format("%Y-%m-%d %H:%M")
                            ),
                        );
                    });
                    ui.add_space(SPACE_XS);
                }
            }
        }
    });

    if let Some((host, port)) = forget {
        app.modal = Some(Modal::Confirm {
            title: format!("Forget the key for {host}:{port}?"),
            body: "The next connection to this server will ask you to confirm its fingerprint \
                   again. Only do this if you know the server's key legitimately changed."
                .to_string(),
            confirm_label: "Forget it".to_string(),
            action: Box::new(ConfirmedAction::ForgetHostKey { host, port }),
        });
    }
}

fn about_card(app: &mut HtmApp, ui: &mut Ui) {
    let palette = app.palette;

    widgets::card(ui, &palette, |ui| {
        widgets::section_title(ui, &palette, "About");
        widgets::kv(ui, &palette, "VERSION", htm_core::VERSION, LABEL_W);
        widgets::kv_mono(
            ui,
            &palette,
            "DATA FOLDER",
            &app.paths.root.display().to_string(),
            LABEL_W,
        );
        widgets::kv_mono(
            ui,
            &palette,
            "LOG FILE",
            &app.paths.log().display().to_string(),
            LABEL_W,
        );
        ui.add_space(SPACE_S);
        widgets::hint(
            ui,
            &palette,
            "Set the HTM_HOME environment variable to keep all of these somewhere else, for \
             instance on a removable drive.",
        );
        ui.add_space(SPACE_S);
        ui.horizontal(|ui| {
            if widgets::ghost_button(ui, &palette, "Save everything now", true).clicked() {
                app.push(Action::SaveNow);
            }
        });
    });
}
