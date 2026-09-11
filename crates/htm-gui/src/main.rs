//! HTM — Hiddify Tunnel Manager.
//!
//! A desktop front end for building, measuring and running tunnels between two
//! servers over SSH. All of the actual work lives in `htm-core`; this crate
//! draws it.

// A GUI application should not open a console window on Windows, but keeping
// one in debug builds makes `cargo run` useful.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod app;
mod logging;
mod state;
mod theme;
mod views;
mod widgets;

use htm_core::crypto::{self, KeySource, Vault};
use htm_core::store::{AppState, Paths};

use crate::app::HtmApp;
use crate::state::Modal;

fn main() -> eframe::Result<()> {
    let verbose = std::env::args().any(|a| a == "--verbose" || a == "-v");

    let paths = match Paths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("HTM could not work out where to keep its files: {error}");
            eprintln!("Set HTM_HOME to a directory you can write to and try again.");
            std::process::exit(1);
        }
    };
    if let Err(error) = paths.ensure() {
        eprintln!(
            "HTM could not create its data folder at {}: {error}",
            paths.root.display()
        );
        std::process::exit(1);
    }

    logging::init(&paths.log(), verbose);
    log::info!("HTM {} starting, data folder {}", htm_core::VERSION, paths.root.display());

    // ── State ───────────────────────────────────────────────────────────────
    let (state, mut startup_note) = match AppState::load(&paths) {
        Ok(result) => result,
        Err(error) => {
            log::error!("could not load state: {error}");
            (
                AppState::default(),
                Some(format!(
                    "Your saved settings could not be read ({error}). HTM started with defaults."
                )),
            )
        }
    };

    // ── Credentials ─────────────────────────────────────────────────────────
    let secrets_path = paths.secrets();
    let needs_master_password = Vault::file_needs_master_password(&secrets_path).unwrap_or(false);

    let (vault, key_source, locked) = if needs_master_password {
        // The real vault is opened once the user types the password into the
        // unlock dialog. Until then HTM runs with an empty one and, crucially,
        // refuses to overwrite the file on disk.
        (
            Vault::new(),
            KeySource::MasterPassword(String::new()),
            true,
        )
    } else {
        match crypto::load_or_create_device_key(&paths.device_key()) {
            Ok(key) => {
                let source = KeySource::DeviceKey(key);
                match Vault::open(&secrets_path, &source) {
                    Ok(vault) => (vault, source, false),
                    Err(error) => {
                        log::error!("could not open the vault: {error}");
                        startup_note = Some(format!(
                            "Your stored credentials could not be read ({error}). HTM will not \
                             overwrite the file; re-enter the passwords you need, or delete \
                             {} to start fresh.",
                            secrets_path.display()
                        ));
                        (Vault::new(), source, true)
                    }
                }
            }
            Err(error) => {
                log::error!("could not prepare the device key: {error}");
                startup_note = Some(format!(
                    "The credential key file could not be prepared ({error}). Passwords will \
                     not be remembered this session."
                ));
                (Vault::new(), KeySource::DeviceKey(vec![0u8; 32]), true)
            }
        }
    };

    let mut application = HtmApp::new(paths, state, vault, key_source, startup_note);
    application.vault_locked = locked;
    if needs_master_password {
        application.modal = Some(Modal::Unlock {
            password: String::new(),
            error: None,
        });
    }

    // ── Window ──────────────────────────────────────────────────────────────
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("HTM — Hiddify Tunnel Manager")
            .with_inner_size([1320.0, 880.0])
            .with_min_inner_size([1024.0, 680.0])
            .with_app_id("htm-hiddify-tunnel-manager"),
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "HTM",
        options,
        Box::new(move |_cc| Ok(Box::new(application))),
    )
}
