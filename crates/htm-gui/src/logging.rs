//! A small file logger.
//!
//! HTM's user-facing log is the one in the Logs tab, built from job events.
//! This one is for the things a user should never have to see unless something
//! has gone wrong: crate-level warnings, panics, and the detail behind an
//! error message.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use log::{Level, LevelFilter, Metadata, Record};

/// Rotate the log once it passes this size, keeping one previous file.
const MAX_BYTES: u64 = 4 * 1024 * 1024;

struct FileLogger {
    file: Mutex<Option<File>>,
    level: LevelFilter,
    /// Echo to stderr as well, which is useful when running from a terminal.
    echo: bool,
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {:<5} [{}] {}\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level(),
            record.target(),
            record.args()
        );

        if self.echo {
            eprint!("{line}");
        }
        // A logger that cannot write must not panic or block the UI, so every
        // failure here is swallowed deliberately.
        if let Ok(mut guard) = self.file.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = file.write_all(line.as_bytes());
                if record.level() <= Level::Warn {
                    let _ = file.flush();
                }
            }
        }
    }

    fn flush(&self) {
        if let Ok(mut guard) = self.file.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = file.flush();
            }
        }
    }
}

/// Start logging to `path`. Returns the path actually used, if any.
///
/// Never fails the application: if the file cannot be opened, logging simply
/// goes to stderr.
pub fn init(path: &Path, verbose: bool) -> Option<PathBuf> {
    rotate_if_large(path);

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok();
    let opened = file.is_some();

    let level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let logger = FileLogger {
        file: Mutex::new(file),
        level,
        echo: cfg!(debug_assertions) || verbose,
    };

    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(level);
    }

    install_panic_hook();

    opened.then(|| path.to_path_buf())
}

fn rotate_if_large(path: &Path) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.len() < MAX_BYTES {
        return;
    }
    let previous = path.with_extension("log.1");
    let _ = std::fs::remove_file(&previous);
    let _ = std::fs::rename(path, &previous);
}

/// Record panics in the log file rather than losing them to a closed console.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".to_string());
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());

        log::error!("panic at {location}: {message}");
        log::logger().flush();
        previous(info);
    }));
}
