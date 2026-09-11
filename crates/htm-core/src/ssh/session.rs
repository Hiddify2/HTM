//! The SSH client HTM drives every remote operation through.
//!
//! Design notes worth knowing before changing anything here:
//!
//! * **Files are transferred over an exec channel, not SFTP.** `cat > file`
//!   works on every host where a shell works, including ones that do not enable
//!   the SFTP subsystem, and it is binary safe. There is one fewer thing to
//!   fail.
//! * **Privilege escalation is decided once, at connect time.** The probe
//!   result lives in [`PrivMode`], so no later command has to guess whether to
//!   prefix `sudo`.
//! * **Long or chatty commands must use [`SshClient::exec_stream`]**, which
//!   folds stderr into stdout. [`SshClient::exec`] keeps the two apart and is
//!   meant for the short control commands whose output fits comfortably in the
//!   channel window.
//! * **`ssh2::Session` is `Send + Sync` and internally mutex-guarded**, so an
//!   `SshClient` can be shared across threads. Calls serialise, which also
//!   means a blocking read on one channel stalls every other channel on that
//!   session — long-running reads therefore get their own connection.

use std::borrow::Cow;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ssh2::{KeyboardInteractivePrompt, Prompt, Session};

use crate::error::{Error, Result};
use crate::model::{AuthKind, ServerCredentials, ServerProfile};
use crate::ssh::dial;
use crate::ssh::hostkey::{key_type_name, HostKeyPolicy, KnownHosts};
use crate::util::{self, sh_quote};

/// How this connection gains root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivMode {
    /// Already uid 0; commands run unchanged.
    Root,
    /// `sudo -n` works, so no password has to be piped in.
    SudoNoPassword,
    /// `sudo -S` with the password on stdin.
    SudoPassword,
    /// No way to escalate. Privileged commands fail with a clear message.
    None,
}

impl PrivMode {
    pub fn can_escalate(self) -> bool {
        !matches!(self, PrivMode::None)
    }

    pub fn describe(self) -> &'static str {
        match self {
            PrivMode::Root => "root",
            PrivMode::SudoNoPassword => "sudo (no password required)",
            PrivMode::SudoPassword => "sudo (password)",
            PrivMode::None => "unprivileged",
        }
    }
}

/// The result of one remote command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub command: String,
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    /// Trimmed stdout, which is what almost every caller wants.
    pub fn out(&self) -> &str {
        self.stdout.trim()
    }

    /// The first line of trimmed stdout.
    pub fn first_line(&self) -> &str {
        self.out().lines().next().unwrap_or("").trim()
    }

    /// stdout if the command succeeded, otherwise an [`Error::Remote`].
    pub fn require(self) -> Result<String> {
        if self.ok() {
            Ok(self.stdout)
        } else {
            Err(Error::Remote {
                command: self.command,
                status: self.status,
                stdout: self.stdout,
                stderr: self.stderr,
            })
        }
    }

    /// Both streams joined, for log display.
    pub fn combined(&self) -> String {
        let mut s = String::new();
        if !self.stdout.trim().is_empty() {
            s.push_str(self.stdout.trim_end());
        }
        if !self.stderr.trim().is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(self.stderr.trim_end());
        }
        s
    }
}

/// Answers every keyboard-interactive challenge with the stored password.
///
/// Many hardened `sshd` configurations disable `PasswordAuthentication` but
/// leave `KbdInteractiveAuthentication` on, where the single challenge is still
/// just the password. Without this, those hosts look like a wrong password.
struct PasswordPrompter {
    password: String,
    /// Set when the server asked something that is clearly not a password, such
    /// as a one-time-code challenge, so the caller can say so precisely.
    saw_non_password_prompt: bool,
    last_prompt: String,
}

impl KeyboardInteractivePrompt for PasswordPrompter {
    fn prompt<'a>(
        &mut self,
        _username: &str,
        _instructions: &str,
        prompts: &[Prompt<'a>],
    ) -> Vec<String> {
        prompts
            .iter()
            .map(|p| {
                let text: Cow<'_, str> = p.text.clone();
                let lowered = text.to_lowercase();
                self.last_prompt = text.to_string();
                if !lowered.contains("password") && !lowered.contains("passphrase") {
                    self.saw_non_password_prompt = true;
                }
                self.password.clone()
            })
            .collect()
    }
}

/// An authenticated SSH connection to one server.
pub struct SshClient {
    session: Session,
    profile: ServerProfile,
    /// Kept so privileged commands can supply the sudo password and so the
    /// connection can be re-established.
    credentials: ServerCredentials,
    priv_mode: PrivMode,
    /// SHA-256 fingerprint of the key this connection accepted.
    host_key_sha256: String,
    host_key_type: String,
    banner: String,
}

impl std::fmt::Debug for SshClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshClient")
            .field("endpoint", &self.profile.endpoint())
            .field("priv_mode", &self.priv_mode)
            .finish()
    }
}

impl SshClient {
    /// Dial, verify the host key, authenticate and probe for root.
    ///
    /// `known` is updated and saved in place when the policy pins a new key.
    pub fn connect(
        credentials: &ServerCredentials,
        known: &mut KnownHosts,
        policy: &HostKeyPolicy,
    ) -> Result<Self> {
        let profile = credentials.profile.clone();
        profile.validate().map_err(Error::Validation)?;

        let timeout = Duration::from_secs(profile.connect_timeout_secs.max(1));
        let stream = dial::dial(
            &profile.host,
            profile.port,
            &profile.proxy,
            &credentials.secrets.proxy_password,
            timeout,
        )?;

        let mut session = Session::new()?;
        session.set_timeout((profile.connect_timeout_secs.max(1) * 1000) as u32);
        session.set_blocking(true);
        session.set_compress(true);
        session.set_tcp_stream(stream);
        session.handshake()?;

        // ── Host key ────────────────────────────────────────────────────────
        let (key_blob, key_kind) = session
            .host_key()
            .ok_or_else(|| Error::msg("the server did not present a host key"))?;
        let key_blob = key_blob.to_vec();
        let key_type = key_type_name(key_kind).to_string();
        let md5 = session
            .host_key_hash(ssh2::HashType::Md5)
            .map(util::hex_colon)
            .unwrap_or_default();

        let changed = known.apply_policy(
            &profile.host,
            profile.port,
            &key_type,
            &key_blob,
            &md5,
            policy,
        )?;
        if changed {
            known.save()?;
        }
        let host_key_sha256 = crate::ssh::hostkey::fingerprint_sha256(&key_blob);
        let banner = session.banner().unwrap_or_default().to_string();

        // ── Authentication ──────────────────────────────────────────────────
        authenticate(&session, credentials)?;
        if !session.authenticated() {
            return Err(Error::Auth {
                user: profile.username.clone(),
                reason: "the server accepted the attempt but the session is not authenticated"
                    .to_string(),
            });
        }

        // Ordinary commands get the longer per-command budget, and the SSH
        // layer sends its own keepalives so idle NAT entries do not expire.
        session.set_timeout((profile.command_timeout_secs.max(5) * 1000) as u32);
        session.set_keepalive(true, 30);

        let mut client = Self {
            session,
            profile,
            credentials: credentials.clone(),
            priv_mode: PrivMode::None,
            host_key_sha256,
            host_key_type: key_type,
            banner,
        };
        client.priv_mode = client.probe_privileges()?;
        Ok(client)
    }

    pub fn profile(&self) -> &ServerProfile {
        &self.profile
    }

    pub fn priv_mode(&self) -> PrivMode {
        self.priv_mode
    }

    pub fn host_key_sha256(&self) -> &str {
        &self.host_key_sha256
    }

    pub fn host_key_type(&self) -> &str {
        &self.host_key_type
    }

    pub fn banner(&self) -> &str {
        &self.banner
    }

    /// `user@host:port`, for log lines.
    pub fn endpoint(&self) -> String {
        self.profile.endpoint()
    }

    /// Send a keepalive; a cheap liveness probe.
    pub fn is_alive(&self) -> bool {
        self.session.keepalive_send().is_ok()
    }

    /// Override the per-command timeout for the calls that follow.
    pub fn set_command_timeout(&self, secs: u64) {
        self.session.set_timeout((secs.max(1) * 1000) as u32);
    }

    /// Restore the profile's configured per-command timeout.
    pub fn reset_command_timeout(&self) {
        self.session
            .set_timeout((self.profile.command_timeout_secs.max(5) * 1000) as u32);
    }

    // ── Command execution ───────────────────────────────────────────────────

    /// Run a command as the login user, capturing stdout and stderr separately.
    ///
    /// Meant for short control commands. Anything that can produce a lot of
    /// output belongs in [`Self::exec_stream`].
    pub fn exec(&self, command: &str) -> Result<CommandOutput> {
        self.exec_inner(command, None)
    }

    /// Run a command with root privileges.
    pub fn exec_priv(&self, command: &str) -> Result<CommandOutput> {
        match self.priv_mode {
            PrivMode::Root => self.exec_inner(command, None),
            PrivMode::SudoNoPassword => {
                self.exec_inner(&format!("sudo -n -- /bin/sh -c {}", sh_quote(command)), None)
            }
            PrivMode::SudoPassword => {
                let password = self.credentials.sudo_password().to_string();
                if password.is_empty() {
                    return Err(Error::Validation(format!(
                        "{} needs a sudo password but none was provided.",
                        self.profile.label
                    )));
                }
                self.exec_inner(
                    &format!("sudo -S -p '' -- /bin/sh -c {}", sh_quote(command)),
                    Some(format!("{password}\n")),
                )
            }
            PrivMode::None => Err(Error::Validation(format!(
                "{} has no way to gain root. Log in as root, or grant the account sudo rights \
                 and supply the sudo password.",
                self.profile.label
            ))),
        }
    }

    /// [`Self::exec_priv`] that returns stdout and errors on a non-zero exit.
    pub fn exec_priv_ok(&self, command: &str) -> Result<String> {
        self.exec_priv(command)?.require()
    }

    /// [`Self::exec`] that returns stdout and errors on a non-zero exit.
    pub fn exec_ok(&self, command: &str) -> Result<String> {
        self.exec(command)?.require()
    }

    /// Run a command and deliver its output line by line as it arrives.
    ///
    /// stderr is folded into stdout so that a build log stays in order and
    /// cannot fill the channel window while we are draining the other stream.
    /// `cancel` is checked between reads, so a stalled command is abandoned
    /// promptly.
    pub fn exec_stream<F>(
        &self,
        command: &str,
        privileged: bool,
        cancel: &Arc<AtomicBool>,
        timeout: Duration,
        mut on_line: F,
    ) -> Result<i32>
    where
        F: FnMut(&str),
    {
        let wrapped = format!("{{ {command} ; }} 2>&1");
        let (full, stdin) = if privileged {
            match self.priv_mode {
                PrivMode::Root => (wrapped, None),
                PrivMode::SudoNoPassword => {
                    (format!("sudo -n -- /bin/sh -c {}", sh_quote(&wrapped)), None)
                }
                PrivMode::SudoPassword => {
                    let password = self.credentials.sudo_password().to_string();
                    if password.is_empty() {
                        return Err(Error::Validation(format!(
                            "{} needs a sudo password but none was provided.",
                            self.profile.label
                        )));
                    }
                    (
                        format!("sudo -S -p '' -- /bin/sh -c {}", sh_quote(&wrapped)),
                        Some(format!("{password}\n")),
                    )
                }
                PrivMode::None => {
                    return Err(Error::Validation(format!(
                        "{} has no way to gain root.",
                        self.profile.label
                    )))
                }
            }
        } else {
            (wrapped, None)
        };

        // A short session timeout turns each read into a poll, which is what
        // makes cancellation responsive.
        self.session.set_timeout(1_500);
        let result = self.stream_inner(&full, stdin, cancel, timeout, &mut on_line);
        self.reset_command_timeout();
        result
    }

    fn stream_inner<F>(
        &self,
        command: &str,
        stdin: Option<String>,
        cancel: &Arc<AtomicBool>,
        timeout: Duration,
        on_line: &mut F,
    ) -> Result<i32>
    where
        F: FnMut(&str),
    {
        let mut channel = self.session.channel_session()?;
        channel.exec(command)?;

        if let Some(data) = stdin {
            channel.write_all(data.as_bytes())?;
            channel.flush()?;
        }
        channel.send_eof()?;

        let deadline = Instant::now() + timeout;
        let mut pending = String::new();
        let mut buf = [0u8; 8192];

        loop {
            if cancel.load(Ordering::Relaxed) {
                let _ = channel.close();
                return Err(Error::Cancelled);
            }
            if Instant::now() >= deadline {
                let _ = channel.close();
                return Err(Error::Timeout {
                    what: util::truncate(command, 80),
                    seconds: timeout.as_secs(),
                });
            }

            match channel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    pending.push_str(&String::from_utf8_lossy(&buf[..n]));
                    // Emit whole lines; keep any partial tail for the next read.
                    while let Some(idx) = pending.find('\n') {
                        let line: String = pending.drain(..=idx).collect();
                        on_line(line.trim_end_matches(['\r', '\n']));
                    }
                    // A single enormous line should not grow without bound.
                    if pending.len() > 64 * 1024 {
                        let flushed = std::mem::take(&mut pending);
                        on_line(flushed.trim_end());
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    // No data yet. Loop round to re-check cancellation.
                    continue;
                }
                Err(e) => {
                    let _ = channel.close();
                    return Err(Error::Io(e));
                }
            }
        }

        if !pending.trim().is_empty() {
            on_line(pending.trim_end());
        }

        channel.send_eof().ok();
        channel.wait_eof().ok();
        channel.close().ok();
        channel.wait_close().ok();
        Ok(channel.exit_status()?)
    }

    fn exec_inner(&self, command: &str, stdin: Option<String>) -> Result<CommandOutput> {
        let mut channel = self.session.channel_session()?;
        channel.exec(command)?;

        if let Some(data) = stdin {
            channel.write_all(data.as_bytes())?;
            channel.flush()?;
        }
        channel.send_eof()?;

        let mut stdout = Vec::new();
        channel.read_to_end(&mut stdout)?;
        let mut stderr = Vec::new();
        channel.stderr().read_to_end(&mut stderr)?;

        channel.wait_eof().ok();
        channel.close().ok();
        channel.wait_close().ok();
        let status = channel.exit_status()?;

        Ok(CommandOutput {
            command: command.to_string(),
            status,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    // ── Files ───────────────────────────────────────────────────────────────

    /// Write `content` to `path` as the login user.
    pub fn write_file(&self, path: &str, content: &str) -> Result<()> {
        let command = format!("cat > {}", sh_quote(path));
        let out = self.exec_inner(&command, Some(content.to_string()))?;
        out.require().map(|_| ())
    }

    /// Write `content` to `path` as root with an explicit mode.
    ///
    /// The payload is staged in a private temporary file first, because piping
    /// directly into a `sudo`-wrapped shell would put the content and the sudo
    /// password on the same stdin.
    pub fn write_file_priv(&self, path: &str, content: &str, mode: &str) -> Result<()> {
        let staging = format!("/tmp/.htm-{}", util::random_hex(8));

        // `umask 077` applies before the redirect creates the file, so a config
        // holding a pre-shared key is never even briefly world-readable.
        let staged = self.exec_inner(
            &format!("umask 077 && cat > {}", sh_quote(&staging)),
            Some(content.to_string()),
        )?;
        if !staged.ok() {
            return Err(Error::Remote {
                command: format!("stage {path}"),
                status: staged.status,
                stdout: staged.stdout,
                stderr: staged.stderr,
            });
        }

        let install = format!(
            "mkdir -p {dir} && install -m {mode} -o root -g root {src} {dst} && rm -f {src}",
            dir = sh_quote(parent_dir(path)),
            mode = sh_quote(mode),
            src = sh_quote(&staging),
            dst = sh_quote(path),
        );
        let result = self.exec_priv(&install)?;
        if !result.ok() {
            // Always clean the staging file up, even on failure.
            let _ = self.exec(&format!("rm -f {}", sh_quote(&staging)));
            return result.require().map(|_| ());
        }
        Ok(())
    }

    /// Upload a shell script to a private temporary file, run it, and delete it.
    ///
    /// Scripts are transferred as file content rather than embedded in a
    /// command line, so `awk` programs, quotes and `$` signs survive untouched.
    /// This is how every non-trivial remote operation in HTM is expressed.
    pub fn run_script(&self, script: &str, privileged: bool) -> Result<CommandOutput> {
        let path = format!("/tmp/.htm-{}.sh", util::random_hex(8));
        let staged = self.exec_inner(
            &format!("umask 077 && cat > {}", sh_quote(&path)),
            Some(script.to_string()),
        )?;
        if !staged.ok() {
            return Err(Error::Remote {
                command: "stage script".to_string(),
                status: staged.status,
                stdout: staged.stdout,
                stderr: staged.stderr,
            });
        }

        let run = format!("/bin/sh {}", sh_quote(&path));
        let result = if privileged {
            self.exec_priv(&run)
        } else {
            self.exec(&run)
        };
        let _ = self.exec(&format!("rm -f {}", sh_quote(&path)));
        result
    }

    /// [`Self::run_script`] with live line-by-line output and cancellation.
    pub fn run_script_stream<F>(
        &self,
        script: &str,
        privileged: bool,
        cancel: &Arc<AtomicBool>,
        timeout: Duration,
        on_line: F,
    ) -> Result<i32>
    where
        F: FnMut(&str),
    {
        let path = format!("/tmp/.htm-{}.sh", util::random_hex(8));
        let staged = self.exec_inner(
            &format!("umask 077 && cat > {}", sh_quote(&path)),
            Some(script.to_string()),
        )?;
        if !staged.ok() {
            return Err(Error::Remote {
                command: "stage script".to_string(),
                status: staged.status,
                stdout: staged.stdout,
                stderr: staged.stderr,
            });
        }

        let result = self.exec_stream(
            &format!("/bin/sh {}", sh_quote(&path)),
            privileged,
            cancel,
            timeout,
            on_line,
        );
        let _ = self.exec(&format!("rm -f {}", sh_quote(&path)));
        result
    }

    /// Read a remote text file.
    pub fn read_file(&self, path: &str) -> Result<String> {
        self.exec_ok(&format!("cat {}", sh_quote(path)))
    }

    /// Read a remote text file with root privileges.
    pub fn read_file_priv(&self, path: &str) -> Result<String> {
        self.exec_priv_ok(&format!("cat {}", sh_quote(path)))
    }

    /// Whether a path exists on the remote host.
    pub fn path_exists(&self, path: &str) -> Result<bool> {
        Ok(self
            .exec(&format!("test -e {} && echo yes || echo no", sh_quote(path)))?
            .first_line()
            == "yes")
    }

    /// Whether a command is on the remote `PATH`.
    pub fn has_command(&self, name: &str) -> Result<bool> {
        Ok(self
            .exec(&format!(
                "command -v {} >/dev/null 2>&1 && echo yes || echo no",
                sh_quote(name)
            ))?
            .first_line()
            == "yes")
    }

    // ── Privilege probing ───────────────────────────────────────────────────

    fn probe_privileges(&self) -> Result<PrivMode> {
        let uid = self.exec("id -u")?;
        if uid.first_line() == "0" {
            return Ok(PrivMode::Root);
        }

        // `sudo -n true` succeeds only when no password is needed.
        let passwordless = self.exec("sudo -n true >/dev/null 2>&1 && echo yes || echo no")?;
        if passwordless.first_line() == "yes" {
            return Ok(PrivMode::SudoNoPassword);
        }

        let password = self.credentials.sudo_password().to_string();
        if password.is_empty() {
            return Ok(PrivMode::None);
        }

        // Verify the password actually works rather than discovering it half
        // way through an install.
        let check = self.exec_inner(
            "sudo -S -p '' -- true >/dev/null 2>&1 && echo yes || echo no",
            Some(format!("{password}\n")),
        )?;
        if check.first_line() == "yes" {
            Ok(PrivMode::SudoPassword)
        } else {
            Ok(PrivMode::None)
        }
    }

    /// Close the connection politely.
    pub fn disconnect(&self) {
        let _ = self
            .session
            .disconnect(None, "HTM session finished", None);
    }
}

impl Drop for SshClient {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// The directory part of a remote path, defaulting to `/`.
fn parent_dir(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => ".",
    }
}

/// Try the configured authentication method, with the fallbacks that make
/// real-world servers work.
fn authenticate(session: &Session, credentials: &ServerCredentials) -> Result<()> {
    let profile = &credentials.profile;
    let user = profile.username.trim();
    let methods = session.auth_methods(user).unwrap_or("").to_string();

    match profile.auth_kind {
        AuthKind::Password => {
            let password = &credentials.secrets.password;
            if password.is_empty() {
                return Err(Error::Auth {
                    user: user.to_string(),
                    reason: "no password was supplied".to_string(),
                });
            }

            let mut first_error: Option<String> = None;
            if methods.is_empty() || methods.split(',').any(|m| m.trim() == "password") {
                match session.userauth_password(user, password) {
                    Ok(()) if session.authenticated() => return Ok(()),
                    Ok(()) => {}
                    Err(e) => first_error = Some(e.to_string()),
                }
            }

            // Fall back to keyboard-interactive, which many hosts use instead.
            if methods.is_empty()
                || methods
                    .split(',')
                    .any(|m| m.trim() == "keyboard-interactive")
            {
                let mut prompter = PasswordPrompter {
                    password: password.clone(),
                    saw_non_password_prompt: false,
                    last_prompt: String::new(),
                };
                match session.userauth_keyboard_interactive(user, &mut prompter) {
                    Ok(()) if session.authenticated() => return Ok(()),
                    Ok(()) => {}
                    Err(e) => {
                        if prompter.saw_non_password_prompt {
                            return Err(Error::Auth {
                                user: user.to_string(),
                                reason: format!(
                                    "the server asked '{}', which looks like two-factor \
                                     authentication. HTM cannot answer that; use key-based \
                                     authentication instead.",
                                    prompter.last_prompt.trim()
                                ),
                            });
                        }
                        if first_error.is_none() {
                            first_error = Some(e.to_string());
                        }
                    }
                }
            }

            Err(Error::Auth {
                user: user.to_string(),
                reason: describe_auth_failure(&methods, first_error),
            })
        }

        AuthKind::PrivateKey => {
            let key_path = profile.private_key_path.trim();
            let passphrase = credentials.secrets.key_passphrase.clone();
            let passphrase = if passphrase.is_empty() {
                None
            } else {
                Some(passphrase)
            };
            // A matching .pub next to the key helps libssh2 with some key
            // formats; passing None is fine when it is absent.
            let pub_path = format!("{key_path}.pub");
            let pub_ref = if Path::new(&pub_path).is_file() {
                Some(Path::new(pub_path.as_str()))
            } else {
                None
            };

            session
                .userauth_pubkey_file(
                    user,
                    pub_ref,
                    Path::new(key_path),
                    passphrase.as_deref(),
                )
                .map_err(|e| Error::Auth {
                    user: user.to_string(),
                    reason: format!(
                        "key '{key_path}' was rejected: {e}. Check the key matches an entry in \
                         the server's authorized_keys and that the passphrase is correct."
                    ),
                })?;

            if session.authenticated() {
                Ok(())
            } else {
                Err(Error::Auth {
                    user: user.to_string(),
                    reason: format!("the server did not accept key '{key_path}'"),
                })
            }
        }

        AuthKind::Agent => {
            session.userauth_agent(user).map_err(|e| Error::Auth {
                user: user.to_string(),
                reason: format!(
                    "no identity from the SSH agent was accepted: {e}. Is the agent running and \
                     does it hold a key for this server?"
                ),
            })?;
            if session.authenticated() {
                Ok(())
            } else {
                Err(Error::Auth {
                    user: user.to_string(),
                    reason: "the SSH agent offered no acceptable identity".to_string(),
                })
            }
        }
    }
}

fn describe_auth_failure(methods: &str, detail: Option<String>) -> String {
    let mut msg = String::from("the server rejected the password");
    if let Some(d) = detail {
        if !d.trim().is_empty() {
            msg.push_str(&format!(" ({})", d.trim()));
        }
    }
    if !methods.trim().is_empty() {
        msg.push_str(&format!(". The server offers: {}", methods.trim()));
        if !methods.contains("password") && !methods.contains("keyboard-interactive") {
            msg.push_str(
                ". Password login appears to be disabled; switch this server to key \
                 authentication.",
            );
        }
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_dir_handles_roots_and_bare_names() {
        assert_eq!(parent_dir("/etc/candytunnel/a.toml"), "/etc/candytunnel");
        assert_eq!(parent_dir("/a.toml"), "/");
        assert_eq!(parent_dir("a.toml"), ".");
    }

    #[test]
    fn command_output_requires_success() {
        let bad = CommandOutput {
            command: "false".into(),
            status: 1,
            stdout: String::new(),
            stderr: "boom".into(),
        };
        assert!(bad.require().is_err());
    }
}
