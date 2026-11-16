#![allow(dead_code)]
//! Compile the real authentication code without linking the desktop.

mod config {
    pub use crate::secret::Secret;
    #[derive(Debug)]
    pub struct PortForward;
    #[derive(Clone, Copy)]
    pub enum AuthMethod {
        Password,
        Key,
        KeyboardInteractive,
        Agent,
    }
    pub struct Session {
        pub id: String,
        pub host: String,
        pub port: u16,
        pub auth: AuthMethod,
        pub private_key_inline: String,
        pub sftp_mode: String,
        pub sftp_command: String,
        pub mfa_profile_id: String,
    }
    static PROFILES: std::sync::OnceLock<std::sync::Mutex<Vec<crate::totp::MfaProfile>>> =
        std::sync::OnceLock::new();
    static DELETE_ON_READ: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> =
        std::sync::OnceLock::new();
    pub struct ConfigStore {
        profiles: Vec<crate::totp::MfaProfile>,
    }
    impl ConfigStore {
        pub fn load() -> anyhow::Result<Self> {
            let mut profiles = PROFILES.get_or_init(Default::default).lock().unwrap();
            let snapshot = profiles.clone();
            for id in DELETE_ON_READ
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .drain(..)
            {
                profiles.retain(|profile| profile.id != id);
            }
            Ok(Self { profiles: snapshot })
        }
        pub fn mfa_profile(&self, id: &str) -> Option<&crate::totp::MfaProfile> {
            self.profiles.iter().find(|profile| profile.id == id)
        }
    }
    #[cfg(test)]
    pub fn delete_profile(id: &str) {
        PROFILES
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .retain(|profile| profile.id != id);
    }
    #[cfg(test)]
    pub fn add_profile(id: &str) {
        let profile = crate::totp::MfaProfile::from_input(
            id.into(),
            "Fixture",
            "JBSWY3DPEHPK3PXP",
            "SHA1",
            6,
            30,
        )
        .unwrap();
        PROFILES
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .push(profile);
        if id == "auto_deleted" {
            DELETE_ON_READ
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .push(id.into());
        }
    }
}
#[path = "../../../src/config/struct/secret.rs"]
mod secret;
#[path = "../../../src/totp.rs"]
mod totp;

#[path = "../../../src/ssh/impls/agent.rs"]
mod agent;
#[path = "../../../src/ssh/impls/authentication.rs"]
mod authentication;
#[path = "../../../src/ssh/impls/channels.rs"]
mod channels;
#[path = "../../../src/ssh/struct/command.rs"]
mod command;
#[path = "../../../src/sftp/impls/elevation.rs"]
mod elevation;
mod i18n {
    pub fn t<'a>(_: &'a str, en: &'a str) -> &'a str {
        en
    }
}
#[path = "../../../src/ssh/impls/connection.rs"]
mod connection;
#[path = "../../../src/ssh/struct/responders.rs"]
mod responders;
#[cfg(test)]
mod shared_protocol;

mod ssh {
    pub(crate) use crate::channels::{reply_session_channel, SessionChannelSource};
    pub(crate) use crate::command::{ProcessKillResult, SessionCommand};
    pub(crate) use crate::connection::{disconnect_ssh, network_stage};
    pub(crate) use crate::responders::MfaResponder;
    pub enum SessionEvent {
        Status(String),
        MfaPrompt {
            session_id: String,
            host: String,
            prompt: String,
            echo: bool,
            responder: MfaResponder,
        },
    }
    pub async fn rsa_hash<H: russh::client::Handler>(
        handle: &russh::client::Handle<H>,
        is_rsa: bool,
    ) -> Option<ssh_key::HashAlg> {
        if !is_rsa {
            return None;
        }
        match handle.best_supported_rsa_hash().await {
            Ok(Some(best)) => best,
            _ => Some(ssh_key::HashAlg::Sha256),
        }
    }
    pub async fn agent_auth<H: russh::client::Handler>(
        handle: &mut russh::client::Handle<H>,
        user: &str,
        _: &crate::config::Session,
        _: &tokio::sync::mpsc::UnboundedSender<SessionEvent>,
    ) -> anyhow::Result<bool> {
        let mut agent = crate::agent::Agent::connect().await?;
        crate::agent::login(handle, user, &mut agent).await
    }
    pub fn load_session_private_key(
        session: &crate::config::Session,
        pass: &str,
    ) -> anyhow::Result<russh::keys::PrivateKey> {
        Ok(russh::keys::decode_secret_key(
            &session.private_key_inline,
            if pass.is_empty() { None } else { Some(pass) },
        )?)
    }
}

#[cfg(test)]
mod protocol {
    use super::{authentication::*, config::*, ssh::SessionEvent};
    use russh::client;
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
        sync::{Arc, Mutex},
        time::Duration,
    };

    struct ServerProcess(Child);
    impl Drop for ServerProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    struct Client;
    impl client::Handler for Client {
        type Error = russh::Error;
        async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
            Ok(true) // Loopback fixture keys only; production host-key logic is unchanged.
        }
    }

    #[derive(Clone, Copy)]
    enum Reply {
        Correct,
        Wrong,
        Cancel,
        Hold,
        NoUi,
    }

    async fn run(
        mode: &str,
        auth: AuthMethod,
        reply: Reply,
    ) -> (anyhow::Result<AuthResult>, Vec<(String, bool)>) {
        let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".into());
        // A cross-compiled test executable runs on a different host, where the
        // build machine's CARGO_MANIFEST_DIR is not a valid filesystem path.
        let script = std::env::var("MEATSHELL_AUTH_FIXTURE_SCRIPT")
            .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/server.py").into());
        let mut child = Command::new(python)
            .arg(script)
            .arg(mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let _server = ServerProcess(child);
        let ready: serde_json::Value =
            serde_json::from_str(&line).expect("fixture did not start (install Python paramiko)");
        let port = ready["port"].as_u64().unwrap() as u16;
        let previous_agent = if mode == "agent_mfa" {
            let previous = std::env::var_os("SSH_AUTH_SOCK");
            std::env::set_var("SSH_AUTH_SOCK", ready["agent_sock"].as_str().unwrap());
            Some(previous)
        } else {
            None
        };
        let session = Session {
            id: "fixture".into(),
            host: "127.0.0.1".into(),
            port,
            auth,
            private_key_inline: ready["key"].as_str().unwrap().into(),
            sftp_mode: String::new(),
            sftp_command: String::new(),
            mfa_profile_id: if mode.starts_with("auto_") {
                mode.into()
            } else {
                String::new()
            },
        };
        if mode.starts_with("auto_") && mode != "auto_missing" {
            add_profile(mode);
        }
        let password = if matches!(auth, AuthMethod::Key) {
            if mode == "key_encrypted" {
                "key-passphrase"
            } else {
                ""
            }
        } else {
            "account-password"
        };
        let mut handle = client::connect(
            Arc::new(client::Config::default()),
            ("127.0.0.1", port),
            Client,
        )
        .await
        .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let prompts = seen.clone();
        let delete_during_prompt = mode == "auto_delete_pending";
        let ui = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let SessionEvent::MfaPrompt {
                    prompt,
                    echo,
                    responder,
                    ..
                } = event
                else {
                    continue;
                };
                prompts.lock().unwrap().push((prompt.clone(), echo));
                if delete_during_prompt {
                    delete_profile("auto_delete_pending");
                }
                match reply {
                    Reply::Hold => std::future::pending::<()>().await,
                    Reply::Cancel | Reply::NoUi => responder.respond(None),
                    Reply::Wrong => responder.respond(Some("wrong-code".into())),
                    Reply::Correct => responder.respond(Some(if prompt.ends_with("Choice:") {
                        "approve".into()
                    } else {
                        "654321".into()
                    })),
                }
            }
        });
        if matches!(reply, Reply::NoUi) {
            ui.abort();
        }
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            authenticate_credentials(&mut handle, &session, "fixture", password, &tx),
        )
        .await
        .expect("authentication hung");
        if let Some(previous) = previous_agent {
            match previous {
                Some(value) => std::env::set_var("SSH_AUTH_SOCK", value),
                None => std::env::remove_var("SSH_AUTH_SOCK"),
            }
        }
        ui.abort();
        if result.is_ok() {
            crate::connection::disconnect_ssh(&handle, "fixture complete").await;
            tokio::time::timeout(Duration::from_secs(1), &mut handle)
                .await
                .expect("transport did not stop after MFA cancellation/disconnect")
                .ok();
        }
        let prompts = seen.lock().unwrap().clone();
        (result, prompts)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn password_then_mfa_stays_on_one_connection() {
        let (result, prompts) = run("password_mfa", AuthMethod::Password, Reply::Correct).await;
        assert_eq!(result.unwrap(), AuthResult::Success);
        assert_eq!(prompts.len(), 1); // Unknown Response: must not get the account password.
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_partial_success_stops_offering_keys_and_continues_mfa() {
        let (result, prompts) = run("agent_mfa", AuthMethod::Agent, Reply::Correct).await;
        assert_eq!(result.unwrap(), AuthResult::Success);
        assert_eq!(prompts.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publickey_and_encrypted_key_continue_mfa_without_leaking_passphrase() {
        for mode in ["key_mfa", "key_encrypted"] {
            let (result, prompts) = run(mode, AuthMethod::Key, Reply::Correct).await;
            assert_eq!(result.unwrap(), AuthResult::Success, "{mode}");
            assert_eq!(prompts.len(), 1);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ordinary_password_key_and_interactive_password_keep_working() {
        for (mode, auth) in [
            ("password_only", AuthMethod::Password),
            ("key_only", AuthMethod::Key),
            ("interactive", AuthMethod::KeyboardInteractive),
            ("fallback", AuthMethod::Password),
        ] {
            let (result, prompts) = run(mode, auth, Reply::Correct).await;
            assert_eq!(result.unwrap(), AuthResult::Success, "{mode}");
            assert!(prompts.is_empty(), "{mode}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_code_and_rejected_key_cannot_login() {
        let (result, _) = run("password_mfa", AuthMethod::Password, Reply::Wrong).await;
        assert_eq!(result.unwrap(), AuthResult::Failed);
        let (result, _) = run("reject_key", AuthMethod::Key, Reply::Correct).await;
        assert_eq!(result.unwrap(), AuthResult::Failed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_and_missing_ui_close_pending_mfa_transport() {
        for reply in [Reply::Cancel, Reply::NoUi] {
            let (result, _) = run("password_mfa", AuthMethod::Password, reply).await;
            assert_eq!(result.unwrap(), AuthResult::Cancelled);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_disconnect_during_request_or_human_input_returns() {
        for mode in ["disconnect_start", "disconnect_prompt"] {
            let (result, _) = run(mode, AuthMethod::Password, Reply::Hold).await;
            assert!(result.is_err(), "{mode}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_echo_multiple_prompts_and_empty_rounds_are_handled() {
        for (mode, count) in [
            ("echo", 1),
            ("context", 1),
            ("password_banner", 1),
            ("new_password", 1),
            ("multi", 3),
            ("empty", 1),
        ] {
            let (result, prompts) = run(mode, AuthMethod::Password, Reply::Correct).await;
            assert_eq!(result.unwrap(), AuthResult::Success, "{mode}");
            assert_eq!(prompts.len(), count, "{mode}");
            if mode == "context" {
                assert!(prompts[0].0.contains("MFA\nPassword:"));
            }
            if mode == "echo" {
                assert!(prompts[0].1);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sixteen_rounds_can_succeed_but_endless_exchange_is_bounded() {
        let (result, prompts) = run("sixteen", AuthMethod::Password, Reply::Correct).await;
        assert_eq!(result.unwrap(), AuthResult::Success);
        assert_eq!(prompts.len(), 16);
        let (result, prompts) = run("endless", AuthMethod::Password, Reply::Correct).await;
        assert_eq!(result.unwrap(), AuthResult::Failed);
        assert_eq!(prompts.len(), 16);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn referenced_totp_answers_otp_without_a_dialog() {
        let (result, prompts) = run("auto_totp", AuthMethod::Password, Reply::Hold).await;
        assert_eq!(result.unwrap(), AuthResult::Success);
        assert!(prompts.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deletion_during_other_field_wait_falls_back_before_sending_otp() {
        let (result, prompts) =
            run("auto_delete_pending", AuthMethod::Password, Reply::Correct).await;
        assert_eq!(result.unwrap(), AuthResult::Success);
        assert_eq!(prompts.len(), 2);
        assert!(prompts[0].0.ends_with("Choice:"));
        assert!(prompts[1].0.ends_with("Verification code:"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_otp_banner_does_not_fill_password_or_menu_fields() {
        for mode in [
            "auto_context_password",
            "auto_menu",
            "auto_missing",
            "auto_repeat",
            "auto_mixed",
            "auto_deleted",
        ] {
            let (result, prompts) = run(mode, AuthMethod::Password, Reply::Correct).await;
            assert_eq!(result.unwrap(), AuthResult::Success, "{mode}");
            assert_eq!(prompts.len(), 1, "{mode}");
        }
    }
}
