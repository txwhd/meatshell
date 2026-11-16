//! Exercise the production channel broker and SFTP privilege layer while a PTY
//! remains active. The fixture accepts only one authenticated TCP connection.
use crate::{
    authentication::*, channels::*, command::SessionCommand, config::*, elevation::Elevation,
    ssh::SessionEvent,
};
use russh::{client, ChannelMsg};
use russh_sftp::client::SftpSession;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, Mutex},
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
        Ok(true)
    }
}

struct Fixture {
    _server: ServerProcess,
    terminal: mpsc::UnboundedSender<SessionCommand>,
    echoed: mpsc::UnboundedReceiver<Vec<u8>>,
    pump: tokio::task::JoinHandle<()>,
    session: Session,
    prompts: Arc<AtomicUsize>,
}

impl Fixture {
    async fn start(mode: &str) -> Self {
        let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".into());
        let script = std::env::var("MEATSHELL_AUTH_FIXTURE_SCRIPT")
            .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/server.py").into());
        let mut child = Command::new(python)
            .args([script.as_str(), mode])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let session = Session {
            id: "shared-fixture".into(),
            host: "127.0.0.1".into(),
            port: ready["port"].as_u64().unwrap() as u16,
            auth: AuthMethod::Password,
            private_key_inline: String::new(),
            sftp_mode: String::new(),
            sftp_command: String::new(),
            mfa_profile_id: String::new(),
        };
        let mut handle = client::connect(
            Arc::new(client::Config::default()),
            ("127.0.0.1", session.port),
            Client,
        )
        .await
        .unwrap();
        let (events, mut received) = mpsc::unbounded_channel();
        let prompts = Arc::new(AtomicUsize::new(0));
        let count = prompts.clone();
        let answers = tokio::spawn(async move {
            while let Some(event) = received.recv().await {
                let SessionEvent::MfaPrompt { responder, .. } = event else {
                    continue;
                };
                count.fetch_add(1, Ordering::SeqCst);
                responder.respond(Some("654321".into()));
            }
        });
        assert_eq!(
            authenticate_credentials(
                &mut handle,
                &session,
                "fixture",
                "account-password",
                &events
            )
            .await
            .unwrap(),
            AuthResult::Success
        );
        answers.abort();
        // Also compile and exercise the dedicated Handle implementation.
        let mut shell = handle.open_session_channel().await.unwrap();
        shell
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        shell.request_shell(true).await.unwrap();
        let handle = Mutex::new(handle);
        let (terminal, mut commands) = mpsc::unbounded_channel();
        let (echo_tx, echoed) = mpsc::unbounded_channel();
        let pump = tokio::spawn(async move {
            loop {
                tokio::select! {
                    command = commands.recv() => match command {
                        Some(SessionCommand::OpenSessionChannel { reply }) => reply_session_channel(&handle,reply).await,
                        Some(SessionCommand::RawInput(data)) => { shell.data(&data[..]).await.unwrap(); }
                        Some(SessionCommand::Close) | None => break,
                        _ => {}
                    },
                    message = shell.wait() => match message {
                        Some(ChannelMsg::Data { data }) => { let _ = echo_tx.send(data.to_vec()); }
                        Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    }
                }
            }
            crate::connection::disconnect_ssh(&*handle.lock().await, "fixture complete").await;
        });
        Self {
            _server: ServerProcess(child),
            terminal,
            echoed,
            pump,
            session,
            prompts,
        }
    }

    async fn assert_echo(&mut self) {
        self.terminal
            .send(SessionCommand::RawInput(b"pty-still-alive\n".to_vec()))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\n") {
            bytes.extend(
                tokio::time::timeout(Duration::from_secs(2), self.echoed.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(bytes, b"pty-still-alive\n");
    }
    async fn close(self) {
        self.terminal.send(SessionCommand::Close).unwrap();
        tokio::time::timeout(Duration::from_secs(2), self.pump)
            .await
            .unwrap()
            .unwrap();
        assert!(self.terminal.open_session_channel().await.is_err());
    }
}

async fn list_and_read(
    elevation: &Elevation,
    terminal: &mpsc::UnboundedSender<SessionCommand>,
) -> SftpSession {
    let stream = elevation.open_stream(terminal).await.unwrap();
    let sftp = SftpSession::new(stream).await.unwrap();
    let mut entries = sftp.read_dir("/").await.unwrap();
    assert!(entries.any(|item| item.file_name() == "fixture.txt"));
    let mut file = sftp.open("/fixture.txt").await.unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).await.unwrap();
    assert_eq!(contents, "shared-channel-content\n");
    drop(file);
    sftp
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_mfa_covers_browse_transfer_and_exec_with_active_pty() {
    let mut fixture = Fixture::start("shared").await;
    let elevation = Elevation::default();
    for _ in 0..3 {
        let terminal = fixture.terminal.clone();
        let (sftp, ()) = tokio::join!(list_and_read(&elevation, &terminal), fixture.assert_echo());
        sftp.close().await.unwrap();
        fixture.assert_echo().await;
    }
    // Owner lookup, tar and cleanup commands all use this same channel source.
    for command in [
        "getent passwd",
        "tar -cf /tmp/fixture.tar /fixture.txt",
        "rm -f /tmp/fixture.tar",
    ] {
        assert_eq!(
            elevation
                .exec_shell(&fixture.terminal, command)
                .await
                .unwrap(),
            0
        );
        fixture.assert_echo().await;
    }
    assert_eq!(fixture.prompts.load(Ordering::SeqCst), 1);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_sftp_keeps_the_authenticated_pty_and_does_not_reconnect() {
    let mut fixture = Fixture::start("shared_no_sftp").await;
    let result = Elevation::default().open_stream(&fixture.terminal).await;
    assert!(result.is_err());
    fixture.assert_echo().await;
    assert_eq!(fixture.prompts.load(Ordering::SeqCst), 1);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_and_both_sudo_modes_reuse_the_same_channel_source() {
    for mode in ["shared_custom", "shared_sudo", "shared_sudo_password"] {
        let mut fixture = Fixture::start(mode).await;
        fixture.session.sftp_mode = if mode == "shared_custom" {
            "custom"
        } else {
            "sudo"
        }
        .into();
        fixture.session.sftp_command = "fixture-sftp".into();
        let elevation = Elevation::resolve(&fixture.terminal, &fixture.session, "account-password")
            .await
            .unwrap();
        let sftp = list_and_read(&elevation, &fixture.terminal).await;
        sftp.close().await.unwrap();
        fixture.assert_echo().await;
        assert_eq!(fixture.prompts.load(Ordering::SeqCst), 1);
        fixture.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_channel_request_does_not_damage_terminal() {
    let mut fixture = Fixture::start("shared").await;
    let (reply, received) = tokio::sync::oneshot::channel();
    drop(received);
    fixture
        .terminal
        .send(SessionCommand::OpenSessionChannel { reply })
        .unwrap();
    fixture.assert_echo().await;
    let sftp = list_and_read(&Elevation::default(), &fixture.terminal).await;
    sftp.close().await.unwrap();
    fixture.assert_echo().await;
    fixture.close().await;
}
