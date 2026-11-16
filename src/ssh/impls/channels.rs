//! Session channels can share the terminal's authenticated transport without
//! sharing credentials, MFA answers, or a lock during file transfer.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use russh::client::{Handle, Handler, Msg};
use russh::Channel;
use tokio::sync::{mpsc::UnboundedSender, oneshot, Mutex};

use crate::ssh::SessionCommand;

#[async_trait]
pub(crate) trait SessionChannelSource: Send + Sync {
    async fn open_session_channel(&self) -> Result<Channel<Msg>>;
}

#[async_trait]
impl<H: Handler + Sync> SessionChannelSource for Handle<H>
where
    H::Error: std::error::Error + Send + Sync + 'static,
{
    async fn open_session_channel(&self) -> Result<Channel<Msg>> {
        Ok(self.channel_open_session().await?)
    }
}

#[async_trait]
impl SessionChannelSource for UnboundedSender<SessionCommand> {
    async fn open_session_channel(&self) -> Result<Channel<Msg>> {
        let (reply, received) = oneshot::channel();
        self.send(SessionCommand::OpenSessionChannel { reply })
            .map_err(|_| anyhow!("terminal SSH connection is closed"))?;
        crate::ssh::network_stage("open SFTP channel through terminal", async {
            received
                .await
                .map_err(|_| anyhow!("terminal SSH connection is closed"))?
        })
        .await
    }
}

/// Called by the terminal pump itself, preserving the existing serialization
/// with PTY polling. Only opening the channel holds the transport lock.
pub(crate) async fn reply_session_channel<H: Handler>(
    handle: &Mutex<Handle<H>>,
    reply: oneshot::Sender<Result<Channel<Msg>>>,
) {
    if reply.is_closed() {
        return;
    }
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        handle.lock().await.channel_open_session().await
    })
    .await
    .map_err(|_| anyhow!("open SFTP channel timed out"))
    .and_then(|result| result.map_err(Into::into));
    // A cancelled request must not leave a successful, unused remote channel.
    if let Err(Ok(channel)) = reply.send(result) {
        let _ = channel.close().await;
    }
}
