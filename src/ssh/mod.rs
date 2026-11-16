#[path = "struct/mod.rs"]
mod structs;
#[path = "impls/agent.rs"]
pub(crate) mod agent;
#[path = "impls/connection.rs"]
mod connection;
#[path = "impls/cwd.rs"]
mod cwd;
pub(crate) use connection::{with_automation_cancellation, inherit_automation_cancellation, disconnect_ssh, network_stage, HandshakeHandler, HostKeyWait};
#[path = "impls/known_hosts.rs"]
pub(crate) mod known_hosts;
#[path = "impls/ppk.rs"]
pub(crate) mod ppk;
#[path = "impls/proxy.rs"]
pub(crate) mod proxy;
#[path = "impls/ssh.rs"]
mod ssh;
#[path = "impls/authentication.rs"]
mod authentication;
pub(crate) use authentication::{authenticate_credentials, AuthResult};
#[path = "impls/channels.rs"]
mod channels;
pub(crate) use channels::{reply_session_channel, SessionChannelSource};
#[path = "impls/ssh_config.rs"]
pub(crate) mod ssh_config;
#[path = "impls/ssh_cli.rs"]
pub(crate) mod ssh_cli;

pub(crate) use ssh::*;
pub(crate) use structs::*;
