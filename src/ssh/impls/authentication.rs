//! Shared first-factor and MFA authentication for terminal, jump hosts and SFTP.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use russh::client::{Handle, Handler, KeyboardInteractiveAuthResponse as Kb};
use russh::keys::key::PrivateKeyWithHashAlg;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{AuthMethod, Session};
use crate::ssh::{
    disconnect_ssh, load_session_private_key, network_stage, MfaResponder, SessionEvent,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthResult {
    Success,
    Cancelled,
    Failed,
}

/// Only final success authorizes channels, even if a first factor passed.
/// Keep the transport alive so any accepted first factor survives the next step.
pub(crate) async fn authenticate_credentials<H>(
    handle: &mut Handle<H>,
    session: &Session,
    user: &str,
    password: &str,
    events: &UnboundedSender<SessionEvent>,
) -> Result<AuthResult>
where
    H: Handler + 'static,
    H::Error: std::error::Error + Send + Sync + 'static,
{
    let result = async {
        let complete = match session.auth {
            AuthMethod::Password => network_stage(
                &format!(
                    "password authentication at {}:{}",
                    session.host, session.port
                ),
                handle.authenticate_password(user, password),
            )
            .await?
            .success(),
            AuthMethod::Key => {
                let key = load_session_private_key(session, password)?;
                let hash = crate::ssh::rsa_hash(handle, key.algorithm().is_rsa()).await;
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
                network_stage(
                    &format!(
                        "public-key authentication at {}:{}",
                        session.host, session.port
                    ),
                    handle.authenticate_publickey(user, key),
                )
                .await?
                .success()
            }
            AuthMethod::KeyboardInteractive => false,
            AuthMethod::Agent => crate::ssh::agent_auth(handle, user, session, events).await?,
        };
        if complete {
            return Ok(AuthResult::Success);
        }
        // The password field in key mode is a local key passphrase, never an
        // account password or an answer to a remote authentication challenge.
        let account_password = if matches!(
            session.auth,
            AuthMethod::Password | AuthMethod::KeyboardInteractive
        ) {
            password
        } else {
            ""
        };
        keyboard_interactive_auth(
            handle,
            user,
            account_password,
            &session.mfa_profile_id,
            &session.id,
            &session.host,
            events,
        )
        .await
        .context("keyboard-interactive auth failed")
    }
    .await;
    if !matches!(&result, Ok(AuthResult::Success)) {
        disconnect_ssh(handle, "authentication did not complete").await;
    }
    result
}

fn looks_like_mfa(prompt: &str) -> bool {
    let text = prompt.to_lowercase();
    [
        "code",
        "otp",
        "mfa",
        "2fa",
        "factor",
        "duo",
        "verification",
        "verify",
        "token",
        "authenticator",
        "passcode",
        "one-time",
        "one time",
        "验证码",
        "动态",
        "令牌",
    ]
    .iter()
    .any(|word| text.contains(word))
}

fn is_account_password_prompt(prompt: &str, echo: bool) -> bool {
    if echo {
        return false;
    }
    let text = prompt
        .trim()
        .trim_end_matches([':', '：'])
        .trim()
        .to_lowercase();
    matches!(
        text.as_str(),
        "password" | "密码" | "请输入密码" | "登录密码" | "请输入登录密码"
    ) || text
        .strip_suffix("'s password")
        .is_some_and(|account| account.contains('@') && !account.chars().any(char::is_whitespace))
}

pub(crate) async fn keyboard_interactive_auth<H>(
    handle: &mut Handle<H>,
    user: &str,
    password: &str,
    mfa_profile_id: &str,
    session_id: &str,
    host: &str,
    events: &UnboundedSender<SessionEvent>,
) -> Result<AuthResult>
where
    H: Handler + 'static,
    H::Error: std::error::Error + Send + Sync + 'static,
{
    let stage = format!("keyboard-interactive authentication at {host}");
    let mut response = network_stage(
        &stage,
        handle.authenticate_keyboard_interactive_start(user, None),
    )
    .await?;
    let mut password_used = false;
    let mut totp_used = false;
    // Allow 16 challenge rounds and still inspect the final response to round 16.
    for round in 0..=16 {
        match response {
            Kb::Success => return Ok(AuthResult::Success),
            Kb::Failure { .. } => return Ok(AuthResult::Failed),
            Kb::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                if round == 16 {
                    return Ok(AuthResult::Failed);
                }
                let mut responses = Vec::with_capacity(prompts.len());
                let mut deferred_totp = None;
                for prompt in prompts {
                    // Include server context: some servers say "Password:" in
                    // the prompt and identify it as an OTP in the instructions.
                    let message = [name.as_str(), instructions.as_str(), prompt.prompt.as_str()]
                        .into_iter()
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>()
                        .join("\n");
                    if !password_used
                        && !password.is_empty()
                        && is_account_password_prompt(&prompt.prompt, prompt.echo)
                        && !looks_like_mfa(&message)
                    {
                        responses.push(password.to_string());
                        password_used = true;
                    } else {
                        if !totp_used {
                            if configured_totp_profile(mfa_profile_id, &prompt.prompt, prompt.echo)
                                .is_some()
                            {
                                deferred_totp =
                                    Some((responses.len(), prompt.prompt, prompt.echo, message));
                                responses.push(String::new());
                                totp_used = true;
                                continue;
                            }
                        }
                        let answer = tokio::select! {
                            answer = ask_mfa_prompt(session_id, host, &message, prompt.echo, events) => answer,
                            _ = &mut *handle => return Err(anyhow!("SSH disconnected while waiting for MFA")),
                        };
                        match answer {
                            Some(answer) => responses.push(answer),
                            None => return Ok(AuthResult::Cancelled),
                        }
                    }
                }
                // Human answers may take minutes, and profiles can be deleted
                // or replaced meanwhile. Generate only after every other field
                // is ready, immediately before submitting the complete round.
                if let Some((index, prompt, echo, message)) = deferred_totp {
                    let answer = tokio::select! {
                        answer = configured_totp_answer(mfa_profile_id, &prompt, echo) => answer,
                        _ = &mut *handle => return Err(anyhow!("SSH disconnected while waiting for MFA")),
                    };
                    responses[index] = match answer {
                        Some(code) => code,
                        None => match tokio::select! {
                            answer = ask_mfa_prompt(session_id, host, &message, echo, events) => answer,
                            _ = &mut *handle => return Err(anyhow!("SSH disconnected while waiting for MFA")),
                        } {
                            Some(answer) => answer,
                            None => return Ok(AuthResult::Cancelled),
                        },
                    };
                }
                response = network_stage(
                    &stage,
                    handle.authenticate_keyboard_interactive_respond(responses),
                )
                .await?;
            }
        }
    }
    Ok(AuthResult::Failed)
}

fn configured_totp_profile(id: &str, prompt: &str, echo: bool) -> Option<crate::totp::MfaProfile> {
    if id.is_empty() || !crate::totp::is_totp_prompt(prompt, echo) {
        return None;
    }
    let profile = crate::config::ConfigStore::load()
        .ok()?
        .mfa_profile(id)?
        .clone();
    profile.validate().ok()?;
    Some(profile)
}

async fn configured_totp_answer(id: &str, prompt: &str, echo: bool) -> Option<String> {
    let profile = configured_totp_profile(id, prompt, echo)?;
    let remaining = profile.remaining_at(crate::totp::now());
    if remaining <= 2 {
        // Do not retain a deleted/replaced entry across the period boundary.
        tokio::time::sleep(std::time::Duration::from_secs(u64::from(remaining))).await;
    }
    let store = crate::config::ConfigStore::load().ok()?;
    store.mfa_profile(id)?.code_at(crate::totp::now()).ok()
}

async fn ask_mfa_prompt(
    session_id: &str,
    host: &str,
    prompt: &str,
    echo: bool,
    events: &UnboundedSender<SessionEvent>,
) -> Option<String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    events
        .send(SessionEvent::MfaPrompt {
            session_id: session_id.to_string(),
            host: host.to_string(),
            prompt: prompt.to_string(),
            echo,
            responder: MfaResponder::new(tx),
        })
        .ok()?;
    rx.await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_hidden_account_password_prompts_are_automatic() {
        for prompt in ["Password:", "jeff@host's password:", "请输入密码:"] {
            assert!(is_account_password_prompt(prompt, false), "{prompt}");
            assert!(!is_account_password_prompt(prompt, true), "{prompt}");
        }
        for prompt in [
            "Response:",
            "New password:",
            "Enter your database password:",
            "请输入新密码:",
            "MFA code:",
            "One-time password (OATH-TOTP):",
            "Verification code:",
            "Duo two-factor login",
            "请输入验证码:",
            "动态口令:",
            "请输入令牌:",
            "MFA\nPassword:",
        ] {
            assert!(!is_account_password_prompt(prompt, false), "{prompt}");
        }
    }
}
