//! RFC 6238 TOTP profiles. Errors never include the input URI or secret.
use crate::config::Secret;
use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MfaProfile {
    pub id: String,
    pub name: String,
    pub secret: Secret,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
}

fn decode_secret(raw: &str) -> Result<Zeroizing<Vec<u8>>> {
    let normalized = Zeroizing::new(
        raw.chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != '-')
            .collect::<String>()
            .to_ascii_uppercase(),
    );
    let value = normalized.as_str();
    if value.is_empty() || value.len() > 4096 {
        bail!("TOTP 密钥为空或过长 / empty or oversized TOTP secret");
    }
    let bytes = if value.contains('=') {
        data_encoding::BASE32.decode(value.as_bytes())
    } else {
        data_encoding::BASE32_NOPAD.decode(value.as_bytes())
    }
    .map_err(|_| anyhow!("TOTP 密钥必须是有效 Base32 / invalid Base32 TOTP secret"))?;
    if bytes.is_empty() {
        bail!("TOTP 密钥为空 / empty TOTP secret");
    }
    Ok(Zeroizing::new(bytes))
}

impl MfaProfile {
    pub fn from_input(
        id: String,
        name: &str,
        input: &str,
        algorithm: &str,
        digits: u32,
        period: u32,
    ) -> Result<Self> {
        let mut name = name.trim().to_string();
        let mut secret = Secret::new(input.trim());
        let mut algorithm = algorithm.to_ascii_uppercase().replace('-', "");
        let mut digits = digits;
        let mut period = period;
        if input.trim().contains("://") {
            let uri = url::Url::parse(input.trim())
                .map_err(|_| anyhow!("无效的 otpauth 链接 / invalid otpauth URI"))?;
            if uri.scheme() != "otpauth" || uri.host_str() != Some("totp") {
                bail!("仅支持 otpauth://totp / only TOTP URIs are supported");
            }
            let mut seen = std::collections::HashSet::new();
            let mut supplied_secret = false;
            for (key, value) in uri.query_pairs() {
                if !seen.insert(key.to_string()) {
                    bail!("otpauth 参数重复 / duplicate otpauth parameter");
                }
                match key.as_ref() {
                    "secret" => {
                        secret = Secret::new(value.as_ref());
                        supplied_secret = true;
                    }
                    "algorithm" => algorithm = value.to_ascii_uppercase().replace('-', ""),
                    "digits" => {
                        digits = value
                            .parse()
                            .map_err(|_| anyhow!("验证码位数无效 / invalid TOTP digits"))?
                    }
                    "period" => {
                        period = value
                            .parse()
                            .map_err(|_| anyhow!("验证码周期无效 / invalid TOTP period"))?
                    }
                    "issuer" if name.is_empty() => name = value.to_string(),
                    _ => {}
                }
            }
            if !supplied_secret {
                bail!("otpauth 缺少 secret / missing TOTP secret");
            }
            if name.is_empty() {
                name = url::form_urlencoded::parse(
                    format!("label={}", uri.path().trim_start_matches('/')).as_bytes(),
                )
                .next()
                .map(|(_, label)| label.into_owned())
                .unwrap_or_default();
            }
        }
        let decoded = decode_secret(secret.as_str())?;
        secret = Secret::new(data_encoding::BASE32_NOPAD.encode(&decoded));
        let profile = Self {
            id,
            name,
            secret,
            algorithm,
            digits,
            period,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.len() > 256 {
            bail!("请填写 MFA 名称 / enter an MFA name");
        }
        if !matches!(self.algorithm.as_str(), "SHA1" | "SHA256" | "SHA512") {
            bail!("不支持的 TOTP 算法 / unsupported TOTP algorithm");
        }
        if !matches!(self.digits, 6 | 8) {
            bail!("TOTP 仅支持 6 或 8 位 / TOTP supports 6 or 8 digits");
        }
        if self.period == 0 || self.period > 86400 {
            bail!("TOTP 周期须为 1–86400 秒 / invalid TOTP period");
        }
        decode_secret(self.secret.as_str())?;
        Ok(())
    }

    pub fn code_at(&self, timestamp: u64) -> Result<String> {
        self.validate()?;
        let key = decode_secret(self.secret.as_str())?;
        let counter = (timestamp / u64::from(self.period)).to_be_bytes();
        macro_rules! digest {
            ($sha:ty) => {{
                let mut mac = <Hmac<$sha> as Mac>::new_from_slice(&key)
                    .map_err(|_| anyhow!("TOTP generation failed"))?;
                mac.update(&counter);
                Zeroizing::new(mac.finalize().into_bytes().to_vec())
            }};
        }
        let hash = match self.algorithm.as_str() {
            "SHA1" => digest!(sha1::Sha1),
            "SHA256" => digest!(sha2::Sha256),
            "SHA512" => digest!(sha2::Sha512),
            _ => unreachable!(),
        };
        let offset = usize::from(hash[hash.len() - 1] & 0x0f);
        let binary = u32::from_be_bytes(hash[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        Ok(format!(
            "{:0width$}",
            binary % 10u32.pow(self.digits),
            width = self.digits as usize
        ))
    }

    pub fn remaining_at(&self, timestamp: u64) -> u32 {
        self.period
            .saturating_sub((timestamp % u64::from(self.period.max(1))) as u32)
    }
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Deliberately uses only the actual prompt, never shared banner/instructions.
pub(crate) fn is_totp_prompt(prompt: &str, echo: bool) -> bool {
    if echo {
        return false;
    }
    let text = prompt.to_lowercase();
    if [
        "select", "choose", "option", "menu", "选择", "选项", "sms", "email", "e-mail", "短信",
        "邮箱", "邮件",
    ]
    .iter()
    .any(|word| text.contains(word))
    {
        return false;
    }
    let without_otp_password = text
        .replace("one-time password", "")
        .replace("one time password", "")
        .replace("动态密码", "");
    if without_otp_password.contains("password") || without_otp_password.contains("密码") {
        return false;
    }
    [
        "otp",
        "one-time password",
        "one time password",
        "verification code",
        "verification-code",
        "authenticator code",
        "authentication code",
        "passcode",
        "token code",
        "验证码",
        "动态口令",
        "动态密码",
        "动态码",
        "令牌码",
    ]
    .iter()
    .any(|word| text.contains(word))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_all_algorithms_and_timestamps() {
        let times = [
            59,
            1111111109,
            1111111111,
            1234567890,
            2000000000,
            20000000000,
        ];
        for (algorithm, key, expected) in [
            (
                "SHA1",
                "12345678901234567890",
                [
                    "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
                ],
            ),
            (
                "SHA256",
                "12345678901234567890123456789012",
                [
                    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
                ],
            ),
            (
                "SHA512",
                "1234567890123456789012345678901234567890123456789012345678901234",
                [
                    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
                ],
            ),
        ] {
            let profile = MfaProfile::from_input(
                "test".into(),
                "RFC",
                &data_encoding::BASE32_NOPAD.encode(key.as_bytes()),
                algorithm,
                8,
                30,
            )
            .unwrap();
            for (time, expected) in times.into_iter().zip(expected) {
                assert_eq!(profile.code_at(time).unwrap(), expected);
            }
            assert_eq!(profile.remaining_at(59), 1);
            assert_eq!(profile.remaining_at(60), 30);
        }
    }
    #[test]
    fn uri_overrides_parameters_and_rejects_bad_values_without_secret_errors() {
        let uri="otpauth://totp/Example%3Aalice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1";
        let p = MfaProfile::from_input("a".into(), "", uri, "SHA512", 6, 60).unwrap();
        assert_eq!(p.name, "Example:alice");
        assert_eq!(p.code_at(59).unwrap(), "94287082");
        for bad in [
            uri.replace("totp/", "hotp/"),
            format!("{uri}&digits=6"),
            uri.replace("SHA1", "MD5"),
            uri.replace("period=30", "period=0"),
            "NOT_A_SECRET!".into(),
        ] {
            let error = MfaProfile::from_input("a".into(), "test", &bad, "SHA1", 6, 30)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("GEZDG"));
            assert!(!error.contains(&bad));
        }
    }
    #[test]
    fn only_explicit_hidden_otp_prompts_are_automatic() {
        for prompt in [
            "Please enter the mobile app OTP verification code:",
            "Verification code:",
            "One-time password:",
            "请输入动态密码:",
        ] {
            assert!(is_totp_prompt(prompt, false));
            assert!(!is_totp_prompt(prompt, true));
        }
        for prompt in [
            "Password:",
            "Response:",
            "MFA",
            "Password and verification code:",
            "Enter passcode or select one of the options:",
            "SMS verification code:",
            "请输入邮箱验证码:",
        ] {
            assert!(!is_totp_prompt(prompt, false), "{prompt}");
        }
    }
}
