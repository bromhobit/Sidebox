#![cfg_attr(not(target_os = "ios"), allow(dead_code))]

use serde::{Deserialize, Serialize};

pub const DEFAULT_TUNNEL_IP: &str = "10.7.0.1";
pub const DEFAULT_RENEW_BEFORE_HOURS: u64 = 48;
pub const MIN_RENEW_BEFORE_HOURS: u64 = 1;
pub const MAX_RENEW_BEFORE_HOURS: u64 = 168;
pub const DEFAULT_ANISETTE_URL: &str = "https://mac-ani.jkcoxson.com";
pub const MAX_BUNDLE_ID_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppHealth {
    Ok,
    ExpiringSoon,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    pub tunnel_ip: String,
    pub renew_before_hours: u64,
    pub anisette_url: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            tunnel_ip: DEFAULT_TUNNEL_IP.to_string(),
            renew_before_hours: DEFAULT_RENEW_BEFORE_HOURS,
            anisette_url: DEFAULT_ANISETTE_URL.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub exists: bool,
    pub valid: bool,
    pub email_masked: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingSummary {
    pub exists: bool,
    pub valid: bool,
    pub udid: Option<String>,
    pub filename: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppOverview {
    pub session: SessionSummary,
    pub pairing: PairingSummary,
    pub settings: AppSettings,
    pub cached_ipa_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub device_name: String,
    pub product_type: String,
    pub ios_version: String,
    pub udid: String,
    pub profile_count: usize,
    pub user_app_count: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedApp {
    pub name: String,
    pub bundle_id: String,
    pub team_id: String,
    pub expires_at_unix: u64,
    pub hours_remaining: u64,
    pub status: AppHealth,
    pub needs_renewal: bool,
    pub has_cached_ipa: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressUpdate {
    pub stage: String,
    pub percent: u8,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoFactorPrompt {
    pub sms: bool,
    pub retry: bool,
    pub last_error: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwoFactorAnswer {
    Code(String),
    Resend,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallOutcome {
    pub bundle_id: String,
    pub app_name: String,
    pub cached_ipa: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshOutcome {
    pub bundle_id: String,
    pub app_name: String,
    pub method: String,
    pub expires_at_unix: Option<u64>,
    pub hours_remaining: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshAllOutcome {
    pub total: usize,
    pub refreshed: usize,
    pub skipped: usize,
    pub failed: usize,
    pub results: Vec<Result<RefreshOutcome, (String, String)>>,
    pub message: String,
}

pub fn validate_bundle_id(bundle: &str) -> Result<(), String> {
    if bundle.is_empty()
        || bundle.len() > MAX_BUNDLE_ID_LEN
        || !bundle.contains('.')
        || bundle
            .split('.')
            .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    {
        return Err(format!("некорректный bundle ID: {bundle}"));
    }
    Ok(())
}

pub fn validate_settings(
    tunnel_ip: &str,
    renew_before_hours: u64,
    anisette_url: &str,
) -> Result<AppSettings, String> {
    // LocalDevVPN shows addresses in CIDR notation. A socket needs only the
    // host address; keep accepting old plain-IP settings as well.
    let input = tunnel_ip.trim();
    let (address, prefix) = input
        .split_once('/')
        .map_or((input, None), |(address, prefix)| (address, Some(prefix)));
    let invalid_ip =
        || "укажите Device IP из LocalDevVPN, например 10.7.0.1 или 10.7.0.1/32".to_string();
    let ip = address
        .parse::<std::net::IpAddr>()
        .map_err(|_| invalid_ip())?;
    if let Some(prefix) = prefix {
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.parse::<u8>().map_err(|_| invalid_ip())?;
        if prefix > max_prefix {
            return Err(invalid_ip());
        }
    }

    if !(MIN_RENEW_BEFORE_HOURS..=MAX_RENEW_BEFORE_HOURS).contains(&renew_before_hours) {
        return Err(format!(
            "окно продления должно быть от {MIN_RENEW_BEFORE_HOURS} до {MAX_RENEW_BEFORE_HOURS} ч"
        ));
    }

    let url_trimmed = anisette_url.trim();
    let valid_scheme = url_trimmed.starts_with("https://") || url_trimmed.starts_with("http://");
    let host_part = url_trimmed
        .strip_prefix("https://")
        .or_else(|| url_trimmed.strip_prefix("http://"))
        .unwrap_or("");
    if !valid_scheme
        || host_part.is_empty()
        || host_part.starts_with('/')
        || url_trimmed.chars().any(char::is_whitespace)
    {
        return Err(
            "укажите корректный URL сервера Anisette (например, https://mac-ani.jkcoxson.com)"
                .to_string(),
        );
    }

    Ok(AppSettings {
        tunnel_ip: ip.to_string(),
        renew_before_hours,
        anisette_url: url_trimmed.to_string(),
    })
}

pub fn mask_email(email: &str) -> String {
    let trimmed = email.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return "***".to_string();
    };
    let mut chars = local.chars();
    let first = chars.next();
    match (first, chars.next()) {
        (Some(ch), Some(_)) => format!("{ch}***@{domain}"),
        (Some(_), None) => format!("*@{domain}"),
        _ => format!("***@{domain}"),
    }
}

pub fn sanitize_message(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    let normalized = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    for sensitive in [
        "GsIdmsToken",
        "GSIdmsToken",
        "com.apple.gs.idms.pet",
        "X-Apple-Identity-Token",
        "HostPrivateKey",
        "RootPrivateKey",
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
    ] {
        if normalized.contains(sensitive) {
            return "Ошибка безопасности или авторизации (подробности скрыты).".to_string();
        }
    }
    const MAX_CHARS: usize = 360;
    if normalized.chars().count() > MAX_CHARS {
        let truncated: String = normalized.chars().take(MAX_CHARS).collect();
        format!("{truncated}...")
    } else {
        normalized
    }
}

pub fn compute_app_health(
    expires_at_unix: u64,
    now_unix: u64,
    renew_before_hours: u64,
) -> (AppHealth, u64, bool, String) {
    if expires_at_unix <= now_unix {
        return (
            AppHealth::Expired,
            0,
            true,
            "Срок подписи истёк".to_string(),
        );
    }
    let remaining_secs = expires_at_unix - now_unix;
    let hours = remaining_secs / 3600;
    let threshold = now_unix.saturating_add(renew_before_hours.saturating_mul(3600));
    if expires_at_unix <= threshold {
        let msg = if hours == 0 {
            "Скоро истечёт: осталось <1 ч".to_string()
        } else {
            format!("Скоро истечёт: осталось ~{hours} ч")
        };
        (AppHealth::ExpiringSoon, hours, true, msg)
    } else {
        let days = hours / 24;
        let rem_h = hours % 24;
        let msg = if days > 0 {
            format!("Действует ещё ~{days} д {rem_h} ч")
        } else {
            format!("Действует ещё ~{hours} ч")
        };
        (AppHealth::Ok, hours, false, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_validation_rules() {
        let ok = validate_settings(" 10.7.0.1 ", 48, "https://mac-ani.jkcoxson.com").unwrap();
        assert_eq!(ok.tunnel_ip, "10.7.0.1");
        assert_eq!(ok.renew_before_hours, 48);
        assert!(validate_settings("fd00::1", 24, "http://127.0.0.1:6969").is_ok());

        assert!(validate_settings("not-an-ip", 48, "https://mac-ani.jkcoxson.com").is_err());
        assert!(validate_settings("10.7.0.1", 0, "https://mac-ani.jkcoxson.com").is_err());
        assert!(validate_settings("10.7.0.1", 200, "https://mac-ani.jkcoxson.com").is_err());
        assert!(validate_settings("10.7.0.1", 48, "ftp://bad").is_err());
        assert!(validate_settings("10.7.0.1", 48, "https://bad host").is_err());
    }

    #[test]
    fn device_ip_accepts_valid_cidr_but_saves_a_socket_address() {
        let url = "https://mac-ani.jkcoxson.com";
        assert_eq!(
            validate_settings(" 10.7.0.1/32 ", 48, url)
                .unwrap()
                .tunnel_ip,
            "10.7.0.1"
        );
        assert_eq!(
            validate_settings("fd00::1/128", 48, url).unwrap().tunnel_ip,
            "fd00::1"
        );
        for invalid in ["10.7.0.1/33", "10.7.0.1/", "10.7.0.1/32/32", "fd00::1/129"] {
            assert!(
                validate_settings(invalid, 48, url).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn email_masking_and_sanitization() {
        assert_eq!(mask_email("alice@icloud.com"), "a***@icloud.com");
        assert_eq!(mask_email("a@b.ru"), "*@b.ru");
        assert_eq!(mask_email("invalid"), "***");
        assert!(!sanitize_message("err GsIdmsToken=SECRET").contains("SECRET"));
        assert!(!sanitize_message("BEGIN PRIVATE KEY XYZ").contains("XYZ"));
    }

    #[test]
    fn health_computation_handles_ok_soon_and_expired() {
        let now = 1_760_000_000;
        let (h1, hrs1, need1, _) = compute_app_health(now + 100 * 3600, now, 48);
        assert_eq!(h1, AppHealth::Ok);
        assert_eq!(hrs1, 100);
        assert!(!need1);

        let (h2, hrs2, need2, _) = compute_app_health(now + 12 * 3600, now, 48);
        assert_eq!(h2, AppHealth::ExpiringSoon);
        assert_eq!(hrs2, 12);
        assert!(need2);

        let (h3, hrs3, need3, _) = compute_app_health(now - 10, now, 48);
        assert_eq!(h3, AppHealth::Expired);
        assert_eq!(hrs3, 0);
        assert!(need3);
    }
}
