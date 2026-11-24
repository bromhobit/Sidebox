#![cfg_attr(not(target_os = "ios"), allow(dead_code))]

use crate::{
    heartbeat::{device_error_detail, with_heartbeat},
    models::{
        AppHealth, AppOverview, AppSettings, InstallOutcome, PairingSummary, ProgressUpdate,
        RefreshAllOutcome, RefreshOutcome, TrackedApp, TunnelStatus, TwoFactorAnswer,
        TwoFactorPrompt, compute_app_health, sanitize_message, validate_bundle_id,
        validate_settings,
    },
    storage::SandboxStorage,
};
use apple_codesign_quick::ProvisioningProfile;
use idevice::{
    IdeviceService, installation_proxy::InstallationProxyClient, lockdown::LockdownClient,
    misagent::MisagentClient, pairing_file::PairingFile, provider::TcpProvider,
};
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        developer_session::{AppIdsApi, DeveloperDeviceType, DeveloperSession, TeamsApi},
        devices::DevicesApi,
    },
    sideload::{
        SideloaderBuilder, TeamSelection,
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
    },
    util::{
        callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
        device::IdeviceInfo,
    },
};
use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Once,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

const TUNNEL_TIMEOUT: Duration = Duration::from_secs(8);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_PROFILE_BYTES: usize = 8 * 1024 * 1024;

static INIT_ONCE: Once = Once::new();

fn ensure_global_init() -> Result<(), String> {
    let mut init_err: Option<String> = None;
    INIT_ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        if isideload::init().is_err() {
            init_err = Some("не удалось инициализировать модуль подписи isideload".to_string());
        }
    });
    if let Some(err) = init_err {
        return Err(err);
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct SideboxEngine {
    storage: SandboxStorage,
    runtime: tokio::runtime::Runtime,
    op_lock: Mutex<()>,
}

impl SideboxEngine {
    pub fn new(documents_dir: PathBuf) -> Result<Self, String> {
        ensure_global_init()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("sidebox-rt")
            .enable_all()
            .build()
            .map_err(|_| "не удалось запустить внутренний async-движок Sidebox".to_string())?;
        let storage = SandboxStorage::new(documents_dir);
        let _ = storage.ensure_documents_dir();
        Ok(Self {
            storage,
            runtime,
            op_lock: Mutex::new(()),
        })
    }

    pub fn get_overview(&self) -> AppOverview {
        AppOverview {
            session: self.storage.inspect_session(),
            pairing: self.storage.inspect_pairing(),
            settings: self.storage.load_settings(),
            cached_ipa_count: self.storage.count_cached_ipas(),
        }
    }

    pub fn save_settings(
        &self,
        tunnel_ip: &str,
        renew_before_hours: u64,
        anisette_url: &str,
    ) -> Result<AppSettings, String> {
        let validated = validate_settings(tunnel_ip, renew_before_hours, anisette_url)?;
        self.storage.save_settings(&validated)?;
        Ok(validated)
    }

    pub fn import_pairing_file(&self, source_path: &Path) -> Result<PairingSummary, String> {
        self.storage.import_pairing_file(source_path)
    }

    pub fn logout_apple(&self) -> Result<(), String> {
        self.storage.delete_session()
    }

    pub fn test_tunnel(&self) -> Result<TunnelStatus, String> {
        let _guard = self
            .op_lock
            .lock()
            .map_err(|_| "внутренняя ошибка блокировки".to_string())?;
        let (provider, settings, pairing) = self.build_tcp_provider()?;
        let tunnel_ip = settings.tunnel_ip.clone();
        self.runtime.block_on(async move {
          with_heartbeat(&provider, async {
            let mut lockdown = tokio::time::timeout(TUNNEL_TIMEOUT, LockdownClient::connect(&provider))
                .await
                .map_err(|_| tunnel_help_error(&tunnel_ip, "таймаут подключения к lockdownd"))?
                .map_err(|e| tunnel_help_error(&tunnel_ip, &device_error_detail(&e)))?;

            tokio::time::timeout(TUNNEL_TIMEOUT, lockdown.start_session(&pairing))
                .await
                .map_err(|_| tunnel_help_error(&tunnel_ip, "таймаут TLS-сессии lockdown"))?
                .map_err(|e| {
                    format!(
                        "Не удалось начать сеанс iPhone ({}). Проверьте связь и pairing-файл.",
                        sanitize_message(&device_error_detail(&e))
                    )
                })?;

            let device_name = lockdown_string(&mut lockdown, "DeviceName")
                .await
                .unwrap_or_else(|| "iPhone".to_string());
            let product_type = lockdown_string(&mut lockdown, "ProductType")
                .await
                .unwrap_or_default();
            let ios_version = lockdown_string(&mut lockdown, "ProductVersion")
                .await
                .unwrap_or_default();
            let udid = lockdown_string(&mut lockdown, "UniqueDeviceID")
                .await
                .or_else(|| pairing.udid.clone())
                .unwrap_or_default();
            drop(lockdown);
            // A connected lockdown socket is not enough: verify the actual
            // services used by the home screen instead of treating errors as 0.
            let profile_count = read_device_profiles(&provider, &tunnel_ip).await?.len();
            let user_app_count = fetch_user_apps(&provider).await?.len();

            let message = format!(
                "Связь OK: {device_name} (iOS {ios_version}) · профилей: {profile_count}, приложений: {user_app_count}"
            );
            Ok(TunnelStatus {
                device_name,
                product_type,
                ios_version,
                udid,
                profile_count,
                user_app_count,
                message,
            })
          }).await
        })
    }

    pub fn list_apps(&self) -> Result<Vec<TrackedApp>, String> {
        let _guard = self
            .op_lock
            .lock()
            .map_err(|_| "внутренняя ошибка блокировки".to_string())?;
        let (provider, settings, _pairing) = self.build_tcp_provider()?;
        let tunnel_ip = settings.tunnel_ip.clone();
        let renew_hours = settings.renew_before_hours;
        let storage = self.storage.clone();

        self.runtime.block_on(async move {
            with_heartbeat(&provider, async {
                let profiles = read_device_profiles(&provider, &tunnel_ip).await?;
                let user_apps = fetch_user_apps(&provider).await.ok();
                let now = now_unix();
                Ok(correlate_tracked_apps(
                    &profiles,
                    user_apps.as_ref(),
                    &storage,
                    now,
                    renew_hours,
                ))
            })
            .await
        })
    }

    pub fn login_apple<F>(
        &self,
        email: &str,
        mut password: String,
        two_fa_provider: F,
    ) -> Result<String, String>
    where
        F: Fn(TwoFactorPrompt) -> TwoFactorAnswer + Send + Sync + 'static,
    {
        let email_trimmed = email.trim().to_string();
        if email_trimmed.is_empty() || !email_trimmed.contains('@') {
            password.zeroize();
            return Err("укажите корректный адрес Apple ID".into());
        }
        if password.is_empty() {
            return Err("введите пароль Apple ID".into());
        }

        let _guard = self
            .op_lock
            .lock()
            .map_err(|_| "внутренняя ошибка блокировки".to_string())?;
        let settings = self.storage.load_settings();
        let storage = self.storage.clone();
        let provider_fn = Arc::new(two_fa_provider);

        let res = self.runtime.block_on(async move {
            let mut account = build_apple_account(&storage, &settings.anisette_url, &email_trimmed).await?;
            let unknown_attempts = Arc::new(AtomicUsize::new(0));
            let login_res = account
                .login(&password, move |params: TwoFactorCallbackParams| {
                    let cb = Arc::clone(&provider_fn);
                    let unknown_count = Arc::clone(&unknown_attempts);
                    async move {
                        if params.unknown {
                            let tries = unknown_count.fetch_add(1, Ordering::Relaxed);
                            if tries == 0 {
                                return Ok(TwoFactorCallbackResponse::SendToDevices);
                            }
                            if let Some(num) = params.numbers.first() {
                                return Ok(TwoFactorCallbackResponse::SendSms(num.id));
                            }
                            return Ok(TwoFactorCallbackResponse::Abort);
                        }

                        let retry = params.last_error.is_some();
                        let msg = if retry {
                            "Неверный код. Введите 6-значный код подтверждения Apple ID ещё раз:"
                        } else if params.sms {
                            "Введите 6-значный код подтверждения Apple ID из SMS:"
                        } else {
                            "Введите 6-значный код подтверждения Apple ID (отправлен на устройства):"
                        };
                        let prompt = TwoFactorPrompt {
                            sms: params.sms,
                            retry,
                            last_error: params.last_error.map(|s| sanitize_message(&s)),
                            message: msg.to_string(),
                        };

                        let answer = tokio::task::spawn_blocking(move || cb(prompt))
                            .await
                            .unwrap_or(TwoFactorAnswer::Cancel);

                        match answer {
                            TwoFactorAnswer::Code(mut code) => {
                                let trimmed = code.trim().to_string();
                                code.zeroize();
                                if trimmed.is_empty() {
                                    Ok(TwoFactorCallbackResponse::Abort)
                                } else {
                                    Ok(TwoFactorCallbackResponse::SubmitCode(trimmed))
                                }
                            }
                            TwoFactorAnswer::Resend => Ok(TwoFactorCallbackResponse::ResendCode),
                            TwoFactorAnswer::Cancel => Ok(TwoFactorCallbackResponse::Abort),
                        }
                    }
                })
                .await;

            password.zeroize();
            login_res.map_err(|e| {
                format!(
                    "не удалось войти в Apple ID: {}",
                    sanitize_message(&e.to_string())
                )
            })?;

            let spd = account
                .spd
                .as_ref()
                .ok_or_else(|| "Apple не вернула данные сессии (SPD)".to_string())?;
            storage.save_session(&email_trimmed, spd)
        });
        res
    }

    pub fn install_ipa<F>(&self, ipa_path: &Path, progress_cb: F) -> Result<InstallOutcome, String>
    where
        F: Fn(ProgressUpdate) + Send + Sync + 'static,
    {
        let _guard = self
            .op_lock
            .lock()
            .map_err(|_| "внутренняя ошибка блокировки".to_string())?;
        let (provider, settings, pairing) = self.build_tcp_provider()?;
        let storage = self.storage.clone();
        let ipa_owned = ipa_path.to_path_buf();
        let cb: Arc<dyn Fn(ProgressUpdate) + Send + Sync> = Arc::new(progress_cb);

        self.runtime.block_on(with_heartbeat(
            &provider,
            install_ipa_async(
                &provider, &settings, &pairing, &storage, &ipa_owned, cb, true,
            ),
        ))
    }

    pub fn refresh_app<F>(&self, bundle_id: &str, progress_cb: F) -> Result<RefreshOutcome, String>
    where
        F: Fn(ProgressUpdate) + Send + Sync + 'static,
    {
        validate_bundle_id(bundle_id)?;
        let _guard = self
            .op_lock
            .lock()
            .map_err(|_| "внутренняя ошибка блокировки".to_string())?;
        let (provider, settings, pairing) = self.build_tcp_provider()?;
        let storage = self.storage.clone();
        let bundle_owned = bundle_id.to_string();
        let cb: Arc<dyn Fn(ProgressUpdate) + Send + Sync> = Arc::new(progress_cb);

        self.runtime.block_on(with_heartbeat(
            &provider,
            refresh_app_async(&provider, &settings, &pairing, &storage, &bundle_owned, cb),
        ))
    }

    pub fn refresh_all<F>(&self, progress_cb: F) -> Result<RefreshAllOutcome, String>
    where
        F: Fn(ProgressUpdate) + Send + Sync + 'static,
    {
        let _guard = self
            .op_lock
            .lock()
            .map_err(|_| "внутренняя ошибка блокировки".to_string())?;
        let (provider, settings, pairing) = self.build_tcp_provider()?;
        let storage = self.storage.clone();
        let cb: Arc<dyn Fn(ProgressUpdate) + Send + Sync> = Arc::new(progress_cb);

        self.runtime.block_on(async move {
            with_heartbeat(&provider, async {
                emit_progress(&cb, "connecting", 5, "Поиск установленных приложений...");
                let profiles = read_device_profiles(&provider, &settings.tunnel_ip).await?;
                let user_apps = fetch_user_apps(&provider).await.ok();
                let apps = correlate_tracked_apps(
                    &profiles,
                    user_apps.as_ref(),
                    &storage,
                    now_unix(),
                    settings.renew_before_hours,
                );
                let total = apps.len();
                if total == 0 {
                    return Ok(RefreshAllOutcome {
                        total: 0,
                        refreshed: 0,
                        skipped: 0,
                        failed: 0,
                        results: Vec::new(),
                        message: "Установленные приложения с профилями подписи не найдены."
                            .to_string(),
                    });
                }

                let mut results = Vec::with_capacity(total);
                let mut refreshed = 0usize;
                let mut failed = 0usize;
                for (idx, app) in apps.iter().enumerate() {
                    let app_name = app.name.clone();
                    let bundle_id = app.bundle_id.clone();
                    let base_pct = 10 + ((idx * 85) / total) as u8;
                    let span_pct = (85 / total).max(1) as u8;
                    let outer_cb = Arc::clone(&cb);
                    let inner_cb: Arc<dyn Fn(ProgressUpdate) + Send + Sync> = Arc::new(move |u| {
                        let mapped = base_pct
                            .saturating_add(((u.percent as u16 * span_pct as u16) / 100) as u8)
                            .min(99);
                        emit_progress(
                            &outer_cb,
                            &u.stage,
                            mapped,
                            &format!("[{}/{}] {}: {}", idx + 1, total, app_name, u.message),
                        );
                    });
                    match refresh_app_async(
                        &provider, &settings, &pairing, &storage, &bundle_id, inner_cb,
                    )
                    .await
                    {
                        Ok(ok) => {
                            refreshed += 1;
                            results.push(Ok(ok));
                        }
                        Err(err) => {
                            failed += 1;
                            results.push(Err((bundle_id, err)));
                        }
                    }
                }

                emit_progress(&cb, "done", 100, "Обновление завершено.");
                let message = if failed == 0 {
                    format!("Продлено приложений: {refreshed} из {total}.")
                } else {
                    format!("Продлено: {refreshed}, с ошибкой: {failed} (всего {total}).")
                };
                Ok(RefreshAllOutcome {
                    total,
                    refreshed,
                    skipped: 0,
                    failed,
                    results,
                    message,
                })
            })
            .await
        })
    }

    fn build_tcp_provider(&self) -> Result<(TcpProvider, AppSettings, PairingFile), String> {
        let settings = self.storage.load_settings();
        let addr: IpAddr = settings.tunnel_ip.parse().map_err(|_| {
            format!(
                "некорректный IP VPN-туннеля в настройках: {}",
                settings.tunnel_ip
            )
        })?;
        let pairing = self.storage.load_pairing_file()?;
        let provider = TcpProvider {
            addr,
            scope_id: None,
            pairing_file: pairing.clone(),
            label: "Sidebox".to_string(),
        };
        Ok((provider, settings, pairing))
    }
}

fn emit_progress(
    cb: &Arc<dyn Fn(ProgressUpdate) + Send + Sync>,
    stage: &str,
    percent: u8,
    message: &str,
) {
    cb(ProgressUpdate {
        stage: stage.to_string(),
        percent: percent.min(100),
        message: sanitize_message(message),
    });
}

fn tunnel_help_error(tunnel_ip: &str, detail: &str) -> String {
    format!(
        "Нет связи с устройством {tunnel_ip}:62078 ({}). Включите LocalDevVPN и проверьте Device IP и pairing-файл.",
        sanitize_message(detail)
    )
}

async fn lockdown_string(lockdown: &mut LockdownClient, key: &str) -> Option<String> {
    tokio::time::timeout(TUNNEL_TIMEOUT, lockdown.get_value(Some(key), None))
        .await
        .ok()?
        .ok()?
        .as_string()
        .map(ToOwned::to_owned)
}

async fn build_apple_account(
    storage: &SandboxStorage,
    anisette_url: &str,
    email: &str,
) -> Result<AppleAccount, String> {
    let provider = RemoteV3AnisetteProvider::default()
        .map_err(|_| "не удалось инициализировать Anisette".to_string())?
        .set_url(anisette_url)
        .set_storage(Box::new(storage.isideload_storage()));
    AppleAccount::builder(email)
        .anisette_provider(provider)
        .build()
        .await
        .map_err(|e| {
            format!(
                "не удалось подключиться к Apple ID: {}",
                sanitize_message(&e.to_string())
            )
        })
}

async fn load_saved_apple_account(
    storage: &SandboxStorage,
    anisette_url: &str,
) -> Result<(AppleAccount, String), String> {
    let (email, spd) = storage.load_session()?;
    let mut account = build_apple_account(storage, anisette_url, &email).await?;
    account.spd = Some(spd);
    Ok((account, email))
}

async fn read_device_profiles(
    provider: &TcpProvider,
    tunnel_ip: &str,
) -> Result<Vec<plist::Dictionary>, String> {
    let mut misagent = tokio::time::timeout(SERVICE_TIMEOUT, MisagentClient::connect(provider))
        .await
        .map_err(|_| format!("Таймаут подключения к службе профилей через {tunnel_ip}."))?
        .map_err(|e| {
            format!(
                "Не удалось открыть службу профилей через {tunnel_ip}: {}",
                sanitize_message(&device_error_detail(&e))
            )
        })?;

    let raw_profiles = tokio::time::timeout(SERVICE_TIMEOUT, misagent.copy_all())
        .await
        .map_err(|_| "таймаут чтения профилей подписи (misagent)".to_string())?
        .map_err(|e| {
            format!(
                "не удалось получить профили подписи: {}",
                sanitize_message(&device_error_detail(&e))
            )
        })?;

    let mut out = Vec::new();
    for blob in &raw_profiles {
        if let Ok(dict) = parse_cms_profile_dict(blob) {
            out.push(dict);
        }
    }
    Ok(out)
}

async fn fetch_user_apps(provider: &TcpProvider) -> Result<HashMap<String, plist::Value>, String> {
    let mut inst =
        tokio::time::timeout(SERVICE_TIMEOUT, InstallationProxyClient::connect(provider))
            .await
            .map_err(|_| "таймаут подключения к installation_proxy".to_string())?
            .map_err(|e| {
                format!(
                    "Не удалось открыть службу приложений: {}",
                    sanitize_message(&device_error_detail(&e))
                )
            })?;
    tokio::time::timeout(SERVICE_TIMEOUT, inst.get_apps(Some("User"), None))
        .await
        .map_err(|_| "таймаут чтения списка приложений".to_string())?
        .map_err(|e| {
            format!(
                "Не удалось получить список приложений: {}",
                sanitize_message(&device_error_detail(&e))
            )
        })
}

struct SignedBundleCleanup {
    temp_dir_to_remove: Option<PathBuf>,
}

fn safe_extracted_temp_dir(input_is_file: bool, signed_app_dir: &Path) -> Option<PathBuf> {
    if !input_is_file {
        return None;
    }
    let tmp_root = fs::canonicalize(std::env::temp_dir()).ok()?;
    let canon_app = fs::canonicalize(signed_app_dir).ok()?;
    if !canon_app.starts_with(&tmp_root) || canon_app == tmp_root {
        return None;
    }
    if let Some(payload_dir) = canon_app.parent() {
        if payload_dir.file_name().and_then(|s| s.to_str()) == Some("Payload") {
            if let Some(extracted_dir) = payload_dir.parent() {
                if extracted_dir.parent() == Some(tmp_root.as_path())
                    && extracted_dir
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|n| n.ends_with("_extracted"))
                {
                    return Some(extracted_dir.to_path_buf());
                }
            }
        }
    }
    Some(canon_app)
}

impl SignedBundleCleanup {
    fn new(input_is_file: bool, signed_app_dir: &Path) -> Self {
        Self {
            temp_dir_to_remove: safe_extracted_temp_dir(input_is_file, signed_app_dir),
        }
    }
}

impl Drop for SignedBundleCleanup {
    fn drop(&mut self) {
        if let Some(ref dir) = self.temp_dir_to_remove {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

fn read_signed_bundle_metadata(app_dir: &Path) -> (Option<String>, Option<String>) {
    let Ok(dict) = plist::from_file::<_, plist::Dictionary>(app_dir.join("Info.plist")) else {
        return (None, None);
    };
    let bundle_id = dict
        .get("CFBundleIdentifier")
        .and_then(plist::Value::as_string)
        .map(ToOwned::to_owned);
    let app_name = dict
        .get("CFBundleDisplayName")
        .or_else(|| dict.get("CFBundleName"))
        .and_then(plist::Value::as_string)
        .map(ToOwned::to_owned);
    (bundle_id, app_name)
}

async fn install_ipa_async(
    provider: &TcpProvider,
    settings: &AppSettings,
    pairing: &PairingFile,
    storage: &SandboxStorage,
    ipa_path: &Path,
    cb: Arc<dyn Fn(ProgressUpdate) + Send + Sync>,
    cache_after_install: bool,
) -> Result<InstallOutcome, String> {
    let ipa_meta =
        fs::metadata(ipa_path).map_err(|_| "выбранный .ipa файл недоступен".to_string())?;
    if !ipa_meta.is_file() || ipa_meta.len() == 0 {
        return Err("выберите корректный непустой .ipa файл".into());
    }

    emit_progress(&cb, "connecting", 5, "Подключение к VPN-туннелю...");
    let device_info = tokio::time::timeout(SERVICE_TIMEOUT, IdeviceInfo::from_device(provider))
        .await
        .map_err(|_| tunnel_help_error(&settings.tunnel_ip, "таймаут подключения к iPhone"))?
        .map_err(|e| tunnel_help_error(&settings.tunnel_ip, &e.to_string()))?;

    let mut pairing_bytes = pairing.clone().serialize().ok();

    emit_progress(&cb, "authenticating", 15, "Вход в Apple ID...");
    let (mut account, email) = load_saved_apple_account(storage, &settings.anisette_url).await?;
    let dev_session = DeveloperSession::from_account(&mut account)
        .await
        .map_err(|_| {
            "сессия Apple ID истекла или недоступна — войдите заново в Настройках".to_string()
        })?;

    let mut sideloader =
        SideloaderBuilder::<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>::new(
            dev_session,
            email,
        )
        .storage(Box::new(storage.isideload_storage()))
        .machine_name("Sidebox".to_string())
        .team_selection(TeamSelection::First)
        .max_certs_behavior(MaxCertsBehavior::Error)
        .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
            ExtensionsBehavior::RegisterAll,
        ))
        .delete_app_after_install(true)
        .build();

    let team = sideloader.get_team().await.map_err(|e| {
        format!(
            "не удалось получить команду Apple Developer: {}",
            sanitize_message(&e.to_string())
        )
    })?;
    sideloader
        .get_dev_session()
        .ensure_device_registered(&team, &device_info.name, &device_info.udid, None)
        .await
        .map_err(|e| {
            format!(
                "не удалось зарегистрировать iPhone в Apple Developer: {}",
                sanitize_message(&e.to_string())
            )
        })?;

    emit_progress(&cb, "signing", 25, "Подпись IPA...");
    let sign_cb = Arc::clone(&cb);
    let sign_res = sideloader
        .sign_app(
            ipa_path.to_path_buf(),
            Some(team),
            false,
            Some(move |frac: f32| {
                let inner = Arc::clone(&sign_cb);
                async move {
                    let pct = 25u8
                        .saturating_add((frac.clamp(0.0, 1.0) * 35.0).round() as u8)
                        .min(60);
                    emit_progress(&inner, "signing", pct, "Подпись IPA и расширений...");
                }
            }),
            pairing_bytes.as_deref(),
            Some(&device_info.udid),
        )
        .await;

    if let Some(ref mut bytes) = pairing_bytes {
        bytes.zeroize();
    }

    let (signed_app_path, _special) = sign_res.map_err(|e| {
        let raw = e.to_string();
        if raw.contains("7460") || raw.contains("Maximum number of certificates") {
            "достигнут лимит сертификатов Apple Developer (отзовите старый сертификат или переподпишите через Boxloader)".to_string()
        } else {
            format!("ошибка подписи IPA: {}", sanitize_message(&raw))
        }
    })?;

    let _cleanup = SignedBundleCleanup::new(true, &signed_app_path);
    let (bundle_id_opt, app_name_opt) = read_signed_bundle_metadata(&signed_app_path);
    let bundle_id = bundle_id_opt.unwrap_or_else(|| "unknown.bundle".to_string());
    let app_name = app_name_opt.unwrap_or_else(|| derive_name_from_bundle(&bundle_id, ""));

    emit_progress(&cb, "uploading", 60, "Загрузка на iPhone...");
    let install_cb = Arc::clone(&cb);
    isideload::sideload::install::install_app(provider, &signed_app_path, move |pct| {
        if pct <= 70 {
            let mapped = 60u8.saturating_add(((pct * 28) / 70) as u8).min(88);
            emit_progress(&install_cb, "uploading", mapped, "Загрузка на iPhone...");
        } else {
            let part = pct.saturating_sub(70).min(30);
            let mapped = 88u8.saturating_add(((part * 11) / 30) as u8).min(99);
            emit_progress(&install_cb, "installing", mapped, "Установка...");
        }
    })
    .await
    .map_err(|e| {
        format!(
            "ошибка установки на iPhone: {}",
            sanitize_message(&e.to_string())
        )
    })?;

    let cached_ipa = if cache_after_install && validate_bundle_id(&bundle_id).is_ok() {
        storage.cache_ipa(&bundle_id, ipa_path).is_ok()
    } else {
        storage.cached_ipa_path(&bundle_id).is_some()
    };

    emit_progress(&cb, "done", 100, &format!("{app_name} установлено!"));
    Ok(InstallOutcome {
        bundle_id,
        app_name: app_name.clone(),
        cached_ipa,
        message: format!("Приложение {app_name} успешно установлено."),
    })
}

async fn refresh_app_async(
    provider: &TcpProvider,
    settings: &AppSettings,
    pairing: &PairingFile,
    storage: &SandboxStorage,
    bundle_id: &str,
    cb: Arc<dyn Fn(ProgressUpdate) + Send + Sync>,
) -> Result<RefreshOutcome, String> {
    match fast_profile_refresh(
        provider,
        settings,
        pairing,
        storage,
        bundle_id,
        Arc::clone(&cb),
    )
    .await
    {
        Ok(outcome) => Ok(outcome),
        Err(fast_err) => {
            if let Some(cached_ipa) = storage.cached_ipa_path(bundle_id) {
                emit_progress(
                    &cb,
                    "signing",
                    20,
                    "Быстрое обновление профиля недоступно — переподпись локального IPA...",
                );
                let install =
                    install_ipa_async(provider, settings, pairing, storage, &cached_ipa, cb, false)
                        .await?;
                Ok(RefreshOutcome {
                    bundle_id: install.bundle_id,
                    app_name: install.app_name.clone(),
                    method: "reinstall".to_string(),
                    expires_at_unix: None,
                    hours_remaining: Some(168),
                    message: format!("Приложение {} переподписано и обновлено.", install.app_name),
                })
            } else {
                Err(fast_err)
            }
        }
    }
}

async fn fast_profile_refresh(
    provider: &TcpProvider,
    settings: &AppSettings,
    pairing: &PairingFile,
    storage: &SandboxStorage,
    bundle_id: &str,
    cb: Arc<dyn Fn(ProgressUpdate) + Send + Sync>,
) -> Result<RefreshOutcome, String> {
    emit_progress(&cb, "connecting", 10, "Подключение к VPN-туннелю...");
    let device_udid =
        match tokio::time::timeout(TUNNEL_TIMEOUT, IdeviceInfo::from_device(provider)).await {
            Ok(Ok(info)) => info.udid,
            _ => pairing
                .udid
                .clone()
                .filter(|u| !u.is_empty())
                .ok_or_else(|| {
                    tunnel_help_error(&settings.tunnel_ip, "не удалось определить UDID устройства")
                })?,
        };

    let current_profiles = read_device_profiles(provider, &settings.tunnel_ip).await?;
    let old_profile = find_newest_matching_profile(&current_profiles, bundle_id)
        .ok_or_else(|| format!("активный профиль для {bundle_id} не найден на устройстве"))?
        .clone();
    let team_id = profile_team_id(&old_profile)
        .ok_or_else(|| "не удалось определить Team ID из установленного профиля".to_string())?;
    let app_name = resolve_app_display_name(&old_profile, None, bundle_id, &team_id);

    emit_progress(
        &cb,
        "authenticating",
        30,
        "Вход в Apple ID и запрос профиля...",
    );
    let (mut account, _email) = load_saved_apple_account(storage, &settings.anisette_url).await?;
    let mut session = DeveloperSession::from_account(&mut account)
        .await
        .map_err(|_| "сессия Apple ID истекла — войдите заново в Настройках".to_string())?;

    let team = session
        .list_teams()
        .await
        .map_err(|e| {
            format!(
                "не удалось получить список команд Apple Developer: {}",
                sanitize_message(&e.to_string())
            )
        })?
        .into_iter()
        .find(|t| t.team_id == team_id)
        .ok_or_else(|| format!("команда {team_id} не найдена в аккаунте Apple ID"))?;

    let app_id = session
        .list_app_ids(&team, DeveloperDeviceType::Ios)
        .await
        .map_err(|e| {
            format!(
                "не удалось получить список App ID: {}",
                sanitize_message(&e.to_string())
            )
        })?
        .app_ids
        .into_iter()
        .find(|a| a.identifier == bundle_id)
        .ok_or_else(|| format!("App ID {bundle_id} не зарегистрирован в команде {team_id}"))?;

    emit_progress(&cb, "signing", 55, "Проверка нового профиля подписи...");
    let fresh = session
        .download_team_provisioning_profile(&team, &app_id, DeveloperDeviceType::Ios)
        .await
        .map_err(|e| {
            format!(
                "Apple не выдала новый профиль: {}",
                sanitize_message(&e.to_string())
            )
        })?;
    let new_bytes: Vec<u8> = fresh.encoded_profile.into();
    let new_dict = parse_cms_profile_dict(&new_bytes)?;
    let now = now_unix();
    let expected_expiry = check_replacement_compatible(
        &old_profile,
        &new_dict,
        &team_id,
        bundle_id,
        &device_udid,
        now,
    )?;

    emit_progress(
        &cb,
        "installing",
        80,
        "Установка нового профиля на iPhone...",
    );
    let mut misagent = tokio::time::timeout(SERVICE_TIMEOUT, MisagentClient::connect(provider))
        .await
        .map_err(|_| "Таймаут подключения к службе профилей.".to_string())?
        .map_err(|e| {
            format!(
                "Не удалось открыть службу профилей: {}",
                sanitize_message(&device_error_detail(&e))
            )
        })?;
    tokio::time::timeout(SERVICE_TIMEOUT, misagent.install(new_bytes))
        .await
        .map_err(|_| "таймаут установки профиля".to_string())?
        .map_err(|e| {
            format!(
                "iOS отклонила профиль: {}",
                sanitize_message(&e.to_string())
            )
        })?;

    emit_progress(
        &cb,
        "installing",
        92,
        "Подтверждение применённого профиля...",
    );
    let after_profiles = read_device_profiles(provider, &settings.tunnel_ip).await?;
    let installed = find_newest_matching_profile(&after_profiles, bundle_id)
        .ok_or_else(|| "не удалось прочитать профиль после установки".to_string())?;
    let installed_expiry = check_replacement_compatible(
        &old_profile,
        installed,
        &team_id,
        bundle_id,
        &device_udid,
        now,
    )?;
    if installed_expiry < expected_expiry || installed != &new_dict {
        return Err("iOS не подтвердила замену профиля".into());
    }

    let hours_remaining = installed_expiry.saturating_sub(now_unix()) / 3600;
    emit_progress(&cb, "done", 100, "Профиль продлён!");
    Ok(RefreshOutcome {
        bundle_id: bundle_id.to_string(),
        app_name: app_name.clone(),
        method: "profile".to_string(),
        expires_at_unix: Some(installed_expiry),
        hours_remaining: Some(hours_remaining),
        message: format!("Подпись {app_name} продлена (~{hours_remaining} ч)."),
    })
}

pub fn parse_cms_profile_dict(bytes: &[u8]) -> Result<plist::Dictionary, String> {
    if bytes.is_empty() || bytes.len() > MAX_PROFILE_BYTES {
        return Err("недопустимый размер профиля подписи".into());
    }
    let parsed = ProvisioningProfile::parse(bytes)
        .map_err(|e| format!("не удалось разобрать CMS-профиль: {e}"))?;
    Ok(parsed.plist().clone())
}

fn profile_application_identifier(profile: &plist::Dictionary) -> Option<&str> {
    profile
        .get("Entitlements")
        .and_then(plist::Value::as_dictionary)
        .and_then(|e| e.get("application-identifier"))
        .and_then(plist::Value::as_string)
}

fn profile_bundle_id(profile: &plist::Dictionary) -> Option<String> {
    let app_id = profile_application_identifier(profile)?;
    if app_id.contains('*') {
        return None;
    }
    let (prefix, suffix) = app_id.split_once('.')?;
    if prefix.is_empty() || suffix.is_empty() {
        return None;
    }
    Some(suffix.to_string())
}

fn profile_team_id(profile: &plist::Dictionary) -> Option<String> {
    profile
        .get("TeamIdentifier")
        .and_then(plist::Value::as_array)
        .and_then(|arr| arr.iter().find_map(plist::Value::as_string))
        .map(ToOwned::to_owned)
        .or_else(|| {
            profile_application_identifier(profile)
                .and_then(|id| id.split_once('.'))
                .map(|(prefix, _)| prefix.to_string())
                .filter(|p| !p.is_empty())
        })
}

fn profile_expiration_unix(profile: &plist::Dictionary) -> Result<u64, String> {
    let date = profile
        .get("ExpirationDate")
        .and_then(plist::Value::as_date)
        .ok_or("в профиле отсутствует ExpirationDate")?;
    SystemTime::from(date)
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "некорректная дата ExpirationDate".into())
}

fn profile_creation_unix(profile: &plist::Dictionary) -> u64 {
    profile
        .get("CreationDate")
        .and_then(plist::Value::as_date)
        .and_then(|d| SystemTime::from(d).duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn find_newest_matching_profile<'a>(
    profiles: &'a [plist::Dictionary],
    bundle_id: &str,
) -> Option<&'a plist::Dictionary> {
    profiles
        .iter()
        .filter(|p| {
            profile_bundle_id(p).as_deref() == Some(bundle_id) && profile_expiration_unix(p).is_ok()
        })
        .max_by_key(|p| {
            (
                profile_expiration_unix(p).unwrap_or(0),
                profile_creation_unix(p),
            )
        })
}

fn non_empty_array<'a>(
    profile: &'a plist::Dictionary,
    key: &str,
) -> Result<&'a [plist::Value], String> {
    profile
        .get(key)
        .and_then(plist::Value::as_array)
        .map(Vec::as_slice)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| format!("в профиле отсутствует {key}"))
}

pub fn check_replacement_compatible(
    old: &plist::Dictionary,
    new: &plist::Dictionary,
    team: &str,
    bundle: &str,
    device_udid: &str,
    now: u64,
) -> Result<u64, String> {
    fn entitlements(p: &plist::Dictionary) -> Result<&plist::Dictionary, String> {
        p.get("Entitlements")
            .and_then(plist::Value::as_dictionary)
            .ok_or_else(|| "в профиле отсутствуют Entitlements".to_string())
    }
    let old_ent = entitlements(old)?;
    let new_ent = entitlements(new)?;
    if profile_bundle_id(old).as_deref() != Some(bundle) || old_ent != new_ent {
        return Err("идентификатор приложения или entitlements не совпадают".into());
    }
    let old_teams = non_empty_array(old, "TeamIdentifier")?;
    let new_teams = non_empty_array(new, "TeamIdentifier")?;
    if old_teams != new_teams || !old_teams.iter().any(|x| x.as_string() == Some(team)) {
        return Err("TeamIdentifier нового профиля не совпадает".into());
    }
    for p in [old, new] {
        if !non_empty_array(p, "ProvisionedDevices")?.iter().any(|x| {
            x.as_string()
                .is_some_and(|id| id.eq_ignore_ascii_case(device_udid))
        }) {
            return Err("профиль не включает этот iPhone".into());
        }
    }
    let new_certs = non_empty_array(new, "DeveloperCertificates")?;
    if !non_empty_array(old, "DeveloperCertificates")?
        .iter()
        .all(|c| c.as_data().is_some() && new_certs.contains(c))
    {
        return Err("сертификат подписи в новом профиле отличается".into());
    }
    let old_exp = profile_expiration_unix(old)?;
    let new_exp = profile_expiration_unix(new)?;
    if new_exp <= old_exp || new_exp <= now {
        return Err("Apple не продлила срок действия профиля".into());
    }
    Ok(new_exp)
}

fn looks_like_team_suffix(segment: &str, team: &str) -> bool {
    if !team.is_empty() && segment.eq_ignore_ascii_case(team) {
        return true;
    }
    segment.len() == 10
        && segment
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn derive_name_from_bundle(bundle: &str, team: &str) -> String {
    let parts: Vec<&str> = bundle.split('.').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 && looks_like_team_suffix(parts[parts.len() - 1], team) {
        return parts[parts.len() - 2].to_string();
    }
    parts
        .last()
        .map(|s| (*s).to_string())
        .unwrap_or_else(|| bundle.to_string())
}

fn resolve_app_display_name(
    profile: &plist::Dictionary,
    app_info: Option<&plist::Value>,
    bundle_id: &str,
    team_id: &str,
) -> String {
    if let Some(name) = app_info
        .and_then(plist::Value::as_dictionary)
        .and_then(|d| {
            d.get("CFBundleDisplayName")
                .or_else(|| d.get("CFBundleName"))
        })
        .and_then(plist::Value::as_string)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return name.to_string();
    }
    if let Some(app_id_name) = profile
        .get("AppIDName")
        .and_then(plist::Value::as_string)
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with("XC "))
    {
        return app_id_name.to_string();
    }
    derive_name_from_bundle(bundle_id, team_id)
}

pub fn correlate_tracked_apps(
    profiles: &[plist::Dictionary],
    user_apps: Option<&HashMap<String, plist::Value>>,
    storage: &SandboxStorage,
    now: u64,
    renew_before_hours: u64,
) -> Vec<TrackedApp> {
    let mut best_by_bundle: HashMap<String, &plist::Dictionary> = HashMap::new();
    for profile in profiles {
        let Some(bundle_id) = profile_bundle_id(profile) else {
            continue;
        };
        let Ok(exp) = profile_expiration_unix(profile) else {
            continue;
        };
        let key_score = (exp, profile_creation_unix(profile));
        match best_by_bundle.get(&bundle_id) {
            None => {
                best_by_bundle.insert(bundle_id, profile);
            }
            Some(prev) => {
                let prev_score = (
                    profile_expiration_unix(prev).unwrap_or(0),
                    profile_creation_unix(prev),
                );
                if key_score > prev_score {
                    best_by_bundle.insert(bundle_id, profile);
                }
            }
        }
    }

    let mut apps = Vec::new();
    for (bundle_id, profile) in best_by_bundle {
        if let Some(installed_map) = user_apps {
            if !installed_map.contains_key(&bundle_id) {
                continue;
            }
        }
        let app_info = user_apps.and_then(|m| m.get(&bundle_id));
        let team_id = profile_team_id(profile).unwrap_or_default();
        let name = resolve_app_display_name(profile, app_info, &bundle_id, &team_id);
        let expires_at_unix = profile_expiration_unix(profile).unwrap_or(0);
        let (status, hours_remaining, needs_renewal, message) =
            compute_app_health(expires_at_unix, now, renew_before_hours);
        let has_cached_ipa = storage.cached_ipa_path(&bundle_id).is_some();
        apps.push(TrackedApp {
            name,
            bundle_id,
            team_id,
            expires_at_unix,
            hours_remaining,
            status,
            needs_renewal,
            has_cached_ipa,
            message,
        });
    }

    apps.sort_by(|a, b| {
        let rank = |h: AppHealth| match h {
            AppHealth::Expired => 0u8,
            AppHealth::ExpiringSoon => 1u8,
            AppHealth::Ok => 2u8,
        };
        rank(a.status)
            .cmp(&rank(b.status))
            .then_with(|| a.expires_at_unix.cmp(&b.expires_at_unix))
            .then_with(|| a.name.cmp(&b.name))
    });
    apps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile(
        team: &str,
        bundle: &str,
        app_name: &str,
        udid: &str,
        cert: &[u8],
        expires: u64,
    ) -> plist::Dictionary {
        let mut ent = plist::Dictionary::new();
        ent.insert(
            "application-identifier".into(),
            plist::Value::String(format!("{team}.{bundle}")),
        );
        let mut d = plist::Dictionary::new();
        d.insert("AppIDName".into(), plist::Value::String(app_name.into()));
        d.insert("Entitlements".into(), plist::Value::Dictionary(ent));
        d.insert(
            "TeamIdentifier".into(),
            plist::Value::Array(vec![plist::Value::String(team.into())]),
        );
        d.insert(
            "ProvisionedDevices".into(),
            plist::Value::Array(vec![plist::Value::String(udid.into())]),
        );
        d.insert(
            "DeveloperCertificates".into(),
            plist::Value::Array(vec![plist::Value::Data(cert.to_vec())]),
        );
        d.insert(
            "ExpirationDate".into(),
            plist::Value::Date((UNIX_EPOCH + Duration::from_secs(expires)).into()),
        );
        d
    }

    #[test]
    fn correlate_filters_extensions_and_sorts_by_urgency() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let docs = std::env::temp_dir().join(format!(
            "sidebox-engine-corr-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&docs).unwrap();
        let storage = SandboxStorage::new(docs.clone());
        let src_ipa = docs.join("s.ipa");
        fs::write(&src_ipa, b"zipdata").unwrap();
        storage
            .cache_ipa("com.bromhobit.Sidebox.TEAM123456", &src_ipa)
            .unwrap();

        let now = 1_760_000_000;
        let profiles = vec![
            sample_profile(
                "TEAM123456",
                "com.bromhobit.Sidebox.TEAM123456",
                "Sidebox",
                "UDID1",
                b"C1",
                now + 140 * 3600,
            ),
            sample_profile(
                "TEAM123456",
                "com.SideStore.SideStore.TEAM123456",
                "SideStore",
                "UDID1",
                b"C1",
                now + 12 * 3600,
            ),
            sample_profile(
                "TEAM123456",
                "com.SideStore.SideStore.TEAM123456.AltWidget",
                "AltWidget",
                "UDID1",
                b"C1",
                now + 12 * 3600,
            ),
        ];

        let mut user_apps = HashMap::new();
        let mut sb_info = plist::Dictionary::new();
        sb_info.insert(
            "CFBundleDisplayName".into(),
            plist::Value::String("Sidebox".into()),
        );
        user_apps.insert(
            "com.bromhobit.Sidebox.TEAM123456".into(),
            plist::Value::Dictionary(sb_info),
        );
        let mut ss_info = plist::Dictionary::new();
        ss_info.insert(
            "CFBundleDisplayName".into(),
            plist::Value::String("SideStore".into()),
        );
        user_apps.insert(
            "com.SideStore.SideStore.TEAM123456".into(),
            plist::Value::Dictionary(ss_info),
        );

        let apps = correlate_tracked_apps(&profiles, Some(&user_apps), &storage, now, 48);
        assert_eq!(apps.len(), 2);
        // ExpiringSoon SideStore must sort before Ok Sidebox; widget extension excluded
        assert_eq!(apps[0].name, "SideStore");
        assert_eq!(apps[0].status, AppHealth::ExpiringSoon);
        assert!(!apps[0].has_cached_ipa);
        assert_eq!(apps[1].name, "Sidebox");
        assert_eq!(apps[1].status, AppHealth::Ok);
        assert!(apps[1].has_cached_ipa);

        let _ = fs::remove_dir_all(&docs);
    }

    #[test]
    fn engine_lifecycle_overview_and_settings_on_host() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let docs = std::env::temp_dir().join(format!(
            "sidebox-engine-life-{}-{nanos}",
            std::process::id()
        ));
        let engine = SideboxEngine::new(docs.clone()).unwrap();
        let ov = engine.get_overview();
        assert!(!ov.session.exists);
        assert!(!ov.pairing.exists);
        assert_eq!(ov.settings.tunnel_ip, "10.7.0.1");

        let saved = engine
            .save_settings("10.7.0.5", 24, "https://mac-ani.jkcoxson.com")
            .unwrap();
        assert_eq!(saved.tunnel_ip, "10.7.0.5");
        assert_eq!(engine.get_overview().settings.renew_before_hours, 24);
        assert!(engine.logout_apple().is_ok());

        let _ = fs::remove_dir_all(&docs);
    }

    #[test]
    fn compatibility_checks_match_all_invariants() {
        let now = 1_760_000_000;
        let b = "com.bromhobit.Sidebox.TEAM123456";
        let old = sample_profile("TEAM123456", b, "Sidebox", "UDID-1", b"CERT1", now + 3600);
        let good = sample_profile(
            "TEAM123456",
            b,
            "Sidebox",
            "udid-1",
            b"CERT1",
            now + 600_000,
        );
        assert_eq!(
            check_replacement_compatible(&old, &good, "TEAM123456", b, "UDID-1", now).unwrap(),
            now + 600_000
        );

        let bad_cert = sample_profile(
            "TEAM123456",
            b,
            "Sidebox",
            "UDID-1",
            b"CERT2",
            now + 600_000,
        );
        assert!(
            check_replacement_compatible(&old, &bad_cert, "TEAM123456", b, "UDID-1", now).is_err()
        );
    }

    #[test]
    fn cleanup_guard_only_deletes_extracted_temp_dirs() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let extracted = std::env::temp_dir().join(format!(
            "sidebox-guard-{}-{nanos}.ipa_extracted",
            std::process::id()
        ));
        let app_dir = extracted.join("Payload").join("App.app");
        fs::create_dir_all(&app_dir).unwrap();

        {
            let _g = SignedBundleCleanup::new(false, &app_dir);
        }
        assert!(app_dir.exists());

        {
            let _g = SignedBundleCleanup::new(true, &app_dir);
        }
        assert!(!extracted.exists());
    }
}
