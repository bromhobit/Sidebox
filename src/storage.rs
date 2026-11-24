#![cfg_attr(not(target_os = "ios"), allow(dead_code))]

use crate::models::{
    AppSettings, PairingSummary, SessionSummary, mask_email, validate_bundle_id, validate_settings,
};
use idevice::pairing_file::PairingFile;
use isideload::util::storage::SideloadingStorage;
use rootcause::prelude::*;
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

const PAIRING_PRIMARY: &str = "pairingFile.plist";
const PAIRING_ALT: &str = "ALTPairingFile.mobiledevicepairing";
const SESSION_FILENAME: &str = "apple-session.plist";
const SETTINGS_FILENAME: &str = "settings.json";
const APPS_SUBDIR: &str = "Apps";
const MAX_PAIRING_BYTES: u64 = 1024 * 1024;
const MAX_SETTINGS_BYTES: u64 = 64 * 1024;

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct SandboxStorage {
    documents_dir: PathBuf,
}

impl SandboxStorage {
    pub fn new(documents_dir: PathBuf) -> Self {
        Self { documents_dir }
    }

    pub fn apps_dir(&self) -> PathBuf {
        self.documents_dir.join(APPS_SUBDIR)
    }

    pub fn session_path(&self) -> PathBuf {
        self.documents_dir.join(SESSION_FILENAME)
    }

    pub fn settings_path(&self) -> PathBuf {
        self.documents_dir.join(SETTINGS_FILENAME)
    }

    pub fn ensure_documents_dir(&self) -> Result<(), String> {
        match fs::symlink_metadata(&self.documents_dir) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err("каталог Documents не является обычной директорией".into());
                }
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.documents_dir)
                    .map_err(|_| "не удалось создать каталог Documents".to_string())?;
                Ok(())
            }
            Err(_) => Err("каталог Documents недоступен".into()),
        }
    }

    pub fn load_settings(&self) -> AppSettings {
        let path = self.settings_path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            return AppSettings::default();
        };
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_SETTINGS_BYTES {
            return AppSettings::default();
        }
        let Ok(bytes) = fs::read(&path) else {
            return AppSettings::default();
        };
        let Ok(parsed) = serde_json::from_slice::<AppSettings>(&bytes) else {
            return AppSettings::default();
        };
        validate_settings(
            &parsed.tunnel_ip,
            parsed.renew_before_hours,
            &parsed.anisette_url,
        )
        .unwrap_or_default()
    }

    pub fn save_settings(&self, settings: &AppSettings) -> Result<(), String> {
        let validated = validate_settings(
            &settings.tunnel_ip,
            settings.renew_before_hours,
            &settings.anisette_url,
        )?;
        self.ensure_documents_dir()?;
        let bytes = serde_json::to_vec_pretty(&validated)
            .map_err(|_| "не удалось сериализовать настройки".to_string())?;
        write_private_atomic(&self.settings_path(), &bytes)
    }

    pub fn resolve_pairing_path(&self) -> Option<PathBuf> {
        for name in [PAIRING_PRIMARY, PAIRING_ALT] {
            let candidate = self.documents_dir.join(name);
            if let Ok(meta) = fs::symlink_metadata(&candidate) {
                if !meta.file_type().is_symlink() && meta.is_file() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    pub fn inspect_pairing(&self) -> PairingSummary {
        let Some(path) = self.resolve_pairing_path() else {
            return PairingSummary {
                exists: false,
                valid: false,
                udid: None,
                filename: None,
                message:
                    "Pairing-файл не загружен. Импортируйте его или отправьте через Boxloader."
                        .to_string(),
            };
        };
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned);
        match read_and_validate_pairing(&path) {
            Ok((pairing, _raw)) => {
                let udid = pairing.udid.clone();
                let msg = match &udid {
                    Some(u) if !u.is_empty() => format!("Pairing-файл готов (UDID: {u})"),
                    _ => "Pairing-файл загружен и проверен".to_string(),
                };
                PairingSummary {
                    exists: true,
                    valid: true,
                    udid,
                    filename,
                    message: msg,
                }
            }
            Err(err) => PairingSummary {
                exists: true,
                valid: false,
                udid: None,
                filename,
                message: format!("Pairing-файл повреждён: {err}"),
            },
        }
    }

    pub fn load_pairing_file(&self) -> Result<PairingFile, String> {
        let path = self.resolve_pairing_path().ok_or_else(|| {
            "pairing-файл не найден — импортируйте pairingFile.plist в Настройках или отправьте через Boxloader".to_string()
        })?;
        tighten_private_file_permissions(&path);
        let (pairing, mut raw) = read_and_validate_pairing(&path)?;
        raw.zeroize();
        Ok(pairing)
    }

    pub fn import_pairing_file(&self, source_path: &Path) -> Result<PairingSummary, String> {
        self.ensure_documents_dir()?;
        let (pairing, mut raw) = read_and_validate_pairing(source_path)?;
        let dest = self.documents_dir.join(PAIRING_PRIMARY);
        let save_res = write_private_atomic(&dest, &raw);
        raw.zeroize();
        save_res?;

        let udid = pairing.udid;
        let message = match &udid {
            Some(u) if !u.is_empty() => format!("Pairing-файл импортирован (UDID: {u})"),
            _ => "Pairing-файл успешно импортирован.".to_string(),
        };
        Ok(PairingSummary {
            exists: true,
            valid: true,
            udid,
            filename: Some(PAIRING_PRIMARY.to_string()),
            message,
        })
    }

    pub fn inspect_session(&self) -> SessionSummary {
        let path = self.session_path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return SessionSummary {
                    exists: false,
                    valid: false,
                    email_masked: None,
                    message: "Требуется вход в Apple ID".to_string(),
                };
            }
            Err(_) => {
                return SessionSummary {
                    exists: false,
                    valid: false,
                    email_masked: None,
                    message: "Не удалось проверить сессию Apple ID".to_string(),
                };
            }
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            return SessionSummary {
                exists: true,
                valid: false,
                email_masked: None,
                message: "Файл сессии Apple ID некорректен".to_string(),
            };
        }
        match plist::from_file::<_, (String, plist::Dictionary)>(&path) {
            Ok((email, spd)) if !email.trim().is_empty() && !spd.is_empty() => {
                let masked = mask_email(&email);
                drop(email);
                drop(spd);
                SessionSummary {
                    exists: true,
                    valid: true,
                    email_masked: Some(masked.clone()),
                    message: format!("Apple ID активна ({masked})"),
                }
            }
            _ => SessionSummary {
                exists: true,
                valid: false,
                email_masked: None,
                message: "Сессия Apple ID повреждена; войдите заново".to_string(),
            },
        }
    }

    pub fn save_session(&self, email: &str, spd: &plist::Dictionary) -> Result<String, String> {
        let trimmed = email.trim();
        if trimmed.is_empty() || !trimmed.contains('@') || spd.is_empty() {
            return Err("некорректные данные сессии Apple ID".into());
        }
        self.ensure_documents_dir()?;
        let mut bytes = Vec::new();
        let record = (trimmed, spd);
        plist::to_writer_binary(&mut bytes, &record)
            .map_err(|_| "не удалось сериализовать сессию Apple ID".to_string())?;
        let save_res = write_private_atomic(&self.session_path(), &bytes);
        bytes.zeroize();
        save_res?;
        Ok(mask_email(trimmed))
    }

    pub fn load_session(&self) -> Result<(String, plist::Dictionary), String> {
        let path = self.session_path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|_| "сессия Apple ID не найдена — выполните вход в Настройках".to_string())?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("apple-session.plist должен быть обычным файлом".into());
        }
        tighten_private_file_permissions(&path);
        let (email, spd): (String, plist::Dictionary) = plist::from_file(&path)
            .map_err(|_| "не удалось прочитать сохранённую сессию Apple ID".to_string())?;
        if email.trim().is_empty() || spd.is_empty() {
            return Err("сессия Apple ID неполна; выполните повторный вход".into());
        }
        Ok((email, spd))
    }

    pub fn delete_session(&self) -> Result<(), String> {
        let path = self.session_path();
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err("apple-session.plist не является обычным файлом".into());
                }
                fs::remove_file(&path)
                    .map_err(|_| "не удалось удалить файл сессии Apple ID".to_string())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("не удалось проверить файл сессии Apple ID".into()),
        }
    }

    pub fn cached_ipa_path(&self, bundle_id: &str) -> Option<PathBuf> {
        validate_bundle_id(bundle_id).ok()?;
        let path = self.apps_dir().join(format!("{bundle_id}.ipa"));
        let meta = fs::symlink_metadata(&path).ok()?;
        if !meta.file_type().is_symlink() && meta.is_file() && meta.len() > 0 {
            Some(path)
        } else {
            None
        }
    }

    pub fn count_cached_ipas(&self) -> usize {
        let Ok(entries) = fs::read_dir(self.apps_dir()) else {
            return 0;
        };
        entries
            .flatten()
            .filter(|e| {
                let p = e.path();
                p.extension().and_then(|s| s.to_str()) == Some("ipa")
                    && fs::symlink_metadata(&p)
                        .is_ok_and(|m| !m.file_type().is_symlink() && m.is_file() && m.len() > 0)
            })
            .count()
    }

    pub fn cache_ipa(&self, bundle_id: &str, source_ipa: &Path) -> Result<PathBuf, String> {
        validate_bundle_id(bundle_id)?;
        let src_meta = fs::metadata(source_ipa)
            .map_err(|_| "исходный .ipa файл недоступен для кэширования".to_string())?;
        if !src_meta.is_file() || src_meta.len() == 0 {
            return Err("исходный .ipa файл пуст или не является файлом".into());
        }

        self.ensure_documents_dir()?;
        let apps_dir = self.apps_dir();
        ensure_private_subdir(&apps_dir)?;
        let dest = apps_dir.join(format!("{bundle_id}.ipa"));

        // Avoid copying onto ourselves if refreshing from the already-cached IPA.
        if let (Ok(c_src), Ok(c_dst)) = (fs::canonicalize(source_ipa), fs::canonicalize(&dest)) {
            if c_src == c_dst {
                return Ok(dest);
            }
        }

        if let Ok(meta) = fs::symlink_metadata(&dest) {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err("целевой путь кэша IPA некорректен".into());
            }
        }

        let tmp = unique_temp_sibling(&apps_dir, &format!("{bundle_id}.ipa"));
        let copy_res = (|| -> io::Result<()> {
            let mut reader = fs::File::open(source_ipa)?;
            let mut writer = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            io::copy(&mut reader, &mut writer)?;
            writer.sync_all()?;
            fs::rename(&tmp, &dest)?;
            Ok(())
        })();
        if let Err(err) = copy_res {
            let _ = fs::remove_file(&tmp);
            return Err(format!("не удалось сохранить копию .ipa: {err}"));
        }
        Ok(dest)
    }

    pub fn isideload_storage(&self) -> PrivateFsStorage {
        PrivateFsStorage::new(self.documents_dir.clone())
    }
}

fn read_and_validate_pairing(path: &Path) -> Result<(PairingFile, Vec<u8>), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "pairing-файл недоступен".to_string())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("pairing-файл должен быть обычным файлом".into());
    }
    if meta.len() == 0 || meta.len() > MAX_PAIRING_BYTES {
        return Err("недопустимый размер pairing-файла".into());
    }
    let raw = fs::read(path).map_err(|_| "не удалось прочитать pairing-файл".to_string())?;
    let pairing = PairingFile::from_bytes(&raw)
        .map_err(|_| "некорректный формат pairing-файла Apple".to_string())?;
    Ok((pairing, raw))
}

fn tighten_private_file_permissions(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_symlink()
            && meta.is_file()
            && (meta.permissions().mode() & 0o077 != 0)
        {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
}

fn ensure_private_subdir(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err("подкаталог хранилища не является обычной директорией".into());
            }
            if meta.permissions().mode() & 0o077 != 0 {
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            match fs::DirBuilder::new().mode(0o700).create(dir) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
                Err(_) => Err("не удалось создать подкаталог хранилища".into()),
            }
        }
        Err(_) => Err("подкаталог хранилища недоступен".into()),
    }
}

fn unique_temp_sibling(parent: &Path, name: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(".{name}.tmp.{pid}-{nanos}-{seq}"))
}

pub fn write_private_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("целевой путь не является обычным файлом".into());
        }
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sidebox");
    let tmp = unique_temp_sibling(parent, name);
    let write_res = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(format!("не удалось сохранить приватный файл: {err}"));
    }
    Ok(())
}

pub struct PrivateFsStorage {
    root: PathBuf,
}

impl PrivateFsStorage {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn safe_join(&self, key: &str) -> Result<PathBuf, Report> {
        let rel = Path::new(key);
        if key.is_empty() || rel.is_absolute() {
            bail!("Invalid storage key");
        }
        let mut out = self.root.clone();
        for comp in rel.components() {
            match comp {
                Component::Normal(part) => out.push(part),
                Component::CurDir => {}
                _ => bail!("Disallowed path component in storage key"),
            }
        }
        Ok(out)
    }
}

impl SideloadingStorage for PrivateFsStorage {
    fn store_data(&self, key: &str, data: &[u8]) -> Result<(), Report> {
        SandboxStorage::new(self.root.clone())
            .ensure_documents_dir()
            .map_err(|e| report!("{e}"))?;
        let path = self.safe_join(key)?;
        if let Some(parent) = path.parent() {
            if parent != self.root {
                let rel = parent
                    .strip_prefix(&self.root)
                    .map_err(|_| report!("Path escapes storage root"))?;
                let mut cur = self.root.clone();
                for comp in rel.components() {
                    let Component::Normal(part) = comp else {
                        bail!("Invalid path component");
                    };
                    cur.push(part);
                    ensure_private_subdir(&cur).map_err(|e| report!("{e}"))?;
                }
            }
        }
        write_private_atomic(&path, data).map_err(|e| report!("{e}"))?;
        Ok(())
    }

    fn retrieve_data(&self, key: &str) -> Result<Option<Vec<u8>>, Report> {
        let path = self.safe_join(key)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    bail!("Storage entry must be a regular file");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(report!(e).into()),
        }
        tighten_private_file_permissions(&path);
        let bytes = fs::read(&path).context("Failed to read storage file")?;
        Ok(Some(bytes))
    }

    fn store(&self, key: &str, value: &str) -> Result<(), Report> {
        self.store_data(key, value.as_bytes())
    }

    fn retrieve(&self, key: &str) -> Result<Option<String>, Report> {
        match self.retrieve_data(key)? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn temp_docs(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "sidebox-storage-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn settings_roundtrip_and_defaults() {
        let docs = temp_docs("settings");
        let st = SandboxStorage::new(docs.clone());
        assert_eq!(st.load_settings(), AppSettings::default());

        let custom = AppSettings {
            tunnel_ip: "10.7.0.2".into(),
            renew_before_hours: 24,
            anisette_url: "https://ani.example.com".into(),
        };
        st.save_settings(&custom).unwrap();
        let mode = fs::metadata(st.settings_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(st.load_settings(), custom);

        let _ = fs::remove_dir_all(&docs);
    }

    #[test]
    fn session_save_load_delete_enforces_0600_and_rejects_symlinks() {
        let docs = temp_docs("session");
        let st = SandboxStorage::new(docs.clone());
        assert!(!st.inspect_session().exists);

        let mut spd = plist::Dictionary::new();
        spd.insert(
            "GsIdmsToken".into(),
            plist::Value::String("SECRET_TOK".into()),
        );
        let masked = st.save_session("alice.demo@icloud.com", &spd).unwrap();
        assert_eq!(masked, "a***@icloud.com");
        let mode = fs::metadata(st.session_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let summary = st.inspect_session();
        assert!(summary.valid);
        assert_eq!(summary.email_masked.as_deref(), Some("a***@icloud.com"));
        assert!(!summary.message.contains("SECRET_TOK"));
        assert!(!summary.message.contains("alice.demo"));

        // Simulating HouseArrest/AFC pushing 0644 file: load_session tightens to 0600 cleanly
        fs::set_permissions(st.session_path(), fs::Permissions::from_mode(0o644)).unwrap();
        let (email, loaded_spd) = st.load_session().unwrap();
        assert_eq!(email, "alice.demo@icloud.com");
        assert!(!loaded_spd.is_empty());
        let tightened = fs::metadata(st.session_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(tightened, 0o600);

        st.delete_session().unwrap();
        assert!(!st.inspect_session().exists);

        // Symlink must be rejected
        let decoy = docs.join("decoy.plist");
        fs::write(&decoy, b"x").unwrap();
        symlink(&decoy, st.session_path()).unwrap();
        assert!(!st.inspect_session().valid);
        assert!(st.load_session().is_err());

        let _ = fs::remove_dir_all(&docs);
    }

    #[test]
    fn ipa_caching_and_private_fs_storage_safety() {
        let docs = temp_docs("ipa");
        let st = SandboxStorage::new(docs.clone());
        let src = docs.join("source.ipa");
        fs::write(&src, b"PK\x03\x04dummy-ipa-data").unwrap();

        assert!(st.cache_ipa("../bad", &src).is_err());
        let cached = st
            .cache_ipa("com.SideStore.SideStore.TEAM123456", &src)
            .unwrap();
        assert_eq!(st.count_cached_ipas(), 1);
        assert_eq!(
            st.cached_ipa_path("com.SideStore.SideStore.TEAM123456"),
            Some(cached.clone())
        );
        assert_eq!(
            fs::metadata(&cached).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Caching onto self must be a safe no-op
        assert_eq!(
            st.cache_ipa("com.SideStore.SideStore.TEAM123456", &cached)
                .unwrap(),
            cached
        );

        let pfs = st.isideload_storage();
        assert!(pfs.store_data("../escape", b"bad").is_err());
        pfs.store_data("cert/key", b"rsa-der").unwrap();
        assert_eq!(
            fs::metadata(docs.join("cert/key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            pfs.retrieve_data("cert/key").unwrap().as_deref(),
            Some(&b"rsa-der"[..])
        );

        let _ = fs::remove_dir_all(&docs);
    }
}
