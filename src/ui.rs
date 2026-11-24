use std::path::Path;

use crate::models::{AppHealth, AppOverview};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiTone {
    Green,
    Amber,
    Red,
    Neutral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Apps,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingFileKind {
    Ipa,
    Pairing,
    Unsupported,
}

pub fn classify_incoming_file(path: &Path) -> IncomingFileKind {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "ipa" => IncomingFileKind::Ipa,
        "mobiledevicepairing" | "plist" => IncomingFileKind::Pairing,
        _ => IncomingFileKind::Unsupported,
    }
}

pub fn health_badge(health: &AppHealth) -> (&'static str, UiTone) {
    match health {
        AppHealth::Ok => ("Действует", UiTone::Green),
        AppHealth::ExpiringSoon => ("Скоро истечёт", UiTone::Amber),
        AppHealth::Expired => ("Истёк", UiTone::Red),
    }
}

pub fn progress_fraction(percent: u8) -> f32 {
    (percent.min(100) as f32) / 100.0
}

pub fn format_remaining(expires_at_unix: u64, now_unix: u64) -> String {
    if expires_at_unix == 0 {
        return "Срок неизвестен".to_string();
    }
    if expires_at_unix <= now_unix {
        let ago = now_unix - expires_at_unix;
        if ago < 60 {
            return "Истёк только что".to_string();
        } else if ago < 3600 {
            return format!("Истёк {} мин. назад", ago / 60);
        } else if ago < 86_400 {
            return format!("Истёк {} ч. назад", ago / 3600);
        } else {
            return format!("Истёк {} дн. назад", ago / 86_400);
        }
    }
    let rem = expires_at_unix - now_unix;
    let days = rem / 86_400;
    let hours = (rem % 86_400) / 3600;
    let mins = (rem % 3600) / 60;
    if days > 0 {
        format!("Осталось: {days} дн. {hours} ч.")
    } else if hours > 0 {
        format!("Осталось: {hours} ч. {mins} мин.")
    } else if mins > 0 {
        format!("Осталось: {mins} мин.")
    } else {
        "Осталось менее 1 мин.".to_string()
    }
}

/// Converts Unix timestamp + timezone offset (seconds) into `(year, month, day, hour, minute, second)`.
pub fn unix_to_ymdhms(unix_secs: i64, tz_offset_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let local = unix_secs.saturating_add(tz_offset_secs);
    let days = local.div_euclid(86_400);
    let sod = local.rem_euclid(86_400) as u32;
    let hour = sod / 3600;
    let min = (sod % 3600) / 60;
    let sec = sod % 60;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32, hour, min, sec)
}

pub fn format_date_ru(unix_secs: u64, tz_offset_secs: i64) -> String {
    const MONTHS: [&str; 12] = [
        "янв.",
        "февр.",
        "мар.",
        "апр.",
        "мая",
        "июн.",
        "июл.",
        "авг.",
        "сент.",
        "окт.",
        "нояб.",
        "дек.",
    ];
    let (year, month, day, hour, min, _) = unix_to_ymdhms(unix_secs as i64, tz_offset_secs);
    let m_str = MONTHS
        .get(month.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("");
    format!("{day} {m_str} {year}, {hour:02}:{min:02}")
}

/// Returns `(title, body, show_open_settings_button)` for the empty/guidance card on Tab 1.
pub fn build_guidance(overview: &AppOverview, list_error: Option<&str>) -> (String, String, bool) {
    if !overview.pairing.valid {
        return (
            "Нужен pairing-файл устройства".to_string(),
            "Откройте «Настройки» и импортируйте pairing-файл (.mobiledevicepairing / pairingFile.plist) или отправьте его с ПК через Boxloader."
                .to_string(),
            true,
        );
    }
    if let Some(err) = list_error
        && !err.trim().is_empty()
    {
        return (
            "Не удалось загрузить приложения".to_string(),
            format!(
                "{}\n\nВключите LocalDevVPN или StosVPN. Проверьте Device IP ({}) и потяните экран вниз для обновления.",
                err.trim(),
                overview.settings.tunnel_ip
            ),
            true,
        );
    }
    if !overview.session.valid {
        return (
            "Войдите в Apple ID".to_string(),
            "Pairing-файл загружен. Для установки и продления приложений выполните вход в Apple ID в разделе «Настройки»."
                .to_string(),
            true,
        );
    }
    (
        "Приложения пока не найдены".to_string(),
        "Нажмите «+ Установить .ipa», чтобы подписать и установить приложение прямо на iPhone, либо потяните вниз для повторного сканирования."
            .to_string(),
        false,
    )
}

#[cfg(target_os = "ios")]
pub fn run() {
    ios_ui::run();
}

#[cfg(target_os = "ios")]
mod ios_ui {
    use std::ffi::{CStr, c_void};
    use std::ptr;
    use std::sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::engine::SideboxEngine;
    use crate::models::{
        AppOverview, ProgressUpdate, TrackedApp, TunnelStatus, TwoFactorAnswer, TwoFactorPrompt,
        sanitize_message,
    };
    use crate::objc_ffi::{
        AutoreleasePool, CGRect, FontWeight, GlobalBlock, Id, NS_LINE_BREAK_BY_TRUNCATING_TAIL,
        NS_LINE_BREAK_BY_WORD_WRAPPING, NS_TEXT_ALIGNMENT_LEFT, OwnedId, SecurityScopedAccess, Sel,
        UI_ACTIVITY_INDICATOR_STYLE_MEDIUM, UI_ALERT_ACTION_STYLE_CANCEL,
        UI_ALERT_ACTION_STYLE_DEFAULT, UI_ALERT_CONTROLLER_STYLE_ALERT, UI_BUTTON_TYPE_SYSTEM,
        UI_CONTENT_INSET_ADJUSTMENT_ALWAYS, UI_CONTROL_EVENT_TOUCH_UP_INSIDE,
        UI_CONTROL_EVENT_VALUE_CHANGED, UI_CONTROL_STATE_DISABLED, UI_CONTROL_STATE_NORMAL,
        UI_KEYBOARD_TYPE_ASCII_CAPABLE_NUMBER_PAD, UI_KEYBOARD_TYPE_EMAIL_ADDRESS,
        UI_KEYBOARD_TYPE_NUMBERS_AND_PUNCTUATION, UI_PROGRESS_VIEW_STYLE_DEFAULT,
        UI_SCROLL_INDICATOR_STYLE_WHITE, UI_SCROLL_KEYBOARD_DISMISS_ON_DRAG,
        UI_STATUS_BAR_STYLE_LIGHT_CONTENT, UI_SWIPE_GESTURE_DIRECTION_DOWN,
        UI_TEXT_AUTOCAPITALIZATION_NONE, UI_TEXT_AUTOCORRECTION_NO, UI_USER_INTERFACE_STYLE_DARK,
        UIApplicationMain, add_method, alloc_init, alloc_init_frame, allocate_class_pair, class,
        is_main_thread, local_tz_offset_secs, mono_font, msg_alert_action, msg_alert_controller,
        msg_bool, msg_bool_bool, msg_i64, msg_id, msg_id_i64, msg_id_id_bool, msg_id_id_sel,
        msg_id_u64, msg_insets, msg_rect, msg_size_size, msg_super_void, msg_u64, msg_void,
        msg_void_bool, msg_void_f32_bool, msg_void_f64, msg_void_i64, msg_void_id, msg_void_id_u64,
        msg_void_perform_main, msg_void_present, msg_void_ptr, msg_void_rect, msg_void_size,
        msg_void_target_action, ns_string, ns_string_to_rust, rect, register_class_pair,
        remove_all_subviews, rgb, rgba, sandbox_documents_dir, sel, size, system_font, url_to_path,
        uttype_array,
    };

    use super::{
        ActiveTab, IncomingFileKind, UiTone, build_guidance, classify_incoming_file,
        format_date_ru, format_remaining, health_badge, progress_fraction,
    };

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum PickerMode {
        Ipa,
        Pairing,
    }

    enum WorkerEvent {
        Progress(ProgressUpdate),
        TwoFactorRequest {
            prompt: TwoFactorPrompt,
            reply_tx: mpsc::Sender<TwoFactorAnswer>,
        },
        AppsLoaded {
            overview: AppOverview,
            result: Result<Vec<TrackedApp>, String>,
        },
        OperationDone {
            overview: AppOverview,
            apps: Option<Vec<TrackedApp>>,
            ok: bool,
            title: String,
            message: String,
        },
        TunnelTested {
            overview: AppOverview,
            result: Result<TunnelStatus, String>,
        },
    }

    struct MainThreadUi {
        controller: Option<OwnedId>,
        scroll_view: Option<OwnedId>,
        content_view: Option<OwnedId>,
        refresh_control: Option<OwnedId>,
        // Live subview handles bound during rebuild for fast in-place progress ticks:
        progress_label: Option<OwnedId>,
        progress_view: Option<OwnedId>,
        active_tab: ActiveTab,
        picker_mode: PickerMode,
        overview: AppOverview,
        apps: Vec<TrackedApp>,
        list_error: Option<String>,
        busy_title: Option<String>,
        busy_progress: u8,
        log_tone: UiTone,
        log_title: String,
        log_message: String,
        last_layout_width: f64,
        last_safe_lr: (f64, f64),
        needs_rebuild: bool,
    }

    impl MainThreadUi {
        fn new(overview: AppOverview) -> Self {
            Self {
                controller: None,
                scroll_view: None,
                content_view: None,
                refresh_control: None,
                progress_label: None,
                progress_view: None,
                active_tab: ActiveTab::Apps,
                picker_mode: PickerMode::Ipa,
                overview,
                apps: Vec::new(),
                list_error: None,
                busy_title: None,
                busy_progress: 0,
                log_tone: UiTone::Neutral,
                log_title: "Готов к работе".to_string(),
                log_message:
                    "Включите LocalDevVPN или StosVPN и выберите действие или потяните экран вниз."
                        .to_string(),
                last_layout_width: 0.0,
                last_safe_lr: (0.0, 0.0),
                needs_rebuild: true,
            }
        }
    }

    struct LayoutSnapshot {
        controller: Id,
        scroll_view: Id,
        content_view: Id,
        active_tab: ActiveTab,
        overview: AppOverview,
        apps: Vec<TrackedApp>,
        list_error: Option<String>,
        busy_title: Option<String>,
        busy_progress: u8,
        log_tone: UiTone,
        log_title: String,
        log_message: String,
    }

    struct MainThreadCell<T>(Mutex<T>);
    unsafe impl<T> Sync for MainThreadCell<T> {}

    static DELEGATE_WINDOW: MainThreadCell<Option<OwnedId>> = MainThreadCell(Mutex::new(None));
    static ACTIVE_ALERT: MainThreadCell<Option<OwnedId>> = MainThreadCell(Mutex::new(None));
    static APP_UI: MainThreadCell<Option<MainThreadUi>> = MainThreadCell(Mutex::new(None));
    static ENGINE: OnceLock<Arc<SideboxEngine>> = OnceLock::new();
    static REBUILDING: AtomicBool = AtomicBool::new(false);
    static BUSY: AtomicBool = AtomicBool::new(false);
    static PENDING_EVENTS: Mutex<Vec<WorkerEvent>> = Mutex::new(Vec::new());
    static PENDING_TFA_REPLY: Mutex<Option<mpsc::Sender<TwoFactorAnswer>>> = Mutex::new(None);
    static PENDING_OPEN_URL: Mutex<Option<usize>> = Mutex::new(None);

    // Static GlobalBlocks for UIAlertAction handlers (zero stack-block UB, zero heap leaks).
    static LOGIN_OK_BLOCK: OnceLock<GlobalBlock> = OnceLock::new();
    static LOGIN_CANCEL_BLOCK: OnceLock<GlobalBlock> = OnceLock::new();
    static TFA_OK_BLOCK: OnceLock<GlobalBlock> = OnceLock::new();
    static TFA_RESEND_BLOCK: OnceLock<GlobalBlock> = OnceLock::new();
    static TFA_CANCEL_BLOCK: OnceLock<GlobalBlock> = OnceLock::new();
    static TUNNEL_IP_OK_BLOCK: OnceLock<GlobalBlock> = OnceLock::new();
    static TUNNEL_IP_CANCEL_BLOCK: OnceLock<GlobalBlock> = OnceLock::new();

    fn engine() -> Arc<SideboxEngine> {
        ENGINE
            .get_or_init(|| {
                let docs = sandbox_documents_dir();
                Arc::new(
                    SideboxEngine::new(docs)
                        .expect("failed to initialize SideboxEngine in sandbox Documents"),
                )
            })
            .clone()
    }

    fn with_main_ui<R>(f: impl FnOnce(&mut MainThreadUi) -> R) -> R {
        assert!(
            is_main_thread(),
            "Sidebox UIKit state must only be accessed on the main thread"
        );
        let mut guard = APP_UI.0.lock().unwrap_or_else(|e| e.into_inner());
        let ui = guard.get_or_insert_with(|| MainThreadUi::new(engine().get_overview()));
        f(ui)
    }

    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn push_event_and_wake(controller_id: Id, ev: WorkerEvent) {
        {
            let mut q = PENDING_EVENTS.lock().unwrap_or_else(|e| e.into_inner());
            q.push(ev);
        }
        unsafe {
            msg_void_perform_main(
                controller_id,
                sel(c"drainWorkerEvents"),
                ptr::null_mut(),
                false,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Sidebox dark theme palette
    // -----------------------------------------------------------------------

    fn col_bg() -> Id {
        rgb(0.039, 0.047, 0.086)
    }
    fn col_card() -> Id {
        rgb(0.075, 0.094, 0.161)
    }
    fn col_card_alt() -> Id {
        rgb(0.063, 0.082, 0.145)
    }
    fn col_input_bg() -> Id {
        rgb(0.051, 0.067, 0.122)
    }
    fn col_border() -> Id {
        rgb(0.145, 0.176, 0.282)
    }
    fn col_divider() -> Id {
        rgb(0.125, 0.153, 0.247)
    }
    fn col_text_primary() -> Id {
        rgb(0.957, 0.969, 0.996)
    }
    fn col_text_secondary() -> Id {
        rgb(0.620, 0.659, 0.773)
    }
    fn col_text_muted() -> Id {
        rgb(0.455, 0.498, 0.624)
    }
    fn col_accent() -> Id {
        rgb(0.490, 0.412, 1.0)
    }
    fn col_cyan() -> Id {
        rgb(0.176, 0.831, 0.749)
    }
    fn col_btn_primary() -> Id {
        rgb(0.435, 0.278, 0.961)
    }
    fn col_btn_secondary() -> Id {
        rgb(0.110, 0.137, 0.231)
    }
    fn col_btn_secondary_border() -> Id {
        rgb(0.200, 0.239, 0.376)
    }
    fn col_btn_danger_bg() -> Id {
        rgba(0.937, 0.267, 0.267, 0.16)
    }
    fn col_btn_danger_border() -> Id {
        rgba(0.937, 0.267, 0.267, 0.45)
    }

    fn tone_fg(tone: UiTone) -> Id {
        match tone {
            UiTone::Green => rgb(0.165, 0.816, 0.427),
            UiTone::Amber => rgb(0.969, 0.659, 0.129),
            UiTone::Red => rgb(0.953, 0.322, 0.322),
            UiTone::Neutral => rgb(0.647, 0.690, 0.792),
        }
    }

    fn tone_pill_bg(tone: UiTone) -> Id {
        match tone {
            UiTone::Green => rgba(0.133, 0.773, 0.369, 0.16),
            UiTone::Amber => rgba(0.961, 0.620, 0.043, 0.16),
            UiTone::Red => rgba(0.937, 0.267, 0.267, 0.16),
            UiTone::Neutral => rgba(0.580, 0.639, 0.722, 0.14),
        }
    }

    fn tone_border(tone: UiTone) -> Id {
        match tone {
            UiTone::Green => rgba(0.165, 0.816, 0.427, 0.34),
            UiTone::Amber => rgba(0.969, 0.659, 0.129, 0.40),
            UiTone::Red => rgba(0.953, 0.322, 0.322, 0.44),
            UiTone::Neutral => col_border(),
        }
    }

    // -----------------------------------------------------------------------
    // UIKit view builders (alloc/init wrapped in OwnedId -> auto-released)
    // -----------------------------------------------------------------------

    unsafe fn style_layer(view: Id, radius: f64, border_width: f64, border_color: Option<Id>) {
        unsafe {
            let layer = msg_id(view, c"layer");
            if layer.is_null() {
                return;
            }
            msg_void_f64(layer, c"setCornerRadius:", radius);
            if border_width > 0.0 {
                msg_void_f64(layer, c"setBorderWidth:", border_width);
                if let Some(color) = border_color {
                    let cg_color = msg_id(color, c"CGColor");
                    msg_void_id(layer, c"setBorderColor:", cg_color);
                }
            }
            msg_void_bool(layer, c"setMasksToBounds:", true);
        }
    }

    unsafe fn make_view(parent: Id, frame: CGRect, bg: Id) -> Id {
        unsafe {
            let view = alloc_init_frame(c"UIView", frame);
            msg_void_id(view.as_id(), c"setBackgroundColor:", bg);
            msg_void_id(parent, c"addSubview:", view.as_id());
            view.as_id()
        }
    }

    unsafe fn make_dot(parent: Id, x: f64, y: f64, diameter: f64, color: Id) {
        unsafe {
            let dot = make_view(parent, rect(x, y, diameter, diameter), color);
            style_layer(dot, diameter * 0.5, 0.0, None);
        }
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn make_label_measured(
        parent: Id,
        x: f64,
        y: f64,
        max_width: f64,
        text: &str,
        font: Id,
        color: Id,
        lines: i64,
        alignment: i64,
    ) -> (Id, f64, f64) {
        unsafe {
            let lbl = alloc_init_frame(c"UILabel", rect(x, y, max_width, 0.0));
            let id = lbl.as_id();
            msg_void_id(id, c"setText:", ns_string(text));
            msg_void_id(id, c"setFont:", font);
            msg_void_id(id, c"setTextColor:", color);
            msg_void_i64(id, c"setNumberOfLines:", lines);
            msg_void_i64(id, c"setTextAlignment:", alignment);
            msg_void_i64(
                id,
                c"setLineBreakMode:",
                if lines == 1 {
                    NS_LINE_BREAK_BY_TRUNCATING_TAIL
                } else {
                    NS_LINE_BREAK_BY_WORD_WRAPPING
                },
            );
            let fitted = msg_size_size(id, c"sizeThatFits:", size(max_width, 10_000.0));
            let final_w = fitted.width.ceil().min(max_width);
            let final_h = fitted.height.ceil().max(14.0);
            msg_void_rect(id, c"setFrame:", rect(x, y, max_width, final_h));
            msg_void_id(parent, c"addSubview:", id);
            (id, final_w, final_h)
        }
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn make_button(
        parent: Id,
        controller: Id,
        frame: CGRect,
        title: &str,
        action: &CStr,
        tag: i64,
        bg: Id,
        border: Option<Id>,
        text_color: Id,
        font_size: f64,
        radius: f64,
        enabled: bool,
    ) {
        unsafe {
            // `+[UIButton buttonWithType:]` returns an autoreleased (+0) object — do NOT release.
            let btn = msg_id_i64(
                class(c"UIButton"),
                c"buttonWithType:",
                UI_BUTTON_TYPE_SYSTEM,
            );
            msg_void_rect(btn, c"setFrame:", frame);
            msg_void_id(btn, c"setBackgroundColor:", bg);
            msg_void_i64(btn, c"setTag:", tag);
            style_layer(
                btn,
                radius,
                if border.is_some() { 1.0 } else { 0.0 },
                border,
            );
            let title_ns = ns_string(title);
            msg_void_id_u64(
                btn,
                c"setTitle:forState:",
                title_ns,
                UI_CONTROL_STATE_NORMAL,
            );
            msg_void_id_u64(
                btn,
                c"setTitle:forState:",
                title_ns,
                UI_CONTROL_STATE_DISABLED,
            );
            msg_void_id_u64(
                btn,
                c"setTitleColor:forState:",
                text_color,
                UI_CONTROL_STATE_NORMAL,
            );
            msg_void_id_u64(
                btn,
                c"setTitleColor:forState:",
                text_color,
                UI_CONTROL_STATE_DISABLED,
            );
            let title_lbl = msg_id(btn, c"titleLabel");
            if !title_lbl.is_null() {
                msg_void_id(
                    title_lbl,
                    c"setFont:",
                    system_font(font_size, FontWeight::Semibold),
                );
            }
            msg_void_bool(btn, c"setEnabled:", enabled);
            msg_void_f64(btn, c"setAlpha:", if enabled { 1.0 } else { 0.48 });
            msg_void_target_action(
                btn,
                c"addTarget:action:forControlEvents:",
                controller,
                sel(action),
                UI_CONTROL_EVENT_TOUCH_UP_INSIDE,
            );
            msg_void_id(parent, c"addSubview:", btn);
        }
    }

    unsafe fn make_pill(
        parent: Id,
        x: f64,
        y: f64,
        max_w: f64,
        text: &str,
        tone: UiTone,
    ) -> (f64, f64) {
        unsafe {
            let font = system_font(12.0, FontWeight::Semibold);
            let probe = alloc_init_frame(c"UILabel", rect(0.0, 0.0, max_w, 0.0));
            msg_void_id(probe.as_id(), c"setText:", ns_string(text));
            msg_void_id(probe.as_id(), c"setFont:", font);
            let fit = msg_size_size(probe.as_id(), c"sizeThatFits:", size(max_w, 36.0));
            drop(probe);

            let dot_d = 7.0;
            let pill_h = (fit.height.ceil() + 10.0).max(26.0);
            let pill_w = (10.0 + dot_d + 6.0 + fit.width.ceil() + 10.0).min(max_w);
            let pill = make_view(parent, rect(x, y, pill_w, pill_h), tone_pill_bg(tone));
            style_layer(pill, pill_h * 0.5, 1.0, Some(tone_border(tone)));
            make_dot(pill, 10.0, (pill_h - dot_d) * 0.5, dot_d, tone_fg(tone));
            let lx = 10.0 + dot_d + 6.0;
            let ly = ((pill_h - fit.height.ceil()) * 0.5).max(0.0);
            make_label_measured(
                pill,
                lx,
                ly,
                (pill_w - lx - 8.0).max(20.0),
                text,
                font,
                tone_fg(tone),
                1,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            (pill_w, pill_h)
        }
    }

    unsafe fn render_section_header(parent: Id, x: f64, y: f64, width: f64, title: &str) -> f64 {
        unsafe {
            let (_, _, h) = make_label_measured(
                parent,
                x + 4.0,
                y,
                width - 8.0,
                title,
                system_font(12.0, FontWeight::Bold),
                col_text_muted(),
                1,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            y + h + 10.0
        }
    }

    // -----------------------------------------------------------------------
    // Full Declarative Layout Rebuild (strictly on main thread, no Mutex held)
    // -----------------------------------------------------------------------

    fn perform_rebuild() {
        assert!(is_main_thread());
        if REBUILDING.swap(true, Ordering::AcqRel) {
            return;
        }
        struct RebuildGuard;
        impl Drop for RebuildGuard {
            fn drop(&mut self) {
                REBUILDING.store(false, Ordering::Release);
            }
        }
        let _guard = RebuildGuard;

        let snapshot = with_main_ui(|ui| {
            let controller = ui.controller.as_ref()?.as_id();
            let scroll_view = ui.scroll_view.as_ref()?.as_id();
            let content_view = ui.content_view.as_ref()?.as_id();
            // Release old dynamic handles before clearing subviews.
            ui.progress_label = None;
            ui.progress_view = None;
            Some(LayoutSnapshot {
                controller,
                scroll_view,
                content_view,
                active_tab: ui.active_tab,
                overview: ui.overview.clone(),
                apps: ui.apps.clone(),
                list_error: ui.list_error.clone(),
                busy_title: ui.busy_title.clone(),
                busy_progress: ui.busy_progress,
                log_tone: ui.log_tone,
                log_title: ui.log_title.clone(),
                log_message: ui.log_message.clone(),
            })
        });
        let Some(snap) = snapshot else {
            return;
        };

        let mut new_prog_label: Option<OwnedId> = None;
        let mut new_prog_view: Option<OwnedId> = None;

        unsafe {
            let root_view = msg_id(snap.controller, c"view");
            if root_view.is_null() {
                return;
            }
            let bounds = msg_rect(root_view, c"bounds");
            let w = bounds.size.width;
            if w < 100.0 {
                return;
            }
            let safe = msg_insets(root_view, c"safeAreaInsets");
            msg_void_rect(snap.scroll_view, c"setFrame:", bounds);
            remove_all_subviews(snap.content_view);

            let side_pad = safe.left.max(safe.right).max(16.0);
            let col_w = (w - side_pad * 2.0).clamp(240.0, 540.0);
            let col_x = (w - col_w) * 0.5;
            let mut y = 14.0;

            // --- Header: SIDEBOX + Apple ID & Pairing status pills ---
            let (_, _, title_h) = make_label_measured(
                snap.content_view,
                col_x,
                y,
                col_w,
                "SIDEBOX",
                system_font(26.0, FontWeight::Bold),
                col_text_primary(),
                1,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            y += title_h + 8.0;

            let (apple_pill_text, apple_tone) = if snap.overview.session.valid {
                ("Apple ID: активна", UiTone::Green)
            } else {
                ("Apple ID: нет входа", UiTone::Amber)
            };
            let (pair_pill_text, pair_tone) = if snap.overview.pairing.valid {
                ("Pairing: загружен", UiTone::Green)
            } else {
                ("Pairing: нет", UiTone::Amber)
            };

            let half_max = (col_w - 8.0) * 0.54;
            let (p1_w, p1_h) = make_pill(
                snap.content_view,
                col_x,
                y,
                half_max,
                apple_pill_text,
                apple_tone,
            );
            let p2_x = col_x + p1_w + 8.0;
            let p2_rem = col_x + col_w - p2_x;
            if p2_rem >= 110.0 {
                let (_, p2_h) = make_pill(
                    snap.content_view,
                    p2_x,
                    y,
                    p2_rem,
                    pair_pill_text,
                    pair_tone,
                );
                y += p1_h.max(p2_h) + 14.0;
            } else {
                y += p1_h + 6.0;
                let (_, p2_h) = make_pill(
                    snap.content_view,
                    col_x,
                    y,
                    col_w,
                    pair_pill_text,
                    pair_tone,
                );
                y += p2_h + 14.0;
            }

            // --- 2-Tab Segmented Capsule Switcher ---
            let seg_h = 40.0;
            let seg_box = make_view(snap.content_view, rect(col_x, y, col_w, seg_h), col_card());
            style_layer(seg_box, 12.0, 1.0, Some(col_border()));
            let inner_pad = 3.0;
            let tab_w = (col_w - inner_pad * 2.0 - 4.0) * 0.5;
            let tab_h = seg_h - inner_pad * 2.0;

            let apps_active = snap.active_tab == ActiveTab::Apps;
            make_button(
                seg_box,
                snap.controller,
                rect(inner_pad, inner_pad, tab_w, tab_h),
                "Приложения",
                c"selectTabApps:",
                0,
                if apps_active {
                    col_btn_primary()
                } else {
                    rgba(0.0, 0.0, 0.0, 0.0)
                },
                None,
                if apps_active {
                    col_text_primary()
                } else {
                    col_text_secondary()
                },
                14.5,
                9.0,
                true,
            );
            make_button(
                seg_box,
                snap.controller,
                rect(inner_pad + tab_w + 4.0, inner_pad, tab_w, tab_h),
                "Настройки",
                c"selectTabSettings:",
                1,
                if !apps_active {
                    col_btn_primary()
                } else {
                    rgba(0.0, 0.0, 0.0, 0.0)
                },
                None,
                if !apps_active {
                    col_text_primary()
                } else {
                    col_text_secondary()
                },
                14.5,
                9.0,
                true,
            );
            y += seg_h + 16.0;

            // --- Live Progress Banner (shown whenever an operation is active) ---
            let is_busy = snap.busy_title.is_some();
            if let Some(busy_msg) = &snap.busy_title {
                let pad = 14.0;
                let inner_w = col_w - pad * 2.0;
                let banner = make_view(
                    snap.content_view,
                    rect(col_x, y, col_w, 72.0),
                    col_card_alt(),
                );
                style_layer(banner, 14.0, 1.0, Some(rgba(0.490, 0.412, 1.0, 0.45)));

                let raw_spin = msg_id(class(c"UIActivityIndicatorView"), c"alloc");
                let spin = OwnedId::from_owned(msg_id_i64(
                    raw_spin,
                    c"initWithActivityIndicatorStyle:",
                    UI_ACTIVITY_INDICATOR_STYLE_MEDIUM,
                ));
                msg_void_rect(spin.as_id(), c"setFrame:", rect(pad, pad, 20.0, 20.0));
                msg_void_id(spin.as_id(), c"setColor:", col_cyan());
                msg_void_id(banner, c"addSubview:", spin.as_id());
                msg_void(spin.as_id(), c"startAnimating");

                let (pl_id, _, pl_h) = make_label_measured(
                    banner,
                    pad + 28.0,
                    pad,
                    (inner_w - 28.0).max(80.0),
                    busy_msg,
                    system_font(14.0, FontWeight::Semibold),
                    col_text_primary(),
                    0,
                    NS_TEXT_ALIGNMENT_LEFT,
                );
                new_prog_label = Some(OwnedId::retain(pl_id));

                let pv_y = pad + pl_h.max(20.0) + 10.0;
                let raw_pv = msg_id(class(c"UIProgressView"), c"alloc");
                let pv = OwnedId::from_owned(msg_id_i64(
                    raw_pv,
                    c"initWithProgressViewStyle:",
                    UI_PROGRESS_VIEW_STYLE_DEFAULT,
                ));
                msg_void_rect(pv.as_id(), c"setFrame:", rect(pad, pv_y, inner_w, 4.0));
                msg_void_id(pv.as_id(), c"setProgressTintColor:", col_cyan());
                msg_void_id(pv.as_id(), c"setTrackTintColor:", col_divider());
                msg_void_f32_bool(
                    pv.as_id(),
                    c"setProgress:animated:",
                    progress_fraction(snap.busy_progress),
                    false,
                );
                msg_void_id(banner, c"addSubview:", pv.as_id());
                new_prog_view = Some(OwnedId::retain(pv.as_id()));

                let bh = pv_y + 4.0 + pad;
                msg_void_rect(banner, c"setFrame:", rect(col_x, y, col_w, bh));
                y += bh + 16.0;
            }

            // --- Tab Body ---
            match snap.active_tab {
                ActiveTab::Apps => {
                    y = render_apps_tab(snap.content_view, col_x, y, col_w, &snap, is_busy);
                }
                ActiveTab::Settings => {
                    y = render_settings_tab(snap.content_view, col_x, y, col_w, &snap, is_busy);
                }
            }

            msg_void_rect(snap.content_view, c"setFrame:", rect(0.0, 0.0, w, y));
            msg_void_size(snap.scroll_view, c"setContentSize:", size(w, y));

            with_main_ui(|ui| {
                ui.progress_label = new_prog_label;
                ui.progress_view = new_prog_view;
                ui.last_layout_width = w;
                ui.last_safe_lr = (safe.left, safe.right);
                ui.needs_rebuild = false;
            });
        }
    }

    unsafe fn render_apps_tab(
        parent: Id,
        x: f64,
        mut y: f64,
        width: f64,
        snap: &LayoutSnapshot,
        is_busy: bool,
    ) -> f64 {
        unsafe {
            // Action row: "+ Установить .ipa" (primary) + "Продлить все" (secondary)
            let gap = 10.0;
            let btn_h = 48.0;
            let primary_w = (width - gap) * 0.56;
            let secondary_w = width - gap - primary_w;

            make_button(
                parent,
                snap.controller,
                rect(x, y, primary_w, btn_h),
                "+ Установить .ipa",
                c"pickIpa:",
                0,
                col_btn_primary(),
                None,
                col_text_primary(),
                15.5,
                13.0,
                !is_busy,
            );
            make_button(
                parent,
                snap.controller,
                rect(x + primary_w + gap, y, secondary_w, btn_h),
                "Продлить все",
                c"refreshAllApps:",
                0,
                col_btn_secondary(),
                Some(col_btn_secondary_border()),
                col_text_primary(),
                15.0,
                13.0,
                !is_busy,
            );
            y += btn_h + 20.0;

            y = render_section_header(parent, x, y, width, "УСТАНОВЛЕННЫЕ ПРИЛОЖЕНИЯ");

            let now = now_unix_secs();
            if snap.apps.is_empty() {
                let (g_title, g_body, show_settings_btn) =
                    build_guidance(&snap.overview, snap.list_error.as_deref());
                let pad = 16.0;
                let inner_w = width - pad * 2.0;
                let card = make_view(parent, rect(x, y, width, 120.0), col_card());
                let border = if snap.list_error.is_some() || !snap.overview.pairing.valid {
                    tone_border(UiTone::Amber)
                } else {
                    col_border()
                };
                style_layer(card, 16.0, 1.0, Some(border));

                let mut cy = pad;
                let (_, _, th) = make_label_measured(
                    card,
                    pad,
                    cy,
                    inner_w,
                    &g_title,
                    system_font(16.5, FontWeight::Bold),
                    col_text_primary(),
                    0,
                    NS_TEXT_ALIGNMENT_LEFT,
                );
                cy += th + 8.0;

                let (_, _, bh) = make_label_measured(
                    card,
                    pad,
                    cy,
                    inner_w,
                    &g_body,
                    system_font(13.5, FontWeight::Regular),
                    col_text_secondary(),
                    0,
                    NS_TEXT_ALIGNMENT_LEFT,
                );
                cy += bh;

                if show_settings_btn {
                    cy += 14.0;
                    make_button(
                        card,
                        snap.controller,
                        rect(pad, cy, inner_w, 42.0),
                        "Открыть Настройки",
                        c"selectTabSettings:",
                        1,
                        col_btn_secondary(),
                        Some(col_btn_secondary_border()),
                        col_text_primary(),
                        14.5,
                        11.0,
                        true,
                    );
                    cy += 42.0;
                }

                let ch = cy + pad;
                msg_void_rect(card, c"setFrame:", rect(x, y, width, ch));
                y += ch + 18.0;
            } else {
                for (idx, app) in snap.apps.iter().enumerate() {
                    y = render_app_card(
                        parent,
                        x,
                        y,
                        width,
                        app,
                        idx,
                        snap.controller,
                        now,
                        is_busy,
                    );
                }
                y += 6.0;
            }

            // Compact latest operation status banner on Tab 1 if non-empty
            y = render_journal_card(parent, x, y, width, snap);
            y
        }
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn render_app_card(
        parent: Id,
        x: f64,
        y: f64,
        width: f64,
        app: &TrackedApp,
        idx: usize,
        controller: Id,
        now: u64,
        is_busy: bool,
    ) -> f64 {
        unsafe {
            let pad = 16.0;
            let inner_w = (width - pad * 2.0).max(120.0);
            let (badge_text, tone) = health_badge(&app.status);
            let card_border = match tone {
                UiTone::Green | UiTone::Neutral => col_border(),
                UiTone::Amber | UiTone::Red => tone_border(tone),
            };
            let card = make_view(parent, rect(x, y, width, 120.0), col_card());
            style_layer(card, 16.0, 1.0, Some(card_border));

            let mut cy = pad;
            let (pill_w, pill_h) = make_pill(
                card,
                width - pad - (inner_w * 0.48),
                cy,
                inner_w * 0.48,
                badge_text,
                tone,
            );
            // Re-align pill cleanly to right edge.
            let subviews = msg_id(card, c"subviews");
            let count = msg_u64(subviews, c"count");
            if count > 0 {
                let pill_view = msg_id_u64(subviews, c"objectAtIndex:", count - 1);
                msg_void_rect(
                    pill_view,
                    c"setFrame:",
                    rect(width - pad - pill_w, cy, pill_w, pill_h),
                );
            }

            let name_w = (inner_w - pill_w - 10.0).max(80.0);
            let title_str = if app.name.trim().is_empty() {
                app.bundle_id.as_str()
            } else {
                app.name.as_str()
            };
            let (_, _, name_h) = make_label_measured(
                card,
                pad,
                cy,
                name_w,
                title_str,
                system_font(17.5, FontWeight::Bold),
                col_text_primary(),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            cy += name_h.max(pill_h) + 4.0;

            let (_, _, bid_h) = make_label_measured(
                card,
                pad,
                cy,
                inner_w,
                &app.bundle_id,
                mono_font(12.0, FontWeight::Regular),
                col_text_secondary(),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            cy += bid_h + 10.0;

            make_view(card, rect(pad, cy, inner_w, 1.0), col_divider());
            cy += 11.0;

            let refresh_btn_w = 104.0;
            let refresh_btn_h = 38.0;
            let info_w = (inner_w - refresh_btn_w - 10.0).max(110.0);

            let rem_text = format_remaining(app.expires_at_unix, now);
            let rem_color = match tone {
                UiTone::Green | UiTone::Neutral => col_text_primary(),
                UiTone::Amber | UiTone::Red => tone_fg(tone),
            };
            let (_, _, rem_h) = make_label_measured(
                card,
                pad,
                cy,
                info_w,
                &rem_text,
                system_font(17.0, FontWeight::Bold),
                rem_color,
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );

            let exp_text = if app.expires_at_unix > 0 {
                let formatted = format_date_ru(
                    app.expires_at_unix,
                    local_tz_offset_secs(app.expires_at_unix),
                );
                if app.expires_at_unix <= now {
                    format!("Истёк: {formatted}")
                } else {
                    format!("До: {formatted}")
                }
            } else {
                "Дата окончания неизвестна".to_string()
            };
            let (_, _, exp_h) = make_label_measured(
                card,
                pad,
                cy + rem_h + 3.0,
                info_w,
                &exp_text,
                system_font(12.5, FontWeight::Regular),
                col_text_secondary(),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );

            let left_block_h = rem_h + 3.0 + exp_h;
            let btn_y = cy + ((left_block_h - refresh_btn_h) * 0.5).max(0.0);
            make_button(
                card,
                controller,
                rect(
                    width - pad - refresh_btn_w,
                    btn_y,
                    refresh_btn_w,
                    refresh_btn_h,
                ),
                "Продлить",
                c"refreshSingleApp:",
                idx as i64,
                col_btn_secondary(),
                Some(rgba(0.490, 0.412, 1.0, 0.45)),
                col_text_primary(),
                14.0,
                10.0,
                !is_busy,
            );

            cy += left_block_h.max(refresh_btn_h);

            if app.has_cached_ipa {
                cy += 8.0;
                let (_, _, c_h) = make_label_measured(
                    card,
                    pad,
                    cy,
                    inner_w,
                    "✓ Локальная копия .ipa сохранена для переподписи",
                    system_font(12.0, FontWeight::Medium),
                    col_cyan(),
                    0,
                    NS_TEXT_ALIGNMENT_LEFT,
                );
                cy += c_h;
            }

            let card_h = cy + pad;
            msg_void_rect(card, c"setFrame:", rect(x, y, width, card_h));
            y + card_h + 12.0
        }
    }

    unsafe fn render_settings_tab(
        parent: Id,
        x: f64,
        mut y: f64,
        width: f64,
        snap: &LayoutSnapshot,
        is_busy: bool,
    ) -> f64 {
        unsafe {
            let pad = 16.0;
            let inner_w = (width - pad * 2.0).max(120.0);

            // 1. Apple ID card
            y = render_section_header(parent, x, y, width, "APPLE ID");
            let apple_card = make_view(parent, rect(x, y, width, 120.0), col_card());
            style_layer(apple_card, 16.0, 1.0, Some(col_border()));
            let mut cy = pad;

            let (apple_status, apple_tone) = if snap.overview.session.valid {
                let email = snap
                    .overview
                    .session
                    .email_masked
                    .as_deref()
                    .unwrap_or("сессия сохранена");
                (format!("Активна ({email})"), UiTone::Green)
            } else {
                ("Требуется вход".to_string(), UiTone::Amber)
            };
            let dot_d = 8.0;
            let (_, _, st_h) = make_label_measured(
                apple_card,
                pad + dot_d + 8.0,
                cy,
                inner_w - dot_d - 8.0,
                &apple_status,
                system_font(15.5, FontWeight::Semibold),
                tone_fg(apple_tone),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            make_dot(
                apple_card,
                pad,
                cy + (st_h - dot_d) * 0.5,
                dot_d,
                tone_fg(apple_tone),
            );
            cy += st_h + 6.0;

            let (_, _, sm_h) = make_label_measured(
                apple_card,
                pad,
                cy,
                inner_w,
                &snap.overview.session.message,
                system_font(13.0, FontWeight::Regular),
                col_text_secondary(),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            cy += sm_h + 14.0;

            if snap.overview.session.exists {
                let gap = 10.0;
                let w1 = (inner_w - gap) * 0.62;
                let w2 = inner_w - gap - w1;
                make_button(
                    apple_card,
                    snap.controller,
                    rect(pad, cy, w1, 44.0),
                    "Войти заново",
                    c"promptAppleLogin:",
                    0,
                    col_btn_primary(),
                    None,
                    col_text_primary(),
                    14.5,
                    11.0,
                    !is_busy,
                );
                make_button(
                    apple_card,
                    snap.controller,
                    rect(pad + w1 + gap, cy, w2, 44.0),
                    "Выйти",
                    c"logoutApple:",
                    0,
                    col_btn_danger_bg(),
                    Some(col_btn_danger_border()),
                    tone_fg(UiTone::Red),
                    14.5,
                    11.0,
                    !is_busy,
                );
            } else {
                make_button(
                    apple_card,
                    snap.controller,
                    rect(pad, cy, inner_w, 44.0),
                    "Войти в Apple ID",
                    c"promptAppleLogin:",
                    0,
                    col_btn_primary(),
                    None,
                    col_text_primary(),
                    15.0,
                    11.0,
                    !is_busy,
                );
            }
            cy += 44.0 + pad;
            msg_void_rect(apple_card, c"setFrame:", rect(x, y, width, cy));
            y += cy + 18.0;

            // 2. Pairing File card
            y = render_section_header(parent, x, y, width, "PAIRING-ФАЙЛ УСТРОЙСТВА");
            let pair_card = make_view(parent, rect(x, y, width, 120.0), col_card());
            style_layer(pair_card, 16.0, 1.0, Some(col_border()));
            let mut py = pad;

            let (pair_status, pair_tone) = if snap.overview.pairing.valid {
                ("Загружен и проверен".to_string(), UiTone::Green)
            } else {
                ("Не загружен".to_string(), UiTone::Amber)
            };
            let (_, _, pst_h) = make_label_measured(
                pair_card,
                pad + dot_d + 8.0,
                py,
                inner_w - dot_d - 8.0,
                &pair_status,
                system_font(15.5, FontWeight::Semibold),
                tone_fg(pair_tone),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            make_dot(
                pair_card,
                pad,
                py + (pst_h - dot_d) * 0.5,
                dot_d,
                tone_fg(pair_tone),
            );
            py += pst_h + 6.0;

            let pair_detail = if let Some(udid) = &snap.overview.pairing.udid {
                let fname = snap
                    .overview
                    .pairing
                    .filename
                    .as_deref()
                    .unwrap_or("pairingFile.plist");
                format!("Файл: {fname}\nUDID: {udid}")
            } else {
                snap.overview.pairing.message.clone()
            };
            let (_, _, pd_h) = make_label_measured(
                pair_card,
                pad,
                py,
                inner_w,
                &pair_detail,
                mono_font(12.0, FontWeight::Regular),
                col_text_secondary(),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            py += pd_h + 14.0;

            make_button(
                pair_card,
                snap.controller,
                rect(pad, py, inner_w, 44.0),
                "Импортировать pairing-файл",
                c"pickPairing:",
                0,
                col_btn_secondary(),
                Some(col_btn_secondary_border()),
                col_text_primary(),
                14.5,
                11.0,
                !is_busy,
            );
            py += 44.0 + pad;
            msg_void_rect(pair_card, c"setFrame:", rect(x, y, width, py));
            y += py + 18.0;

            // 3. VPN Tunnel (LocalDevVPN / StosVPN / WireGuard) card
            y = render_section_header(parent, x, y, width, "VPN-ТУННЕЛЬ (LOCALDEVVPN / STOSVPN)");
            let vpn_card = make_view(parent, rect(x, y, width, 210.0), col_card());
            style_layer(vpn_card, 16.0, 1.0, Some(col_border()));
            let mut vy = pad;

            let (_, _, vh) = make_label_measured(
                vpn_card,
                pad,
                vy,
                inner_w,
                "LocalDevVPN: Tunnel IP обычно 10.7.1.1/32. Для связи укажите Device IP из настроек LocalDevVPN (обычно 10.7.0.1/32).",
                system_font(13.5, FontWeight::Regular),
                col_text_secondary(),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            vy += vh + 10.0;

            let current_ip = &snap.overview.settings.tunnel_ip;
            let ip_box = make_view(vpn_card, rect(pad, vy, inner_w, 46.0), col_input_bg());
            style_layer(ip_box, 10.0, 1.0, Some(col_btn_secondary_border()));
            make_label_measured(
                ip_box,
                14.0,
                13.0,
                inner_w - 28.0,
                &format!("Device IP: {current_ip}"),
                mono_font(15.0, FontWeight::Semibold),
                col_text_primary(),
                1,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            vy += 46.0 + 12.0;

            let gap = 10.0;
            let bw = (inner_w - gap) * 0.5;
            make_button(
                vpn_card,
                snap.controller,
                rect(pad, vy, bw, 44.0),
                "Изменить IP…",
                c"promptTunnelIp:",
                0,
                col_btn_primary(),
                None,
                col_text_primary(),
                14.5,
                11.0,
                !is_busy,
            );
            make_button(
                vpn_card,
                snap.controller,
                rect(pad + bw + gap, vy, bw, 44.0),
                "Проверить связь",
                c"testTunnel:",
                0,
                col_btn_secondary(),
                Some(col_btn_secondary_border()),
                col_cyan(),
                14.5,
                11.0,
                !is_busy,
            );
            vy += 44.0 + 12.0;

            let (_, _, ph) = make_label_measured(
                vpn_card,
                pad,
                vy,
                inner_w,
                "Быстрый выбор IP:",
                system_font(12.0, FontWeight::Medium),
                col_text_muted(),
                1,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            vy += ph + 8.0;

            let is_p1 = current_ip == "10.7.0.1";
            let is_p2 = current_ip == "10.7.0.2";
            make_button(
                vpn_card,
                snap.controller,
                rect(pad, vy, bw, 38.0),
                "10.7.0.1",
                c"presetTunnelIp:",
                1,
                if is_p1 {
                    rgba(0.435, 0.278, 0.961, 0.24)
                } else {
                    col_btn_secondary()
                },
                Some(if is_p1 {
                    col_accent()
                } else {
                    col_btn_secondary_border()
                }),
                col_text_primary(),
                14.0,
                10.0,
                !is_busy,
            );
            make_button(
                vpn_card,
                snap.controller,
                rect(pad + bw + gap, vy, bw, 38.0),
                "10.7.0.2",
                c"presetTunnelIp:",
                2,
                if is_p2 {
                    rgba(0.435, 0.278, 0.961, 0.24)
                } else {
                    col_btn_secondary()
                },
                Some(if is_p2 {
                    col_accent()
                } else {
                    col_btn_secondary_border()
                }),
                col_text_primary(),
                14.0,
                10.0,
                !is_busy,
            );
            vy += 38.0 + pad;
            msg_void_rect(vpn_card, c"setFrame:", rect(x, y, width, vy));
            y += vy + 18.0;

            // 4. Journal / Latest result card
            y = render_journal_card(parent, x, y, width, snap);
            y
        }
    }

    unsafe fn render_journal_card(
        parent: Id,
        x: f64,
        mut y: f64,
        width: f64,
        snap: &LayoutSnapshot,
    ) -> f64 {
        unsafe {
            y = render_section_header(parent, x, y, width, "ЖУРНАЛ");
            let pad = 16.0;
            let inner_w = (width - pad * 2.0).max(120.0);
            let card = make_view(parent, rect(x, y, width, 90.0), col_card_alt());
            style_layer(card, 16.0, 1.0, Some(tone_border(snap.log_tone)));

            let mut cy = pad;
            let dot_d = 8.0;
            let (_, _, th) = make_label_measured(
                card,
                pad + dot_d + 8.0,
                cy,
                inner_w - dot_d - 8.0,
                &snap.log_title,
                system_font(15.0, FontWeight::Semibold),
                col_text_primary(),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            make_dot(
                card,
                pad,
                cy + (th - dot_d) * 0.5,
                dot_d,
                tone_fg(snap.log_tone),
            );
            cy += th + 8.0;

            let (_, _, bh) = make_label_measured(
                card,
                pad,
                cy,
                inner_w,
                &snap.log_message,
                system_font(13.5, FontWeight::Regular),
                rgb(0.827, 0.855, 0.933),
                0,
                NS_TEXT_ALIGNMENT_LEFT,
            );
            cy += bh + pad;
            msg_void_rect(card, c"setFrame:", rect(x, y, width, cy));
            y + cy + 28.0
        }
    }

    // -----------------------------------------------------------------------
    // Native UIAlertController flows (Apple ID Login + Dynamic 2FA)
    // -----------------------------------------------------------------------

    fn present_apple_login_alert(controller: Id) {
        assert!(is_main_thread());
        if BUSY.load(Ordering::Acquire) {
            return;
        }
        unsafe {
            let alert = msg_alert_controller(
                ns_string("Вход в Apple ID"),
                ns_string("Пароль используется только для входа в Apple и не сохраняется."),
                UI_ALERT_CONTROLLER_STYLE_ALERT,
            );
            // Add Email field
            msg_void_ptr(alert, c"addTextFieldWithConfigurationHandler:", ptr::null());
            // Add Password field
            msg_void_ptr(alert, c"addTextFieldWithConfigurationHandler:", ptr::null());

            let fields = msg_id(alert, c"textFields");
            if !fields.is_null() && msg_u64(fields, c"count") >= 2 {
                let tf_email = msg_id_u64(fields, c"objectAtIndex:", 0);
                msg_void_id(tf_email, c"setPlaceholder:", ns_string("Apple ID (email)"));
                msg_void_i64(
                    tf_email,
                    c"setKeyboardType:",
                    UI_KEYBOARD_TYPE_EMAIL_ADDRESS,
                );
                msg_void_i64(
                    tf_email,
                    c"setAutocorrectionType:",
                    UI_TEXT_AUTOCORRECTION_NO,
                );
                msg_void_i64(
                    tf_email,
                    c"setAutocapitalizationType:",
                    UI_TEXT_AUTOCAPITALIZATION_NONE,
                );

                let tf_pass = msg_id_u64(fields, c"objectAtIndex:", 1);
                msg_void_id(tf_pass, c"setPlaceholder:", ns_string("Пароль Apple ID"));
                msg_void_bool(tf_pass, c"setSecureTextEntry:", true);
            }

            let ok_blk = LOGIN_OK_BLOCK.get_or_init(|| GlobalBlock::new(on_login_alert_submit));
            let cancel_blk =
                LOGIN_CANCEL_BLOCK.get_or_init(|| GlobalBlock::new(on_login_alert_cancel));

            let ok_act = msg_alert_action(
                ns_string("Войти"),
                UI_ALERT_ACTION_STYLE_DEFAULT,
                ok_blk.as_ptr(),
            );
            let cancel_act = msg_alert_action(
                ns_string("Отмена"),
                UI_ALERT_ACTION_STYLE_CANCEL,
                cancel_blk.as_ptr(),
            );
            msg_void_id(alert, c"addAction:", cancel_act);
            msg_void_id(alert, c"addAction:", ok_act);

            let retained = OwnedId::retain(alert);
            let old = {
                let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
                std::mem::replace(&mut *g, Some(retained))
            };
            drop(old);

            msg_void_present(controller, alert, true, ptr::null());
        }
    }

    unsafe extern "C" fn on_login_alert_submit(_block: *mut GlobalBlock, _action: Id) {
        assert!(is_main_thread());
        let alert = {
            let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        let Some(alert_owned) = alert else {
            return;
        };

        let (email, password) = unsafe {
            let fields = msg_id(alert_owned.as_id(), c"textFields");
            if fields.is_null() || msg_u64(fields, c"count") < 2 {
                return;
            }
            let tf_email = msg_id_u64(fields, c"objectAtIndex:", 0);
            let tf_pass = msg_id_u64(fields, c"objectAtIndex:", 1);
            let em = ns_string_to_rust(msg_id(tf_email, c"text"));
            let pw = ns_string_to_rust(msg_id(tf_pass, c"text"));
            // Immediately wipe password from the UIKit text field!
            msg_void_id(tf_pass, c"setText:", ns_string(""));
            (em.trim().to_string(), pw)
        };
        drop(alert_owned);

        if email.is_empty() || !email.contains('@') || password.is_empty() {
            with_main_ui(|ui| {
                ui.log_tone = UiTone::Red;
                ui.log_title = "Ошибка входа".to_string();
                ui.log_message = "Укажите корректный email и пароль Apple ID.".to_string();
                ui.needs_rebuild = true;
            });
            perform_rebuild();
            return;
        }

        let ctrl = with_main_ui(|ui| ui.controller.as_ref().map(OwnedId::as_id));
        if let Some(ctrl_id) = ctrl {
            start_apple_login(ctrl_id, email, password);
        }
    }

    unsafe extern "C" fn on_login_alert_cancel(_block: *mut GlobalBlock, _action: Id) {
        assert!(is_main_thread());
        let old = {
            let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        drop(old);
    }

    fn save_tunnel_ip_value(ip: &str) {
        assert!(is_main_thread());
        let current_settings = with_main_ui(|ui| ui.overview.settings.clone());
        let trimmed = ip.trim();
        let eng = engine();
        let res = eng.save_settings(
            trimmed,
            current_settings.renew_before_hours,
            &current_settings.anisette_url,
        );
        let overview = eng.get_overview();
        with_main_ui(|ui| {
            ui.overview = overview;
            match res {
                Ok(saved) => {
                    ui.log_tone = UiTone::Green;
                    ui.log_title = "Device IP сохранён".to_string();
                    ui.log_message = format!(
                        "Адрес устройства: {}. Нажмите «Проверить связь» для проверки.",
                        saved.tunnel_ip
                    );
                }
                Err(err) => {
                    ui.log_tone = UiTone::Red;
                    ui.log_title = "Некорректный IP-адрес".to_string();
                    ui.log_message = sanitize_message(&err);
                }
            }
            ui.needs_rebuild = true;
        });
        perform_rebuild();
    }

    fn present_tunnel_ip_alert(controller: Id) {
        assert!(is_main_thread());
        if BUSY.load(Ordering::Acquire) {
            return;
        }
        let current_ip = with_main_ui(|ui| ui.overview.settings.tunnel_ip.clone());
        unsafe {
            let alert = msg_alert_controller(
                ns_string("IP устройства"),
                ns_string(
                    "Введите Device IP из настроек LocalDevVPN, например 10.7.0.1/32. Tunnel IP 10.7.1.1/32 — отдельный адрес.",
                ),
                UI_ALERT_CONTROLLER_STYLE_ALERT,
            );
            msg_void_ptr(alert, c"addTextFieldWithConfigurationHandler:", ptr::null());
            let fields = msg_id(alert, c"textFields");
            if !fields.is_null() && msg_u64(fields, c"count") >= 1 {
                let tf = msg_id_u64(fields, c"objectAtIndex:", 0);
                msg_void_id(tf, c"setPlaceholder:", ns_string("10.7.0.1"));
                msg_void_id(tf, c"setText:", ns_string(&current_ip));
                msg_void_i64(
                    tf,
                    c"setKeyboardType:",
                    UI_KEYBOARD_TYPE_NUMBERS_AND_PUNCTUATION,
                );
                msg_void_i64(tf, c"setAutocorrectionType:", UI_TEXT_AUTOCORRECTION_NO);
                msg_void_i64(
                    tf,
                    c"setAutocapitalizationType:",
                    UI_TEXT_AUTOCAPITALIZATION_NONE,
                );
            }

            // The editor is an alert, so its keyboard is managed by UIKit.
            // A downward swipe on the alert dismisses the keyboard without
            // losing the value; tapping the field brings it back.
            let gesture_alloc = msg_id(class(c"UISwipeGestureRecognizer"), c"alloc");
            let gesture = OwnedId::from_owned(msg_id_id_sel(
                gesture_alloc,
                c"initWithTarget:action:",
                controller,
                sel(c"dismissTunnelKeyboard:"),
            ));
            msg_void_i64(
                gesture.as_id(),
                c"setDirection:",
                UI_SWIPE_GESTURE_DIRECTION_DOWN as i64,
            );
            msg_void_bool(gesture.as_id(), c"setCancelsTouchesInView:", false);
            msg_void_id(
                msg_id(alert, c"view"),
                c"addGestureRecognizer:",
                gesture.as_id(),
            );

            let ok_blk = TUNNEL_IP_OK_BLOCK.get_or_init(|| GlobalBlock::new(on_tunnel_ip_submit));
            let cancel_blk =
                TUNNEL_IP_CANCEL_BLOCK.get_or_init(|| GlobalBlock::new(on_tunnel_ip_cancel));

            msg_void_id(
                alert,
                c"addAction:",
                msg_alert_action(
                    ns_string("Отмена"),
                    UI_ALERT_ACTION_STYLE_CANCEL,
                    cancel_blk.as_ptr(),
                ),
            );
            msg_void_id(
                alert,
                c"addAction:",
                msg_alert_action(
                    ns_string("Готово"),
                    UI_ALERT_ACTION_STYLE_DEFAULT,
                    ok_blk.as_ptr(),
                ),
            );

            let retained = OwnedId::retain(alert);
            let old = {
                let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
                std::mem::replace(&mut *g, Some(retained))
            };
            drop(old);

            msg_void_present(controller, alert, true, ptr::null());
        }
    }

    unsafe extern "C" fn on_tunnel_ip_submit(_block: *mut GlobalBlock, _action: Id) {
        assert!(is_main_thread());
        let alert = {
            let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        let ip = alert
            .as_ref()
            .map(|a| unsafe {
                let fields = msg_id(a.as_id(), c"textFields");
                if fields.is_null() || msg_u64(fields, c"count") < 1 {
                    return String::new();
                }
                let tf = msg_id_u64(fields, c"objectAtIndex:", 0);
                ns_string_to_rust(msg_id(tf, c"text"))
            })
            .unwrap_or_default();
        drop(alert);
        save_tunnel_ip_value(&ip);
    }

    unsafe extern "C" fn on_tunnel_ip_cancel(_block: *mut GlobalBlock, _action: Id) {
        assert!(is_main_thread());
        let old = {
            let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        drop(old);
    }

    fn present_tfa_alert(
        controller: Id,
        prompt: TwoFactorPrompt,
        reply_tx: mpsc::Sender<TwoFactorAnswer>,
    ) {
        assert!(is_main_thread());
        {
            let mut slot = PENDING_TFA_REPLY.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(prev) = slot.replace(reply_tx) {
                let _ = prev.send(TwoFactorAnswer::Cancel);
            }
        }

        let body = if prompt.retry {
            match prompt.last_error.as_deref() {
                Some(err) if !err.is_empty() => {
                    format!("Неверный код ({err}). Введите 6-значный код подтверждения ещё раз.")
                }
                _ => "Неверный код. Введите 6-значный код подтверждения ещё раз.".to_string(),
            }
        } else if !prompt.message.trim().is_empty() {
            prompt.message
        } else if prompt.sms {
            "Введите 6-значный код подтверждения из SMS.".to_string()
        } else {
            "Введите 6-значный код подтверждения с доверенного устройства Apple.".to_string()
        };

        unsafe {
            let alert = msg_alert_controller(
                ns_string("Код подтверждения (2FA)"),
                ns_string(&body),
                UI_ALERT_CONTROLLER_STYLE_ALERT,
            );
            msg_void_ptr(alert, c"addTextFieldWithConfigurationHandler:", ptr::null());
            let fields = msg_id(alert, c"textFields");
            if !fields.is_null() && msg_u64(fields, c"count") >= 1 {
                let tf = msg_id_u64(fields, c"objectAtIndex:", 0);
                msg_void_id(tf, c"setPlaceholder:", ns_string("123456"));
                msg_void_i64(
                    tf,
                    c"setKeyboardType:",
                    UI_KEYBOARD_TYPE_ASCII_CAPABLE_NUMBER_PAD,
                );
            }

            let ok_blk = TFA_OK_BLOCK.get_or_init(|| GlobalBlock::new(on_tfa_submit));
            let resend_blk = TFA_RESEND_BLOCK.get_or_init(|| GlobalBlock::new(on_tfa_resend));
            let cancel_blk = TFA_CANCEL_BLOCK.get_or_init(|| GlobalBlock::new(on_tfa_cancel));

            msg_void_id(
                alert,
                c"addAction:",
                msg_alert_action(
                    ns_string("Подтвердить"),
                    UI_ALERT_ACTION_STYLE_DEFAULT,
                    ok_blk.as_ptr(),
                ),
            );
            msg_void_id(
                alert,
                c"addAction:",
                msg_alert_action(
                    ns_string("Отправить снова"),
                    UI_ALERT_ACTION_STYLE_DEFAULT,
                    resend_blk.as_ptr(),
                ),
            );
            msg_void_id(
                alert,
                c"addAction:",
                msg_alert_action(
                    ns_string("Отмена"),
                    UI_ALERT_ACTION_STYLE_CANCEL,
                    cancel_blk.as_ptr(),
                ),
            );

            let retained = OwnedId::retain(alert);
            let old = {
                let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
                std::mem::replace(&mut *g, Some(retained))
            };
            drop(old);

            msg_void_present(controller, alert, true, ptr::null());
        }
    }

    unsafe extern "C" fn on_tfa_submit(_block: *mut GlobalBlock, _action: Id) {
        assert!(is_main_thread());
        let alert = {
            let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        let tx = {
            let mut s = PENDING_TFA_REPLY.lock().unwrap_or_else(|e| e.into_inner());
            s.take()
        };
        let code = alert
            .as_ref()
            .map(|a| unsafe {
                let fields = msg_id(a.as_id(), c"textFields");
                if fields.is_null() || msg_u64(fields, c"count") < 1 {
                    return String::new();
                }
                let tf = msg_id_u64(fields, c"objectAtIndex:", 0);
                let txt = ns_string_to_rust(msg_id(tf, c"text"));
                msg_void_id(tf, c"setText:", ns_string(""));
                txt.trim().to_string()
            })
            .unwrap_or_default();
        drop(alert);
        if let Some(sender) = tx {
            let answer = if code.is_empty() {
                TwoFactorAnswer::Cancel
            } else {
                TwoFactorAnswer::Code(code)
            };
            let _ = sender.send(answer);
        }
    }

    unsafe extern "C" fn on_tfa_resend(_block: *mut GlobalBlock, _action: Id) {
        assert!(is_main_thread());
        let old = {
            let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        drop(old);
        let tx = {
            let mut s = PENDING_TFA_REPLY.lock().unwrap_or_else(|e| e.into_inner());
            s.take()
        };
        if let Some(sender) = tx {
            let _ = sender.send(TwoFactorAnswer::Resend);
        }
    }

    unsafe extern "C" fn on_tfa_cancel(_block: *mut GlobalBlock, _action: Id) {
        assert!(is_main_thread());
        let old = {
            let mut g = ACTIVE_ALERT.0.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        drop(old);
        let tx = {
            let mut s = PENDING_TFA_REPLY.lock().unwrap_or_else(|e| e.into_inner());
            s.take()
        };
        if let Some(sender) = tx {
            let _ = sender.send(TwoFactorAnswer::Cancel);
        }
    }

    // -----------------------------------------------------------------------
    // Native Document Picker (IPA + Pairing File)
    // -----------------------------------------------------------------------

    fn present_document_picker(controller: Id, mode: PickerMode) {
        assert!(is_main_thread());
        if BUSY.load(Ordering::Acquire) {
            return;
        }
        with_main_ui(|ui| ui.picker_mode = mode);
        unsafe {
            let types = match mode {
                PickerMode::Ipa => {
                    uttype_array(&["com.apple.itunes.ipa", "public.archive", "public.data"])
                }
                PickerMode::Pairing => uttype_array(&[
                    "com.bromhobit.sidebox.mobiledevicepairing",
                    "com.apple.plist",
                    "public.data",
                    "public.item",
                ]),
            };
            let raw = msg_id(class(c"UIDocumentPickerViewController"), c"alloc");
            let picker = OwnedId::from_owned(msg_id_id_bool(
                raw,
                c"initForOpeningContentTypes:asCopy:",
                types,
                true,
            ));
            msg_void_id(picker.as_id(), c"setDelegate:", controller);
            msg_void_bool(picker.as_id(), c"setAllowsMultipleSelection:", false);
            msg_void_present(controller, picker.as_id(), true, ptr::null());
        }
    }

    // -----------------------------------------------------------------------
    // Background Engine Operations (100% in-process, zero subprocesses)
    // -----------------------------------------------------------------------

    fn begin_busy(title: &str) -> bool {
        assert!(is_main_thread());
        if BUSY.swap(true, Ordering::AcqRel) {
            let rc = with_main_ui(|ui| ui.refresh_control.as_ref().map(OwnedId::as_id));
            if let Some(rc_id) = rc {
                unsafe {
                    if msg_bool(rc_id, c"isRefreshing") {
                        msg_void(rc_id, c"endRefreshing");
                    }
                }
            }
            return false;
        }
        with_main_ui(|ui| {
            ui.busy_title = Some(title.to_string());
            ui.busy_progress = 5;
            ui.needs_rebuild = true;
        });
        perform_rebuild();
        true
    }

    fn start_scan_apps(controller: Id) {
        if !begin_busy("Загружаем список приложений…") {
            return;
        }
        let ctrl_addr = unsafe { OwnedId::retain(controller) }.into_raw_addr();
        let eng = engine();
        std::thread::spawn(move || {
            let _pool = AutoreleasePool::new();
            let ctrl = unsafe { OwnedId::from_owned(ctrl_addr as Id) };
            let overview = eng.get_overview();
            let result = if overview.pairing.valid {
                eng.list_apps()
            } else {
                Ok(Vec::new())
            };
            push_event_and_wake(ctrl.as_id(), WorkerEvent::AppsLoaded { overview, result });
        });
    }

    fn start_test_tunnel(controller: Id) {
        if !begin_busy("Проверяем соединение с туннелем…") {
            return;
        }
        let ctrl_addr = unsafe { OwnedId::retain(controller) }.into_raw_addr();
        let eng = engine();
        std::thread::spawn(move || {
            let _pool = AutoreleasePool::new();
            let ctrl = unsafe { OwnedId::from_owned(ctrl_addr as Id) };
            let result = eng.test_tunnel();
            let overview = eng.get_overview();
            push_event_and_wake(ctrl.as_id(), WorkerEvent::TunnelTested { overview, result });
        });
    }

    fn start_apple_login(controller: Id, email: String, password: String) {
        if !begin_busy("Подключаемся к Apple ID…") {
            return;
        }
        let ctrl_addr = unsafe { OwnedId::retain(controller) }.into_raw_addr();
        let eng = engine();
        std::thread::spawn(move || {
            let _pool = AutoreleasePool::new();
            let ctrl = unsafe { OwnedId::from_owned(ctrl_addr as Id) };
            let cb_ctrl_addr = unsafe { OwnedId::retain(ctrl.as_id()) }.into_raw_addr();
            struct RetainedSend(usize);
            impl Drop for RetainedSend {
                fn drop(&mut self) {
                    let _pool = AutoreleasePool::new();
                    let _owned = unsafe { OwnedId::from_owned(self.0 as Id) };
                }
            }
            let cb_ctrl = RetainedSend(cb_ctrl_addr);

            let res = eng.login_apple(&email, password, move |prompt| {
                let (tx, rx) = mpsc::channel();
                push_event_and_wake(
                    cb_ctrl.0 as Id,
                    WorkerEvent::TwoFactorRequest {
                        prompt,
                        reply_tx: tx,
                    },
                );
                rx.recv().unwrap_or(TwoFactorAnswer::Cancel)
            });

            let overview = eng.get_overview();
            match res {
                Ok(masked) => push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps: None,
                        ok: true,
                        title: "Вход выполнен".to_string(),
                        message: format!("Сессия Apple ID активна ({masked})."),
                    },
                ),
                Err(err) => push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps: None,
                        ok: false,
                        title: "Ошибка входа Apple ID".to_string(),
                        message: sanitize_message(&err),
                    },
                ),
            }
        });
    }

    fn start_logout_apple(controller: Id) {
        if !begin_busy("Выходим из Apple ID…") {
            return;
        }
        let ctrl_addr = unsafe { OwnedId::retain(controller) }.into_raw_addr();
        let eng = engine();
        std::thread::spawn(move || {
            let _pool = AutoreleasePool::new();
            let ctrl = unsafe { OwnedId::from_owned(ctrl_addr as Id) };
            let res = eng.logout_apple();
            let overview = eng.get_overview();
            match res {
                Ok(()) => push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps: None,
                        ok: true,
                        title: "Сессия удалена".to_string(),
                        message: "Вы вышли из учётной записи Apple ID.".to_string(),
                    },
                ),
                Err(err) => push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps: None,
                        ok: false,
                        title: "Ошибка выхода".to_string(),
                        message: sanitize_message(&err),
                    },
                ),
            }
        });
    }

    fn start_refresh_single(controller: Id, bundle_id: String) {
        if !begin_busy(&format!("Продлеваем {bundle_id}…")) {
            return;
        }
        let ctrl_addr = unsafe { OwnedId::retain(controller) }.into_raw_addr();
        let eng = engine();
        std::thread::spawn(move || {
            let _pool = AutoreleasePool::new();
            let ctrl = unsafe { OwnedId::from_owned(ctrl_addr as Id) };
            let cb_ctrl_addr = unsafe { OwnedId::retain(ctrl.as_id()) }.into_raw_addr();
            struct RetainedSend(usize);
            impl Drop for RetainedSend {
                fn drop(&mut self) {
                    let _pool = AutoreleasePool::new();
                    let _owned = unsafe { OwnedId::from_owned(self.0 as Id) };
                }
            }
            let cb_ctrl = RetainedSend(cb_ctrl_addr);

            let res = eng.refresh_app(&bundle_id, move |update| {
                push_event_and_wake(cb_ctrl.0 as Id, WorkerEvent::Progress(update));
            });
            let apps = eng.list_apps().ok();
            let overview = eng.get_overview();
            match res {
                Ok(out) => push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps,
                        ok: true,
                        title: format!("Продлено: {}", out.app_name),
                        message: out.message,
                    },
                ),
                Err(err) => push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps,
                        ok: false,
                        title: "Ошибка продления".to_string(),
                        message: sanitize_message(&err),
                    },
                ),
            }
        });
    }

    fn start_refresh_all(controller: Id) {
        if !begin_busy("Продлеваем все приложения…") {
            return;
        }
        let ctrl_addr = unsafe { OwnedId::retain(controller) }.into_raw_addr();
        let eng = engine();
        std::thread::spawn(move || {
            let _pool = AutoreleasePool::new();
            let ctrl = unsafe { OwnedId::from_owned(ctrl_addr as Id) };
            let cb_ctrl_addr = unsafe { OwnedId::retain(ctrl.as_id()) }.into_raw_addr();
            struct RetainedSend(usize);
            impl Drop for RetainedSend {
                fn drop(&mut self) {
                    let _pool = AutoreleasePool::new();
                    let _owned = unsafe { OwnedId::from_owned(self.0 as Id) };
                }
            }
            let cb_ctrl = RetainedSend(cb_ctrl_addr);

            let res = eng.refresh_all(move |update| {
                push_event_and_wake(cb_ctrl.0 as Id, WorkerEvent::Progress(update));
            });
            let apps = eng.list_apps().ok();
            let overview = eng.get_overview();
            match res {
                Ok(out) => push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps,
                        ok: out.failed == 0,
                        title: if out.failed == 0 {
                            "Продление завершено".to_string()
                        } else {
                            "Продлено с ошибками".to_string()
                        },
                        message: out.message,
                    },
                ),
                Err(err) => push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps,
                        ok: false,
                        title: "Ошибка продления".to_string(),
                        message: sanitize_message(&err),
                    },
                ),
            }
        });
    }

    fn start_handle_url(controller: Id, url: Id, forced_mode: Option<PickerMode>) {
        assert!(is_main_thread());
        if url.is_null() {
            return;
        }
        if !begin_busy("Обработка выбранного файла…") {
            return;
        }
        let url_addr = unsafe { OwnedId::retain(url) }.into_raw_addr();
        let ctrl_addr = unsafe { OwnedId::retain(controller) }.into_raw_addr();
        let eng = engine();

        std::thread::spawn(move || {
            let _pool = AutoreleasePool::new();
            let ctrl = unsafe { OwnedId::from_owned(ctrl_addr as Id) };
            let url_owned = unsafe { OwnedId::from_owned(url_addr as Id) };
            let _scope = unsafe { SecurityScopedAccess::begin(url_owned.as_id()) };

            let Some(path) = (unsafe { url_to_path(url_owned.as_id()) }) else {
                let overview = eng.get_overview();
                push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps: None,
                        ok: false,
                        title: "Неподдерживаемая ссылка".to_string(),
                        message: "Не удалось получить путь к файлу из URL.".to_string(),
                    },
                );
                return;
            };

            let mode = forced_mode.unwrap_or_else(|| match classify_incoming_file(&path) {
                IncomingFileKind::Ipa => PickerMode::Ipa,
                IncomingFileKind::Pairing => PickerMode::Pairing,
                IncomingFileKind::Unsupported => PickerMode::Ipa,
            });

            if forced_mode.is_none()
                && classify_incoming_file(&path) == IncomingFileKind::Unsupported
            {
                let overview = eng.get_overview();
                push_event_and_wake(
                    ctrl.as_id(),
                    WorkerEvent::OperationDone {
                        overview,
                        apps: None,
                        ok: false,
                        title: "Неподдерживаемый формат".to_string(),
                        message: "Откройте файл .ipa (для установки) или .mobiledevicepairing / .plist (для pairing)."
                            .to_string(),
                    },
                );
                return;
            }

            match mode {
                PickerMode::Ipa => {
                    let cb_ctrl_addr = unsafe { OwnedId::retain(ctrl.as_id()) }.into_raw_addr();
                    struct RetainedSend(usize);
                    impl Drop for RetainedSend {
                        fn drop(&mut self) {
                            let _pool = AutoreleasePool::new();
                            let _owned = unsafe { OwnedId::from_owned(self.0 as Id) };
                        }
                    }
                    let cb_ctrl = RetainedSend(cb_ctrl_addr);
                    let res = eng.install_ipa(&path, move |update| {
                        push_event_and_wake(cb_ctrl.0 as Id, WorkerEvent::Progress(update));
                    });
                    let apps = eng.list_apps().ok();
                    let overview = eng.get_overview();
                    match res {
                        Ok(out) => push_event_and_wake(
                            ctrl.as_id(),
                            WorkerEvent::OperationDone {
                                overview,
                                apps,
                                ok: true,
                                title: format!("Установлено: {}", out.app_name),
                                message: out.message,
                            },
                        ),
                        Err(err) => push_event_and_wake(
                            ctrl.as_id(),
                            WorkerEvent::OperationDone {
                                overview,
                                apps,
                                ok: false,
                                title: "Ошибка установки .ipa".to_string(),
                                message: sanitize_message(&err),
                            },
                        ),
                    }
                }
                PickerMode::Pairing => {
                    let res = eng.import_pairing_file(&path);
                    let overview = eng.get_overview();
                    let apps = if res.is_ok() {
                        eng.list_apps().ok()
                    } else {
                        None
                    };
                    match res {
                        Ok(summary) => push_event_and_wake(
                            ctrl.as_id(),
                            WorkerEvent::OperationDone {
                                overview,
                                apps,
                                ok: true,
                                title: "Pairing-файл импортирован".to_string(),
                                message: summary.message,
                            },
                        ),
                        Err(err) => push_event_and_wake(
                            ctrl.as_id(),
                            WorkerEvent::OperationDone {
                                overview,
                                apps: None,
                                ok: false,
                                title: "Ошибка импорта pairing".to_string(),
                                message: sanitize_message(&err),
                            },
                        ),
                    }
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Objective-C Method Implementations
    // -----------------------------------------------------------------------

    unsafe extern "C" fn delegate_window(_this: Id, _cmd: Sel) -> Id {
        assert!(is_main_thread());
        let guard = DELEGATE_WINDOW.0.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .map(OwnedId::as_id)
            .unwrap_or(ptr::null_mut())
    }

    unsafe extern "C" fn delegate_set_window(_this: Id, _cmd: Sel, window: Id) {
        assert!(is_main_thread());
        let new_owned = if window.is_null() {
            None
        } else {
            Some(unsafe { OwnedId::retain(window) })
        };
        let old = {
            let mut guard = DELEGATE_WINDOW.0.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *guard, new_owned)
        };
        drop(old);
    }

    unsafe extern "C" fn delegate_did_finish_launching(
        _this: Id,
        _cmd: Sel,
        _app: Id,
        _opts: Id,
    ) -> bool {
        // Initialize sandbox engine right away so Documents/ exists.
        let _ = engine();
        unsafe {
            let screen = msg_id(class(c"UIScreen"), c"mainScreen");
            let bounds = msg_rect(screen, c"bounds");

            let window = alloc_init_frame(c"UIWindow", bounds);
            let window_id = window.as_id();
            msg_void_i64(
                window_id,
                c"setOverrideUserInterfaceStyle:",
                UI_USER_INTERFACE_STYLE_DARK,
            );
            msg_void_id(window_id, c"setBackgroundColor:", col_bg());

            let controller = alloc_init(c"SideboxController");
            let controller_id = controller.as_id();

            {
                let mut guard = DELEGATE_WINDOW.0.lock().unwrap_or_else(|e| e.into_inner());
                *guard = Some(window);
            }
            with_main_ui(|ui| {
                ui.controller = Some(controller);
            });

            msg_void_id(window_id, c"setRootViewController:", controller_id);
            msg_void(window_id, c"makeKeyAndVisible");

            let pending_url = {
                let mut slot = PENDING_OPEN_URL.lock().unwrap_or_else(|e| e.into_inner());
                slot.take()
            };
            if let Some(addr) = pending_url {
                let owned_url = OwnedId::from_owned(addr as Id);
                start_handle_url(controller_id, owned_url.as_id(), None);
            } else {
                start_scan_apps(controller_id);
            }
        }
        true
    }

    unsafe extern "C" fn delegate_open_url(
        _this: Id,
        _cmd: Sel,
        _app: Id,
        url: Id,
        _options: Id,
    ) -> bool {
        if url.is_null() {
            return false;
        }
        let ctrl = with_main_ui(|ui| ui.controller.as_ref().map(OwnedId::as_id));
        if let Some(ctrl_id) = ctrl {
            // Switch to relevant tab cleanly before starting file handling.
            let target_tab = unsafe { url_to_path(url) }
                .map(|p| match classify_incoming_file(&p) {
                    IncomingFileKind::Pairing => ActiveTab::Settings,
                    _ => ActiveTab::Apps,
                })
                .unwrap_or(ActiveTab::Apps);
            with_main_ui(|ui| {
                ui.active_tab = target_tab;
                ui.needs_rebuild = true;
            });
            if BUSY.load(Ordering::Acquire) {
                let retained = unsafe { OwnedId::retain(url) }.into_raw_addr();
                let mut slot = PENDING_OPEN_URL.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(old_addr) = slot.replace(retained) {
                    let _drop_old = unsafe { OwnedId::from_owned(old_addr as Id) };
                }
            } else {
                start_handle_url(ctrl_id, url, None);
            }
            true
        } else {
            let retained = unsafe { OwnedId::retain(url) }.into_raw_addr();
            let mut slot = PENDING_OPEN_URL.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(old_addr) = slot.replace(retained) {
                let _drop_old = unsafe { OwnedId::from_owned(old_addr as Id) };
            }
            true
        }
    }

    unsafe extern "C" fn controller_preferred_status_bar_style(_this: Id, _cmd: Sel) -> i64 {
        UI_STATUS_BAR_STYLE_LIGHT_CONTENT
    }

    unsafe extern "C" fn controller_view_did_load(this: Id, _cmd: Sel) {
        unsafe {
            msg_super_void(this, class(c"UIViewController"), c"viewDidLoad");
            msg_void_i64(
                this,
                c"setOverrideUserInterfaceStyle:",
                UI_USER_INTERFACE_STYLE_DARK,
            );
            let root_view = msg_id(this, c"view");
            msg_void_id(root_view, c"setBackgroundColor:", col_bg());

            let bounds = msg_rect(root_view, c"bounds");
            let scroll = alloc_init_frame(c"UIScrollView", bounds);
            let scroll_id = scroll.as_id();
            msg_void_id(scroll_id, c"setBackgroundColor:", col_bg());
            msg_void_bool(scroll_id, c"setAlwaysBounceVertical:", true);
            msg_void_bool(scroll_id, c"setShowsVerticalScrollIndicator:", true);
            msg_void_i64(
                scroll_id,
                c"setIndicatorStyle:",
                UI_SCROLL_INDICATOR_STYLE_WHITE,
            );
            msg_void_i64(
                scroll_id,
                c"setKeyboardDismissMode:",
                UI_SCROLL_KEYBOARD_DISMISS_ON_DRAG,
            );
            msg_void_i64(
                scroll_id,
                c"setContentInsetAdjustmentBehavior:",
                UI_CONTENT_INSET_ADJUSTMENT_ALWAYS,
            );
            msg_void_id(root_view, c"addSubview:", scroll_id);

            let content = alloc_init_frame(c"UIView", rect(0.0, 0.0, bounds.size.width, 0.0));
            let content_id = content.as_id();
            msg_void_id(content_id, c"setBackgroundColor:", rgba(0.0, 0.0, 0.0, 0.0));
            msg_void_id(scroll_id, c"addSubview:", content_id);

            let refresh_ctl = alloc_init(c"UIRefreshControl");
            let rc_id = refresh_ctl.as_id();
            msg_void_id(rc_id, c"setTintColor:", col_accent());
            msg_void_target_action(
                rc_id,
                c"addTarget:action:forControlEvents:",
                this,
                sel(c"handlePullToRefresh:"),
                UI_CONTROL_EVENT_VALUE_CHANGED,
            );
            msg_void_id(scroll_id, c"setRefreshControl:", rc_id);

            with_main_ui(|ui| {
                ui.scroll_view = Some(scroll);
                ui.content_view = Some(content);
                ui.refresh_control = Some(refresh_ctl);
                ui.needs_rebuild = true;
            });
        }
    }

    unsafe extern "C" fn controller_view_did_layout_subviews(this: Id, _cmd: Sel) {
        unsafe {
            msg_super_void(this, class(c"UIViewController"), c"viewDidLayoutSubviews");
            if REBUILDING.load(Ordering::Acquire) {
                return;
            }
            let root_view = msg_id(this, c"view");
            if root_view.is_null() {
                return;
            }
            let bounds = msg_rect(root_view, c"bounds");
            let safe = msg_insets(root_view, c"safeAreaInsets");

            let (scroll_id, should_rebuild) = with_main_ui(|ui| {
                let sv = ui.scroll_view.as_ref().map(OwnedId::as_id);
                let width_changed = (bounds.size.width - ui.last_layout_width).abs() > 0.5;
                let insets_changed = (safe.left - ui.last_safe_lr.0).abs() > 0.5
                    || (safe.right - ui.last_safe_lr.1).abs() > 0.5;
                (sv, ui.needs_rebuild || width_changed || insets_changed)
            });

            if let Some(sv) = scroll_id {
                msg_void_rect(sv, c"setFrame:", bounds);
            }
            if should_rebuild {
                perform_rebuild();
            }
        }
    }

    unsafe extern "C" fn controller_safe_area_did_change(this: Id, _cmd: Sel) {
        unsafe {
            msg_super_void(
                this,
                class(c"UIViewController"),
                c"viewSafeAreaInsetsDidChange",
            );
        }
        if REBUILDING.load(Ordering::Acquire) {
            return;
        }
        with_main_ui(|ui| ui.needs_rebuild = true);
        perform_rebuild();
    }

    unsafe extern "C" fn controller_select_tab_apps(this: Id, _cmd: Sel, _sender: Id) {
        with_main_ui(|ui| {
            ui.active_tab = ActiveTab::Apps;
            ui.needs_rebuild = true;
        });
        perform_rebuild();
        start_scan_apps(this);
    }

    unsafe extern "C" fn controller_select_tab_settings(_this: Id, _cmd: Sel, _sender: Id) {
        with_main_ui(|ui| {
            ui.active_tab = ActiveTab::Settings;
            ui.needs_rebuild = true;
        });
        perform_rebuild();
    }

    unsafe extern "C" fn controller_pull_to_refresh(this: Id, _cmd: Sel, _sender: Id) {
        start_scan_apps(this);
    }

    unsafe extern "C" fn controller_pick_ipa(this: Id, _cmd: Sel, _sender: Id) {
        present_document_picker(this, PickerMode::Ipa);
    }

    unsafe extern "C" fn controller_pick_pairing(this: Id, _cmd: Sel, _sender: Id) {
        present_document_picker(this, PickerMode::Pairing);
    }

    unsafe extern "C" fn controller_refresh_all(this: Id, _cmd: Sel, _sender: Id) {
        start_refresh_all(this);
    }

    unsafe extern "C" fn controller_refresh_single(this: Id, _cmd: Sel, sender: Id) {
        if sender.is_null() {
            return;
        }
        let idx = unsafe { msg_i64(sender, c"tag") };
        if idx < 0 {
            return;
        }
        let bundle = with_main_ui(|ui| ui.apps.get(idx as usize).map(|a| a.bundle_id.clone()));
        if let Some(bundle_id) = bundle {
            start_refresh_single(this, bundle_id);
        }
    }

    unsafe extern "C" fn controller_prompt_apple_login(this: Id, _cmd: Sel, _sender: Id) {
        present_apple_login_alert(this);
    }

    unsafe extern "C" fn controller_logout_apple(this: Id, _cmd: Sel, _sender: Id) {
        start_logout_apple(this);
    }

    unsafe extern "C" fn controller_prompt_tunnel_ip(this: Id, _cmd: Sel, _sender: Id) {
        present_tunnel_ip_alert(this);
    }

    unsafe extern "C" fn controller_dismiss_tunnel_keyboard(_this: Id, _cmd: Sel, gesture: Id) {
        if !gesture.is_null() {
            unsafe {
                let view = msg_id(gesture, c"view");
                if !view.is_null() {
                    let _ = msg_bool_bool(view, c"endEditing:", true);
                }
            }
        }
    }

    unsafe extern "C" fn controller_preset_tunnel_ip(_this: Id, _cmd: Sel, sender: Id) {
        if sender.is_null() || BUSY.load(Ordering::Acquire) {
            return;
        }
        let ip = match unsafe { msg_i64(sender, c"tag") } {
            1 => "10.7.0.1",
            2 => "10.7.0.2",
            _ => return,
        };
        save_tunnel_ip_value(ip);
    }

    unsafe extern "C" fn controller_test_tunnel(this: Id, _cmd: Sel, _sender: Id) {
        start_test_tunnel(this);
    }

    unsafe extern "C" fn controller_picker_did_pick(this: Id, _cmd: Sel, _picker: Id, urls: Id) {
        if urls.is_null() || unsafe { msg_u64(urls, c"count") } == 0 {
            return;
        }
        let url = unsafe { msg_id_u64(urls, c"objectAtIndex:", 0) };
        let mode = with_main_ui(|ui| ui.picker_mode);
        start_handle_url(this, url, Some(mode));
    }

    unsafe extern "C" fn controller_picker_cancelled(_this: Id, _cmd: Sel, _picker: Id) {
        // User dismissed document picker — no action needed.
    }

    unsafe extern "C" fn controller_drain_worker_events(this: Id, _cmd: Sel) {
        assert!(is_main_thread());
        let events = {
            let mut q = PENDING_EVENTS.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *q)
        };

        let mut need_rebuild = false;
        let mut finish_busy = false;
        let mut pending_tfa: Option<(TwoFactorPrompt, mpsc::Sender<TwoFactorAnswer>)> = None;

        for ev in events {
            match ev {
                WorkerEvent::Progress(u) => {
                    let msg = sanitize_message(&u.message);
                    let (pl, pv) = with_main_ui(|ui| {
                        ui.busy_title = Some(msg.clone());
                        ui.busy_progress = u.percent;
                        (
                            ui.progress_label.as_ref().map(OwnedId::as_id),
                            ui.progress_view.as_ref().map(OwnedId::as_id),
                        )
                    });
                    unsafe {
                        if let Some(pl_id) = pl {
                            msg_void_id(pl_id, c"setText:", ns_string(&msg));
                        }
                        if let Some(pv_id) = pv {
                            msg_void_f32_bool(
                                pv_id,
                                c"setProgress:animated:",
                                progress_fraction(u.percent),
                                true,
                            );
                        }
                    }
                }
                WorkerEvent::TwoFactorRequest { prompt, reply_tx } => {
                    pending_tfa = Some((prompt, reply_tx));
                }
                WorkerEvent::AppsLoaded { overview, result } => {
                    finish_busy = true;
                    need_rebuild = true;
                    with_main_ui(|ui| {
                        ui.overview = overview;
                        match result {
                            Ok(apps) => {
                                let count = apps.len();
                                ui.apps = apps;
                                ui.list_error = None;
                                ui.log_tone = UiTone::Green;
                                ui.log_title = "Список обновлён".to_string();
                                ui.log_message = format!("Найдено приложений: {count}.");
                            }
                            Err(err) => {
                                let safe = sanitize_message(&err);
                                ui.list_error = Some(safe.clone());
                                ui.log_tone = UiTone::Amber;
                                ui.log_title = "Не удалось обновить список".to_string();
                                ui.log_message = safe;
                            }
                        }
                        ui.busy_title = None;
                        ui.busy_progress = 0;
                        ui.needs_rebuild = true;
                    });
                }
                WorkerEvent::OperationDone {
                    overview,
                    apps,
                    ok,
                    title,
                    message,
                } => {
                    finish_busy = true;
                    need_rebuild = true;
                    with_main_ui(|ui| {
                        ui.overview = overview;
                        if let Some(list) = apps {
                            ui.apps = list;
                            ui.list_error = None;
                        }
                        ui.log_tone = if ok { UiTone::Green } else { UiTone::Red };
                        ui.log_title = title;
                        ui.log_message = sanitize_message(&message);
                        ui.busy_title = None;
                        ui.busy_progress = 0;
                        ui.needs_rebuild = true;
                    });
                }
                WorkerEvent::TunnelTested { overview, result } => {
                    finish_busy = true;
                    need_rebuild = true;
                    with_main_ui(|ui| {
                        ui.overview = overview;
                        match result {
                            Ok(st) => {
                                ui.log_tone = UiTone::Green;
                                ui.log_title = format!("Туннель активен: {}", st.device_name);
                                ui.log_message = format!(
                                    "iOS {} ({}) · UDID: {}\nПрофилей: {}, пользовательских приложений: {}",
                                    st.ios_version,
                                    st.product_type,
                                    st.udid,
                                    st.profile_count,
                                    st.user_app_count
                                );
                            }
                            Err(err) => {
                                ui.log_tone = UiTone::Red;
                                ui.log_title = "Проверка связи не пройдена".to_string();
                                ui.log_message = sanitize_message(&err);
                            }
                        }
                        ui.busy_title = None;
                        ui.busy_progress = 0;
                        ui.needs_rebuild = true;
                    });
                }
            }
        }

        if finish_busy {
            BUSY.store(false, Ordering::Release);
            let rc = with_main_ui(|ui| ui.refresh_control.as_ref().map(OwnedId::as_id));
            if let Some(rc_id) = rc {
                unsafe {
                    if msg_bool(rc_id, c"isRefreshing") {
                        msg_void(rc_id, c"endRefreshing");
                    }
                }
            }
        }
        if need_rebuild {
            perform_rebuild();
        }
        if finish_busy {
            let queued = {
                let mut slot = PENDING_OPEN_URL.lock().unwrap_or_else(|e| e.into_inner());
                slot.take()
            };
            if let Some(addr) = queued {
                let owned_url = unsafe { OwnedId::from_owned(addr as Id) };
                start_handle_url(this, owned_url.as_id(), None);
            }
        }
        if let Some((prompt, reply_tx)) = pending_tfa {
            present_tfa_alert(this, prompt, reply_tx);
        }
    }

    // -----------------------------------------------------------------------
    // Application Entry Point
    // -----------------------------------------------------------------------

    pub fn run() {
        let _pool = AutoreleasePool::new();
        unsafe {
            let delegate_cls = allocate_class_pair(class(c"UIResponder"), c"SideboxDelegate");
            add_method(
                delegate_cls,
                c"application:didFinishLaunchingWithOptions:",
                delegate_did_finish_launching as *const c_void,
                c"B@:@@",
            );
            add_method(
                delegate_cls,
                c"application:openURL:options:",
                delegate_open_url as *const c_void,
                c"B@:@@@",
            );
            add_method(
                delegate_cls,
                c"window",
                delegate_window as *const c_void,
                c"@@:",
            );
            add_method(
                delegate_cls,
                c"setWindow:",
                delegate_set_window as *const c_void,
                c"v@:@",
            );
            register_class_pair(delegate_cls);

            let controller_cls =
                allocate_class_pair(class(c"UIViewController"), c"SideboxController");
            add_method(
                controller_cls,
                c"preferredStatusBarStyle",
                controller_preferred_status_bar_style as *const c_void,
                c"q@:",
            );
            add_method(
                controller_cls,
                c"viewDidLoad",
                controller_view_did_load as *const c_void,
                c"v@:",
            );
            add_method(
                controller_cls,
                c"viewDidLayoutSubviews",
                controller_view_did_layout_subviews as *const c_void,
                c"v@:",
            );
            add_method(
                controller_cls,
                c"viewSafeAreaInsetsDidChange",
                controller_safe_area_did_change as *const c_void,
                c"v@:",
            );
            add_method(
                controller_cls,
                c"selectTabApps:",
                controller_select_tab_apps as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"selectTabSettings:",
                controller_select_tab_settings as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"handlePullToRefresh:",
                controller_pull_to_refresh as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"pickIpa:",
                controller_pick_ipa as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"pickPairing:",
                controller_pick_pairing as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"refreshAllApps:",
                controller_refresh_all as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"refreshSingleApp:",
                controller_refresh_single as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"promptAppleLogin:",
                controller_prompt_apple_login as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"logoutApple:",
                controller_logout_apple as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"promptTunnelIp:",
                controller_prompt_tunnel_ip as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"dismissTunnelKeyboard:",
                controller_dismiss_tunnel_keyboard as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"presetTunnelIp:",
                controller_preset_tunnel_ip as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"testTunnel:",
                controller_test_tunnel as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"documentPicker:didPickDocumentsAtURLs:",
                controller_picker_did_pick as *const c_void,
                c"v@:@@",
            );
            add_method(
                controller_cls,
                c"documentPickerWasCancelled:",
                controller_picker_cancelled as *const c_void,
                c"v@:@",
            );
            add_method(
                controller_cls,
                c"drainWorkerEvents",
                controller_drain_worker_events as *const c_void,
                c"v@:",
            );
            register_class_pair(controller_cls);

            let delegate_name = ns_string("SideboxDelegate");
            UIApplicationMain(0, ptr::null(), ptr::null_mut(), delegate_name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AppSettings, PairingSummary, SessionSummary};

    #[test]
    fn classifies_incoming_files_by_extension() {
        assert_eq!(
            classify_incoming_file(Path::new("/tmp/MyApp.IPA")),
            IncomingFileKind::Ipa
        );
        assert_eq!(
            classify_incoming_file(Path::new("/tmp/ALTPairingFile.mobiledevicepairing")),
            IncomingFileKind::Pairing
        );
        assert_eq!(
            classify_incoming_file(Path::new("/tmp/pairingFile.plist")),
            IncomingFileKind::Pairing
        );
        assert_eq!(
            classify_incoming_file(Path::new("/tmp/readme.txt")),
            IncomingFileKind::Unsupported
        );
    }

    #[test]
    fn formats_remaining_and_russian_dates() {
        assert_eq!(
            format_remaining(1000 + 86_400 * 3 + 7200, 1000),
            "Осталось: 3 дн. 2 ч."
        );
        assert_eq!(
            format_remaining(1000 + 3600 * 5 + 900, 1000),
            "Осталось: 5 ч. 15 мин."
        );
        assert_eq!(format_remaining(1000 + 45, 1000), "Осталось менее 1 мин.");
        assert_eq!(format_remaining(10_000 - 7200, 10_000), "Истёк 2 ч. назад");
        assert_eq!(format_date_ru(1_709_249_400, 0), "29 февр. 2024, 23:30");
        assert_eq!(format_date_ru(1_709_249_400, 10_800), "1 мар. 2024, 02:30");
    }

    #[test]
    fn builds_guidance_and_health_badges() {
        assert_eq!(health_badge(&AppHealth::Ok), ("Действует", UiTone::Green));
        assert_eq!(
            health_badge(&AppHealth::ExpiringSoon),
            ("Скоро истечёт", UiTone::Amber)
        );
        assert_eq!(health_badge(&AppHealth::Expired), ("Истёк", UiTone::Red));
        assert!((progress_fraction(150) - 1.0).abs() < f32::EPSILON);

        let ov_no_pair = AppOverview {
            session: SessionSummary {
                exists: false,
                valid: false,
                email_masked: None,
                message: String::new(),
            },
            pairing: PairingSummary {
                exists: false,
                valid: false,
                udid: None,
                filename: None,
                message: String::new(),
            },
            settings: AppSettings::default(),
            cached_ipa_count: 0,
        };
        let (title, _, open_settings) = build_guidance(&ov_no_pair, None);
        assert!(title.contains("pairing"));
        assert!(open_settings);

        let ov_ready = AppOverview {
            session: SessionSummary {
                exists: true,
                valid: true,
                email_masked: Some("a***@gmail.com".to_string()),
                message: String::new(),
            },
            pairing: PairingSummary {
                exists: true,
                valid: true,
                udid: Some("UDID".to_string()),
                filename: Some("pairingFile.plist".to_string()),
                message: String::new(),
            },
            settings: AppSettings::default(),
            cached_ipa_count: 1,
        };
        let (_, body, open_settings2) = build_guidance(&ov_ready, Some("connection refused"));
        assert!(body.contains("10.7.0.1"));
        assert!(open_settings2);

        let (_, _, open_settings3) = build_guidance(&ov_ready, None);
        assert!(!open_settings3);
    }
}
