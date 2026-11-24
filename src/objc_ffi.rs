#![cfg(target_os = "ios")]

use std::ffi::{CStr, CString, c_char, c_void};
use std::path::PathBuf;
use std::ptr;

pub type Id = *mut c_void;
pub type Sel = *const c_void;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CGPoint {
    pub x: f64,
    pub y: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CGSize {
    pub width: f64,
    pub height: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CGRect {
    pub origin: CGPoint,
    pub size: CGSize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UIEdgeInsets {
    pub top: f64,
    pub left: f64,
    pub bottom: f64,
    pub right: f64,
}

#[repr(C)]
struct ObjcSuper {
    receiver: Id,
    super_class: Id,
}

/// Clang Apple Block ABI descriptor for a static global block (`BLOCK_IS_GLOBAL`).
#[repr(C)]
pub struct BlockDescriptor {
    pub reserved: usize,
    pub size: usize,
}

/// Apple Objective-C Global Block (`void (^)(id)`) — immutable, no copy/dispose helpers needed.
#[repr(C)]
pub struct GlobalBlock {
    isa: *const c_void,
    flags: i32,
    reserved: i32,
    invoke: unsafe extern "C" fn(*mut GlobalBlock, Id),
    descriptor: &'static BlockDescriptor,
}

unsafe impl Send for GlobalBlock {}
unsafe impl Sync for GlobalBlock {}

const BLOCK_IS_GLOBAL: i32 = 1 << 28;

static GLOBAL_BLOCK_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: std::mem::size_of::<GlobalBlock>(),
};

impl GlobalBlock {
    pub fn new(invoke: unsafe extern "C" fn(*mut GlobalBlock, Id)) -> Self {
        Self {
            isa: (&raw const _NSConcreteGlobalBlock) as *const c_void,
            flags: BLOCK_IS_GLOBAL,
            reserved: 0,
            invoke,
            descriptor: &GLOBAL_BLOCK_DESCRIPTOR,
        }
    }

    pub fn as_ptr(&self) -> *const c_void {
        (self as *const Self).cast::<c_void>()
    }
}

pub const fn rect(x: f64, y: f64, width: f64, height: f64) -> CGRect {
    CGRect {
        origin: CGPoint { x, y },
        size: CGSize { width, height },
    }
}

pub const fn size(width: f64, height: f64) -> CGSize {
    CGSize { width, height }
}

// UIKit constants verified against iPhoneOS16.5.sdk headers.
pub const UI_STATUS_BAR_STYLE_LIGHT_CONTENT: i64 = 1;
pub const UI_USER_INTERFACE_STYLE_DARK: i64 = 2;
pub const UI_SCROLL_INDICATOR_STYLE_WHITE: i64 = 2;
pub const UI_SCROLL_KEYBOARD_DISMISS_ON_DRAG: i64 = 1;
pub const UI_SWIPE_GESTURE_DIRECTION_DOWN: u64 = 1 << 3;
pub const UI_CONTENT_INSET_ADJUSTMENT_ALWAYS: i64 = 3;
pub const UI_ACTIVITY_INDICATOR_STYLE_MEDIUM: i64 = 100;
pub const UI_PROGRESS_VIEW_STYLE_DEFAULT: i64 = 0;
pub const UI_BUTTON_TYPE_SYSTEM: i64 = 1;
pub const UI_CONTROL_STATE_NORMAL: u64 = 0;
pub const UI_CONTROL_STATE_DISABLED: u64 = 1 << 1;
pub const UI_CONTROL_EVENT_TOUCH_UP_INSIDE: u64 = 1 << 6;
pub const UI_CONTROL_EVENT_VALUE_CHANGED: u64 = 1 << 12;
pub const NS_TEXT_ALIGNMENT_LEFT: i64 = 0;
pub const NS_LINE_BREAK_BY_WORD_WRAPPING: i64 = 0;
pub const NS_LINE_BREAK_BY_TRUNCATING_TAIL: i64 = 4;
pub const UI_ALERT_CONTROLLER_STYLE_ALERT: i64 = 1;
pub const UI_ALERT_ACTION_STYLE_DEFAULT: i64 = 0;
pub const UI_ALERT_ACTION_STYLE_CANCEL: i64 = 1;
pub const UI_TEXT_AUTOCAPITALIZATION_NONE: i64 = 0;
pub const UI_TEXT_AUTOCORRECTION_NO: i64 = 1;
pub const UI_KEYBOARD_TYPE_NUMBERS_AND_PUNCTUATION: i64 = 2;
pub const UI_KEYBOARD_TYPE_EMAIL_ADDRESS: i64 = 7;
pub const UI_KEYBOARD_TYPE_ASCII_CAPABLE_NUMBER_PAD: i64 = 11;

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn objc_allocateClassPair(superclass: Id, name: *const c_char, extra: usize) -> Id;
    fn class_addMethod(
        class: Id,
        selector: Sel,
        implementation: *const c_void,
        types: *const c_char,
    ) -> bool;
    fn objc_registerClassPair(class: Id);
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(context: *mut c_void);
    fn objc_msgSend();
    fn objc_msgSendSuper();
}

unsafe extern "C" {
    static _NSConcreteGlobalBlock: [usize; 32];
}

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    fn NSHomeDirectory() -> Id;
}

#[link(name = "UniformTypeIdentifiers", kind = "framework")]
unsafe extern "C" {}

#[link(name = "UIKit", kind = "framework")]
unsafe extern "C" {
    static UIFontWeightRegular: f64;
    static UIFontWeightMedium: f64;
    static UIFontWeightSemibold: f64;
    static UIFontWeightBold: f64;

    pub fn UIApplicationMain(
        argc: i32,
        argv: *const *const c_char,
        principal: Id,
        delegate: Id,
    ) -> i32;
}

/// RAII wrapper around `objc_autoreleasePoolPush` / `objc_autoreleasePoolPop`.
pub struct AutoreleasePool {
    ctx: *mut c_void,
}

impl AutoreleasePool {
    pub fn new() -> Self {
        let ctx = unsafe { objc_autoreleasePoolPush() };
        Self { ctx }
    }
}

impl Drop for AutoreleasePool {
    fn drop(&mut self) {
        unsafe { objc_autoreleasePoolPop(self.ctx) };
    }
}

/// RAII owning handle (+1 retain count) for an Objective-C object.
pub struct OwnedId {
    ptr: Id,
}

impl OwnedId {
    /// Takes ownership of an already-retained (+1) Objective-C pointer (`alloc`/`init`/`new`/`retain`).
    ///
    /// # Safety
    /// Caller must transfer an owning (+1) reference; `ptr` must be valid or null.
    pub unsafe fn from_owned(ptr: Id) -> Self {
        Self { ptr }
    }

    /// Retains a non-owned (+0) Objective-C pointer and returns an owning handle.
    ///
    /// # Safety
    /// `ptr` must be a valid Objective-C object pointer or null.
    pub unsafe fn retain(ptr: Id) -> Self {
        if !ptr.is_null() {
            let retained = unsafe { msg_id(ptr, c"retain") };
            Self { ptr: retained }
        } else {
            Self {
                ptr: ptr::null_mut(),
            }
        }
    }

    pub fn as_id(&self) -> Id {
        self.ptr
    }

    /// Transfers ownership out as a raw address (for moving a thread-safe retained NSObject across threads).
    pub fn into_raw_addr(mut self) -> usize {
        let raw = self.ptr as usize;
        self.ptr = ptr::null_mut();
        raw
    }
}

impl Drop for OwnedId {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { msg_void(self.ptr, c"release") };
            self.ptr = ptr::null_mut();
        }
    }
}

/// RAII guard for `-[NSURL startAccessingSecurityScopedResource]` / `stopAccessingSecurityScopedResource`.
pub struct SecurityScopedAccess {
    url: Id,
    active: bool,
}

impl SecurityScopedAccess {
    /// # Safety
    /// `url` must remain alive for the lifetime of this guard.
    pub unsafe fn begin(url: Id) -> Self {
        let active = if !url.is_null() {
            unsafe { msg_bool(url, c"startAccessingSecurityScopedResource") }
        } else {
            false
        };
        Self { url, active }
    }
}

impl Drop for SecurityScopedAccess {
    fn drop(&mut self) {
        if self.active && !self.url.is_null() {
            unsafe { msg_void(self.url, c"stopAccessingSecurityScopedResource") };
            self.active = false;
        }
    }
}

pub fn class(name: &CStr) -> Id {
    let cls = unsafe { objc_getClass(name.as_ptr()) };
    assert!(!cls.is_null(), "Objective-C class not found: {name:?}");
    cls
}

pub fn sel(name: &CStr) -> Sel {
    unsafe { sel_registerName(name.as_ptr()) }
}

pub unsafe fn allocate_class_pair(superclass: Id, name: &CStr) -> Id {
    let cls = unsafe { objc_allocateClassPair(superclass, name.as_ptr(), 0) };
    assert!(!cls.is_null(), "Failed to allocate class pair: {name:?}");
    cls
}

pub unsafe fn register_class_pair(cls: Id) {
    unsafe { objc_registerClassPair(cls) };
}

pub unsafe fn add_method(cls: Id, selector: &CStr, imp: *const c_void, types: &CStr) {
    let ok = unsafe { class_addMethod(cls, sel(selector), imp, types.as_ptr()) };
    assert!(ok, "class_addMethod failed for {selector:?}");
}

// ---------------------------------------------------------------------------
// Strictly-typed ARM64 objc_msgSend / objc_msgSendSuper dispatchers.
// ---------------------------------------------------------------------------

pub unsafe fn msg_void(obj: Id, name: &CStr) {
    let f: unsafe extern "C" fn(Id, Sel) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name)) };
}

pub unsafe fn msg_void_id(obj: Id, name: &CStr, a: Id) {
    let f: unsafe extern "C" fn(Id, Sel, Id) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) };
}

pub unsafe fn msg_void_ptr(obj: Id, name: &CStr, a: *const c_void) {
    let f: unsafe extern "C" fn(Id, Sel, *const c_void) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) };
}

pub unsafe fn msg_void_i64(obj: Id, name: &CStr, a: i64) {
    let f: unsafe extern "C" fn(Id, Sel, i64) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) };
}

pub unsafe fn msg_void_f64(obj: Id, name: &CStr, a: f64) {
    let f: unsafe extern "C" fn(Id, Sel, f64) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) };
}

pub unsafe fn msg_void_bool(obj: Id, name: &CStr, a: bool) {
    let f: unsafe extern "C" fn(Id, Sel, bool) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) };
}

pub unsafe fn msg_void_f32_bool(obj: Id, name: &CStr, a: f32, b: bool) {
    let f: unsafe extern "C" fn(Id, Sel, f32, bool) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a, b) };
}

pub unsafe fn msg_void_rect(obj: Id, name: &CStr, a: CGRect) {
    let f: unsafe extern "C" fn(Id, Sel, CGRect) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) };
}

pub unsafe fn msg_void_size(obj: Id, name: &CStr, a: CGSize) {
    let f: unsafe extern "C" fn(Id, Sel, CGSize) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) };
}

pub unsafe fn msg_void_id_u64(obj: Id, name: &CStr, a: Id, b: u64) {
    let f: unsafe extern "C" fn(Id, Sel, Id, u64) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a, b) };
}

pub unsafe fn msg_void_target_action(obj: Id, name: &CStr, target: Id, action: Sel, events: u64) {
    let f: unsafe extern "C" fn(Id, Sel, Id, Sel, u64) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), target, action, events) };
}

pub unsafe fn msg_void_present(controller: Id, vc: Id, animated: bool, completion: *const c_void) {
    let f: unsafe extern "C" fn(Id, Sel, Id, bool, *const c_void) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe {
        f(
            controller,
            sel(c"presentViewController:animated:completion:"),
            vc,
            animated,
            completion,
        )
    };
}

pub unsafe fn msg_void_perform_main(obj: Id, selector: Sel, arg: Id, wait_until_done: bool) {
    let f: unsafe extern "C" fn(Id, Sel, Sel, Id, bool) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe {
        f(
            obj,
            sel(c"performSelectorOnMainThread:withObject:waitUntilDone:"),
            selector,
            arg,
            wait_until_done,
        )
    };
}

pub unsafe fn msg_super_void(obj: Id, super_class: Id, name: &CStr) {
    let mut sup = ObjcSuper {
        receiver: obj,
        super_class,
    };
    let f: unsafe extern "C" fn(*mut ObjcSuper, Sel) =
        unsafe { std::mem::transmute(objc_msgSendSuper as *const ()) };
    unsafe { f(&mut sup, sel(name)) };
}

pub unsafe fn msg_id(obj: Id, name: &CStr) -> Id {
    let f: unsafe extern "C" fn(Id, Sel) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name)) }
}

pub unsafe fn msg_id_id(obj: Id, name: &CStr, a: Id) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, Id) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) }
}

pub unsafe fn msg_id_id_sel(obj: Id, name: &CStr, a: Id, b: Sel) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, Id, Sel) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a, b) }
}

pub unsafe fn msg_id_id_bool(obj: Id, name: &CStr, a: Id, b: bool) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, Id, bool) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a, b) }
}

pub unsafe fn msg_id_i64(obj: Id, name: &CStr, a: i64) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, i64) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) }
}

pub unsafe fn msg_id_u64(obj: Id, name: &CStr, a: u64) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, u64) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) }
}

pub unsafe fn msg_id_f64(obj: Id, name: &CStr, a: f64) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, f64) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) }
}

pub unsafe fn msg_id_f64_f64(obj: Id, name: &CStr, a: f64, b: f64) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, f64, f64) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a, b) }
}

pub unsafe fn msg_id_rect(obj: Id, name: &CStr, a: CGRect) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, CGRect) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) }
}

pub unsafe fn msg_alert_controller(title: Id, message: Id, style: i64) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, Id, Id, i64) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe {
        f(
            class(c"UIAlertController"),
            sel(c"alertControllerWithTitle:message:preferredStyle:"),
            title,
            message,
            style,
        )
    }
}

pub unsafe fn msg_alert_action(title: Id, style: i64, handler: *const c_void) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, Id, i64, *const c_void) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe {
        f(
            class(c"UIAlertAction"),
            sel(c"actionWithTitle:style:handler:"),
            title,
            style,
            handler,
        )
    }
}

pub unsafe fn msg_nsarray_with_objects(items: &[Id]) -> Id {
    let f: unsafe extern "C" fn(Id, Sel, *const Id, u64) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe {
        f(
            class(c"NSArray"),
            sel(c"arrayWithObjects:count:"),
            items.as_ptr(),
            items.len() as u64,
        )
    }
}

pub unsafe fn msg_bool(obj: Id, name: &CStr) -> bool {
    let f: unsafe extern "C" fn(Id, Sel) -> bool =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name)) }
}

pub unsafe fn msg_bool_bool(obj: Id, name: &CStr, a: bool) -> bool {
    let f: unsafe extern "C" fn(Id, Sel, bool) -> bool =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) }
}

pub unsafe fn msg_i64(obj: Id, name: &CStr) -> i64 {
    let f: unsafe extern "C" fn(Id, Sel) -> i64 =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name)) }
}

pub unsafe fn msg_u64(obj: Id, name: &CStr) -> u64 {
    let f: unsafe extern "C" fn(Id, Sel) -> u64 =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name)) }
}

pub unsafe fn msg_i64_id(obj: Id, name: &CStr, a: Id) -> i64 {
    let f: unsafe extern "C" fn(Id, Sel, Id) -> i64 =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) }
}

pub unsafe fn msg_cstr(obj: Id, name: &CStr) -> *const c_char {
    let f: unsafe extern "C" fn(Id, Sel) -> *const c_char =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name)) }
}

pub unsafe fn msg_rect(obj: Id, name: &CStr) -> CGRect {
    let f: unsafe extern "C" fn(Id, Sel) -> CGRect =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name)) }
}

pub unsafe fn msg_insets(obj: Id, name: &CStr) -> UIEdgeInsets {
    let f: unsafe extern "C" fn(Id, Sel) -> UIEdgeInsets =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name)) }
}

pub unsafe fn msg_size_size(obj: Id, name: &CStr, a: CGSize) -> CGSize {
    let f: unsafe extern "C" fn(Id, Sel, CGSize) -> CGSize =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(name), a) }
}

// ---------------------------------------------------------------------------
// High-level Foundation / UIKit / UTType helpers
// ---------------------------------------------------------------------------

pub fn is_main_thread() -> bool {
    unsafe { msg_bool(class(c"NSThread"), c"isMainThread") }
}

/// Resolves the iOS sandbox `Documents/` directory strictly via Foundation `NSHomeDirectory()`.
pub fn sandbox_documents_dir() -> PathBuf {
    let _pool = AutoreleasePool::new();
    let home = unsafe { ns_string_to_rust(NSHomeDirectory()) };
    PathBuf::from(home).join("Documents")
}

/// Converts an `NSString *` to a Rust `String` (empty if null).
pub unsafe fn ns_string_to_rust(ns: Id) -> String {
    if ns.is_null() {
        return String::new();
    }
    let ptr = unsafe { msg_cstr(ns, c"UTF8String") };
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Converts a file `NSURL *` to a filesystem `PathBuf`.
pub unsafe fn url_to_path(url: Id) -> Option<PathBuf> {
    if url.is_null() || !unsafe { msg_bool(url, c"isFileURL") } {
        return None;
    }
    let ptr = unsafe { msg_cstr(url, c"fileSystemRepresentation") };
    if ptr.is_null() {
        return None;
    }
    let path_str = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    if path_str.is_empty() {
        None
    } else {
        Some(PathBuf::from(path_str))
    }
}

/// Returns an autoreleased `NSString *`.
pub fn ns_string(text: &str) -> Id {
    let clean = CString::new(text.replace('\0', "")).unwrap_or_default();
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel, *const c_char) -> Id =
            std::mem::transmute(objc_msgSend as *const ());
        f(
            class(c"NSString"),
            sel(c"stringWithUTF8String:"),
            clean.as_ptr(),
        )
    }
}

/// Returns an autoreleased `UIColor *`.
pub fn rgba(r: f64, g: f64, b: f64, a: f64) -> Id {
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel, f64, f64, f64, f64) -> Id =
            std::mem::transmute(objc_msgSend as *const ());
        f(
            class(c"UIColor"),
            sel(c"colorWithRed:green:blue:alpha:"),
            r,
            g,
            b,
            a,
        )
    }
}

pub fn rgb(r: f64, g: f64, b: f64) -> Id {
    rgba(r, g, b, 1.0)
}

#[derive(Clone, Copy)]
pub enum FontWeight {
    Regular,
    Medium,
    Semibold,
    Bold,
}

impl FontWeight {
    fn as_cgfloat(self) -> f64 {
        unsafe {
            match self {
                Self::Regular => UIFontWeightRegular,
                Self::Medium => UIFontWeightMedium,
                Self::Semibold => UIFontWeightSemibold,
                Self::Bold => UIFontWeightBold,
            }
        }
    }
}

pub fn system_font(pt: f64, weight: FontWeight) -> Id {
    unsafe {
        msg_id_f64_f64(
            class(c"UIFont"),
            c"systemFontOfSize:weight:",
            pt,
            weight.as_cgfloat(),
        )
    }
}

pub fn mono_font(pt: f64, weight: FontWeight) -> Id {
    unsafe {
        msg_id_f64_f64(
            class(c"UIFont"),
            c"monospacedSystemFontOfSize:weight:",
            pt,
            weight.as_cgfloat(),
        )
    }
}

/// Returns an autoreleased `NSArray<UTType *>` built from UTI identifier strings.
pub unsafe fn uttype_array(identifiers: &[&str]) -> Id {
    let cls = class(c"UTType");
    let mut objs = Vec::with_capacity(identifiers.len());
    for id_str in identifiers {
        let ut = unsafe { msg_id_id(cls, c"typeWithIdentifier:", ns_string(id_str)) };
        if !ut.is_null() {
            objs.push(ut);
        }
    }
    unsafe { msg_nsarray_with_objects(&objs) }
}

/// Queries the device's local timezone GMT offset in seconds for `unix_secs`.
pub fn local_tz_offset_secs(unix_secs: u64) -> i64 {
    let _pool = AutoreleasePool::new();
    unsafe {
        let tz = msg_id(class(c"NSTimeZone"), c"localTimeZone");
        let date = msg_id_f64(
            class(c"NSDate"),
            c"dateWithTimeIntervalSince1970:",
            unix_secs as f64,
        );
        if tz.is_null() || date.is_null() {
            return 0;
        }
        msg_i64_id(tz, c"secondsFromGMTForDate:", date)
    }
}

pub unsafe fn alloc_init_frame(cls_name: &CStr, frame: CGRect) -> OwnedId {
    unsafe {
        let raw = msg_id(class(cls_name), c"alloc");
        let initialized = msg_id_rect(raw, c"initWithFrame:", frame);
        OwnedId::from_owned(initialized)
    }
}

pub unsafe fn alloc_init(cls_name: &CStr) -> OwnedId {
    unsafe {
        let raw = msg_id(class(cls_name), c"alloc");
        let initialized = msg_id(raw, c"init");
        OwnedId::from_owned(initialized)
    }
}

pub unsafe fn remove_all_subviews(parent: Id) {
    unsafe {
        let arr = msg_id(parent, c"subviews");
        if arr.is_null() {
            return;
        }
        let count = msg_u64(arr, c"count");
        for i in (0..count).rev() {
            let sub = msg_id_u64(arr, c"objectAtIndex:", i);
            if !sub.is_null() {
                msg_void(sub, c"removeFromSuperview");
            }
        }
    }
}
