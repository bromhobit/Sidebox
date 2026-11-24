mod engine;
mod heartbeat;
mod models;
#[cfg(target_os = "ios")]
mod objc_ffi;
mod storage;
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
mod ui;

fn main() {
    #[cfg(target_os = "ios")]
    {
        ui::run();
    }
    #[cfg(not(target_os = "ios"))]
    {
        eprintln!("Sidebox runs only on iOS (aarch64-apple-ios).");
    }
}
