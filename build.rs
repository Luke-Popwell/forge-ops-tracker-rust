// Records the version of the compiler building this crate, for the startup change snapshot's
// `runtime` (see src/change_tracking.rs). Rust has no runtime to ask once the binary is built, but
// the whole binary is built by the one compiler Cargo hands every build script as `RUSTC`, so this
// is the same number `rustc --version` printed for the app itself. Plain std, no build dependency;
// if anything here fails the variable is simply never set and the snapshot sends "rust" alone.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let Ok(output) = Command::new(rustc).arg("--version").output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    // "rustc 1.85.0 (4d91de4e4 2025-02-17)": the second word is the version.
    let text = String::from_utf8_lossy(&output.stdout);
    let mut words = text.split_whitespace();
    if words.next() != Some("rustc") {
        return;
    }
    if let Some(version) = words
        .next()
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
    {
        println!("cargo:rustc-env=FORGE_OPS_RUSTC_VERSION={version}");
    }
}
