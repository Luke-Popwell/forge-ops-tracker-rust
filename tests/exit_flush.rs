// Runs this test binary again as a child process (the `child` test below, selected by an
// environment variable), so what's checked is a real process exiting right after it reports
// something: the only way to show nothing is left behind on the delivery thread, which dies with
// the process.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MODE_ENV: &str = "FORGE_OPS_EXIT_FLUSH_MODE";
const DSN_ENV: &str = "FORGE_OPS_EXIT_FLUSH_DSN";

#[test]
fn child() {
    let Ok(mode) = std::env::var(MODE_ENV) else {
        return; // only does anything as the child process of the tests below
    };

    if mode == "setup-page" {
        // Exactly what the setup page shows: FORGE_OPS_DSN in the environment (set by the parent)
        // and a bare init. Called twice to show the "not sending" warning still prints only once.
        forge_ops_tracker::init(|_| {});
        forge_ops_tracker::init(|_| {});
        let err = std::io::Error::other("first test error");
        forge_ops_tracker::capture_error(&err, HashMap::new(), None);
        forge_ops_tracker::flush(Duration::from_secs(2));
        std::process::exit(0);
    }

    forge_ops_tracker::init(|c| {
        c.dsn = std::env::var(DSN_ENV).ok();
        c.environment = "production".to_string();
        c.timeout = Duration::from_secs(2);
        c.detect_changes = false;
    });

    match mode.as_str() {
        // What a script's main looks like: report, flush, exit straight away.
        "capture" => {
            let err = std::io::Error::other("reported just before exit");
            forge_ops_tracker::capture_error(&err, HashMap::new(), None);
            forge_ops_tracker::flush(Duration::from_secs(2));
        }
        // A panic reported by the panic hook alone, with the process exiting the moment it's over.
        "panic" => {
            std::panic::set_hook(Box::new(|_| {}));
            forge_ops_tracker::install_panic_hook();
            let _ = std::panic::catch_unwind(|| panic!("crashed just after starting"));
        }
        other => panic!("unknown mode {other}"),
    }
    std::process::exit(0);
}

// Answers each request only after a delay, counting it once answered: a child that exited without
// waiting would never be counted.
fn spawn_slow_server() -> (SocketAddr, Arc<AtomicI32>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(AtomicI32::new(0));
    let received_clone = Arc::clone(&received);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let request = read_full_request(&mut stream);
            thread::sleep(Duration::from_millis(200));
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            // Only errors count: a child left at its defaults also sends a change snapshot.
            if request.starts_with(b"POST /events ") {
                received_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (addr, received)
}

// The header block and the Content-Length-declared body after it; see src/test_support.rs for why
// the whole request has to be read before answering.
fn read_full_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = [0u8; 8192];
    let mut total = Vec::new();
    loop {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            return total;
        }
        total.extend_from_slice(&buf[..n]);
        let Some(pos) = total.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let content_length: usize = String::from_utf8_lossy(&total[..pos])
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if total.len() >= pos + 4 + content_length {
            return total;
        }
    }
}

fn run_child(mode: &str, addr: SocketAddr) {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["child", "--exact", "--nocapture", "--test-threads=1"])
        .env(MODE_ENV, mode)
        .env(DSN_ENV, format!("http://key@{addr}/events"))
        .status()
        .unwrap();
    assert!(status.success(), "child process failed: {status}");
}

// Runs the "setup-page" child with every FORGE_OPS_* variable from this process removed (so the
// machine running the tests can't change the result) and `env` added, returning its stderr.
fn run_setup_page_child(env: &[(&str, String)]) -> String {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["child", "--exact", "--nocapture", "--test-threads=1"]);
    for (name, _) in std::env::vars() {
        if name.starts_with("FORGE_OPS_") {
            command.env_remove(name);
        }
    }
    command.env(MODE_ENV, "setup-page");
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "child process failed: {}\n{stderr}",
        output.status
    );
    stderr
}

#[test]
fn a_dsn_alone_delivers_the_first_error() {
    let (addr, received) = spawn_slow_server();
    let stderr = run_setup_page_child(&[("FORGE_OPS_DSN", format!("http://key@{addr}/events"))]);
    assert_eq!(received.load(Ordering::SeqCst), 1);
    assert!(
        !stderr.contains("Not sending"),
        "unexpected warning: {stderr}"
    );
}

#[test]
fn a_development_environment_sends_nothing_and_says_so_once() {
    let (addr, received) = spawn_slow_server();
    let stderr = run_setup_page_child(&[
        ("FORGE_OPS_DSN", format!("http://key@{addr}/events")),
        ("FORGE_OPS_ENVIRONMENT", "development".to_string()),
    ]);
    assert_eq!(received.load(Ordering::SeqCst), 0);
    let warning = "[ForgeOps] Not sending: this environment is \"development\", and only \
        production, staging are enabled. Set FORGE_OPS_ENVIRONMENT=production (or add \
        \"development\" to the enabled environments) to send from here.\n";
    assert!(stderr.contains(warning), "stderr = {stderr}");
    assert_eq!(
        stderr.matches("Not sending").count(),
        1,
        "stderr = {stderr}"
    );
}

#[test]
fn a_process_that_flushes_before_exiting_delivers_its_error() {
    let (addr, received) = spawn_slow_server();
    run_child("capture", addr);
    assert_eq!(received.load(Ordering::SeqCst), 1);
}

#[test]
fn a_panic_is_delivered_even_when_the_process_exits_right_after() {
    let (addr, received) = spawn_slow_server();
    run_child("panic", addr);
    assert_eq!(received.load(Ordering::SeqCst), 1);
}
