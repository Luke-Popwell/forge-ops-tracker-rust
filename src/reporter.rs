// Ties Configuration, EventBuilder, and DeliveryQueue together into the one thing callers actually
// need: report an error. Mirrors gems/forge_ops_tracker's ErrorSubscriber#report: never panics
// back into the caller. An error reporter that can itself crash the host app while reporting an
// error is the worst possible failure mode, so every path here is guarded.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use crate::breadcrumb_buffer::Breadcrumb;
use crate::change_tracking::{self, Change};
use crate::configuration::Configuration;
use crate::delivery_queue::DeliveryQueue;
use crate::event_builder::{capture_backtrace, Event, EventBuilder, Frame};
use crate::pii_scrubber::Value;

pub struct Reporter {
    configuration: Arc<RwLock<Configuration>>,
    delivery_queue: DeliveryQueue,
}

impl Reporter {
    pub fn new(configuration: Arc<RwLock<Configuration>>, delivery_queue: DeliveryQueue) -> Self {
        Reporter {
            configuration,
            delivery_queue,
        }
    }

    /// Waits for everything already queued for delivery (events and changes) to go, at most
    /// `timeout`; see `DeliveryQueue::flush`.
    pub fn flush(&self, timeout: std::time::Duration) -> bool {
        self.delivery_queue.flush(timeout)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn report(
        &self,
        exception_class: &str,
        message: &str,
        backtrace: Vec<Frame>,
        context: HashMap<String, Value>,
        user: Option<HashMap<String, Value>>,
        breadcrumbs: Vec<Breadcrumb>,
    ) {
        self.report_with_sql(
            exception_class,
            message,
            backtrace,
            context,
            user,
            breadcrumbs,
            None,
        );
    }

    /// The same as `report`, plus the raw SQL statement behind the error when the caller has one.
    #[allow(clippy::too_many_arguments)]
    pub fn report_with_sql(
        &self,
        exception_class: &str,
        message: &str,
        backtrace: Vec<Frame>,
        context: HashMap<String, Value>,
        user: Option<HashMap<String, Value>>,
        breadcrumbs: Vec<Breadcrumb>,
        sql: Option<&str>,
    ) {
        // Deliberately broad: this must never panic back into the host app.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let config = self.configuration.read().unwrap();
            if !config.is_enabled() {
                return;
            }
            let event: Event = EventBuilder::new(&config).build_with_sql(
                exception_class,
                message,
                backtrace,
                context,
                user,
                breadcrumbs,
                sql,
            );
            drop(config);
            self.delivery_queue.push(event);
        }));
    }

    /// The same as `report_with_captured_backtrace`, plus the raw SQL statement behind the error.
    pub fn report_with_captured_backtrace_and_sql(
        &self,
        exception_class: &str,
        message: &str,
        context: HashMap<String, Value>,
        user: Option<HashMap<String, Value>>,
        breadcrumbs: Vec<Breadcrumb>,
        sql: &str,
    ) {
        let backtrace = { capture_backtrace(&self.configuration.read().unwrap()) };
        self.report_with_sql(
            exception_class,
            message,
            backtrace,
            context,
            user,
            breadcrumbs,
            Some(sql),
        );
    }

    /// Queues one explicit change for the delivery thread. The same guarantees as `report`: a
    /// no-op when reporting isn't enabled, and never panics back into the caller.
    pub fn record_change(&self, change: &Change) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let config = self.configuration.read().unwrap();
            if !config.is_enabled() {
                return;
            }
            let Some(body) = change_tracking::change_body(&config, change) else {
                return;
            };
            drop(config);
            self.delivery_queue.push_change(body);
        }));
    }

    /// Queues the startup change snapshot, returning whether it was queued: false when reporting
    /// isn't enabled or `detect_changes` is off, so a later `init()` that turns either on still
    /// gets to send it. Building it only reads this process's environment variable names, so it
    /// costs the caller nothing noticeable; the request itself goes out on the delivery thread.
    pub fn send_change_snapshot(&self) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            let config = self.configuration.read().unwrap();
            if !config.is_enabled() || !config.detect_changes {
                return false;
            }
            let body =
                change_tracking::snapshot_body(&config, change_tracking::process_env_var_names);
            drop(config);
            self.delivery_queue.push_change_snapshot(body)
        }))
        .unwrap_or(false)
    }

    /// Convenience for the common case: capture the backtrace right here (at Reporter::report's
    /// own call site) rather than requiring every caller to call capture_backtrace itself first.
    pub fn report_with_captured_backtrace(
        &self,
        exception_class: &str,
        message: &str,
        context: HashMap<String, Value>,
        user: Option<HashMap<String, Value>>,
        breadcrumbs: Vec<Breadcrumb>,
    ) {
        let backtrace = { capture_backtrace(&self.configuration.read().unwrap()) };
        self.report(
            exception_class,
            message,
            backtrace,
            context,
            user,
            breadcrumbs,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::time::Duration;

    fn serving_reporter(status_ok: bool, environment: &str) -> (Reporter, Arc<AtomicI32>) {
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(AtomicI32::new(0));
        let received_clone = Arc::clone(&received);

        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                crate::test_support::read_full_request(&mut stream);
                received_clone.fetch_add(1, Ordering::SeqCst);
                let status_line = if status_ok {
                    "HTTP/1.1 200 OK"
                } else {
                    "HTTP/1.1 500 Internal Server Error"
                };
                let _ = stream.write_all(
                    format!("{status_line}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}")
                        .as_bytes(),
                );
            }
        });

        let mut config = Configuration::new();
        config.dsn = Some(format!("http://key@{addr}/events"));
        config.environment = environment.to_string();
        config.timeout = Duration::from_secs(2);
        let configuration = Arc::new(RwLock::new(config));
        let client = Arc::new(Client::new(Arc::clone(&configuration)));
        let delivery_queue = DeliveryQueue::new(10, client);

        (Reporter::new(configuration, delivery_queue), received)
    }

    #[test]
    fn report_skips_when_disabled() {
        let (reporter, received) = serving_reporter(true, "development");

        reporter.report_with_captured_backtrace("Error", "boom", HashMap::new(), None, Vec::new());
        std::thread::sleep(Duration::from_millis(100));

        assert_eq!(received.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn report_delivers_when_enabled() {
        let (reporter, received) = serving_reporter(true, "production");

        reporter.report_with_captured_backtrace("Error", "boom", HashMap::new(), None, Vec::new());

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while received.load(Ordering::SeqCst) < 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(received.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn report_includes_the_given_user_never_scrubbed_even_though_its_an_email() {
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let total = crate::test_support::read_full_request(&mut stream);
            let _ = tx.send(String::from_utf8_lossy(&total).into_owned());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        });

        let mut config = Configuration::new();
        config.dsn = Some(format!("http://key@{addr}/events"));
        config.environment = "production".to_string();
        config.timeout = Duration::from_secs(2);
        let configuration = Arc::new(RwLock::new(config));
        let client = Arc::new(Client::new(Arc::clone(&configuration)));
        let delivery_queue = DeliveryQueue::new(10, client);
        let reporter = Reporter::new(configuration, delivery_queue);

        let mut user = HashMap::new();
        user.insert("id".to_string(), Value::Number(42.0));
        user.insert(
            "email".to_string(),
            Value::String("alice@example.com".to_string()),
        );
        reporter.report_with_captured_backtrace(
            "Error",
            "boom",
            HashMap::new(),
            Some(user),
            Vec::new(),
        );

        let body = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server never received a request");
        assert!(body.contains("alice@example.com"));
    }

    // Serves every request with `status`, sending each one's request line and body back.
    fn capturing_reporter(
        status: u16,
        environment: &str,
    ) -> (Reporter, std::sync::mpsc::Receiver<(String, String)>) {
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let total = crate::test_support::read_full_request(&mut stream);
                let text = String::from_utf8_lossy(&total).into_owned();
                let request_line = text.lines().next().unwrap_or("").to_string();
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                let _ = tx.send((request_line, body));
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                    )
                    .as_bytes(),
                );
            }
        });

        let mut config = Configuration::new();
        config.dsn = Some(format!("http://key@{addr}/api/v1/events"));
        config.environment = environment.to_string();
        config.timeout = Duration::from_secs(2);
        let configuration = Arc::new(RwLock::new(config));
        let client = Arc::new(Client::new(Arc::clone(&configuration)));
        let delivery_queue = DeliveryQueue::new(10, client);
        (Reporter::new(configuration, delivery_queue), rx)
    }

    #[test]
    fn record_change_posts_the_change_to_the_changes_endpoint() {
        let (reporter, rx) = capturing_reporter(202, "production");
        reporter.record_change(&Change {
            actor: Some("alice".to_string()),
            ..Change::new("not_a_kind", "Raised the pool size")
        });

        let (request_line, body) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            request_line.starts_with("POST /api/v1/changes "),
            "{request_line}"
        );
        assert!(body.starts_with(
            "{\"kind\":\"other\",\"title\":\"Raised the pool size\",\"environment\":\"production\""
        ));
        assert!(body.ends_with(",\"actor\":\"alice\"}"));
    }

    #[test]
    fn record_change_and_the_snapshot_are_no_ops_when_disabled() {
        let (reporter, rx) = capturing_reporter(202, "development");
        reporter.record_change(&Change::new("config", "x"));
        assert!(!reporter.send_change_snapshot());
        assert!(rx.recv_timeout(Duration::from_millis(150)).is_err());
    }

    #[test]
    fn record_change_never_panics_on_a_403_or_an_unreachable_host() {
        let (reporter, rx) = capturing_reporter(403, "production");
        reporter.record_change(&Change::new("config", "x"));
        assert!(reporter.send_change_snapshot());
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let mut config = Configuration::new();
        config.dsn = Some("http://key@127.0.0.1:1/api/v1/events".to_string());
        config.environment = "production".to_string();
        config.timeout = Duration::from_millis(200);
        let configuration = Arc::new(RwLock::new(config));
        let client = Arc::new(Client::new(Arc::clone(&configuration)));
        let reporter = Reporter::new(configuration, DeliveryQueue::new(10, client));
        reporter.record_change(&Change::new("config", "x"));
        assert!(reporter.send_change_snapshot());
        std::thread::sleep(Duration::from_millis(300));
    }

    #[test]
    fn send_change_snapshot_posts_runtime_and_respects_detect_changes() {
        let (reporter, rx) = capturing_reporter(202, "production");
        assert!(reporter.send_change_snapshot());
        let (request_line, body) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            request_line.starts_with("POST /api/v1/change_snapshots "),
            "{request_line}"
        );
        assert!(body.starts_with("{\"environment\":\"production\",\"state\":{\"runtime\":\"rust"));
        assert!(!body.contains("env_var_names"));

        reporter.configuration.write().unwrap().detect_changes = false;
        assert!(!reporter.send_change_snapshot());
        assert!(rx.recv_timeout(Duration::from_millis(150)).is_err());
    }

    #[test]
    fn report_never_panics_even_when_delivery_fails() {
        let (reporter, _received) = serving_reporter(false, "production");
        // Must not panic: an error reporter that can crash the host app while reporting is the
        // worst possible failure mode.
        reporter.report_with_captured_backtrace("Error", "boom", HashMap::new(), None, Vec::new());
    }
}
