// Delivers one event over HTTP. Every failure mode: DNS, connection, timeout, TLS, a non-2xx
// response: is caught here and turned into a `false` return (or, for the batch senders, an
// `Outcome`) rather than a propagated error, since a broken or unreachable tracker must never be
// able to break the host app. Ported from
// gems/forge_ops_tracker/lib/forge_ops_tracker/client.rb.
//
// Uses `ureq` rather than std alone: unlike Python's urllib, Go's net/http, or Java's
// java.net.http, Rust's standard library has no HTTP client at all. See README.md's
// "Dependencies" section.

use std::sync::Arc;
use std::sync::RwLock;

use crate::configuration::Configuration;
use crate::event_builder::Event;

/// How many flushes in a row may fail before a batch sender (the performance flusher, a metric
/// buffer) drops the batch it has been holding on to and starts clean, so an outage that never
/// ends can't keep one ever-growing batch alive for as long as the process lives.
pub const MAX_FLUSH_FAILURES: u32 = 5;

/// What became of one POST, as far as whoever is holding the payload needs to know: whether to let
/// go of it, and whether sending it again could ever help.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Any 2xx.
    Delivered,
    /// A 4xx other than 408 and 429 (a bad payload, a revoked key, a plan without the feature).
    /// The same payload will never be accepted, so it must not be sent again.
    Rejected,
    /// A network error, a timeout, a 5xx, a 408 or a 429. Sending the same payload again later may
    /// well succeed.
    Failed,
}

impl Outcome {
    /// Sorts a response status into the three outcomes. 408 (the server gave up waiting for the
    /// request) and 429 (rate limited) are the two 4xx statuses that say nothing about the payload
    /// itself, so they count as failed for now. Anything else that isn't a 2xx or a 4xx (a 5xx, or
    /// a redirect that wasn't followed) does too.
    fn for_status(status: u16) -> Outcome {
        match status {
            200..=299 => Outcome::Delivered,
            408 | 429 => Outcome::Failed,
            400..=499 => Outcome::Rejected,
            _ => Outcome::Failed,
        }
    }
}

pub struct Client {
    configuration: Arc<RwLock<Configuration>>,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(configuration: Arc<RwLock<Configuration>>) -> Self {
        let timeout = configuration.read().unwrap().timeout;
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        Client {
            configuration,
            agent,
        }
    }

    pub fn deliver(&self, event: &Event) -> bool {
        let (uri, api_key) = {
            let config = self.configuration.read().unwrap();
            (config.ingestion_uri(), config.api_key())
        };
        self.post(uri, api_key, &event.to_json()) == Outcome::Delivered
    }

    /// Same delivery contract as `deliver`, against the DSN's performance_samples endpoint (see
    /// `Configuration::performance_samples_uri`). `body` is the whole request body, already
    /// encoded: `{"samples":[...]}`, the shape Api::V1::PerformanceSamplesController expects.
    /// Returns an `Outcome` rather than a bool, as the two metrics deliveries below do: a batch
    /// sender has to tell a rejected batch from one that only failed for now.
    pub fn deliver_performance_samples(&self, body: &str) -> Outcome {
        let (uri, api_key) = {
            let config = self.configuration.read().unwrap();
            (config.performance_samples_uri(), config.api_key())
        };
        self.post(uri, api_key, body)
    }

    /// Delivers one finished trace (`{"trace_id":...,"spans":[...]}`, already encoded) to the
    /// DSN's spans endpoint.
    pub fn deliver_spans(&self, body: &str) -> bool {
        let (uri, api_key) = {
            let config = self.configuration.read().unwrap();
            (config.spans_uri(), config.api_key())
        };
        self.post(uri, api_key, body) == Outcome::Delivered
    }

    /// Delivers one batch of individual `capture_metric` entries (`{"metrics":[...]}`, already
    /// encoded) to the DSN's custom metrics endpoint.
    pub fn deliver_metrics(&self, body: &str) -> Outcome {
        let (uri, api_key) = {
            let config = self.configuration.read().unwrap();
            (config.custom_metrics_uri(), config.api_key())
        };
        self.post(uri, api_key, body)
    }

    /// The same for infrastructure readings.
    pub fn deliver_infrastructure_metrics(&self, body: &str) -> Outcome {
        let (uri, api_key) = {
            let config = self.configuration.read().unwrap();
            (config.infrastructure_metrics_uri(), config.api_key())
        };
        self.post(uri, api_key, body)
    }

    /// Delivers one `record_change` body (already encoded) to the DSN's changes endpoint. A plan
    /// without change tracking answers 403, which is just another `false` here.
    pub fn deliver_change(&self, body: &str) -> bool {
        let (uri, api_key) = {
            let config = self.configuration.read().unwrap();
            (config.changes_uri(), config.api_key())
        };
        self.post(uri, api_key, body) == Outcome::Delivered
    }

    /// The same for the startup snapshot, to the change_snapshots endpoint.
    pub fn deliver_change_snapshot(&self, body: &str) -> bool {
        let (uri, api_key) = {
            let config = self.configuration.read().unwrap();
            (config.change_snapshots_uri(), config.api_key())
        };
        self.post(uri, api_key, body) == Outcome::Delivered
    }

    fn post(&self, uri: Option<String>, api_key: Option<String>, body: &str) -> Outcome {
        let (Some(uri), Some(api_key)) = (uri, api_key) else {
            return Outcome::Failed;
        };

        let result = self
            .agent
            .post(&uri)
            .set("Authorization", &format!("Bearer {api_key}"))
            .set("Content-Type", "application/json")
            .send_string(body);

        // ureq hands back a 4xx or 5xx as an error carrying the response, not as an `Ok`.
        match result {
            Ok(response) => Outcome::for_status(response.status()),
            Err(ureq::Error::Status(status, _)) => Outcome::for_status(status),
            Err(_) => Outcome::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    fn test_event() -> Event {
        Event {
            exception_class: "std::io::Error".to_string(),
            message: "boom".to_string(),
            backtrace: vec![],
            occurred_at: "2024-01-15T10:30:00Z".to_string(),
            environment: "production".to_string(),
            release: None,
            server_name: None,
            context: HashMap::new(),
            tags: HashMap::new(),
            sdk_name: "rust".to_string(),
            user: None,
            breadcrumbs: vec![],
            sql_objects: None,
            sql_statement: None,
            trace_id: None,
            message_fingerprint: None,
        }
    }

    // A minimal single-request HTTP/1.1 server over a raw TcpListener: avoids adding an HTTP
    // server crate as a dev-dependency just to answer one POST in these tests. Reads the request,
    // hands the caller its method/path/headers/body via the channel, and always answers with the
    // given status code.
    fn serve_once(status: u16) -> (String, mpsc::Receiver<(String, String)>) {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();

            let received = crate::test_support::read_full_request(&mut stream);
            let text = String::from_utf8_lossy(&received).into_owned();
            let mut lines = text.lines();
            let request_line = lines.next().unwrap_or("").to_string();
            let auth_header = lines
                .find(|l| l.to_lowercase().starts_with("authorization:"))
                .unwrap_or("")
                .to_string();
            let _ = tx.send((request_line, auth_header));

            let body = "{}";
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });

        (format!("http://{addr}/api/v1/events"), rx)
    }

    #[test]
    fn deliver_sends_authorized_request_and_returns_true_on_2xx() {
        let (base_uri, rx) = serve_once(200);
        let dsn = base_uri.replacen("http://", "http://secret-key@", 1);

        let mut config = Configuration::new();
        config.dsn = Some(dsn);
        config.timeout = Duration::from_secs(2);
        let client = Client::new(Arc::new(RwLock::new(config)));

        let ok = client.deliver(&test_event());
        assert!(ok);

        let (request_line, auth_header) = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server never received a request");
        assert!(
            request_line.starts_with("POST "),
            "request line = {request_line:?}"
        );
        assert!(
            auth_header.to_lowercase().contains("bearer secret-key"),
            "authorization header = {auth_header:?}"
        );
    }

    #[test]
    fn deliver_returns_false_on_non_2xx() {
        let (base_uri, _rx) = serve_once(500);
        let dsn = base_uri.replacen("http://", "http://key@", 1);

        let mut config = Configuration::new();
        config.dsn = Some(dsn);
        config.timeout = Duration::from_secs(2);
        let client = Client::new(Arc::new(RwLock::new(config)));

        assert!(!client.deliver(&test_event()));
    }

    #[test]
    fn deliver_returns_false_when_unreachable() {
        let mut config = Configuration::new();
        config.dsn = Some("http://key@127.0.0.1:1/events".to_string());
        config.timeout = Duration::from_millis(200);
        let client = Client::new(Arc::new(RwLock::new(config)));

        assert!(!client.deliver(&test_event()));
    }

    #[test]
    fn a_status_is_sorted_into_delivered_rejected_or_failed_for_now() {
        for status in [200, 202, 204] {
            assert_eq!(Outcome::for_status(status), Outcome::Delivered, "{status}");
        }
        for status in [400, 401, 403, 404, 413, 422] {
            assert_eq!(Outcome::for_status(status), Outcome::Rejected, "{status}");
        }
        for status in [408, 429, 500, 502, 503, 302] {
            assert_eq!(Outcome::for_status(status), Outcome::Failed, "{status}");
        }
    }

    fn metrics_outcome_against(status: u16) -> Outcome {
        let (base_uri, _rx) = serve_once(status);
        let mut config = Configuration::new();
        config.dsn = Some(base_uri.replacen("http://", "http://key@", 1));
        config.timeout = Duration::from_secs(2);
        Client::new(Arc::new(RwLock::new(config))).deliver_metrics("{\"metrics\":[]}")
    }

    #[test]
    fn a_batch_delivery_reports_a_rejection_and_a_failure_for_now_differently() {
        assert_eq!(metrics_outcome_against(202), Outcome::Delivered);
        assert_eq!(metrics_outcome_against(403), Outcome::Rejected);
        assert_eq!(metrics_outcome_against(422), Outcome::Rejected);
        assert_eq!(metrics_outcome_against(429), Outcome::Failed);
        assert_eq!(metrics_outcome_against(503), Outcome::Failed);
    }

    #[test]
    fn a_batch_delivery_to_an_unreachable_host_failed_for_now() {
        let mut config = Configuration::new();
        config.dsn = Some("http://key@127.0.0.1:1/api/v1/events".to_string());
        config.timeout = Duration::from_millis(200);
        let client = Client::new(Arc::new(RwLock::new(config)));

        assert_eq!(client.deliver_metrics("{\"metrics\":[]}"), Outcome::Failed);
    }

    #[test]
    fn deliver_returns_false_with_no_dsn() {
        let config = Configuration::new();
        let client = Client::new(Arc::new(RwLock::new(config)));

        assert!(!client.deliver(&test_event()));
    }
}
