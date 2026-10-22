// Collects individual capture_metric/capture_infrastructure_metric calls in-process and periodically
// flushes them as one batch, rather than one network call per capture. Unlike the performance
// flusher this keeps a list of individually meaningful entries instead of summing them into buckets:
// a customer's own signup or payment is exactly the kind of thing they will want a genuinely accurate
// count/sum of later, so the server stores one row per entry as-is. Ported from
// gems/forge_ops_tracker's metric_buffer.rb and infrastructure_metric_buffer.rb, which are the same
// class twice; here it is one type instantiated twice (Kind::Custom, Kind::Infrastructure).
//
// Four deliberate differences from the Ruby buffers:
//
// - A flush snapshots the first N entries and, on success, removes exactly those N, instead of
//   resetting the whole list, so an entry recorded while the request is in flight (the lock is
//   released around the network call) is kept for the next flush rather than lost.
// - The buffer is capped at MAX_ENTRIES, and once full further entries are dropped until a flush
//   makes room, so an outage can't grow it without bound. Dropping the newest rather than the oldest
//   keeps the entries a flush is delivering at the front of the list, which is what makes removing
//   exactly them afterward exact.
// - A batch the server rejected (a 4xx other than 408 and 429, see `Outcome::Rejected`: a plan
//   without the feature answers 403 on every flush) is dropped rather than kept, since it would be
//   rejected again at every flush and, once the buffer was full, keep every new metric out too. A
//   batch whose delivery failed MAX_FLUSH_FAILURES flushes in a row is dropped as well.
// - A NaN or infinite value is dropped at record time: it is not valid JSON, and one bad entry would
//   make the server reject the whole batch behind it.
//
// Entries are stored already encoded as one JSON object each, so a flush only has to join them. Like
// the performance flusher, the flush thread is a daemon started lazily on the first capture, and Rust
// has no exit hook: a short-lived program must call `flush_metrics` before it returns from main.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::client::{Client, Outcome, MAX_FLUSH_FAILURES};
use crate::configuration::Configuration;
use crate::event_builder::format_unix_timestamp;
use crate::pii_scrubber::json_string;

pub const MAX_ENTRIES: usize = 1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Custom,
    Infrastructure,
}

pub struct MetricBuffer {
    kind: Kind,
    configuration: Arc<RwLock<Configuration>>,
    client: Arc<Client>,
    entries: Mutex<Vec<String>>,
    /// How many flushes in a row have failed for now; see `flush`.
    failures: AtomicU32,
    worker_started: AtomicBool,
}

impl MetricBuffer {
    pub fn new(
        kind: Kind,
        configuration: Arc<RwLock<Configuration>>,
        client: Arc<Client>,
    ) -> Arc<Self> {
        Arc::new(MetricBuffer {
            kind,
            configuration,
            client,
            entries: Mutex::new(Vec::new()),
            failures: AtomicU32::new(0),
            worker_started: AtomicBool::new(false),
        })
    }

    /// Adds one entry: `fields` are the already-encoded `"key":value` pairs of everything but
    /// `recorded_at`, which is stamped here. Returns whether it was kept.
    pub fn record(self: &Arc<Self>, value: f64, fields: &str) -> bool {
        if !value.is_finite() {
            return false;
        }

        self.ensure_worker_started();
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= MAX_ENTRIES {
            return false;
        }
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        entries.push(format!(
            "{{{fields},\"recorded_at\":{}}}",
            json_string(&format_unix_timestamp(secs))
        ));
        true
    }

    /// Delivers everything buffered so far as one batch. A failed delivery keeps every entry, so the
    /// next flush's batch just grows, until MAX_FLUSH_FAILURES flushes in a row have failed and the
    /// batch is dropped. A rejected batch is dropped at once.
    pub fn flush(&self) {
        let snapshot: Vec<String> = {
            let entries = self.entries.lock().unwrap();
            if entries.is_empty() {
                return;
            }
            entries.clone()
        };

        let body = format!("{{\"metrics\":[{}]}}", snapshot.join(","));
        let outcome = match self.kind {
            Kind::Custom => self.client.deliver_metrics(&body),
            Kind::Infrastructure => self.client.deliver_infrastructure_metrics(&body),
        };
        if outcome == Outcome::Failed
            && self.failures.fetch_add(1, Ordering::SeqCst) + 1 < MAX_FLUSH_FAILURES
        {
            return;
        }
        self.failures.store(0, Ordering::SeqCst);

        // Exactly the entries just delivered (or dropped): anything recorded while the request was
        // in flight sits after them and stays for the next flush.
        self.entries.lock().unwrap().drain(..snapshot.len());
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    fn ensure_worker_started(self: &Arc<Self>) {
        if self
            .worker_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let buffer = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name("forge-ops-tracker-metrics".to_string())
            .spawn(move || loop {
                let interval = {
                    let config = buffer.configuration.read().unwrap();
                    match buffer.kind {
                        Kind::Custom => config.metric_flush_interval,
                        Kind::Infrastructure => config.infrastructure_metric_flush_interval,
                    }
                }
                .max(Duration::from_millis(1));
                thread::sleep(interval);
                // One bad flush must not kill every flush after it.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| buffer.flush()));
            });
        if spawned.is_err() {
            // Couldn't start the thread (out of resources): let a later record() try again.
            self.worker_started.store(false, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::mpsc;

    use super::*;

    /// Serves `responses` in order, one per connection (a status and an optional gate that holds the
    /// answer): returns the DSN and a channel of (request line, body) pairs plus a "received" signal.
    #[allow(clippy::type_complexity)]
    fn serve(
        responses: Vec<(u16, Option<mpsc::Receiver<()>>)>,
    ) -> (String, mpsc::Receiver<(String, String)>, mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (body_tx, body_rx) = mpsc::channel();
        let (received_tx, received_rx) = mpsc::channel();

        thread::spawn(move || {
            for (status, gate) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let received = crate::test_support::read_full_request(&mut stream);
                let text = String::from_utf8_lossy(&received).into_owned();
                let request_line = text.lines().next().unwrap_or("").to_string();
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                let _ = body_tx.send((request_line, body));
                let _ = received_tx.send(());
                if let Some(gate) = gate {
                    let _ = gate.recv();
                }
                let reply = "{}";
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                        reply.len()
                    )
                    .as_bytes(),
                );
            }
        });

        (
            format!("http://key@{addr}/api/v1/events"),
            body_rx,
            received_rx,
        )
    }

    fn buffer_for(kind: Kind, dsn: String) -> Arc<MetricBuffer> {
        let mut config = Configuration::new();
        config.dsn = Some(dsn);
        config.environment = "production".to_string();
        config.timeout = Duration::from_secs(2);
        config.metric_flush_interval = Duration::from_secs(3600);
        config.infrastructure_metric_flush_interval = Duration::from_secs(3600);
        let configuration = Arc::new(RwLock::new(config));
        let client = Arc::new(Client::new(Arc::clone(&configuration)));
        MetricBuffer::new(kind, configuration, client)
    }

    fn name(n: &str) -> String {
        format!("\"metric_name\":{}", json_string(n))
    }

    #[test]
    fn flush_delivers_every_entry_as_one_batch_to_its_own_endpoint_stamped_with_recorded_at() {
        let (dsn, bodies, _received) = serve(vec![(202, None)]);
        let buffer = buffer_for(Kind::Custom, dsn);

        assert!(buffer.record(1.0, &format!("{},\"value\":1", name("signup"))));
        assert!(buffer.record(-12.5, &format!("{},\"value\":-12.5", name("refund"))));
        buffer.flush();

        let (request_line, body) = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            request_line.starts_with("POST /api/v1/custom_metrics "),
            "{request_line}"
        );
        assert!(
            body.starts_with("{\"metrics\":[{\"metric_name\":\"signup\""),
            "{body}"
        );
        assert!(body.contains("\"value\":-12.5"));
        assert_eq!(body.matches("\"recorded_at\":\"").count(), 2);
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn infrastructure_readings_go_to_infrastructure_metrics() {
        let (dsn, bodies, _received) = serve(vec![(202, None)]);
        let buffer = buffer_for(Kind::Infrastructure, dsn);
        buffer.record(
            0.42,
            &format!("{},\"value\":0.42,\"hostname\":\"db-1\"", name("cpu")),
        );
        buffer.flush();

        let (request_line, body) = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            request_line.starts_with("POST /api/v1/infrastructure_metrics "),
            "{request_line}"
        );
        assert!(body.contains("\"hostname\":\"db-1\""));
    }

    #[test]
    fn nan_and_infinite_values_are_dropped() {
        let buffer = buffer_for(
            Kind::Custom,
            "http://key@127.0.0.1:1/api/v1/events".to_string(),
        );
        assert!(!buffer.record(f64::NAN, "\"value\":0"));
        assert!(!buffer.record(f64::INFINITY, "\"value\":0"));
        assert!(buffer.record(3.0, "\"value\":3"));
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn a_failed_delivery_keeps_every_entry_so_the_next_flush_carries_more() {
        let (dsn, bodies, _received) = serve(vec![(500, None), (202, None)]);
        let buffer = buffer_for(Kind::Custom, dsn);
        buffer.record(1.0, &format!("{},\"value\":1", name("a")));
        buffer.flush();
        assert_eq!(buffer.len(), 1);
        buffer.record(2.0, &format!("{},\"value\":2", name("b")));
        buffer.flush();

        let _first = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        let (_, second) = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            second.contains("\"metric_name\":\"a\"") && second.contains("\"metric_name\":\"b\""),
            "{second}"
        );
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn a_rejected_batch_is_dropped_and_never_sent_again() {
        // Only two responses are on offer: a third request would find nobody answering.
        let (dsn, bodies, _received) = serve(vec![(403, None), (202, None)]);
        let buffer = buffer_for(Kind::Custom, dsn);
        buffer.record(1.0, &format!("{},\"value\":1", name("a")));
        buffer.flush();
        assert_eq!(buffer.len(), 0);
        buffer.flush(); // nothing left to send

        buffer.record(2.0, &format!("{},\"value\":2", name("b")));
        buffer.flush();

        let _rejected = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        let (_, second) = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            !second.contains("\"metric_name\":\"a\"") && second.contains("\"metric_name\":\"b\""),
            "{second}"
        );
        assert!(bodies.recv_timeout(Duration::from_millis(100)).is_err());
    }

    #[test]
    fn a_full_buffer_takes_new_metrics_again_once_its_rejected_batch_is_dropped() {
        let (dsn, _bodies, _received) = serve(vec![(403, None)]);
        let buffer = buffer_for(Kind::Infrastructure, dsn);
        for _ in 0..MAX_ENTRIES {
            buffer.record(1.0, "\"value\":1");
        }
        assert!(!buffer.record(1.0, "\"value\":1"));

        buffer.flush();

        assert!(buffer.record(1.0, "\"value\":1"));
    }

    #[test]
    fn a_network_failure_or_a_429_keeps_every_entry() {
        let buffer = buffer_for(
            Kind::Custom,
            "http://key@127.0.0.1:1/api/v1/events".to_string(),
        );
        buffer.record(1.0, &format!("{},\"value\":1", name("a")));
        buffer.flush();
        assert_eq!(buffer.len(), 1);

        let (dsn, _bodies, _received) = serve(vec![(429, None)]);
        let buffer = buffer_for(Kind::Custom, dsn);
        buffer.record(1.0, &format!("{},\"value\":1", name("a")));
        buffer.flush();
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn the_fifth_failed_flush_in_a_row_drops_the_batch() {
        let (dsn, bodies, _received) = serve(vec![
            (503, None),
            (503, None),
            (503, None),
            (503, None),
            (503, None),
            (503, None),
        ]);
        let buffer = buffer_for(Kind::Custom, dsn);

        for flush in 1..=4 {
            buffer.record(1.0, &format!("{},\"value\":1", name("a")));
            buffer.flush();
            assert_eq!(buffer.len(), flush, "after failed flush {flush}");
        }

        buffer.flush(); // the fifth in a row
        assert_eq!(buffer.len(), 0);
        buffer.flush(); // nothing left to send
        assert_eq!(bodies.try_iter().count(), 5);

        // Starts clean: the next batch gets five flushes of its own.
        buffer.record(2.0, &format!("{},\"value\":2", name("b")));
        buffer.flush();
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn only_failed_flushes_in_a_row_count_toward_the_drop() {
        let mut responses = Vec::new();
        for _ in 0..2 {
            responses.extend([(500, None), (500, None), (500, None), (500, None)]);
            responses.push((202, None));
        }
        let (dsn, bodies, _received) = serve(responses);
        let buffer = buffer_for(Kind::Custom, dsn);

        for round in 0..2 {
            for _ in 0..4 {
                buffer.record(1.0, &format!("{},\"value\":1", name("m")));
                buffer.flush();
            }
            buffer.flush(); // delivers all four, and resets the count of failures

            let (_, delivered) = bodies.try_iter().last().unwrap();
            assert_eq!(
                delivered.matches("\"metric_name\":\"m\"").count(),
                4,
                "round {round}: {delivered}"
            );
            assert_eq!(buffer.len(), 0);
        }
    }

    #[test]
    fn an_entry_recorded_while_delivery_is_in_flight_is_never_lost() {
        let (release_tx, release_rx) = mpsc::channel();
        let (dsn, _bodies, received) = serve(vec![(202, Some(release_rx))]);
        let buffer = buffer_for(Kind::Custom, dsn);
        buffer.record(1.0, &format!("{},\"value\":1", name("first")));

        let flushing = Arc::clone(&buffer);
        let handle = thread::spawn(move || flushing.flush());
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        buffer.record(2.0, &format!("{},\"value\":2", name("during")));
        release_tx.send(()).unwrap();
        handle.join().unwrap();

        assert_eq!(buffer.len(), 1);
        assert!(buffer.entries.lock().unwrap()[0].contains("\"metric_name\":\"during\""));
    }

    #[test]
    fn the_buffer_is_capped_and_drops_further_entries_until_a_flush_succeeds() {
        let buffer = buffer_for(
            Kind::Custom,
            "http://key@127.0.0.1:1/api/v1/events".to_string(),
        );
        let accepted = (0..MAX_ENTRIES + 50)
            .filter(|_| buffer.record(1.0, "\"value\":1"))
            .count();
        assert_eq!(accepted, MAX_ENTRIES);
    }

    #[test]
    fn the_background_worker_flushes_on_its_own_interval() {
        let (dsn, bodies, _received) = serve(vec![(202, None)]);
        let buffer = buffer_for(Kind::Custom, dsn);
        buffer.configuration.write().unwrap().metric_flush_interval = Duration::from_millis(50);
        buffer.record(1.0, &format!("{},\"value\":1", name("tick")));

        let (_, body) = bodies.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(body.contains("tick"));
    }
}
