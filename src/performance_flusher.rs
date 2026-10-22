// Times work in-process, bucketed by transaction name, and periodically flushes each distinct
// bucket as one small aggregate report, rather than one network call per timed call. Ported from
// gems/forge_ops_tracker/lib/forge_ops_tracker/performance_flusher.rb, and from sdks/go's own
// port of it, including the one thing both of those learned the hard way: see `flush`'s own
// comment on why it subtracts what it delivered instead of clearing the buckets.
//
// Unlike the Ruby gem and Go client, which start their flush loop lazily on first record (so a
// prefork server forking after load doesn't leave a dead thread in every child), this starts its
// worker lazily too, but for a simpler reason: a thread nobody has any use for yet shouldn't
// exist. Rust programs essentially never fork at the application level, so the fork hazard those
// clients guard against doesn't apply here.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::client::{Client, Outcome, MAX_FLUSH_FAILURES};
use crate::configuration::Configuration;
use crate::event_builder::format_unix_timestamp;
use crate::histogram_bucketer::{bucket_index, histogram_json, BUCKET_COUNT};
use crate::pii_scrubber::json_string;

/// One distinct transaction's own tally within the current flush window.
#[derive(Clone, Copy, Default)]
struct Bucket {
    count: u64,
    duration_sum_ms: f64,
    max_duration_ms: f64,
    /// A count per latency bucket, see histogram_bucketer.rs.
    histogram: [u64; BUCKET_COUNT],
}

struct Inner {
    buckets: HashMap<String, Bucket>,
    period_started_at: SystemTime,
    /// How many flushes in a row have failed for now; see `flush`.
    failures: u32,
}

pub struct PerformanceFlusher {
    configuration: Arc<RwLock<Configuration>>,
    client: Arc<Client>,
    inner: Mutex<Inner>,
    worker_started: AtomicBool,
}

impl PerformanceFlusher {
    pub fn new(configuration: Arc<RwLock<Configuration>>, client: Arc<Client>) -> Arc<Self> {
        Arc::new(PerformanceFlusher {
            configuration,
            client,
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                period_started_at: SystemTime::now(),
                failures: 0,
            }),
            worker_started: AtomicBool::new(false),
        })
    }

    /// Buckets one timed call's duration under `transaction_name`. Does nothing (and starts no
    /// thread) when `track_performance` is off or reporting isn't enabled for this environment:
    /// nothing would ever be sent, so there's nothing worth tallying.
    pub fn record(self: &Arc<Self>, transaction_name: &str, duration_ms: f64) {
        // Under strict privacy a raw path keeps only its first segment before it's ever a bucket's name.
        let transaction_name = {
            let config = self.configuration.read().unwrap();
            if !config.track_performance || !config.is_enabled() {
                return;
            }
            if config.strict_privacy {
                crate::strict_privacy::transaction_name(transaction_name)
            } else {
                transaction_name.to_string()
            }
        };
        self.ensure_worker_started();

        let mut inner = self.inner.lock().unwrap();
        let bucket = inner.buckets.entry(transaction_name).or_default();
        bucket.count += 1;
        bucket.duration_sum_ms += duration_ms;
        if duration_ms > bucket.max_duration_ms {
            bucket.max_duration_ms = duration_ms;
        }
        // The distribution count/sum/max can't reconstruct: see histogram_bucketer.rs for why the
        // server approximates a percentile from these bucket counts.
        bucket.histogram[bucket_index(duration_ms)] += 1;
    }

    /// Snapshots the buffered buckets and delivers them as one batch. A failed delivery keeps
    /// every bucket where it is, so the next flush's batch just grows instead of losing what was
    /// already tallied: there's no other copy of this data anywhere.
    ///
    /// That only holds while sending again could still work. A batch the server rejected (a 4xx
    /// other than 408 and 429, see `Outcome::Rejected`) is let go of at once: it would be rejected
    /// again at every flush for as long as the process lives. So is a batch whose delivery has now
    /// failed `MAX_FLUSH_FAILURES` flushes in a row, which bounds what an outage that never ends
    /// can pile up.
    ///
    /// Only exactly what this snapshot delivered is removed afterward, subtracted from whatever
    /// is in each bucket by then, never the whole map cleared outright. `record` can run
    /// concurrently with this (that's what the mutex is for), and delivery here happens with the
    /// lock released, so a `record` call for a transaction already in the snapshot, or a brand-new
    /// one, can land in the exact window between the snapshot and delivery succeeding. Clearing
    /// the map afterward, as if delivery had covered everything now in it, would silently discard
    /// that concurrently-recorded data forever, before any later flush got a chance to send it.
    /// This is a real bug `sdks/go` had and fixed (confirmed there by a deterministic test, not
    /// assumed), and that `gems/forge_ops_tracker`'s reference implementation still has, unfixed;
    /// see this crate's own test for the same deterministic reproduction.
    pub fn flush(&self) {
        let (snapshot, period_end) = {
            let inner = self.inner.lock().unwrap();
            if inner.buckets.is_empty() {
                return;
            }
            (
                inner.buckets.clone(),
                (inner.period_started_at, SystemTime::now()),
            )
        };
        let (period_start, period_end) = period_end;

        let (environment, release) = {
            let config = self.configuration.read().unwrap();
            (config.environment.clone(), config.release.clone())
        };
        let samples: Vec<String> = snapshot
            .iter()
            .map(|(name, bucket)| {
                format!(
                    "{{\"transaction_name\":{},\"environment\":{},\"release\":{},\"period_started_at\":{},\"period_ended_at\":{},\"request_count\":{},\"duration_sum_ms\":{},\"max_duration_ms\":{},\"histogram\":{}}}",
                    json_string(name),
                    json_string(&environment),
                    release.as_deref().map(json_string).unwrap_or_else(|| "null".to_string()),
                    json_string(&timestamp(period_start)),
                    json_string(&timestamp(period_end)),
                    bucket.count,
                    bucket.duration_sum_ms,
                    bucket.max_duration_ms,
                    histogram_json(&bucket.histogram)
                )
            })
            .collect();

        let outcome = self
            .client
            .deliver_performance_samples(&format!("{{\"samples\":[{}]}}", samples.join(",")));

        let mut inner = self.inner.lock().unwrap();
        if outcome == Outcome::Failed {
            inner.failures += 1;
            if inner.failures < MAX_FLUSH_FAILURES {
                return;
            }
        }
        inner.failures = 0;
        // Delivered or dropped, what this snapshot covered is let go of the same way.
        for (name, sent) in &snapshot {
            let Some(current) = inner.buckets.get_mut(name) else {
                continue;
            };
            current.count = current.count.saturating_sub(sent.count);
            current.duration_sum_ms = (current.duration_sum_ms - sent.duration_sum_ms).max(0.0);
            for (index, sent_count) in sent.histogram.iter().enumerate() {
                current.histogram[index] = current.histogram[index].saturating_sub(*sent_count);
            }
            if current.count == 0 {
                inner.buckets.remove(name);
            }
            // max_duration_ms is deliberately left as whatever is currently on the bucket, sent
            // or not: unlike count/duration_sum_ms, a max can't be correctly "subtracted" back
            // out (the true max of what's left is anything at or below it, not knowable from the
            // two numbers alone), and leaving it never overstates the next period's own max, only
            // potentially understates how far back it was actually set.
        }
        inner.period_started_at = period_end;
    }

    fn ensure_worker_started(self: &Arc<Self>) {
        if self
            .worker_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let flusher = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name("forge-ops-tracker-performance".to_string())
            .spawn(move || loop {
                let interval = flusher
                    .configuration
                    .read()
                    .unwrap()
                    .performance_flush_interval
                    .max(Duration::from_millis(1));
                thread::sleep(interval);
                // One bad flush must not kill every flush after it: same reasoning
                // DeliveryQueue's own per-item catch_unwind documents.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| flusher.flush()));
            });
        if spawned.is_err() {
            // Couldn't start the thread (out of resources): let a later record() try again.
            self.worker_started.store(false, Ordering::SeqCst);
        }
    }

    #[cfg(test)]
    fn bucket(&self, name: &str) -> Option<(u64, f64, f64)> {
        let inner = self.inner.lock().unwrap();
        inner
            .buckets
            .get(name)
            .map(|b| (b.count, b.duration_sum_ms, b.max_duration_ms))
    }
}

fn timestamp(time: SystemTime) -> String {
    format_unix_timestamp(
        time.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::mpsc;

    use super::*;

    /// Serves `responses` in order, one per connection: each entry is (status, gate) where, if a
    /// gate is given, the server tells `received_tx` it has the request body, then waits for the
    /// gate before answering. Returns the base DSN host and a channel of request bodies.
    #[allow(clippy::type_complexity)]
    fn serve(
        responses: Vec<(u16, Option<mpsc::Receiver<()>>)>,
    ) -> (String, mpsc::Receiver<String>, mpsc::Receiver<()>) {
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
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                let _ = body_tx.send(body);
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

    fn flusher_for(dsn: String) -> Arc<PerformanceFlusher> {
        let mut config = Configuration::new();
        config.dsn = Some(dsn);
        config.environment = "production".to_string();
        config.timeout = Duration::from_secs(2);
        config.performance_flush_interval = Duration::from_secs(3600); // tests flush by hand
        let configuration = Arc::new(RwLock::new(config));
        let client = Arc::new(Client::new(Arc::clone(&configuration)));
        PerformanceFlusher::new(configuration, client)
    }

    #[test]
    fn record_buckets_by_transaction_name_with_count_sum_and_max() {
        let flusher = flusher_for("http://key@127.0.0.1:1/api/v1/events".to_string());

        flusher.record("GET /users/:id", 10.0);
        flusher.record("GET /users/:id", 30.0);
        flusher.record("POST /orders", 5.0);

        assert_eq!(flusher.bucket("GET /users/:id"), Some((2, 40.0, 30.0)));
        assert_eq!(flusher.bucket("POST /orders"), Some((1, 5.0, 5.0)));
    }

    #[test]
    fn strict_privacy_cuts_a_raw_path_transaction_name_to_its_first_segment() {
        for strict in [true, false] {
            let flusher = flusher_for("http://key@127.0.0.1:1/api/v1/events".to_string());
            flusher.configuration.write().unwrap().strict_privacy = strict;

            flusher.record("GET /patients/42/notes", 10.0);
            flusher.record("GET /users/:id", 10.0);

            assert_eq!(flusher.bucket("GET /patients/:path").is_some(), strict);
            assert_eq!(flusher.bucket("GET /patients/42/notes").is_some(), !strict);
            assert!(flusher.bucket("GET /users/:id").is_some());
        }
    }

    #[test]
    fn record_does_nothing_when_track_performance_is_off() {
        let flusher = flusher_for("http://key@127.0.0.1:1/api/v1/events".to_string());
        flusher.configuration.write().unwrap().track_performance = false;

        flusher.record("GET /x", 10.0);

        assert_eq!(flusher.bucket("GET /x"), None);
    }

    #[test]
    fn record_does_nothing_when_reporting_is_not_enabled_for_this_environment() {
        let flusher = flusher_for("http://key@127.0.0.1:1/api/v1/events".to_string());
        flusher.configuration.write().unwrap().environment = "development".to_string();

        flusher.record("GET /x", 10.0);

        assert_eq!(flusher.bucket("GET /x"), None);
    }

    #[test]
    fn flush_delivers_one_batch_to_performance_samples_and_empties_the_buckets() {
        let (dsn, bodies, _received) = serve(vec![(202, None)]);
        let flusher = flusher_for(dsn);
        flusher.configuration.write().unwrap().release = Some("a1b2c3d".to_string());
        flusher.record("GET /users/:id", 10.0);
        flusher.record("GET /users/:id", 30.0);

        flusher.flush();

        let body = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(body.starts_with("{\"samples\":[{"), "body = {body}");
        assert!(body.contains("\"transaction_name\":\"GET /users/:id\""));
        assert!(body.contains("\"request_count\":2"));
        assert!(body.contains("\"duration_sum_ms\":40"));
        assert!(body.contains("\"max_duration_ms\":30"));
        assert!(body.contains("\"environment\":\"production\""));
        assert!(body.contains("\"release\":\"a1b2c3d\""));
        assert_eq!(flusher.bucket("GET /users/:id"), None);
    }

    #[test]
    fn flush_does_nothing_when_there_is_nothing_to_send() {
        let flusher = flusher_for("http://key@127.0.0.1:1/api/v1/events".to_string());

        flusher.flush(); // must not attempt a delivery (there's nothing listening) or panic
    }

    #[test]
    fn a_failed_delivery_keeps_every_bucket_so_the_next_flush_carries_more() {
        let (dsn, bodies, _received) = serve(vec![(500, None), (202, None)]);
        let flusher = flusher_for(dsn);
        flusher.record("GET /x", 10.0);

        flusher.flush();
        assert_eq!(flusher.bucket("GET /x"), Some((1, 10.0, 10.0)));

        flusher.record("GET /x", 20.0);
        flusher.flush();

        let _first = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(second.contains("\"request_count\":2"), "body = {second}");
        assert_eq!(flusher.bucket("GET /x"), None);
    }

    #[test]
    fn a_rejected_batch_is_dropped_and_never_sent_again() {
        // Only two responses are on offer: a third request would find nobody answering.
        let (dsn, bodies, _received) = serve(vec![(422, None), (202, None)]);
        let flusher = flusher_for(dsn);
        flusher.record("GET /x", 10.0);
        flusher.record("GET /x", 30.0);

        flusher.flush();
        assert_eq!(flusher.bucket("GET /x"), None);
        flusher.flush(); // nothing left to send

        flusher.record("GET /x", 20.0);
        flusher.flush();

        let _rejected = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(second.contains("\"request_count\":1"), "body = {second}");
        assert!(bodies.recv_timeout(Duration::from_millis(100)).is_err());
    }

    #[test]
    fn a_network_failure_or_a_429_keeps_every_bucket() {
        let flusher = flusher_for("http://key@127.0.0.1:1/api/v1/events".to_string());
        flusher.record("GET /x", 10.0);
        flusher.flush();
        assert_eq!(flusher.bucket("GET /x"), Some((1, 10.0, 10.0)));

        let (dsn, _bodies, _received) = serve(vec![(429, None)]);
        let flusher = flusher_for(dsn);
        flusher.record("GET /x", 10.0);
        flusher.flush();
        assert_eq!(flusher.bucket("GET /x"), Some((1, 10.0, 10.0)));
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
        let flusher = flusher_for(dsn);

        for flush in 1..=4u64 {
            flusher.record("GET /x", 10.0);
            flusher.flush();
            assert_eq!(
                flusher.bucket("GET /x").map(|b| b.0),
                Some(flush),
                "after failed flush {flush}"
            );
        }

        flusher.flush(); // the fifth in a row
        assert_eq!(flusher.bucket("GET /x"), None);
        flusher.flush(); // nothing left to send
        assert_eq!(bodies.try_iter().count(), 5);

        // Starts clean: the next batch gets five flushes of its own.
        flusher.record("GET /x", 10.0);
        flusher.flush();
        assert_eq!(flusher.bucket("GET /x"), Some((1, 10.0, 10.0)));
    }

    #[test]
    fn only_failed_flushes_in_a_row_count_toward_the_drop() {
        let mut responses = Vec::new();
        for _ in 0..2 {
            responses.extend([(500, None), (500, None), (500, None), (500, None)]);
            responses.push((202, None));
        }
        let (dsn, bodies, _received) = serve(responses);
        let flusher = flusher_for(dsn);

        for round in 0..2 {
            for _ in 0..4 {
                flusher.record("GET /x", 10.0);
                flusher.flush();
            }
            flusher.flush(); // delivers all four, and resets the count of failures

            let delivered = bodies.try_iter().last().unwrap();
            assert!(
                delivered.contains("\"request_count\":4"),
                "round {round} body = {delivered}"
            );
            assert_eq!(flusher.bucket("GET /x"), None);
        }
    }

    #[test]
    fn a_record_that_lands_during_delivery_is_never_lost() {
        // Deterministic reproduction of the race flush()'s own comment describes: the server
        // holds its response until this test has recorded again, guaranteeing that record() runs
        // strictly between the snapshot and delivery succeeding.
        let (release_tx, release_rx) = mpsc::channel();
        let (dsn, _bodies, received) = serve(vec![(202, Some(release_rx))]);
        let flusher = flusher_for(dsn);
        flusher.record("GET /x", 10.0);

        let flushing = Arc::clone(&flusher);
        let handle = thread::spawn(move || flushing.flush());
        received.recv_timeout(Duration::from_secs(2)).unwrap();

        flusher.record("GET /x", 25.0); // same transaction, mid-delivery
        flusher.record("GET /new", 7.0); // a brand-new one, mid-delivery
        release_tx.send(()).unwrap();
        handle.join().unwrap();

        assert_eq!(flusher.bucket("GET /x"), Some((1, 25.0, 25.0)));
        assert_eq!(flusher.bucket("GET /new"), Some((1, 7.0, 7.0)));
    }

    #[test]
    fn the_background_worker_flushes_on_its_own_interval() {
        let (dsn, bodies, _received) = serve(vec![(202, None)]);
        let flusher = flusher_for(dsn);
        flusher
            .configuration
            .write()
            .unwrap()
            .performance_flush_interval = Duration::from_millis(50);

        flusher.record("GET /x", 10.0);

        let body = bodies.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(body.contains("\"transaction_name\":\"GET /x\""));
    }

    #[test]
    fn flush_delivers_a_latency_histogram_alongside_count_sum_and_max() {
        let (dsn, bodies, _received) = serve(vec![(202, None)]);
        let flusher = flusher_for(dsn);
        for duration in [10.0, 40.0, 120.0, 700.0, 12_000.0] {
            flusher.record("GET /posts", duration);
        }

        flusher.flush();

        let body = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            body.contains("\"histogram\":{\"50\":2,\"250\":1,\"1000\":1,\"inf\":1}"),
            "body = {body}"
        );
        assert!(body.contains("\"request_count\":5"));
    }

    #[test]
    fn a_failed_delivery_keeps_histogram_counts_for_the_next_flush() {
        let (dsn, bodies, _received) = serve(vec![(500, None), (202, None)]);
        let flusher = flusher_for(dsn);
        flusher.record("GET /posts", 10.0);
        flusher.flush(); // the first delivery fails: the histogram must survive it

        flusher.record("GET /posts", 300.0);
        flusher.flush();

        let _first = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            second.contains("\"histogram\":{\"50\":1,\"500\":1}"),
            "body = {second}"
        );
    }

    #[test]
    fn a_histogram_count_recorded_during_delivery_is_sent_on_the_next_flush() {
        let (release_tx, release_rx) = mpsc::channel();
        let (dsn, bodies, received) = serve(vec![(202, Some(release_rx)), (202, None)]);
        let flusher = flusher_for(dsn);
        flusher.record("GET /posts", 10.0);

        let flushing = Arc::clone(&flusher);
        let handle = thread::spawn(move || flushing.flush());
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        flusher.record("GET /posts", 300.0); // same transaction, mid-delivery
        flusher.record("GET /new", 5.0); // a brand-new one, mid-delivery
        release_tx.send(()).unwrap();
        handle.join().unwrap();
        let first = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(first.contains("\"histogram\":{\"50\":1}"), "body = {first}");

        flusher.flush();
        let second = bodies.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            second.contains("\"histogram\":{\"500\":1}"),
            "body = {second}"
        );
        assert!(
            second.contains("\"transaction_name\":\"GET /new\""),
            "body = {second}"
        );
    }
}
