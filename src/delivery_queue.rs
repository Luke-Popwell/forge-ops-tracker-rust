// A small in-process worker thread + bounded channel, so delivery never blocks the caller that
// reported the error and never depends on the host app having any particular job backend
// configured. Ported from gems/forge_ops_tracker/lib/forge_ops_tracker/delivery_queue.rb.
//
// Unlike the Ruby gem and Python client, which start their worker lazily on first push
// specifically so a prefork server (Puma, Gunicorn) forking after the module has already loaded
// doesn't leave a dead thread in every forked child, this starts its worker eagerly in `new`:
// the same choice the .NET SDK makes, and for the same reason: Rust programs essentially never
// fork themselves at the application level, so that hazard doesn't apply here, and eager start
// keeps DeliveryQueue itself simpler (no lazy-init synchronization to get right).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{channel, sync_channel, Sender, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::client::Client;
use crate::event_builder::Event;

/// The delivery worker thread's name, which the panic hook checks so a panic on this thread never
/// waits for this thread to flush.
pub(crate) const WORKER_THREAD_NAME: &str = "forge-ops-tracker-delivery";

// What the worker thread delivers: an error event, or one of the two small change bodies
// (already encoded) that share this same thread rather than each starting one of their own.
// Events are nearly all of the traffic and the channel held a bare `Event` before, so boxing it to
// shrink the rare change variants would only add an allocation per event. `Flush` is the marker
// `flush` waits on: the worker answers it once everything queued ahead of it has gone.
#[allow(clippy::large_enum_variant)]
enum Delivery {
    Event(Event),
    Change(String),
    ChangeSnapshot(String),
    Flush(Sender<()>),
}

/// Queues the marker `make` builds (waiting for room while the queue is full) and then waits for
/// the worker to answer it, all before `deadline`. Shared by `DeliveryQueue::flush` and
/// `SpanQueue::flush`: the channel's own ordering is what guarantees everything queued earlier went
/// first, and items queued later never keep it waiting.
pub(crate) fn send_marker_and_wait<T>(
    sender: &SyncSender<T>,
    make: impl FnOnce(Sender<()>) -> T,
    deadline: Instant,
) -> bool {
    let (done, answered) = channel();
    let mut marker = make(done);
    loop {
        match sender.try_send(marker) {
            Ok(()) => break,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(returned)) => {
                if Instant::now() >= deadline {
                    return false;
                }
                marker = returned;
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
    answered
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .is_ok()
}

pub struct DeliveryQueue {
    sender: SyncSender<Delivery>,
}

impl DeliveryQueue {
    pub fn new(queue_size: usize, client: Arc<Client>) -> Self {
        let (sender, receiver) = sync_channel::<Delivery>(queue_size.max(1));

        thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_string())
            .spawn(move || {
                for delivery in receiver {
                    // Per-item, not wrapping the whole loop: one bad delivery must not kill the
                    // worker for every event after it. Client::deliver already turns every
                    // failure mode of its own into a plain `false` return rather than a panic;
                    // this is a second, redundant layer of safety around it. Whatever comes back,
                    // the item is gone once it has been tried: nothing here is ever sent twice,
                    // whether the server rejected it or delivery only failed for now.
                    let _ = catch_unwind(AssertUnwindSafe(|| match &delivery {
                        Delivery::Event(event) => client.deliver(event),
                        Delivery::Change(body) => client.deliver_change(body),
                        Delivery::ChangeSnapshot(body) => client.deliver_change_snapshot(body),
                        // A flush that already gave up has dropped its receiver; nothing to do.
                        Delivery::Flush(done) => done.send(()).is_ok(),
                    }));
                }
            })
            .expect("failed to spawn the forge-ops-tracker delivery thread");

        DeliveryQueue { sender }
    }

    /// Enqueues event for delivery, returning false (and dropping it) if the queue is already
    /// full rather than blocking the caller.
    pub fn push(&self, event: Event) -> bool {
        self.send(Delivery::Event(event))
    }

    /// The same for a `record_change` body.
    pub fn push_change(&self, body: String) -> bool {
        self.send(Delivery::Change(body))
    }

    /// The same for the startup change snapshot's body.
    pub fn push_change_snapshot(&self, body: String) -> bool {
        self.send(Delivery::ChangeSnapshot(body))
    }

    /// Waits until everything queued before this call has been delivered (or given up on: a failed
    /// delivery counts as done, the same as on the worker itself), at most `timeout`, and returns
    /// whether it got there in time.
    pub fn flush(&self, timeout: Duration) -> bool {
        send_marker_and_wait(&self.sender, Delivery::Flush, Instant::now() + timeout)
    }

    fn send(&self, delivery: Delivery) -> bool {
        match self.sender.try_send(delivery) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    use super::*;
    use crate::configuration::Configuration;

    fn test_event(n: i64) -> Event {
        let mut context = HashMap::new();
        context.insert(
            "n".to_string(),
            crate::pii_scrubber::Value::Number(n as f64),
        );
        Event {
            exception_class: "Error".to_string(),
            message: "boom".to_string(),
            backtrace: vec![],
            occurred_at: "2024-01-15T10:30:00Z".to_string(),
            environment: "production".to_string(),
            release: None,
            server_name: None,
            context,
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

    fn client_targeting(addr: std::net::SocketAddr) -> Arc<Client> {
        let mut config = Configuration::new();
        config.dsn = Some(format!("http://key@{addr}/events"));
        config.timeout = Duration::from_secs(5);
        Arc::new(Client::new(Arc::new(RwLock::new(config))))
    }

    #[test]
    fn push_delivers_in_background() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicI32, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(AtomicI32::new(0));
        let received_clone = Arc::clone(&received);

        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                crate::test_support::read_full_request(&mut stream);
                received_clone.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            }
        });

        let client = client_targeting(addr);
        let queue = DeliveryQueue::new(10, client);

        queue.push(test_event(1));
        queue.push(test_event(2));

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while received.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(received.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn change_bodies_go_to_their_own_endpoints_on_the_same_worker() {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let received = crate::test_support::read_full_request(&mut stream);
                let text = String::from_utf8_lossy(&received).into_owned();
                let _ = tx.send(text.lines().next().unwrap_or("").to_string());
                let _ = stream.write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            }
        });

        let queue = DeliveryQueue::new(10, client_targeting(addr));
        assert!(queue.push_change("{}".to_string()));
        assert!(queue.push_change_snapshot("{}".to_string()));

        let first = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(first.starts_with("POST /changes "), "{first}");
        assert!(second.starts_with("POST /change_snapshots "), "{second}");
    }

    #[test]
    fn drops_when_full() {
        use std::net::TcpListener;

        // A listener that accepts a connection and then never reads/responds, so the worker
        // thread stays busy (blocked inside ureq waiting on the response) long enough for the
        // queue behind it to actually fill up.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::mem::forget(stream); // hold the connection open without ever responding
            }
        });

        let mut config = Configuration::new();
        config.dsn = Some(format!("http://key@{addr}/events"));
        config.timeout = Duration::from_secs(5);
        let client = Arc::new(Client::new(Arc::new(RwLock::new(config))));
        let queue = DeliveryQueue::new(1, client);

        assert!(
            queue.push(test_event(1)),
            "first push should have succeeded"
        );
        thread::sleep(Duration::from_millis(100)); // let the worker pick it up and start blocking

        assert!(
            queue.push(test_event(2)),
            "second push should have filled the size-1 queue"
        );
        assert!(
            !queue.push(test_event(3)),
            "third push should have been dropped: queue was full"
        );
    }

    // Answers each request only after a delay, counting it once answered: slow enough that nothing
    // would have been counted yet if flush returned without waiting.
    fn spawn_slow_server(
        delay: Duration,
    ) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicI32>) {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicI32, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(AtomicI32::new(0));
        let received_clone = Arc::clone(&received);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                crate::test_support::read_full_request(&mut stream);
                thread::sleep(delay);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
                received_clone.fetch_add(1, Ordering::SeqCst);
            }
        });
        (addr, received)
    }

    #[test]
    fn flush_waits_for_everything_queued() {
        use std::sync::atomic::Ordering;

        let (addr, received) = spawn_slow_server(Duration::from_millis(30));
        let queue = DeliveryQueue::new(10, client_targeting(addr));
        for n in 1..=3 {
            queue.push(test_event(n));
        }

        assert!(queue.flush(Duration::from_secs(2)));
        assert_eq!(received.load(Ordering::SeqCst), 3);
    }

    // Answers every request with `status`, counting each one.
    fn spawn_status_server(
        status: u16,
    ) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicI32>) {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicI32, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(AtomicI32::new(0));
        let received_clone = Arc::clone(&received);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                crate::test_support::read_full_request(&mut stream);
                received_clone.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(
                    format!("HTTP/1.1 {status} OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}")
                        .as_bytes(),
                );
            }
        });
        (addr, received)
    }

    #[test]
    fn an_event_the_server_rejects_or_fails_is_dropped_and_never_sent_again() {
        use std::sync::atomic::Ordering;

        for status in [422, 500] {
            let (addr, received) = spawn_status_server(status);
            let queue = DeliveryQueue::new(10, client_targeting(addr));
            queue.push(test_event(1));

            assert!(
                queue.flush(Duration::from_secs(2)),
                "a dropped event still counts as done after a {status}"
            );
            assert!(queue.flush(Duration::from_secs(2)));
            assert_eq!(received.load(Ordering::SeqCst), 1, "after a {status}");
        }
    }

    #[test]
    fn flush_with_nothing_queued_returns_at_once() {
        let queue = DeliveryQueue::new(10, client_targeting("127.0.0.1:1".parse().unwrap()));
        let started = Instant::now();
        assert!(queue.flush(Duration::from_secs(1)));
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn flush_gives_up_at_the_timeout() {
        let (addr, _received) = spawn_slow_server(Duration::from_secs(3));
        let queue = DeliveryQueue::new(10, client_targeting(addr));
        queue.push(test_event(1));

        let started = Instant::now();
        assert!(
            !queue.flush(Duration::from_millis(100)),
            "the only delivery was still waiting on the server"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100) && elapsed < Duration::from_secs(1),
            "flush(100ms) returned after {elapsed:?}"
        );
    }

    #[test]
    fn flush_gives_up_when_the_queue_stays_full() {
        let (addr, _received) = spawn_slow_server(Duration::from_secs(3));
        let queue = DeliveryQueue::new(1, client_targeting(addr));
        queue.push(test_event(1));
        thread::sleep(Duration::from_millis(100)); // the worker is now waiting on the server
        queue.push(test_event(2)); // and this fills the size-1 queue, leaving no room for the marker

        assert!(!queue.flush(Duration::from_millis(100)));
    }
}
