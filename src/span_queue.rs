// A small worker thread + bounded channel that delivers finished traces (already-encoded request
// bodies) to the spans endpoint, the same shape as DeliveryQueue: pushing never blocks the caller,
// and a full queue drops the trace, since a request slow enough to be traced must not also be made
// slower by the tracker.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{sync_channel, Sender, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::client::Client;
use crate::delivery_queue::send_marker_and_wait;

// One trace body, or the marker `flush` waits on (see DeliveryQueue's own `Delivery::Flush`).
enum Item {
    Trace(String),
    Flush(Sender<()>),
}

pub struct SpanQueue {
    sender: SyncSender<Item>,
}

impl SpanQueue {
    pub fn new(queue_size: usize, client: Arc<Client>) -> Self {
        let (sender, receiver) = sync_channel::<Item>(queue_size.max(1));

        thread::Builder::new()
            .name("forge-ops-tracker-spans".to_string())
            .spawn(move || {
                for item in receiver {
                    match item {
                        Item::Trace(body) => {
                            let _ = catch_unwind(AssertUnwindSafe(|| {
                                client.deliver_spans(&body);
                            }));
                        }
                        Item::Flush(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })
            .expect("failed to spawn the forge-ops-tracker span thread");

        SpanQueue { sender }
    }

    /// Enqueues a trace body, returning false (and dropping it) if the queue is already full.
    pub fn push(&self, body: String) -> bool {
        match self.sender.try_send(Item::Trace(body)) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Waits until every trace queued before this call has been delivered, at most `timeout`: the
    /// same marker approach as `DeliveryQueue::flush`.
    pub fn flush(&self, timeout: Duration) -> bool {
        send_marker_and_wait(&self.sender, Item::Flush, Instant::now() + timeout)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::sync::RwLock;
    use std::time::Duration;

    use super::*;
    use crate::configuration::Configuration;

    fn serve() -> (String, mpsc::Receiver<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let received = crate::test_support::read_full_request(&mut stream);
                let text = String::from_utf8_lossy(&received).into_owned();
                let request_line = text.lines().next().unwrap_or("").to_string();
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                let _ = tx.send((request_line, body));
                let _ = stream.write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            }
        });
        (format!("http://key@{addr}/api/v1/events"), rx)
    }

    #[test]
    fn a_pushed_trace_is_delivered_in_the_background_to_the_spans_endpoint() {
        let (dsn, rx) = serve();
        let mut config = Configuration::new();
        config.dsn = Some(dsn);
        config.timeout = Duration::from_secs(2);
        let client = Arc::new(Client::new(Arc::new(RwLock::new(config))));
        let queue = SpanQueue::new(10, client);

        assert!(queue.push("{\"trace_id\":\"t\",\"spans\":[]}".to_string()));

        let (request_line, body) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(
            request_line.starts_with("POST /api/v1/spans "),
            "request_line = {request_line}"
        );
        assert_eq!(body, "{\"trace_id\":\"t\",\"spans\":[]}");
    }

    #[test]
    fn a_full_queue_drops_the_trace_instead_of_blocking() {
        // No server listening: the single worker stays busy on (and then fails) the first
        // delivery while the rest pile up; with room for one, a burst must overflow.
        let mut config = Configuration::new();
        config.dsn = Some("http://key@127.0.0.1:1/api/v1/events".to_string());
        config.timeout = Duration::from_millis(200);
        let client = Arc::new(Client::new(Arc::new(RwLock::new(config))));
        let queue = SpanQueue::new(1, client);

        let accepted = (0..50).filter(|_| queue.push("{}".to_string())).count();
        assert!(accepted < 50, "accepted = {accepted}");
    }
}
