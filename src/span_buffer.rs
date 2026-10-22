// One trace's worth of spans (a request's, or a job's, own call tree), sharing a single trace id.
// Held in a `thread_local!`, the same choice the breadcrumb trail and CURRENT_USER already made and
// with the same caveat: it follows a thread, not an async task, so it suits this crate's
// synchronous, thread-per-request-shaped design. Nesting comes from a stack of open span ids: a
// span opened while another is open becomes its child, and anything else parents under the root.
//
// A trace is sent only when its root span took at least `Configuration.trace_capture_threshold`,
// decided here once the root finishes, so a fast request costs nothing on the wire.
//
// A trace exists whenever reporting is enabled, even with `track_tracing` off: its id still goes on
// errors captured inside it and on the `traceparent` header `http_span` hands out, since that id
// is what links an error here to one in another service. Only sending the spans is gated.
//
// `trace_id` and `remote_parent_span_id` come from an incoming `traceparent` header when the trace
// continues another service's (see trace_parent.rs); the root span then points at that remote
// span, which the server nests it under even though it arrives in a different upload.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::configuration::Configuration;
use crate::event_builder::format_unix_timestamp;
use crate::pii_scrubber::{json_string, Value};
use crate::trace_parent::{self, generate_span_id, generate_trace_id};

pub const MAX_SPANS: usize = 500;

pub const DB_STATEMENT: &str = "db.statement";
pub const DB_SYSTEM: &str = "db.system";

/// Masks a database span's `db.statement` in place with the crate's SQL masker, so the SQL as
/// written never reaches the payload however the map was built. The span's `db.system` goes along,
/// so a MySQL or MariaDB statement's "double quoted" strings are masked too. A statement that isn't
/// a string, or is blank, is dropped.
pub fn mask_database_data(data: &mut HashMap<String, Value>) {
    let Some(raw) = data.remove(DB_STATEMENT) else {
        return;
    };
    if let Value::String(statement) = raw {
        let system = match data.get(DB_SYSTEM) {
            Some(Value::String(system)) => Some(system.as_str()),
            _ => None,
        };
        if let Some(masked) = crate::sql_statement::mask(&statement, system) {
            data.insert(DB_STATEMENT.to_string(), Value::String(masked));
        }
    }
}

// The kinds the ingestion API accepts; anything else would fail validation for the whole trace,
// so an unknown kind is sent as "other" instead.
const KINDS: [&str; 7] = [
    "controller",
    "service",
    "database",
    "redis",
    "http",
    "job",
    "other",
];

struct Span {
    span_id: String,
    parent_span_id: Option<String>,
    name: String,
    kind: String,
    started_at: SystemTime,
    duration_ms: f64,
    data: HashMap<String, Value>,
}

pub struct SpanBuffer {
    trace_id: String,
    root_span_id: String,
    remote_parent_span_id: Option<String>,
    // `track_tracing` as it was when the trace began: whether `end` sends the spans at all.
    send: bool,
    spans: Vec<Span>,
    open: Vec<String>,
    environment: String,
    release: Option<String>,
    // `strict_privacy` as it was when the trace began: whether spans go out as strict_privacy.rs
    // reduces them.
    strict_privacy: bool,
}

thread_local! {
    static TRACE: RefCell<Option<SpanBuffer>> = const { RefCell::new(None) };
}

impl SpanBuffer {
    fn new(config: &Configuration, incoming: Option<trace_parent::Context>) -> Self {
        let (trace_id, remote_parent_span_id) = match incoming {
            Some(context) => (context.trace_id, Some(context.parent_span_id)),
            None => (generate_trace_id(), None),
        };
        SpanBuffer {
            trace_id,
            root_span_id: generate_span_id(),
            remote_parent_span_id,
            send: config.track_tracing,
            spans: Vec::new(),
            open: Vec::new(),
            environment: config.environment.clone(),
            release: config.release.clone(),
            strict_privacy: config.strict_privacy,
        }
    }

    fn current_parent(&self) -> String {
        self.open
            .last()
            .cloned()
            .unwrap_or_else(|| self.root_span_id.clone())
    }

    fn record(&mut self, mut span: Span) {
        if self.spans.len() >= MAX_SPANS - 1 {
            return; // leave room for the root
        }
        if span.kind == "database" {
            mask_database_data(&mut span.data);
        }
        self.spans.push(span);
    }

    fn span_json(&self, span: &Span) -> String {
        let kind = if KINDS.contains(&span.kind.as_str()) {
            span.kind.as_str()
        } else {
            "other"
        };
        // Under strict privacy the name keeps no path or query and the data keeps only the masked
        // statement and database system, left out entirely when neither is there.
        let (name, data) = if self.strict_privacy {
            let data = crate::strict_privacy::span_data(&span.data);
            (
                crate::strict_privacy::span_name(&span.name),
                if data.is_empty() {
                    String::new()
                } else {
                    format!(",\"data\":{}", Value::Object(data).to_json())
                },
            )
        } else {
            (
                span.name.clone(),
                format!(",\"data\":{}", Value::Object(span.data.clone()).to_json()),
            )
        };
        format!(
            "{{\"span_id\":{},\"parent_span_id\":{},\"name\":{},\"kind\":{},\"started_at\":{},\"duration_ms\":{},\"environment\":{},\"release\":{}{}}}",
            json_string(&span.span_id),
            span.parent_span_id
                .as_deref()
                .map(json_string)
                .unwrap_or_else(|| "null".to_string()),
            json_string(&name),
            json_string(kind),
            json_string(&timestamp(span.started_at)),
            (span.duration_ms * 100.0).round() / 100.0,
            json_string(&self.environment),
            self.release
                .as_deref()
                .map(json_string)
                .unwrap_or_else(|| "null".to_string()),
            data
        )
    }
}

/// Starts a trace on the calling thread, continuing `incoming` (a parsed `traceparent`) when
/// given one and starting a fresh trace id otherwise. Returns false (and starts nothing) when a
/// trace is already open here, which lets a nested `trace` degrade to a span; also starts nothing
/// when reporting isn't enabled, but still returns true, since the caller then owns a (no-op)
/// root. With `track_tracing` off a trace still starts (for its id) but `end` never sends it.
pub fn begin(config: &Configuration, incoming: Option<trace_parent::Context>) -> bool {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if trace.is_some() {
            return false;
        }
        if config.is_enabled() {
            *trace = Some(SpanBuffer::new(config, incoming));
        }
        true
    })
}

/// The id of the trace open on the calling thread, or None outside one.
pub fn current_trace_id() -> Option<String> {
    TRACE.with(|trace| {
        trace
            .borrow()
            .as_ref()
            .map(|buffer| buffer.trace_id.clone())
    })
}

#[cfg(test)]
pub fn is_active() -> bool {
    TRACE.with(|trace| trace.borrow().is_some())
}

/// Ends the calling thread's trace, always clearing it, and returns the whole request body
/// (`{"trace_id":...,"spans":[...]}`) when the root took at least `threshold` and `track_tracing`
/// was on when it began.
pub fn end(
    threshold: Duration,
    root_name: &str,
    root_kind: &str,
    started_at: SystemTime,
    duration_ms: f64,
) -> Option<String> {
    let buffer = TRACE.with(|trace| trace.borrow_mut().take())?;
    if !buffer.send || duration_ms < threshold.as_secs_f64() * 1000.0 {
        return None;
    }

    let root = Span {
        span_id: buffer.root_span_id.clone(),
        parent_span_id: buffer.remote_parent_span_id.clone(),
        name: root_name.to_string(),
        kind: root_kind.to_string(),
        started_at,
        duration_ms,
        data: HashMap::new(),
    };
    let spans: Vec<String> = std::iter::once(&root)
        .chain(buffer.spans.iter())
        .map(|span| buffer.span_json(span))
        .collect();
    Some(format!(
        "{{\"trace_id\":{},\"spans\":[{}]}}",
        json_string(&buffer.trace_id),
        spans.join(",")
    ))
}

/// Opens a span under whatever is open (or the root), returning its id and its parent's, or None
/// outside a trace. The id exists before the span's work runs, which is what lets `http_span` name
/// it in the `traceparent` header of the very call it times.
pub fn open_span() -> Option<(String, String)> {
    TRACE.with(|trace| {
        trace.borrow_mut().as_mut().map(|buffer| {
            let parent = buffer.current_parent();
            let id = generate_span_id();
            buffer.open.push(id.clone());
            (id, parent)
        })
    })
}

pub fn close_span(
    id: String,
    parent: String,
    name: &str,
    kind: &str,
    started_at: SystemTime,
    duration_ms: f64,
    data: HashMap<String, Value>,
) {
    TRACE.with(|trace| {
        if let Some(buffer) = trace.borrow_mut().as_mut() {
            buffer.open.retain(|open| open != &id);
            buffer.record(Span {
                span_id: id,
                parent_span_id: Some(parent),
                name: name.to_string(),
                kind: kind.to_string(),
                started_at,
                duration_ms,
                data,
            });
        }
    });
}

/// Records an already-finished span under whatever is currently open; a no-op outside a trace.
pub fn record_leaf(
    name: &str,
    kind: &str,
    started_at: SystemTime,
    duration_ms: f64,
    data: HashMap<String, Value>,
) {
    TRACE.with(|trace| {
        if let Some(buffer) = trace.borrow_mut().as_mut() {
            let parent = buffer.current_parent();
            buffer.record(Span {
                span_id: generate_span_id(),
                parent_span_id: Some(parent),
                name: name.to_string(),
                kind: kind.to_string(),
                started_at,
                duration_ms,
                data,
            });
        }
    });
}

/// ISO 8601 with milliseconds, UTC.
fn timestamp(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let whole = format_unix_timestamp(since.as_secs());
    format!(
        "{}.{:03}Z",
        whole.trim_end_matches('Z'),
        since.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Configuration {
        let mut config = Configuration::new();
        config.dsn = Some("https://key@tracker.example.com/api/v1/events".to_string());
        config.environment = "production".to_string();
        config.release = Some("abc123".to_string());
        config.trace_capture_threshold = Duration::from_millis(10);
        config
    }

    fn finish(config: &Configuration, name: &str, duration_ms: f64) -> Option<String> {
        end(
            config.trace_capture_threshold,
            name,
            "controller",
            SystemTime::now(),
            duration_ms,
        )
    }

    fn spans_of(body: &str) -> Vec<HashMap<String, String>> {
        // A tiny purpose-built reader, not a JSON parser: pulls the flat string fields this
        // test asserts on out of each span object.
        let start = body.find("\"spans\":[").unwrap() + "\"spans\":[".len();
        body[start..]
            .split("{\"span_id\"")
            .skip(1)
            .map(|chunk| {
                let chunk = format!("{{\"span_id\"{chunk}");
                let mut fields = HashMap::new();
                for key in ["span_id", "parent_span_id", "name", "kind", "started_at"] {
                    let needle = format!("\"{key}\":");
                    if let Some(at) = chunk.find(&needle) {
                        let rest = &chunk[at + needle.len()..];
                        let value = if let Some(stripped) = rest.strip_prefix('"') {
                            stripped.split('"').next().unwrap().to_string()
                        } else {
                            "null".to_string()
                        };
                        fields.insert(key.to_string(), value);
                    }
                }
                fields
            })
            .collect()
    }

    #[test]
    fn nests_spans_under_the_open_one_and_the_root_with_the_wire_shape() {
        let config = config();
        assert!(begin(&config, None));
        let (outer, parent) = open_span().unwrap();
        record_leaf(
            "SELECT users",
            "database",
            SystemTime::now(),
            3.0,
            HashMap::new(),
        );
        close_span(
            outer,
            parent,
            "charge",
            "service",
            SystemTime::now(),
            20.0,
            HashMap::new(),
        );
        record_leaf(
            "sibling",
            "database",
            SystemTime::now(),
            1.0,
            HashMap::new(),
        );

        let body = finish(&config, "GET /x", 1500.0).unwrap();
        assert!(!is_active(), "end clears the trace");
        let spans = spans_of(&body);
        let by_name: HashMap<_, _> = spans.iter().map(|s| (s["name"].clone(), s)).collect();

        assert!(body.contains("\"trace_id\":\""));
        assert_eq!(by_name["GET /x"]["parent_span_id"], "null");
        assert_eq!(by_name["GET /x"]["kind"], "controller");
        assert_eq!(
            by_name["SELECT users"]["parent_span_id"],
            by_name["charge"]["span_id"]
        );
        assert_eq!(
            by_name["charge"]["parent_span_id"],
            by_name["GET /x"]["span_id"]
        );
        assert_eq!(
            by_name["sibling"]["parent_span_id"],
            by_name["GET /x"]["span_id"]
        );
        assert_eq!(by_name["charge"]["span_id"].len(), 16);
        assert!(body.contains("\"environment\":\"production\""));
        assert!(body.contains("\"release\":\"abc123\""));
        assert!(body.contains("\"parent_span_id\":null"));
        let started = &by_name["charge"]["started_at"];
        assert_eq!(started.len(), 24, "started_at = {started}");
        assert!(started.ends_with('Z') && started.as_bytes()[19] == b'.');
    }

    #[test]
    fn trace_id_is_32_hex_and_ids_are_unique() {
        let config = config();
        assert!(begin(&config, None));
        let body = finish(&config, "a", 500.0).unwrap();
        let at = body.find("\"trace_id\":\"").unwrap() + "\"trace_id\":\"".len();
        let id = &body[at..at + 32];
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(&body[at + 32..at + 33], "\"");

        assert!(!body.contains(&"0".repeat(32)));
    }

    #[test]
    fn an_unknown_kind_is_sent_as_other_since_the_server_would_reject_the_whole_trace() {
        let config = config();
        begin(&config, None);
        record_leaf("q", "db", SystemTime::now(), 1.0, HashMap::new());
        record_leaf("r", "database", SystemTime::now(), 1.0, HashMap::new());
        let spans = spans_of(&finish(&config, "root", 500.0).unwrap());
        let by_name: HashMap<_, _> = spans.iter().map(|s| (s["name"].clone(), s)).collect();
        assert_eq!(by_name["q"]["kind"], "other");
        assert_eq!(by_name["r"]["kind"], "database");
    }

    #[test]
    fn nothing_is_sent_under_the_threshold_and_the_trace_is_cleared() {
        let config = config();
        begin(&config, None);
        assert_eq!(finish(&config, "GET /fast", 1.0), None);
        assert!(!is_active());
    }

    #[test]
    fn tracing_off_still_has_a_trace_id_but_never_sends_and_reporting_disabled_starts_nothing() {
        let mut off = config();
        off.track_tracing = false;
        assert!(begin(&off, None));
        assert!(
            is_active(),
            "the trace id still goes on errors and outgoing headers"
        );
        assert_eq!(current_trace_id().map(|id| id.len()), Some(32));
        open_span();
        assert_eq!(finish(&off, "x", 500.0), None);
        assert!(!is_active());
        assert_eq!(current_trace_id(), None);

        let mut disabled = config();
        disabled.dsn = None;
        assert!(begin(&disabled, None));
        assert!(!is_active());
    }

    #[test]
    fn continuing_an_incoming_trace_keeps_its_id_and_parents_the_root_under_the_remote_span() {
        let config = config();
        let incoming =
            trace_parent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        assert!(begin(&config, incoming));
        assert_eq!(
            current_trace_id().as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        record_leaf("q", "database", SystemTime::now(), 1.0, HashMap::new());
        let body = finish(&config, "POST /orders", 500.0).unwrap();
        assert!(body.starts_with("{\"trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\""));
        let spans = spans_of(&body);
        let by_name: HashMap<_, _> = spans.iter().map(|s| (s["name"].clone(), s)).collect();
        assert_eq!(
            by_name["POST /orders"]["parent_span_id"],
            "00f067aa0ba902b7"
        );
        assert_eq!(
            by_name["q"]["parent_span_id"],
            by_name["POST /orders"]["span_id"]
        );
    }

    #[test]
    fn a_second_begin_on_the_same_thread_reports_a_trace_is_already_open() {
        let config = config();
        assert!(begin(&config, None));
        assert!(!begin(&config, None));
        finish(&config, "x", 500.0);
    }

    #[test]
    fn caps_a_trace_at_500_spans_including_the_root() {
        let config = config();
        begin(&config, None);
        for _ in 0..700 {
            record_leaf("q", "database", SystemTime::now(), 1.0, HashMap::new());
        }
        let body = finish(&config, "GET /x", 2000.0).unwrap();
        assert_eq!(body.matches("\"span_id\"").count(), 500);
    }

    #[test]
    fn a_database_span_sends_its_statement_masked_with_its_system_lowercased() {
        let config = config();
        begin(&config, None);
        let rows = crate::database_span(
            "load orders",
            "SELECT * FROM orders WHERE email = 'jane@example.com' AND total > 4200",
            Some(" PostgreSQL "),
            || {
                crate::record_database_span(
                    "load user",
                    "SELECT name FROM users WHERE id = 9911",
                    None,
                    SystemTime::now(),
                    2.0,
                );
                vec!["row"]
            },
        );
        assert_eq!(rows, vec!["row"]);

        let body = finish(&config, "GET /orders", 1500.0).unwrap();
        assert!(
            body.contains(
                "\"db.statement\":\"SELECT * FROM orders WHERE email = ? AND total > ?\""
            ),
            "{body}"
        );
        assert!(body.contains("\"db.system\":\"postgresql\""), "{body}");
        assert!(
            body.contains("\"db.statement\":\"SELECT name FROM users WHERE id = ?\""),
            "{body}"
        );
        assert_eq!(body.matches("db.system").count(), 1, "{body}");
        for literal in ["jane@example.com", "4200", "9911"] {
            assert!(!body.contains(literal), "{literal} leaked: {body}");
        }
        let spans = spans_of(&body);
        let by_name: HashMap<_, _> = spans.iter().map(|s| (s["name"].clone(), s)).collect();
        assert_eq!(by_name["load orders"]["kind"], "database");
        assert_eq!(
            by_name["load user"]["parent_span_id"],
            by_name["load orders"]["span_id"]
        );
    }

    #[test]
    fn a_statement_put_in_data_by_hand_is_masked_on_a_database_span() {
        let config = config();
        begin(&config, None);
        let mut data = HashMap::new();
        data.insert(
            DB_STATEMENT.to_string(),
            Value::from("DELETE FROM carts WHERE token = 'tok-77xq'"),
        );
        data.insert("rows".to_string(), Value::from(3i64));
        record_leaf("clear cart", "database", SystemTime::now(), 1.0, data);
        let mut not_a_string = HashMap::new();
        not_a_string.insert(DB_STATEMENT.to_string(), Value::from(42i64));
        record_leaf("odd", "database", SystemTime::now(), 1.0, not_a_string);

        let body = finish(&config, "POST /checkout", 1500.0).unwrap();
        assert!(
            body.contains("\"db.statement\":\"DELETE FROM carts WHERE token = ?\""),
            "{body}"
        );
        assert!(body.contains("\"rows\":3"), "{body}");
        assert!(!body.contains("tok-77xq"), "{body}");
        assert_eq!(body.matches("db.statement").count(), 1, "{body}");
    }

    #[test]
    fn a_long_statement_is_truncated_and_blank_values_are_left_out() {
        let sql = format!("SELECT {}id FROM orders", "column_name, ".repeat(500));
        let mut data = crate::database_span_data(&sql, Some("mysql"));
        mask_database_data(&mut data);
        let Some(Value::String(masked)) = data.get(DB_STATEMENT) else {
            panic!("no statement: {data:?}");
        };
        assert_eq!(masked.chars().count(), 4003);
        assert!(masked.ends_with("..."));
        assert_eq!(data.get(DB_SYSTEM), Some(&Value::from("mysql")));

        assert!(crate::database_span_data("  ", Some(" ")).is_empty());
    }

    #[test]
    fn a_mysql_statement_has_its_double_quoted_strings_masked_too() {
        let sql = r#"SELECT "name" FROM users WHERE token = "abc""#;
        let mut data = crate::database_span_data(sql, Some("MySQL"));
        mask_database_data(&mut data);
        assert_eq!(
            data.get(DB_STATEMENT),
            Some(&Value::from("SELECT ? FROM users WHERE token = ?"))
        );

        let mut data = crate::database_span_data(sql, Some("postgresql"));
        mask_database_data(&mut data);
        assert_eq!(data.get(DB_STATEMENT), Some(&Value::from(sql)));
    }

    #[test]
    fn a_database_span_outside_a_trace_just_runs_f() {
        assert_eq!(
            crate::database_span("free", "SELECT 1", Some("sqlite"), || 7),
            7
        );
    }

    #[test]
    fn the_trace_is_per_thread() {
        let config = config();
        begin(&config, None);
        std::thread::spawn(|| assert!(!is_active())).join().unwrap();
        finish(&config, "x", 500.0);
    }
}
