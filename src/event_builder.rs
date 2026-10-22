// Turns a reported error/panic into the payload shape the ingestion API expects. Ported from
// gems/forge_ops_tracker/lib/forge_ops_tracker/event_builder.rb: backtrace frames come from the
// `backtrace` crate rather than regex-parsing MRI backtrace lines, but the resulting shape
// (file/line/method/in_app) is the same.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::breadcrumb_buffer::Breadcrumb;
use crate::configuration::Configuration;
use crate::pii_scrubber::{scrub_string, scrub_value, Value};
use crate::sql_statement::{self, SqlObjects};

/// Caps how many backtrace frames a single event carries, the same limit every other client in
/// this repo applies.
pub const MAX_FRAMES: usize = 500;

/// This crate's own module path prefix, as `backtrace`'s symbol names render it: used to skip
/// this SDK's own leading frames the same way every other client's backtrace builder excludes its
/// own internals.
const CRATE_PREFIX: &str = "forge_ops_tracker::";

/// How many lines of source to grab on either side of an in-app frame's culprit line (see
/// `attach_source_context`), and the longest a single captured line is allowed to be before
/// getting truncated: guards against a single pathological minified/generated line ballooning
/// the payload. ForgeOps itself re-truncates on arrival too, the same "don't just trust the SDK"
/// posture MAX_FRAMES already gets on the server side.
const CONTEXT_LINES: usize = 5;
const MAX_CONTEXT_LINE_LENGTH: usize = 500;

/// Identifies this crate to the server's auto language-detection on the project the event lands
/// in (see Project#note_sdk_platform server-side); matches this repo's own sdks/rust directory
/// name, the same convention every other language's client follows.
const SDK_NAME: &str = "rust";

#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    pub file: String,
    pub line: u32,
    pub method: String,
    pub in_app: bool,
    pub context_line: Option<String>,
    pub pre_context: Option<Vec<String>>,
    pub post_context: Option<Vec<String>>,
}

impl Frame {
    /// Convenience constructor for the common case (no source context attached yet): keeps call
    /// sites and tests from having to spell out the three context fields every time.
    pub fn new(file: String, line: u32, method: String, in_app: bool) -> Self {
        Frame {
            file,
            line,
            method,
            in_app,
            context_line: None,
            pre_context: None,
            post_context: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub exception_class: String,
    pub message: String,
    pub backtrace: Vec<Frame>,
    pub occurred_at: String,
    pub environment: String,
    pub release: Option<String>,
    pub server_name: Option<String>,
    pub context: HashMap<String, Value>,
    pub tags: HashMap<String, Value>,
    pub sdk_name: String,
    pub user: Option<HashMap<String, Value>>,
    pub breadcrumbs: Vec<Breadcrumb>,
    /// Procedure/function and table/view names the failing SQL touched, and (opt-in) the statement
    /// itself with every string and number masked; see sql_statement.rs. Both omitted from the wire
    /// entirely when `None`.
    pub sql_objects: Option<SqlObjects>,
    pub sql_statement: Option<String>,
    /// The id of the trace open on the reporting thread (see `trace`/`continue_trace`), linking
    /// this error to that trace's spans and, through `traceparent`, to errors in the other services
    /// it touched. Omitted from the wire entirely when `None`. A structured id, never scrubbed.
    pub trace_id: Option<String>,
    /// Set only under `Configuration.strict_privacy`, in place of the message (which is then
    /// empty): 32 hex characters, a one-way hash of the message with its ids taken out (see
    /// strict_privacy.rs). An event carrying one also leaves out `context`/`tags` when they're
    /// empty, matching what the server keeps for a strict project.
    pub message_fingerprint: Option<String>,
}

impl Event {
    pub fn to_json(&self) -> String {
        use crate::pii_scrubber::json_string;

        let backtrace: Vec<String> = self
            .backtrace
            .iter()
            .map(|f| {
                // context_line/pre_context/post_context are only present at all when source
                // context was actually attached (see attach_source_context): omitted from the
                // wire entirely rather than sent as null, mirroring the Ruby gem's frame hash,
                // which simply has no such keys on a frame that never got context.
                let context_fields = match (&f.context_line, &f.pre_context, &f.post_context) {
                    (Some(context_line), Some(pre_context), Some(post_context)) => format!(
                        ",\"context_line\":{},\"pre_context\":{},\"post_context\":{}",
                        json_string(context_line),
                        string_array_json(pre_context),
                        string_array_json(post_context)
                    ),
                    _ => String::new(),
                };

                format!(
                    "{{\"file\":{},\"line\":{},\"method\":{},\"in_app\":{}{}}}",
                    json_string(&f.file),
                    f.line,
                    json_string(&f.method),
                    f.in_app,
                    context_fields
                )
            })
            .collect();

        let optional_string = |v: &Option<String>| {
            v.as_deref()
                .map(json_string)
                .unwrap_or_else(|| "null".to_string())
        };

        // Omitted from the wire entirely when absent, the same "no key at all, not a null" shape
        // context_fields above gives a frame with no source context: matches every other client
        // in this repo's own "user" field, which is likewise only ever present when actually set.
        let user_field = match &self.user {
            Some(user) if !user.is_empty() => {
                format!(",\"user\":{}", Value::Object(user.clone()).to_json())
            }
            _ => String::new(),
        };

        // Omitted entirely rather than an empty array when there's nothing to send, the same
        // "no key at all, not an empty placeholder" shape user_field above already uses: matches
        // gems/forge_ops_tracker's own `if breadcrumbs && !breadcrumbs.empty?`.
        let breadcrumbs_field = if self.breadcrumbs.is_empty() {
            String::new()
        } else {
            let entries: Vec<String> = self
                .breadcrumbs
                .iter()
                .map(|b| {
                    format!(
                        "{{\"category\":{},\"message\":{},\"level\":{},\"timestamp\":{},\"data\":{}}}",
                        json_string(&b.category),
                        json_string(&b.message),
                        json_string(&b.level),
                        json_string(&b.timestamp),
                        Value::Object(b.data.clone()).to_json()
                    )
                })
                .collect();
            format!(",\"breadcrumbs\":[{}]", entries.join(","))
        };

        let sql_field = format!(
            "{}{}",
            self.sql_objects
                .as_ref()
                .map(|o| format!(",\"sql_objects\":{}", o.to_json()))
                .unwrap_or_default(),
            self.sql_statement
                .as_deref()
                .map(|s| format!(",\"sql_statement\":{}", json_string(s)))
                .unwrap_or_default()
        );

        let trace_field = self
            .trace_id
            .as_deref()
            .map(|id| format!(",\"trace_id\":{}", json_string(id)))
            .unwrap_or_default();

        let fingerprint_field = self
            .message_fingerprint
            .as_deref()
            .map(|f| format!(",\"message_fingerprint\":{}", json_string(f)))
            .unwrap_or_default();
        let fields_field = |key: &str, fields: &HashMap<String, Value>| {
            if fields.is_empty() && self.message_fingerprint.is_some() {
                String::new()
            } else {
                format!(",\"{key}\":{}", Value::Object(fields.clone()).to_json())
            }
        };

        format!(
            "{{\"exception_class\":{},\"message\":{},\"backtrace\":[{}],\"occurred_at\":{},\"environment\":{},\"release\":{},\"server_name\":{}{}{},\"sdk_name\":{}{}{}{}{}{}}}",
            json_string(&self.exception_class),
            json_string(&self.message),
            backtrace.join(","),
            json_string(&self.occurred_at),
            json_string(&self.environment),
            optional_string(&self.release),
            optional_string(&self.server_name),
            fields_field("context", &self.context),
            fields_field("tags", &self.tags),
            json_string(&self.sdk_name),
            user_field,
            breadcrumbs_field,
            sql_field,
            trace_field,
            fingerprint_field
        )
    }
}

/// Renders a list of source-context lines as a JSON array, reusing `Value`'s own array encoding
/// (see pii_scrubber.rs) rather than hand-rolling a second array-joining routine.
fn string_array_json(items: &[String]) -> String {
    Value::Array(items.iter().cloned().map(Value::String).collect()).to_json()
}

pub struct EventBuilder<'a> {
    configuration: &'a Configuration,
}

impl<'a> EventBuilder<'a> {
    pub fn new(configuration: &'a Configuration) -> Self {
        EventBuilder { configuration }
    }

    // Only the tests build an event without SQL directly now: every real report goes through
    // `build_with_sql` (via Reporter::report), passing `None` when the caller had no statement.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        &self,
        exception_class: &str,
        message: &str,
        backtrace: Vec<Frame>,
        context: HashMap<String, Value>,
        user: Option<HashMap<String, Value>>,
        breadcrumbs: Vec<Breadcrumb>,
    ) -> Event {
        self.build_with_sql(
            exception_class,
            message,
            backtrace,
            context,
            user,
            breadcrumbs,
            None,
        )
    }

    /// The same as `build`, plus the raw SQL statement behind the error when the caller has one
    /// (see `capture_error_with_sql`). The statement is masked here, and only the names and/or the
    /// masked statement it produces ever reach the event, per the two `capture_sql_*` settings.
    #[allow(clippy::too_many_arguments)]
    pub fn build_with_sql(
        &self,
        exception_class: &str,
        message: &str,
        backtrace: Vec<Frame>,
        context: HashMap<String, Value>,
        user: Option<HashMap<String, Value>>,
        breadcrumbs: Vec<Breadcrumb>,
        sql: Option<&str>,
    ) -> Event {
        let mut event = Event {
            exception_class: exception_class.to_string(),
            message: message.to_string(),
            backtrace,
            occurred_at: format_now(),
            environment: self.configuration.environment.clone(),
            release: self.configuration.release.clone(),
            server_name: self.configuration.server_name.clone(),
            context,
            tags: HashMap::new(),
            sdk_name: SDK_NAME.to_string(),
            user: user.filter(|u| !u.is_empty()),
            breadcrumbs,
            sql_objects: None,
            sql_statement: None,
            // Read here, on the reporting thread itself, the same thread-local `set_user` and the
            // breadcrumb trail already rely on.
            trace_id: crate::span_buffer::current_trace_id(),
            message_fingerprint: None,
        };

        if self.configuration.capture_sql_objects || self.configuration.capture_sql_statement {
            if let Some(masked) = sql.and_then(|sql| sql_statement::mask(sql, None)) {
                if self.configuration.capture_sql_objects {
                    event.sql_objects = sql_statement::extract_objects(&masked);
                }
                if self.configuration.capture_sql_statement {
                    event.sql_statement = Some(masked);
                }
            }
        }

        if self.configuration.scrub_pii {
            event = scrub_event(event);
        }
        if self.configuration.strict_privacy {
            event = crate::strict_privacy::apply_to_event(
                event,
                &self.configuration.privacy_allowed_fields,
            );
        }
        event
    }
}

// exception_class/occurred_at/environment/release/server_name/sdk_name/user are left alone:
// structured fields this client or the host app sets deliberately, not free text an error or its
// context could accidentally spill sensitive data into. Scrubbing `user` would defeat the whole
// point of identifying users in the first place.
fn scrub_event(mut event: Event) -> Event {
    event.message = scrub_string(&event.message);
    event.backtrace = event
        .backtrace
        .into_iter()
        .map(|f| Frame {
            file: scrub_string(&f.file),
            method: scrub_string(&f.method),
            ..f
        })
        .collect();

    let Value::Object(context) = scrub_value(&Value::Object(event.context), "") else {
        unreachable!()
    };
    event.context = context;
    let Value::Object(tags) = scrub_value(&Value::Object(event.tags), "") else {
        unreachable!()
    };
    event.tags = tags;

    // category/level/timestamp are left alone, the same "structured fields this client sets
    // deliberately, not free text" exemption exception_class/environment/etc. already get above:
    // only message (arbitrary text) and data (arbitrary caller-supplied values, the same shape
    // context already is) can carry anything worth scrubbing.
    event.sql_statement = event
        .sql_statement
        .map(|statement| scrub_string(&statement));

    event.breadcrumbs = event
        .breadcrumbs
        .into_iter()
        .map(|b| {
            let Value::Object(data) = scrub_value(&Value::Object(b.data), "") else {
                unreachable!()
            };
            Breadcrumb {
                message: scrub_string(&b.message),
                data,
                ..b
            }
        })
        .collect();
    event
}

/// Captures the current call stack via the `backtrace` crate, called at the point CaptureError/
/// the panic hook fires: this client captures the stack at the call site rather than from the
/// error value itself, since a plain Rust `std::error::Error` carries no stack of its own, unlike
/// Python's traceback or Java's Throwable, which travel with the exception.
pub fn capture_backtrace(configuration: &Configuration) -> Vec<Frame> {
    let bt = backtrace::Backtrace::new();
    let mut frames = Vec::new();
    let mut seen_app_frame = false;

    'frames: for frame in bt.frames() {
        for symbol in frame.symbols() {
            let name = symbol
                .name()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "<unknown>".to_string());

            // Skip this SDK's own frames: capture_backtrace/capture_error/the panic hook's own
            // call chain adds no diagnostic value, the same reason interpreter-internal frames
            // never show up in a Python traceback. Only skipped until real caller code is
            // reached, so a host app frame that happens to also start with this crate's own name
            // (unlikely in practice) still gets included once we're past the SDK's own plumbing.
            if !seen_app_frame && name.starts_with(CRATE_PREFIX) {
                continue;
            }
            seen_app_frame = true;

            let file = symbol
                .filename()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let line = symbol.lineno().unwrap_or(0);
            let in_app = is_in_app(configuration, &file);
            let frame = Frame::new(file, line, name, in_app);
            frames.push(attach_source_context(configuration, frame));

            if frames.len() >= MAX_FRAMES {
                break 'frames;
            }
        }
    }
    frames
}

fn is_in_app(configuration: &Configuration, file: &str) -> bool {
    let root = match &configuration.app_root {
        Some(r) if !r.is_empty() => r,
        _ => return false,
    };
    if file.is_empty() || !file.starts_with(root.as_str()) {
        return false;
    }
    // Third-party crate source under Cargo's registry, and the Rust toolchain's own std/core
    // source under a rustc sysroot path, are never in_app regardless of app_root: the same role
    // site-packages/dist-packages plays for Python and the module cache plays for Go.
    !file.contains("/.cargo/registry/") && !file.contains("/rustc/")
}

/// Reads a few lines of source straight off disk around the culprit line, at capture time, in the
/// same running process the panic/error came from. Gated on two things: the frame has to be
/// in-app (never a third-party dependency: there'd be nothing meaningful of the host app's own
/// to show), and `configuration.capture_source_context` has to be true (see Configuration for why
/// it defaults to true and why ForgeOps' own per-project setting, not this field, is the durable,
/// server-enforced way to turn it off), with `strict_privacy` off. Best-effort: any file that can't be read (moved, deleted,
/// permission denied, a path that only ever existed inside a build step and isn't present in this
/// deployment) just leaves the frame exactly as it was, never a panic of the reporting path
/// itself.
fn attach_source_context(configuration: &Configuration, mut frame: Frame) -> Frame {
    if !configuration.capture_source_context || configuration.strict_privacy || !frame.in_app {
        return frame;
    }

    let Ok(contents) = std::fs::read_to_string(&frame.file) else {
        return frame;
    };
    let lines: Vec<&str> = contents.lines().collect();
    if frame.line == 0 || frame.line as usize > lines.len() {
        return frame;
    }
    let index = frame.line as usize - 1;

    let from = index.saturating_sub(CONTEXT_LINES);
    let to = (index + CONTEXT_LINES).min(lines.len() - 1);

    frame.context_line = Some(truncate_line(lines[index]));
    frame.pre_context = Some(
        lines[from..index]
            .iter()
            .map(|l| truncate_line(l))
            .collect(),
    );
    frame.post_context = Some(
        lines[(index + 1)..=to]
            .iter()
            .map(|l| truncate_line(l))
            .collect(),
    );
    frame
}

fn truncate_line(line: &str) -> String {
    if line.chars().count() <= MAX_CONTEXT_LINE_LENGTH {
        return line.to_string();
    }
    let truncated: String = line.chars().take(MAX_CONTEXT_LINE_LENGTH).collect();
    format!("{truncated}...")
}

fn format_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_timestamp(secs)
}

/// Formats a Unix timestamp as "YYYY-MM-DDTHH:MM:SSZ" using plain civil-calendar arithmetic (the
/// well-known "days from civil" algorithm) rather than a datetime crate: std has no calendar
/// formatting at all, but this client only ever needs UTC-and-this-one-format, so the smallest
/// possible amount of arithmetic beats adding a dependency for it. `pub(crate)`, not private:
/// breadcrumb_buffer.rs's own timestamps need the identical format and reuse this rather than a
/// second copy of the algorithm below.
pub(crate) fn format_unix_timestamp(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let (hour, minute, second) = (
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    );

    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's "days from civil" algorithm, run in reverse (civil_from_days): a standard,
/// widely-published constant-time conversion from a day count (here, since the Unix epoch) to a
/// proleptic-Gregorian (year, month, day), used here purely for its adaptation as the
/// well-documented public-domain algorithm it is at https://howardhinnant.github.io/date_algorithms.html.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_configuration() -> Configuration {
        Configuration {
            environment: "production".to_string(),
            release: Some("a1b2c3d".to_string()),
            server_name: Some("test-host".to_string()),
            app_root: Some("/app".to_string()),
            scrub_pii: true,
            ..Configuration::new()
        }
    }

    #[test]
    fn build_basic_fields() {
        let config = test_configuration();
        let builder = EventBuilder::new(&config);
        let mut context = HashMap::new();
        context.insert("order_id".to_string(), Value::Number(42.0));

        let event = builder.build("std::io::Error", "boom", vec![], context, None, vec![]);

        assert_eq!(event.message, "boom");
        assert_eq!(event.environment, "production");
        assert_eq!(event.release, Some("a1b2c3d".to_string()));
        assert_eq!(event.server_name, Some("test-host".to_string()));
        assert_eq!(event.context["order_id"], Value::Number(42.0));
        assert_eq!(event.sdk_name, "rust");
    }

    #[test]
    fn build_includes_the_user_when_given_one_never_scrubbed_even_though_its_an_email() {
        let config = test_configuration();
        let builder = EventBuilder::new(&config);
        let mut user = HashMap::new();
        user.insert("id".to_string(), Value::Number(42.0));
        user.insert(
            "email".to_string(),
            Value::String("ada@example.com".to_string()),
        );

        let event = builder.build("Error", "boom", vec![], HashMap::new(), Some(user), vec![]);

        assert_eq!(
            event.user.unwrap()["email"],
            Value::String("ada@example.com".to_string())
        );
    }

    #[test]
    fn build_omits_the_user_entirely_when_none_was_given() {
        let config = test_configuration();
        let builder = EventBuilder::new(&config);

        let event = builder.build("Error", "boom", vec![], HashMap::new(), None, vec![]);

        assert_eq!(event.user, None);
    }

    #[test]
    fn build_scrubs_message_and_context_when_enabled() {
        let config = test_configuration();
        let builder = EventBuilder::new(&config);
        let mut context = HashMap::new();
        context.insert(
            "api_key".to_string(),
            Value::String("shh-secret".to_string()),
        );

        let event = builder.build(
            "Error",
            "failed to charge user@example.com",
            vec![],
            context,
            None,
            vec![],
        );

        assert_eq!(event.message, "failed to charge [EMAIL FILTERED]");
        assert_eq!(
            event.context["api_key"],
            Value::String(crate::pii_scrubber::REDACTED.to_string())
        );
    }

    #[test]
    fn build_does_not_scrub_when_disabled() {
        let mut config = test_configuration();
        config.scrub_pii = false;
        let builder = EventBuilder::new(&config);

        let event = builder.build(
            "Error",
            "contact user@example.com",
            vec![],
            HashMap::new(),
            None,
            vec![],
        );

        assert_eq!(event.message, "contact user@example.com");
    }

    #[test]
    fn is_in_app_excludes_registry_and_toolchain_and_outside_root() {
        let config = test_configuration();
        assert!(is_in_app(&config, "/app/src/main.rs"));
        assert!(!is_in_app(&config, "/other/src/main.rs"));
        assert!(!is_in_app(
            &config,
            "/app/.cargo/registry/src/index.crates.io/crate/lib.rs"
        ));
        assert!(!is_in_app(&config, ""));
    }

    #[test]
    fn capture_backtrace_excludes_this_crates_own_frames() {
        let config = test_configuration();
        let frames = capture_backtrace(&config);

        assert!(!frames.is_empty(), "expected at least one backtrace frame");
        for frame in &frames {
            assert!(
                !frame.method.starts_with(CRATE_PREFIX),
                "frame {:?} should have been filtered out as SDK-internal",
                frame.method
            );
        }
    }

    #[test]
    fn format_unix_timestamp_known_value() {
        // 2024-01-15T10:30:00Z
        assert_eq!(format_unix_timestamp(1705314600), "2024-01-15T10:30:00Z");
        // The Unix epoch itself.
        assert_eq!(format_unix_timestamp(0), "1970-01-01T00:00:00Z");
    }

    mod source_context {
        use super::*;
        use std::sync::atomic::{AtomicU64, Ordering};

        // A real temp file on disk, not a hardcoded fixture path: std::env::temp_dir() plus a
        // process-id/nanosecond/counter suffix keeps concurrently-run tests from colliding.
        struct TempFile {
            path: std::path::PathBuf,
        }

        impl TempFile {
            fn with_contents(contents: &str) -> Self {
                static COUNTER: AtomicU64 = AtomicU64::new(0);
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let path = std::env::temp_dir().join(format!(
                    "forge_ops_tracker_test_{}_{nanos}_{n}.rs",
                    std::process::id()
                ));
                std::fs::write(&path, contents).expect("failed to write temp test file");
                TempFile { path }
            }

            fn path_string(&self) -> String {
                self.path.to_string_lossy().into_owned()
            }
        }

        impl Drop for TempFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
            }
        }

        fn numbered_lines(count: usize) -> String {
            (1..=count)
                .map(|n| format!("line {n}"))
                .collect::<Vec<_>>()
                .join("\n")
        }

        fn frame_in_app(file: String, line: u32) -> Frame {
            Frame::new(file, line, "call".to_string(), true)
        }

        #[test]
        fn attaches_window_around_the_culprit_line_by_default() {
            let file = TempFile::with_contents(&numbered_lines(20));
            let mut config = test_configuration();
            config.app_root = Some(std::env::temp_dir().to_string_lossy().into_owned());

            let frame = attach_source_context(&config, frame_in_app(file.path_string(), 10));

            assert_eq!(frame.context_line, Some("line 10".to_string()));
            assert_eq!(
                frame.pre_context,
                Some((5..=9).map(|n| format!("line {n}")).collect())
            );
            assert_eq!(
                frame.post_context,
                Some((11..=15).map(|n| format!("line {n}")).collect())
            );
        }

        #[test]
        fn clamps_at_the_start_and_end_of_the_file_rather_than_panicking() {
            let file = TempFile::with_contents(&numbered_lines(3));
            let config = test_configuration();

            let first = attach_source_context(&config, frame_in_app(file.path_string(), 1));
            let last = attach_source_context(&config, frame_in_app(file.path_string(), 3));

            assert_eq!(first.pre_context, Some(vec![]));
            assert_eq!(
                first.post_context,
                Some(vec!["line 2".to_string(), "line 3".to_string()])
            );
            assert_eq!(
                last.pre_context,
                Some(vec!["line 1".to_string(), "line 2".to_string()])
            );
            assert_eq!(last.post_context, Some(vec![]));
        }

        #[test]
        fn truncates_a_line_longer_than_max_context_line_length() {
            let overlong = "x".repeat(600);
            let file = TempFile::with_contents(&overlong);
            let config = test_configuration();

            let frame = attach_source_context(&config, frame_in_app(file.path_string(), 1));

            assert_eq!(frame.context_line, Some(format!("{}...", "x".repeat(500))));
        }

        #[test]
        fn never_attaches_context_to_a_frame_that_is_not_in_app() {
            let file = TempFile::with_contents(&numbered_lines(20));
            let config = test_configuration();
            let frame = Frame::new(file.path_string(), 10, "call".to_string(), false);

            let frame = attach_source_context(&config, frame);

            assert_eq!(frame.context_line, None);
            assert_eq!(frame.pre_context, None);
            assert_eq!(frame.post_context, None);
        }

        // Rust's std::fs offers no seam to spy on whether read_to_string was actually called (no
        // trait indirection is used here, matching every other file in this crate), so this
        // proves the behavioral contract instead: with the flag off, a frame whose file is real
        // and reads back real, distinguishable content still comes back with no context fields
        // at all: the only way that's possible is if attach_source_context's config check
        // short-circuits before ever reaching the fs::read_to_string call below it.
        #[test]
        fn leaves_the_frame_untouched_when_capture_source_context_is_disabled() {
            let file = TempFile::with_contents(&numbered_lines(20));
            let mut config = test_configuration();
            config.capture_source_context = false;

            let frame = attach_source_context(&config, frame_in_app(file.path_string(), 10));

            assert_eq!(frame.context_line, None);
            assert_eq!(frame.pre_context, None);
            assert_eq!(frame.post_context, None);
        }

        #[test]
        fn leaves_the_frame_untouched_when_the_file_cannot_be_read() {
            let config = test_configuration();
            let missing_path = std::env::temp_dir()
                .join("forge_ops_tracker_test_does_not_exist_12345.rs")
                .to_string_lossy()
                .into_owned();

            let frame = attach_source_context(&config, frame_in_app(missing_path, 1));

            assert_eq!(frame.context_line, None);
            assert_eq!(frame.pre_context, None);
            assert_eq!(frame.post_context, None);
        }

        #[test]
        fn wire_format_uses_snake_case_keys_when_context_is_present_and_omits_them_otherwise() {
            let with_context = Frame {
                context_line: Some("line 10".to_string()),
                pre_context: Some(vec!["line 9".to_string()]),
                post_context: Some(vec!["line 11".to_string()]),
                ..frame_in_app("/app/src/main.rs".to_string(), 10)
            };
            let event = Event {
                exception_class: "Error".to_string(),
                message: "boom".to_string(),
                backtrace: vec![with_context],
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
            };

            let json = event.to_json();

            assert!(json.contains("\"context_line\":\"line 10\""));
            assert!(json.contains("\"pre_context\":[\"line 9\"]"));
            assert!(json.contains("\"post_context\":[\"line 11\"]"));
            assert!(!json.contains("\"user\""));

            let without_context = Event {
                backtrace: vec![frame_in_app("/app/src/main.rs".to_string(), 10)],
                ..event
            };
            let json = without_context.to_json();

            assert!(!json.contains("context_line"));
            assert!(!json.contains("pre_context"));
            assert!(!json.contains("post_context"));
        }

        #[test]
        fn wire_format_includes_user_when_present_and_omits_it_otherwise() {
            let mut user = HashMap::new();
            user.insert(
                "email".to_string(),
                Value::String("ada@example.com".to_string()),
            );
            let event = Event {
                exception_class: "Error".to_string(),
                message: "boom".to_string(),
                backtrace: vec![],
                occurred_at: "2024-01-15T10:30:00Z".to_string(),
                environment: "production".to_string(),
                release: None,
                server_name: None,
                context: HashMap::new(),
                tags: HashMap::new(),
                sdk_name: "rust".to_string(),
                user: Some(user),
                breadcrumbs: vec![],
                sql_objects: None,
                sql_statement: None,
                trace_id: None,
                message_fingerprint: None,
            };

            let json = event.to_json();

            assert!(json.contains("\"user\":{\"email\":\"ada@example.com\"}"));

            let without_user = Event {
                user: None,
                ..event
            };
            assert!(!without_user.to_json().contains("\"user\""));
        }

        #[test]
        fn wire_format_includes_breadcrumbs_when_present_and_omits_them_otherwise() {
            let crumb = Breadcrumb {
                category: "controller".to_string(),
                message: "GET /orders/42".to_string(),
                level: "info".to_string(),
                timestamp: "2024-01-15T10:29:58Z".to_string(),
                data: HashMap::from([("status".to_string(), Value::Number(200.0))]),
            };
            let event = Event {
                exception_class: "Error".to_string(),
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
                breadcrumbs: vec![crumb],
                sql_objects: None,
                sql_statement: None,
                trace_id: None,
                message_fingerprint: None,
            };

            let json = event.to_json();

            assert!(json.contains(
                "\"breadcrumbs\":[{\"category\":\"controller\",\"message\":\"GET /orders/42\",\"level\":\"info\",\"timestamp\":\"2024-01-15T10:29:58Z\",\"data\":{\"status\":200}}]"
            ));

            let without_breadcrumbs = Event {
                breadcrumbs: vec![],
                ..event
            };
            assert!(!without_breadcrumbs.to_json().contains("\"breadcrumbs\""));
        }

        #[test]
        fn wire_format_includes_trace_id_when_present_and_omits_it_otherwise() {
            let event = Event {
                exception_class: "Error".to_string(),
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
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                message_fingerprint: None,
            };

            assert!(event
                .to_json()
                .ends_with(",\"trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\"}"));

            let without_trace = Event {
                trace_id: None,
                ..event
            };
            assert!(!without_trace.to_json().contains("\"trace_id\""));
        }
    }

    mod sql_capture {
        use super::*;
        use crate::Configuration;

        fn build(config: &Configuration, sql: Option<&str>) -> Event {
            EventBuilder::new(config).build_with_sql(
                "Error",
                "boom",
                vec![],
                HashMap::new(),
                None,
                vec![],
                sql,
            )
        }

        const SQL: &str = "EXEC dbo.sp_refund_order @order_id = 8814, @note = 'a@b.co'";

        #[test]
        fn sends_the_procedure_name_but_not_the_statement_by_default() {
            let event = build(&Configuration::new(), Some(SQL));

            assert_eq!(
                event.sql_objects.unwrap().procedures,
                vec!["dbo.sp_refund_order"]
            );
            assert_eq!(event.sql_statement, None);
        }

        #[test]
        fn sends_the_masked_statement_when_opted_in() {
            let mut config = Configuration::new();
            config.capture_sql_statement = true;

            let event = build(&config, Some(SQL));

            assert_eq!(
                event.sql_statement.as_deref(),
                Some("EXEC dbo.sp_refund_order @order_id = ?, @note = ?")
            );
            assert!(event.to_json().contains(
                "\"sql_statement\":\"EXEC dbo.sp_refund_order @order_id = ?, @note = ?\""
            ));
            assert!(event
                .to_json()
                .contains("\"sql_objects\":{\"operation\":\"EXEC\""));
        }

        #[test]
        fn sends_nothing_when_both_are_off_or_no_sql_was_given() {
            let mut config = Configuration::new();
            config.capture_sql_objects = false;
            let off = build(&config, Some(SQL));
            assert!(off.sql_objects.is_none() && off.sql_statement.is_none());

            let none = build(&Configuration::new(), None);
            assert!(none.sql_objects.is_none() && none.sql_statement.is_none());
            assert!(!none.to_json().contains("sql_"));
        }
    }
}
