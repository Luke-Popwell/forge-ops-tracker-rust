//! ForgeOps error tracking client for ForgeOps:
//!
//! ```no_run
//! forge_ops_tracker::init(|c| {
//!     c.dsn = Some("https://<api_key>@getforgeops.net/api/v1/events".to_string());
//! });
//! ```
//!
//! See the README for what gets captured automatically vs. what needs an explicit
//! [`capture_error`] call. A from-scratch port of `gems/forge_ops_tracker` (the Rails client):
//! see that gem's README for the shared design rationale behind the pieces this crate is built
//! from (Configuration, EventBuilder, DeliveryQueue, Reporter, Client).

mod breadcrumb_buffer;
mod change_tracking;
mod client;
mod configuration;
mod delivery_queue;
mod event_builder;
mod histogram_bucketer;
mod metric_buffer;
mod performance_flusher;
mod pii_scrubber;
mod reporter;
mod span_buffer;
mod span_queue;
mod sql_statement;
mod strict_privacy;
#[cfg(test)]
mod test_support;
mod trace_parent;

pub use breadcrumb_buffer::Breadcrumb;
pub use change_tracking::Change;
pub use configuration::{Configuration, TracePropagationTarget};
pub use event_builder::{Event, Frame};
pub use pii_scrubber::Value;
pub use sql_statement::SqlObjects;

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use client::Client;
use delivery_queue::DeliveryQueue;
use metric_buffer::{Kind, MetricBuffer};
use performance_flusher::PerformanceFlusher;
use reporter::Reporter;
use span_queue::SpanQueue;

struct State {
    configuration: Arc<RwLock<Configuration>>,
    reporter: Reporter,
    performance_flusher: Arc<PerformanceFlusher>,
    span_queue: SpanQueue,
    metrics: Arc<MetricBuffer>,
    infrastructure_metrics: Arc<MetricBuffer>,
}

static STATE: OnceLock<State> = OnceLock::new();

// Whether this process has queued its startup change snapshot: once per process, however many
// times `init()` runs.
static CHANGE_SNAPSHOT_SENT: AtomicBool = AtomicBool::new(false);

thread_local! {
    // The user set via `set_user`, if any. A plain thread-local, not a process-wide global: the
    // right choice for the thread-per-request model this crate's own synchronous, non-async
    // design naturally pairs with (see Cargo.toml's own comment on why `ureq`, not an async HTTP
    // client, was chosen), the same reasoning `gems/forge_ops_tracker` documents for its own
    // `Thread.current` use. **Does not propagate across an `.await` in an async runtime**: unlike
    // Ruby's green/native threads, a single OS thread in an async executor (tokio, async-std)
    // interleaves multiple unrelated tasks, so a value set on one task can leak into, or simply
    // never reach, another. A host app built on an async runtime should pass `user` explicitly to
    // `capture_error`/`capture_error_with_class` instead of relying on `set_user`, the same way
    // `sdks/node` needs `AsyncLocalStorage` rather than a bare thread-local for the identical
    // reason.
    static CURRENT_USER: RefCell<Option<HashMap<String, Value>>> = const { RefCell::new(None) };
}

fn current_user() -> Option<HashMap<String, Value>> {
    CURRENT_USER.with(|u| u.borrow().clone())
}

fn state() -> &'static State {
    STATE.get_or_init(|| {
        let configuration = Arc::new(RwLock::new(Configuration::new()));
        let client = Arc::new(Client::new(Arc::clone(&configuration)));
        let queue_size = configuration.read().unwrap().queue_size;
        let delivery_queue = DeliveryQueue::new(queue_size, Arc::clone(&client));
        let span_queue = SpanQueue::new(queue_size, Arc::clone(&client));
        let metrics = MetricBuffer::new(
            Kind::Custom,
            Arc::clone(&configuration),
            Arc::clone(&client),
        );
        let infrastructure_metrics = MetricBuffer::new(
            Kind::Infrastructure,
            Arc::clone(&configuration),
            Arc::clone(&client),
        );
        let reporter = Reporter::new(Arc::clone(&configuration), delivery_queue);
        let performance_flusher = PerformanceFlusher::new(Arc::clone(&configuration), client);
        State {
            configuration,
            reporter,
            performance_flusher,
            span_queue,
            metrics,
            infrastructure_metrics,
        }
    })
}

/// Set once the "not sending from this environment" warning has printed, so it prints once per
/// process however many times `init` runs.
static NOT_SENDING_WARNED: AtomicBool = AtomicBool::new(false);

/// Writes [`Configuration::not_sending_warning`] to `out` (stderr, outside tests) at most once,
/// tracked by `warned`: this crate has no logger, and a DSN that quietly sends nothing is the one
/// setup mistake a new install can't otherwise see. Silent without a DSN.
fn warn_if_not_sending(config: &Configuration, warned: &AtomicBool, out: &mut impl std::io::Write) {
    let Some(warning) = config.not_sending_warning() else {
        return;
    };
    if warned
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let _ = writeln!(out, "[ForgeOps] {warning}");
    }
}

/// Configures the client. Call once at startup, before your server starts accepting requests.
/// Pass a closure to set any [`Configuration`] field:
///
/// ```no_run
/// forge_ops_tracker::init(|c| {
///     c.dsn = Some("https://<api_key>@getforgeops.net/api/v1/events".to_string());
///     c.release = Some("a1b2c3d".to_string());
/// });
/// ```
///
/// Installs the global panic hook (see [`install_panic_hook`]) unless
/// `Configuration.install_panic_hook` is set to `false` inside the closure.
///
/// The first `init()` that leaves reporting enabled also queues one change snapshot (see
/// `Configuration.detect_changes`), delivered on the background thread so startup never waits on
/// it or fails because of it.
///
/// Delivery happens on background threads that don't outlive `main`, so a short-lived program
/// should hold a [`flush_guard`] or call [`flush`] before it returns.
pub fn init(configure: impl FnOnce(&mut Configuration)) {
    let s = state();
    let install_hook = {
        let mut config = s.configuration.write().unwrap();
        configure(&mut config);
        warn_if_not_sending(&config, &NOT_SENDING_WARNED, &mut std::io::stderr());
        config.install_panic_hook
    };
    if install_hook {
        install_panic_hook();
    }
    if CHANGE_SNAPSHOT_SENT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
        && !s.reporter.send_change_snapshot()
    {
        CHANGE_SNAPSHOT_SENT.store(false, Ordering::SeqCst);
    }
}

/// Records one change (a feature flag flip, a config edit, a migration, anything worth lining up
/// against your errors) so ForgeOps can show it next to what happened afterward. Delivered on the
/// background thread like any error, so this never blocks; a no-op when reporting isn't enabled,
/// and a failed delivery (including a plan without change tracking) is silently dropped.
///
/// ```no_run
/// use forge_ops_tracker::{context, Change};
///
/// forge_ops_tracker::record_change(Change::new("migration", "Add index to orders.created_at"));
/// forge_ops_tracker::record_change(Change {
///     details: context! {"flag" => "new_checkout", "enabled" => true},
///     actor: Some("alice@example.com".to_string()),
///     ..Change::new("feature_flag", "Enabled new checkout for everyone")
/// });
/// ```
pub fn record_change(change: Change) {
    state().reporter.record_change(&change);
}

/// Reports an error you've already handled. Call it right at the point you'd otherwise just log
/// it:
///
/// ```no_run
/// # use std::collections::HashMap;
/// # fn charge_card() -> Result<(), std::io::Error> { Ok(()) }
/// if let Err(err) = charge_card() {
///     forge_ops_tracker::capture_error(&err, HashMap::new(), None);
/// }
/// ```
///
/// The backtrace is captured right here, at the call site: unlike Python/Java/PHP, a plain Rust
/// `std::error::Error` carries no stack of its own, so `capture_error` has to be the one call that
/// knows where the trace starts. `exception_class` is inferred via [`std::any::type_name`], which
/// needs `E` to be a concrete, statically-known type: for a `Box<dyn Error>` or other trait
/// object, where that isn't possible, use [`capture_error_with_class`] instead and supply the
/// class yourself.
///
/// `user` defaults to whatever [`set_user`] last established on this thread, if anything (`None`
/// here means "use that", not "no user"); pass `Some(..)` to override it for this one report.
pub fn capture_error<E: std::error::Error>(
    err: &E,
    context: HashMap<String, Value>,
    user: Option<HashMap<String, Value>>,
) {
    capture_error_with_class(std::any::type_name::<E>(), err, context, user);
}

/// The same as [`capture_error`], but for a `&dyn std::error::Error` (a `Box<dyn Error>`, a trait
/// object) whose concrete type isn't known at the call site, so `exception_class` has to be
/// supplied explicitly rather than inferred.
pub fn capture_error_with_class(
    exception_class: &str,
    err: &dyn std::error::Error,
    context: HashMap<String, Value>,
    user: Option<HashMap<String, Value>>,
) {
    let s = state();
    s.reporter.report_with_captured_backtrace(
        exception_class,
        &err.to_string(),
        context,
        user.or_else(current_user),
        breadcrumb_buffer::current_breadcrumbs(),
    );
}

/// The same as [`capture_error`], for an error caused by a database call: pass the SQL that ran.
/// A Rust error carries no statement of its own and no Rust database crate puts one on its error
/// types, so the code that ran the query has to hand it over.
///
/// With `Configuration::capture_sql_objects` on (the default), the names of the stored procedure,
/// table and view the statement touched are sent, so an issue says where to start looking. With
/// `Configuration::capture_sql_statement` on too (off by default), the statement itself is sent as
/// well, with every string and number replaced by `?` first. The raw statement never leaves this
/// process either way.
///
/// ```ignore
/// if let Err(err) = sqlx::query(QUERY).bind(id).execute(&pool).await {
///     forge_ops_tracker::capture_error_with_sql(&err, QUERY, HashMap::new(), None);
/// }
/// ```
pub fn capture_error_with_sql<E: std::error::Error>(
    err: &E,
    statement: &str,
    context: HashMap<String, Value>,
    user: Option<HashMap<String, Value>>,
) {
    capture_error_with_class_and_sql(std::any::type_name::<E>(), err, statement, context, user);
}

/// The same as [`capture_error_with_sql`], but for a `&dyn std::error::Error` whose concrete type
/// isn't known at the call site, so `exception_class` is supplied explicitly.
pub fn capture_error_with_class_and_sql(
    exception_class: &str,
    err: &dyn std::error::Error,
    statement: &str,
    context: HashMap<String, Value>,
    user: Option<HashMap<String, Value>>,
) {
    let s = state();
    s.reporter.report_with_captured_backtrace_and_sql(
        exception_class,
        &err.to_string(),
        context,
        user.or_else(current_user),
        breadcrumb_buffer::current_breadcrumbs(),
        statement,
    );
}

/// Manually attaches an affected user to whatever gets reported from here on, *on this thread*
/// (an explicit [`capture_error`]/[`capture_error_with_class`] call with no `user` argument, or a
/// panic the installed hook catches): there's no way to automatically detect "the current user"
/// the way a server-side web framework with its own session/auth middleware can, so call this
/// yourself, e.g. right after sign-in. `id`/`email`/`username` are all independently optional;
/// call with an empty map to clear whatever was set, e.g. on sign-out. See this crate's own
/// `CURRENT_USER` thread-local (in the source) for why this is thread-local, and the real caveat
/// that comes with that choice under an async runtime.
pub fn set_user(user: HashMap<String, Value>) {
    let user = if user.is_empty() { None } else { Some(user) };
    CURRENT_USER.with(|u| *u.borrow_mut() = user);
}

/// Records one entry into the current thread's breadcrumb trail: a query, an outbound call, or
/// anything worth remembering right up to the moment something actually goes wrong. `category`
/// defaults to `"custom"` and `level` to `"info"` when passed an empty string. A no-op, not an
/// error, when `Configuration.track_breadcrumbs` is `false`.
///
/// This crate has no web framework integration of its own (unlike `sdks/go`'s net/http/Gin
/// middleware), so there's no automatic breadcrumb source and no middleware to start a fresh trail
/// per request on its own: call [`clear_breadcrumbs`] yourself at the start of each request, the
/// same place you'd already be calling [`set_user`] from, or entries from an earlier request
/// handled on a reused thread will bleed into this one's own report.
pub fn add_breadcrumb(message: &str, category: &str, level: &str, data: HashMap<String, Value>) {
    let config = state().configuration.read().unwrap();
    // Strict privacy never sends breadcrumbs, so none are recorded either.
    breadcrumb_buffer::add_breadcrumb(
        config.track_breadcrumbs && !config.strict_privacy,
        config.max_breadcrumbs,
        message,
        category,
        level,
        data,
    );
}

/// Clears the current thread's breadcrumb trail. See [`add_breadcrumb`]'s own doc for why calling
/// this yourself, at the start of each request, is this crate's responsibility to ask of you
/// rather than something it can do on its own.
pub fn clear_breadcrumbs() {
    breadcrumb_buffer::clear_breadcrumbs();
}

/// Records one timed call's duration, in milliseconds, under `transaction_name`: tallied
/// in-process (count, total, max) and flushed periodically as one small aggregate report, for the
/// Performance page's per-transaction table, not one network call per call. A no-op when
/// `Configuration.track_performance` is `false` or reporting isn't enabled for this environment.
///
/// This crate has no web framework integration of its own (unlike `sdks/go`'s net/http/Gin
/// middleware), so nothing is timed automatically: wrap whatever you want on the Performance page
/// yourself, e.g. a request handler, with [`time_transaction`], or call this directly with a
/// duration you measured. Keep `transaction_name` low-cardinality (`"GET /users/:id"`, not
/// `"GET /users/42"`): every distinct name is its own row.
pub fn record_performance(transaction_name: &str, duration_ms: f64) {
    state()
        .performance_flusher
        .record(transaction_name, duration_ms);
}

/// Runs `f`, records how long it took under `transaction_name` (see [`record_performance`]), and
/// returns whatever `f` returned. Recorded even if `f` panics: the duration up to the panic is
/// still a real duration, and a handler that panics is exactly one worth seeing on the
/// Performance page.
///
/// ```no_run
/// # fn handle_request() -> u32 { 200 }
/// let status = forge_ops_tracker::time_transaction("GET /users/:id", || handle_request());
/// ```
pub fn time_transaction<T>(transaction_name: &str, f: impl FnOnce() -> T) -> T {
    struct Timing<'a> {
        name: &'a str,
        started_at: std::time::Instant,
    }
    impl Drop for Timing<'_> {
        fn drop(&mut self) {
            record_performance(self.name, self.started_at.elapsed().as_secs_f64() * 1000.0);
        }
    }

    let _timing = Timing {
        name: transaction_name,
        started_at: std::time::Instant::now(),
    };
    f()
}

/// Delivers whatever has been tallied so far right now, instead of waiting for the next
/// `performance_flush_interval` tick. The background flush thread is a daemon: it does not run on
/// a normal process exit the way the Ruby gem's `at_exit` hook does (Rust has no equivalent), so a
/// short-lived program, or one about to shut down, should call this itself to avoid losing the
/// last partial window.
pub fn flush_performance() {
    state().performance_flusher.flush();
}

/// Records a named business metric (a signup, a payment, anything you want to name), buffered and
/// flushed periodically as one batch rather than one network call per capture. Pass `1.0` for a bare
/// counter-style call ("a signup happened") or a real magnitude ("a $49 payment"); it may be negative
/// (a refund). A no-op when the client isn't enabled (no DSN, or this environment isn't in
/// `enabled_environments`), and a NaN or infinite value is dropped.
///
/// Rust has no exit hook to flush from, so a short-lived program should call [`flush`] (or
/// [`flush_metrics`]) before it returns from `main`.
///
/// ```no_run
/// forge_ops_tracker::capture_metric("signup", 1.0);
/// forge_ops_tracker::capture_metric("payment", 49.0);
/// ```
pub fn capture_metric(name: &str, value: f64) {
    let s = state();
    let (enabled, environment, release) = {
        let config = s.configuration.read().unwrap();
        (
            config.is_enabled(),
            config.environment.clone(),
            config.release.clone(),
        )
    };
    if !enabled {
        return;
    }
    let release = release
        .as_deref()
        .map(pii_scrubber::json_string)
        .unwrap_or_else(|| "null".to_string());
    s.metrics.record(
        value,
        &format!(
            "\"metric_name\":{},\"value\":{value},\"environment\":{},\"release\":{release}",
            pii_scrubber::json_string(name),
            pii_scrubber::json_string(&environment),
        ),
    );
}

/// Records one infrastructure reading (CPU, memory, disk, anything else a program of yours reads)
/// from one of your own hosts. `hostname` defaults to `Configuration.server_name` when `None`, so a
/// script running on the box it reports about needs no argument. Same buffered-batch delivery and
/// no-op-when-disabled contract as [`capture_metric`].
///
/// ```no_run
/// forge_ops_tracker::capture_infrastructure_metric("cpu", 0.42, None);
/// forge_ops_tracker::capture_infrastructure_metric("disk", 0.81, Some("db-1"));
/// forge_ops_tracker::flush_metrics();
/// ```
pub fn capture_infrastructure_metric(name: &str, value: f64, hostname: Option<&str>) {
    let s = state();
    let (enabled, server_name) = {
        let config = s.configuration.read().unwrap();
        (config.is_enabled(), config.server_name.clone())
    };
    if !enabled {
        return;
    }
    let hostname = hostname
        .map(str::to_string)
        .or(server_name)
        .unwrap_or_default();
    s.infrastructure_metrics.record(
        value,
        &format!(
            "\"metric_name\":{},\"value\":{value},\"hostname\":{}",
            pii_scrubber::json_string(name),
            pii_scrubber::json_string(&hostname),
        ),
    );
}

/// Delivers every buffered metric and infrastructure reading right now, instead of waiting for the
/// next flush interval. The background flush thread is a daemon and Rust has no exit hook, so call
/// this before a short-lived program ends.
pub fn flush_metrics() {
    let s = state();
    s.metrics.flush();
    s.infrastructure_metrics.flush();
}

/// Sends everything this client is still holding: queued errors and changes, captured traces,
/// buffered metrics and infrastructure readings, and the current performance window. Waits at most
/// `timeout` in total and returns whether it all finished in time (a delivery the server rejected
/// still counts as finished: this is about not leaving anything behind, not about whether ForgeOps
/// accepted it). [`flush_metrics`], [`flush_performance`] and the periodic flushes keep working as
/// before; this is the one call that covers all of them.
///
/// Delivery happens on background threads and Rust has no exit hook (statics are never dropped),
/// so a program that returns from `main` right after reporting something loses it unless it calls
/// this first. Call it at the end of `main` in a script, CLI or cron job, or hold a
/// [`flush_guard`] so it also runs on an early return or `?`:
///
/// ```no_run
/// # use std::time::Duration;
/// forge_ops_tracker::init(|c| { /* ... */ });
/// // ... the program's work ...
/// forge_ops_tracker::flush(Duration::from_secs(2));
/// ```
///
/// A long-running server doesn't need it, other than on a graceful shutdown. Returns `true` at
/// once if nothing was ever reported.
pub fn flush(timeout: Duration) -> bool {
    let Some(s) = STATE.get() else {
        return true;
    };
    let deadline = Instant::now() + timeout;
    if !s.reporter.flush(timeout) {
        return false;
    }
    if !s
        .span_queue
        .flush(deadline.saturating_duration_since(Instant::now()))
    {
        return false;
    }
    // The buffers deliver synchronously, with only Configuration.timeout as a bound; run them on a
    // thread of their own so this call's own timeout still holds. One that overruns keeps going in
    // the background; it just isn't waited for.
    let (done, finished) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("forge-ops-tracker-flush".to_string())
        .spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                s.performance_flusher.flush();
                s.metrics.flush();
                s.infrastructure_metrics.flush();
            }));
            let _ = done.send(());
        });
    spawned.is_ok()
        && finished
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok()
}

/// Calls [`flush`] with `timeout` when dropped. See [`flush_guard`].
#[must_use = "the guard flushes when it's dropped, so binding it to `_` flushes immediately"]
pub struct FlushGuard {
    timeout: Duration,
}

impl Drop for FlushGuard {
    fn drop(&mut self) {
        flush(self.timeout);
    }
}

/// Returns a guard that calls [`flush`] with `timeout` when it goes out of scope, so a `main` that
/// returns early, or through `?`, still sends what it reported. Hold it for the whole of `main`:
///
/// ```no_run
/// # use std::time::Duration;
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     forge_ops_tracker::init(|c| { /* ... */ });
///     let _flush = forge_ops_tracker::flush_guard(Duration::from_secs(2));
///     // ... the program's work ...
///     Ok(())
/// }
/// ```
///
/// Not run by `std::process::exit`, which skips destructors: call [`flush`] yourself before one.
pub fn flush_guard(timeout: Duration) -> FlushGuard {
    FlushGuard { timeout }
}

/// How long the panic hook waits for the panic it just reported to go out before letting the panic
/// continue: long enough for one delivery at the default `Configuration.timeout`, short enough that
/// an unreachable ForgeOps barely delays the crash.
const PANIC_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// The name of the W3C Trace Context header: what [`continue_trace`] reads from an incoming
/// request and what [`http_span`]'s value goes out as.
pub const TRACEPARENT_HEADER: &str = trace_parent::HEADER;

/// Runs `f` as a trace named `root_name` (for example `"GET /checkout"` or `"job:reindex"`): every
/// [`span`], [`http_span`] and [`record_span`] inside it, on this thread, nests beneath this root.
/// When `f` took at least `Configuration.trace_capture_threshold` (1 second by default) the whole
/// trace is sent to ForgeOps, so fast calls cost nothing on the wire. Sent even if `f` panics.
/// Called inside an already-open trace it just records a span instead. Errors captured inside it
/// carry its trace id (see [`current_trace_id`]).
///
/// This crate has no web framework integration, so nothing starts a trace automatically: wrap
/// whatever you want traced, typically a request handler or a background job. To continue a trace
/// another service started, use [`continue_trace`] with its `traceparent` header.
///
/// ```no_run
/// # fn handle_request() -> u32 { 200 }
/// let status = forge_ops_tracker::trace("GET /checkout", || handle_request());
/// ```
pub fn trace<T>(root_name: &str, f: impl FnOnce() -> T) -> T {
    continue_trace(root_name, None, f)
}

/// The same as [`trace`], continuing the caller's trace when `traceparent` is a usable W3C
/// `traceparent` header value, typically the incoming request's own header: the trace keeps the
/// caller's trace id, and its root span records the caller's span as its parent, so it nests under
/// that span on ForgeOps. `None`, blank, or malformed starts a fresh trace, exactly like [`trace`].
/// Ignored inside an already-open trace.
///
/// ```no_run
/// # fn handle_request() -> u32 { 200 }
/// # let incoming: Option<String> = None;
/// // `incoming` is the request's own "traceparent" header, however your server exposes it.
/// let status = forge_ops_tracker::continue_trace("POST /orders", incoming.as_deref(), || {
///     handle_request()
/// });
/// ```
pub fn continue_trace<T>(root_name: &str, traceparent: Option<&str>, f: impl FnOnce() -> T) -> T {
    let (owns_trace, threshold) = {
        let config = state().configuration.read().unwrap();
        let incoming = traceparent.and_then(trace_parent::parse);
        (
            span_buffer::begin(&config, incoming),
            config.trace_capture_threshold,
        )
    };
    if !owns_trace {
        return span(root_name, "service", HashMap::new(), f);
    }

    struct Root<'a> {
        name: &'a str,
        started_at: std::time::SystemTime,
        timer: std::time::Instant,
        threshold: std::time::Duration,
    }
    impl Drop for Root<'_> {
        fn drop(&mut self) {
            let duration_ms = self.timer.elapsed().as_secs_f64() * 1000.0;
            if let Some(body) = span_buffer::end(
                self.threshold,
                self.name,
                "controller",
                self.started_at,
                duration_ms,
            ) {
                state().span_queue.push(body);
            }
        }
    }

    let _root = Root {
        name: root_name,
        started_at: std::time::SystemTime::now(),
        timer: std::time::Instant::now(),
        threshold,
    };
    f()
}

/// Times `f` as a child span of whatever span is open on this thread (or of the trace's root),
/// returning what `f` returned. Outside a [`trace`] it just runs `f`. Recorded even if `f` panics.
/// `kind` is one of `"controller"`, `"service"`, `"database"`, `"redis"`, `"http"`, `"job"`,
/// `"other"` (anything else is sent as `"other"`).
///
/// ```no_run
/// # use std::collections::HashMap;
/// # fn charge(id: u32) -> u32 { id }
/// let charged = forge_ops_tracker::span("charge card", "service", HashMap::new(), || charge(7));
/// ```
pub fn span<T>(name: &str, kind: &str, data: HashMap<String, Value>, f: impl FnOnce() -> T) -> T {
    let Some((id, parent)) = span_buffer::open_span() else {
        return f();
    };

    struct Open<'a> {
        id: String,
        parent: String,
        name: &'a str,
        kind: &'a str,
        data: HashMap<String, Value>,
        started_at: std::time::SystemTime,
        timer: std::time::Instant,
    }
    impl Drop for Open<'_> {
        fn drop(&mut self) {
            span_buffer::close_span(
                std::mem::take(&mut self.id),
                std::mem::take(&mut self.parent),
                self.name,
                self.kind,
                self.started_at,
                self.timer.elapsed().as_secs_f64() * 1000.0,
                std::mem::take(&mut self.data),
            );
        }
    }

    let _open = Open {
        id,
        parent,
        name,
        kind,
        data,
        started_at: std::time::SystemTime::now(),
        timer: std::time::Instant::now(),
    };
    f()
}

/// Times a database query as a `"database"` span carrying its SQL, so ForgeOps can show which
/// statement a slow request spent its time in. Returns what `f` returned; outside a [`trace`] it
/// just runs `f`.
///
/// ```no_run
/// # fn load_orders(sql: &str) -> Vec<u64> { let _ = sql; vec![] }
/// let sql = "SELECT id FROM orders WHERE customer_id = $1 AND status = 'open'";
/// let orders = forge_ops_tracker::database_span("load orders", sql, Some("postgresql"), || load_orders(sql));
/// ```
///
/// The statement is masked (every string and number replaced by `?`) and cut to 4000 characters
/// when the span is recorded, then sent as `db.statement`; `db_system` (`"postgresql"`, `"mysql"`,
/// `"sqlite"`, `"mssql"`, `"oracle"`, or any other name) goes out lowercased as `db.system`. Bind
/// values are never taken.
pub fn database_span<T>(
    name: &str,
    statement: &str,
    db_system: Option<&str>,
    f: impl FnOnce() -> T,
) -> T {
    span(
        name,
        "database",
        database_span_data(statement, db_system),
        f,
    )
}

/// [`record_span`] for a query you timed yourself, carrying its SQL as [`database_span`] does.
pub fn record_database_span(
    name: &str,
    statement: &str,
    db_system: Option<&str>,
    started_at: std::time::SystemTime,
    duration_ms: f64,
) {
    record_span(
        name,
        "database",
        started_at,
        duration_ms,
        database_span_data(statement, db_system),
    );
}

/// The data a database span carries: `db.statement` and `db.system`, each left out when blank.
/// Add your own keys and pass it to [`span`] or [`record_span`] with kind `"database"` if you
/// prefer; a `db.statement` on any database span is masked when it's recorded, however the map
/// was built.
pub fn database_span_data(statement: &str, db_system: Option<&str>) -> HashMap<String, Value> {
    let mut data = HashMap::new();
    if !statement.trim().is_empty() {
        data.insert(
            span_buffer::DB_STATEMENT.to_string(),
            Value::from(statement),
        );
    }
    if let Some(system) = db_system.map(str::trim).filter(|s| !s.is_empty()) {
        data.insert(
            span_buffer::DB_SYSTEM.to_string(),
            Value::String(system.to_lowercase()),
        );
    }
    data
}

/// Times an outgoing HTTP call as an `http` span named `"<METHOD> <host>"` (never the path or
/// query, which can carry ids or tokens) and hands `f` the `traceparent` header value to send with
/// that request: its parent id is this span's own id, so the called service's root span nests under
/// it when it continues the trace. Set it however your HTTP client does:
///
/// ```no_run
/// # use std::collections::HashMap;
/// let url = "https://api.example.com/orders";
/// let response = forge_ops_tracker::http_span("POST", url, HashMap::new(), |traceparent| {
///     let mut request = ureq::post(url);
///     if let Some(value) = traceparent {
///         request = request.set(forge_ops_tracker::TRACEPARENT_HEADER, value);
///     }
///     request.send_string("{}")
/// });
/// ```
///
/// `f` gets `None` outside a [`trace`], when `Configuration.propagate_traces` is off, or when the
/// URL's host isn't in `Configuration.trace_propagation_targets`; outside a trace no span is
/// recorded either. Recorded even if `f` panics. This crate doesn't instrument any HTTP client on
/// its own, so a call made without this helper carries no header.
pub fn http_span<T>(
    method: &str,
    url: &str,
    data: HashMap<String, Value>,
    f: impl FnOnce(Option<&str>) -> T,
) -> T {
    let Some((id, parent)) = span_buffer::open_span() else {
        return f(None);
    };
    let host = trace_parent::url_host(url);
    let traceparent = {
        let config = state().configuration.read().unwrap();
        config.should_propagate_trace(host.as_deref())
    }
    .then(span_buffer::current_trace_id)
    .flatten()
    .map(|trace_id| trace_parent::build(&trace_id, &id));
    let name = format!(
        "{} {}",
        method.to_ascii_uppercase(),
        host.as_deref().unwrap_or("unknown")
    );

    struct Open {
        id: String,
        parent: String,
        name: String,
        data: HashMap<String, Value>,
        started_at: std::time::SystemTime,
        timer: std::time::Instant,
    }
    impl Drop for Open {
        fn drop(&mut self) {
            span_buffer::close_span(
                std::mem::take(&mut self.id),
                std::mem::take(&mut self.parent),
                &self.name,
                "http",
                self.started_at,
                self.timer.elapsed().as_secs_f64() * 1000.0,
                std::mem::take(&mut self.data),
            );
        }
    }

    let _open = Open {
        id,
        parent,
        name,
        data,
        started_at: std::time::SystemTime::now(),
        timer: std::time::Instant::now(),
    };
    f(traceparent.as_deref())
}

/// The id of the trace open on this thread (32 lowercase hex characters), or `None` outside a
/// [`trace`]. Errors captured on this thread while it's open carry it automatically.
pub fn current_trace_id() -> Option<String> {
    span_buffer::current_trace_id()
}

/// Records a span you timed yourself under the current one; a no-op outside a [`trace`].
pub fn record_span(
    name: &str,
    kind: &str,
    started_at: std::time::SystemTime,
    duration_ms: f64,
    data: HashMap<String, Value>,
) {
    span_buffer::record_leaf(name, kind, started_at, duration_ms, data);
}

/// Installs a global panic hook that reports any panic on any thread, then calls whatever hook
/// was previously installed (Rust's own default, which prints to stderr, unless something else
/// already replaced it): never changing panic behavior itself, the same "report, then don't
/// change program behavior" rule the .NET middleware and Python `excepthook` wrapper both follow.
///
/// Unlike Go, where only a `defer Recover()` in the same goroutine can see a panic, Rust's panic
/// hook is genuinely process-wide: it fires for a panic on *any* thread, including a web
/// framework's own worker threads, with no per-framework middleware needed at all. `init()` calls
/// this automatically unless `Configuration.install_panic_hook` is set to `false`; call it
/// directly only if you're managing configuration some other way.
///
/// Always chains onto whatever hook is *currently* installed via `take_hook()`, rather than
/// latching "already installed" after the first call: deliberately, even though that means
/// calling this more than once wraps another reporting layer each time (a real panic would then
/// report once per accumulated layer). A one-shot latch was tried first and rejected: it makes
/// this call a silent no-op the moment anything else calls `std::panic::set_hook` after this one
/// runs (a host app installing its own hook after `init()`, say), discarding this crate's
/// reporting entirely with no error or warning. Duplicate reports from calling this redundantly
/// is a far more visible, far less damaging failure mode than reporting silently going dark, and
/// is easily avoided the same way `init()` already asks to be called: once, at startup.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report_panic(info);
        flush_reported_panic();
        previous(info);
    }));
}

/// Waits (up to `PANIC_FLUSH_TIMEOUT`) for the error queue to deliver the panic just reported, so
/// a panic that ends the process (on the main thread, or anywhere under `panic = "abort"`) still
/// reaches ForgeOps rather than dying with the delivery thread. Only the error queue, not traces or
/// metrics, so a panicking request thread in a server isn't held up by an unrelated flush. Skipped
/// on the delivery thread itself, which would otherwise wait on its own queue.
fn flush_reported_panic() {
    if std::thread::current().name() == Some(delivery_queue::WORKER_THREAD_NAME) {
        return;
    }
    if let Some(s) = STATE.get() {
        s.reporter.flush(PANIC_FLUSH_TIMEOUT);
    }
}

fn report_panic(info: &std::panic::PanicHookInfo) {
    let s = state();
    let (exception_class, message) = panic_message(info);

    let mut context = HashMap::new();
    if let Some(location) = info.location() {
        context.insert(
            "panic_location".to_string(),
            Value::String(format!(
                "{}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            )),
        );
    }

    s.reporter.report_with_captured_backtrace(
        &exception_class,
        &message,
        context,
        current_user(),
        breadcrumb_buffer::current_breadcrumbs(),
    );
}

/// panic!() accepts any value, but the overwhelming majority of real panics carry either a `&str`
/// (`panic!("boom")`) or a `String` (`panic!("boom: {err}")`) payload: these are the only two
/// downcast targets std's own default panic hook special-cases too. Anything else reports as a
/// generic "non-string panic payload" message, since there's no way to `Display` an arbitrary
/// `dyn Any` payload.
fn panic_message(info: &std::panic::PanicHookInfo) -> (String, String) {
    let payload = info.payload();
    if let Some(s) = payload.downcast_ref::<&str>() {
        ("panic".to_string(), s.to_string())
    } else if let Some(s) = payload.downcast_ref::<String>() {
        ("panic".to_string(), s.clone())
    } else {
        ("panic".to_string(), "non-string panic payload".to_string())
    }
}

/// Builds a `HashMap<String, Value>` from `key => value` pairs, the same literal-context ergonomics
/// every other client in this repo gets for free from its own language (a Python dict, a JS object
/// literal, a PHP array):
///
/// ```
/// let ctx = forge_ops_tracker::context!{"order_id" => 42, "customer" => "acme-inc"};
/// ```
#[macro_export]
macro_rules! context {
    ( $( $key:expr => $value:expr ),* $(,)? ) => {{
        #[allow(unused_mut)]
        let mut map = ::std::collections::HashMap::new();
        $( map.insert(::std::string::ToString::to_string($key), $crate::Value::from($value)); )*
        map
    }};
}

/// Extension trait for `Result`, so a fallible call can report its own error and still propagate
/// it in one step:
///
/// ```no_run
/// # use std::collections::HashMap;
/// use forge_ops_tracker::ResultReportExt;
/// # fn charge_card() -> Result<(), std::io::Error> { Ok(()) }
/// # fn run() -> Result<(), std::io::Error> {
/// charge_card().report_err(HashMap::new(), None)?;
/// # Ok(())
/// # }
/// ```
pub trait ResultReportExt<T> {
    fn report_err(
        self,
        context: HashMap<String, Value>,
        user: Option<HashMap<String, Value>>,
    ) -> Self;
}

impl<T, E: std::error::Error> ResultReportExt<T> for Result<T, E> {
    fn report_err(
        self,
        context: HashMap<String, Value>,
        user: Option<HashMap<String, Value>>,
    ) -> Self {
        if let Err(ref err) = self {
            capture_error(err, context, user);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering as AtomicOrdering};
    use std::sync::Mutex;
    use std::time::Duration;

    // A minimal single-request-per-connection HTTP server, the same pattern client.rs's own tests
    // use, kept local to this module rather than shared: these tests specifically drive the
    // *public* init/capture_error/panic-hook API end to end, not the lower-level types directly.
    fn spawn_tracker_server() -> (std::net::SocketAddr, Arc<AtomicI32>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(AtomicI32::new(0));
        let received_clone = Arc::clone(&received);

        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                crate::test_support::read_full_request(&mut stream);
                received_clone.fetch_add(1, AtomicOrdering::SeqCst);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            }
        });

        (addr, received)
    }

    // Same shape as spawn_tracker_server, but also reads and records each request's full body
    // (headers *and* the Content-Length-declared body after them, not just the header block): the
    // set_user/explicit-user-override scenarios below need to inspect the delivered JSON itself,
    // not merely count deliveries.
    fn spawn_tracker_server_capturing_body(
    ) -> (std::net::SocketAddr, Arc<AtomicI32>, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(AtomicI32::new(0));
        let received_clone = Arc::clone(&received);
        let last_body = Arc::new(Mutex::new(String::new()));
        let last_body_clone = Arc::clone(&last_body);

        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut buf = [0u8; 8192];
                let mut total = Vec::new();
                let mut header_end = None;
                loop {
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    total.extend_from_slice(&buf[..n]);
                    if let Some(pos) = total.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let header_text = String::from_utf8_lossy(&total[..pos]).into_owned();
                        let content_length: usize = header_text
                            .lines()
                            .find(|l| l.to_lowercase().starts_with("content-length:"))
                            .and_then(|l| l.split(':').nth(1))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        while total.len() < pos + 4 + content_length {
                            let n = stream.read(&mut buf).unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            total.extend_from_slice(&buf[..n]);
                        }
                        break;
                    }
                }
                if let Some(header_end) = header_end {
                    let body = String::from_utf8_lossy(&total[header_end..]).into_owned();
                    *last_body_clone.lock().unwrap() = body;
                }
                received_clone.fetch_add(1, AtomicOrdering::SeqCst);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            }
        });

        (addr, received, last_body)
    }

    fn wait_for(received: &AtomicI32, count: i32) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while received.load(AtomicOrdering::SeqCst) < count && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(received.load(AtomicOrdering::SeqCst), count);
    }

    // The public API sits behind one process-wide OnceLock (see `state()` above), so every test
    // touching it has to run against that same singleton: unlike this crate's other modules,
    // which build fresh, independent instances per test. Rather than fight Rust's default
    // parallel test execution (or add a dev-dependency purely to serialize a handful of tests),
    // every scenario that touches the public API lives in this one #[test] function and runs
    // sequentially. Configuration itself is re-read from its RwLock on every delivery attempt
    // (see Client::deliver), so repeatedly calling `init()` to point at a fresh DSN between
    // scenarios below works correctly even though the underlying Reporter/DeliveryQueue/Client
    // are only ever constructed once.
    #[test]
    fn public_api_end_to_end() {
        // init + capture_error delivers through the full stack
        let (addr, received) = spawn_tracker_server();
        init(|c| {
            c.dsn = Some(format!("http://key@{addr}/events"));
            c.environment = "production".to_string();
            c.timeout = Duration::from_secs(2);
            c.install_panic_hook = false; // installed explicitly, in the last scenario below instead
            c.detect_changes = false; // the snapshot has its own scenario below
        });

        let err = std::io::Error::other("boom");
        capture_error(&err, context! {"order_id" => 7}, None);
        wait_for(&received, 1);

        // capture_error_with_class works for a trait-object error
        let (addr, received) = spawn_tracker_server();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        let boxed: Box<dyn std::error::Error> = Box::new(std::io::Error::other("boxed boom"));
        capture_error_with_class("std::io::Error", boxed.as_ref(), HashMap::new(), None);
        wait_for(&received, 1);

        // ResultReportExt reports on Err and passes the Result through unchanged
        let (addr, received) = spawn_tracker_server();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        let result: Result<(), std::io::Error> = Err(std::io::Error::other("reported via ext"));
        let passed_through = result.report_err(HashMap::new(), None);
        assert!(passed_through.is_err());
        wait_for(&received, 1);

        let ok: Result<i32, std::io::Error> = Ok(42);
        assert_eq!(ok.report_err(HashMap::new(), None).unwrap(), 42);

        // set_user attaches the user to a later capture_error call with no explicit user, on this
        // thread
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        set_user(context! {"id" => 42, "email" => "alice@example.com"});
        capture_error(&std::io::Error::other("boom"), HashMap::new(), None);
        wait_for(&received, 1);
        assert!(last_body.lock().unwrap().contains("alice@example.com"));

        // an explicit user argument overrides whatever set_user last set
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        set_user(context! {"id" => 42});
        capture_error(
            &std::io::Error::other("boom"),
            HashMap::new(),
            Some(context! {"id" => 99}),
        );
        wait_for(&received, 1);
        assert!(last_body.lock().unwrap().contains("\"id\":99"));
        set_user(HashMap::new()); // clear, so it doesn't leak into whatever test runs on this thread next

        // add_breadcrumb accumulates on this thread and capture_error attaches the trail
        // automatically; clear_breadcrumbs empties it again
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        add_breadcrumb("opened checkout", "custom", "info", HashMap::new());
        add_breadcrumb(
            "charged card",
            "custom",
            "info",
            context! {"order_id" => 42},
        );
        capture_error(&std::io::Error::other("boom"), HashMap::new(), None);
        wait_for(&received, 1);
        {
            let body = last_body.lock().unwrap();
            assert!(body.contains("opened checkout"));
            assert!(body.contains("charged card"));
        }
        clear_breadcrumbs();

        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        capture_error(&std::io::Error::other("boom"), HashMap::new(), None);
        wait_for(&received, 1);
        assert!(!last_body.lock().unwrap().contains("\"breadcrumbs\""));

        // record_performance tallies in-process and flush_performance delivers one aggregate batch
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        record_performance("GET /users/:id", 10.0);
        record_performance("GET /users/:id", 30.0);
        flush_performance();
        wait_for(&received, 1);
        {
            let body = last_body.lock().unwrap();
            assert!(body.starts_with("{\"samples\":["), "body = {body}");
            assert!(body.contains("\"transaction_name\":\"GET /users/:id\""));
            assert!(body.contains("\"request_count\":2"));
        }

        // time_transaction returns the closure's own value and records how long it took, even if
        // the closure panics
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        let value = time_transaction("timed", || 42);
        assert_eq!(value, 42);
        let panicked = std::panic::catch_unwind(|| {
            time_transaction("timed panics", || -> u32 {
                panic!("inside a timed transaction")
            })
        });
        assert!(panicked.is_err());
        flush_performance();
        wait_for(&received, 1);
        {
            let body = last_body.lock().unwrap();
            assert!(
                body.contains("\"transaction_name\":\"timed\""),
                "body = {body}"
            );
            assert!(
                body.contains("\"transaction_name\":\"timed panics\""),
                "body = {body}"
            );
        }

        // track_performance = false records and delivers nothing
        let (addr, received, _last_body) = spawn_tracker_server_capturing_body();
        init(|c| {
            c.dsn = Some(format!("http://key@{addr}/events"));
            c.track_performance = false;
        });
        record_performance("never recorded", 10.0);
        flush_performance();
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(received.load(AtomicOrdering::SeqCst), 0);
        init(|c| c.track_performance = true);

        // an error captured inside a continued trace carries the caller's trace id, even with
        // track_tracing off; outside a trace it carries none
        let incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| {
            c.dsn = Some(format!("http://key@{addr}/events"));
            c.track_tracing = false;
        });
        continue_trace("POST /orders", Some(incoming), || {
            assert_eq!(
                current_trace_id().as_deref(),
                Some("4bf92f3577b34da6a3ce929d0e0e4736")
            );
            capture_error(&std::io::Error::other("boom"), HashMap::new(), None);
        });
        wait_for(&received, 1);
        assert!(last_body
            .lock()
            .unwrap()
            .contains("\"trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\""));
        assert_eq!(current_trace_id(), None);

        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| {
            c.dsn = Some(format!("http://key@{addr}/events"));
            c.track_tracing = true;
        });
        capture_error(&std::io::Error::other("boom"), HashMap::new(), None);
        wait_for(&received, 1);
        assert!(!last_body.lock().unwrap().contains("\"trace_id\""));

        // a fresh trace gets a W3C trace id of its own, which errors inside it carry
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        let fresh = trace("job:reindex", || {
            capture_error(&std::io::Error::other("boom"), HashMap::new(), None);
            current_trace_id().unwrap()
        });
        wait_for(&received, 1);
        assert_eq!(fresh.len(), 32);
        assert!(last_body
            .lock()
            .unwrap()
            .contains(&format!("\"trace_id\":\"{fresh}\"")));
        // a malformed traceparent starts a fresh trace too
        let fallback = continue_trace("GET /x", Some("00-nope"), || current_trace_id().unwrap());
        assert_eq!(fallback.len(), 32);

        // http_span hands out a traceparent naming its own span, records that span, and the root
        // of a continued trace is sent under the caller's span
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| {
            c.dsn = Some(format!("http://key@{addr}/events"));
            c.trace_capture_threshold = Duration::ZERO;
        });
        let header = continue_trace("POST /orders", Some(incoming), || {
            http_span(
                "post",
                "https://Payments.example.com/charges/42?token=secret",
                HashMap::new(),
                |traceparent| traceparent.map(str::to_string),
            )
        })
        .unwrap();
        wait_for(&received, 1);
        let parsed = trace_parent::parse(&header).unwrap();
        assert_eq!(parsed.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(header.starts_with("00-") && header.ends_with("-01"));
        {
            let body = last_body.lock().unwrap();
            assert!(body.starts_with("{\"trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\""));
            assert!(body.contains(&format!(
                "{{\"span_id\":\"{}\",\"parent_span_id\":",
                parsed.parent_span_id
            )));
            assert!(body.contains("\"name\":\"POST payments.example.com\",\"kind\":\"http\""));
            assert!(body.contains("\"parent_span_id\":\"00f067aa0ba902b7\""));
            assert!(!body.contains("secret") && !body.contains("/charges"));
        }

        // no header for a host outside trace_propagation_targets, or with propagate_traces off,
        // though the span is still recorded; and outside a trace, no header and no span
        init(|c| {
            c.trace_propagation_targets = Some(vec!["example.com".into()]);
        });
        trace("GET /x", || {
            http_span("GET", "https://badexample.com/", HashMap::new(), |tp| {
                assert_eq!(tp, None)
            });
            http_span("GET", "https://api.example.com/", HashMap::new(), |tp| {
                assert!(tp.is_some())
            });
        });
        init(|c| {
            c.trace_propagation_targets = None;
            c.propagate_traces = false;
        });
        trace("GET /x", || {
            http_span("GET", "https://api.example.com/", HashMap::new(), |tp| {
                assert_eq!(tp, None)
            });
        });
        wait_for(&received, 3);
        assert!(last_body.lock().unwrap().contains("\"kind\":\"http\""));
        init(|c| {
            c.propagate_traces = true;
            c.trace_capture_threshold = Duration::from_secs(1);
        });
        let outside = http_span("GET", "https://api.example.com/", HashMap::new(), |tp| {
            assert_eq!(tp, None);
            7
        });
        assert_eq!(outside, 7);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(received.load(AtomicOrdering::SeqCst), 3);

        // record_change goes out on the delivery thread to the changes endpoint
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        init(|c| c.dsn = Some(format!("http://key@{addr}/api/v1/events")));
        record_change(Change {
            id: Some("deploy-7".to_string()),
            ..Change::new("infrastructure", "Moved to the new database host")
        });
        wait_for(&received, 1);
        assert!(last_body.lock().unwrap().starts_with(
            "{\"kind\":\"infrastructure\",\"title\":\"Moved to the new database host\""
        ));

        // with detect_changes back on, the next init sends the snapshot, env var names included
        // only when opted in; any later init sends nothing more
        let (addr, received, last_body) = spawn_tracker_server_capturing_body();
        std::env::set_var("FORGE_OPS_TEST_APP_SETTING", "never sent");
        init(|c| {
            c.dsn = Some(format!("http://key@{addr}/api/v1/events"));
            c.detect_changes = true;
            c.track_env_var_names = true;
        });
        wait_for(&received, 1);
        {
            let body = last_body.lock().unwrap();
            assert!(body.contains("\"runtime\":\"rust"), "body = {body}");
            assert!(body.contains("\"env_var_names\":["), "body = {body}");
            assert!(!body.contains("FORGE_OPS_") && !body.contains("never sent"));
        }
        init(|c| c.track_env_var_names = false);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(received.load(AtomicOrdering::SeqCst), 1);

        // flush delivers what's queued before returning: errors and buffered metrics alike
        let (addr, received) = spawn_tracker_server();
        init(|c| c.dsn = Some(format!("http://key@{addr}/api/v1/events")));
        capture_error(&std::io::Error::other("first"), HashMap::new(), None);
        capture_error(&std::io::Error::other("second"), HashMap::new(), None);
        capture_metric("signup", 1.0);
        assert!(flush(Duration::from_secs(2)));
        assert_eq!(received.load(AtomicOrdering::SeqCst), 3);

        // and gives up at its timeout when a delivery is stuck
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stuck_addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::mem::forget(stream); // hold the connection open without ever responding
            }
        });
        init(|c| {
            c.dsn = Some(format!("http://key@{stuck_addr}/events"));
            c.timeout = Duration::from_millis(500);
        });
        capture_error(&std::io::Error::other("stuck"), HashMap::new(), None);
        let started = std::time::Instant::now();
        assert!(!flush(Duration::from_millis(100)));
        assert!(started.elapsed() < Duration::from_secs(1));
        // Let the stuck delivery time out, so it's off the queue before the scenarios below.
        assert!(flush(Duration::from_secs(2)));
        init(|c| c.timeout = Duration::from_secs(2));

        // a FlushGuard flushes when it goes out of scope
        let (addr, received) = spawn_tracker_server();
        init(|c| c.dsn = Some(format!("http://key@{addr}/events")));
        {
            let _flush = flush_guard(Duration::from_secs(2));
            capture_error(&std::io::Error::other("guarded"), HashMap::new(), None);
        }
        assert_eq!(received.load(AtomicOrdering::SeqCst), 1);

        // init's automatic panic hook reports a panic, then still lets it unwind unchanged
        let (addr, received) = spawn_tracker_server();
        let previous_hook_ran = Arc::new(AtomicBool::new(false));
        let previous_hook_ran_clone = Arc::clone(&previous_hook_ran);
        // Installed *before* init() specifically to prove install_panic_hook chains onto whatever
        // hook already exists (via take_hook()) rather than replacing it outright.
        std::panic::set_hook(Box::new(move |_| {
            previous_hook_ran_clone.store(true, AtomicOrdering::SeqCst);
        }));
        init(|c| {
            c.dsn = Some(format!("http://key@{addr}/events"));
            c.install_panic_hook = true;
        });

        let result = std::panic::catch_unwind(|| {
            panic!("test panic");
        });
        assert!(result.is_err());
        assert!(
            previous_hook_ran.load(AtomicOrdering::SeqCst),
            "the previously-installed hook should still have run"
        );
        // No waiting here: the hook itself flushes before the panic carries on.
        assert_eq!(received.load(AtomicOrdering::SeqCst), 1);

        // Restore a silent hook so later tests in this binary don't print this test's own
        // intentional panic to stderr.
        std::panic::set_hook(Box::new(|_| {}));
    }

    #[test]
    fn span_just_runs_the_closure_outside_a_trace() {
        assert_eq!(span("free", "service", HashMap::new(), || 7), 7);
        // record_span outside a trace is a no-op, not a panic.
        record_span(
            "free",
            "database",
            std::time::SystemTime::now(),
            1.0,
            HashMap::new(),
        );
    }

    #[test]
    fn a_panic_inside_trace_or_span_propagates_and_leaves_no_trace_behind() {
        // Only the thread-local matters here, so this holds whether or not another test has
        // already enabled reporting on the shared global configuration.
        let result = std::panic::catch_unwind(|| {
            trace("GET /boom", || {
                span("bad", "service", HashMap::new(), || panic!("boom"));
            })
        });
        assert!(result.is_err());
        assert!(!span_buffer::is_active());
    }

    #[test]
    fn trace_returns_the_closures_value_and_a_nested_trace_is_a_span() {
        let value = trace("outer", || trace("inner", || 5));
        assert_eq!(value, 5);
        assert!(!span_buffer::is_active());
    }

    fn development_config() -> Configuration {
        Configuration {
            dsn: Some("https://abc123@forgeops.example/api/v1/events".to_string()),
            environment: "development".to_string(),
            ..Configuration::new()
        }
    }

    #[test]
    fn warn_if_not_sending_writes_the_warning_once() {
        let warned = AtomicBool::new(false);
        let mut out = Vec::new();
        warn_if_not_sending(&development_config(), &warned, &mut out);
        warn_if_not_sending(&development_config(), &warned, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "[ForgeOps] Not sending: this environment is \"development\", and only production, \
             staging are enabled. Set FORGE_OPS_ENVIRONMENT=production (or add \"development\" \
             to the enabled environments) to send from here.\n"
        );
    }

    #[test]
    fn warn_if_not_sending_is_silent_without_a_dsn() {
        let warned = AtomicBool::new(false);
        let mut out = Vec::new();
        let config = Configuration {
            dsn: None,
            ..development_config()
        };
        warn_if_not_sending(&config, &warned, &mut out);
        assert!(out.is_empty());
        assert!(!warned.load(AtomicOrdering::SeqCst));
    }

    #[test]
    fn context_macro_builds_expected_map() {
        let ctx = context! {"order_id" => 42, "customer" => "acme-inc"};
        assert_eq!(ctx.get("order_id"), Some(&Value::Number(42.0)));
        assert_eq!(
            ctx.get("customer"),
            Some(&Value::String("acme-inc".to_string()))
        );
    }
}
