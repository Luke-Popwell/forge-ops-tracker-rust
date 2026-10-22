# forge-ops-tracker

Rust error reporting client for [ForgeOps](https://getforgeops.net).
Requires Rust 1.81+. It captures panics on any thread and explicitly reported errors, builds a
backtrace, scrubs likely PII, and delivers events to ForgeOps over HTTP without blocking whatever
raised them.

> For health or personal data, turn on [strict privacy](#strict-privacy): the SDK then sends only structured facts about each error (its type, stack trace, release and route), never the message, a raw path, breadcrumbs, or context you haven't allowed.

## Installation

```toml
[dependencies]
forge-ops-tracker = "0.17.1"
```

### Dependencies

Rust's standard library has no HTTP client, no structured per-frame backtrace access on stable, and
no regular expression engine. This crate depends on exactly the three widely-used crates that fill
those three specific gaps, each doing something `std` genuinely can't:

- **[`ureq`](https://crates.io/crates/ureq)**: delivers events over HTTPS. `std` has no HTTP
  client at all.
- **[`backtrace`](https://crates.io/crates/backtrace)**: structured per-frame file/line/function
  data. `std::backtrace::Backtrace` captures a trace on stable Rust, but only exposes it as a
  formatted string (no public per-frame accessors) so it can't produce the structured
  file/line/method/in_app shape this client needs to build an event payload.
- **[`regex`](https://crates.io/crates/regex)**: the PII scrubber's pattern matching. `std` has
  no regular expression engine.

Everything else (the event payload's own JSON encoding, a DSN parser, timestamp formatting, the
SHA-256 behind strict privacy's message fingerprint) is
hand-rolled rather than reaching for `serde_json`/`url`/`chrono`: this crate only depends on
something outside `std` when the language truly can't do it itself.

## Configuration

Set a DSN (from a project's settings page in ForgeOps), either via the `FORGE_OPS_DSN` environment
variable or explicitly:

```rust
forge_ops_tracker::init(|c| {
    c.dsn = Some("https://<api_key>@getforgeops.net/api/v1/events".to_string()); // or leave unset to read FORGE_OPS_DSN
    c.release = Some("...".to_string());
    c.environment = "production".to_string();
});
```

Call `init` once at startup, before your server starts accepting requests. Pass a closure to set
any `Configuration` field, so every option is available through the one call without a long list
of positional arguments or a separate setter for each field.

### Environments

The environment comes from `c.environment`, or the `FORGE_OPS_ENVIRONMENT` environment variable,
and is `"production"` when neither is set, so a DSN alone is enough to start sending. Errors are
only sent from the enabled environments (`c.enabled_environments`, default `production` and
`staging`). On a machine that shouldn't send, such as a laptop, set
`FORGE_OPS_ENVIRONMENT=development`. When a DSN is configured but the environment isn't enabled,
`init` says so once on stderr:

```
[ForgeOps] Not sending: this environment is "development", and only production, staging are enabled. Set FORGE_OPS_ENVIRONMENT=production (or add "development" to the enabled environments) to send from here.
```

## What gets reported automatically, and what doesn't

**A panic on any thread needs no further wiring at all**, once `init()` has run. Rust's panic hook
(`std::panic::set_hook`) is process-wide: it fires for a panic on *any* thread, including a web
framework's own worker threads (Actix, Axum/Tokio, a plain `std::thread`), with **no per-framework
middleware needed at all**.

`init()` installs this hook automatically unless `Configuration.install_panic_hook` is set to
`false`. It never swallows the panic: after reporting, it calls whatever hook was previously
installed (Rust's own default, which prints to stderr, unless something else already replaced it),
so reporting a panic never changes what your program actually does afterward. Before handing the
panic on, it waits (up to 2 seconds) for the report to be delivered, so a panic that ends the
process (on the main thread, or anywhere with `panic = "abort"`) still reaches ForgeOps. Call
`install_panic_hook()` directly only if you're managing configuration some other way than
`init()`.

**Rust doesn't have exceptions**, so an error your own code already caught (a `Result::Err`) is a
second, separate case: report it explicitly, right at the point you'd otherwise just log it:

```rust
if let Err(err) = charge_card(&order) {
    forge_ops_tracker::capture_error(&err, forge_ops_tracker::context!{"order_id" => order.id}, None);
    return Err(err);
}
```

Or, more concisely, via the `ResultReportExt` extension trait, which reports on `Err` and passes
the `Result` through unchanged:

```rust
use forge_ops_tracker::ResultReportExt;

charge_card(&order).report_err(forge_ops_tracker::context!{"order_id" => order.id}, None)?;
```

A plain Rust `std::error::Error` carries no stack trace of its own, so `capture_error` captures the
backtrace at its own call site. Call it as close to the point you learned about the error as you
reasonably can, for the most useful trace.

`exception_class` is inferred via [`std::any::type_name`], which needs a concrete, statically-known
error type: for a `Box<dyn Error>` or other trait object, where that isn't possible, use
`capture_error_with_class(class, err, context, user)` instead and supply the class yourself.

[`std::any::type_name`]: https://doc.rust-lang.org/std/any/fn.type_name.html

Delivery happens on a background thread with a bounded channel and a short per-request HTTP
timeout (`Configuration.timeout`, 2s default). Every failure mode: network errors, timeouts, a
full queue, a malformed DSN: is caught and dropped rather than propagated, so a broken or
unreachable tracker can never take down the host app. The worker thread starts eagerly, at `init()`
time, rather than waiting for the first push: Rust programs essentially never fork themselves at
the application level after startup, so there's no risk of an eagerly-started thread being left
dead in a forked child, and starting it up front means it's ready before the first event needs to
be delivered.

### Scripts, CLIs and cron jobs: flush before `main` returns

Delivery happens on background threads and Rust has no exit hook (the client's state lives in a
static, which is never dropped), so anything still queued when `main` returns is lost with the
process. A short-lived program should flush before it ends. Hold a guard for the whole of `main`,
so an early return or `?` flushes too:

```rust
use std::time::Duration;
use forge_ops_tracker::ResultReportExt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    forge_ops_tracker::init(|c| { /* ... */ });
    let _flush = forge_ops_tracker::flush_guard(Duration::from_secs(2));

    run().report_err(Default::default(), None)?;
    Ok(())
}
```

or call `forge_ops_tracker::flush(Duration::from_secs(2))` yourself as the last thing `main` does.
`flush(timeout)` sends everything the client is still holding (queued errors and changes, captured
traces, buffered metrics and the current performance window), waits at most `timeout`, and returns
whether it all finished in time. Bind the guard to a name (`_flush`), not `_`, which drops it at
once. `std::process::exit` skips destructors, so call `flush` yourself before one. A long-running
server doesn't need either, other than on a graceful shutdown.

## Identifying users

```rust
forge_ops_tracker::capture_error(&err, forge_ops_tracker::context!{}, Some(forge_ops_tracker::context!{"id" => user.id, "email" => user.email}));
```

Or `set_user` to attach it to every subsequently reported error on this thread (an explicit
`capture_error`/`capture_error_with_class` call, or a panic the installed hook catches) until
changed or cleared, rather than passing it to every call by hand, e.g. right after authenticating
a request:

```rust
forge_ops_tracker::set_user(forge_ops_tracker::context!{"id" => user.id, "email" => user.email});
// once the request is done, or on sign-out:
forge_ops_tracker::set_user(std::collections::HashMap::new());
```

There's no way to automatically detect "the current user" the way a server-side web framework with
its own session/auth middleware can, so this is always manual. `set_user` is a **plain
thread-local**, not a process-wide global: the right choice for the thread-per-request model this
crate's own synchronous, non-async design naturally pairs with (see "Dependencies" below for why
`ureq`, not an async HTTP client, was chosen). **It does not propagate across an `.await` in an
async runtime**: unlike a native OS thread, a single thread in an async executor (Tokio,
async-std) interleaves multiple unrelated tasks, so a value set on one task can leak into, or never
reach, another. A host app built on an async runtime should pass `user` explicitly to
`capture_error`/`capture_error_with_class` on every call instead of relying on `set_user`, the same
reason `sdks/node` needs `AsyncLocalStorage` rather than a bare thread-local. `id`/`email`/
`username` keys are all independently optional. Shows up on an issue's own detail page, and as its
own affected-users count alongside the regular event count.

## Breadcrumbs

A bounded, ordered trail of what happened right before an error: on by default, capped at the 30
most recent entries per thread, both configurable:

```rust
forge_ops_tracker::init(|c| {
    c.track_breadcrumbs = false; // opt out entirely
    c.max_breadcrumbs = 50;      // default 30
});
```

```rust
forge_ops_tracker::add_breadcrumb("charged card", "custom", "info", forge_ops_tracker::context!{"order_id" => order.id});
```

`capture_error`/`capture_error_with_class`/the installed panic hook all attach the current
thread's trail automatically, the same way they already read `set_user`; there's no separate
argument to pass it through by hand.

**A plain thread-local**, the same choice `set_user` already made and for the identical reason
(see "Identifying users" above): the right fit for this crate's synchronous, thread-per-request
design, not an async runtime, where a single OS thread can interleave multiple unrelated tasks.

This crate has no web framework integration of its own, unlike `sdks/go`'s net/http/Gin
middleware or `gems/forge_ops_tracker`'s Rack middleware, so there's no automatic breadcrumb
source (no request/controller timing to record one from) and no middleware to start a fresh trail
per request on its own. Call `clear_breadcrumbs()` yourself at the start of each request, the same
place you'd already be calling `set_user` (or clearing it) from:

```rust
forge_ops_tracker::clear_breadcrumbs();
```

Without this, a synchronous, thread-pool-based server (actix-web's own worker threads, for
instance) would let one request's trail bleed into the next one handled on the same reused thread.

## Performance monitoring

Times whatever you wrap and reports one small aggregate per transaction (how many times it ran,
total and maximum duration) every `performance_flush_interval` (60s by default), for the Performance
page's per-transaction table. Not one network call per timed call.

Each aggregate also carries a small latency histogram (a count per fixed latency bucket: 50, 100,
250, 500, 1000, 2500, 5000 and 10000ms, plus an overflow bucket), so ForgeOps can show an
approximate p50/p95/p99 per transaction, not just an average. Percentiles are accurate to the width
of whichever bucket a duration falls into; the SDK never stores the individual durations.

```rust
// Wrap a whole request handler, or any block you want on the Performance page:
let response = forge_ops_tracker::time_transaction("GET /users/:id", || handle_request(req));

// Or record a duration you measured yourself:
forge_ops_tracker::record_performance("nightly-export", elapsed.as_secs_f64() * 1000.0);
```

This crate has no web framework integration (unlike `sdks/go`'s net/http and Gin middleware), so
**nothing is timed automatically**: you choose what to wrap. Keep transaction names low-cardinality
(`"GET /users/:id"`, not `"GET /users/42"`): every distinct name is its own row. `time_transaction`
records even if the closure panics. Turn it off with `track_performance = false`; it also does
nothing (and starts no thread) when reporting isn't enabled for the current environment.

The flush thread is a daemon: Rust has no equivalent of the Ruby gem's `at_exit`, so it does not run
on a normal process exit. A short-lived program, or one about to shut down, should call
`forge_ops_tracker::flush(timeout)` (which covers everything, see
[Scripts, CLIs and cron jobs](#scripts-clis-and-cron-jobs-flush-before-main-returns)) or
`forge_ops_tracker::flush_performance()` itself to send the last partial window.

A delivery that failed for now (a network error, a timeout, a 5xx, a 408 or a 429) keeps every tally,
so the next flush's window just grows; after 5 flushes in a row that failed, the window is dropped.
A flush the server rejects (any other 4xx) is dropped at once and never sent again. What a flush delivered
is *subtracted* from the tallies afterward, never the whole map cleared: a `record_performance` call
that lands while a delivery is in flight would otherwise be silently discarded (a real bug `sdks/go`
had and fixed; `gems/forge_ops_tracker`'s reference implementation still has it). A deterministic
test pins this.

## Distributed tracing

A slow call's own breakdown: which database calls, HTTP calls, or pieces of your code the time went
to, shown as a span tree on ForgeOps. Wrap the unit of work in `trace`, and anything inside it, on
the same thread, can add spans; the trace is sent only when the whole thing took at least
`trace_capture_threshold` (1 second by default), so fast calls cost nothing on the wire. A trace can
also be followed into the services you call and continued from the service that called you (see
"Following a request across services" below).

```rust
let response = forge_ops_tracker::trace("GET /checkout", || {
    let order = forge_ops_tracker::span("load order", "database", context! {"order_id" => 42}, || repo.find(42));
    forge_ops_tracker::span("charge card", "service", HashMap::new(), || gateway.charge(&order));
    render(&order)
});

// Something you timed yourself (kind is one of controller/service/database/redis/http/job/other;
// anything else is sent as "other"):
forge_ops_tracker::record_span("SELECT orders", "database", started_at, duration_ms, HashMap::new());
```

This crate has no web framework integration, so **nothing starts a trace or records a span
automatically**: you choose what to wrap. `span` nests under whichever span is open on the same
thread, records even when the closure panics, and just runs the closure outside a `trace`; a
`trace` inside another `trace` records a span instead. The open trace is a `thread_local!`, like the
breadcrumb trail, so it follows a thread, not an async task. A trace holds at most 500 spans and is
delivered on its own background thread and bounded queue, dropping rather than blocking when full.
Turn span reporting off with `track_tracing = false`.

**Database spans with their SQL.** No database driver is instrumented either, so wrap a query in
`database_span` and pass its SQL; ForgeOps then shows which statement a slow call spent its time in:

```rust
use postgres::{Client, NoTls};

fn open_order_ids(db: &mut Client, customer_id: i64) -> Result<Vec<i64>, postgres::Error> {
    const OPEN_ORDERS: &str = "SELECT id FROM orders WHERE customer_id = $1 AND status = 'open'";
    forge_ops_tracker::database_span("load open orders", OPEN_ORDERS, Some("postgresql"), || {
        let rows = db.query(OPEN_ORDERS, &[&customer_id])?;
        Ok(rows.iter().map(|row| row.get(0)).collect())
    })
}

fn main() -> Result<(), postgres::Error> {
    forge_ops_tracker::init(|_| {}); // DSN from FORGE_OPS_DSN
    let mut db = Client::connect("host=localhost dbname=shop", NoTls)?;
    let ids = forge_ops_tracker::trace("GET /orders", || open_order_ids(&mut db, 42))?;
    println!("{ids:?}");
    Ok(())
}
```

The statement is masked when the span is recorded: every string and number becomes `?`, so this
span carries `SELECT id FROM orders WHERE customer_id = $1 AND status = ?`, and ForgeOps masks it
again on arrival. Strings with backslash escapes (`'o\'brien'`) or a type prefix (`E''`, `X''`,
`N''`, `B''`, `U&''`) and hex, binary and exponent numbers (`0x1F`, `0b101`, `1.5E-3`) are masked
too, and with `db_system` `"mysql"` or `"mariadb"` so is "double quoted" text, a string there; on
any other database it's a name and is left alone. It's cut to 4000 characters, and bind values
(`&[&customer_id]`) are never taken.
It goes out in the span's data as `db.statement`, with the database name (`"postgresql"`,
`"mysql"`, `"sqlite"`, `"mssql"`, `"oracle"`, or any other; optional) lowercased as `db.system`.
For a query you timed yourself, use `forge_ops_tracker::record_database_span(name, sql, db_system,
started_at, duration_ms)`. `forge_ops_tracker::database_span_data(sql, db_system)` builds the data
map if you'd rather add your own keys and call `span`/`record_span` with kind `"database"`; a
`db.statement` on any database span is masked the same way, however the map was built.

### Following a request across services

Traces use the [W3C Trace Context](https://www.w3.org/TR/trace-context/) standard (a `traceparent`
header), so an error or a slow call can be followed from one service into the next.

**Outgoing**: wrap each HTTP call you make inside a trace in `http_span`. It records the call as an
`http` span named after the method and host (never the path or query) and hands your closure the
`traceparent` header value to send; its parent id is that span's own id, so the called service's
spans nest under it:

```rust
use std::collections::HashMap;

forge_ops_tracker::trace("POST /checkout", || {
    let url = "https://payments.example.com/charges";
    let response = forge_ops_tracker::http_span("POST", url, HashMap::new(), |traceparent| {
        let mut request = ureq::post(url);
        if let Some(value) = traceparent {
            request = request.set(forge_ops_tracker::TRACEPARENT_HEADER, value);
        }
        request.send_string(&body)
    });
    // ...
});
```

`http_span` works with any HTTP client (the value is a plain `Option<&str>`), records the span even
when the closure panics, and returns whatever the closure returned. Outside a `trace` it records
nothing and the closure gets `None`. This crate doesn't instrument any HTTP client itself, so a call
made without `http_span` carries no header.

**Incoming**: pass the request's own `traceparent` header to `continue_trace` and it continues the
caller's trace (same trace id, root span parented under the caller's span). `None` or a malformed
value just starts a new trace, exactly like `trace`:

```rust
// `headers` is however your server exposes the incoming request's headers.
let traceparent = headers.get("traceparent").map(String::as_str);
let response = forge_ops_tracker::continue_trace("POST /orders", traceparent, || handle(request));
```

Every error captured inside a trace (through `capture_error` and friends, or a panic the hook
catches on that thread) carries that trace's id (`forge_ops_tracker::current_trace_id()` returns it
too, for your own logs), so ForgeOps can show it next to errors from the other services that handled
the same request. Errors captured outside a trace are unchanged. The trace id and the header exist
even with `track_tracing = false`, since they are also what links errors across services; only span
reporting stops.

The service on the other end must also report to ForgeOps (the Ruby SDK continues the trace
automatically from 0.12.0), and both projects must be linked in ForgeOps to see them connected.

Narrow or turn off where the header goes, for example if a third-party API rejects unknown headers:

```rust
forge_ops_tracker::init(|c| {
    // None (the default) means every host. A host string matches that host and its subdomains
    // ("example.com" matches "api.example.com", never "badexample.com"); a regex::Regex is
    // searched for anywhere in the host.
    c.trace_propagation_targets = Some(vec![
        "example.com".into(),
        regex::Regex::new(r"^svc-\d+\.internal$").unwrap().into(),
    ]);
    // Or never send it at all (default true):
    c.propagate_traces = false;
});
```

## Custom metrics and infrastructure monitoring

Two explicit calls (nothing is automatic, so there is no `track_metrics` flag): a business event you
name yourself, and a reading from one of your own hosts.

```rust
forge_ops_tracker::capture_metric("signup", 1.0);   // a bare counter
forge_ops_tracker::capture_metric("payment", 49.0); // a real magnitude; it may be negative (a refund)

forge_ops_tracker::capture_infrastructure_metric("cpu", 0.42, None); // None defaults to server_name
forge_ops_tracker::capture_infrastructure_metric("disk", 0.81, Some("db-1"));
forge_ops_tracker::flush_metrics(); // send the metrics right now
```

Each capture is buffered and flushed as one batch every `metric_flush_interval` /
`infrastructure_metric_flush_interval` (60 seconds by default) on a daemon thread started on the first
capture. **Rust has no exit hook to flush from**, so a short-lived program (a cron job) must flush
before it returns from `main`: `flush(timeout)` or a `flush_guard` covers metrics along with errors
and everything else, and `flush_metrics()` still sends just the metrics. Every entry is stored as it was captured (a signup is
a row, not a running total), so a count or sum you compute later is exact. Both are a no-op when the
client isn't enabled for the environment.

A delivery that failed for now (a network error, a timeout, a 5xx, a 408 or a 429) keeps every entry
for the next flush, and an entry captured while a delivery is in flight is kept too (the Ruby gem's
own buffer loses it; a test pins this with a gated delivery). After 5 flushes in a row that failed,
the batch is dropped and the buffer starts clean. A batch the server rejects (any other 4xx, such as
the 403 a plan without the feature answers) is dropped at once and never sent again. The buffer holds
at most 1000 entries per kind and drops further ones until a flush makes room.
A NaN or infinite value is dropped at capture: it is not valid JSON and would make the server reject the
whole batch behind it. Requires a ForgeOps plan that includes custom metrics / infrastructure
monitoring.

## What changed

Record a change (a feature flag flip, a config edit, a migration) so ForgeOps can line it up with
the errors and slowdowns that came after it:

```rust
use forge_ops_tracker::{context, Change};

fn main() {
    forge_ops_tracker::init(|c| {
        c.dsn = Some("https://<api_key>@getforgeops.net/api/v1/events".to_string());
        c.environment = "production".to_string();
    });

    forge_ops_tracker::record_change(Change::new("migration", "Add index to orders.created_at"));

    forge_ops_tracker::record_change(Change {
        details: context! {"flag" => "new_checkout", "enabled" => true},
        actor: Some("alice@example.com".to_string()),
        url: Some("https://git.example.com/shop/pull/412".to_string()),
        id: Some("new-checkout-rollout".to_string()), // recording the same id twice stores one change
        ..Change::new("feature_flag", "Enabled new checkout for everyone")
    });
}
```

`kind` is one of `"feature_flag"`, `"config"`, `"migration"`, `"dependency"`, `"infrastructure"` or
`"other"`; anything else is sent as `"other"`. `title` is required and truncated to 200 characters.
`environment` defaults to `Configuration.environment` and `occurred_at` (a `SystemTime`) to now;
`details`, `service`, `actor`, `url` and `id` are optional. It goes out on the same background thread
as errors, so it never blocks, and like everything else here it's a no-op when reporting isn't enabled
and never panics or returns an error (a plan without change tracking just drops it).

`init()` also sends one snapshot of what this process sees, once per process, on that background
thread, so startup never waits on it. ForgeOps compares it with the previous one for the same
environment and records what changed. It contains the version of Rust the binary was built with.
It never lists crates: a compiled binary keeps no record of them to read back, so rather than guess,
that part is left out. Environment variable *names* (never values) are included only if you opt in,
minus names that differ from host to host (`HOSTNAME`, `PATH`, `LC_*`, `KUBERNETES_*`, this crate's
own `FORGE_OPS_*`, and similar):

```rust
forge_ops_tracker::init(|c| {
    c.track_env_var_names = true; // default false
    // c.detect_changes = false;  // default true; false never sends the snapshot
});
```

Requires a ForgeOps plan that includes change tracking.

## `in_app` backtrace frames

A Rust binary built with debug info embeds the real build-time source paths, so file-path matching
against `Configuration.app_root` is a straightforward prefix comparison against those embedded
paths. Defaults to the current working directory; set it explicitly if that doesn't match your
binary's actual build layout. Third-party crate source under Cargo's registry cache and the Rust
toolchain's own std/core source are never marked `in_app`, regardless of `app_root`.

## Source context

By default, each in-app backtrace frame (never a third-party crate) is captured along with the 5
lines of source on either side of the culprit line, read straight off disk at capture time, so an
issue's detail page can show the actual code that broke, not just a file:line:method reference.
This never applies to a frame outside your own app's code, and it fails silently (no context, not
a panic) for any file that can't be read for whatever reason, e.g. built in a container image the
running host doesn't have access to.

This is a real, deliberate exception to "off by default is safer": literal source code is being
transmitted, not just a reference to it, and the real protection here isn't this field. Every
project on ForgeOps has its own setting (on by default, off durably and immediately once an org
owner turns it off, regardless of what any individual app's own local `Configuration` is still set
to) that governs whether the server will ever actually store what a client sends. Set
`capture_source_context` to `false` if you'd rather this crate never even attempt the disk read in
the first place:

```rust
forge_ops_tracker::init(|c| {
    c.capture_source_context = false;
});
```

## PII scrubbing

By default, the message, backtrace, and any context you attach are scanned for likely personal
data (email addresses, formatted SSNs/credit cards, known API key/token formats, and anything
under a suspiciously-named key like `password`, `api_key`, or `ssn`) and redacted before
the payload ever leaves this process. ForgeOps itself scrubs again on arrival regardless, so this
is a second, earlier layer, not the only one. The user attached via `capture_error`'s third
argument or `set_user` above is a deliberate exception: it's never scrubbed, since redacting it
would defeat the whole point of identifying users in the first place.

To disable it:

```rust
forge_ops_tracker::init(|c| {
    c.scrub_pii = false;
});
```

## Strict privacy

For apps that can't let personal or health data (PII, PHI) leave their own servers. With strict
privacy on, an error is sent as structured facts only, never free text a person could have typed:

- no message: a `message_fingerprint` is sent instead, a one-way hash of the message (as PII
  scrubbing leaves it) with its numbers, hex ids and UUIDs taken out, computed in this process, so
  errors still group by message;
- no breadcrumbs (`add_breadcrumb` records nothing), no SQL statement (`sql_objects`, the table and
  procedure names, still go), and no source context;
- the user's `id` only, never an email or username;
- `context` and `tags` keep only the keys you list in `privacy_allowed_fields`, and only when the
  value is a string, number or boolean.

Spans are reduced too: an outbound HTTP span is named by method and host alone
(`GET api.example.com`), and span data keeps only `db.statement` (already masked) and `db.system`. A
raw path (one with no route parameter like `:id` or `{id}` in it) keeps only its first segment, then
`/:path` if there was more, since anything after it can name a person: `/patients/jane-doe/12` is
sent as `/patients/:path`, `/42/edit` as `/:id/:path`. A route template (`/patients/:id/notes`) is
sent as it is, so reporting routes rather than raw paths loses nothing. That applies to span names
and to performance samples' transaction names; name your traces and transactions by route
(`"GET /users/:id"`) to keep the whole route. The exception class, stack frames, release,
environment, server and trace id are unchanged, as are metrics and change snapshots.

```rust
forge_ops_tracker::init(|c| {
    c.strict_privacy = true;
    c.privacy_allowed_fields = vec!["error_code".to_string(), "feature".to_string()];
});
```

Both are off and empty by default, and can be set from the environment instead:
`FORGE_OPS_STRICT_PRIVACY=true` and `FORGE_OPS_PRIVACY_ALLOWED_FIELDS=error_code,feature` (comma
separated). A value set in `init` wins over the environment.

ForgeOps applies the same rules again on arrival when the project's own Strict privacy setting is
on, so an app with an older or misconfigured client still can't get text stored for that project.

## Database errors

A Rust error carries no SQL of its own, and no Rust database crate puts the statement on its error types, so the code that ran the query hands it over with `capture_error_with_sql`. The event includes the names of the stored procedure, table and view that SQL touched, so the issue tells you where to start looking. Names are identifiers, never values; the raw statement never leaves the process.

To also send the SQL statement itself, opt in. Every string and number is replaced by `?` before it
leaves your process (`WHERE email = 'a@b.co' AND id = 42` is sent as `WHERE email = ? AND id = ?`),
and ForgeOps masks it again on arrival:

```rust
if let Err(err) = sqlx::query(QUERY).bind(id).execute(&pool).await {
    forge_ops_tracker::capture_error_with_sql(&err, QUERY, HashMap::new(), None);
}

// Opt in to also sending the masked statement (default false).
forge_ops_tracker::init(|c| {
    c.capture_sql_statement = true;
    // c.capture_sql_objects = false; // default true; false stops even the names
});
```

Each ForgeOps project also has its own "Capture the SQL behind database errors" setting. Turn it off
there and the statement is never stored for that project, whatever this flag says; the names are
still kept. A view and a table are written the same way in SQL, so both show as tables/views; the
database's own error message usually settles which it was.

## Running the tests

```bash
cd sdks/rust
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
