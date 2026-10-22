# Changelog

## 0.17.1 (2026-10-22)

- The README says what strict privacy does in its opening lines.
- The source is public at https://github.com/Luke-Popwell/forge-ops-tracker-rust, and the package links to it.

## 0.17.0 (2026-10-20)

- **Strict privacy: raw paths keep only their first segment.** With `strict_privacy` on, a span name or performance sample's transaction name that is a raw path (one with no route parameter such as `:id` or `{id}`) used to keep every segment without a digit, so `/patients/jane-doe` went out as written. It is now cut to its first segment, then `/:path` if there was more: `GET /patients/jane-doe/12` is sent as `GET /patients/:path`. A route template (`GET /patients/:id/notes`) is sent as it is, so naming traces and transactions by route loses nothing. With strict privacy off, nothing changes.
- No API changes.

## 0.16.0 (2026-10-20)

- **Strict privacy.** New `Configuration.strict_privacy` (off by default) sends only structured facts about an error, for apps that can't let personal or health data leave their own servers: no message (a `message_fingerprint` computed in this process instead, so errors still group), no breadcrumbs (`add_breadcrumb` records nothing), no SQL statement, no source context, the user's `id` only, and only the `context` and `tags` keys listed in the new `Configuration.privacy_allowed_fields`, when their value is a string, number or boolean. Spans are named by method and host for outbound calls, with ids stripped from paths, and keep only `db.statement` and `db.system` as data. Both can be set with `FORGE_OPS_STRICT_PRIVACY=true` and `FORGE_OPS_PRIVACY_ALLOWED_FIELDS=error_code,feature`; a value set in `init` wins. With it off, nothing changes on the wire. See the README's "Strict privacy" section. A transaction name that's a raw path rather than a route has its ids stripped the same way in performance samples. Span names, outbound hosts included, are read by hand rather than with a URL parser, so an address a parser would reject still loses its path.
- `Event` has a new public field, `message_fingerprint: Option<String>` (`None` unless strict privacy is on), so code that builds an `Event` by hand needs to set it. No new dependencies: the SHA-256 is part of the crate.

## 0.15.0 (2026-10-13)

- **A batch the server rejects is no longer re-sent forever.** Performance samples, custom metrics and infrastructure readings are sent in batches, and a batch whose delivery failed used to be kept and sent again at every flush, with whatever had been recorded since added to it, whatever the reason for the failure. A response that means the server will never take the batch (a 4xx other than 408 and 429: a revoked key, a plan without the feature, a payload it can't accept) now drops the batch at once. Before, an app on a plan without custom metrics re-sent the same metrics at every flush for as long as it ran, and once 1000 of them were buffered every new metric was dropped as well.
- A batch whose delivery failed for now (a network error, a timeout, a 5xx, a 408 or a 429) is still kept for the next flush, but only for so long: after 5 flushes in a row that failed, it is dropped and the next batch starts clean. The 1000 entry cap on each metric buffer is unchanged.
- Errors, changes and traces are unchanged: each is sent once and never retried.
- No API changes.

## 0.14.0 (2026-10-02)

- **The default environment changed from `development` to `production`.** With `FORGE_OPS_ENVIRONMENT` unset and `c.environment` not assigned, the client used to report itself as `development`, which isn't one of the default enabled environments (`production`, `staging`), so an app set up with only a DSN silently sent nothing. It now defaults to `production`, so a DSN alone is enough. A set but blank `FORGE_OPS_ENVIRONMENT` also means `production` now. To keep the old behavior, set `FORGE_OPS_ENVIRONMENT=development` (or `c.environment = "development".to_string()`) wherever you don't want errors sent, such as developer machines and CI.
- When a DSN is configured but the environment isn't enabled, `init` now says so once per process on stderr: `[ForgeOps] Not sending: this environment is "development", and only production, staging are enabled. Set FORGE_OPS_ENVIRONMENT=production (or add "development" to the enabled environments) to send from here.` Nothing is printed when no DSN is configured. New `Configuration::not_sending_warning()` returns that message, or `None`.
- The README's install snippet now names the current version.

## 0.13.0 (2026-10-01)

- An error reported just before a program exits is no longer lost. Delivery happens on background threads and the client's state lives in a static that is never dropped, so returning from `main` right after `capture_error` used to drop the event. New `forge_ops_tracker::flush(timeout: Duration) -> bool` sends everything the client is still holding (queued errors and changes, captured traces, buffered metrics and infrastructure readings, and the current performance window), waits at most `timeout`, and returns whether it all finished in time. New `forge_ops_tracker::flush_guard(timeout)` returns a `FlushGuard` that calls `flush` when dropped, so holding it for the whole of `main` (`let _flush = forge_ops_tracker::flush_guard(Duration::from_secs(2));`) also covers an early return or `?`. `init()` itself is unchanged. `flush_metrics` and `flush_performance` are unchanged.
- The panic hook now waits (up to 2 seconds) for the panic it reports to be delivered before handing it on, so a panic that ends the process (on the main thread, or anywhere under `panic = "abort"`) still reaches ForgeOps. A panic on another thread waits the same way before it unwinds that thread.

## 0.12.1 (2026-09-29)

- SQL masking now catches values it used to let through, matching ForgeOps's own masker again: a string with a backslash-escaped quote (`'o\'brien'`, `E'o\'brien'`) is masked whole instead of leaving the rest of it visible, a string's type prefix goes with it (`E''`, `X''`, `N''`, `B''` and `U&''` each become one `?`), and hex (`0x1F`), binary (`0b101`), exponent (`3e10`, `1.5E-3`) and leading-dot (`.5`) numbers are masked. On a database span whose `db.system` is `mysql` or `mariadb`, "double quoted" text is a string and is masked too; on any other database it's a name and is still left alone.

## 0.12.0 (2026-09-25)

- A database span can now carry the SQL it ran. New `forge_ops_tracker::database_span(name, sql, db_system, f)` and `forge_ops_tracker::record_database_span(name, sql, db_system, started_at, duration_ms)` record a `"database"` span whose data holds the statement as `db.statement` and the database name, lowercased, as `db.system` (`database_span_data(sql, db_system)` builds that map for `span`/`record_span`). The statement is masked (every string and number becomes `?`) and cut to 4000 characters when the span is recorded, and a `db.statement` on any database span is masked the same way, so the SQL as written never leaves the process. Bind values are never taken.

## 0.11.0 (2026-09-25)

- What changed. `forge_ops_tracker::record_change(Change)` records a feature flag flip, config edit, migration, dependency or infrastructure change (or `"other"`, which an unknown kind is sent as) so ForgeOps can show it next to the errors that followed. Build a `Change` with `Change::new(kind, title)` plus struct update syntax for the optional `details`, `environment` (defaults to `Configuration.environment`), `service`, `actor`, `url`, `id` (an idempotency key) and `occurred_at` (defaults to now). Delivered on the existing background delivery thread; a no-op when reporting isn't enabled, and never panics or blocks, whatever the response.
- `init()` now sends one change snapshot per process, on the background delivery thread, so ForgeOps can record what changed since the last one for the same environment: the Rust version the binary was built with (read by a new `build.rs` from the compiler Cargo uses, with no build dependency; just `"rust"` if it can't be read), and, only with the new `track_env_var_names` (default false), the names (never the values) of this process's environment variables, minus host-specific ones such as `HOSTNAME`, `PATH`, `LC_*`, `KUBERNETES_*` and `FORGE_OPS_*`. Crate versions are not sent, since a compiled binary keeps no reliable record of them. New `detect_changes` (default true) turns the snapshot off.
- The README's "Running the tests" commands are runnable again (`cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`).

## 0.10.0

- Distributed tracing across services, using the W3C Trace Context standard (`traceparent`). `forge_ops_tracker::http_span(method, url, data, |traceparent| ...)` records an outgoing HTTP call as an `http` span named after the method and host, and hands the closure the `traceparent` header value (`Option<&str>`) to send with that request; its parent id is the span's own id, so the called service's root span nests under it. `forge_ops_tracker::continue_trace(root_name, traceparent, || ...)` continues an incoming request's trace (same trace id, root span parented under the caller's span); `None` or a malformed value starts a fresh trace. `forge_ops_tracker::TRACEPARENT_HEADER` is the header's name. New `propagate_traces` (default true) and `trace_propagation_targets` (default `None`, meaning every host; or a list of `TracePropagationTarget`s, built with `.into()` from a host string, which matches that host and its subdomains, or a `regex::Regex`) control where the header goes.
- Errors captured inside a trace (explicitly or by the panic hook) now carry a top-level `trace_id`, so ForgeOps can link them to errors from other services that handled the same request. `forge_ops_tracker::current_trace_id()` returns it. Errors captured outside a trace are unchanged.
- With `track_tracing = false`, a `trace` still has a trace id (attached to errors and propagated in the header, since that is also what links errors across services); only span reporting stops. Previously nothing happened inside a `trace` with tracing off.
- Trace and span ids were already W3C shaped (32 and 16 lowercase hex characters); they are now also guaranteed never to be all zeros, the one value the standard reserves as invalid.
- `Event` (exported for reference, never constructed by callers of the public API) gains a `trace_id: Option<String>` field.

This crate has earlier releases (see `Cargo.toml`'s version history in source control), but no `CHANGELOG.md` existed for it before this entry; it starts here rather than backfilling every earlier version.
