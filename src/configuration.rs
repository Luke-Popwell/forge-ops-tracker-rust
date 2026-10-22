use std::collections::HashSet;
use std::env;
use std::time::Duration;

/// Holds a single ForgeOps DSN plus everything else the client needs to build and deliver events.
/// Mirrors gems/forge_ops_tracker's Configuration: a single DSN string carries both
/// the ingestion URL and the project's API key: "https://<api_key>@host/api/v1/events".
pub struct Configuration {
    pub dsn: Option<String>,
    pub environment: String,
    pub release: Option<String>,
    pub server_name: Option<String>,

    /// Decides whether a backtrace frame is "in_app": a frame's file path is compared against
    /// this root, the same file-path matching the Ruby gem does against Rails.root and the Python
    /// client does against os.getcwd(). A Rust binary built with debug info embeds real
    /// build-time source paths, so the same approach works here too. Defaults to the current
    /// working directory; set it explicitly if that doesn't match your app's actual layout.
    pub app_root: Option<String>,

    pub enabled_environments: HashSet<String>,
    pub queue_size: usize,
    pub timeout: Duration,
    pub scrub_pii: bool,

    /// Whether `init()` installs the global panic hook (see lib.rs's install_panic_hook) that
    /// reports anything that panics on any thread, with zero further wiring: the same
    /// "unhandled needs no wiring" case Rails.error/ASP.NET Core's middleware and Python's
    /// excepthook wrapper cover automatically for their own languages. Doesn't change panic
    /// behavior (the previously-installed hook still runs afterward), so on by default is safe;
    /// set false to opt out.
    pub install_panic_hook: bool,

    /// Whether `EventBuilder` reads a few lines of source off disk around each in-app frame's
    /// culprit line (see event_builder.rs's `attach_source_context`). Defaults to `true` so a
    /// snippet shows up with zero extra setup, but this field isn't the durable protection
    /// against literal source code leaving a deployment it shouldn't: ForgeOps' own per-project
    /// setting is, since it applies server-side regardless of what any given app happens to have
    /// this field set to locally. Set false here if this app should never even attempt the disk
    /// read in the first place.
    pub capture_source_context: bool,

    /// When an error is reported with the SQL behind a failed database call (see
    /// `capture_error_with_sql`), send the names of the stored procedure, table and view that SQL
    /// touched, so an issue says where to start looking. Names are identifiers, never values,
    /// which is why this defaults on. `capture_sql_statement` is the separate, opt-in step of also
    /// sending the statement itself, with every string and number replaced by `?`; off by default
    /// because even a masked statement describes your schema, and ForgeOps' own per-project
    /// setting is what durably governs whether the server stores it.
    pub capture_sql_objects: bool,
    pub capture_sql_statement: bool,

    /// Whether `add_breadcrumb` actually records anything, and whether a report reads the current
    /// thread's trail back at all: `add_breadcrumb` itself never panics or errors when this is
    /// false, it just becomes a no-op, the same "the call site never has to check first" posture
    /// every other independent tracking mechanism in this crate already has. On by default.
    pub track_breadcrumbs: bool,
    /// The most recent entries a single thread's trail keeps; the oldest is dropped once full.
    /// Matches gems/forge_ops_tracker's own default exactly.
    pub max_breadcrumbs: usize,

    /// Whether `record_performance`/`time_transaction` time anything at all. On by default, the
    /// same "on unless you turn it off" posture error reporting itself already has. This crate has
    /// no web framework integration, so nothing is timed automatically: this only gates the manual
    /// API below.
    pub track_performance: bool,
    /// How often the in-process tallies are flushed as one small aggregate report, rather than one
    /// network call per timed call. Matches gems/forge_ops_tracker's own default (60s).
    pub performance_flush_interval: Duration,

    /// Whether `trace`/`continue_trace` report their trace (when slow) to `/spans`. `span`,
    /// `http_span` and `record_span` only record inside a trace, so this gates every span. With it
    /// off, a trace still has an id, attached to errors captured inside it and handed out by
    /// `http_span` (see `propagate_traces`), since that id is also what links an error here to one
    /// in another service. This crate has no web framework integration, so nothing starts a trace
    /// automatically.
    pub track_tracing: bool,
    /// How often the buffered `capture_metric` entries are flushed as one batch. There is no
    /// `track_metrics` flag the way `track_performance` has one: these are explicit calls the host
    /// app's own code makes, not automatic instrumentation, so there is nothing to turn off that
    /// simply not calling them doesn't already do.
    pub metric_flush_interval: Duration,
    /// The same for `capture_infrastructure_metric`.
    pub infrastructure_metric_flush_interval: Duration,
    /// A trace is only sent when its root span took at least this long.
    pub trace_capture_threshold: Duration,

    /// Whether `http_span` hands its closure a W3C `traceparent` header value for the outgoing
    /// call, so the service being called continues this trace. On by default, matching
    /// gems/forge_ops_tracker: the header carries the trace id that links an error here to an error
    /// there, which is useful with or without spans, so it goes out even with `track_tracing` off.
    pub propagate_traces: bool,
    /// Which hosts get that header. `None` (the default) means every host. Otherwise a list of
    /// [`TracePropagationTarget`]s: a host string matches that host and its subdomains on a dot
    /// boundary (`"example.com"` matches `"api.example.com"`, never `"badexample.com"`), and a
    /// `regex::Regex` is searched for anywhere in the (lowercased) host, so anchor it yourself.
    /// Useful for a third-party API that rejects unknown headers, or that shouldn't learn your
    /// trace ids at all.
    pub trace_propagation_targets: Option<Vec<TracePropagationTarget>>,

    /// Whether `init()` sends one snapshot of what this process sees (the Rust version it was
    /// built with, plus environment variable names if `track_env_var_names` is on) so ForgeOps can
    /// show what changed since the last deploy. Sent once per process, on the delivery thread, so
    /// it never delays startup. On by default; set false to never send it. `record_change` is
    /// unaffected either way.
    pub detect_changes: bool,
    /// Whether that snapshot includes the *names* of this process's environment variables, so an
    /// added or removed variable shows up as a change. Values are never read or sent. Names that
    /// differ from host to host (HOSTNAME, PATH, LC_*, KUBERNETES_*, this crate's own
    /// FORGE_OPS_*, and the like) are left out. Off by default.
    pub track_env_var_names: bool,

    /// Send only structured facts about an error, never free text that could hold personal or
    /// health data: no message (a fingerprint of it instead, so errors still group), no
    /// breadcrumbs (none are recorded), SQL statement or source context, only the user's id, and
    /// only the context and tag keys named in `privacy_allowed_fields`. Spans are named by method
    /// and host for outbound calls, raw paths cut to their first segment, and keep no data beyond the
    /// masked statement and database system. Off by default; `FORGE_OPS_STRICT_PRIVACY=true` turns
    /// it on. See strict_privacy.rs.
    pub strict_privacy: bool,
    /// The context and tag keys strict privacy still sends, when their value is a string, number
    /// or boolean (your own error codes, say). Empty by default;
    /// `FORGE_OPS_PRIVACY_ALLOWED_FIELDS=error_code,feature` sets it.
    pub privacy_allowed_fields: Vec<String>,
}

/// One entry in `Configuration.trace_propagation_targets`. Build one with `.into()` from a `&str`
/// or `String` (a host) or a `regex::Regex`:
///
/// ```no_run
/// forge_ops_tracker::init(|c| {
///     c.trace_propagation_targets = Some(vec![
///         "example.com".into(),
///         regex::Regex::new(r"^internal-\d+\.corp$").unwrap().into(),
///     ]);
/// });
/// ```
#[derive(Debug, Clone)]
pub enum TracePropagationTarget {
    /// Matches this host and its subdomains on a dot boundary, ignoring case and a leading dot.
    Host(String),
    /// Searched for anywhere in the lowercased host.
    Pattern(regex::Regex),
}

impl From<&str> for TracePropagationTarget {
    fn from(host: &str) -> Self {
        TracePropagationTarget::Host(host.to_string())
    }
}

impl From<String> for TracePropagationTarget {
    fn from(host: String) -> Self {
        TracePropagationTarget::Host(host)
    }
}

impl From<regex::Regex> for TracePropagationTarget {
    fn from(pattern: regex::Regex) -> Self {
        TracePropagationTarget::Pattern(pattern)
    }
}

impl TracePropagationTarget {
    fn matches(&self, host: &str) -> bool {
        match self {
            TracePropagationTarget::Host(target) => {
                let domain = target.to_ascii_lowercase();
                let domain = domain.strip_prefix('.').unwrap_or(&domain);
                !domain.is_empty()
                    && (host == domain
                        || host
                            .strip_suffix(domain)
                            .is_some_and(|prefix| prefix.ends_with('.')))
            }
            TracePropagationTarget::Pattern(pattern) => pattern.is_match(host),
        }
    }
}

impl Configuration {
    /// Seeds a Configuration from FORGE_OPS_DSN/FORGE_OPS_ENVIRONMENT/FORGE_OPS_RELEASE (plus
    /// FORGE_OPS_STRICT_PRIVACY/FORGE_OPS_PRIVACY_ALLOWED_FIELDS) and sensible defaults for everything else: the same env vars and defaults every other client
    /// in this repo reads. `environment` is "production" unless FORGE_OPS_ENVIRONMENT says
    /// otherwise (see `resolve_environment`).
    pub fn new() -> Self {
        let mut enabled_environments = HashSet::new();
        enabled_environments.insert("production".to_string());
        enabled_environments.insert("staging".to_string());
        let (strict_privacy, privacy_allowed_fields) =
            crate::strict_privacy::from_environment(|key| env::var(key).ok());

        Configuration {
            dsn: env::var("FORGE_OPS_DSN").ok().filter(|s| !s.is_empty()),
            environment: resolve_environment(|key| env::var(key).ok()),
            release: env::var("FORGE_OPS_RELEASE").ok().filter(|s| !s.is_empty()),
            server_name: safe_hostname(),
            app_root: env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().into_owned()),
            enabled_environments,
            queue_size: 1000,
            timeout: Duration::from_secs(2),
            scrub_pii: true,
            install_panic_hook: true,
            capture_source_context: true,
            capture_sql_objects: true,
            capture_sql_statement: false,
            track_breadcrumbs: true,
            max_breadcrumbs: 30,
            track_performance: true,
            performance_flush_interval: Duration::from_secs(60),
            track_tracing: true,
            metric_flush_interval: Duration::from_secs(60),
            infrastructure_metric_flush_interval: Duration::from_secs(60),
            trace_capture_threshold: Duration::from_secs(1),
            propagate_traces: true,
            trace_propagation_targets: None,
            detect_changes: true,
            track_env_var_names: false,
            strict_privacy,
            privacy_allowed_fields,
        }
    }

    /// Whether an outgoing call to `host` should carry a `traceparent` header; case-insensitive,
    /// since hostnames are. A call with no host only matches when there is no target list.
    pub fn should_propagate_trace(&self, host: Option<&str>) -> bool {
        if !self.propagate_traces {
            return false;
        }
        let Some(targets) = &self.trace_propagation_targets else {
            return true;
        };
        let host = host.unwrap_or("").to_ascii_lowercase();
        !host.is_empty() && targets.iter().any(|target| target.matches(&host))
    }

    /// The DSN's userinfo component, percent-decoded: None if the DSN is unset or malformed.
    pub fn api_key(&self) -> Option<String> {
        self.parsed_dsn().and_then(|d| d.api_key)
    }

    /// The ingestion URL with credentials stripped out: they travel as the Authorization header
    /// instead, never embedded in the request URI.
    pub fn ingestion_uri(&self) -> Option<String> {
        self.parsed_dsn().map(|d| d.ingestion_uri)
    }

    /// Same derivation as `ingestion_uri`, with the trailing "/events" swapped for
    /// "/performance_samples": one DSN, two endpoints, matching the Ruby gem's own
    /// `Configuration#performance_samples_uri`.
    pub fn performance_samples_uri(&self) -> Option<String> {
        self.ingestion_uri()
            .map(|uri| match uri.strip_suffix("/events") {
                Some(base) => format!("{base}/performance_samples"),
                None => uri,
            })
    }

    /// Same derivation again, swapping the trailing "/events" for "/custom_metrics".
    pub fn custom_metrics_uri(&self) -> Option<String> {
        self.swap_events_suffix("/custom_metrics")
    }

    /// Same derivation again, swapping the trailing "/events" for "/infrastructure_metrics".
    pub fn infrastructure_metrics_uri(&self) -> Option<String> {
        self.swap_events_suffix("/infrastructure_metrics")
    }

    fn swap_events_suffix(&self, replacement: &str) -> Option<String> {
        self.ingestion_uri()
            .map(|uri| match uri.strip_suffix("/events") {
                Some(base) => format!("{base}{replacement}"),
                None => uri,
            })
    }

    /// Same derivation again, swapping the trailing "/events" for "/changes".
    pub fn changes_uri(&self) -> Option<String> {
        self.swap_events_suffix("/changes")
    }

    /// Same derivation again, swapping the trailing "/events" for "/change_snapshots".
    pub fn change_snapshots_uri(&self) -> Option<String> {
        self.swap_events_suffix("/change_snapshots")
    }

    /// Same derivation again, swapping the trailing "/events" for "/spans".
    pub fn spans_uri(&self) -> Option<String> {
        self.ingestion_uri()
            .map(|uri| match uri.strip_suffix("/events") {
                Some(base) => format!("{base}/spans"),
                None => uri,
            })
    }

    pub fn is_enabled(&self) -> bool {
        self.dsn.is_some()
            && self.api_key().is_some()
            && self.enabled_environments.contains(&self.environment)
    }

    /// Why nothing will be sent, when this configuration has a DSN but its `environment` isn't one
    /// of `enabled_environments`. None when there's nothing to warn about (no DSN, or the
    /// environment is enabled). [`crate::init`] prints it once per process.
    pub fn not_sending_warning(&self) -> Option<String> {
        if self.dsn.is_none()
            || self.api_key().is_none()
            || self.enabled_environments.contains(&self.environment)
        {
            return None;
        }
        let mut enabled: Vec<&str> = self
            .enabled_environments
            .iter()
            .map(String::as_str)
            .collect();
        enabled.sort_unstable();
        let list = if enabled.is_empty() {
            "no environments are enabled".to_string()
        } else {
            format!("only {} are enabled", enabled.join(", "))
        };
        let environment = &self.environment;
        Some(format!(
            "Not sending: this environment is \"{environment}\", and {list}. \
             Set FORGE_OPS_ENVIRONMENT=production (or add \"{environment}\" to the enabled \
             environments) to send from here."
        ))
    }

    fn parsed_dsn(&self) -> Option<ParsedDsn> {
        self.dsn.as_deref().and_then(parse_dsn)
    }
}

/// The environment a new [`Configuration`] starts with, read through `getenv`:
/// FORGE_OPS_ENVIRONMENT when set and not blank, otherwise "production", so a process given a DSN
/// and nothing else sends. Rust has no standard runtime variable naming the environment, so none
/// is consulted. Set FORGE_OPS_ENVIRONMENT=development where nothing should be sent.
pub(crate) fn resolve_environment(getenv: impl Fn(&str) -> Option<String>) -> String {
    getenv("FORGE_OPS_ENVIRONMENT")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "production".to_string())
}

impl Default for Configuration {
    fn default() -> Self {
        Self::new()
    }
}

struct ParsedDsn {
    api_key: Option<String>,
    ingestion_uri: String,
}

/// Hand-parses a DSN of the form "scheme://api_key@host[:port]/path[?query]" rather than pulling
/// in a URL-parsing crate: the shape is fixed and simple enough that a small dependency-free
/// parser is clearer here than a general-purpose one, the same spirit as the Perl client's own
/// dependency-free design.
fn parse_dsn(dsn: &str) -> Option<ParsedDsn> {
    let (scheme, rest) = dsn.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let (userinfo, host_and_path) = rest.split_once('@')?;
    if userinfo.is_empty() || host_and_path.is_empty() {
        return None;
    }

    let api_key = percent_decode(userinfo);
    Some(ParsedDsn {
        api_key: if api_key.is_empty() {
            None
        } else {
            Some(api_key)
        },
        ingestion_uri: format!("{scheme}://{host_and_path}"),
    })
}

/// Minimal percent-decoding for a DSN's userinfo component: the only place this client ever
/// needs it, not a general-purpose URL decoder.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// std has no cross-platform hostname lookup: shells out to the `hostname` command (present on
/// macOS, Linux, and Windows alike) rather than add a crate for one lookup done once at startup.
/// Mirrors the Ruby gem's own Socket.gethostname wrapped in a rescue: any failure here yields
/// None rather than being able to crash the host app.
fn safe_hostname() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const DEVELOPMENT_WARNING: &str = "Not sending: this environment is \"development\", \
        and only production, staging are enabled. Set FORGE_OPS_ENVIRONMENT=production (or add \
        \"development\" to the enabled environments) to send from here.";

    fn development_config() -> Configuration {
        Configuration {
            dsn: Some("https://abc123@forgeops.example/api/v1/events".to_string()),
            environment: "development".to_string(),
            ..Configuration::new()
        }
    }

    #[test]
    fn environment_defaults_to_production_when_nothing_is_set() {
        assert_eq!(resolve_environment(|_| None), "production");
        assert_eq!(
            resolve_environment(|_| Some("  ".to_string())),
            "production"
        );
    }

    #[test]
    fn environment_comes_from_forge_ops_environment() {
        let env = HashMap::from([("FORGE_OPS_ENVIRONMENT", "development")]);
        assert_eq!(
            resolve_environment(|key| env.get(key).map(|v| v.to_string())),
            "development"
        );
    }

    #[test]
    fn rust_env_variables_are_not_consulted() {
        let env = HashMap::from([("RUST_ENV", "development"), ("APP_ENV", "development")]);
        assert_eq!(
            resolve_environment(|key| env.get(key).map(|v| v.to_string())),
            "production"
        );
    }

    #[test]
    fn not_sending_warning_explains_a_disabled_environment() {
        assert_eq!(
            development_config().not_sending_warning().as_deref(),
            Some(DEVELOPMENT_WARNING)
        );
    }

    #[test]
    fn no_not_sending_warning_when_enabled_or_unconfigured() {
        let mut config = development_config();
        config.environment = "staging".to_string();
        assert_eq!(config.not_sending_warning(), None);

        let mut config = development_config();
        config.dsn = None;
        assert_eq!(config.not_sending_warning(), None);

        let mut config = development_config();
        config
            .enabled_environments
            .insert("development".to_string());
        assert_eq!(config.not_sending_warning(), None);
    }

    #[test]
    fn api_key_and_ingestion_uri() {
        let config = Configuration {
            dsn: Some("https://abc123@forgeops.example/api/v1/events".to_string()),
            ..Configuration::new()
        };

        assert_eq!(config.api_key(), Some("abc123".to_string()));
        assert_eq!(
            config.ingestion_uri(),
            Some("https://forgeops.example/api/v1/events".to_string())
        );
    }

    #[test]
    fn api_key_percent_decodes() {
        let config = Configuration {
            dsn: Some("https://ab%2Fc@forgeops.example/api/v1/events".to_string()),
            ..Configuration::new()
        };

        assert_eq!(config.api_key(), Some("ab/c".to_string()));
    }

    #[test]
    fn empty_or_malformed_dsn() {
        for dsn in [
            "",
            "not-a-url",
            "://broken",
            "https://forgeops.example/no-userinfo",
        ] {
            let config = Configuration {
                dsn: Some(dsn.to_string()),
                ..Configuration::new()
            };
            assert_eq!(config.api_key(), None, "dsn = {dsn:?}");
            assert_eq!(config.ingestion_uri(), None, "dsn = {dsn:?}");
        }
    }

    #[test]
    fn is_enabled_requires_dsn_api_key_and_enabled_environment() {
        let mut config = Configuration::new();
        config.dsn = Some("https://key@host/path".to_string());

        config.environment = "production".to_string();
        assert!(config.is_enabled());

        config.environment = "development".to_string();
        assert!(!config.is_enabled());

        config.environment = "production".to_string();
        config.dsn = None;
        assert!(!config.is_enabled());
    }

    #[test]
    fn defaults() {
        let config = Configuration::new();
        assert_eq!(config.queue_size, 1000);
        assert_eq!(config.timeout, Duration::from_secs(2));
        assert!(config.scrub_pii);
        assert!(config.capture_source_context);
        assert!(config.enabled_environments.contains("production"));
        assert!(config.enabled_environments.contains("staging"));
        assert!(config.propagate_traces);
        assert!(config.trace_propagation_targets.is_none());
        assert!(config.detect_changes);
        assert!(!config.track_env_var_names);
    }

    #[test]
    fn change_endpoints_share_the_dsn() {
        let config = Configuration {
            dsn: Some("https://abc123@forgeops.example/api/v1/events".to_string()),
            ..Configuration::new()
        };
        assert_eq!(
            config.changes_uri(),
            Some("https://forgeops.example/api/v1/changes".to_string())
        );
        assert_eq!(
            config.change_snapshots_uri(),
            Some("https://forgeops.example/api/v1/change_snapshots".to_string())
        );
    }

    #[test]
    fn should_propagate_trace_to_every_host_by_default_and_never_when_off() {
        let mut config = Configuration::new();
        assert!(config.should_propagate_trace(Some("anything.example")));
        assert!(config.should_propagate_trace(None));
        config.propagate_traces = false;
        assert!(!config.should_propagate_trace(Some("anything.example")));
    }

    #[test]
    fn should_propagate_trace_matches_hosts_on_a_dot_boundary_ignoring_case_and_a_leading_dot() {
        let mut config = Configuration::new();
        config.trace_propagation_targets = Some(vec![
            "Example.com".into(),
            ".internal.corp".to_string().into(),
            "".into(),
        ]);
        assert!(config.should_propagate_trace(Some("example.com")));
        assert!(config.should_propagate_trace(Some("API.example.COM")));
        assert!(config.should_propagate_trace(Some("internal.corp")));
        assert!(config.should_propagate_trace(Some("db.internal.corp")));
        assert!(!config.should_propagate_trace(Some("badexample.com")));
        assert!(!config.should_propagate_trace(Some("example.com.evil.net")));
        assert!(!config.should_propagate_trace(Some("other.net")));
        assert!(!config.should_propagate_trace(None));

        config.trace_propagation_targets = Some(vec![]);
        assert!(!config.should_propagate_trace(Some("example.com")));
    }

    #[test]
    fn should_propagate_trace_searches_regex_targets_in_the_lowercased_host() {
        let mut config = Configuration::new();
        config.trace_propagation_targets =
            Some(vec![regex::Regex::new(r"^svc-\d+\.local$").unwrap().into()]);
        assert!(config.should_propagate_trace(Some("svc-12.local")));
        assert!(config.should_propagate_trace(Some("SVC-12.LOCAL")));
        assert!(!config.should_propagate_trace(Some("svc-x.local")));
    }
}
