// "What changed": the request bodies for an explicit `record_change` and for the snapshot sent
// once at startup. Both are delivered by DeliveryQueue's worker thread like any event; this module
// only builds them. The SDK stays stateless: the server diffs each snapshot against the last one
// for the same project and environment and records what changed.
//
// The snapshot sends only what this process can know for certain. `runtime` is the compiler that
// built the binary (see build.rs). Dependencies are left out entirely: a compiled Rust binary
// carries no record of the crates linked into it that could be read back at runtime, and the
// server treats a missing key as unknown rather than "everything was removed". Environment
// variable names are opt-in, and values are never read at all.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::configuration::Configuration;
use crate::event_builder::format_unix_timestamp;
use crate::pii_scrubber::{json_string, Value};

// The kinds the changes endpoint accepts; it rejects anything else, so an unknown kind is sent as
// "other" instead.
const KINDS: [&str; 6] = [
    "feature_flag",
    "config",
    "migration",
    "dependency",
    "infrastructure",
    "other",
];

const MAX_TITLE_CHARS: usize = 200;

/// One change to record with [`record_change`](crate::record_change): a flag flip, a config edit, a
/// migration, a deploy of infrastructure. Build one with [`Change::new`] and set whichever optional
/// fields apply with struct update syntax:
///
/// ```no_run
/// use forge_ops_tracker::{context, Change};
///
/// forge_ops_tracker::record_change(Change {
///     details: context! {"flag" => "new_checkout", "enabled" => true},
///     actor: Some("alice@example.com".to_string()),
///     ..Change::new("feature_flag", "Enabled new checkout for everyone")
/// });
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Change {
    /// One of `"feature_flag"`, `"config"`, `"migration"`, `"dependency"`, `"infrastructure"`,
    /// `"other"`; anything else is sent as `"other"`.
    pub kind: String,
    /// Required; truncated to 200 characters. A blank title is dropped, since it can't be stored.
    pub title: String,
    pub details: HashMap<String, Value>,
    /// Defaults to `Configuration.environment`.
    pub environment: Option<String>,
    pub service: Option<String>,
    pub actor: Option<String>,
    /// A link to the change itself: a pull request, a flag's settings page. `http` or `https`.
    pub url: Option<String>,
    /// An idempotency key: recording the same id twice stores one change.
    pub id: Option<String>,
    /// Defaults to now.
    pub occurred_at: Option<SystemTime>,
}

impl Change {
    pub fn new(kind: &str, title: &str) -> Self {
        Change {
            kind: kind.to_string(),
            title: title.to_string(),
            details: HashMap::new(),
            environment: None,
            service: None,
            actor: None,
            url: None,
            id: None,
            occurred_at: None,
        }
    }
}

/// The `/changes` request body, or `None` for a blank title.
pub fn change_body(configuration: &Configuration, change: &Change) -> Option<String> {
    let title = change.title.trim();
    if title.is_empty() {
        return None;
    }
    let title: String = title.chars().take(MAX_TITLE_CHARS).collect();
    let kind = if KINDS.contains(&change.kind.as_str()) {
        change.kind.as_str()
    } else {
        "other"
    };
    let environment = change
        .environment
        .as_deref()
        .unwrap_or(&configuration.environment);
    let occurred_at = change
        .occurred_at
        .unwrap_or_else(SystemTime::now)
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut body = format!(
        "{{\"kind\":{},\"title\":{},\"environment\":{},\"occurred_at\":{}",
        json_string(kind),
        json_string(&title),
        json_string(environment),
        json_string(&format_unix_timestamp(occurred_at)),
    );
    if !change.details.is_empty() {
        body.push_str(",\"details\":");
        body.push_str(&Value::Object(change.details.clone()).to_json());
    }
    for (key, value) in [
        ("service", &change.service),
        ("actor", &change.actor),
        ("url", &change.url),
        ("id", &change.id),
    ] {
        if let Some(value) = value.as_deref().filter(|v| !v.is_empty()) {
            body.push_str(&format!(",\"{key}\":{}", json_string(value)));
        }
    }
    body.push('}');
    Some(body)
}

/// `"rust 1.85.0"`, or just `"rust"` if build.rs couldn't read the compiler's version.
pub fn runtime() -> String {
    match option_env!("FORGE_OPS_RUSTC_VERSION") {
        Some(version) => format!("rust {version}"),
        None => "rust".to_string(),
    }
}

/// Whether an environment variable's name is host-specific noise (or this crate's own
/// configuration) rather than something the app itself defines: every host in a fleet has a
/// different HOSTNAME, and a platform adds and drops its own variables on every restart, which
/// would otherwise show up as a change on every deploy. The same list every ForgeOps SDK uses.
pub fn is_noise_env_var_name(name: &str) -> bool {
    const EXACT: [&str; 19] = [
        "HOSTNAME",
        "HOST",
        "HOME",
        "PATH",
        "PWD",
        "OLDPWD",
        "SHLVL",
        "_",
        "TERM",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "TMPDIR",
        "TZ",
        "PORT",
        "DYNO",
        "INVOCATION_ID",
        "JOURNAL_STREAM",
    ];
    const PREFIXES: [&str; 5] = [
        "LC_",
        "SYSTEMD_",
        "MEMORY_PRESSURE_",
        "KUBERNETES_",
        "FORGE_OPS_",
    ];

    // Upper-cased first: Windows treats names case-insensitively, so "Path" is PATH there.
    let name = name.to_ascii_uppercase();
    EXACT.contains(&name.as_str())
        || PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || name.ends_with("_SERVICE_HOST")
        || name.contains("_SERVICE_PORT")
        || name
            .find("_PORT_")
            .is_some_and(|i| name[i + "_PORT_".len()..].contains("_TCP"))
}

/// The names (never the values) of `names`, minus the noise above, sorted and deduplicated so the
/// same set always encodes the same way.
pub fn env_var_names(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut kept: Vec<String> = names
        .into_iter()
        .filter(|name| !name.is_empty() && !is_noise_env_var_name(name))
        .collect();
    kept.sort();
    kept.dedup();
    kept
}

/// The `/change_snapshots` request body. `env_names` is only read when
/// `Configuration.track_env_var_names` is on.
pub fn snapshot_body(
    configuration: &Configuration,
    env_names: impl FnOnce() -> Vec<String>,
) -> String {
    let mut state = format!("\"runtime\":{}", json_string(&runtime()));
    if configuration.track_env_var_names {
        let names: Vec<String> = env_var_names(env_names())
            .iter()
            .map(|name| json_string(name))
            .collect();
        state.push_str(&format!(",\"env_var_names\":[{}]", names.join(",")));
    }
    format!(
        "{{\"environment\":{},\"state\":{{{state}}}}}",
        json_string(&configuration.environment)
    )
}

/// Every environment variable name this process sees, skipping any that isn't valid UTF-8.
/// `vars_os`, not `vars`: `vars` panics on a non-UTF-8 name or value, and the values are never
/// looked at here.
pub fn process_env_var_names() -> Vec<String> {
    std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn config() -> Configuration {
        let mut config = Configuration::new();
        config.environment = "production".to_string();
        config
    }

    #[test]
    fn change_body_has_the_required_fields_and_defaults_environment() {
        let body = change_body(
            &config(),
            &Change {
                occurred_at: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
                ..Change::new("migration", "Add index to orders")
            },
        )
        .unwrap();
        assert_eq!(
            body,
            "{\"kind\":\"migration\",\"title\":\"Add index to orders\",\"environment\":\"production\",\"occurred_at\":\"2023-11-14T22:13:20Z\"}"
        );
    }

    #[test]
    fn change_body_includes_every_optional_field_given() {
        let body = change_body(
            &config(),
            &Change {
                details: crate::context! {"flag" => "new_checkout"},
                environment: Some("staging".to_string()),
                service: Some("billing".to_string()),
                actor: Some("alice".to_string()),
                url: Some("https://example.com/pr/1".to_string()),
                id: Some("flag-42".to_string()),
                ..Change::new("feature_flag", "Enabled \"new checkout\"")
            },
        )
        .unwrap();
        assert!(body.starts_with(
            "{\"kind\":\"feature_flag\",\"title\":\"Enabled \\\"new checkout\\\"\",\"environment\":\"staging\""
        ));
        assert!(body.contains(",\"details\":{\"flag\":\"new_checkout\"}"));
        assert!(body.ends_with(
            ",\"service\":\"billing\",\"actor\":\"alice\",\"url\":\"https://example.com/pr/1\",\"id\":\"flag-42\"}"
        ));
    }

    #[test]
    fn an_unknown_kind_is_sent_as_other() {
        for kind in ["deploy", "", "Feature_Flag"] {
            let body = change_body(&config(), &Change::new(kind, "x")).unwrap();
            assert!(body.starts_with("{\"kind\":\"other\","), "kind = {kind:?}");
        }
        for kind in KINDS {
            let body = change_body(&config(), &Change::new(kind, "x")).unwrap();
            assert!(body.starts_with(&format!("{{\"kind\":\"{kind}\",")));
        }
    }

    #[test]
    fn a_blank_title_is_dropped_and_a_long_one_truncated() {
        assert_eq!(change_body(&config(), &Change::new("config", "  ")), None);
        let body = change_body(&config(), &Change::new("config", &"é".repeat(300))).unwrap();
        assert!(body.contains(&format!("\"title\":\"{}\"", "é".repeat(200))));
    }

    #[test]
    fn runtime_names_rust_and_the_compiler_version_when_known() {
        let runtime = runtime();
        assert!(
            runtime == "rust" || runtime.starts_with("rust 1."),
            "{runtime}"
        );
    }

    #[test]
    fn the_denylist_drops_host_noise_and_keeps_app_names() {
        for name in [
            "HOSTNAME",
            "PATH",
            "Path",
            "_",
            "LC_ALL",
            "SYSTEMD_EXEC_PID",
            "MEMORY_PRESSURE_WATCH",
            "KUBERNETES_SERVICE_HOST",
            "REDIS_SERVICE_HOST",
            "REDIS_SERVICE_PORT",
            "REDIS_SERVICE_PORT_HTTP",
            "REDIS_PORT_6379_TCP",
            "REDIS_PORT_6379_TCP_ADDR",
            "FORGE_OPS_DSN",
            "DYNO",
        ] {
            assert!(is_noise_env_var_name(name), "{name} should be dropped");
        }
        for name in [
            "DATABASE_URL",
            "STRIPE_KEY",
            "REDIS_PORT",
            "PORTAL_URL",
            "HOSTS",
        ] {
            assert!(!is_noise_env_var_name(name), "{name} should be kept");
        }
    }

    #[test]
    fn snapshot_sends_runtime_only_by_default() {
        let body = snapshot_body(&config(), || panic!("env names read without opting in"));
        assert_eq!(
            body,
            format!(
                "{{\"environment\":\"production\",\"state\":{{\"runtime\":{}}}}}",
                json_string(&runtime())
            )
        );
        assert!(!body.contains("dependencies") && !body.contains("schema_version"));
    }

    #[test]
    fn snapshot_sends_sorted_filtered_env_var_names_when_opted_in() {
        let mut config = config();
        config.track_env_var_names = true;
        let body = snapshot_body(&config, || {
            [
                "STRIPE_KEY",
                "HOME",
                "DATABASE_URL",
                "FORGE_OPS_DSN",
                "STRIPE_KEY",
            ]
            .map(str::to_string)
            .to_vec()
        });
        assert!(
            body.ends_with(",\"env_var_names\":[\"DATABASE_URL\",\"STRIPE_KEY\"]}}"),
            "{body}"
        );
    }

    #[test]
    fn process_env_var_names_are_names_only() {
        let names = process_env_var_names();
        assert!(names.iter().all(|name| !name.contains('=')));
    }
}
