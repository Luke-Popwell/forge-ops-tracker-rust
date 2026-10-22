// Reads and writes the W3C Trace Context `traceparent` header (https://www.w3.org/TR/trace-context/),
// the vendor-neutral format for carrying one trace across service boundaries:
// `00-<32 hex trace id>-<16 hex parent span id>-<2 hex flags>`. Mirrors
// gems/forge_ops_tracker's own `TraceParent`: `parse` lets `continue_trace` pick up a caller's
// trace, and `build` is what `http_span` hands over for the next service along.
//
// Strict on the way in, the posture the spec asks receivers to take: a malformed value, uppercase
// hex, the reserved version `ff`, or an all-zero trace or parent id all mean "no usable header"
// (`parse` returns None and a fresh trace starts), never half-trusted. A future version is still
// accepted when its first four fields have version 00's shape; version 00 itself must have exactly
// four. Hand-rolled rather than a `regex::Regex`: the shape is fixed-width, so a byte check is
// both simpler and cheaper than compiling a pattern.

use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const HEADER: &str = "traceparent";

// Always "01" (sampled) on the way out: whether a trace is sent is only decided once it's over
// (see Configuration.trace_capture_threshold), long after this header has gone out, so "this may be
// recorded" is the only honest answer. The next service makes its own decision either way.
const SAMPLED_FLAGS: &str = "01";

// "vv-" + 32 + "-" + 16 + "-" + "ff": the four fields every version shares.
const FIXED_LENGTH: usize = 55;

/// A usable incoming header's two ids: the caller's trace, and the caller's span that this work
/// runs under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub trace_id: String,
    pub parent_span_id: String,
}

pub fn parse(value: &str) -> Option<Context> {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() < FIXED_LENGTH {
        return None;
    }
    let lower_hex = |range: std::ops::Range<usize>| {
        bytes[range]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    };
    if !(lower_hex(0..2)
        && bytes[2] == b'-'
        && lower_hex(3..35)
        && bytes[35] == b'-'
        && lower_hex(36..52)
        && bytes[52] == b'-'
        && lower_hex(53..55))
    {
        return None;
    }
    // Everything checked so far is ASCII, so these slices all land on char boundaries.
    let version = &value[0..2];
    let rest = &value[FIXED_LENGTH..];
    if version == "ff" {
        return None;
    }
    if !rest.is_empty() && (version == "00" || !rest.starts_with('-')) {
        return None;
    }
    let trace_id = &value[3..35];
    let parent_span_id = &value[36..52];
    if all_zeros(trace_id) || all_zeros(parent_span_id) {
        return None;
    }
    Some(Context {
        trace_id: trace_id.to_string(),
        parent_span_id: parent_span_id.to_string(),
    })
}

pub fn build(trace_id: &str, span_id: &str) -> String {
    format!("00-{trace_id}-{span_id}-{SAMPLED_FLAGS}")
}

/// 32 lowercase hex characters, never all zeros (the spec's one invalid value).
pub fn generate_trace_id() -> String {
    random_non_zero_hex(2)
}

/// 16 lowercase hex characters, never all zeros.
pub fn generate_span_id() -> String {
    random_non_zero_hex(1)
}

fn all_zeros(id: &str) -> bool {
    id.bytes().all(|b| b == b'0')
}

fn random_non_zero_hex(words: usize) -> String {
    loop {
        let id = random_hex(words);
        if !all_zeros(&id) {
            return id;
        }
    }
}

/// `words` 64-bit words of hex (1 = a 16-char span id, 2 = a 32-char trace id). Rust's standard
/// library has no random number generator, so this mixes the per-process random `RandomState`
/// keys with the clock and a counter: an id only has to be unique within one project's traces, not
/// unpredictable, so this avoids a dependency for it.
fn random_hex(words: usize) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    (0..words)
        .map(|_| {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
            hasher.write_u128(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            );
            format!("{:016x}", hasher.finish())
        })
        .collect()
}

/// The host of an absolute URL (`scheme://[userinfo@]host[:port]/...`), lowercased, or None when
/// there isn't one. Hand-parsed for the same reason configuration.rs parses the DSN by hand: this
/// only ever needs the host, so a URL crate would be a dependency for one field.
pub fn url_host(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_and_port = match authority.rsplit_once('@') {
        Some((_, after)) => after,
        None => authority,
    };
    let host = if host_and_port.starts_with('[') {
        // An IPv6 literal keeps its brackets, the way java.net.URI reports it.
        let end = host_and_port.find(']')?;
        &host_and_port[..=end]
    } else {
        host_and_port.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const SPAN_ID: &str = "00f067aa0ba902b7";

    #[test]
    fn parses_a_valid_version_00_header() {
        let context = parse(&format!("00-{TRACE_ID}-{SPAN_ID}-01")).unwrap();
        assert_eq!(context.trace_id, TRACE_ID);
        assert_eq!(context.parent_span_id, SPAN_ID);
        assert_eq!(
            parse(&format!("  00-{TRACE_ID}-{SPAN_ID}-00 ")),
            Some(context),
            "surrounding whitespace and an unsampled flag are fine"
        );
    }

    #[test]
    fn rejects_anything_malformed() {
        for value in [
            String::new(),
            "garbage".to_string(),
            format!("00-{}-{SPAN_ID}-01", TRACE_ID.to_uppercase()),
            format!("00-{TRACE_ID}-{}-01", SPAN_ID.to_uppercase()),
            format!("ff-{TRACE_ID}-{SPAN_ID}-01"),
            format!("00-{}-{SPAN_ID}-01", "0".repeat(32)),
            format!("00-{TRACE_ID}-{}-01", "0".repeat(16)),
            format!("00-{}-{SPAN_ID}-01", &TRACE_ID[..31]),
            format!("00-{TRACE_ID}-{}-01", &SPAN_ID[..15]),
            format!("00_{TRACE_ID}-{SPAN_ID}-01"),
            format!("00-{TRACE_ID}-{SPAN_ID}-1"),
            format!("00-{TRACE_ID}-{SPAN_ID}-01-extra"),
            format!("0g-{TRACE_ID}-{SPAN_ID}-01"),
            format!("00-{TRACE_ID}-{SPAN_ID}-01é"),
        ] {
            assert_eq!(parse(&value), None, "value = {value:?}");
        }
    }

    #[test]
    fn accepts_a_future_version_with_extra_fields_but_not_glued_on_characters() {
        let context = parse(&format!("01-{TRACE_ID}-{SPAN_ID}-01-what-comes-next")).unwrap();
        assert_eq!(context.trace_id, TRACE_ID);
        assert_eq!(parse(&format!("01-{TRACE_ID}-{SPAN_ID}-01")), Some(context));
        assert_eq!(parse(&format!("01-{TRACE_ID}-{SPAN_ID}-01x")), None);
    }

    #[test]
    fn builds_a_sampled_version_00_header_that_parses_back() {
        let header = build(TRACE_ID, SPAN_ID);
        assert_eq!(header, format!("00-{TRACE_ID}-{SPAN_ID}-01"));
        assert_eq!(parse(&header).unwrap().parent_span_id, SPAN_ID);
    }

    #[test]
    fn generated_ids_are_lowercase_hex_of_the_right_length_and_unique() {
        let is_lower_hex = |id: &str| {
            id.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let trace_id = generate_trace_id();
        assert_eq!(trace_id.len(), 32);
        assert!(is_lower_hex(&trace_id));
        let span_id = generate_span_id();
        assert_eq!(span_id.len(), 16);
        assert!(is_lower_hex(&span_id));

        let ids: std::collections::HashSet<String> =
            (0..1000).map(|_| generate_span_id()).collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn url_host_extracts_just_the_host() {
        assert_eq!(
            url_host("https://API.Example.com/orders/42?x=1").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            url_host("http://user:pw@example.com:8080/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            url_host("http://example.com?q=a@b").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            url_host("http://example.com#frag").as_deref(),
            Some("example.com")
        );
        assert_eq!(url_host("http://[::1]:3000/").as_deref(), Some("[::1]"));
        assert_eq!(url_host("example.com/no-scheme"), None);
        assert_eq!(url_host("http:///path-only"), None);
        assert_eq!(url_host(""), None);
    }
}
