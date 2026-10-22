// Strict privacy (`Configuration.strict_privacy`) is for apps that can't let personal or health
// data leave their own servers: an event carries only structured facts (the error's type, its
// stack frames, release, environment, server), never free text a person could have typed. The
// rules, and the vectors every client's tests check against, are in this repo's
// sdks/STRICT_PRIVACY.md; the server applies the same rules again on arrival
// (app/services/strict_privacy.rb) when the project's own Strict privacy setting is on.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::event_builder::{Event, Frame};
use crate::pii_scrubber::Value;

/// How many hex characters of the SHA-256 digest `message_fingerprint` keeps.
const FINGERPRINT_LENGTH: usize = 32;

/// Span data that's structure, not content: the masked statement and which database it ran on.
const SPAN_DATA_KEYS: [&str; 2] = ["db.statement", "db.system"];

/// FORGE_OPS_STRICT_PRIVACY and FORGE_OPS_PRIVACY_ALLOWED_FIELDS read through `getenv`, for
/// `Configuration::new`'s defaults. Anything set on the Configuration afterwards wins.
pub(crate) fn from_environment(getenv: impl Fn(&str) -> Option<String>) -> (bool, Vec<String>) {
    let on =
        getenv("FORGE_OPS_STRICT_PRIVACY").is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
    let fields = getenv("FORGE_OPS_PRIVACY_ALLOWED_FIELDS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(str::to_string)
        .collect();
    (on, fields)
}

/// The message with hex object ids, UUIDs and standalone numbers replaced, in that order: "0x"
/// plus 4 or more hex digits becomes "0x", a UUID becomes "<uuid>" and a run of digits becomes
/// "<n>", the last two only where no ASCII word character ([A-Za-z0-9_]) touches them. The regex
/// crate has no lookbehind, so each step is a scan that checks the neighbouring bytes by hand.
/// Every pattern byte is ASCII and no byte of a multi-byte UTF-8 character is, so scanning bytes
/// never splits or misreads a character.
pub fn normalize_message(message: &str) -> String {
    replace_numbers(&replace_uuids(&replace_hex_object_ids(message)))
}

/// The first 32 hex characters of the SHA-256 of `normalize_message(message)`'s UTF-8 bytes: lets
/// ForgeOps group errors whose messages differ only in ids, without the message being sent.
pub fn message_fingerprint(message: &str) -> String {
    let digest = sha256(normalize_message(message).as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex[..FINGERPRINT_LENGTH].to_string()
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Copies `input` into a new string, replacing each match `find` reports at a position (its
/// length in bytes) with `replacement`. Matches only ever start and end on ASCII bytes, so every
/// slice taken here is on a character boundary.
fn replace_with(
    input: &str,
    replacement: &str,
    find: impl Fn(&[u8], usize) -> Option<usize>,
) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        match find(bytes, i) {
            Some(length) => {
                out.push_str(&input[copied..i]);
                out.push_str(replacement);
                i += length;
                copied = i;
            }
            None => i += 1,
        }
    }
    out.push_str(&input[copied..]);
    out
}

fn replace_hex_object_ids(input: &str) -> String {
    replace_with(input, "0x", |bytes, i| {
        if bytes[i] != b'0' || bytes.get(i + 1) != Some(&b'x') {
            return None;
        }
        let digits = bytes[i + 2..]
            .iter()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count();
        (digits >= 4).then_some(2 + digits)
    })
}

fn replace_uuids(input: &str) -> String {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    const LENGTH: usize = 36;
    replace_with(input, "<uuid>", |bytes, i| {
        if i > 0 && is_word(bytes[i - 1]) {
            return None;
        }
        let mut at = i;
        for (group, length) in GROUPS.iter().enumerate() {
            if group > 0 {
                if bytes.get(at) != Some(&b'-') {
                    return None;
                }
                at += 1;
            }
            for _ in 0..*length {
                if !bytes.get(at).is_some_and(u8::is_ascii_hexdigit) {
                    return None;
                }
                at += 1;
            }
        }
        if bytes.get(i + LENGTH).is_some_and(|&byte| is_word(byte)) {
            return None;
        }
        Some(LENGTH)
    })
}

fn replace_numbers(input: &str) -> String {
    replace_with(input, "<n>", |bytes, i| {
        if !bytes[i].is_ascii_digit() || (i > 0 && is_word(bytes[i - 1])) {
            return None;
        }
        let digits = bytes[i..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if bytes.get(i + digits).is_some_and(|&byte| is_word(byte)) {
            return None;
        }
        Some(digits)
    })
}

/// A request or page path under strict privacy, with no query or fragment. A route template
/// ("/patients/:id/notes", "/orders/{id}") is kept as it is: its words are a developer's and its
/// parameters are already placeholders. A raw path keeps only its first segment (":id" when it
/// holds an ASCII digit or is longer than 40 characters), then "/:path" if there was more, since
/// anything after it can name a person: "/patients/jane-doe/12" is "/patients/:path". No segments
/// at all is "/".
pub fn strict_path(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or("");
    if is_route_template(path) {
        return path.to_string();
    }
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let Some(first) = segments.first() else {
        return "/".to_string();
    };
    let first = if first.bytes().any(|byte| byte.is_ascii_digit()) || first.chars().count() > 40 {
        ":id"
    } else {
        first
    };
    format!(
        "{}{first}{}",
        if path.starts_with('/') { "/" } else { "" },
        if segments.len() > 1 { "/:path" } else { "" }
    )
}

/// Whether any segment of `path` is a route parameter: ":id", "{id}", "<int:id>", "[slug]" or
/// "*path".
fn is_route_template(path: &str) -> bool {
    path.split('/').any(|segment| {
        let wrapped = |open: char, close: char| {
            segment.len() > 2 && segment.starts_with(open) && segment.ends_with(close)
        };
        (segment.len() > 1 && segment.starts_with(':'))
            || segment.starts_with('*')
            || wrapped('{', '}')
            || wrapped('<', '>')
            || wrapped('[', ']')
    })
}

fn http_method() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?i)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[ \t\r\n\x0B\x0C]+([^ \t\r\n\x0B\x0C]+)",
        )
        .unwrap()
    })
}

/// A span's name under strict privacy: an outbound call keeps its method and host
/// ("GET https://api.example.com/patients/42?x=1" is "GET api.example.com"), a request named by
/// its path goes through `strict_path` ("GET /patients/42/notes" is "GET /patients/:path"), so
/// does a bare path ("/42/edit" is "/:id/:path"), and any other name ("OrdersController#create")
/// is kept. The host is read by hand, never with a URL parser, so an address a parser would reject
/// still loses its path.
pub fn span_name(name: &str) -> String {
    if name.starts_with('/') {
        return strict_path(name);
    }
    let Some(captures) = http_method().captures(name) else {
        return name.to_string();
    };
    let method = captures[1].to_ascii_uppercase();
    let target = &captures[2];
    match (!target.starts_with('/'))
        .then(|| host_of(target))
        .flatten()
    {
        Some(host) => format!("{method} {host}"),
        None => format!("{method} {}", strict_path(target)),
    }
}

/// A transaction name under strict privacy: a route or a controller action is kept, but a raw
/// path keeps only its first segment, by the same rule as a span's name.
pub fn transaction_name(name: &str) -> String {
    if name.trim().is_empty() {
        name.to_string()
    } else {
        span_name(name)
    }
}

/// An outbound call's host: whatever comes before the first "/", "?" or "#", without a scheme,
/// credentials or port. It's a host when the address had a scheme or a port, or it has a dot or
/// is "localhost"; otherwise (a relative path) None.
fn host_of(target: &str) -> Option<&str> {
    let scheme_length = scheme_length(target);
    let rest = &target[scheme_length..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, after)| after);
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host, true)
        }
        _ => (authority, false),
    };
    let is_host =
        scheme_length > 0 || port || host.contains('.') || host.eq_ignore_ascii_case("localhost");
    (!host.is_empty() && is_host).then_some(host)
}

/// The length of a leading "scheme://" ([a-z][a-z0-9+.-]* in any case), or 0 when there isn't one.
fn scheme_length(target: &str) -> usize {
    let bytes = target.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return 0;
    }
    let name = bytes
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'.' || b == b'-')
        .count();
    if target[name..].starts_with("://") {
        name + 3
    } else {
        0
    }
}

/// Reduces a built event to what strict privacy sends: the message is replaced by its
/// fingerprint; breadcrumbs, the SQL statement and source context are dropped; context and tags
/// keep only allowed keys with plain values; the user keeps only its id.
pub(crate) fn apply_to_event(mut event: Event, allowed_fields: &[String]) -> Event {
    event.message_fingerprint = Some(message_fingerprint(&event.message));
    event.message = String::new();
    event.breadcrumbs = Vec::new();
    event.sql_statement = None;
    event.context = allowed(event.context, allowed_fields);
    event.tags = allowed(event.tags, allowed_fields);
    event.user = event.user.and_then(user_id).map(|id| {
        let mut user = HashMap::new();
        user.insert("id".to_string(), Value::String(id));
        user
    });
    event.backtrace = event
        .backtrace
        .into_iter()
        .map(|frame| Frame::new(frame.file, frame.line, frame.method, frame.in_app))
        .collect();
    event
}

/// `fields`' allowed top-level keys whose value is a string, number or boolean.
fn allowed(fields: HashMap<String, Value>, allowed_fields: &[String]) -> HashMap<String, Value> {
    fields
        .into_iter()
        .filter(|(key, value)| {
            allowed_fields.contains(key)
                && matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
        })
        .collect()
}

/// The user's "id" as a string, or None when there is none (or it's blank).
fn user_id(user: HashMap<String, Value>) -> Option<String> {
    let id = match user.get("id")? {
        Value::String(id) => id.clone(),
        Value::Null => return None,
        other => other.to_json(),
    };
    (!id.trim().is_empty()).then_some(id)
}

/// A span's data under strict privacy: only the masked statement and the database system.
pub(crate) fn span_data(data: &HashMap<String, Value>) -> HashMap<String, Value> {
    data.iter()
        .filter(|(key, _)| SPAN_DATA_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// SHA-256 (FIPS 180-4), written out here because Rust's standard library has none and the
/// fingerprint is the only hash this crate needs, so a crate for it would be a dependency for one
/// function. Checked against the shared vectors and the standard test values below.
fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Padding: a 1 bit, zeros up to 56 bytes mod 64, then the message length in bits, big-endian.
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((input.len() as u64).wrapping_mul(8)).to_be_bytes());

    for block in message.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (state, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *state = state.wrapping_add(value);
        }
    }

    let mut digest = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::breadcrumb_buffer::Breadcrumb;
    use crate::configuration::Configuration;
    use crate::event_builder::EventBuilder;
    use std::time::{Duration, SystemTime};

    /// tests/fixtures/strict_privacy_vectors.json, a byte-identical copy of this repo's
    /// sdks/strict_privacy_vectors.json, generated from the server's own implementation.
    const VECTORS: &str = include_str!("../tests/fixtures/strict_privacy_vectors.json");

    /// The objects in one of the vectors file's sections, as key/value string pairs. A tiny
    /// purpose-built reader, not a JSON parser: the file holds only arrays of flat objects of
    /// strings, whose only escapes are \t, \n, \" and \\.
    fn section(name: &str) -> Vec<HashMap<String, String>> {
        let start = VECTORS.find(&format!("\"{name}\": [")).expect("section") + name.len() + 4;
        let mut entries = Vec::new();
        let mut entry = HashMap::new();
        let mut strings = Vec::new();
        let mut chars = VECTORS[start..].chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    let mut s = String::new();
                    while let Some(c) = chars.next() {
                        match c {
                            '"' => break,
                            '\\' => s.push(match chars.next().unwrap() {
                                't' => '\t',
                                'n' => '\n',
                                other => other,
                            }),
                            other => s.push(other),
                        }
                    }
                    strings.push(s);
                    if strings.len() == 2 {
                        let value = strings.pop().unwrap();
                        entry.insert(strings.pop().unwrap(), value);
                    }
                }
                '}' => entries.push(std::mem::take(&mut entry)),
                ']' => break,
                _ => {}
            }
        }
        assert!(!entries.is_empty(), "no {name} vectors");
        entries
    }

    #[test]
    fn every_fingerprint_vector_normalizes_and_hashes_exactly() {
        for vector in section("fingerprint") {
            assert_eq!(
                normalize_message(&vector["message"]),
                vector["normalized"],
                "{vector:?}"
            );
            assert_eq!(
                message_fingerprint(&vector["message"]),
                vector["fingerprint"],
                "{vector:?}"
            );
        }
    }

    #[test]
    fn every_span_name_vector() {
        for vector in section("span_name") {
            assert_eq!(span_name(&vector["name"]), vector["strict"], "{vector:?}");
        }
    }

    #[test]
    fn transaction_names_keep_only_a_raw_paths_first_segment_and_keep_routes() {
        for (name, want) in [
            ("GET /patients/42/notes", "GET /patients/:path"),
            ("GET /patients/jane-doe", "GET /patients/:path"),
            ("GET /users/:id", "GET /users/:id"),
            ("OrdersController#create", "OrdersController#create"),
            ("/patients/jane-doe-1961", "/patients/:path"),
            ("app::jobs::Sync", "app::jobs::Sync"),
            ("", ""),
        ] {
            assert_eq!(transaction_name(name), want, "{name}");
        }
    }

    #[test]
    fn every_path_vector() {
        for vector in section("path") {
            assert_eq!(strict_path(&vector["path"]), vector["strict"], "{vector:?}");
        }
    }

    #[test]
    fn sha256_matches_the_standard_test_values() {
        let hex =
            |input: &[u8]| -> String { sha256(input).iter().map(|b| format!("{b:02x}")).collect() };
        assert_eq!(
            hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&[b'a'; 1000]),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn options_come_from_the_environment() {
        let env: HashMap<&str, &str> = [
            ("FORGE_OPS_STRICT_PRIVACY", "true"),
            ("FORGE_OPS_PRIVACY_ALLOWED_FIELDS", "error_code, feature,,"),
        ]
        .into_iter()
        .collect();
        let (on, fields) = from_environment(|key| env.get(key).map(|v| v.to_string()));
        assert!(on);
        assert_eq!(fields, vec!["error_code", "feature"]);
        assert_eq!(from_environment(|_| None), (false, Vec::new()));
    }

    fn strict_configuration() -> Configuration {
        Configuration {
            environment: "production".to_string(),
            app_root: Some("/app".to_string()),
            capture_sql_statement: true,
            strict_privacy: true,
            privacy_allowed_fields: vec![
                "error_code".to_string(),
                "feature".to_string(),
                "nested".to_string(),
            ],
            ..Configuration::new()
        }
    }

    fn crumbs() -> Vec<Breadcrumb> {
        vec![Breadcrumb {
            category: "custom".to_string(),
            message: "opened Jane's chart".to_string(),
            level: "info".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            data: HashMap::new(),
        }]
    }

    fn frame_with_context() -> Frame {
        Frame {
            context_line: Some("let patient = \"Jane\";".to_string()),
            pre_context: Some(vec!["fn main() {".to_string()]),
            post_context: Some(vec!["}".to_string()]),
            ..Frame::new(
                "/app/src/main.rs".to_string(),
                2,
                "app::main".to_string(),
                true,
            )
        }
    }

    fn build(config: &Configuration) -> Event {
        let mut context = HashMap::new();
        context.insert("error_code".to_string(), Value::from("E42"));
        context.insert("feature".to_string(), Value::Number(7.0));
        context.insert("nested".to_string(), Value::Object(HashMap::new()));
        context.insert("patient".to_string(), Value::from("Jane Doe"));
        let mut user = HashMap::new();
        user.insert("id".to_string(), Value::Number(42.0));
        user.insert("email".to_string(), Value::from("jane@example.com"));
        user.insert("username".to_string(), Value::from("jane"));
        EventBuilder::new(config).build_with_sql(
            "app::NotFound",
            "Couldn't find Invoice with id=8821",
            vec![frame_with_context()],
            context,
            Some(user),
            crumbs(),
            Some("SELECT * FROM invoices WHERE id = 8821"),
        )
    }

    #[test]
    fn a_strict_event_carries_no_free_text() {
        let event = build(&strict_configuration());
        let json = event.to_json();

        assert_eq!(event.message, "");
        assert_eq!(
            event.message_fingerprint.as_deref(),
            Some("b6959809369b97323c7852eaeb67d4ef")
        );
        assert!(json.contains("\"message\":\"\""), "{json}");
        assert!(
            json.contains("\"message_fingerprint\":\"b6959809369b97323c7852eaeb67d4ef\""),
            "{json}"
        );
        for absent in [
            "breadcrumbs",
            "sql_statement",
            "endpoint",
            "context_line",
            "pre_context",
            "post_context",
            "email",
            "username",
            "patient",
            "nested",
            "\"tags\"",
            "Jane",
        ] {
            assert!(!json.contains(absent), "{absent} in {json}");
        }
        assert_eq!(event.context.len(), 2);
        assert_eq!(event.context["error_code"], Value::from("E42"));
        assert_eq!(event.context["feature"], Value::Number(7.0));
        assert!(json.contains("\"user\":{\"id\":\"42\"}"), "{json}");
        assert!(json.contains("\"sql_objects\""), "{json}");
        assert!(json.contains("\"file\":\"/app/src/main.rs\",\"line\":2,\"method\":\"app::main\",\"in_app\":true}"), "{json}");
    }

    #[test]
    fn a_strict_event_leaves_out_context_and_user_when_nothing_is_left() {
        let config = Configuration {
            privacy_allowed_fields: Vec::new(),
            ..strict_configuration()
        };
        let mut user = HashMap::new();
        user.insert("email".to_string(), Value::from("jane@example.com"));
        let mut context = HashMap::new();
        context.insert("error_code".to_string(), Value::from("E42"));
        let json = EventBuilder::new(&config)
            .build("app::Boom", "boom", vec![], context, Some(user), vec![])
            .to_json();
        for absent in ["\"context\"", "\"tags\"", "\"user\""] {
            assert!(!json.contains(absent), "{absent} in {json}");
        }
        assert!(
            json.contains("\"message_fingerprint\":\"81f52337ebb4cb1669bb802c708807dd\""),
            "{json}"
        );
    }

    #[test]
    fn the_fingerprint_is_of_the_message_as_pii_scrubbing_leaves_it() {
        let config = strict_configuration();
        let message = "no invoice for jane@example.com";
        let event = EventBuilder::new(&config).build(
            "app::Boom",
            message,
            vec![],
            HashMap::new(),
            None,
            vec![],
        );
        assert_eq!(
            event.message_fingerprint,
            Some(message_fingerprint(&crate::pii_scrubber::scrub_string(
                message
            )))
        );
        assert_ne!(
            event.message_fingerprint,
            Some(message_fingerprint(message))
        );
    }

    #[test]
    fn strict_privacy_off_leaves_events_as_before() {
        let config = Configuration {
            strict_privacy: false,
            ..strict_configuration()
        };
        let event = build(&config);
        let json = event.to_json();
        assert_eq!(event.message, "Couldn't find Invoice with id=8821");
        assert_eq!(event.message_fingerprint, None);
        assert!(!json.contains("message_fingerprint"), "{json}");
        assert_eq!(event.context.len(), 4);
        assert_eq!(event.user.as_ref().unwrap().len(), 3);
        assert_eq!(event.breadcrumbs.len(), 1);
        assert_eq!(
            event.sql_statement.as_deref(),
            Some("SELECT * FROM invoices WHERE id = ?")
        );
        assert!(event.backtrace[0].context_line.is_some());
        assert!(json.contains("\"tags\":{}"), "{json}");
    }

    #[test]
    fn source_context_is_never_read_under_strict_privacy() {
        // capture_backtrace's frames from this test file are in-app with app_root set to this
        // crate's directory, so with strict privacy off they'd carry source context.
        let root = env!("CARGO_MANIFEST_DIR").to_string();
        let mut config = Configuration {
            app_root: Some(root),
            ..strict_configuration()
        };
        let frames = crate::event_builder::capture_backtrace(&config);
        assert!(frames.iter().any(|f| f.in_app), "{frames:?}");
        assert!(
            frames.iter().all(|f| f.context_line.is_none()),
            "{frames:?}"
        );

        config.strict_privacy = false;
        let frames = crate::event_builder::capture_backtrace(&config);
        assert!(
            frames.iter().any(|f| f.context_line.is_some()),
            "{frames:?}"
        );
    }

    #[test]
    fn strict_spans_keep_only_method_host_and_statement_data() {
        let mut config = strict_configuration();
        config.dsn = Some("https://key@tracker.example.com/api/v1/events".to_string());
        config.trace_capture_threshold = Duration::from_millis(0);
        assert!(crate::span_buffer::begin(&config, None));

        let mut http = HashMap::new();
        http.insert("status".to_string(), Value::Number(200.0));
        http.insert(
            "url".to_string(),
            Value::from("https://api.example.com/patients/42"),
        );
        crate::span_buffer::record_leaf(
            "GET https://api.example.com/patients/42?x=1",
            "http",
            SystemTime::now(),
            1.0,
            http,
        );
        crate::span_buffer::record_leaf(
            "load patient",
            "database",
            SystemTime::now(),
            1.0,
            crate::database_span_data(
                "SELECT * FROM patients WHERE name = 'Jane'",
                Some("postgresql"),
            ),
        );
        let body = crate::span_buffer::end(
            Duration::ZERO,
            "GET /patients/42/notes",
            "controller",
            SystemTime::now(),
            5.0,
        )
        .unwrap();

        assert!(body.contains("\"name\":\"GET /patients/:path\""), "{body}");
        assert!(body.contains("\"name\":\"GET api.example.com\""), "{body}");
        for absent in ["patients/42", "\"status\"", "\"url\"", "Jane"] {
            assert!(!body.contains(absent), "{absent} in {body}");
        }
        assert!(
            body.contains("\"db.statement\":\"SELECT * FROM patients WHERE name = ?\""),
            "{body}"
        );
        assert!(body.contains("\"db.system\":\"postgresql\""), "{body}");
        assert_eq!(body.matches("\"data\"").count(), 1, "{body}");
    }

    #[test]
    fn spans_are_unchanged_with_strict_privacy_off() {
        let mut config = strict_configuration();
        config.strict_privacy = false;
        config.dsn = Some("https://key@tracker.example.com/api/v1/events".to_string());
        assert!(crate::span_buffer::begin(&config, None));
        let mut http = HashMap::new();
        http.insert("status".to_string(), Value::Number(200.0));
        crate::span_buffer::record_leaf(
            "GET api.example.com",
            "http",
            SystemTime::now(),
            1.0,
            http,
        );
        let body = crate::span_buffer::end(
            Duration::ZERO,
            "GET /patients/42/notes",
            "controller",
            SystemTime::now(),
            5.0,
        )
        .unwrap();
        assert!(
            body.contains("\"name\":\"GET /patients/42/notes\""),
            "{body}"
        );
        assert!(body.contains("\"data\":{\"status\":200}"), "{body}");
        assert!(body.contains("\"data\":{}"), "{body}");
    }
}
