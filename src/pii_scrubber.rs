// Redacts likely-sensitive content out of a payload before it ever leaves this process: the
// same patterns ForgeOps itself applies again on arrival (defense in depth: this layer keeps the
// data off the wire and out of any request logging in between; the server-side layer is what
// actually protects the database, and doesn't depend on every reporting app running an up-to-date
// version of this client). Ported from
// gems/forge_ops_tracker/lib/forge_ops_tracker/pii_scrubber.rb.
//
// Can be turned off via Configuration.scrub_pii = false for a host app that already scrubs its
// own data before it ever reaches error context, or that has its own reasons to want the raw
// payload. Off by default is not an option: the safe default has to be "on."

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

pub const REDACTED: &str = "[FILTERED]";

/// A JSON-like value: what context/tags are built out of. Hand-rolled rather than depending on
/// serde_json's Value: this crate already needs regex/backtrace/ureq for things Rust's standard
/// library genuinely lacks (see README.md's "Dependencies" section), and a fourth dependency
/// purely for a value type this small isn't worth it.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v)
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Number(v as f64)
    }
}
impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Number(v as f64)
    }
}
impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::Number(v as f64)
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Number(v)
    }
}

impl Value {
    /// Serializes this value as JSON. Hand-rolled for the same reason Value itself is (see
    /// above): object key order follows HashMap's own (unspecified, but stable within one
    /// process) iteration order, which the ingestion API doesn't care about.
    pub fn to_json(&self) -> String {
        match self {
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => {
                if n.fract() == 0.0 && n.abs() < 1e15 {
                    format!("{}", *n as i64)
                } else {
                    n.to_string()
                }
            }
            Value::String(s) => json_string(s),
            Value::Array(items) => {
                let parts: Vec<String> = items.iter().map(Value::to_json).collect();
                format!("[{}]", parts.join(","))
            }
            Value::Object(map) => {
                let parts: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{}:{}", json_string(k), v.to_json()))
                    .collect();
                format!("{{{}}}", parts.join(","))
            }
        }
    }
}

pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "apisecret",
    "clientsecret",
    "secretkey",
    "token",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "apitoken",
    "authorization",
    "authtoken",
    "bearer",
    "sessiontoken",
    "csrftoken",
    "creditcard",
    "cardnumber",
    "cardnum",
    "cvv",
    "cvv2",
    "cvc",
    "iban",
    "accountnumber",
    "routingnumber",
    "bankaccount",
    "ssn",
    "socialsecuritynumber",
    "socialsecurity",
    "privatekey",
];

fn patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (
                "EMAIL",
                Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
            ),
            ("SSN", Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()),
            (
                "CREDIT CARD",
                Regex::new(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}\b").unwrap(),
            ),
            (
                "BEARER TOKEN",
                Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*").unwrap(),
            ),
            (
                "JWT",
                Regex::new(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
                    .unwrap(),
            ),
            ("AWS KEY", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
            (
                "STRIPE KEY",
                Regex::new(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b").unwrap(),
            ),
            (
                "GITHUB TOKEN",
                Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b").unwrap(),
            ),
        ]
    })
}

/// IBAN candidates: two letters, two check digits and 11 to 30 more letters or digits, compact or
/// in groups of four. The regex crate picks the same leftmost match a backtracking engine would
/// here; `(?-u)` keeps `\b` and `\d` ASCII, as sdks/PII_SCRUBBING.md asks. A candidate is scrubbed
/// only when the IBAN check passes (is_iban).
fn iban_pattern() -> &'static Regex {
    static IBAN: OnceLock<Regex> = OnceLock::new();
    IBAN.get_or_init(|| {
        Regex::new(
            r"(?-u)\b[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)\b",
        )
        .unwrap()
    })
}

/// Runs every pattern above over a single string, independent of any key: used both directly (a
/// message, a stack frame's file/method) and as the leaf case of scrub_value below. IBANs go first
/// (a spaced IBAN's middle groups look like a formatted card number), then the patterns above,
/// then card numbers in any other shape. sdks/PII_SCRUBBING.md is the rule and
/// tests/fixtures/pii_scrubbing_vectors.json pins it.
pub fn scrub_string(text: &str) -> String {
    let mut result = iban_pattern()
        .replace_all(text, |caps: &regex::Captures| {
            let candidate = &caps[0];
            if is_iban(candidate) {
                "[IBAN FILTERED]".to_string()
            } else {
                candidate.to_string()
            }
        })
        .into_owned();
    for (label, re) in patterns() {
        result = re
            .replace_all(&result, format!("[{label} FILTERED]").as_str())
            .into_owned();
    }
    scrub_card_numbers(&result)
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Finds what `(?<![A-Za-z0-9_])\d(?:[ -]?\d)*(?![A-Za-z0-9_])` would, by hand (the regex crate
/// has no lookaround): a run of digits joined by single spaces or dashes, starting at a digit not
/// preceded by a word character. When the full run is followed by a word character, a regex
/// engine backs off to just before the run's last separator (a separator is not a word
/// character); with no separator to back off to, the run is no match at all and scanning carries
/// on after it. Every boundary here is an ASCII byte, so slicing `text` there is always valid.
fn scrub_card_numbers(text: &str) -> String {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut copied = 0;
    let mut i = 0;
    while i < n {
        if !bytes[i].is_ascii_digit() || (i > 0 && is_word_byte(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let mut end = i + 1;
        let mut last_separator = None;
        while end < n {
            if bytes[end].is_ascii_digit() {
                end += 1;
            } else if (bytes[end] == b' ' || bytes[end] == b'-')
                && end + 1 < n
                && bytes[end + 1].is_ascii_digit()
            {
                last_separator = Some(end);
                end += 2;
            } else {
                break;
            }
        }
        if end < n && is_word_byte(bytes[end]) {
            match last_separator {
                Some(separator) => end = separator,
                None => {
                    i = end;
                    continue;
                }
            }
        }
        out.push_str(&text[copied..i]);
        out.push_str(&scrub_card_numbers_in(&text[i..end]));
        copied = end;
        i = end;
    }
    out.push_str(&text[copied..]);
    out
}

/// Splits a run into its groups at each space or dash. From each group on, the longest stretch of
/// whole groups that is a card number is replaced, and scanning carries on after it; with none,
/// from the next group. So a card followed by its CVV ("4242424242424242 123"), two cards in a
/// row, and Amex's 4-6-5 grouping are all found.
fn scrub_card_numbers_in(run: &str) -> String {
    let mut groups = Vec::new();
    let mut separators = Vec::new();
    let mut start = 0;
    for (k, b) in run.bytes().enumerate() {
        if b == b' ' || b == b'-' {
            groups.push(&run[start..k]);
            separators.push(&run[k..k + 1]);
            start = k + 1;
        }
    }
    groups.push(&run[start..]);
    separators.push("");

    let mut out = String::with_capacity(run.len());
    let mut i = 0;
    while i < groups.len() {
        // A card number has at most 19 digits, so only stretches that short can be one; the last
        // one that is wins, the same as trying the longest stretch first.
        let mut found = None;
        let mut joined = String::new();
        let mut last = i;
        while last < groups.len() && joined.len() + groups[last].len() <= 19 {
            joined.push_str(groups[last]);
            if is_card_number(&joined) {
                found = Some(last);
            }
            last += 1;
        }
        match found {
            Some(j) => {
                out.push_str("[CREDIT CARD FILTERED]");
                out.push_str(separators[j]);
                i = j + 1;
            }
            None => {
                out.push_str(groups[i]);
                out.push_str(separators[i]);
                i += 1;
            }
        }
    }
    out
}

/// 13 to 19 digits, a card network's prefix, and the Luhn check.
fn is_card_number(digits: &str) -> bool {
    let d = digits.as_bytes();
    if d.len() < 13 || d.len() > 19 || !has_card_prefix(d) {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(k, &c)| {
            let value = u32::from(c - b'0');
            if k % 2 == 1 {
                let doubled = value * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                value
            }
        })
        .sum();
    sum % 10 == 0
}

/// 4, 51 to 55, 2221 to 2720, 34, 37, 6011, 644 to 649, 65, 3528 to 3589, 36, 300 to 305, 62.
/// Only called with at least 13 digits.
fn has_card_prefix(d: &[u8]) -> bool {
    let digit = |k: usize| u32::from(d[k] - b'0');
    let two = digit(0) * 10 + digit(1);
    let three = two * 10 + digit(2);
    let four = three * 10 + digit(3);
    d[0] == b'4'
        || (51..=55).contains(&two)
        || matches!(two, 34 | 37 | 65 | 36 | 62)
        || (2221..=2720).contains(&four)
        || four == 6011
        || (3528..=3589).contains(&four)
        || (644..=649).contains(&three)
        || (300..=305).contains(&three)
}

/// The IBAN check, a digit at a time so no big integers are needed: with spaces removed, 15 to 34
/// characters; the first four moved to the end, each letter read as two digits (A is 10, Z is
/// 35), and the remainder by 97 is 1.
fn is_iban(candidate: &str) -> bool {
    let compact: Vec<u8> = candidate.bytes().filter(|&b| b != b' ').collect();
    if compact.len() < 15 || compact.len() > 34 {
        return false;
    }
    let remainder = compact[4..]
        .iter()
        .chain(&compact[..4])
        .fold(0u32, |r, &c| {
            if c.is_ascii_uppercase() {
                let value = u32::from(c - b'A') + 10;
                let r = (r * 10 + value / 10) % 97;
                (r * 10 + value % 10) % 97
            } else {
                (r * 10 + u32::from(c - b'0')) % 97
            }
        });
    remainder == 1
}

/// Redacts value based on key (an entire value redacted wholesale if key looks sensitive,
/// regardless of type) and recurses into arrays/objects, matching every other client's behavior
/// in this repo.
pub fn scrub_value(value: &Value, key: &str) -> Value {
    if !matches!(value, Value::Null) && is_sensitive_key(key) {
        return Value::String(REDACTED.to_string());
    }

    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), scrub_value(v, k)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|v| scrub_value(v, key)).collect()),
        Value::String(s) => Value::String(scrub_string(s)),
        other => other.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let normalized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| normalized.contains(sensitive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_string_email() {
        assert_eq!(
            scrub_string("contact user@example.com for help"),
            "contact [EMAIL FILTERED] for help"
        );
    }

    #[test]
    fn scrub_string_credit_card() {
        assert_ne!(
            scrub_string("charged card 4242-4242-4242-4242 successfully"),
            "charged card 4242-4242-4242-4242 successfully"
        );
    }

    #[test]
    fn scrub_string_leaves_ordinary_numeric_id_alone() {
        let text = "order id 1234567890123456";
        assert_eq!(scrub_string(text), text);
    }

    #[test]
    fn scrub_string_ssn() {
        assert_eq!(
            scrub_string("ssn on file: 123-45-6789"),
            "ssn on file: [SSN FILTERED]"
        );
    }

    #[test]
    fn scrub_string_known_token_formats() {
        for text in [
            "Authorization: Bearer abc123DEF.456-xyz",
            "aws key AKIAABCDEFGHIJKLMNOP in use",
            "stripe key sk_live_abcdefghijklmnop",
            "github token ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ",
        ] {
            assert_ne!(scrub_string(text), text, "expected {text:?} to be redacted");
        }
    }

    #[test]
    fn scrub_value_redacts_whole_value_under_sensitive_key() {
        assert_eq!(
            scrub_value(&Value::Number(12345.0), "apiKey"),
            Value::String(REDACTED.to_string())
        );
    }

    #[test]
    fn scrub_value_recurses_into_objects_and_arrays() {
        let mut input = HashMap::new();
        input.insert("password".to_string(), Value::String("hunter2".to_string()));
        input.insert(
            "note".to_string(),
            Value::String("email me at user@example.com".to_string()),
        );

        let mut nested = HashMap::new();
        nested.insert("token".to_string(), Value::String("abc".to_string()));
        input.insert(
            "items".to_string(),
            Value::Array(vec![
                Value::Object(nested),
                Value::String("visit user@example.com".to_string()),
            ]),
        );

        let scrubbed = scrub_value(&Value::Object(input), "");
        let Value::Object(map) = scrubbed else {
            panic!("expected an object")
        };

        assert_eq!(map["password"], Value::String(REDACTED.to_string()));
        assert_eq!(
            map["note"],
            Value::String("email me at [EMAIL FILTERED]".to_string())
        );

        let Value::Array(items) = &map["items"] else {
            panic!("expected an array")
        };
        let Value::Object(first) = &items[0] else {
            panic!("expected an object")
        };
        assert_eq!(first["token"], Value::String(REDACTED.to_string()));
        assert_eq!(
            items[1],
            Value::String("visit [EMAIL FILTERED]".to_string())
        );
    }

    #[test]
    fn is_sensitive_key_ignores_case_and_punctuation() {
        for key in ["API_KEY", "Api-Key", "apiKey", "X-Api-Key"] {
            assert!(is_sensitive_key(key), "expected {key:?} to be sensitive");
        }
        assert!(!is_sensitive_key("username"));
    }

    #[test]
    fn value_to_json() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), Value::Number(1.0));
        let value = Value::Object(map);
        assert_eq!(value.to_json(), "{\"a\":1}");

        assert_eq!(
            Value::String("he said \"hi\"".to_string()).to_json(),
            "\"he said \\\"hi\\\"\""
        );
        assert_eq!(
            Value::Array(vec![Value::Bool(true), Value::Null]).to_json(),
            "[true,null]"
        );
    }

    /// tests/fixtures/pii_scrubbing_vectors.json, a byte-identical copy of this repo's
    /// sdks/pii_scrubbing_vectors.json, generated from the server's own scrubber (see
    /// sdks/PII_SCRUBBING.md).
    const VECTORS: &str = include_str!("../tests/fixtures/pii_scrubbing_vectors.json");

    /// The objects in one of the vectors file's sections, as key/value string pairs (true and
    /// false read as "true" and "false"). A tiny purpose-built reader, not a JSON parser: the file
    /// holds only arrays of flat objects of strings and booleans, whose only escapes are \" and \\.
    fn section(name: &str) -> Vec<HashMap<String, String>> {
        let start = VECTORS.find(&format!("\"{name}\": [")).expect("section") + name.len() + 4;
        let mut entries = Vec::new();
        let mut entry = HashMap::new();
        let mut tokens = Vec::new();
        let mut chars = VECTORS[start..].chars();
        while let Some(c) = chars.next() {
            let token = match c {
                '"' => {
                    let mut s = String::new();
                    while let Some(c) = chars.next() {
                        match c {
                            '"' => break,
                            '\\' => s.push(chars.next().unwrap()),
                            other => s.push(other),
                        }
                    }
                    s
                }
                't' => {
                    chars.nth(2);
                    "true".to_string()
                }
                'f' => {
                    chars.nth(3);
                    "false".to_string()
                }
                '}' => {
                    entries.push(std::mem::take(&mut entry));
                    continue;
                }
                ']' => break,
                _ => continue,
            };
            tokens.push(token);
            if tokens.len() == 2 {
                let value = tokens.pop().unwrap();
                entry.insert(tokens.pop().unwrap(), value);
            }
        }
        assert!(!entries.is_empty(), "no {name} vectors");
        entries
    }

    #[test]
    fn every_pii_scrubbing_string_vector_scrubs_exactly() {
        let vectors = section("strings");
        assert_eq!(vectors.len(), VECTORS.matches("\"scrubbed\":").count());
        for vector in vectors {
            assert_eq!(
                scrub_string(&vector["input"]),
                vector["scrubbed"],
                "{vector:?}"
            );
        }
    }

    #[test]
    fn every_pii_scrubbing_key_vector_redacts_exactly() {
        let vectors = section("keys");
        assert_eq!(vectors.len(), VECTORS.matches("\"redacted\":").count());
        for vector in vectors {
            let key = &vector["key"];
            let mut map = HashMap::new();
            map.insert(key.clone(), Value::from("x"));
            let Value::Object(scrubbed) = scrub_value(&Value::Object(map), "") else {
                panic!("expected an object")
            };
            let redacted = scrubbed[key] == Value::String(REDACTED.to_string());
            assert_eq!(redacted, vector["redacted"] == "true", "{vector:?}");
        }
    }

    #[test]
    fn card_scan_backs_off_to_the_last_separator_before_a_word_character() {
        assert_eq!(
            scrub_string("4242424242424242 123x"),
            "[CREDIT CARD FILTERED] 123x"
        );
        assert_eq!(
            scrub_string("x4242 4242424242424242"),
            "x4242 [CREDIT CARD FILTERED]"
        );
        assert_eq!(scrub_string("4242424242424242x"), "4242424242424242x");
    }

    #[test]
    fn iban_word_boundary_is_ascii() {
        assert_eq!(
            scrub_string("\u{e9}DE89370400440532013000"),
            "\u{e9}[IBAN FILTERED]"
        );
    }
}
