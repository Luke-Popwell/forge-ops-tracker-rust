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

/// Runs every pattern above over a single string, independent of any key: used both directly (a
/// message, a stack frame's file/method) and as the leaf case of scrub_value below.
pub fn scrub_string(text: &str) -> String {
    let mut result = text.to_string();
    for (label, re) in patterns() {
        result = re
            .replace_all(&result, format!("[{label} FILTERED]").as_str())
            .into_owned();
    }
    result
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
}
