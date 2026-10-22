// Finds the SQL behind a database error and reduces it to something safe to send: the names of the
// stored procedures, tables and views it touched, and (only if `capture_sql_statement` is on) the
// statement itself with every string and number replaced by "?". Ported from
// gems/forge_ops_tracker's SqlStatement, which is itself ported from the server's own
// SqlStatementMasker/SqlObjectExtractor: same rules everywhere, and the server applies them again
// on arrival, so a difference here can only ever mean less is masked client-side, never that
// something unmasked gets stored.
//
// Written as a hand-rolled scanner and tokenizer rather than regular expressions: the `regex`
// crate deliberately has no lookaround or backreferences, which the shared pattern relies on (a
// number is only a value when it isn't part of an identifier, and a dollar-quoted body ends at the
// same tag that opened it). The rules are identical; only the mechanism differs.
//
// Deliberately not a SQL parser.

const MASK: &str = "?";
pub(crate) const MAX_SQL_LENGTH: usize = 4000;
const MAX_NAMES: usize = 10;
const MAX_NAME_LENGTH: usize = 200;

/// What extraction found in a statement: its operation (the first keyword), the stored
/// procedures/functions it called, and the tables/views it touched. A view and a table are written
/// the same way in SQL text, so both land in `relations`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlObjects {
    pub operation: Option<String>,
    pub procedures: Vec<String>,
    pub relations: Vec<String>,
}

impl SqlObjects {
    pub fn to_json(&self) -> String {
        use crate::pii_scrubber::json_string;
        let list = |names: &[String]| {
            let quoted: Vec<String> = names.iter().map(|n| json_string(n)).collect();
            format!("[{}]", quoted.join(","))
        };
        let operation = self
            .operation
            .as_deref()
            .map(|op| format!("\"operation\":{},", json_string(op)))
            .unwrap_or_default();
        format!(
            "{{{}\"procedures\":{},\"relations\":{}}}",
            operation,
            list(&self.procedures),
            list(&self.relations)
        )
    }
}

fn is_word(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// `db.system` values where "double quotes" are a string, not a name.
const DOUBLE_QUOTED_STRING_SYSTEMS: [&str; 2] = ["mysql", "mariadb"];

/// Replaces every string literal and number in `statement` with `?`. `None` for a blank statement.
/// `system` is the database's `db.system` when known: for `"mysql"` or `"mariadb"` (any case),
/// "double quoted" text is a string and is masked too; otherwise it's an identifier and is left
/// alone.
pub(crate) fn mask(statement: &str, system: Option<&str>) -> Option<String> {
    if statement.trim().is_empty() {
        return None;
    }
    let double_quoted_strings = system.is_some_and(|system| {
        DOUBLE_QUOTED_STRING_SYSTEMS
            .iter()
            .any(|s| system.eq_ignore_ascii_case(s))
    });

    let s = statement.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        // A string literal, with its E/X/N/B/U& prefix if it has one. '' is an escaped quote and so
        // is \', and one cut off by truncation (no closing quote) is masked to the end of the
        // statement, never left half-visible.
        let string_end = string_quote(s, i)
            .or_else(|| (double_quoted_strings && c == b'"').then_some(i))
            .map(|quote| quoted_end(s, quote));
        if let Some(end) = string_end {
            out.extend_from_slice(MASK.as_bytes());
            i = end;
        } else if c == b'$' {
            // A dollar-quoted body ($tag$ ... $tag$): PostgreSQL function bodies and DO blocks.
            let mut j = i + 1;
            while j < s.len() && (s[j] == b'_' || s[j].is_ascii_alphabetic()) {
                j += 1;
            }
            if j < s.len() && s[j] == b'$' {
                let tag = &s[i..=j];
                let rest = &s[j + 1..];
                let end = rest
                    .windows(tag.len())
                    .position(|w| w == tag)
                    .map(|p| j + 1 + p + tag.len())
                    .unwrap_or(s.len());
                out.extend_from_slice(MASK.as_bytes());
                i = end;
            } else {
                out.push(c);
                i += 1;
            }
        } else if c.is_ascii_digit() || c == b'.' {
            // A number, unless it's part of an identifier (orders2, sp_v2), a $1 placeholder, or
            // the fraction of another number; those digits are left alone.
            let part_of_something =
                i > 0 && (is_word(s[i - 1]) || s[i - 1] == b'$' || s[i - 1] == b'.');
            match if part_of_something {
                None
            } else {
                number_end(s, i)
            } {
                Some(end) => {
                    out.extend_from_slice(MASK.as_bytes());
                    i = end;
                }
                None => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }

    // Only ever cut at ASCII delimiters above, so this is always valid UTF-8.
    let masked = String::from_utf8_lossy(&out).into_owned();
    if masked.chars().count() > MAX_SQL_LENGTH {
        let truncated: String = masked.chars().take(MAX_SQL_LENGTH).collect();
        return Some(format!("{truncated}..."));
    }
    Some(masked)
}

// Where the opening quote is when a string literal starts at `i`: the quote itself, or the one
// right after an E, X, N, B or U& prefix. The prefix only counts when it isn't the end of a longer
// word, but a quote always starts a string, so LIKE'%x%' is still masked (to LIKE?).
fn string_quote(s: &[u8], i: usize) -> Option<usize> {
    if s[i] == b'\'' {
        return Some(i);
    }
    if i > 0 && (is_word(s[i - 1]) || s[i - 1] == b'$') {
        return None;
    }
    let quote = match s[i] {
        b'E' | b'e' | b'X' | b'x' | b'N' | b'n' | b'B' | b'b' => i + 1,
        b'U' | b'u' if s.get(i + 1) == Some(&b'&') => i + 2,
        _ => return None,
    };
    (s.get(quote) == Some(&b'\'')).then_some(quote)
}

// Where the text opened by the quote at `open` ends: a backslash escapes the next character and a
// doubled quote is one quote. Without a closing quote (a string cut off by truncation, even right
// after a backslash) it runs to the end of the statement.
fn quoted_end(s: &[u8], open: usize) -> usize {
    let quote = s[open];
    let mut j = open + 1;
    while j < s.len() {
        if s[j] == b'\\' {
            j += 2;
        } else if s[j] == quote {
            if s.get(j + 1) != Some(&quote) {
                return j + 1;
            }
            j += 2;
        } else {
            j += 1;
        }
    }
    s.len()
}

// Where the number starting at `i` ends, or None when it isn't a standalone number (immediately
// followed by a letter, digit or underscore). Hex (0x1F) and binary (0b101) first, then a decimal
// (42, 1.5, .5) with an optional exponent (3e10, 1.5E-3). One that fails that check falls back to
// a shorter reading, the same way the shared pattern's backtracking does: 1.5x masks just the 1.
fn number_end(s: &[u8], i: usize) -> Option<usize> {
    let ends_here = |k: usize| k >= s.len() || !is_word(s[k]);

    if s[i] == b'0' {
        let radix_digit: Option<fn(&u8) -> bool> = match s.get(i + 1) {
            Some(b'x' | b'X') => Some(u8::is_ascii_hexdigit),
            Some(b'b' | b'B') => Some(|c| *c == b'0' || *c == b'1'),
            _ => None,
        };
        if let Some(radix_digit) = radix_digit {
            let mut k = i + 2;
            while k < s.len() && radix_digit(&s[k]) {
                k += 1;
            }
            if k > i + 2 && ends_here(k) {
                return Some(k);
            }
        }
    }

    // Longest reading first: with the fraction, then without.
    let int_end = digits_end(s, i);
    let mantissas = if int_end > i {
        [fraction_end(s, int_end), Some(int_end)]
    } else {
        [fraction_end(s, i), None]
    };
    for end in mantissas.into_iter().flatten() {
        if let Some(exponent) = exponent_end(s, end).filter(|&k| ends_here(k)) {
            return Some(exponent);
        }
        if ends_here(end) {
            return Some(end);
        }
    }
    None
}

fn digits_end(s: &[u8], mut k: usize) -> usize {
    while k < s.len() && s[k].is_ascii_digit() {
        k += 1;
    }
    k
}

// Where the fraction (.5) starting at `dot` ends, if there is one.
fn fraction_end(s: &[u8], dot: usize) -> Option<usize> {
    (s.get(dot) == Some(&b'.') && s.get(dot + 1).is_some_and(u8::is_ascii_digit))
        .then(|| digits_end(s, dot + 1))
}

// Where the exponent (e10, E-3, e+2) starting at `i` ends, if there is one.
fn exponent_end(s: &[u8], i: usize) -> Option<usize> {
    if !matches!(s.get(i), Some(b'e' | b'E')) {
        return None;
    }
    let mut k = i + 1;
    if matches!(s.get(k), Some(b'+' | b'-')) {
        k += 1;
    }
    let end = digits_end(s, k);
    (end > k).then_some(end)
}

struct Token {
    text: String,
    is_name: bool,
}

// Where the identifier part starting at `i` ends: bare (letters, digits, _ $ # @), "double
// quoted", [bracketed] (SQL Server) or `backticked`.
fn name_part_end(s: &[u8], i: usize) -> Option<usize> {
    let c = *s.get(i)?;
    if is_word(c) || c == b'$' || c == b'#' || c == b'@' {
        let mut j = i;
        while j < s.len() && (is_word(s[j]) || s[j] == b'$' || s[j] == b'#' || s[j] == b'@') {
            j += 1;
        }
        return Some(j);
    }
    if c == b'"' || c == b'`' || c == b'[' {
        let closer = if c == b'[' { b']' } else { c };
        let mut j = i + 1;
        while j < s.len() && s[j] != closer {
            j += 1;
        }
        if j < s.len() && j > i + 1 {
            return Some(j + 1);
        }
    }
    None
}

// Where the (optionally schema-qualified) name starting at `i` ends.
fn name_end(s: &[u8], i: usize) -> Option<usize> {
    let mut end = name_part_end(s, i)?;
    while end < s.len() && s[end] == b'.' {
        match name_part_end(s, end + 1) {
            Some(next) => end = next,
            None => break,
        }
    }
    Some(end)
}

fn tokenize(sql: &str) -> Vec<Token> {
    let s = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i].is_ascii_whitespace() || s[i] == 0x0b {
            i += 1;
            continue;
        }
        if let Some(end) = name_end(s, i) {
            tokens.push(Token {
                text: sql[i..end].to_string(),
                is_name: true,
            });
            i = end;
            continue;
        }
        // Any other character is its own token; step by whole characters so a multi-byte one is
        // never split.
        let width = sql[i..].chars().next().map_or(1, char::len_utf8);
        tokens.push(Token {
            text: sql[i..i + width].to_string(),
            is_name: false,
        });
        i += width;
    }
    tokens
}

fn is_full_name(name: &str) -> bool {
    !name.is_empty() && name_end(name.as_bytes(), 0) == Some(name.len())
}

const OPERATIONS: [&str; 13] = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "WITH", "CALL", "EXEC", "EXECUTE", "CREATE",
    "ALTER", "DROP", "TRUNCATE",
];
const BUILTINS: [&str; 21] = [
    "count",
    "sum",
    "min",
    "max",
    "avg",
    "now",
    "coalesce",
    "nullif",
    "lower",
    "upper",
    "length",
    "concat",
    "cast",
    "date_trunc",
    "current_timestamp",
    "current_date",
    "row_number",
    "rank",
    "json_build_object",
    "json_agg",
    "array_agg",
];
const KEYWORDS_NOT_NAMES: [&str; 8] = [
    "select",
    "set",
    "values",
    "where",
    "lateral",
    "only",
    "unnest",
    "generate_series",
];

/// Takes an already-masked statement (so a keyword inside a string value can't be mistaken for
/// SQL) and returns the names it touched, or `None` when nothing recognizable was found.
pub(crate) fn extract_objects(masked: &str) -> Option<SqlObjects> {
    if masked.trim().is_empty() {
        return None;
    }

    // EXTRACT(year FROM col), SUBSTRING(x FROM 2), TRIM(BOTH FROM x): a FROM that isn't a table.
    let all = tokenize(masked);
    let mut tokens: Vec<&Token> = Vec::new();
    let mut i = 0;
    while i < all.len() {
        let t = &all[i];
        if t.is_name
            && ["extract", "substring", "trim", "overlay"].contains(&t.text.to_lowercase().as_str())
            && all.get(i + 1).is_some_and(|n| n.text == "(")
        {
            let mut close = None;
            for (j, token) in all.iter().enumerate().skip(i + 2) {
                if token.text == "(" {
                    break;
                }
                if token.text == ")" {
                    close = Some(j);
                    break;
                }
            }
            if let Some(j) = close {
                i = j + 1;
                continue;
            }
        }
        tokens.push(t);
        i += 1;
    }

    let mut procedures: Vec<String> = Vec::new();
    let mut relations: Vec<String> = Vec::new();

    let mut i = 0;
    while i + 1 < tokens.len() {
        if tokens[i].is_name
            && ["call", "exec", "execute", "perform"]
                .contains(&tokens[i].text.to_lowercase().as_str())
            && tokens[i + 1].is_name
        {
            let name = &tokens[i + 1].text;
            let first = name.split('.').next().unwrap_or("").to_lowercase();
            if !["immediate", "function", "procedure"].contains(&first.as_str()) {
                procedures.push(name.clone());
                i += 1;
            }
        }
        i += 1;
    }

    let mut i = 0;
    while i + 1 < tokens.len() {
        let keyword = tokens[i].text.to_lowercase();
        if !(tokens[i].is_name
            && ["from", "join", "into", "update", "table"].contains(&keyword.as_str())
            && tokens[i + 1].is_name)
        {
            i += 1;
            continue;
        }
        let name = tokens[i + 1].text.clone();
        let paren = tokens.get(i + 2).is_some_and(|t| t.text == "(");
        i += 2;
        if KEYWORDS_NOT_NAMES.contains(&name.to_lowercase().as_str()) {
            continue;
        }
        // FROM/JOIN some_function(...) is a set-returning function (often a stored one), not a
        // table. INSERT INTO t (a, b) is just a column list, so INTO/UPDATE/TABLE never count.
        if paren && (keyword == "from" || keyword == "join") {
            procedures.push(name);
        } else {
            relations.push(name);
        }
    }

    if tokens.len() >= 3
        && tokens[0].is_name
        && tokens[0].text.eq_ignore_ascii_case("select")
        && tokens[1].is_name
        && tokens[2].text == "("
        && !BUILTINS.contains(&tokens[1].text.to_lowercase().as_str())
        && !tokens
            .iter()
            .any(|t| t.is_name && t.text.eq_ignore_ascii_case("from"))
    {
        procedures.push(tokens[1].text.clone());
    }

    let operation = tokens.first().and_then(|t| {
        let word: String = t
            .text
            .bytes()
            .take_while(|b| is_word(*b))
            .map(char::from)
            .collect();
        let upper = word.to_uppercase();
        OPERATIONS.contains(&upper.as_str()).then_some(upper)
    });

    let objects = SqlObjects {
        operation,
        procedures: clean(procedures),
        relations: clean(relations),
    };
    if objects.procedures.is_empty() && objects.relations.is_empty() && objects.operation.is_none()
    {
        return None;
    }
    Some(objects)
}

fn clean(names: Vec<String>) -> Vec<String> {
    let mut cleaned: Vec<String> = Vec::new();
    for raw in names {
        let name: String = raw.trim().chars().take(MAX_NAME_LENGTH).collect();
        if is_full_name(&name) && !cleaned.contains(&name) {
            cleaned.push(name);
        }
    }
    cleaned.truncate(MAX_NAMES);
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objects(sql: &str) -> Option<SqlObjects> {
        extract_objects(sql)
    }

    #[test]
    fn masks_strings_and_numbers_but_not_identifiers_or_placeholders() {
        assert_eq!(
            mask(
                "SELECT * FROM orders2 WHERE email = 'a@b.co' AND id = 42 AND x = $1",
                None
            )
            .unwrap(),
            "SELECT * FROM orders2 WHERE email = ? AND id = ? AND x = $1"
        );
        assert_eq!(
            mask("SELECT price * 1.5 FROM t WHERE a IN (1,2,3)", None).unwrap(),
            "SELECT price * ? FROM t WHERE a IN (?,?,?)"
        );
        assert_eq!(
            mask("SELECT 1.5x FROM t", None).unwrap(),
            "SELECT ?.5x FROM t"
        );
    }

    #[test]
    fn masks_an_escaped_quote_a_cut_off_string_and_a_dollar_quoted_body() {
        assert_eq!(
            mask("EXEC sp_x @t = 'it''s'", None).unwrap(),
            "EXEC sp_x @t = ?"
        );
        assert_eq!(
            mask("SELECT 1 WHERE n = 'oops", None).unwrap(),
            "SELECT ? WHERE n = ?"
        );
        assert_eq!(
            mask("DO $b$ BEGIN PERFORM 1; END $b$", None).unwrap(),
            "DO ?"
        );
    }

    #[test]
    fn keeps_multibyte_text_intact_and_is_idempotent_truncating_and_blank_safe() {
        assert_eq!(
            mask("SELECT \"naïve\" FROM t WHERE a = 'é'", None).unwrap(),
            "SELECT \"naïve\" FROM t WHERE a = ?"
        );
        let once = mask("SELECT * FROM t WHERE a = 'x' AND b = 9", None).unwrap();
        assert_eq!(mask(&once, None).unwrap(), once);
        assert_eq!(
            mask(&format!("SELECT {} b", "a, ".repeat(3000)), None)
                .unwrap()
                .chars()
                .count(),
            MAX_SQL_LENGTH + 3
        );
        assert_eq!(mask("  ", None), None);
    }

    // The shared masking corpus: the same cases, with the same expected output, are checked in
    // every SDK and against the server's SqlStatementMasker.
    const CORPUS: &[(&str, Option<&str>, &str)] = &[
        ("SELECT * FROM orders WHERE email = 'a@b.co' AND id = 42 LIMIT 10", None, "SELECT * FROM orders WHERE email = ? AND id = ? LIMIT ?"),
        ("EXEC sp_note @text = 'it''s broken'", None, "EXEC sp_note @text = ?"),
        ("SELECT 1 WHERE name = 'unterminated", None, "SELECT ? WHERE name = ?"),
        ("DO $body$ BEGIN PERFORM 1; END $body$", None, "DO ?"),
        ("SELECT \"user id\" FROM orders2 WHERE id = $1 AND v = sp_v2(?)", None, "SELECT \"user id\" FROM orders2 WHERE id = $1 AND v = sp_v2(?)"),
        ("SELECT price * 1.5 FROM t", None, "SELECT price * ? FROM t"),
        ("SELECT * FROM users WHERE name = E'o\\'brien' AND id = 1", None, "SELECT * FROM users WHERE name = ? AND id = ?"),
        ("SELECT * FROM users WHERE name = 'o\\'brien' AND id = 1", None, "SELECT * FROM users WHERE name = ? AND id = ?"),
        ("SELECT * FROM t WHERE b = X'DEADBEEF' AND s = N'uni' AND u = U&'d\\0061t' AND e = e'x'", None, "SELECT * FROM t WHERE b = ? AND s = ? AND u = ? AND e = ?"),
        ("SELECT * FROM t WHERE a LIKE'%secret%'", None, "SELECT * FROM t WHERE a LIKE?"),
        ("SELECT * FROM t WHERE f = 0x1F AND b = 0b101 AND n = 3e10 AND m = 1.5E-3 AND k = .5", None, "SELECT * FROM t WHERE f = ? AND b = ? AND n = ? AND m = ? AND k = ?"),
        ("SELECT e, t.col, 1e5e FROM t", None, "SELECT e, t.col, 1e5e FROM t"),
        ("SELECT \"user id\" FROM t WHERE token = \"abc123secret\"", Some("mysql"), "SELECT ? FROM t WHERE token = ?"),
        ("SELECT \"user id\" FROM t WHERE token = \"abc123secret\"", Some("MariaDB"), "SELECT ? FROM t WHERE token = ?"),
        ("SELECT \"user id\" FROM t WHERE token = \"abc123secret\"", Some("postgresql"), "SELECT \"user id\" FROM t WHERE token = \"abc123secret\""),
        ("SELECT \"user id\" FROM t WHERE token = \"abc123secret\"", None, "SELECT \"user id\" FROM t WHERE token = \"abc123secret\""),
        ("SELECT * FROM t WHERE a = 'x' AND b = 9", None, "SELECT * FROM t WHERE a = ? AND b = ?"),
        ("SELECT * FROM t WHERE a = ? AND b = ?", None, "SELECT * FROM t WHERE a = ? AND b = ?"),
        ("SELECT * FROM t WHERE path = 'C:\\\\dir\\\\' AND n = 5", None, "SELECT * FROM t WHERE path = ? AND n = ?"),
        ("INSERT INTO t (a, b) VALUES (-5, +3.25e+2)", None, "INSERT INTO t (a, b) VALUES (-?, +?)"),
        ("SELECT * FROM t WHERE a = 'secret\\", None, "SELECT * FROM t WHERE a = ?"),
        ("SELECT * FROM t WHERE a = \"secret\\", Some("mysql"), "SELECT * FROM t WHERE a = ?"),
    ];

    #[test]
    fn masks_the_shared_corpus_exactly_like_the_server() {
        for &(input, system, expected) in CORPUS {
            assert_eq!(
                mask(input, system).as_deref(),
                Some(expected),
                "{input:?} ({system:?})"
            );
            assert_eq!(
                mask(expected, system).as_deref(),
                Some(expected),
                "{expected:?} ({system:?})"
            );
        }
    }

    #[test]
    fn finds_a_stored_procedure_with_its_schema() {
        assert_eq!(
            objects("EXEC dbo.sp_refund_order @id = ?").unwrap(),
            SqlObjects {
                operation: Some("EXEC".into()),
                procedures: vec!["dbo.sp_refund_order".into()],
                relations: vec![]
            }
        );
        assert_eq!(
            objects("CALL refund_order(?, ?)").unwrap().procedures,
            vec!["refund_order"]
        );
        assert_eq!(
            objects("SELECT refund_order(?, ?)").unwrap().procedures,
            vec!["refund_order"]
        );
    }

    #[test]
    fn finds_views_joined_tables_and_table_functions() {
        assert_eq!(
            objects("SELECT * FROM v_totals t JOIN public.customers c ON c.id = t.id")
                .unwrap()
                .relations,
            vec!["v_totals", "public.customers"]
        );
        assert_eq!(
            objects("SELECT * FROM get_open_orders(?) o")
                .unwrap()
                .procedures,
            vec!["get_open_orders"]
        );
    }

    #[test]
    fn does_not_misread_column_lists_builtins_or_from_inside_extract() {
        assert_eq!(
            objects("INSERT INTO audit_log (a) VALUES (?)")
                .unwrap()
                .procedures,
            Vec::<String>::new()
        );
        assert_eq!(
            objects("SELECT count(*) FROM orders").unwrap().procedures,
            Vec::<String>::new()
        );
        assert_eq!(
            objects("SELECT 1 FROM orders WHERE extract(year FROM created_at) = ?")
                .unwrap()
                .relations,
            vec!["orders"]
        );
        assert_eq!(objects("garbage"), None);
    }

    #[test]
    fn keeps_quoted_and_bracketed_identifiers_whole() {
        assert_eq!(
            objects("UPDATE \"Order Items\" SET qty = ?")
                .unwrap()
                .relations,
            vec!["\"Order Items\""]
        );
        assert_eq!(
            objects("INSERT INTO [dbo].[audit_log] (a) VALUES (?)")
                .unwrap()
                .relations,
            vec!["[dbo].[audit_log]"]
        );
    }

    #[test]
    fn serializes_to_json() {
        let json = objects("EXEC dbo.sp_x @id = ?").unwrap().to_json();
        assert_eq!(
            json,
            "{\"operation\":\"EXEC\",\"procedures\":[\"dbo.sp_x\"],\"relations\":[]}"
        );
    }
}
