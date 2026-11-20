//! The pure parts: how free SQL is boxed in, how query texts lose their literals, and how a result
//! is cut to its byte cap. Nothing here talks to a database.

use serde_json::Value;

use crate::ToolFailure;

/// Bytes kept free for the envelope of a result (`returned_rows`, the truncation marker).
const ENVELOPE_RESERVE: usize = 384;

/// The free SQL as the caller sent it, with surrounding white space and trailing semicolons
/// removed, or a refusal.
fn clean(sql: &str, max_sql_bytes: usize) -> Result<&str, ToolFailure> {
    if sql.len() > max_sql_bytes {
        return Err(ToolFailure::Refused(format!(
            "the SQL text is {} bytes; at most {max_sql_bytes} are accepted",
            sql.len()
        )));
    }
    if sql.contains('\0') {
        return Err(ToolFailure::Refused(
            "the SQL text contains a NUL byte".to_owned(),
        ));
    }
    let trimmed = sql
        .trim()
        .trim_end_matches(|c: char| c == ';' || c.is_whitespace());
    if trimmed.is_empty() {
        return Err(ToolFailure::Refused("the SQL text is empty".to_owned()));
    }
    Ok(trimmed)
}

/// The key of a row that was over the byte cap on its own: `{"_cut_row": "<its first bytes>"}`.
pub const CUT_ROW_KEY: &str = "_cut_row";

/// Wraps free SQL as a subquery whose rows come back as JSON text, with a row limit one above
/// the cap so the caller can tell that more rows exist. Each row's text is cut in SQL to one
/// character more than `max_row_bytes`, so no row larger than the byte cap is ever sent: a cut
/// row is recognised by its length and is not valid JSON.
///
/// The newlines around the text keep a trailing `--` comment from swallowing the closing
/// parenthesis. The result must be sent with the extended protocol, which accepts one statement:
/// a `;` that closes the subquery early leaves a second statement, and the server refuses it.
///
/// # Errors
/// [`ToolFailure::Refused`] for an empty, oversized or NUL-carrying text.
pub fn wrap_query(
    sql: &str,
    max_rows: usize,
    max_sql_bytes: usize,
    max_row_bytes: usize,
) -> Result<String, ToolFailure> {
    let body = clean(sql, max_sql_bytes)?;
    Ok(format!(
        "SELECT left(to_jsonb(q)::text, {}) FROM (\n{body}\n) AS q LIMIT {}",
        max_row_bytes.saturating_add(1),
        max_rows.saturating_add(1)
    ))
}

/// Wraps free SQL for `EXPLAIN (FORMAT JSON)` without `ANALYZE`: the plan of the query as a
/// subquery, so only a query can be explained and nothing is executed.
///
/// # Errors
/// [`ToolFailure::Refused`] for an empty, oversized or NUL-carrying text.
pub fn wrap_explain(sql: &str, max_sql_bytes: usize) -> Result<String, ToolFailure> {
    let body = clean(sql, max_sql_bytes)?;
    Ok(format!(
        "EXPLAIN (FORMAT JSON) SELECT * FROM (\n{body}\n) AS q"
    ))
}

/// Wraps a fixed query of this crate so that its rows come back as JSON text, each cut as
/// [`wrap_query`] cuts it.
pub(crate) fn wrap_fixed(sql: &str, max_row_bytes: usize) -> String {
    format!(
        "SELECT left(to_jsonb(q)::text, {}) FROM (\n{sql}\n) AS q",
        max_row_bytes.saturating_add(1)
    )
}

/// Replaces the literals of a query text with `?`: quoted strings (with `''` and, after `E`,
/// backslash escapes), dollar-quoted strings and numbers. Identifiers, keywords, `$1`
/// parameters and comments' structure stay, so a person can still tell which statement it is.
/// A statement in `pg_stat_activity` may carry a value a client wrote inline; this keeps it out.
pub fn scrub_literals(query: &str) -> String {
    let chars: Vec<char> = query.chars().collect();
    let mut out = String::with_capacity(query.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // A string constant, plain or with the E prefix.
        if c == '\'' {
            let escapes = i > 0
                && matches!(chars[i - 1], 'e' | 'E')
                && !is_word(i.checked_sub(2).and_then(|p| chars.get(p).copied()));
            if escapes {
                out.pop();
            }
            i = skip_quoted(&chars, i + 1, escapes);
            out.push('?');
            continue;
        }
        // A dollar-quoted string: $tag$ ... $tag$. A parameter ($1) is not one.
        if c == '$'
            && let Some(tag_end) = dollar_tag_end(&chars, i)
        {
            let tag: String = chars[i..=tag_end].iter().collect();
            let mut j = tag_end + 1;
            let mut closed = None;
            while j < chars.len() {
                if chars[j] == '$'
                    && chars[j..]
                        .iter()
                        .take(tag.chars().count())
                        .copied()
                        .eq(tag.chars())
                {
                    closed = Some(j + tag.chars().count());
                    break;
                }
                j += 1;
            }
            i = closed.unwrap_or(chars.len());
            out.push('?');
            continue;
        }
        // A number that does not belong to an identifier or a parameter.
        if c.is_ascii_digit() && !is_word(out.chars().last()) && !out.ends_with('$') {
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '.' || chars[i] == '_')
            {
                i += 1;
            }
            out.push('?');
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn is_word(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// The index after the closing quote of a string that starts at `start`.
fn skip_quoted(chars: &[char], start: usize, backslash_escapes: bool) -> usize {
    let mut i = start;
    while i < chars.len() {
        match chars[i] {
            '\\' if backslash_escapes => i += 2,
            '\'' if chars.get(i + 1) == Some(&'\'') => i += 2,
            '\'' => return i + 1,
            _ => i += 1,
        }
    }
    chars.len()
}

/// When a dollar-quote opening tag (`$$` or `$name$`) starts at `start`, the index of its last `$`.
fn dollar_tag_end(chars: &[char], start: usize) -> Option<usize> {
    if is_word(start.checked_sub(1).and_then(|p| chars.get(p).copied())) {
        return None;
    }
    let mut j = start + 1;
    if chars.get(j).is_some_and(char::is_ascii_digit) {
        return None;
    }
    while j < chars.len() {
        let c = chars[j];
        if c == '$' {
            return Some(j);
        }
        if !(c.is_alphanumeric() || c == '_') {
            return None;
        }
        j += 1;
    }
    None
}

/// The largest prefix of `text` that fits `max` bytes and ends on a character boundary.
fn prefix_within(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Renders rows as one JSON object of at most `max_bytes` bytes:
///
/// `{"rows":[...],"returned_rows":N,"more_rows_than_limit":B}` and, when rows or bytes were
/// cut, `"truncated":{"omitted_rows":R,"omitted_bytes":Y,"limit_bytes":L,"note":"..."}`.
///
/// Whole rows are kept while they fit. When even the first row does not fit, a cut copy of it
/// comes back as `{"_cut_row": "<first bytes of its JSON>"}` so the caller sees what it is.
pub fn render_rows(rows: &[Value], more_rows_than_limit: bool, max_bytes: usize) -> String {
    render_read(rows, more_rows_than_limit, false, max_bytes)
}

/// The text of a row that the reader cut at the byte cap (`{"_cut_row": "<text>"}`), if it is one.
fn cut_row_text(row: &Value) -> Option<&str> {
    match row {
        Value::Object(map) if map.len() == 1 => map.get(CUT_ROW_KEY).and_then(Value::as_str),
        _ => None,
    }
}

/// [`render_rows`] for rows read under the byte cap. `stopped` says that reading stopped at the
/// cap: the `truncated` object is then always present, says `"reading_stopped": true`, and its
/// counts are of what was read, so they are lower bounds.
pub fn render_read(
    rows: &[Value],
    more_rows_than_limit: bool,
    stopped: bool,
    max_bytes: usize,
) -> String {
    let budget = max_bytes.saturating_sub(ENVELOPE_RESERVE).max(16);
    let mut kept: Vec<String> = Vec::new();
    let mut used = 0usize;
    let mut omitted_rows = 0usize;
    let mut omitted_bytes = 0usize;
    for row in rows {
        // A row the reader cut is shown by its own first bytes, never whole.
        let text = cut_row_text(row).map_or_else(|| row.to_string(), str::to_owned);
        let cost = text.len() + 1;
        if omitted_rows == 0 && cut_row_text(row).is_none() && used + cost <= budget {
            used += cost;
            kept.push(text);
            continue;
        }
        if kept.is_empty() && omitted_rows == 0 {
            // Room for the wrapper object and the escaping of a few quotes.
            let room = budget.saturating_sub(64) / 2;
            let prefix = prefix_within(&text, room);
            let preview = serde_json::json!({ "_cut_row": prefix }).to_string();
            omitted_bytes += text.len() - prefix.len();
            used += preview.len() + 1;
            kept.push(preview);
            omitted_rows += 1;
            continue;
        }
        omitted_rows += 1;
        omitted_bytes += text.len();
    }
    let mut out = String::with_capacity(used + ENVELOPE_RESERVE);
    out.push_str("{\"rows\":[");
    out.push_str(&kept.join(","));
    out.push_str("],\"returned_rows\":");
    let whole = if omitted_rows > 0 && kept.len() == 1 && kept[0].starts_with("{\"_cut_row\"") {
        0
    } else {
        kept.len()
    };
    out.push_str(&whole.to_string());
    out.push_str(",\"more_rows_than_limit\":");
    out.push_str(if more_rows_than_limit {
        "true"
    } else {
        "false"
    });
    if stopped {
        out.push_str(&format!(
            ",\"truncated\":{{\"omitted_rows\":{omitted_rows},\"omitted_bytes\":{omitted_bytes},\"limit_bytes\":{max_bytes},\"reading_stopped\":true,\"note\":\"over the byte limit: reading stopped and the rest was never fetched; select fewer columns or rows\"}}"
        ));
    } else if omitted_rows > 0 {
        out.push_str(&format!(
            ",\"truncated\":{{\"omitted_rows\":{omitted_rows},\"omitted_bytes\":{omitted_bytes},\"limit_bytes\":{max_bytes},\"note\":\"the result was over the byte limit; select fewer columns or rows\"}}"
        ));
    }
    out.push('}');
    out
}

/// Renders named sections, each with an even share of the byte cap, as one JSON object.
pub fn render_sections(sections: &[(&str, Vec<Value>, bool)], max_bytes: usize) -> String {
    let share = max_bytes.saturating_sub(32 * sections.len()) / sections.len().max(1);
    let mut out = String::from("{");
    for (index, (name, rows, more)) in sections.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&Value::String((*name).to_owned()).to_string());
        out.push(':');
        out.push_str(&render_rows(rows, *more, share));
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn free_sql_becomes_a_limited_subquery_on_its_own_lines() {
        let wrapped = wrap_query("  select 1 as a ;; \n", 200, 1000, 65536).expect("wrapped");
        assert_eq!(
            wrapped,
            "SELECT left(to_jsonb(q)::text, 65537) FROM (\nselect 1 as a\n) AS q LIMIT 201"
        );
    }

    #[test]
    fn a_trailing_line_comment_cannot_eat_the_closing_parenthesis() {
        let wrapped = wrap_query("select 1 -- note", 5, 1000, 100).expect("wrapped");
        assert!(wrapped.ends_with("-- note\n) AS q LIMIT 6"), "{wrapped}");
    }

    #[test]
    fn the_comment_trick_stays_two_statements_inside_one_text() {
        // The text closes the subquery early. The wrapper does not try to stop that: the
        // extended protocol refuses the second statement (the integration tests show it).
        let wrapped =
            wrap_query("SELECT 1) q; DELETE FROM jobs --", 5, 1000, 100).expect("wrapped");
        assert!(wrapped.contains("SELECT 1) q; DELETE FROM jobs --\n) AS q LIMIT 6"));
    }

    #[test]
    fn empty_oversized_and_nul_texts_are_refused() {
        assert!(matches!(
            wrap_query(" ; ", 5, 100, 100),
            Err(ToolFailure::Refused(_))
        ));
        assert!(matches!(
            wrap_query("select 1", 5, 3, 100),
            Err(ToolFailure::Refused(_))
        ));
        assert!(matches!(
            wrap_query("select '\0'", 5, 100, 100),
            Err(ToolFailure::Refused(_))
        ));
        assert!(matches!(
            wrap_explain("", 100),
            Err(ToolFailure::Refused(_))
        ));
    }

    #[test]
    fn explain_never_analyzes_and_explains_a_subquery() {
        let wrapped = wrap_explain("select * from jobs", 1000).expect("wrapped");
        assert_eq!(
            wrapped,
            "EXPLAIN (FORMAT JSON) SELECT * FROM (\nselect * from jobs\n) AS q"
        );
        assert!(!wrapped.to_ascii_uppercase().contains("ANALYZE"));
    }

    #[test]
    fn literals_are_scrubbed_and_structure_kept() {
        assert_eq!(
            scrub_literals("UPDATE t SET a = 'it''s secret', b = 42 WHERE id = $1 AND c = 3.5e2"),
            "UPDATE t SET a = ?, b = ? WHERE id = $1 AND c = ?"
        );
        assert_eq!(
            scrub_literals("select E'a\\'b' , $$body$$, $x$in$x$ from t2 where col1 = 7"),
            "select ? , ?, ? from t2 where col1 = ?"
        );
        assert_eq!(scrub_literals("select 'unterminated"), "select ?");
        assert_eq!(
            scrub_literals("insert into j_2 values ($12)"),
            "insert into j_2 values ($12)"
        );
    }

    #[test]
    fn small_results_are_whole() {
        let rows = vec![json!({"a": 1}), json!({"a": 2})];
        let text = render_rows(&rows, false, 65536);
        let value: Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(value["returned_rows"], json!(2));
        assert_eq!(value["more_rows_than_limit"], json!(false));
        assert!(value.get("truncated").is_none());
    }

    #[test]
    fn large_results_are_cut_at_the_byte_cap_and_say_how_much() {
        let rows: Vec<Value> = (0..500)
            .map(|n| json!({"n": n, "pad": "x".repeat(400)}))
            .collect();
        let text = render_rows(&rows, true, 65536);
        assert!(text.len() <= 65536, "{} bytes", text.len());
        let value: Value = serde_json::from_str(&text).expect("JSON");
        let kept = value["returned_rows"].as_u64().expect("count");
        let omitted = value["truncated"]["omitted_rows"]
            .as_u64()
            .expect("omitted");
        assert_eq!(kept + omitted, 500);
        assert!(value["truncated"]["omitted_bytes"].as_u64().expect("bytes") > 100_000);
        assert_eq!(value["more_rows_than_limit"], json!(true));
    }

    #[test]
    fn a_single_huge_row_comes_back_cut_with_its_size() {
        let rows = vec![json!({"big": "é".repeat(100_000)})];
        let text = render_rows(&rows, false, 4096);
        assert!(text.len() <= 4096, "{} bytes", text.len());
        let value: Value = serde_json::from_str(&text).expect("JSON");
        assert!(value["rows"][0]["_cut_row"].is_string());
        assert_eq!(value["returned_rows"], json!(0));
        assert_eq!(value["truncated"]["omitted_rows"], json!(1));
    }

    #[test]
    fn a_read_that_stopped_says_so_and_shows_a_cut_row_by_its_first_bytes() {
        let cut = json!({ CUT_ROW_KEY: format!("{{\"big\": \"{}", "z".repeat(9000)) });
        let text = render_read(&[cut], false, true, 4096);
        assert!(text.len() <= 4096, "{} bytes", text.len());
        let value: Value = serde_json::from_str(&text).expect("JSON");
        let shown = value["rows"][0][CUT_ROW_KEY].as_str().expect("the cut row");
        assert!(shown.starts_with("{\"big\": \"zzz"), "{shown}");
        assert_eq!(value["returned_rows"], json!(0));
        assert_eq!(value["truncated"]["reading_stopped"], json!(true));
        // Rows that fit, then a stop: the marker is there even though nothing was omitted.
        let text = render_read(&[json!({"n": 1})], false, true, 4096);
        let value: Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(value["returned_rows"], json!(1));
        assert_eq!(value["truncated"]["reading_stopped"], json!(true));
        assert!(
            render_read(&[json!({"n": 1})], false, false, 4096)
                .find("truncated")
                .is_none()
        );
    }

    #[test]
    fn sections_share_the_cap() {
        let big: Vec<Value> = (0..400)
            .map(|n| json!({"n": n, "pad": "y".repeat(300)}))
            .collect();
        let text = render_sections(&[("one", big.clone(), false), ("two", big, false)], 65536);
        assert!(text.len() <= 65536, "{} bytes", text.len());
        let value: Value = serde_json::from_str(&text).expect("JSON");
        assert!(value["one"]["truncated"].is_object());
        assert!(value["two"]["truncated"].is_object());
    }
}
