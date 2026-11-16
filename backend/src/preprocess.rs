//! Local log preprocessing: secret redaction, level classification and template folding.
//! Everything that leaves this module (DB, API, AI context) has been redacted.

use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::config::LogKind;

/// Maximum characters kept from a single record.
pub const MAX_RECORD_CHARS: usize = 2000;

struct Rule {
    re: Regex,
    rep: &'static str,
}

fn rule(re: &str, rep: &'static str) -> Rule {
    Rule {
        re: Regex::new(re).expect("valid redaction regex"),
        rep,
    }
}

static REDACTIONS: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        // PEM blocks
        rule(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
            "<private-key>",
        ),
        // credentials inside URLs: scheme://user:pass@host
        rule(
            r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@",
            "${1}***@",
        ),
        // Authorization headers / bearer tokens
        rule(
            r"(?i)\b(authorization\s*[:=]\s*)(bearer|basic|token)?\s*[A-Za-z0-9._~+/=-]+",
            "${1}${2} ***",
        ),
        rule(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer ***"),
        // JWT
        rule(
            r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}",
            "<jwt>",
        ),
        // Well-known key formats
        rule(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "<aws-key>"),
        rule(r"\b(sk|pk|rk)-[A-Za-z0-9_-]{16,}", "<api-key>"),
        rule(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", "<github-token>"),
        rule(r"\bxox[abpr]-[A-Za-z0-9-]{10,}", "<slack-token>"),
        rule(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", "<telegram-token>"),
        // key=value / "key": "value" pairs with secret-looking keys
        rule(
            r#"(?i)(["']?\b[a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?id|cookie|credential)[a-z0-9_.-]*["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&}\]]+)"#,
            "${1}***",
        ),
        // e-mail addresses
        rule(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "<email>",
        ),
        // card-like numbers (15-16 digits starting 3-6, optional separators); ms timestamps start with 1
        rule(r"\b[3-6]\d{3}(?:[ -]?\d{4}){2}[ -]?\d{3,4}\b", "<card?>"),
    ]
});

/// Removes secrets and personal data from a log line (truncated to `MAX_RECORD_CHARS`).
pub fn redact(input: &str) -> String {
    redact_long(&input.chars().take(MAX_RECORD_CHARS).collect::<String>())
}

/// Like `redact` but without truncation, for script output and samples.
pub fn redact_long(input: &str) -> String {
    let mut s = input.to_string();
    for r in REDACTIONS.iter() {
        if r.re.is_match(&s) {
            s = r.re.replace_all(&s, r.rep).into_owned();
        }
    }
    s
}

static TEMPLATE_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        // leading timestamps in common formats
        rule(
            r"^\s*\[?\d{1,4}[-/][A-Za-z0-9]{1,3}[-/]\d{1,4}[ T:]\d{1,2}:\d{2}:\d{2}(\.\d+)?\s*([+-]\d{2}:?\d{2}|Z|[A-Z]{2,5})?\]?\s*",
            "",
        ),
        rule(
            r"^\s*\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]\s*",
            "",
        ),
        rule(r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}\s+", ""),
        rule(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            "<uuid>",
        ),
        rule(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", "<ip>"),
        rule(r"\b0x[0-9a-fA-F]+\b", "<hex>"),
        rule(r"\b[0-9a-fA-F]{12,}\b", "<hex>"),
        rule(r"\d+(\.\d+)?", "<n>"),
        rule(r"\s+", " "),
    ]
});

/// Collapses variable parts (numbers, ids, addresses) so repeated messages share a template.
pub fn template(redacted: &str) -> String {
    let first_line = redacted.lines().next().unwrap_or("");
    let mut s = first_line.to_string();
    for r in TEMPLATE_RULES.iter() {
        s = r.re.replace_all(&s, r.rep).into_owned();
    }
    let s = s.trim();
    s.chars().take(300).collect()
}

pub fn fingerprint(source: &str, level: &str, template: &str) -> String {
    let mut h = Sha256::new();
    h.update(source.as_bytes());
    h.update([0]);
    h.update(level.as_bytes());
    h.update([0]);
    h.update(template.as_bytes());
    hex::encode(&h.finalize()[..8])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    Info,
    Slow,
    Warning,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Slow => "slow",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
    pub fn counts_as_error(self) -> bool {
        self == Self::Error
    }
}

static GENERIC_ERR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(fatal|panic|critical|crit|emerg|alert|error|err|exception|traceback|segfault|unhandled|uncaught|out of memory|oom)\b").unwrap()
});
static GENERIC_WARN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(warn|warning|deprecated|notice|timeout|timed out|retry)\b").unwrap()
});
static NGINX_ACCESS_STATUS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"" (\d{3}) "#).unwrap());
static NGINX_ACCESS_REQ: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([A-Z]+) ([^ ?"]+)[^"]*" (\d{3})"#).unwrap());
static NGINX_ERR_LEVEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[(emerg|alert|crit|error|warn|notice|info|debug)\]").unwrap());

fn classify_generic(line: &str) -> Level {
    if GENERIC_ERR.is_match(line) {
        Level::Error
    } else if GENERIC_WARN.is_match(line) {
        Level::Warning
    } else {
        Level::Info
    }
}

/// Classifies a (multi-line) record. Returns the level and an optional template override
/// (e.g. normalized request lines for access logs).
pub fn classify(kind: LogKind, record: &str) -> (Level, Option<String>) {
    match kind {
        LogKind::PhpError => {
            let l = record.to_ascii_lowercase();
            let level = if l.contains("fatal error")
                || l.contains("parse error")
                || l.contains("uncaught")
                || l.contains("error:")
                || l.contains(" error ")
                || l.contains("[error]")
            {
                Level::Error
            } else if l.contains("warning") {
                Level::Warning
            } else if l.contains("notice") || l.contains("deprecated") {
                Level::Info
            } else {
                classify_generic(record)
            };
            (level, None)
        }
        LogKind::PhpSlow | LogKind::MysqlSlow => (Level::Slow, None),
        LogKind::NginxAccess => {
            let status: u16 = NGINX_ACCESS_STATUS
                .captures(record)
                .and_then(|c| c[1].parse().ok())
                .unwrap_or(200);
            let level = match status {
                500..=599 => Level::Error,
                400..=499 => Level::Warning,
                _ => Level::Info,
            };
            let tpl = NGINX_ACCESS_REQ.captures(record).map(|c| {
                let path = template(&c[2]);
                format!("{} {} {}", &c[1], path, &c[3])
            });
            (level, tpl)
        }
        LogKind::NginxError => {
            let level = match NGINX_ERR_LEVEL
                .captures(record)
                .map(|c| c[1].to_string())
                .as_deref()
            {
                Some("emerg" | "alert" | "crit" | "error") => Level::Error,
                Some("warn") => Level::Warning,
                Some(_) => Level::Info,
                None => classify_generic(record),
            };
            (level, None)
        }
        LogKind::Node => {
            // pino / bunyan JSON lines: numeric level >= 50 is error, 40 warn
            if record.trim_start().starts_with('{')
                && let Ok(v) =
                    serde_json::from_str::<serde_json::Value>(record.lines().next().unwrap_or(""))
            {
                let msg = v
                    .get("msg")
                    .or_else(|| v.get("message"))
                    .and_then(|m| m.as_str())
                    .map(str::to_string);
                let level = match v.get("level") {
                    Some(serde_json::Value::Number(n)) => match n.as_u64().unwrap_or(30) {
                        50.. => Level::Error,
                        40..=49 => Level::Warning,
                        _ => Level::Info,
                    },
                    Some(serde_json::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                        "error" | "fatal" | "crit" | "critical" => Level::Error,
                        "warn" | "warning" => Level::Warning,
                        _ => Level::Info,
                    },
                    _ => classify_generic(record),
                };
                return (level, msg.map(|m| template(&m)));
            }
            (classify_generic(record), None)
        }
        LogKind::Generic | LogKind::Docker => (classify_generic(record), None),
    }
}

/// Continuation lines (stack traces, indented details) belong to the previous record.
pub fn is_continuation(kind: LogKind, line: &str) -> bool {
    if line.is_empty() {
        return true;
    }
    let first = line.as_bytes()[0];
    if first == b' ' || first == b'\t' {
        return true;
    }
    match kind {
        LogKind::PhpError => {
            line.starts_with("Stack trace:")
                || line.starts_with('#')
                || line.starts_with("  thrown in")
                || line.starts_with("Next ")
        }
        LogKind::MysqlSlow => !line.starts_with("# Time:") && !line.starts_with("# User@Host:"),
        LogKind::PhpSlow => !line.starts_with('['),
        LogKind::Node | LogKind::Generic | LogKind::Docker => {
            line.starts_with("at ")
                || line.starts_with("Caused by")
                || line.starts_with("Traceback")
                || line.starts_with("File \"")
        }
        _ => false,
    }
}

/// A redacted, classified record ready to be counted.
#[derive(Debug, Clone)]
pub struct Record {
    pub level: Level,
    pub template: String,
    pub sample: String,
}

pub fn process(kind: LogKind, raw: &str) -> Record {
    let redacted = redact(raw);
    let (level, tpl) = classify(kind, &redacted);
    let template = match (kind, tpl) {
        (_, Some(t)) => t,
        (LogKind::MysqlSlow, None) => {
            // the statement is the last non-comment line
            let stmt = redacted
                .lines()
                .filter(|l| !l.starts_with('#') && !l.starts_with("SET timestamp"))
                .last()
                .unwrap_or("");
            template(stmt)
        }
        (LogKind::PhpSlow, None) => {
            // first frame of the slow-log stack is the most useful key
            let frame = redacted
                .lines()
                .find(|l| l.contains(") ") && l.contains(':'))
                .unwrap_or(&redacted);
            template(frame)
        }
        _ => template(&redacted),
    };
    let sample: String = redacted.chars().take(1000).collect();
    Record {
        level,
        template,
        sample,
    }
}

/// Joins raw lines into records, keeping stack traces with their header.
pub struct Assembler {
    kind: LogKind,
    pending: Option<String>,
    max_lines: usize,
    pending_lines: usize,
}

impl Assembler {
    pub fn new(kind: LogKind) -> Self {
        Self {
            kind,
            pending: None,
            max_lines: 60,
            pending_lines: 0,
        }
    }

    /// Feeds one line; returns a completed record when a new one starts.
    pub fn push(&mut self, line: &str) -> Option<String> {
        if let Some(p) = self.pending.as_mut()
            && is_continuation(self.kind, line)
        {
            if self.pending_lines < self.max_lines {
                p.push('\n');
                p.push_str(line);
                self.pending_lines += 1;
            }
            return None;
        }
        if line.is_empty() {
            return None;
        }
        self.pending_lines = 1;
        self.pending.replace(line.to_string())
    }

    pub fn flush(&mut self) -> Option<String> {
        self.pending_lines = 0;
        self.pending.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secrets() {
        let cases = [
            ("password=hunter2 user=bob", "hunter2"),
            (r#"{"api_key": "abcd1234efgh"}"#, "abcd1234efgh"),
            (
                "Authorization: Bearer abc.def.ghi123456",
                "abc.def.ghi123456",
            ),
            ("mysql://root:s3cret@db:3306/app", "s3cret"),
            (
                "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk",
                "eyJhbGciOiJIUzI1NiJ9",
            ),
            ("key AKIAABCDEFGHIJKLMNOP used", "AKIAABCDEFGHIJKLMNOP"),
            ("contact alice@example.com now", "alice@example.com"),
            ("sk-abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx"),
            ("card 4111 1111 1111 1111 ok", "4111 1111 1111 1111"),
            ("GET /cb?session_id=zzz123&x=1", "zzz123"),
        ];
        for (input, secret) in cases {
            let out = redact(input);
            assert!(
                !out.contains(secret),
                "{input:?} -> {out:?} still contains {secret:?}"
            );
        }
    }

    #[test]
    fn keeps_useful_text() {
        let out = redact(
            "PHP Fatal error: Uncaught Error: Call to undefined function foo() in /app/index.php:12",
        );
        assert!(out.contains("Call to undefined function foo()"));
    }

    #[test]
    fn templates_fold_variable_parts() {
        let a = template(
            "2024-05-01 12:00:01 user 42 failed from 10.0.0.1 req 6f1c2a3b-1111-2222-3333-444455556666",
        );
        let b = template(
            "2024-05-02 08:13:59 user 7 failed from 192.168.1.20 req 0e1c2a3b-1111-2222-3333-444455556666",
        );
        assert_eq!(a, b);
        assert_eq!(fingerprint("s", "error", &a), fingerprint("s", "error", &b));
        assert_ne!(fingerprint("s", "error", &a), fingerprint("t", "error", &a));
    }

    #[test]
    fn classifies_kinds() {
        assert_eq!(
            classify(
                LogKind::PhpError,
                "[01-May-2024 10:00:00 UTC] PHP Fatal error:  boom"
            )
            .0,
            Level::Error
        );
        assert_eq!(
            classify(
                LogKind::PhpError,
                "[01-May-2024 10:00:00 UTC] PHP Warning:  hmm"
            )
            .0,
            Level::Warning
        );
        let access = r#"1.2.3.4 - - [01/May/2024:10:00:00 +0000] "GET /api/users/123?x=1 HTTP/1.1" 502 12 "-" "curl""#;
        let (lvl, tpl) = classify(LogKind::NginxAccess, access);
        assert_eq!(lvl, Level::Error);
        assert_eq!(tpl.as_deref(), Some("GET /api/users/<n> 502"));
        assert_eq!(
            classify(LogKind::NginxError, "2024/05/01 10:00:00 [crit] 1#1: x").0,
            Level::Error
        );
        assert_eq!(
            classify(LogKind::Node, r#"{"level":50,"msg":"db down 3"}"#).0,
            Level::Error
        );
        assert_eq!(classify(LogKind::Generic, "all good").0, Level::Info);
    }

    #[test]
    fn assembles_stack_traces() {
        let mut a = Assembler::new(LogKind::PhpError);
        assert!(a.push("[x] PHP Fatal error: boom").is_none());
        assert!(a.push("Stack trace:").is_none());
        assert!(a.push("#0 /app/a.php(3): f()").is_none());
        let rec = a.push("[y] PHP Warning: next").unwrap();
        assert_eq!(rec.lines().count(), 3);
        assert_eq!(a.flush().unwrap(), "[y] PHP Warning: next");
    }

    #[test]
    fn mysql_slow_template_uses_statement() {
        let rec = "# Time: 2024-05-01T10:00:00\n# User@Host: app[app] @ localhost []\n# Query_time: 3.2 Lock_time: 0\nSET timestamp=1714557600;\nSELECT * FROM orders WHERE user_id = 42;";
        let r = process(LogKind::MysqlSlow, rec);
        assert_eq!(r.level, Level::Slow);
        assert_eq!(r.template, "SELECT * FROM orders WHERE user_id = <n>;");
    }
}
