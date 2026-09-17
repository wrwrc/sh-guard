use crate::types::RiskFactor;

#[derive(Debug, Clone)]
pub struct InjectionPattern {
    pub name: &'static str,
    pub detect_fn: fn(&str, &str) -> bool, // (unquoted_text, raw_text) -> matched
    pub score: u8,
    pub risk_factor: RiskFactor,
    pub description: &'static str,
}

// Command/process substitution and arithmetic expansion score low on their
// own: the parser analyzes every substitution body as a command segment in
// its own right (see `parser::parse`), so `$(rm -rf /)` is scored as the
// deletion it runs, while everyday `X=$(date +%s)` / `$((E-S))` stay quiet.
pub static INJECTION_PATTERNS: &[InjectionPattern] = &[
    InjectionPattern {
        name: "command_substitution_dollar",
        detect_fn: |unquoted, _raw| unquoted.contains("$("),
        score: 15,
        risk_factor: RiskFactor::CommandSubstitution,
        description: "$() command substitution",
    },
    InjectionPattern {
        name: "command_substitution_backtick",
        detect_fn: |unquoted, _raw| unquoted.contains('`'),
        score: 15,
        risk_factor: RiskFactor::CommandSubstitution,
        description: "Backtick command substitution",
    },
    InjectionPattern {
        name: "process_substitution_in",
        detect_fn: |unquoted, _raw| unquoted.contains("<("),
        score: 15,
        risk_factor: RiskFactor::ProcessSubstitution,
        description: "<() process substitution",
    },
    InjectionPattern {
        name: "process_substitution_out",
        detect_fn: |unquoted, _raw| unquoted.contains(">("),
        score: 15,
        risk_factor: RiskFactor::ProcessSubstitution,
        description: ">() process substitution",
    },
    InjectionPattern {
        name: "parameter_expansion",
        // Plain `${VAR}`, defaults (`${VAR:-x}`, `${VAR:=x}`, `${VAR:?}`,
        // `${VAR:+x}`), lengths (`${#VAR}`) and prefix/suffix trims
        // (`${f%.txt}`) are everyday shell. Only the forms that can
        // assemble or disguise text are a signal: substrings, pattern
        // substitution, case conversion and indirection.
        detect_fn: |unquoted, _raw| has_obfuscating_parameter_expansion(unquoted),
        score: 35,
        risk_factor: RiskFactor::ShellInjection,
        description: "${} parameter expansion",
    },
    InjectionPattern {
        name: "ifs_injection",
        detect_fn: |unquoted, _raw| unquoted.contains("$IFS") || unquoted.contains("${IFS"),
        score: 50,
        risk_factor: RiskFactor::ShellInjection,
        description: "IFS variable manipulation",
    },
    InjectionPattern {
        name: "arithmetic_expansion",
        detect_fn: |unquoted, _raw| unquoted.contains("$(("),
        score: 5,
        risk_factor: RiskFactor::ShellInjection,
        description: "Arithmetic expansion",
    },
    InjectionPattern {
        name: "unicode_whitespace",
        detect_fn: |_unquoted, raw| {
            raw.chars()
                .any(|c| c.is_whitespace() && !matches!(c, ' ' | '\t' | '\n' | '\r'))
        },
        score: 45,
        risk_factor: RiskFactor::ShellInjection,
        description: "Non-ASCII whitespace (obfuscation)",
    },
    InjectionPattern {
        name: "control_characters",
        detect_fn: |_unquoted, raw| {
            raw.bytes()
                .any(|b| matches!(b, 0x00..=0x08 | 0x0E..=0x1F | 0x7F))
        },
        score: 45,
        risk_factor: RiskFactor::ShellInjection,
        description: "Control characters in command",
    },
    InjectionPattern {
        name: "carriage_return",
        detect_fn: |_unquoted, raw| raw.contains('\r'),
        score: 40,
        risk_factor: RiskFactor::ShellInjection,
        description: "Carriage return (misparsing risk)",
    },
    InjectionPattern {
        name: "ansi_c_quoting",
        // Only as a quoting construct in shell-active text: `"...-$$"`
        // (the PID, then a closing quote) is not `$"..."` locale quoting.
        detect_fn: |_unquoted, raw| has_ansi_c_quoting(raw),
        score: 35,
        risk_factor: RiskFactor::ObfuscatedCommand,
        description: "ANSI-C quoting (can encode arbitrary bytes)",
    },
    InjectionPattern {
        name: "escaped_semicolon",
        detect_fn: |unquoted, _raw| unquoted.contains("\\;"),
        score: 25,
        risk_factor: RiskFactor::ShellInjection,
        description: "Escaped semicolon",
    },
    InjectionPattern {
        name: "escaped_pipe",
        // Inside quotes `\|` is regex alternation (`grep "a\|b"`), not a
        // shell escape.
        detect_fn: |unquoted, _raw| unquoted.contains("\\|"),
        score: 25,
        risk_factor: RiskFactor::ShellInjection,
        description: "Escaped pipe",
    },
    InjectionPattern {
        name: "escaped_ampersand",
        detect_fn: |unquoted, _raw| unquoted.contains("\\&"),
        score: 25,
        risk_factor: RiskFactor::ShellInjection,
        description: "Escaped ampersand",
    },
    InjectionPattern {
        name: "brace_expansion",
        detect_fn: |unquoted, _raw| {
            // Must contain {, at least one comma, and }
            if let Some(start) = unquoted.find('{') {
                if let Some(end) = unquoted[start..].find('}') {
                    return unquoted[start..start + end].contains(',');
                }
            }
            false
        },
        score: 20,
        risk_factor: RiskFactor::ShellInjection,
        description: "Brace expansion",
    },
    InjectionPattern {
        name: "proc_environ_access",
        detect_fn: |_unquoted, raw| {
            raw.contains("/proc/self/environ") || raw.contains("/proc/") && raw.contains("/environ")
        },
        score: 50,
        risk_factor: RiskFactor::SecretsExposure,
        description: "Process environment access",
    },
    InjectionPattern {
        name: "dev_tcp_udp",
        detect_fn: |_unquoted, raw| raw.contains("/dev/tcp/") || raw.contains("/dev/udp/"),
        score: 55,
        risk_factor: RiskFactor::NetworkExfiltration,
        description: "Bash /dev/tcp or /dev/udp network access",
    },
    InjectionPattern {
        name: "base64_pipe",
        detect_fn: |_unquoted, raw| {
            (raw.contains("base64") || raw.contains("b64"))
                && (raw.contains("|") || raw.contains(">"))
        },
        score: 30,
        risk_factor: RiskFactor::ObfuscatedCommand,
        description: "Base64 encoding in pipeline (potential obfuscation)",
    },
    InjectionPattern {
        name: "eval_usage",
        detect_fn: |unquoted, _raw| {
            unquoted.starts_with("eval ")
                || unquoted.contains(" eval ")
                || unquoted.starts_with("source ")
                || unquoted.contains(" source ")
        },
        score: 50,
        risk_factor: RiskFactor::CommandExecution,
        description: "eval/source command usage",
    },
    InjectionPattern {
        name: "dot_sourcing",
        detect_fn: |unquoted, _raw| {
            // Detect ". /path" (dot-sourcing) at start or in middle.
            // Must be followed by a space and then a path starting with /
            // to avoid false positives on relative paths like "./script".
            unquoted.starts_with(". /") || unquoted.contains(" . /")
        },
        score: 50,
        risk_factor: RiskFactor::CommandExecution,
        description: "Dot-sourcing a script (. /path)",
    },
    InjectionPattern {
        name: "hex_escape_sequences",
        // `$'\x41'` is covered by ansi_c_quoting; inside ordinary quotes
        // `\x`/`\u` are regex or printf escapes, not shell obfuscation.
        detect_fn: |unquoted, _raw| unquoted.contains("\\x") || unquoted.contains("\\u"),
        score: 35,
        risk_factor: RiskFactor::ObfuscatedCommand,
        description: "Hex/unicode escape sequences (obfuscation)",
    },
    InjectionPattern {
        name: "ld_preload",
        detect_fn: |_unquoted, raw| has_library_injection(raw),
        score: 55,
        risk_factor: RiskFactor::PathInjection,
        description:
            "Dynamic loader injection (LD_PRELOAD, DYLD_INSERT_LIBRARIES, non-system library paths)",
    },
    InjectionPattern {
        name: "path_injection",
        detect_fn: |_unquoted, raw| has_path_injection(raw),
        score: 50,
        risk_factor: RiskFactor::PathInjection,
        description: "PATH environment variable override",
    },
    InjectionPattern {
        name: "history_manipulation",
        detect_fn: |_unquoted, raw| {
            raw.contains("HISTFILE") || raw.contains(".bash_history") || raw.contains("HISTSIZE=0")
        },
        score: 40,
        risk_factor: RiskFactor::ShellInjection,
        description: "Shell history manipulation",
    },
    InjectionPattern {
        name: "null_byte",
        detect_fn: |_unquoted, raw| raw.bytes().any(|b| b == 0),
        score: 50,
        risk_factor: RiskFactor::ShellInjection,
        description: "Null byte injection",
    },
    InjectionPattern {
        name: "pipe_to_shell",
        // Matched as a whole word after the pipe: `| sh` but not `| shasum`,
        // `| node` but not `| nodemon`, and only outside quotes -- a
        // `'... | sh'` string argument pipes nothing.
        detect_fn: |unquoted, _raw| pipes_into_interpreter(unquoted),
        score: 55,
        risk_factor: RiskFactor::PipeToExecution,
        description: "Output piped to shell or interpreter execution",
    },
];

/// The parts of `raw` the shell actually interprets.
///
/// Single-quoted text, ANSI-C `$'...'` bodies and the bodies of quoted
/// heredocs (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) are literal: no expansion,
/// substitution or escape inside them does anything, so patterns such as
/// `$(`, `` ` ``, `{a,b}` or `\|` found there are not injection. They are
/// replaced by a single space. Double-quoted text is kept, because `$(...)`,
/// `${...}` and backticks still expand inside double quotes.
pub fn shell_active_text(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    let mut in_double = false;
    // A quoted heredoc delimiter seen on the current line; its body starts
    // on the next line.
    let mut pending_heredoc: Option<String> = None;

    while i < chars.len() {
        let c = chars[i];

        if in_double {
            // Inside double quotes only expansions are live. Everything else
            // -- including `\|`, `{a,b}` or `| sh` -- is literal text, so it
            // is blanked out and can't match the syntax patterns.
            match c {
                '"' => {
                    in_double = false;
                    out.push(c);
                    i += 1;
                }
                '\\' => {
                    // `\$`, `\``, `\"`, `\\` are escaped literals.
                    out.push_str("  ");
                    i += 2;
                }
                '$' => {
                    let end = expansion_end(&chars, i);
                    out.extend(&chars[i..end]);
                    i = end;
                }
                '`' => {
                    let mut end = i + 1;
                    while end < chars.len() && chars[end] != '`' {
                        if chars[end] == '\\' {
                            end += 1;
                        }
                        end += 1;
                    }
                    let end = (end + 1).min(chars.len());
                    out.extend(&chars[i..end]);
                    i = end;
                }
                _ => {
                    out.push(if c == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
            }
            continue;
        }

        if c == '\\' && i + 1 < chars.len() {
            out.push(c);
            out.push(chars[i + 1]);
            i += 2;
            continue;
        }

        match c {
            '\'' => {
                // Skip to the closing quote (no escapes inside single quotes).
                let ansi_c = i > 0 && chars[i - 1] == '$';
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    if ansi_c && chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                out.push(' ');
                i += 1;
            }
            '"' => {
                in_double = true;
                out.push(c);
                i += 1;
            }
            '<' if chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') => {
                out.push_str("<<");
                i += 2;
                if chars.get(i) == Some(&'-') {
                    out.push('-');
                    i += 1;
                }
                while chars.get(i) == Some(&' ') || chars.get(i) == Some(&'\t') {
                    out.push(chars[i]);
                    i += 1;
                }
                let quote = match chars.get(i) {
                    Some('\'') | Some('"') => Some(chars[i]),
                    Some('\\') => Some('\\'),
                    _ => None,
                };
                if let Some(q) = quote {
                    i += 1;
                    let mut delim = String::new();
                    while i < chars.len()
                        && !(q != '\\' && chars[i] == q)
                        && !chars[i].is_whitespace()
                    {
                        delim.push(chars[i]);
                        i += 1;
                    }
                    if q != '\\' && chars.get(i) == Some(&q) {
                        i += 1;
                    }
                    if !delim.is_empty() {
                        pending_heredoc = Some(delim);
                    }
                    out.push(' ');
                }
            }
            '\n' => {
                out.push(c);
                i += 1;
                if let Some(delim) = pending_heredoc.take() {
                    // Drop body lines up to and including the delimiter line.
                    loop {
                        let line_start = i;
                        while i < chars.len() && chars[i] != '\n' {
                            i += 1;
                        }
                        let line: String = chars[line_start..i].iter().collect();
                        if i < chars.len() {
                            i += 1; // the newline
                        }
                        if line.trim_start_matches('\t') == delim || i >= chars.len() {
                            break;
                        }
                    }
                    out.push('\n');
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }

    out
}

/// End index (exclusive) of the expansion starting at `chars[start] == '$'`:
/// `$(...)` / `$((...))` / `${...}` with nesting, or `$name` / `$1` / `$$`.
fn expansion_end(chars: &[char], start: usize) -> usize {
    let mut i = start + 1;
    match chars.get(i) {
        Some('(') | Some('{') => {
            let (open, close) = if chars[i] == '(' {
                ('(', ')')
            } else {
                ('{', '}')
            };
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == open {
                    depth += 1;
                } else if chars[i] == close {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                i += 1;
            }
            chars.len()
        }
        Some(ch) if ch.is_ascii_alphanumeric() || *ch == '_' => {
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            i
        }
        Some('$') | Some('?') | Some('!') | Some('#') | Some('@') | Some('*') | Some('-') => i + 1,
        _ => i,
    }
}

/// `$'...'` / `$"..."` used as a quoting construct in shell-active text.
pub fn has_ansi_c_quoting(raw: &str) -> bool {
    let chars: Vec<char> = raw.chars().collect();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_single {
            if c == '\'' {
                in_single = false;
            }
        } else if c == '\\' {
            i += 1;
        } else if c == '$'
            && !in_double
            && matches!(chars.get(i + 1), Some('\'') | Some('"'))
            && (i == 0 || chars[i - 1] != '$')
        {
            return true;
        } else if c == '\'' && !in_double {
            in_single = true;
        } else if c == '"' {
            in_double = !in_double;
        }
        i += 1;
    }
    false
}

fn has_obfuscating_parameter_expansion(text: &str) -> bool {
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return false;
        };
        let body = &after[..end];
        let name_len = body
            .char_indices()
            .find(|(idx, ch)| {
                !(ch.is_ascii_alphanumeric()
                    || *ch == '_'
                    || (*idx == 0 && (*ch == '#' || *ch == '@' || *ch == '*')))
            })
            .map(|(idx, _)| idx)
            .unwrap_or(body.len());
        let op = &body[name_len..];
        let obfuscating = body.starts_with('!')
            || op.starts_with('/')
            || op.starts_with('^')
            || op.starts_with(',')
            || op.starts_with('@')
            || (op.starts_with(':')
                && op[1..]
                    .trim_start()
                    .starts_with(|ch: char| ch.is_ascii_digit() || ch == '$' || ch == '('));
        if obfuscating {
            return true;
        }
        rest = &after[end..];
    }
    false
}

const PIPE_INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "fish", "ksh", "csh", "tcsh", "dash", "python", "python3", "python2",
    "perl", "ruby", "node", "nodejs",
];

fn pipes_into_interpreter(text: &str) -> bool {
    let lower = text.to_lowercase();
    let mut rest = lower.as_str();
    while let Some(pos) = rest.find('|') {
        let after = &rest[pos + 1..];
        // `||` is a logical OR, not a pipe.
        if let Some(stripped) = after.strip_prefix('|') {
            rest = stripped;
            continue;
        }
        let word: String = after
            .trim_start()
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '/' || *ch == '.' || *ch == '_')
            .collect();
        let base = word.rsplit('/').next().unwrap_or(&word);
        if PIPE_INTERPRETERS.contains(&base) {
            return true;
        }
        rest = after;
    }
    false
}

/// `NAME=value` assignments appearing as words in `raw` (prefix
/// assignments, `export NAME=value`, bare statements). The name must be the
/// whole identifier, so `DYLD_FALLBACK_LIBRARY_PATH=` is not `PATH=` and
/// `MANPATH=` is not either.
fn assignments(raw: &str) -> Vec<(String, String)> {
    raw.split(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '|' || c == '(')
        .filter_map(|word| {
            let (name, value) = word.split_once('=')?;
            let valid = !name.is_empty()
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            valid.then(|| {
                (
                    name.to_string(),
                    value.trim_matches(['\'', '"']).to_string(),
                )
            })
        })
        .collect()
}

const SYSTEM_LIBRARY_DIRS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/local/lib",
    "/System/",
    "/Library/",
    "/opt/homebrew/lib",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
];

fn is_system_dir(entry: &str) -> bool {
    entry.is_empty()
        || entry.starts_with('$')
        || SYSTEM_LIBRARY_DIRS
            .iter()
            .any(|d| entry == d.trim_end_matches('/') || entry.starts_with(d))
}

fn has_library_injection(raw: &str) -> bool {
    assignments(raw)
        .iter()
        .any(|(name, value)| match name.as_str() {
            // Force-load arbitrary code into every process that starts.
            "LD_PRELOAD" | "DYLD_INSERT_LIBRARIES" | "LD_AUDIT" => !value.is_empty(),
            // Search paths: only a concern when they point somewhere non-system.
            "LD_LIBRARY_PATH"
            | "DYLD_LIBRARY_PATH"
            | "DYLD_FALLBACK_LIBRARY_PATH"
            | "DYLD_FRAMEWORK_PATH"
            | "DYLD_FALLBACK_FRAMEWORK_PATH" => value.split(':').any(|entry| !is_system_dir(entry)),
            _ => false,
        })
}

fn has_path_injection(raw: &str) -> bool {
    assignments(raw).iter().any(|(name, value)| {
        if name != "PATH" {
            return false;
        }
        // Replacing PATH outright, or putting a world-writable / relative
        // directory ahead of the real one, lets a planted binary shadow a
        // system command. Prepending `$HOME/bin` or `/usr/local/bin` does not.
        if !value.contains("$PATH") && !value.contains("${PATH}") {
            return true;
        }
        value
            .split(':')
            .take_while(|e| *e != "$PATH" && *e != "${PATH}")
            .any(|entry| {
                entry.starts_with("/tmp")
                    || entry.starts_with("/var/tmp")
                    || entry.starts_with("/dev/shm")
                    || entry == "."
                    || entry.starts_with("./")
                    || (!entry.starts_with('/')
                        && !entry.starts_with('$')
                        && !entry.starts_with('~'))
            })
    })
}

/// Check `raw` against all injection patterns, deriving the shell-active
/// text itself. Prefer this over `detect_injections`.
pub fn detect_injections_in(raw: &str) -> Vec<(&'static str, u8, RiskFactor, &'static str)> {
    detect_injections(&shell_active_text(raw), raw)
}

/// Check a command against all injection patterns.
/// Returns list of (pattern_name, score, risk_factor, description) for matches.
pub fn detect_injections(
    unquoted: &str,
    raw: &str,
) -> Vec<(&'static str, u8, RiskFactor, &'static str)> {
    INJECTION_PATTERNS
        .iter()
        .filter(|p| (p.detect_fn)(unquoted, raw))
        .map(|p| (p.name, p.score, p.risk_factor, p.description))
        .collect()
}
