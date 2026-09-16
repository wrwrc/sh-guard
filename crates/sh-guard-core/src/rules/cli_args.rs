//! Shared helpers for subcommand-aware CLI classifiers (`rules::git`,
//! `rules::gh`): matching already-tokenized, quote-aware arguments against
//! flag names, and separating "real" positionals from the values consumed
//! by options that take one.
//!
//! Kept separate from any one classifier because the logic (and the bugs
//! it guards against -- an option's own value being mistaken for a
//! positional/verb, or a flag rule matching noise) is identical across
//! tools; only the *vocabulary* of flags/verbs differs.

use crate::types::{FlagAnalysis, RiskFactor};

/// Build a `FlagAnalysis`.
pub fn flag(modifier: i8, risk_factor: RiskFactor, flag: &str, description: &str) -> FlagAnalysis {
    FlagAnalysis {
        flag: flag.to_string(),
        modifier,
        risk_factor,
        description: description.to_string(),
    }
}

/// True if `args` contains a long option (`--foo`, `--foo=value`, or --
/// when `allow_prefix` is set -- an unambiguous prefix like `--fo`) whose
/// name is in `longs`, or a short option cluster (`-x`, `-fdx`, ...)
/// containing `short`.
///
/// `allow_prefix` should be `true` for tools that support unambiguous
/// long-option-prefix abbreviation (git) and `false` for tools that don't
/// (gh's Cobra-based CLI rejects abbreviated long options outright, so
/// treating a prefix as a match there would both over- and under-flag).
/// `--no-<name>` is always treated as an explicit negation, never a match.
pub fn has_flag(args: &[String], short: Option<char>, longs: &[&str], allow_prefix: bool) -> bool {
    args.iter()
        .any(|a| flag_token_matches(a, short, longs, allow_prefix))
}

fn flag_token_matches(a: &str, short: Option<char>, longs: &[&str], allow_prefix: bool) -> bool {
    if let Some(name) = a.strip_prefix("--") {
        let name = name.split('=').next().unwrap_or(name);
        if name.starts_with("no-") {
            return false;
        }
        if longs.contains(&name) {
            return true;
        }
        if allow_prefix && name.len() >= 3 {
            return longs.iter().any(|l| l.starts_with(name));
        }
        false
    } else if let Some(cluster) = a.strip_prefix('-') {
        match short {
            Some(c) => {
                !cluster.is_empty()
                    && !cluster.starts_with('-')
                    && cluster.chars().all(|ch| ch.is_ascii_alphabetic())
                    && cluster.contains(c)
            }
            None => false,
        }
    } else {
        false
    }
}

/// Exact token equality (e.g. matching a literal `-D`/`--all` token).
pub fn has_exact(args: &[String], token: &str) -> bool {
    args.iter().any(|a| a == token)
}

/// Count of non-flag (doesn't start with `-`) tokens, with no
/// value-consumption awareness. Prefer `effective_positionals` when any
/// flag in scope takes a separate-token value.
pub fn positional_count(args: &[String]) -> usize {
    args.iter().filter(|a| !a.starts_with('-')).count()
}

/// Positional (non-flag) args, with the values consumed by any of
/// `value_flags` (options that take a following, separate-token value --
/// e.g. `-b <branch>`, `-R <owner/repo>`, `--title <text>`) excluded. Used
/// so an option's own argument doesn't get mistaken for a target/verb when
/// counting or inspecting "real" positionals.
pub fn effective_positionals(args: &[String], value_flags: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if value_flags.contains(&a.as_str()) {
            i += 2; // skip the flag and the value it consumes
            continue;
        }
        if value_flags
            .iter()
            .any(|f| a.starts_with(&format!("{}=", f)))
        {
            i += 1; // fused `--flag=value` form: no separate token consumed
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    out
}
