//! `xargs` payload-aware classification.
//!
//! `xargs` is a wrapper, not an operation: it builds and runs a command
//! line from its input. The generic `CommandRule` model scored every
//! invocation as `Intent::Execute` (weight 50) with no flag analysis, so
//! `xargs echo` and `xargs rm -rf` were both DANGER 60, and -- because
//! `pipeline::classify_sink` treats any `Intent::Execute` segment as an
//! execution sink -- any `... | xargs <anything>` was CRITICAL "data piped
//! to shell execution", including routine `find ... | xargs ls`.
//!
//! This module instead splits xargs' own options from the payload command
//! and classifies the payload with the same machinery used for `find
//! -exec`/`fd -x` (`rules::find_fd::classify_payload`), letting the
//! payload's intent lead: `xargs ls` is a listing, `xargs rm -rf` is a
//! recursive delete, `xargs sh -c '...'` is code execution (and so still a
//! pipeline execution sink), and an unrecognized payload stays
//! conservatively `Intent::Execute`.
//!
//! xargs' own risk-relevant behavior is folded in as flags: running the
//! payload once per input line (the default) applies it to every match,
//! and `-P` runs those in parallel.

use super::cli_args::flag;
use super::find_fd;
use crate::types::{FlagAnalysis, Intent, Reversibility, RiskFactor};

/// Result of classifying an `xargs` invocation.
pub struct XargsClassification {
    pub intent: Vec<Intent>,
    pub reversibility: Reversibility,
    pub flags: Vec<FlagAnalysis>,
}

/// xargs options that consume the following token as their value.
const OPTS_WITH_VALUE: &[&str] = &[
    "-a",
    "--arg-file",
    "-d",
    "--delimiter",
    "-E",
    "-I",
    "--replace",
    "-L",
    "--max-lines",
    "-n",
    "--max-args",
    "-P",
    "--max-procs",
    "-s",
    "--max-chars",
    "--process-slot-var",
];

/// xargs options that take no value.
const OPTS_NO_VALUE: &[&str] = &[
    "-0",
    "--null",
    "-o",
    "--open-tty",
    "-p",
    "--interactive",
    "-r",
    "--no-run-if-empty",
    "-t",
    "--verbose",
    "-x",
    "--exit",
    "--show-limits",
    "--help",
    "--version",
];

/// Split xargs' own options from the payload command's argv.
///
/// The payload is everything from the first non-option token onwards --
/// xargs has no `--`-style terminator, and once the command name is seen
/// every remaining token belongs to it (`xargs rm -rf` passes `-rf` to
/// `rm`, not to xargs). Fused forms (`-n1`, `-P8`, `-I{}`, `-d,`) are
/// handled, as are `--opt=value` spellings.
fn split_payload(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut own = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let a = args[i].as_str();

        if a == "--" {
            own.push(args[i].clone());
            i += 1;
            continue;
        }
        if !a.starts_with('-') || a == "-" {
            return (own, args[i..].to_vec());
        }
        if OPTS_WITH_VALUE.contains(&a) {
            own.push(args[i].clone());
            if i + 1 < args.len() {
                own.push(args[i + 1].clone());
            }
            i += 2;
            continue;
        }
        if OPTS_WITH_VALUE
            .iter()
            .any(|o| a.starts_with(&format!("{}=", o)))
            || OPTS_NO_VALUE.contains(&a)
        {
            own.push(args[i].clone());
            i += 1;
            continue;
        }
        // Fused short option with its value attached (`-n1`, `-I{}`, ...),
        // or any other option-looking token: xargs' own either way, since
        // the payload cannot start with a `-`.
        own.push(args[i].clone());
        i += 1;
    }

    (own, vec![])
}

fn has_own_flag(own: &[String], short: char, long: &str) -> bool {
    own.iter().any(|a| {
        a == &format!("-{short}")
            || a == long
            || a.starts_with(&format!("{long}="))
            // fused short form with an attached value: -n1, -P8, -I{}
            || (a.starts_with('-')
                && !a.starts_with("--")
                && a.len() > 2
                && a[1..2].starts_with(short))
    })
}

/// Classify an `xargs ...` invocation given its arguments (everything after
/// the `xargs`/`/usr/bin/xargs` executable token, tokenized/quote-aware).
pub fn classify(args: &[String]) -> XargsClassification {
    let (own, payload) = split_payload(args);

    // With no command given, xargs runs `echo`.
    let payload_result = if payload.is_empty() {
        find_fd::classify_payload(&["echo".to_string()])
    } else {
        find_fd::classify_payload(&payload)
    };

    // A deleting payload is applied to every input line, which is much
    // closer to `find ... -delete` than to a single `rm <file>` -- price
    // the batching accordingly.
    let batches_a_deletion = payload_result.intent.first() == Some(&Intent::Delete);
    let mut flags = vec![flag(
        if batches_a_deletion { 20 } else { 10 },
        RiskFactor::CommandExecution,
        "xargs",
        "Builds and runs a command line from its input, once per batch of arguments",
    )];

    if has_own_flag(&own, 'P', "--max-procs") {
        flags.push(flag(
            5,
            RiskFactor::CommandExecution,
            "xargs -P",
            "Runs the command in parallel across multiple processes",
        ));
    }

    flags.extend(payload_result.flags);

    let mut intent = payload_result.intent;
    if intent.is_empty() {
        intent.push(Intent::Execute);
    }

    XargsClassification {
        intent,
        reversibility: payload_result.reversibility,
        flags,
    }
}
