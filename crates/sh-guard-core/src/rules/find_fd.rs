//! `find`/`fd`(`fdfind`) payload-aware classification.
//!
//! Both tools are searches by default (`Intent::Search`, low weight) but can
//! run an arbitrary command for every match: find's `-exec`/`-execdir`/
//! `-ok`/`-okdir` and fd's `-x`/`-X`/`--exec`/`--exec-batch`. The generic
//! `CommandRule` model previously flagged those as a flat modifier
//! regardless of payload, so `-exec echo {} \;` and `-exec rm -rf {} \;`
//! scored the same. This module instead:
//!
//! 1. Extracts the payload argv for each `-exec`/`-execdir`/`-ok`/`-okdir`
//!    clause (find) or the `-x`/`-X`/`--exec`/`--exec-batch` invocation
//!    (fd), terminated by a bare `+`, a (possibly shell-escaped) `;`, or end
//!    of arguments.
//! 2. Classifies that payload's own head command the same way the rest of
//!    sh-guard would -- via `git`/`gh`'s subcommand-aware classifiers or a
//!    plain `CommandRule` lookup -- and folds the result in (worst
//!    reversibility, union of intents/flags), so `find -exec rm -rf {} +`
//!    inherits `rm -rf`'s destructiveness and `fd -x git push --force`
//!    inherits git's dangerous-flag handling.
//! 3. Adds find's non-`-exec` actions that matter for risk: `-delete`
//!    (recursive delete; scope amplification already comes for free via
//!    the target extracted from find's search root), and the `-fprintf`/
//!    `-fprint`/`-fprint0`/`-fls` family (writes find's output to an
//!    arbitrary file).
//! 4. Adds small scope-widening modifiers for fd's `-u`/`--unrestricted`,
//!    `-H`/`--hidden`, `-I`/`--no-ignore`, and both tools' symlink-following
//!    options.
//!
//! Everything not covered here (plain reads: `-name`, `-print`, `-type`,
//! fd's `-e`/`--extension`, `--max-depth`, ...) stays at the baseline
//! `Intent::Search` -- these tools are still safe reads with no escalating
//! action present.

use super::cli_args;
use crate::rules;
use crate::types::{FlagAnalysis, Intent, Reversibility, RiskFactor};

/// Result of classifying a `find`/`fd` invocation.
pub struct FindFdClassification {
    pub intent: Vec<Intent>,
    pub reversibility: Reversibility,
    pub flags: Vec<FlagAnalysis>,
}

impl FindFdClassification {
    fn simple(intent: Intent, reversibility: Reversibility) -> Self {
        FindFdClassification {
            intent: vec![intent],
            reversibility,
            flags: vec![],
        }
    }
}

use cli_args::flag;

pub(crate) fn worse(a: Reversibility, b: Reversibility) -> Reversibility {
    use Reversibility::*;
    match (a, b) {
        (Irreversible, _) | (_, Irreversible) => Irreversible,
        (HardToReverse, _) | (_, HardToReverse) => HardToReverse,
        _ => Reversible,
    }
}

pub(crate) fn strip_quotes(s: &str) -> String {
    s.trim_matches(['\'', '"']).to_string()
}

// ========================================================
// Shared: payload argv extraction + classification
// ========================================================

/// Scan `rest` (the tokens following an `-exec`/`-execdir`/`-ok`/`-okdir`/
/// `-x`/`-X`/`--exec`/`--exec-batch` marker) for the payload command's argv,
/// terminated by a bare `+`, a `;` (escaped as `\;` by the shell, or --
/// defensively -- a literal unescaped `;` token), or end of input. Returns
/// the payload tokens and how many tokens of `rest` were consumed
/// (including the terminator, if any), so the caller can resume scanning
/// find's own primaries after a `+`/`;`-terminated `-exec` clause.
pub(crate) fn extract_payload(rest: &[String]) -> (Vec<String>, usize) {
    for (idx, tok) in rest.iter().enumerate() {
        if matches!(tok.as_str(), "+" | ";" | "\\;") {
            return (rest[..idx].to_vec(), idx + 1);
        }
    }
    (rest.to_vec(), rest.len())
}

/// The result of classifying a payload command's argv -- shared with
/// `rules::kubectl`, which reuses this payload machinery for `kubectl exec
/// ... -- <cmd>` / `run ... -- <cmd>` / `debug ... -- <cmd>` rather than
/// duplicating it.
pub(crate) struct PayloadResult {
    pub(crate) intent: Vec<Intent>,
    pub(crate) reversibility: Reversibility,
    pub(crate) flags: Vec<FlagAnalysis>,
}

/// Classify a payload command's argv (e.g. `["rm", "-rf", "{}"]`) using the
/// same machinery the rest of sh-guard uses for a top-level command:
/// git/gh's subcommand-aware classifiers, or a plain `CommandRule` lookup
/// (whose `dangerous_flags` are matched the same way `analyzer::flag_matches`
/// matches them for a real top-level invocation). Quotes are trimmed off
/// the head token before it's used as a command name -- the tokenizer
/// preserves them (e.g. `-exec 'rm' -rf {} \;` yields `"'rm'"`), but a
/// quoted token is never itself a flag/subcommand name.
///
/// An unknown payload command defaults to `Intent::Execute` /
/// `HardToReverse`, mirroring `analyzer::analyze_segment`'s conservative
/// default for an unrecognized top-level executable.
pub(crate) fn classify_payload(tokens: &[String]) -> PayloadResult {
    let Some(head_raw) = tokens.first() else {
        return PayloadResult {
            intent: vec![Intent::Execute],
            reversibility: Reversibility::HardToReverse,
            flags: vec![],
        };
    };
    let head = strip_quotes(head_raw);
    let head_base = head.rsplit('/').next().unwrap_or(&head).to_string();
    let sub_args = &tokens[1..];

    // `env bash --version`, `xargs php -l`: the payload only describes
    // itself or syntax-checks a file, exactly as at the top level.
    let probe_eligible = rules::lookup_command(&head_base)
        .is_none_or(|r| r.intent == Intent::Execute)
        && rules::classify_special(Some(&head_base), &[], &[]).is_none();
    if probe_eligible
        && (crate::analyzer::is_info_probe(sub_args)
            || crate::analyzer::is_syntax_check(Some(&head_base), sub_args))
    {
        return PayloadResult {
            intent: vec![Intent::Info],
            reversibility: Reversibility::Reversible,
            flags: vec![],
        };
    }

    // Route through the same dispatch `analyzer` uses, so a payload that
    // is itself a subcommand-aware tool (git, gh, kubectl, find/fd, xargs)
    // gets its real classification rather than its coarse `CommandRule`
    // fallback -- `-x kubectl delete namespace prod` must inherit what
    // `kubectl delete namespace prod` would score on its own.
    if let Some(special) = rules::classify_special(Some(&head_base), sub_args, &[]) {
        return PayloadResult {
            intent: special.intent,
            reversibility: special.reversibility,
            flags: special.flags,
        };
    }

    if rules::lookup_command(&head_base).is_none() {
        if let Some(custom) = crate::custom_rules::active_command(&head_base) {
            let (intent, reversibility, flags) = crate::custom_rules::resolve(&custom, sub_args);
            return PayloadResult {
                intent: vec![intent],
                reversibility,
                flags,
            };
        }
    }

    match rules::lookup_command(&head_base) {
        Some(rule) => {
            let mut flags = vec![];
            for flag_rule in rule.dangerous_flags {
                if crate::analyzer::flag_matches(&tokens.join(" "), flag_rule) {
                    flags.push(FlagAnalysis {
                        flag: flag_rule.flags[0].to_string(),
                        modifier: flag_rule.modifier,
                        risk_factor: flag_rule.risk_factor,
                        description: flag_rule.description.to_string(),
                    });
                }
            }
            PayloadResult {
                intent: vec![rule.intent],
                reversibility: rule.reversibility,
                flags,
            }
        }
        None => PayloadResult {
            intent: vec![Intent::Execute],
            reversibility: Reversibility::HardToReverse,
            flags: vec![],
        },
    }
}

/// Fold a payload's classification into the running find/fd classification.
///
/// The payload's own intents lead, so the invocation scores (and reads) as
/// what it actually does: `-exec rm -rf {} +` is a deletion, `-exec ls {} +`
/// is still a listing, and only an unrecognized payload falls back to
/// `Intent::Execute`. Scoring the wrapper itself as `Intent::Execute`
/// (weight 50) regardless of payload would floor every `-exec`/`-x` at
/// DANGER and leave `-exec ls` indistinguishable from `-exec rm`.
/// Reversibility takes the worst of the two, and a wrapper-level
/// `CommandExecution` flag is added alongside whatever flags the payload's
/// own classification produced (e.g. `rm -rf`'s `RecursiveDelete`,
/// `git push --force`'s `GitHistoryDestruction`).
fn fold_exec_payload(
    result: &mut FindFdClassification,
    label: &str,
    description: &str,
    wrapper_modifier: i8,
    payload: &[String],
) {
    let payload_result = classify_payload(payload);

    result
        .intent
        .retain(|i| !matches!(i, Intent::Info | Intent::Search));
    for i in &payload_result.intent {
        if !result.intent.contains(i) {
            result.intent.push(*i);
        }
    }
    if result.intent.is_empty() {
        result.intent.push(Intent::Execute);
    }

    result.reversibility = worse(result.reversibility, payload_result.reversibility);

    result.flags.push(flag(
        wrapper_modifier,
        RiskFactor::CommandExecution,
        label,
        description,
    ));
    result.flags.extend(payload_result.flags);
}

fn escalate_delete(result: &mut FindFdClassification) {
    result
        .intent
        .retain(|i| !matches!(i, Intent::Info | Intent::Search));
    if !result.intent.contains(&Intent::Delete) {
        result.intent.insert(0, Intent::Delete);
    }
    result.reversibility = worse(result.reversibility, Reversibility::Irreversible);
    result.flags.push(flag(
        25,
        RiskFactor::RecursiveDelete,
        "-delete",
        "Deletes every matched file; the search root's scope (/, ~, /etc, ...) further amplifies this",
    ));
}

fn escalate_write(result: &mut FindFdClassification, label: &str, description: &str) {
    result
        .intent
        .retain(|i| !matches!(i, Intent::Info | Intent::Search));
    if !result.intent.contains(&Intent::Write) {
        result.intent.insert(0, Intent::Write);
    }
    result.reversibility = worse(result.reversibility, Reversibility::HardToReverse);
    result
        .flags
        .push(flag(10, RiskFactor::Write, label, description));
}

fn add_modifier_once(
    result: &mut FindFdClassification,
    modifier: i8,
    risk_factor: RiskFactor,
    label: &str,
    description: &str,
) {
    if result.flags.iter().any(|f| f.flag == label) {
        return;
    }
    result
        .flags
        .push(flag(modifier, risk_factor, label, description));
}

// ========================================================
// find
// ========================================================

/// find primaries that consume exactly one following token as a value
/// (never a new primary/action) -- so e.g. `find . -name -delete` doesn't
/// mistake `-delete`'s literal name for the actual `-delete` action, and
/// `find . -name "-exec"` doesn't mistake a quoted pattern for `-exec`.
/// Not exhaustive of every GNU find primary, but covers the ones whose
/// value could otherwise be misread as an action/flag.
const FIND_VALUE_FLAGS_1: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-regex",
    "-iregex",
    "-lname",
    "-ilname",
    "-wholename",
    "-iwholename",
    "-perm",
    "-user",
    "-uid",
    "-group",
    "-gid",
    "-size",
    "-newer",
    "-anewer",
    "-cnewer",
    "-mtime",
    "-atime",
    "-ctime",
    "-mmin",
    "-amin",
    "-cmin",
    "-maxdepth",
    "-mindepth",
    "-type",
    "-fstype",
    "-inum",
    "-links",
    "-samefile",
    "-context",
    "-printf",
];

/// Classify a `find ...` invocation given its arguments (everything after
/// the `find`/`/usr/bin/find` executable token, tokenized/quote-aware).
pub fn classify_find(args: &[String]) -> FindFdClassification {
    let mut result = FindFdClassification::simple(Intent::Search, Reversibility::Reversible);

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();

        match a {
            "-exec" | "-execdir" | "-ok" | "-okdir" => {
                let (payload, consumed) = extract_payload(&args[i + 1..]);
                let (label, description) = match a {
                    "-exec" => (
                        "-exec",
                        "Executes a command for each matched file (or once with all matches, for -exec ... +)",
                    ),
                    "-execdir" => (
                        "-execdir",
                        "Executes a command in the directory of each matched file",
                    ),
                    "-ok" => (
                        "-ok",
                        "Prompts before executing a command for each matched file, but still runs an arbitrary command",
                    ),
                    _ => (
                        "-okdir",
                        "Prompts before executing a command in the directory of each matched file, but still runs an arbitrary command",
                    ),
                };
                // 15 keeps a read-only payload (`-exec cat {} +` -> Read 10)
                // inside the safe band while leaving destructive payloads
                // dominated by their own intent/flags; -ok/-okdir prompt
                // first, so they sit one notch lower still.
                let modifier = if a == "-ok" || a == "-okdir" { 10 } else { 15 };
                fold_exec_payload(&mut result, label, description, modifier, &payload);
                i += 1 + consumed;
                continue;
            }
            "-delete" => {
                escalate_delete(&mut result);
                i += 1;
                continue;
            }
            "-fprintf" => {
                escalate_write(
                    &mut result,
                    "-fprintf",
                    "Writes find's output (in a custom format) to an arbitrary file instead of stdout",
                );
                i += 3; // flag + file + format
                continue;
            }
            "-fprint" => {
                escalate_write(
                    &mut result,
                    "-fprint",
                    "Writes find's output to an arbitrary file instead of stdout",
                );
                i += 2; // flag + file
                continue;
            }
            "-fprint0" => {
                escalate_write(
                    &mut result,
                    "-fprint0",
                    "Writes find's output (NUL-separated) to an arbitrary file instead of stdout",
                );
                i += 2; // flag + file
                continue;
            }
            "-fls" => {
                escalate_write(
                    &mut result,
                    "-fls",
                    "Writes an `ls -l`-style listing of matches to an arbitrary file instead of stdout",
                );
                i += 2; // flag + file
                continue;
            }
            "-L" | "-H" | "-follow" => {
                add_modifier_once(
                    &mut result,
                    5,
                    RiskFactor::BroadScope,
                    "-L/-H/-follow",
                    "Follows symbolic links while searching, which can widen the effective scope",
                );
                i += 1;
                continue;
            }
            _ => {}
        }

        if FIND_VALUE_FLAGS_1.contains(&a) {
            i += 2; // skip the primary and the value it consumes
            continue;
        }
        // `-newerXY <ref>` (X, Y each one of a/B/c/t): one value.
        if a.starts_with("-newer") && a.len() > "-newer".len() {
            i += 2;
            continue;
        }

        i += 1;
    }

    result
}

// ========================================================
// fd / fdfind
// ========================================================

/// fd flags that consume exactly one following token as a value. Used both
/// to avoid misreading a value as `-x`/`-X` (defensively -- those are
/// matched as exact tokens anyway, so this mainly matters for
/// `fd_target_paths`' positional scan) and to keep this list in one place.
const FD_VALUE_FLAGS: &[&str] = &[
    "-e",
    "--extension",
    "-E",
    "--exclude",
    "-d",
    "--max-depth",
    "--min-depth",
    "--exact-depth",
    "-j",
    "--threads",
    "-t",
    "--type",
    "--ignore-file",
    "--format",
    "--path-separator",
    "-S",
    "--size",
    "--changed-within",
    "--changed-before",
    "-c",
    "--color",
    "--max-results",
    "-o",
    "--owner",
];

const FD_PATH_VALUE_FLAGS: &[&str] = &["--search-path", "--base-directory"];

/// fd's `-x`/`--exec` and `-X`/`--exec-batch` consume ALL following
/// positional args as the command template -- there's no mandatory
/// terminator (unlike find, which always needs `;`/`+`). `\;` is optional
/// and only needed when more fd flags/options follow on the same command
/// line (e.g. `fd -x echo {} \; -e rs`), in which case scanning resumes
/// after it. `-x`/`--exec` runs the command once per result (like find's
/// `-exec ... \;`); `-X`/`--exec-batch` runs it once with all results
/// appended (like find's `-exec ... +`).
///
/// Splits `args` into fd's own flag/positional tokens (`own`, with every
/// exec clause's tokens removed) and the list of exec clauses found
/// (`(action, payload)` pairs, in order -- fd allows more than one just
/// like find does).
struct FdSplit {
    own: Vec<String>,
    execs: Vec<(String, Vec<String>)>,
}

fn fd_split(args: &[String]) -> FdSplit {
    let mut own = Vec::new();
    let mut execs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if matches!(a, "-x" | "-X" | "--exec" | "--exec-batch") {
            let (payload, consumed) = extract_payload(&args[i + 1..]);
            execs.push((a.to_string(), payload));
            i += 1 + consumed;
            continue;
        }
        own.push(args[i].clone());
        i += 1;
    }
    FdSplit { own, execs }
}

/// Classify a `fd`/`fdfind ...` invocation given its arguments.
pub fn classify_fd(args: &[String]) -> FindFdClassification {
    let mut result = FindFdClassification::simple(Intent::Search, Reversibility::Reversible);

    // fd's own flags can appear before an exec clause, after a `\;`-
    // terminated one, or both -- `fd_split` strips every exec clause's own
    // tokens (including any payload arguments, e.g. a `-H` flag meant for
    // the payload command, not fd) out of `own` first, so this scan can't
    // misread them as fd's.
    let split = fd_split(args);
    let pre = &split.own;

    if cli_args::has_flag(pre, Some('u'), &["unrestricted"], false) {
        add_modifier_once(
            &mut result,
            10,
            RiskFactor::BroadScope,
            "-u/--unrestricted",
            "Includes ignored and hidden files/directories in the search",
        );
    } else {
        if cli_args::has_flag(pre, Some('H'), &["hidden"], false) {
            add_modifier_once(
                &mut result,
                5,
                RiskFactor::BroadScope,
                "-H/--hidden",
                "Includes hidden files/directories in the search",
            );
        }
        // `cli_args::has_flag`'s long-option matching treats any
        // `--no-<name>` as an explicit negation and never a match (so it
        // doesn't mistake e.g. `--no-force` for `--force`) -- but
        // `--no-ignore` is fd's real flag name, not a negation of some
        // `--ignore`. Check the short form via `has_flag` and the long
        // form via an exact-token match instead.
        if cli_args::has_flag(pre, Some('I'), &[], false) || cli_args::has_exact(pre, "--no-ignore")
        {
            add_modifier_once(
                &mut result,
                5,
                RiskFactor::BroadScope,
                "-I/--no-ignore",
                "Includes files/directories normally excluded by .gitignore in the search",
            );
        }
    }
    if cli_args::has_flag(pre, Some('L'), &["follow"], false) {
        add_modifier_once(
            &mut result,
            5,
            RiskFactor::BroadScope,
            "-L/--follow",
            "Follows symbolic links while searching, which can widen the effective scope",
        );
    }

    for (action, payload) in &split.execs {
        let (label, description, modifier) = match action.as_str() {
            "-x" | "--exec" => (
                "fd -x/--exec",
                "Executes a command for each search result",
                15,
            ),
            _ => (
                "fd -X/--exec-batch",
                "Executes a command once with all search results as arguments",
                15,
            ),
        };
        fold_exec_payload(&mut result, label, description, modifier, payload);
    }

    result
}

/// Path targets for a `fd`/`fdfind` invocation. Unlike `find`, where every
/// positional argument is a path, fd's grammar is
/// `fd [FLAGS/OPTIONS] [<pattern>] [<path>...]` -- the first positional is
/// a search *pattern*, not a path (`fd ~/.ssh` searches the current
/// directory for files matching the pattern `~/.ssh`; `fd x ~/.ssh` has the
/// path second). Heuristic: skip the first effective positional
/// unconditionally (treat it as the pattern), then take the rest, plus any
/// `--search-path`/`--base-directory` values (which are always paths
/// regardless of position). Tokens making up an `-x`/`-X`/`--exec`/
/// `--exec-batch` payload are excluded -- they're the payload's own argv,
/// not fd's positionals.
pub fn fd_target_paths(args: &[String]) -> Vec<String> {
    let split = fd_split(args);
    let scanned = &split.own;

    let mut explicit_paths = Vec::new();
    let mut i = 0;
    while i < scanned.len() {
        let a = scanned[i].as_str();
        if FD_PATH_VALUE_FLAGS.contains(&a) {
            if let Some(v) = scanned.get(i + 1) {
                explicit_paths.push(strip_quotes(v));
            }
            i += 2;
            continue;
        }
        if let Some(v) = FD_PATH_VALUE_FLAGS
            .iter()
            .find_map(|f| a.strip_prefix(&format!("{}=", f)))
        {
            explicit_paths.push(strip_quotes(v));
            i += 1;
            continue;
        }
        i += 1;
    }

    let mut all_value_flags: Vec<&str> = FD_VALUE_FLAGS.to_vec();
    all_value_flags.extend_from_slice(FD_PATH_VALUE_FLAGS);
    let positionals = cli_args::effective_positionals(scanned, &all_value_flags);
    let path_positionals = positionals.into_iter().skip(1).map(|p| strip_quotes(&p));

    explicit_paths.into_iter().chain(path_positionals).collect()
}
