//! GitHub CLI (`gh`) subcommand-aware classification.
//!
//! Mirrors `rules::git`: `gh` is not one operation either -- `gh pr list`
//! is a read, `gh repo delete owner/repo --yes` deletes a GitHub
//! repository outright. Without this module every `gh` invocation falls
//! through to the unknown-command default (`Intent::Execute`, DANGER),
//! scoring `gh pr list` the same as `gh repo delete --yes`.
//!
//! Structure:
//! 1. Skip `gh`'s persistent/global options (`-R/--repo`, `--hostname`,
//!    `--help`, `--version`) to find the real command group (`pr`, `repo`,
//!    `issue`, ...), then normalize built-in group *and* verb aliases
//!    (`gh ext` == `gh extension`, `gh pr ls` == `gh pr list`, `gh pr co`
//!    == `gh pr checkout`, ...) before dispatch, all verified against the
//!    installed `gh` CLI's own `--help` output and hidden aliases.
//! 2. Locate the verb as the first positional token *after* skipping
//!    `-R`/`--repo` (which gh accepts both before and after the verb --
//!    `gh pr -R o/r merge 1 --admin` is valid) -- never `args.first()` --
//!    so a flag's own value (`-R owner/delete`, `--title delete`) can
//!    never be mistaken for a verb, and a leading `-R` between group and
//!    verb never eats a flag that comes after it.
//! 3. Classify group + verb into an intent/reversibility, using the
//!    verb's own arguments where useful (`gh pr merge --admin`, `gh cache
//!    delete --all`, `gh api -X DELETE ...`).
//! 4. Unlike git, gh's CLI (Cobra) does NOT support abbreviated long
//!    options, so flag matching here never does prefix matching --
//!    `cli_args::has_flag(..., false)`.
//! 5. Inspects `NAME=value` prefix assignments for `GH_TOKEN`-like env
//!    vars (secret material inline on the command line) and
//!    `GH_PAGER`/`PAGER`/`GH_BROWSER`/`BROWSER`/`GH_EDITOR`/`EDITOR`/
//!    `VISUAL` (arbitrary command execution via an external program gh
//!    shells out to).
//! 6. Commands that shell out to a local `git` (`repo clone`, `repo fork
//!    --clone`, `gist clone`, `pr checkout`) reuse `rules::git`'s own
//!    `GIT_*` env and dangerous-config-key detection rather than
//!    duplicating it, since a malicious `-c`/`--config`/`--template` after
//!    `--` or a `GIT_*` env var rides along on the `gh` invocation exactly
//!    as it would on a bare `git` one.

use super::cli_args::{effective_positionals, flag, has_exact};
use crate::rules::git as git_rules;
use crate::types::{FlagAnalysis, Intent, Reversibility, RiskFactor};

/// Result of classifying a `gh ...` invocation.
pub struct GhClassification {
    pub intent: Vec<Intent>,
    pub reversibility: Reversibility,
    pub flags: Vec<FlagAnalysis>,
}

impl GhClassification {
    fn simple(intent: Intent, reversibility: Reversibility) -> Self {
        GhClassification {
            intent: vec![intent],
            reversibility,
            flags: vec![],
        }
    }

    fn with_flag(intent: Intent, reversibility: Reversibility, f: FlagAnalysis) -> Self {
        GhClassification {
            intent: vec![intent],
            reversibility,
            flags: vec![f],
        }
    }
}

/// Cobra long-option matching: exact name (or `--name=value`) only, never
/// a prefix -- `gh` rejects abbreviated long options.
fn has_flag(args: &[String], short: Option<char>, longs: &[&str]) -> bool {
    super::cli_args::has_flag(args, short, longs, false)
}

/// `gh`'s own persistent global options that take a separate-token value,
/// recognized only *before* the group (i.e. before we know which verb
/// vocabulary applies).
const GLOBAL_OPTS_WITH_VALUE: &[&str] = &["-R", "--repo", "--hostname"];
/// `gh`'s own persistent global options that take no value.
const GLOBAL_OPTS_NO_VALUE: &[&str] = &["--help", "-h", "--version"];

/// `-R`/`--repo` is gh's one flag that's commonly seen *between* the group
/// and the verb too (`gh pr -R o/r merge 1`), so verb-location has to skip
/// it wherever it appears, not just before the group.
const LEADING_VALUE_FLAGS: &[&str] = &["-R", "--repo"];

/// `GH_*`/generic env vars whose *value*, when assigned inline
/// (`GH_TOKEN=ghp_xxx gh ...`), is itself sensitive token material typed
/// in plaintext on the command line (and so lands in shell history/process
/// listings).
fn is_token_env(name: &str) -> bool {
    matches!(name, "GH_TOKEN" | "GITHUB_TOKEN" | "GH_ENTERPRISE_TOKEN")
}

/// Env vars that make gh shell out to an arbitrary attacker-controlled
/// program (a pager, browser, or editor).
fn is_dangerous_gh_env(name: &str) -> bool {
    matches!(
        name,
        "GH_PAGER" | "PAGER" | "GH_BROWSER" | "BROWSER" | "GH_EDITOR" | "EDITOR" | "VISUAL"
    )
}

/// Classify a `gh ...` invocation given its arguments (everything after
/// the `gh`/`/opt/homebrew/bin/gh` executable token, tokenized/quote-aware)
/// and any `NAME=value` prefix assignments attached to the same command.
pub fn classify(args: &[String], env_assignments: &[(String, String)]) -> GhClassification {
    let global_rest = scan_global_options(args);

    let (mut result, group, verb, group_rest) = match global_rest.split_first() {
        None => (
            GhClassification::simple(Intent::Info, Reversibility::Reversible),
            String::new(),
            None,
            Vec::new(),
        ),
        Some((raw_group, group_args)) => {
            let group = normalize_group(raw_group).to_string();
            // `api`'s first positional is the endpoint (or `graphql`), not
            // a verb -- `verb_and_rest` would otherwise mistake it for one
            // and strip it out from under `classify_api`.
            if group == "api" {
                let classification = classify_api(group_args);
                (classification, group, None, group_args.to_vec())
            } else {
                let (raw_verb, rest) = verb_and_rest(group_args);
                let verb = raw_verb.map(|v| normalize_verb(&group, &v));
                let classification = dispatch_group(&group, verb.as_deref(), &rest);
                (classification, group, verb, rest)
            }
        }
    };

    // Commands that shell out to a local `git` inherit git's own
    // command-execution surface.
    if forwards_raw_git_flags(&group, verb.as_deref(), &group_rest) {
        if let Some(reason) = git_clone_tail_danger(&group_rest) {
            escalate_to_execute(&mut result, &reason);
        }
    }
    if shells_out_to_local_git(&group, verb.as_deref(), &group_rest) {
        if let Some(name) = env_assignments
            .iter()
            .find(|(name, _)| git_rules::is_dangerous_git_env(name))
            .map(|(name, _)| name.clone())
        {
            escalate_to_execute(
                &mut result,
                &format!(
                    "environment variable {} can make the underlying git invocation run an arbitrary command",
                    name
                ),
            );
        }
    }

    if let Some(name) = env_assignments
        .iter()
        .find(|(name, _)| is_token_env(name))
        .map(|(name, _)| name.clone())
    {
        add_secrets_exposure(
            &mut result,
            &format!(
                "environment variable {} carries an auth token inline on the command line",
                name
            ),
        );
    }

    if let Some(name) = env_assignments
        .iter()
        .find(|(name, _)| is_dangerous_gh_env(name))
        .map(|(name, _)| name.clone())
    {
        escalate_to_execute(
            &mut result,
            &format!(
                "environment variable {} can make gh run an arbitrary command",
                name
            ),
        );
    }

    result
}

/// Bump a classification to reflect that it can run an arbitrary command:
/// puts `Intent::Execute` first (dropping `Intent::Info`) and raises
/// reversibility to at least `HardToReverse`. Mirrors
/// `rules::git::escalate_to_execute` -- Execute goes first specifically so
/// `scorer::generate_reason` (which reads `intent.first()`) reports "Code
/// execution" rather than e.g. "Information command".
fn escalate_to_execute(result: &mut GhClassification, reason: &str) {
    result
        .intent
        .retain(|i| *i != Intent::Info && *i != Intent::Execute);
    result.intent.insert(0, Intent::Execute);
    if result.reversibility == Reversibility::Reversible {
        result.reversibility = Reversibility::HardToReverse;
    }
    result.flags.push(flag(
        35,
        RiskFactor::CommandExecution,
        "dangerous gh/git env or flag",
        reason,
    ));
}

/// Bump a classification for inline secret material. Doesn't change the
/// intent to Execute (an inline token doesn't grant execution, it just
/// leaks a credential into shell history/process listings) -- but a bare
/// `Intent::Info` is promoted to `Intent::Read` so `scorer::generate_reason`
/// doesn't report "Information command" for something that just leaked a
/// token.
fn add_secrets_exposure(result: &mut GhClassification, reason: &str) {
    if result.intent.first() == Some(&Intent::Info) {
        result.intent[0] = Intent::Read;
    }
    if result.reversibility == Reversibility::Reversible {
        result.reversibility = Reversibility::HardToReverse;
    }
    result.flags.push(flag(
        50,
        RiskFactor::SecretsExposure,
        "token env var inline",
        reason,
    ));
}

// ========================================================
// Alias normalization
// ========================================================

/// Built-in group aliases, confirmed against `gh <group> --help`'s
/// ALIASES section on gh 2.100.0.
fn normalize_group(raw: &str) -> &str {
    match raw {
        "ext" | "extensions" => "extension",
        "cs" => "codespace",
        "rs" => "ruleset",
        "at" => "attestation",
        "agent" | "agents" | "agent-tasks" => "agent-task",
        other => other,
    }
}

/// Groups where `ls` is a hidden alias for `list` (confirmed functionally:
/// `gh <group> ls --help` succeeds and matches `list`'s help text).
const LS_ALIAS_GROUPS: &[&str] = &[
    "codespace",
    "gist",
    "issue",
    "org",
    "pr",
    "project",
    "release",
    "repo",
    "cache",
    "run",
    "workflow",
    "alias",
    "config",
    "extension",
    "gpg-key",
    "label",
    "ruleset",
    "secret",
    "ssh-key",
    "variable",
];
/// Groups where `new` is a hidden alias for `create`.
const NEW_ALIAS_GROUPS: &[&str] = &["gist", "issue", "pr", "release", "repo"];

/// Built-in verb aliases, scoped to the (already-normalized) group they
/// apply to.
fn normalize_verb(group: &str, verb: &str) -> String {
    if verb == "ls" && LS_ALIAS_GROUPS.contains(&group) {
        return "list".to_string();
    }
    if verb == "new" && NEW_ALIAS_GROUPS.contains(&group) {
        return "create".to_string();
    }
    if group == "pr" && verb == "co" {
        return "checkout".to_string();
    }
    if (group == "secret" || group == "variable") && verb == "remove" {
        return "delete".to_string();
    }
    if group == "extension" && verb == "uninstall" {
        return "remove".to_string();
    }
    verb.to_string()
}

// ========================================================
// Global option parsing / verb location
// ========================================================

fn scan_global_options(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut in_globals = true;

    while i < args.len() {
        let a = &args[i];

        if !in_globals {
            out.push(a.clone());
            i += 1;
            continue;
        }

        if GLOBAL_OPTS_WITH_VALUE.contains(&a.as_str()) {
            i += 2;
            continue;
        }
        if GLOBAL_OPTS_WITH_VALUE
            .iter()
            .any(|o| a.starts_with(&format!("{}=", o)))
        {
            i += 1;
            continue;
        }
        if GLOBAL_OPTS_NO_VALUE.contains(&a.as_str()) {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            // Unrecognized global-looking option: don't mistake it for
            // the group.
            i += 1;
            continue;
        }

        in_globals = false;
        out.push(a.clone());
        i += 1;
    }

    out
}

/// Locate the verb (first positional token), skipping `-R`/`--repo` (with
/// its value) wherever it appears before the verb, and defensively
/// skipping any other leading flag-looking token (assumed to take no
/// value -- `-R`/`--repo` is the only documented pre-verb value flag).
/// Returns the verb and the remaining arguments with *only* the verb
/// token itself removed (everything else, including a leading `-R
/// <value>`, is preserved so downstream flag-matching still sees it).
fn verb_and_rest(args: &[String]) -> (Option<String>, Vec<String>) {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if LEADING_VALUE_FLAGS.contains(&a.as_str()) {
            i += 2;
            continue;
        }
        if LEADING_VALUE_FLAGS
            .iter()
            .any(|f| a.starts_with(&format!("{}=", f)))
        {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }

    if i >= args.len() {
        return (None, args.to_vec());
    }
    let verb = args[i].clone();
    let mut rest = args.to_vec();
    rest.remove(i);
    (Some(verb), rest)
}

/// A middling default for a recognized group but an unrecognized verb: we
/// know the surface area (it's not an arbitrary extension), but not
/// precisely what this verb does, so don't assume it's safe.
fn unknown_verb_fallback() -> GhClassification {
    GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
}

// ========================================================
// git shell-out detection (repo clone, repo fork --clone, gist clone,
// pr checkout)
// ========================================================

/// True for gh subcommands that support `-- <gitflags>` forwarded
/// straight to a local `git clone` invocation.
fn forwards_raw_git_flags(group: &str, verb: Option<&str>, rest: &[String]) -> bool {
    match (group, verb) {
        ("repo", Some("clone")) => true,
        ("gist", Some("clone")) => true,
        ("repo", Some("fork")) => fork_will_clone(rest),
        _ => false,
    }
}

/// `gh repo fork` only clones locally when `--clone` is given (and not
/// explicitly disabled with `--clone=false`).
fn fork_will_clone(rest: &[String]) -> bool {
    has_flag(rest, None, &["clone"]) && !rest.iter().any(|a| a == "--clone=false")
}

/// True for gh subcommands that invoke a local `git` at all (a superset of
/// `forwards_raw_git_flags`: `pr checkout` shells out to `git fetch`/`git
/// checkout` but doesn't expose a `-- <gitflags>` passthrough).
fn shells_out_to_local_git(group: &str, verb: Option<&str>, rest: &[String]) -> bool {
    forwards_raw_git_flags(group, verb, rest) || (group == "pr" && verb == Some("checkout"))
}

/// Scan the `-- <gitflags>` tail (if any) of a `gh repo clone`/`gh repo
/// fork`/`gh gist clone` invocation for a dangerous `-c`/`--config` key or
/// a `--template=<dir>`, both of which let the resulting local `git clone`
/// run an arbitrary command. Returns the escalation reason, if any.
fn git_clone_tail_danger(rest: &[String]) -> Option<String> {
    let sep = rest.iter().position(|a| a == "--")?;
    let tail = &rest[sep + 1..];
    let mut i = 0;
    while i < tail.len() {
        let a = &tail[i];

        if a == "--template" || a.starts_with("--template=") {
            return Some(
                "git clone --template=<dir> copies that directory's hooks into the new repo, \
                 running them on future git operations"
                    .to_string(),
            );
        }

        let key_value: Option<String> = if a == "-c" || a == "--config" {
            let v = tail.get(i + 1).cloned();
            i += 2;
            v
        } else if let Some(v) = a.strip_prefix("--config=") {
            i += 1;
            Some(v.to_string())
        } else if !a.starts_with("--") {
            let fused = a.strip_prefix("-c").filter(|v| !v.is_empty());
            i += 1;
            fused.map(|v| v.to_string())
        } else {
            i += 1;
            None
        };

        if let Some(kv) = key_value {
            let key = kv.split('=').next().unwrap_or(&kv);
            if git_rules::is_dangerous_config_key(key) {
                return Some(format!(
                    "git clone -c/--config sets '{}', which can run an arbitrary command or change git's trust boundary",
                    key
                ));
            }
        }
    }
    None
}

// ========================================================
// Group dispatch
// ========================================================

fn dispatch_group(group: &str, verb: Option<&str>, rest: &[String]) -> GhClassification {
    match group {
        "auth" => classify_auth(verb, rest),
        "browse" => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        "codespace" => classify_codespace(verb, rest),
        "gist" => classify_gist(verb),
        "issue" => classify_issue(verb),
        "org" => classify_read_only_group(verb, &["list"]),
        "pr" => classify_pr(verb, rest),
        "project" => classify_project(verb),
        "release" => classify_release(verb),
        "repo" => classify_repo(verb, rest),
        "cache" => classify_cache(verb, rest),
        "run" => classify_run(verb),
        "workflow" => classify_workflow(verb),
        "alias" => classify_alias(verb, rest),
        "api" => classify_api(rest),
        "attestation" => classify_attestation(verb),
        "completion" => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        "config" => classify_config(verb, rest),
        "extension" => classify_extension(verb),
        "gpg-key" => classify_key_store(verb),
        "label" => classify_label(verb),
        "preview" => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        "ruleset" => classify_ruleset(verb),
        "search" => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        "secret" => classify_secret_or_variable(verb, rest, true),
        "ssh-key" => classify_key_store(verb),
        "status" => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        "variable" => classify_secret_or_variable(verb, rest, false),
        "copilot" => classify_copilot(verb),
        "agent-task" => classify_agent_task(verb),

        // Unknown top-level group: could be a `gh <extension>` (an
        // installed extension binary) or a user alias expanding to
        // anything, including a shell command. Conservative default,
        // matching today's (pre-classification) behavior for all of `gh`.
        _ => GhClassification::simple(Intent::Execute, Reversibility::HardToReverse),
    }
}

fn classify_read_only_group(verb: Option<&str>, read_verbs: &[&str]) -> GhClassification {
    match verb {
        None => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        Some(v) if read_verbs.contains(&v) => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// auth
// ========================================================

fn classify_auth(verb: Option<&str>, rest: &[String]) -> GhClassification {
    match verb {
        None => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("status") => {
            let show_token = has_flag(rest, Some('t'), &["show-token"]);
            if show_token {
                GhClassification::with_flag(
                    Intent::Read,
                    Reversibility::HardToReverse,
                    flag(
                        50,
                        RiskFactor::SecretsExposure,
                        "auth status --show-token/-t",
                        "Prints the active auth token to stdout",
                    ),
                )
            } else {
                GhClassification::simple(Intent::Info, Reversibility::Reversible)
            }
        }
        Some("token") => GhClassification::with_flag(
            Intent::Read,
            Reversibility::HardToReverse,
            flag(
                50,
                RiskFactor::SecretsExposure,
                "auth token",
                "Prints the active auth token to stdout",
            ),
        ),
        Some("login") | Some("refresh") | Some("setup-git") | Some("switch") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
        }
        // Trivially reversible (log in again); no data is destroyed.
        Some("logout") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// codespace
// ========================================================

fn classify_codespace(verb: Option<&str>, rest: &[String]) -> GhClassification {
    match verb {
        None | Some("list") | Some("view") | Some("logs") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("create") | Some("edit") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        Some("stop") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        Some("rebuild") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
        }
        Some("delete") => {
            let all = has_flag(rest, None, &["all"]);
            if all {
                GhClassification::with_flag(
                    Intent::Delete,
                    Reversibility::Irreversible,
                    flag(
                        15,
                        RiskFactor::ForceFlag,
                        "codespace delete --all",
                        "Deletes every codespace without per-item confirmation",
                    ),
                )
            } else {
                GhClassification::simple(Intent::Delete, Reversibility::Irreversible)
            }
        }
        // ssh/cp/code/jupyter open an interactive shell / copy files /
        // launch an editor or notebook session inside the codespace --
        // runs arbitrary commands.
        Some("ssh") | Some("cp") | Some("code") | Some("jupyter") => GhClassification::with_flag(
            Intent::Execute,
            Reversibility::HardToReverse,
            flag(
                30,
                RiskFactor::CommandExecution,
                "codespace ssh/cp/code/jupyter",
                "Opens a shell/session or transfers files to and from a remote codespace",
            ),
        ),
        Some("ports") => classify_codespace_ports(rest),
        _ => unknown_verb_fallback(),
    }
}

fn classify_codespace_ports(rest: &[String]) -> GhClassification {
    let (verb, rest) = verb_and_rest(rest);
    match verb.as_deref() {
        None => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("forward") => GhClassification::simple(Intent::Network, Reversibility::Reversible),
        Some("visibility") => GhClassification::with_flag(
            Intent::EnvModify,
            Reversibility::HardToReverse,
            flag(
                15,
                RiskFactor::BroadScope,
                "codespace ports visibility",
                "Changes a forwarded port's visibility, which can expose it publicly",
            ),
        ),
        _ => {
            let _ = rest;
            unknown_verb_fallback()
        }
    }
}

// ========================================================
// gist
// ========================================================

fn classify_gist(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("list") | Some("view") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("create") | Some("edit") | Some("rename") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        Some("delete") => GhClassification::simple(Intent::Delete, Reversibility::Irreversible),
        // Runs `git clone` under the hood, writing to local disk. Any
        // `-- <gitflags>`/`GIT_*` env escalation is applied by the
        // top-level `classify()`.
        Some("clone") => GhClassification {
            intent: vec![Intent::Execute, Intent::Write],
            reversibility: Reversibility::Reversible,
            flags: vec![],
        },
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// issue
// ========================================================

fn classify_issue(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("list") | Some("view") | Some("status") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("create") | Some("comment") | Some("edit") | Some("reopen") | Some("pin")
        | Some("unpin") | Some("develop") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        Some("close") | Some("lock") | Some("unlock") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
        }
        Some("transfer") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Irreversible)
        }
        Some("delete") => GhClassification::simple(Intent::Delete, Reversibility::Irreversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// pr
// ========================================================

fn classify_pr(verb: Option<&str>, rest: &[String]) -> GhClassification {
    match verb {
        None | Some("list") | Some("view") | Some("diff") | Some("checks") | Some("status") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("create") | Some("comment") | Some("edit") | Some("review") | Some("ready")
        | Some("reopen") | Some("revert") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        Some("close") | Some("lock") | Some("unlock") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
        }
        // Fetches and checks out the PR's branch locally: local git
        // mutation plus network. Any `GIT_*` env escalation for the
        // underlying git invocation is applied by the top-level
        // `classify()`.
        Some("checkout") => GhClassification {
            intent: vec![Intent::GitMutation, Intent::Network],
            reversibility: Reversibility::Reversible,
            flags: vec![],
        },
        Some("merge") => classify_pr_merge(rest),
        Some("update-branch") => classify_pr_update_branch(rest),
        _ => unknown_verb_fallback(),
    }
}

fn classify_pr_merge(args: &[String]) -> GhClassification {
    let mut flags = vec![];
    // --admin bypasses branch protection / required reviews entirely.
    if has_flag(args, None, &["admin"]) {
        flags.push(flag(
            25,
            RiskFactor::PrivilegeEscalation,
            "pr merge --admin",
            "Bypasses branch protection and required reviews to force the merge",
        ));
    }
    if has_flag(args, None, &["delete-branch"]) {
        flags.push(flag(
            10,
            RiskFactor::GitHistoryDestruction,
            "pr merge --delete-branch",
            "Deletes the source branch after merging",
        ));
    }
    GhClassification {
        intent: vec![Intent::EnvModify],
        reversibility: Reversibility::HardToReverse,
        flags,
    }
}

fn classify_pr_update_branch(args: &[String]) -> GhClassification {
    // Default behavior merges the base branch in (non-destructive);
    // --rebase rewrites the PR branch's own commit history instead (the
    // server-side equivalent of a force push).
    if has_flag(args, None, &["rebase"]) {
        GhClassification::with_flag(
            Intent::EnvModify,
            Reversibility::HardToReverse,
            flag(
                15,
                RiskFactor::GitHistoryDestruction,
                "pr update-branch --rebase",
                "Rebases the PR branch, rewriting its commit history",
            ),
        )
    } else {
        GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
    }
}

// ========================================================
// project
// ========================================================

fn classify_project(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("list") | Some("view") | Some("field-list") | Some("item-list") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("delete") | Some("field-delete") | Some("item-delete") => {
            GhClassification::simple(Intent::Delete, Reversibility::Irreversible)
        }
        Some("close")
        | Some("copy")
        | Some("create")
        | Some("edit")
        | Some("field-create")
        | Some("item-add")
        | Some("item-archive")
        | Some("item-create")
        | Some("item-edit")
        | Some("link")
        | Some("mark-template")
        | Some("unlink") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// release
// ========================================================

fn classify_release(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("view") | Some("list") | Some("verify") | Some("verify-asset") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        // Writes files to local disk but doesn't mutate anything remotely.
        Some("download") => GhClassification::simple(Intent::Write, Reversibility::Reversible),
        Some("create") | Some("edit") | Some("upload") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        Some("delete") | Some("delete-asset") => {
            GhClassification::simple(Intent::Delete, Reversibility::Irreversible)
        }
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// repo
// ========================================================

fn classify_repo(verb: Option<&str>, rest: &[String]) -> GhClassification {
    match verb {
        None | Some("view") | Some("list") | Some("read-file") | Some("read-dir")
        | Some("gitignore") | Some("license") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("autolink") => classify_repo_autolink(rest),
        Some("create") | Some("set-default") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        // Undoes an archive -- a plain config write.
        Some("unarchive") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        Some("fork") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        Some("sync") => classify_repo_sync(rest),
        Some("deploy-key") => classify_repo_deploy_key(rest),
        // Runs `git clone`: network + writes to local disk. Any
        // `-- <gitflags>`/`GIT_*` env escalation is applied by the
        // top-level `classify()`.
        Some("clone") => GhClassification {
            intent: vec![Intent::Execute, Intent::Network, Intent::Write],
            reversibility: Reversibility::Reversible,
            flags: vec![],
        },
        Some("delete") => classify_repo_delete(rest),
        Some("archive") => GhClassification::with_flag(
            Intent::EnvModify,
            Reversibility::HardToReverse,
            flag(
                15,
                RiskFactor::GitHistoryDestruction,
                "repo archive",
                "Archives the repository, making it read-only",
            ),
        ),
        Some("rename") => GhClassification::with_flag(
            Intent::EnvModify,
            Reversibility::HardToReverse,
            flag(
                10,
                RiskFactor::GitHistoryDestruction,
                "repo rename",
                "Renames the repository; old clone URLs stop resolving",
            ),
        ),
        Some("edit") => classify_repo_edit(rest),
        _ => unknown_verb_fallback(),
    }
}

fn classify_repo_autolink(rest: &[String]) -> GhClassification {
    let (verb, _rest) = verb_and_rest(rest);
    match verb.as_deref() {
        None | Some("list") | Some("view") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("create") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        Some("delete") => GhClassification::simple(Intent::Delete, Reversibility::Irreversible),
        _ => unknown_verb_fallback(),
    }
}

fn classify_repo_sync(args: &[String]) -> GhClassification {
    // `--force` hard-resets the destination branch to match the source,
    // discarding any commits that only exist on the destination.
    if has_flag(args, None, &["force"]) {
        GhClassification::with_flag(
            Intent::EnvModify,
            Reversibility::HardToReverse,
            flag(
                15,
                RiskFactor::GitHistoryDestruction,
                "repo sync --force",
                "Hard-resets the destination branch to match the source, discarding any commits only on the destination",
            ),
        )
    } else {
        GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
    }
}

fn classify_repo_delete(args: &[String]) -> GhClassification {
    let mut flags = vec![flag(
        20,
        RiskFactor::GitHistoryDestruction,
        "repo delete",
        "Permanently deletes the GitHub repository, including all history, issues and PRs",
    )];
    if has_flag(args, Some('y'), &["yes", "confirm"]) {
        flags.push(flag(
            15,
            RiskFactor::ForceFlag,
            "repo delete --yes",
            "Skips the interactive confirmation prompt, enabling silent/scripted deletion",
        ));
    }
    GhClassification {
        intent: vec![Intent::Delete],
        reversibility: Reversibility::Irreversible,
        flags,
    }
}

fn classify_repo_edit(args: &[String]) -> GhClassification {
    // `--visibility public|internal|private`: changing to a more open
    // visibility can expose previously private code/history publicly.
    // Erring toward flagging any explicit --visibility change, mirroring
    // git's philosophy of flagging plausibly-dangerous options.
    let visibility_change = args
        .iter()
        .any(|a| a == "--visibility" || a.starts_with("--visibility="));
    if visibility_change {
        GhClassification::with_flag(
            Intent::EnvModify,
            Reversibility::HardToReverse,
            flag(
                25,
                RiskFactor::SecretsExposure,
                "repo edit --visibility",
                "Changes repository visibility, which can expose private code/history publicly",
            ),
        )
    } else {
        GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
    }
}

fn classify_repo_deploy_key(rest: &[String]) -> GhClassification {
    let (verb, _rest) = verb_and_rest(rest);
    match verb.as_deref() {
        None | Some("list") => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("add") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        Some("delete") => GhClassification::simple(Intent::Delete, Reversibility::Irreversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// cache
// ========================================================

fn classify_cache(verb: Option<&str>, rest: &[String]) -> GhClassification {
    match verb {
        None | Some("list") => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("delete") => {
            let all = has_flag(rest, None, &["all"]) || has_exact(rest, "--all");
            if all {
                GhClassification::with_flag(
                    Intent::Delete,
                    Reversibility::Irreversible,
                    flag(
                        15,
                        RiskFactor::ForceFlag,
                        "cache delete --all",
                        "Deletes every Actions cache for the repository",
                    ),
                )
            } else {
                GhClassification::simple(Intent::Delete, Reversibility::Irreversible)
            }
        }
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// run
// ========================================================

fn classify_run(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("list") | Some("view") | Some("watch") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        // Writes the run's log/artifacts to local disk.
        Some("download") => GhClassification::simple(Intent::Write, Reversibility::Reversible),
        Some("rerun") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        Some("cancel") => GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse),
        Some("delete") => GhClassification::simple(Intent::Delete, Reversibility::Irreversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// workflow
// ========================================================

fn classify_workflow(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("list") | Some("view") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        // Triggers a workflow_dispatch run: causes CI-defined code to
        // execute on GitHub's infrastructure. Not local code execution,
        // but still meaningfully more than a config change.
        Some("run") => GhClassification::simple(Intent::Network, Reversibility::HardToReverse),
        Some("enable") | Some("disable") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// alias
// ========================================================

fn classify_alias(verb: Option<&str>, rest: &[String]) -> GhClassification {
    match verb {
        None | Some("list") => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("set") => classify_alias_set(rest),
        Some("delete") | Some("clear") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        // `import` can bring in shell-expansion (`!...`) aliases too;
        // without parsing the imported file's contents, treat plain
        // import as a moderate config write.
        Some("import") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        _ => unknown_verb_fallback(),
    }
}

fn classify_alias_set(args: &[String]) -> GhClassification {
    // `--shell`/`-s` marks the expansion as a shell command; an expansion
    // literally starting with `!` is gh's own shorthand for the same
    // thing. Either way, invoking the alias later runs an arbitrary shell
    // command.
    let shell_flag = has_flag(args, Some('s'), &["shell"]);
    // The tokenizer preserves surrounding quote characters verbatim (they
    // aren't shell-stripped here), so trim a matching pair before checking
    // for the leading `!` -- `gh alias set co '!git checkout'` is the
    // common real-world form.
    let bang_expansion = effective_positionals(args, &["--shell"])
        .iter()
        .any(|p| p.trim_matches(['\'', '"']).starts_with('!'));
    if shell_flag || bang_expansion {
        GhClassification::with_flag(
            Intent::Execute,
            Reversibility::HardToReverse,
            flag(
                30,
                RiskFactor::CommandExecution,
                "alias set --shell / '!' expansion",
                "Defines an alias that runs an arbitrary shell command when invoked",
            ),
        )
    } else {
        GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
    }
}

// ========================================================
// api
// ========================================================

/// HTTP method `gh api` will use, resolved from `-X`/`--method` (any
/// casing, `-X DELETE`, `-XDELETE`, `--method=delete` all accepted) or,
/// absent that, implied POST from any of the field-setting flags, else the
/// default GET.
#[derive(Debug, PartialEq, Eq)]
enum ApiMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Other,
}

fn parse_api_method(args: &[String]) -> ApiMethod {
    let mut explicit: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "-X" || a == "--method" {
            if let Some(v) = args.get(i + 1) {
                explicit = Some(v.clone());
            }
            i += 2;
            continue;
        }
        if let Some(v) = a.strip_prefix("--method=") {
            explicit = Some(v.to_string());
            i += 1;
            continue;
        }
        // Fused short form: `-XDELETE`.
        if let Some(v) = a.strip_prefix("-X") {
            if !v.is_empty() {
                explicit = Some(v.to_string());
            }
            i += 1;
            continue;
        }
        i += 1;
    }

    if let Some(m) = explicit {
        return match m.to_ascii_uppercase().as_str() {
            "GET" | "HEAD" => ApiMethod::Get,
            "POST" => ApiMethod::Post,
            "PUT" => ApiMethod::Put,
            "PATCH" => ApiMethod::Patch,
            "DELETE" => ApiMethod::Delete,
            _ => ApiMethod::Other,
        };
    }

    // No explicit method: any field-setting flag implies POST (gh's own
    // default behavior); otherwise it's a plain GET.
    let implies_post = has_flag(args, Some('f'), &["field"])
        || has_flag(args, Some('F'), &["raw-field"])
        || has_flag(args, None, &["input"]);
    if implies_post {
        ApiMethod::Post
    } else {
        ApiMethod::Get
    }
}

/// Flags that consume a separate-token value, so their value doesn't get
/// mistaken for the endpoint positional. Confirmed against `gh api --help`
/// on gh 2.100.0.
const API_VALUE_FLAGS: &[&str] = &[
    "-X",
    "--method",
    "-f",
    "--field",
    "-F",
    "--raw-field",
    "--input",
    "-H",
    "--header",
    "--hostname",
    "--cache",
    "-t",
    "--template",
    "-p",
    "--preview",
    "-q",
    "--jq",
];

/// Strip leading/trailing slashes and any query string, so
/// `repos/o/r/`, `/repos/o/r`, and `repos/o/r?foo=bar` all normalize to
/// the same `repos/o/r`.
fn normalize_endpoint(raw: &str) -> String {
    // The tokenizer preserves surrounding quote characters verbatim, so
    // trim a matching pair before normalizing slashes/query string.
    let e = raw.trim_matches(['\'', '"']);
    let e = e.trim_matches('/');
    e.split('?').next().unwrap_or(e).to_string()
}

/// Endpoint paths whose mutation is especially dangerous: repo/org
/// deletion, secrets/variables, webhooks, collaborator/membership/team/
/// permission changes, branch protection and rulesets, deploy/SSH/GPG
/// keys, deployments, Pages, and repo transfer.
fn is_sensitive_endpoint(endpoint: &str) -> bool {
    let e = endpoint;

    // repos/:owner/:repo (exactly, no further path segments) is the
    // repo-deletion endpoint under DELETE.
    if e.starts_with("repos/") && e.matches('/').count() == 2 {
        return true;
    }
    // orgs/:org (exactly) is the org-deletion endpoint under DELETE.
    if e.starts_with("orgs/") && e.matches('/').count() == 1 {
        return true;
    }
    if e.contains("/branches/") && e.contains("/protection") {
        return true;
    }

    const SENSITIVE_SUBSTRINGS: &[&str] = &[
        // Covers `/actions/secrets`, `/environments/*/secrets`, and
        // `orgs/*/actions/secrets` alike.
        "/secrets",
        "/actions/variables",
        "/actions/permissions",
        "/hooks",
        "/collaborators",
        "/rulesets",
        "/keys",
        "/members",
        "/memberships",
        "/teams",
        "/permissions",
        "/deployments",
        "/pages",
        "/transfer",
        "user/emails",
        "user/ssh_signing_keys",
        "user/gpg_keys",
    ];
    SENSITIVE_SUBSTRINGS.iter().any(|s| e.contains(s))
}

fn classify_api(rest: &[String]) -> GhClassification {
    let endpoint_raw = effective_positionals(rest, API_VALUE_FLAGS)
        .into_iter()
        .next()
        .unwrap_or_default();

    if endpoint_raw == "graphql" {
        return classify_api_graphql(rest);
    }

    let endpoint = normalize_endpoint(&endpoint_raw);
    let method = parse_api_method(rest);
    let sensitive = is_sensitive_endpoint(&endpoint);

    match method {
        ApiMethod::Get => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        ApiMethod::Post | ApiMethod::Patch | ApiMethod::Put => {
            if sensitive {
                GhClassification::with_flag(
                    Intent::EnvModify,
                    Reversibility::Irreversible,
                    flag(
                        20,
                        RiskFactor::PrivilegeEscalation,
                        "api POST/PUT/PATCH on sensitive endpoint",
                        "Writes to a sensitive REST endpoint (secrets/hooks/collaborators/branch protection/...)",
                    ),
                )
            } else {
                GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
            }
        }
        ApiMethod::Delete => {
            if sensitive {
                GhClassification::with_flag(
                    Intent::Delete,
                    Reversibility::Irreversible,
                    flag(
                        25,
                        RiskFactor::GitHistoryDestruction,
                        "api DELETE on sensitive endpoint",
                        "Deletes via a sensitive REST endpoint (e.g. the repo/org itself, a webhook, a collaborator)",
                    ),
                )
            } else {
                GhClassification::simple(Intent::Delete, Reversibility::Irreversible)
            }
        }
        ApiMethod::Other => {
            GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
        }
    }
}

/// Find the value passed for `key=...` via `-f`/`-F`/`--field`/
/// `--raw-field`, in either separate-token (`-f key=value`) or fused
/// (`-fkey=value`, `--field=key=value`) form. Surrounding quote
/// characters (the tokenizer doesn't strip them) are trimmed.
fn extract_field(args: &[String], key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if matches!(a.as_str(), "-f" | "-F" | "--field" | "--raw-field") {
            if let Some(v) = args.get(i + 1) {
                if let Some(rest) = v.strip_prefix(prefix.as_str()) {
                    return Some(rest.trim_matches(['\'', '"']).to_string());
                }
            }
            i += 2;
            continue;
        }
        if let Some(v) = a
            .strip_prefix("--field=")
            .or_else(|| a.strip_prefix("--raw-field="))
        {
            if let Some(rest) = v.strip_prefix(prefix.as_str()) {
                return Some(rest.trim_matches(['\'', '"']).to_string());
            }
            i += 1;
            continue;
        }
        if !a.starts_with("--") {
            if let Some(v) = a.strip_prefix("-f").or_else(|| a.strip_prefix("-F")) {
                if let Some(rest) = v.strip_prefix(prefix.as_str()) {
                    return Some(rest.trim_matches(['\'', '"']).to_string());
                }
            }
        }
        i += 1;
    }
    None
}

fn classify_api_graphql(args: &[String]) -> GhClassification {
    match extract_field(args, "query") {
        // No `query=...` field found at all (e.g. `--input file.graphql`):
        // unknown content, treat conservatively as a possible mutation.
        None => GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse),
        // `query=@file`/`query=@-`: content read from a file/stdin, not
        // visible to us -- same conservative treatment as `--input`.
        Some(v) if v.starts_with('@') => {
            GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
        }
        Some(v) => {
            // Look for a standalone `mutation` token anywhere in the
            // document (not just as a literal prefix), so leading
            // GraphQL comments (`# ...`) or whitespace before the
            // operation keyword don't hide it.
            let has_mutation_token = v
                .split(|c: char| !c.is_alphanumeric())
                .any(|tok| tok.eq_ignore_ascii_case("mutation"));
            if has_mutation_token {
                GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
            } else {
                GhClassification::simple(Intent::Info, Reversibility::Reversible)
            }
        }
    }
}

// ========================================================
// attestation
// ========================================================

fn classify_attestation(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("verify") | Some("trusted-root") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        // Writes attestation bundles to local disk.
        Some("download") => GhClassification::simple(Intent::Write, Reversibility::Reversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// config
// ========================================================

fn classify_config(verb: Option<&str>, rest: &[String]) -> GhClassification {
    match verb {
        None | Some("get") | Some("list") | Some("clear-cache") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("set") => classify_config_set(rest),
        _ => unknown_verb_fallback(),
    }
}

fn classify_config_set(args: &[String]) -> GhClassification {
    // The key is the first positional after skipping `-h/--host <value>`,
    // which `gh config set` accepts before or after the key/value pair.
    let key = effective_positionals(args, &["-h", "--host"])
        .into_iter()
        .next();
    let dangerous = matches!(
        key.as_deref().map(str::to_ascii_lowercase).as_deref(),
        Some("pager") | Some("editor") | Some("browser")
    );
    if dangerous {
        // Persists an external command gh will shell out to on every
        // future invocation -- equivalent to git's core.pager/core.editor.
        GhClassification {
            intent: vec![Intent::Execute],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                35,
                RiskFactor::CommandExecution,
                "config set pager/editor/browser",
                "Persists an external command gh will shell out to on future invocations",
            )],
        }
    } else {
        GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
    }
}

// ========================================================
// extension
// ========================================================

fn classify_extension(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("list") | Some("search") | Some("browse") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("install") | Some("upgrade") => GhClassification::with_flag(
            Intent::Execute,
            Reversibility::HardToReverse,
            flag(
                25,
                RiskFactor::CommandExecution,
                "extension install/upgrade",
                "Downloads and installs a third-party extension binary/script",
            ),
        ),
        Some("exec") => GhClassification::with_flag(
            Intent::Execute,
            Reversibility::HardToReverse,
            flag(
                30,
                RiskFactor::CommandExecution,
                "extension exec",
                "Directly runs an installed extension",
            ),
        ),
        Some("remove") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        Some("create") => GhClassification::simple(Intent::Write, Reversibility::Reversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// gpg-key / ssh-key (share the same verb vocabulary)
// ========================================================

fn classify_key_store(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("list") => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("add") => GhClassification::simple(Intent::EnvModify, Reversibility::Reversible),
        Some("delete") => GhClassification::simple(Intent::Delete, Reversibility::Irreversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// label
// ========================================================

fn classify_label(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("list") => GhClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("create") | Some("edit") | Some("clone") => {
            GhClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        Some("delete") => GhClassification::simple(Intent::Delete, Reversibility::Irreversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// ruleset
// ========================================================

/// gh 2.100.0's `ruleset` group only exposes `check`/`list`/`view` --
/// there is no `create`/`edit`/`delete` verb in the CLI (rulesets are
/// managed via `gh api` instead, already covered by `is_sensitive_endpoint`
/// -- `/rulesets`). Don't invent a special "ruleset mutation" case for
/// verbs that don't exist; fall back to the generic moderate default.
fn classify_ruleset(verb: Option<&str>) -> GhClassification {
    classify_read_only_group(verb, &["list", "check", "view"])
}

// ========================================================
// secret / variable (share the same verb vocabulary)
// ========================================================

fn classify_secret_or_variable(
    verb: Option<&str>,
    rest: &[String],
    is_secret: bool,
) -> GhClassification {
    match verb {
        None | Some("list") | Some("get") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("set") => {
            let body_inline = is_secret
                && rest
                    .iter()
                    .any(|a| a == "--body" || a.starts_with("--body="));
            if body_inline {
                GhClassification::with_flag(
                    Intent::EnvModify,
                    Reversibility::Irreversible,
                    flag(
                        30,
                        RiskFactor::SecretsExposure,
                        "secret set --body",
                        "Secret value passed inline, exposing it in shell history/process listings",
                    ),
                )
            } else {
                // Overwriting via a file/stdin redirect (the documented
                // way to set a secret) doesn't itself expose or destroy
                // anything sh-guard can observe; HardToReverse (rather
                // than Irreversible) keeps this at Danger rather than
                // Critical even when the source file is itself sensitive
                // (e.g. `gh secret set FOO < .env`).
                GhClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
            }
        }
        Some("delete") => GhClassification::simple(Intent::Delete, Reversibility::Irreversible),
        _ => unknown_verb_fallback(),
    }
}

// ========================================================
// copilot / agent-task
// ========================================================

fn classify_copilot(verb: Option<&str>) -> GhClassification {
    match verb {
        // `suggest`/`explain` only print AI-generated text; they don't run
        // anything themselves (the user must copy/paste any suggestion).
        None | Some("suggest") | Some("explain") | Some("alias") => {
            GhClassification::simple(Intent::Read, Reversibility::Reversible)
        }
        _ => unknown_verb_fallback(),
    }
}

fn classify_agent_task(verb: Option<&str>) -> GhClassification {
    match verb {
        None | Some("list") | Some("view") => {
            GhClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        // `create` (and similar) dispatches an autonomous coding agent
        // that can write code, push commits and open PRs on your behalf.
        _ => GhClassification::with_flag(
            Intent::Execute,
            Reversibility::HardToReverse,
            flag(
                25,
                RiskFactor::CommandExecution,
                "agent-task create/run",
                "Dispatches an autonomous coding agent that can write code and push changes",
            ),
        ),
    }
}
