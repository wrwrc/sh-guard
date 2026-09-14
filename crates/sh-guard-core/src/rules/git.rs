//! Git subcommand-aware classification.
//!
//! `git` is not one operation: `git status` is read-only while `git push
//! --force` rewrites remote history. The generic `CommandRule` model (one
//! intent/reversibility per executable, flag rules matched against raw
//! whitespace-split text) can't express that, so git gets its own
//! classifier here. It:
//!
//! 1. Skips git's global options (`-C <path>`, `-c <k=v>`, `--git-dir`,
//!    etc.) to find the real subcommand -- while inspecting `-c`/
//!    `--config-env` values and `GIT_*` environment prefix assignments for
//!    config keys that let a "read-only" invocation run arbitrary code
//!    (`core.pager`, `core.fsmonitor`, `credential.helper`, ...).
//! 2. Classifies the subcommand into an intent + reversibility, using the
//!    subcommand's own (already-tokenized, quote-aware) arguments where the
//!    classification is context-dependent (e.g. `git branch` alone lists
//!    branches, `git branch -D foo` force-deletes one).
//! 3. Applies subcommand-scoped "dangerous flag" checks (e.g. `push
//!    --force`, `clean -fdx`, `reset --hard`) that only look at that
//!    subcommand's own arguments -- so `git log --grep push -f` or
//!    `git commit -m "reset --hard"` can't false-positive on another
//!    subcommand's dangerous flags. Long-option matching accepts git's
//!    unambiguous-prefix abbreviations (`--forc` for `--force`, `--har`
//!    for `--hard`), erring toward flagging when a prefix is ambiguous
//!    between a dangerous and a safe option.

use crate::types::{FlagAnalysis, Intent, Reversibility, RiskFactor};

/// Result of classifying a git invocation.
pub struct GitClassification {
    pub intent: Vec<Intent>,
    pub reversibility: Reversibility,
    pub flags: Vec<FlagAnalysis>,
}

impl GitClassification {
    fn simple(intent: Intent, reversibility: Reversibility) -> Self {
        GitClassification {
            intent: vec![intent],
            reversibility,
            flags: vec![],
        }
    }
}

/// Global options that consume a following argument as a separate token
/// (`-C /repo`) or via `--opt=value`. `-c`/`--config-env` and `--exec-path`
/// are handled separately since their values matter for classification.
const GLOBAL_OPTS_WITH_SEPARATE_VALUE: &[&str] = &["-C", "--git-dir", "--work-tree", "--namespace"];

/// Global options that take no value.
const GLOBAL_OPTS_NO_VALUE: &[&str] = &[
    "-p",
    "--paginate",
    "-P",
    "--no-pager",
    "--no-replace-objects",
    "--bare",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
    "--no-optional-locks",
    "--no-lazy-fetch",
    "--no-advice",
    "--no-super-prefix",
    "--info-path",
    "--html-path",
    "--man-path",
];

/// `GIT_*` environment variables that let an otherwise-innocuous git
/// invocation run an arbitrary command (pagers, diff/merge drivers, SSH
/// transport, editors) or smuggle extra config in.
fn is_dangerous_git_env(name: &str) -> bool {
    matches!(
        name,
        "GIT_PAGER"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_EDITOR"
            | "GIT_SEQUENCE_EDITOR"
            | "GIT_ASKPASS"
            | "GIT_CONFIG_PARAMETERS"
            | "GIT_CONFIG_COUNT"
            | "GIT_CONFIG_GLOBAL"
            | "GIT_EXEC_PATH"
            | "GIT_PROXY_COMMAND"
    ) || name.starts_with("GIT_CONFIG_KEY_")
        || name.starts_with("GIT_CONFIG_VALUE_")
}

/// Config keys that, when set via `-c`/`--config-env`/gitconfig, let git
/// invoke an external program (pager, editor, ssh, diff/merge/filter
/// drivers, credential helpers, hooks) or change the trust boundary
/// (`safe.directory`, `include*`, `protocol.*.allow`).
fn is_dangerous_config_key(raw_key: &str) -> bool {
    let key = raw_key.to_ascii_lowercase();

    const EXACT: &[&str] = &[
        "core.pager",
        "core.fsmonitor",
        "core.sshcommand",
        "core.editor",
        "core.hookspath",
        "core.askpass",
        "diff.external",
        "sequence.editor",
        "credential.helper",
        "gpg.program",
        "uploadpack.packobjectshook",
        "include.path",
    ];
    if EXACT.contains(&key.as_str()) {
        return true;
    }

    let parts: Vec<&str> = key.split('.').collect();
    match parts.as_slice() {
        ["diff", _, "textconv"] => true,
        ["diff", _, "command"] => true,
        ["merge", _, "driver"] => true,
        ["filter", _, "clean"] | ["filter", _, "smudge"] | ["filter", _, "process"] => true,
        // protocol.allow or protocol.<name>.allow
        [.., "allow"] if parts[0] == "protocol" => true,
        // gpg.program or gpg.<format>.program
        [.., "program"] if parts[0] == "gpg" => true,
        // pager.<command>
        ["pager", _] => true,
        ["alias", ..] => true,
        ["includeif", ..] => true,
        ["safe", "directory"] => true,
        _ => false,
    }
}

/// Classify a `git ...` invocation given its arguments (everything after
/// the `git`/`/usr/bin/git` executable token, in tokenized/quote-aware
/// form -- i.e. `CommandSegment::args` values) and any `NAME=value` prefix
/// assignments attached to the same command (`CommandSegment::assignments`).
pub fn classify(args: &[String], env_assignments: &[(String, String)]) -> GitClassification {
    let scan = scan_global_options(args);

    let mut result = match scan.rest.split_first() {
        None => GitClassification::simple(Intent::Info, Reversibility::Reversible),
        Some((sub, sub_args)) => classify_subcommand(sub, sub_args),
    };

    if let Some(name) = env_assignments
        .iter()
        .find(|(name, _)| is_dangerous_git_env(name))
        .map(|(name, _)| name.clone())
    {
        escalate_to_execute(
            &mut result,
            &format!(
                "environment variable {} can make git run an arbitrary command",
                name
            ),
        );
    }

    if let Some(key) = scan
        .config_overrides
        .iter()
        .map(|ov| ov.split('=').next().unwrap_or(ov).to_string())
        .find(|key| is_dangerous_config_key(key))
    {
        escalate_to_execute(
            &mut result,
            &format!(
                "-c/--config-env sets '{}', which can run an arbitrary command or change git's trust boundary",
                key
            ),
        );
    }

    if scan.exec_path_override {
        escalate_to_execute(
            &mut result,
            "--exec-path=<dir> changes where git looks for helper binaries, allowing execution of attacker-controlled executables",
        );
    }

    result
}

/// Bump a classification to reflect that it can run an arbitrary command:
/// puts `Intent::Execute` first (dropping `Intent::Info` -- the command is
/// no longer meaningfully read-only once an arbitrary command can run),
/// adds a `CommandExecution` flag explaining why, and raises reversibility
/// to at least `HardToReverse`. Execute goes first specifically so
/// `scorer::generate_reason` (which reads `intent.first()`) reports "Code
/// execution" instead of e.g. "Information command" for an escalated
/// `git status`.
fn escalate_to_execute(result: &mut GitClassification, reason: &str) {
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
        "dangerous git config/env",
        reason,
    ));
}

fn classify_subcommand(sub: &str, sub_args: &[String]) -> GitClassification {
    match sub {
        // -----------------------------------------------------------
        // Read-only (porcelain + plumbing inspection commands)
        // -----------------------------------------------------------
        "status" | "blame" | "annotate" | "shortlog" | "describe" | "ls-files" | "ls-tree"
        | "ls-remote" | "rev-parse" | "rev-list" | "cat-file" | "show-ref" | "show-branch"
        | "for-each-ref" | "name-rev" | "merge-base" | "whatchanged" | "cherry" | "range-diff"
        | "count-objects" | "fsck" | "verify-commit" | "verify-tag" | "verify-pack"
        | "check-ignore" | "check-attr" | "check-ref-format" | "help" | "version" | "var"
        | "diff-tree" | "diff-files" | "diff-index" | "bugreport" | "merge-tree" | "stripspace"
        | "interpret-trailers" | "check-mailmap" | "patch-id" | "mailinfo" | "column"
        | "fmt-merge-msg" | "get-tar-commit-id" | "show-index" | "fast-export" | "gitk"
        | "backfill" | "refs" | "last-modified" | "survey" | "request-pull" => {
            GitClassification::simple(Intent::Info, Reversibility::Reversible)
        }

        // `--output`/`--output=` writes the result to an arbitrary file
        // instead of stdout; otherwise these are plain reads.
        "log" | "show" | "diff" => classify_output_writable(sub_args),

        "grep" => classify_grep(sub_args),

        // Writes files to disk (patches / archive) but doesn't touch the
        // repository's history or working tree state.
        "archive" | "format-patch" => {
            GitClassification::simple(Intent::Write, Reversibility::Reversible)
        }
        "unpack-file" => GitClassification::simple(Intent::Write, Reversibility::Reversible),
        "init-db" => GitClassification::simple(Intent::Write, Reversibility::Reversible),

        "reflog" => classify_reflog(sub_args),

        // -----------------------------------------------------------
        // Context-dependent
        // -----------------------------------------------------------
        "branch" => classify_branch(sub_args),
        "tag" => classify_tag(sub_args),
        "remote" => classify_remote(sub_args),
        "stash" => classify_stash(sub_args),
        "config" => classify_config(sub_args),
        "worktree" => classify_worktree(sub_args),
        "notes" => classify_notes(sub_args),
        "submodule" => classify_submodule(sub_args),
        "bisect" => classify_bisect(sub_args),
        "sparse-checkout" => classify_sparse_checkout(sub_args),
        "symbolic-ref" => classify_symbolic_ref(sub_args),
        "lfs" => classify_lfs(sub_args),
        "clean" => classify_clean(sub_args),
        "checkout" => classify_checkout(sub_args),
        "restore" => classify_restore(sub_args),
        "switch" => classify_switch(sub_args),
        "reset" => classify_reset(sub_args),
        "commit" => classify_commit(sub_args),
        "push" => classify_push(sub_args),
        "rm" => classify_rm(sub_args),
        "rebase" => classify_rebase(sub_args),
        "difftool" => classify_difftool(sub_args),
        "hook" => classify_hook(sub_args),
        "credential" | "credential-cache" | "credential-store" => classify_credential(sub_args),
        "bundle" => classify_bundle(sub_args),
        "hash-object" => classify_hash_object(sub_args),
        "rerere" => classify_rerere(sub_args),
        "gc" => classify_gc(sub_args),

        // -----------------------------------------------------------
        // Plain mutation
        // -----------------------------------------------------------
        "add" => GitClassification::simple(Intent::Write, Reversibility::Reversible),
        "merge" => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
        "cherry-pick" => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        "revert" => GitClassification::simple(Intent::GitMutation, Reversibility::Reversible),
        "pull" => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
        "fetch" => GitClassification::simple(Intent::Network, Reversibility::Reversible),
        "clone" => GitClassification {
            intent: vec![Intent::Network, Intent::Write],
            reversibility: Reversibility::Reversible,
            flags: vec![],
        },
        "send-email" => GitClassification::simple(Intent::Network, Reversibility::HardToReverse),
        "daemon" | "http-backend" | "instaweb" | "upload-pack" | "receive-pack" => {
            GitClassification::simple(Intent::Network, Reversibility::HardToReverse)
        }
        "init" => GitClassification::simple(Intent::Write, Reversibility::Reversible),
        "mv" => GitClassification::simple(Intent::Write, Reversibility::Reversible),
        "am" | "apply" => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        "update-index" => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        "update-ref" => classify_update_ref(sub_args),
        "write-tree" | "commit-tree" | "mktree" => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        "repack" => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
        "prune" => GitClassification::simple(Intent::GitMutation, Reversibility::Irreversible),
        "prune-packed" | "pack-refs" | "commit-graph" | "multi-pack-index" => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        "maintenance" => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        "replace" | "filter-repo" | "replay" => {
            GitClassification::simple(Intent::GitMutation, Reversibility::Irreversible)
        }
        // filter-branch runs attacker/user-supplied filter scripts (--tree-filter,
        // --index-filter, ...) against every rewritten commit.
        "filter-branch" => GitClassification {
            intent: vec![Intent::Execute, Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![],
        },
        // Always launches an external merge tool (configured via
        // merge.tool / mergetool.<tool>.cmd) to resolve conflicts.
        "mergetool" => GitClassification::simple(Intent::Execute, Reversibility::HardToReverse),
        "fast-import" => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        "citool" | "gui" => {
            GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
        }

        // Unknown/uncommon subcommand (including user-defined aliases):
        // fall back to the conservative default the rest of sh-guard uses
        // for unknown commands.
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
    }
}

// ========================================================
// Global option parsing
// ========================================================

struct GlobalScan {
    /// Tokens from the subcommand onward.
    rest: Vec<String>,
    /// Raw `key=value` (or `key=ENVVAR` for `--config-env`) strings passed
    /// via `-c`/`--config-env`.
    config_overrides: Vec<String>,
    /// True if `--exec-path=<dir>` (not the bare, informational
    /// `--exec-path`) was given.
    exec_path_override: bool,
}

fn scan_global_options(args: &[String]) -> GlobalScan {
    let mut out = Vec::new();
    let mut config_overrides = Vec::new();
    let mut exec_path_override = false;
    let mut i = 0;
    let mut in_globals = true;

    while i < args.len() {
        let a = &args[i];

        if !in_globals {
            out.push(a.clone());
            i += 1;
            continue;
        }

        if a == "-c" || a == "--config-env" {
            if let Some(val) = args.get(i + 1) {
                config_overrides.push(val.clone());
            }
            i += 2;
            continue;
        }
        if let Some(val) = a.strip_prefix("--config-env=") {
            config_overrides.push(val.to_string());
            i += 1;
            continue;
        }
        // Fused short form: `-ckey=value` (no space after -c).
        if a.starts_with("-c") && !a.starts_with("--") && a.len() > 2 {
            config_overrides.push(a[2..].to_string());
            i += 1;
            continue;
        }

        if GLOBAL_OPTS_WITH_SEPARATE_VALUE.contains(&a.as_str()) {
            // `-C /path` / `--git-dir /path` -- skip flag + its value.
            i += 2;
            continue;
        }
        if GLOBAL_OPTS_WITH_SEPARATE_VALUE
            .iter()
            .any(|o| a.starts_with(&format!("{}=", o)))
        {
            // `--git-dir=/path`
            i += 1;
            continue;
        }

        if a == "--exec-path" {
            // Bare form: prints git's current exec path. No argument, no
            // effect on where git looks for helpers.
            i += 1;
            continue;
        }
        if a.starts_with("--exec-path=") {
            exec_path_override = true;
            i += 1;
            continue;
        }

        if GLOBAL_OPTS_NO_VALUE.contains(&a.as_str()) {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            // Unrecognized global-looking option (e.g. `-h`, `--version`,
            // or a future git flag we don't know about yet). Conservatively
            // treat it as a valueless global option rather than mistaking
            // it for the subcommand.
            i += 1;
            continue;
        }

        // First non-option token: this is the subcommand.
        in_globals = false;
        out.push(a.clone());
        i += 1;
    }

    GlobalScan {
        rest: out,
        config_overrides,
        exec_path_override,
    }
}

// ========================================================
// Flag-matching helpers (operate on already-tokenized,
// quote-aware subcommand arguments, never on raw text)
// ========================================================

/// True if `args` contains a long option (`--foo`, `--foo=value`, or an
/// unambiguous prefix like `--fo`) whose name is in `longs`, or a short
/// option cluster (`-x`, `-fdx`, ...) containing `short`.
///
/// Prefix matching requires at least 3 characters after `--` (to avoid
/// matching on noise like `--f`) and, per subcommand, deliberately doesn't
/// try to fully replicate git's ambiguous-option-prefix error: if a short
/// prefix could refer to more than one option we know about across
/// different `has_flag` calls for the same subcommand, each call is
/// evaluated independently, so an ambiguous-but-plausibly-dangerous prefix
/// tends to get flagged by at least one of them (erring toward flagging).
/// `--no-<name>` is treated as an explicit negation, never a match.
fn has_flag(args: &[String], short: Option<char>, longs: &[&str]) -> bool {
    args.iter().any(|a| flag_token_matches(a, short, longs))
}

fn flag_token_matches(a: &str, short: Option<char>, longs: &[&str]) -> bool {
    if let Some(name) = a.strip_prefix("--") {
        let name = name.split('=').next().unwrap_or(name);
        if name.starts_with("no-") {
            return false;
        }
        if longs.contains(&name) {
            return true;
        }
        if name.len() >= 3 {
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

fn has_exact(args: &[String], token: &str) -> bool {
    args.iter().any(|a| a == token)
}

fn positional_count(args: &[String]) -> usize {
    args.iter().filter(|a| !a.starts_with('-')).count()
}

fn flag(modifier: i8, risk_factor: RiskFactor, flag: &str, description: &str) -> FlagAnalysis {
    FlagAnalysis {
        flag: flag.to_string(),
        modifier,
        risk_factor,
        description: description.to_string(),
    }
}

// ========================================================
// Per-subcommand classifiers
// ========================================================

fn has_write_output_flag(args: &[String]) -> bool {
    args.iter()
        .any(|a| a == "--output" || a.starts_with("--output="))
}

fn classify_output_writable(args: &[String]) -> GitClassification {
    if has_write_output_flag(args) {
        GitClassification::simple(Intent::Write, Reversibility::Reversible)
    } else {
        GitClassification::simple(Intent::Info, Reversibility::Reversible)
    }
}

fn classify_grep(args: &[String]) -> GitClassification {
    let open_in_pager = args.iter().any(|a| {
        a == "-O"
            || (a.starts_with("-O") && !a.starts_with("--"))
            || a == "--open-files-in-pager"
            || a.starts_with("--open-files-in-pager=")
    });
    if open_in_pager {
        GitClassification {
            intent: vec![Intent::Execute],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                35,
                RiskFactor::CommandExecution,
                "grep -O/--open-files-in-pager",
                "Opens matches with an external pager/command, which can run arbitrary commands",
            )],
        }
    } else {
        GitClassification::simple(Intent::Info, Reversibility::Reversible)
    }
}

fn classify_reflog(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        None | Some("show") => GitClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("expire") | Some("delete") => GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                20,
                RiskFactor::GitHistoryDestruction,
                "reflog expire/delete",
                "Expires or deletes reflog entries, losing the ability to recover commits",
            )],
        },
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
    }
}

fn classify_branch(args: &[String]) -> GitClassification {
    if args.is_empty() {
        return GitClassification::simple(Intent::Info, Reversibility::Reversible);
    }

    let force_delete = has_exact(args, "-D")
        || (has_flag(args, None, &["delete"]) && has_flag(args, Some('f'), &["force"]));
    if force_delete {
        return GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                15,
                RiskFactor::GitHistoryDestruction,
                "branch -D",
                "Force deletes a branch regardless of merge status",
            )],
        };
    }
    // Force-move/force-create a branch pointer (`branch -f main HEAD~10`):
    // silently discards commits only reachable from the old tip.
    if has_flag(args, Some('f'), &["force"]) {
        return GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                15,
                RiskFactor::GitHistoryDestruction,
                "branch -f/--force",
                "Force-moves or force-creates a branch, which can strand commits only reachable from the old tip",
            )],
        };
    }
    if has_flag(args, Some('d'), &["delete"]) {
        return GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse);
    }
    if has_flag(args, Some('m'), &["move"]) || has_flag(args, Some('M'), &[]) {
        return GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse);
    }
    if has_flag(args, Some('c'), &["copy"]) {
        return GitClassification::simple(Intent::GitMutation, Reversibility::Reversible);
    }

    let read_only = [
        "-l",
        "--list",
        "-a",
        "--all",
        "-r",
        "--remotes",
        "-v",
        "-vv",
        "--verbose",
        "--show-current",
        "--contains",
        "--merged",
        "--no-merged",
        "--points-at",
    ];
    if args.iter().any(|a| read_only.contains(&a.as_str())) {
        return GitClassification::simple(Intent::Info, Reversibility::Reversible);
    }

    // Positional args with no recognized flag: creating a new branch.
    GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
}

fn classify_tag(args: &[String]) -> GitClassification {
    if args.is_empty() {
        return GitClassification::simple(Intent::Info, Reversibility::Reversible);
    }
    if has_flag(args, Some('d'), &["delete"]) {
        return GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                10,
                RiskFactor::GitHistoryDestruction,
                "tag -d",
                "Deletes a tag; the tag object itself is not recoverable unless noted elsewhere",
            )],
        };
    }
    let read_only = [
        "-l",
        "--list",
        "-v",
        "--verify",
        "--contains",
        "--points-at",
    ];
    if args.iter().any(|a| read_only.contains(&a.as_str())) {
        return GitClassification::simple(Intent::Info, Reversibility::Reversible);
    }
    GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
}

fn classify_remote(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        None => GitClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("show") | Some("get-url") => {
            GitClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("add") | Some("rename") | Some("set-url") => {
            GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
        }
        Some("remove") | Some("rm") | Some("prune") => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        _ => {
            if args
                .iter()
                .any(|a| matches!(a.as_str(), "-v" | "--verbose"))
            {
                GitClassification::simple(Intent::Info, Reversibility::Reversible)
            } else {
                GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
            }
        }
    }
}

fn classify_stash(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        // `git stash` with no subcommand defaults to `stash push`, which
        // mutates the working tree/index.
        None => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
        Some("list") | Some("show") => {
            GitClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("drop") | Some("clear") => GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                15,
                RiskFactor::GitHistoryDestruction,
                "stash drop/clear",
                "Permanently discards stashed changes",
            )],
        },
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
    }
}

fn classify_config(args: &[String]) -> GitClassification {
    // Git 2.46+ subcommand syntax: `git config get|list|set|unset|edit|...`
    match args.first().map(String::as_str) {
        Some("get") | Some("list") => {
            return GitClassification::simple(Intent::Info, Reversibility::Reversible);
        }
        Some("set")
        | Some("unset")
        | Some("edit")
        | Some("rename-section")
        | Some("remove-section")
        | Some("add") => {
            return GitClassification::simple(Intent::EnvModify, Reversibility::HardToReverse);
        }
        _ => {}
    }

    let read_only = [
        "--get",
        "--get-all",
        "--list",
        "-l",
        "--get-regexp",
        "--get-urlmatch",
    ];
    if args.iter().any(|a| read_only.contains(&a.as_str())) {
        return GitClassification::simple(Intent::Info, Reversibility::Reversible);
    }
    let write_flags = [
        "--unset",
        "--unset-all",
        "--add",
        "--edit",
        "--replace-all",
        "--remove-section",
        "--rename-section",
    ];
    if args.iter().any(|a| write_flags.contains(&a.as_str())) {
        return GitClassification::simple(Intent::EnvModify, Reversibility::HardToReverse);
    }
    // `git config <key>` (one positional arg) reads; `git config <key>
    // <value>` (two) writes.
    if positional_count(args) <= 1 {
        GitClassification::simple(Intent::Info, Reversibility::Reversible)
    } else {
        GitClassification::simple(Intent::EnvModify, Reversibility::Reversible)
    }
}

fn classify_worktree(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        None | Some("list") => GitClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("add") | Some("move") | Some("lock") | Some("unlock") => {
            GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
        }
        Some("remove") => {
            if has_flag(args, Some('f'), &["force"]) {
                GitClassification {
                    intent: vec![Intent::GitMutation],
                    reversibility: Reversibility::Irreversible,
                    flags: vec![flag(
                        15,
                        RiskFactor::GitHistoryDestruction,
                        "worktree remove --force",
                        "Force-removes a worktree, discarding any uncommitted changes in it",
                    )],
                }
            } else {
                GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
            }
        }
        Some("prune") => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
    }
}

fn classify_notes(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        None | Some("list") | Some("show") => {
            GitClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::Reversible),
    }
}

fn classify_submodule(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        None | Some("status") | Some("summary") => {
            GitClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        // `foreach` runs an arbitrary command in each submodule.
        Some("foreach") => GitClassification::simple(Intent::Execute, Reversibility::HardToReverse),
        Some("deinit") => {
            if has_flag(args, Some('f'), &["force"]) {
                GitClassification {
                    intent: vec![Intent::GitMutation],
                    reversibility: Reversibility::Irreversible,
                    flags: vec![flag(
                        15,
                        RiskFactor::GitHistoryDestruction,
                        "submodule deinit -f",
                        "Force de-initializes a submodule, discarding local changes in it",
                    )],
                }
            } else {
                GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
            }
        }
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
    }
}

fn classify_bisect(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        None | Some("log") | Some("visualize") | Some("view") => {
            GitClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("run") => GitClassification {
            intent: vec![Intent::Execute, Intent::GitMutation],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                25,
                RiskFactor::CommandExecution,
                "bisect run",
                "Repeatedly executes an external script during bisection",
            )],
        },
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
    }
}

fn classify_sparse_checkout(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        None | Some("list") => GitClassification::simple(Intent::Info, Reversibility::Reversible),
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::Reversible),
    }
}

fn classify_symbolic_ref(args: &[String]) -> GitClassification {
    if has_flag(args, Some('d'), &["delete"]) {
        return GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                15,
                RiskFactor::GitHistoryDestruction,
                "symbolic-ref -d/--delete",
                "Deletes a symbolic ref (e.g. HEAD)",
            )],
        };
    }
    if positional_count(args) <= 1 {
        GitClassification::simple(Intent::Info, Reversibility::Reversible)
    } else {
        GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
    }
}

fn classify_lfs(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        None => GitClassification::simple(Intent::Info, Reversibility::Reversible),
        Some("ls-files") | Some("status") | Some("env") => {
            GitClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
    }
}

fn classify_clean(args: &[String]) -> GitClassification {
    let dry_run = has_flag(args, Some('n'), &["dry-run"]);
    if dry_run {
        // A dry run always just prints what would be removed, regardless
        // of -f/config.
        return GitClassification::simple(Intent::Info, Reversibility::Reversible);
    }

    let force_explicit = has_flag(args, Some('f'), &["force"]);
    let extended = has_flag(args, Some('d'), &[]) || has_flag(args, Some('x'), &[]);

    // Even without an explicit -f, `clean.requireForce` may be configured
    // off (via gitconfig, or `-c clean.requireForce=false` -- flagged
    // separately as a dangerous config key), in which case a bare
    // `git clean` DOES delete files. Treat any non-dry-run invocation as
    // destructive; a plain `git clean` is currently the least severe case.
    let (modifier, label, description) = if extended {
        (
            30,
            "clean -fdx",
            "Removes all untracked (and, with -x, ignored) files and directories",
        )
    } else if force_explicit {
        (20, "clean -f", "Removes untracked files")
    } else {
        (
            15,
            "clean (no -n)",
            "May delete untracked files depending on the clean.requireForce config setting",
        )
    };

    GitClassification {
        intent: vec![Intent::GitMutation],
        reversibility: Reversibility::Irreversible,
        flags: vec![flag(
            modifier,
            RiskFactor::GitHistoryDestruction,
            label,
            description,
        )],
    }
}

/// Positional (non-flag) args, with the values consumed by any of
/// `value_flags` (options that take a following, separate-token value --
/// e.g. `-b <branch>`) excluded. Used so an option's own argument (a new
/// branch name, a start-point, a `--source` revision, ...) doesn't get
/// mistaken for a target pathspec when counting "real" positionals.
fn effective_positionals(args: &[String], value_flags: &[&str]) -> Vec<String> {
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

/// True if a lone positional looks like a pathspec rather than a plain
/// branch/tag/commit name: glob metacharacters or the `:/` "from repo
/// root" pathspec magic. Deliberately does NOT treat a bare `/` or `.`
/// inside the token as a signal -- those are extremely common in ordinary
/// branch and tag names (`feature/login`, `v1.2.0`) and would make every
/// other `git checkout <branch>` a false positive.
fn looks_like_pathspec(p: &str) -> bool {
    p.contains('*') || p.contains('?') || p.contains('[') || p.contains(":/")
}

/// `git checkout <tree-ish> <path>...` (restoring paths from a tree-ish
/// without `--`) overwrites working tree files just like `checkout -- `.
/// Heuristic, applied to the *effective* positionals (i.e. excluding
/// values consumed by `-b`/`-B`/`--orphan`/`--conflict`, which are branch
/// names or start-points, not pathspecs): 2+ effective positionals (a
/// `<tree-ish> <path>` pair), or a single one that `looks_like_pathspec`.
fn checkout_pathspec_restore(args: &[String]) -> bool {
    const VALUE_FLAGS: &[&str] = &["-b", "-B", "--orphan", "--conflict"];
    let positionals = effective_positionals(args, VALUE_FLAGS);
    if positionals.len() >= 2 {
        return true;
    }
    positionals.first().is_some_and(|p| looks_like_pathspec(p))
}

fn classify_checkout(args: &[String]) -> GitClassification {
    let pathspec_from_file = args
        .iter()
        .any(|a| a == "--pathspec-from-file" || a.starts_with("--pathspec-from-file="));

    let discarding = has_exact(args, ".")
        || has_flag(args, Some('f'), &["force"])
        || has_exact(args, "--")
        || has_flag(args, Some('B'), &[]) // force create/reset branch-and-switch
        || pathspec_from_file
        || checkout_pathspec_restore(args);

    if discarding {
        GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                20,
                RiskFactor::GitHistoryDestruction,
                "checkout -- / checkout . / checkout -f / checkout -B / checkout <tree-ish> <path>",
                "Discards uncommitted changes in the working directory",
            )],
        }
    } else {
        // Switching branches / creating a branch (`-b <name> [<start-point>]`).
        GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
    }
}

fn classify_restore(args: &[String]) -> GitClassification {
    let staged = has_flag(args, Some('S'), &["staged"]);
    let worktree = has_flag(args, Some('W'), &["worktree"]);
    // `restore` always operates on a pathspec, so `--source`/`--source=<rev>`
    // given at all -- with an actual pathspec argument left over once the
    // separate-token form's own value is excluded -- means an arbitrary
    // source is being used to overwrite working tree files.
    let has_real_pathspec = !effective_positionals(args, &["--source"]).is_empty();
    let source_override = args
        .iter()
        .any(|a| a == "--source" || a.starts_with("--source="))
        && has_real_pathspec;

    let broad = has_exact(args, ".") || (staged && worktree) || source_override;

    if broad {
        GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                20,
                RiskFactor::GitHistoryDestruction,
                "restore . / -SW / --source=<rev>",
                "Overwrites working tree files, discarding uncommitted changes",
            )],
        }
    } else {
        GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
    }
}

fn classify_switch(args: &[String]) -> GitClassification {
    let discarding = has_flag(args, None, &["discard-changes"])
        || has_flag(args, Some('f'), &["force"])
        || has_flag(args, Some('C'), &[]); // force create/reset (-C / --force-create)
    if discarding {
        GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                20,
                RiskFactor::GitHistoryDestruction,
                "switch --discard-changes/-f/-C",
                "Discards local changes when switching branches",
            )],
        }
    } else {
        GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
    }
}

fn classify_reset(args: &[String]) -> GitClassification {
    if has_flag(args, None, &["hard"]) {
        GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                25,
                RiskFactor::GitHistoryDestruction,
                "reset --hard",
                "Hard reset discards all uncommitted changes",
            )],
        }
    } else if has_flag(args, None, &["merge"]) || has_flag(args, None, &["keep"]) {
        GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                12,
                RiskFactor::GitHistoryDestruction,
                "reset --merge/--keep",
                "Resets and updates the working tree, discarding local modifications to touched files",
            )],
        }
    } else {
        // --soft / --mixed (default): index/HEAD only, working tree untouched.
        GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
    }
}

fn classify_commit(args: &[String]) -> GitClassification {
    if has_flag(args, None, &["amend"]) {
        GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
    } else {
        GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
    }
}

fn classify_push(args: &[String]) -> GitClassification {
    let mut flags = vec![];

    if has_flag(args, Some('f'), &["force"]) {
        flags.push(flag(
            30,
            RiskFactor::GitHistoryDestruction,
            "push --force/-f",
            "Force push overwrites remote branch history",
        ));
    } else if has_flag(args, None, &["force-with-lease"])
        || has_flag(args, None, &["force-if-includes"])
    {
        flags.push(flag(
            15,
            RiskFactor::GitHistoryDestruction,
            "push --force-with-lease/--force-if-includes",
            "Force push with lease, safer but still rewrites history",
        ));
    }
    if has_flag(args, None, &["mirror"]) {
        flags.push(flag(
            25,
            RiskFactor::GitHistoryDestruction,
            "push --mirror",
            "Mirrors local refs to the remote, including deletions",
        ));
    }
    if has_flag(args, Some('d'), &["delete"]) {
        flags.push(flag(
            20,
            RiskFactor::GitHistoryDestruction,
            "push --delete/-d",
            "Deletes a remote branch or tag",
        ));
    }
    if has_flag(args, None, &["prune"]) {
        flags.push(flag(
            15,
            RiskFactor::GitHistoryDestruction,
            "push --prune",
            "Removes remote refs that no longer exist locally",
        ));
    }
    // Refspecs that delete (`:branch`) or force-update (`+branch`) a
    // remote ref. A bare `:` (push nothing / old "matching" push) or bare
    // `+` are not refspecs on their own and must NOT be flagged.
    if args
        .iter()
        .any(|a| !a.starts_with('-') && a.len() > 1 && (a.starts_with(':') || a.starts_with('+')))
    {
        flags.push(flag(
            20,
            RiskFactor::GitHistoryDestruction,
            "push :ref / +ref",
            "Refspec deletes or force-updates a remote ref",
        ));
    }

    // Reversibility stays HardToReverse even for force pushes: the
    // GitHistoryDestruction flag modifier above already carries the
    // extra risk, and the remote's previous state is often still
    // recoverable via the reflog on someone's machine or the remote's
    // own history, unlike e.g. `git clean -fdx` which has no fallback.
    GitClassification {
        intent: vec![Intent::GitMutation],
        reversibility: Reversibility::HardToReverse,
        flags,
    }
}

fn classify_rm(args: &[String]) -> GitClassification {
    // `--cached` only removes files from the index; the working tree
    // copies are left untouched. That's a git bookkeeping change, not a
    // file deletion -- classify it as a plain (reversible: `git add` puts
    // it right back) mutation rather than Intent::Delete.
    if has_flag(args, None, &["cached"]) {
        return GitClassification::simple(Intent::GitMutation, Reversibility::Reversible);
    }

    let recursive = has_flag(args, Some('r'), &[]);
    let force = has_flag(args, Some('f'), &["force"]);

    let mut flags = vec![];
    if recursive && force {
        flags.push(flag(
            20,
            RiskFactor::GitHistoryDestruction,
            "rm -rf",
            "Recursively force-removes files from the index and working tree",
        ));
    } else if recursive {
        flags.push(flag(
            10,
            RiskFactor::GitHistoryDestruction,
            "rm -r",
            "Recursively removes files from the index and working tree",
        ));
    } else if force {
        flags.push(flag(
            10,
            RiskFactor::GitHistoryDestruction,
            "rm -f",
            "Force-removes files even with local modifications",
        ));
    }

    GitClassification {
        intent: vec![Intent::Delete],
        reversibility: if recursive || force {
            Reversibility::Irreversible
        } else {
            Reversibility::HardToReverse
        },
        flags,
    }
}

fn classify_rebase(args: &[String]) -> GitClassification {
    if has_flag(args, Some('x'), &["exec"]) {
        GitClassification {
            intent: vec![Intent::Execute, Intent::GitMutation],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                25,
                RiskFactor::CommandExecution,
                "rebase -x/--exec",
                "Runs an arbitrary command after each commit during the rebase",
            )],
        }
    } else {
        GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
    }
}

fn classify_difftool(args: &[String]) -> GitClassification {
    if has_flag(args, Some('x'), &["extcmd"]) {
        GitClassification {
            intent: vec![Intent::Execute],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                30,
                RiskFactor::CommandExecution,
                "difftool -x/--extcmd",
                "Runs an arbitrary command as the diff tool",
            )],
        }
    } else {
        GitClassification::simple(Intent::Info, Reversibility::Reversible)
    }
}

fn classify_hook(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        Some("run") => GitClassification {
            intent: vec![Intent::Execute],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                25,
                RiskFactor::CommandExecution,
                "hook run",
                "Runs a repository hook script",
            )],
        },
        _ => GitClassification::simple(Intent::Info, Reversibility::Reversible),
    }
}

// Covers `git credential <op>`, `git credential-cache <op>` and
// `git credential-store <op>`, which share the same verb vocabulary
// (`fill`/`get` retrieve a stored secret; `approve`/`reject`/`store`/
// `erase` write to the helper's store; `exit` only stops the cache
// daemon).
fn classify_credential(args: &[String]) -> GitClassification {
    // Helper options can precede the operation (`credential-store --file
    // <path> get`, `credential-cache --timeout <s> --socket <path> get`), so
    // skip them -- and the values they consume -- to find it.
    let operation = effective_positionals(args, &["--file", "--timeout", "--socket"]);
    match operation.first().map(String::as_str) {
        // `fill` (git-credential) and `get` (credential-cache/-store) both
        // print a stored username/password to stdout.
        Some("fill") | Some("get") => GitClassification {
            intent: vec![Intent::Read],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                50,
                RiskFactor::SecretsExposure,
                "credential fill/get",
                "Retrieves a stored credential (e.g. from ~/.git-credentials or a credential helper) and prints it to stdout",
            )],
        },
        Some("approve") | Some("reject") | Some("store") | Some("erase") => {
            GitClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
        }
        Some("exit") => GitClassification::simple(Intent::ProcessControl, Reversibility::Reversible),
        // Bare `credential`/`credential-cache`/`credential-store` (no
        // operation given) or an operation we don't recognize: don't
        // assume it's safe just because we don't know what it does.
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
    }
}

fn classify_bundle(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        Some("create") => GitClassification::simple(Intent::Write, Reversibility::Reversible),
        Some("unbundle") => {
            GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
        }
        _ => GitClassification::simple(Intent::Info, Reversibility::Reversible),
    }
}

fn classify_hash_object(args: &[String]) -> GitClassification {
    if has_flag(args, Some('w'), &["write"]) {
        GitClassification::simple(Intent::GitMutation, Reversibility::Reversible)
    } else {
        GitClassification::simple(Intent::Info, Reversibility::Reversible)
    }
}

fn classify_rerere(args: &[String]) -> GitClassification {
    match args.first().map(String::as_str) {
        None | Some("status") | Some("diff") | Some("remaining") => {
            GitClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        _ => GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse),
    }
}

fn classify_update_ref(args: &[String]) -> GitClassification {
    if has_flag(args, Some('d'), &[]) {
        GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                20,
                RiskFactor::GitHistoryDestruction,
                "update-ref -d",
                "Deletes a ref",
            )],
        }
    } else {
        GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
    }
}

fn classify_gc(args: &[String]) -> GitClassification {
    // `--aggressive` only repacks more thoroughly; it doesn't change what
    // gets pruned, so it must NOT be treated as history-destructive on its
    // own. Any explicit `--prune=<value>` (`now`, a date, `all`, ...)
    // overrides the default 2-week grace period for unreachable objects.
    let explicit_prune = args.iter().any(|a| a.starts_with("--prune="));
    if explicit_prune {
        GitClassification {
            intent: vec![Intent::GitMutation],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                15,
                RiskFactor::GitHistoryDestruction,
                "gc --prune=<value>",
                "Overrides the default grace period, immediately expiring and removing unreachable objects",
            )],
        }
    } else {
        GitClassification::simple(Intent::GitMutation, Reversibility::HardToReverse)
    }
}
