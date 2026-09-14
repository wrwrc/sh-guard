//! Git subcommand-aware classification tests.
//!
//! Covers every subcommand category from the classification table in
//! `crates/sh-guard-core/src/rules/git.rs`: read-only, context-dependent,
//! plain mutation, and destructive, plus global-option handling and
//! false-positive avoidance.

use sh_guard_core::*;

fn analyze(cmd: &str) -> AnalysisResult {
    classify(cmd, None)
}

fn first_sub(result: &AnalysisResult) -> &CommandAnalysis {
    &result.sub_commands[0]
}

fn has_risk_factor(a: &CommandAnalysis, rf: RiskFactor) -> bool {
    a.risk_factors.contains(&rf)
}

fn has_intent(a: &CommandAnalysis, intent: Intent) -> bool {
    a.intent.contains(&intent)
}

// ========================================================================
// Table-driven: read-only git subcommands -> Intent::Info, SAFE, reversible
// ========================================================================

#[test]
fn read_only_subcommands_are_info_and_safe() {
    let cases: &[&str] = &[
        "git status",
        "git log --oneline -5",
        "git show HEAD",
        "git diff",
        "git blame file.rs",
        "git annotate file.rs",
        "git shortlog",
        "git describe",
        "git grep TODO",
        "git ls-files",
        "git ls-tree HEAD",
        "git ls-remote",
        "git rev-parse HEAD",
        "git rev-list HEAD",
        "git cat-file -p HEAD",
        "git show-ref",
        "git show-branch",
        "git for-each-ref",
        "git name-rev HEAD",
        "git merge-base main HEAD",
        "git whatchanged",
        "git cherry",
        "git range-diff main HEAD",
        "git count-objects",
        "git fsck",
        "git verify-commit HEAD",
        "git verify-tag v1.0",
        "git verify-pack pack.idx",
        "git check-ignore file.rs",
        "git check-attr text file.rs",
        "git check-ref-format refs/heads/main",
        "git help",
        "git version",
        "git var GIT_AUTHOR_IDENT",
        "git diff-tree HEAD",
        "git diff-files",
        "git diff-index HEAD",
        "git bugreport",
        "git reflog",
        "git reflog show",
    ];

    for cmd in cases {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_intent(a, Intent::Info),
            "{cmd}: expected Info intent, got {:?}",
            a.intent
        );
        assert_eq!(
            a.reversibility,
            Reversibility::Reversible,
            "{cmd}: expected Reversible"
        );
        assert_eq!(
            result.level,
            RiskLevel::Safe,
            "{cmd}: expected SAFE, got {:?} (score {})",
            result.level,
            result.score
        );
        assert!(
            result.reason.contains("Information"),
            "{cmd}: reason should mention Information, got {:?}",
            result.reason
        );
    }
}

// ========================================================================
// archive / format-patch: write files, not history-destructive
// ========================================================================

#[test]
fn archive_and_format_patch_are_write_not_destructive() {
    for cmd in ["git archive HEAD", "git format-patch main"] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Write), "{cmd}: expected Write");
        assert!(
            !has_risk_factor(a, RiskFactor::GitHistoryDestruction),
            "{cmd}: should not be flagged destructive"
        );
    }
}

// ========================================================================
// Context-dependent: branch
// ========================================================================

#[test]
fn branch_no_args_is_read() {
    let result = analyze("git branch");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Info));
    assert_eq!(result.level, RiskLevel::Safe);
}

#[test]
fn branch_list_flags_are_read() {
    for cmd in [
        "git branch -l",
        "git branch --list",
        "git branch -a",
        "git branch -r",
        "git branch -v",
        "git branch --show-current",
        "git branch --contains main",
        "git branch --merged",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Info), "{cmd}: expected Info");
    }
}

#[test]
fn branch_create_is_mutation_not_destructive() {
    let result = analyze("git branch new-feature");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::GitMutation));
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn branch_move_and_copy_are_mutation() {
    for cmd in [
        "git branch -m old new",
        "git branch -M old new",
        "git branch -c old new",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::GitMutation), "{cmd}");
    }
}

#[test]
fn branch_delete_is_mutation_not_destructive() {
    let result = analyze("git branch -d old-feature");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::GitMutation));
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn branch_force_delete_is_destructive() {
    let result = analyze("git branch -D old-feature");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_eq!(a.reversibility, Reversibility::Irreversible);
    assert!(matches!(
        result.level,
        RiskLevel::Danger | RiskLevel::Critical
    ));
}

// ========================================================================
// Context-dependent: tag
// ========================================================================

#[test]
fn tag_read_variants() {
    for cmd in [
        "git tag",
        "git tag -l",
        "git tag --list",
        "git tag --contains main",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Info), "{cmd}");
    }
}

#[test]
fn tag_create_is_mutation() {
    let result = analyze("git tag v1.0");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::GitMutation));
}

#[test]
fn tag_delete_is_flagged() {
    let result = analyze("git tag -d v1.0");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

// ========================================================================
// Context-dependent: remote
// ========================================================================

#[test]
fn remote_read_variants() {
    for cmd in [
        "git remote",
        "git remote -v",
        "git remote show origin",
        "git remote get-url origin",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Info), "{cmd}");
    }
}

#[test]
fn remote_mutation_variants() {
    for cmd in [
        "git remote add origin https://example.com/repo.git",
        "git remote remove origin",
        "git remote rm origin",
        "git remote rename origin upstream",
        "git remote set-url origin https://example.com/repo.git",
        "git remote prune origin",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::GitMutation), "{cmd}");
    }
}

// ========================================================================
// Context-dependent: stash
// ========================================================================

#[test]
fn stash_read_variants() {
    for cmd in ["git stash list", "git stash show"] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Info), "{cmd}");
    }
}

#[test]
fn stash_mutation_variants() {
    for cmd in [
        "git stash",
        "git stash push",
        "git stash save",
        "git stash pop",
        "git stash apply",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::GitMutation), "{cmd}");
    }
}

#[test]
fn stash_drop_and_clear_are_destructive() {
    for cmd in ["git stash drop", "git stash clear"] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_risk_factor(a, RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
    }
}

// ========================================================================
// Context-dependent: config
// ========================================================================

#[test]
fn config_read_variants() {
    for cmd in [
        "git config --get user.name",
        "git config --list",
        "git config -l",
        "git config user.name",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Info), "{cmd}");
    }
}

#[test]
fn config_write_variants() {
    for cmd in [
        "git config user.name \"Jane Doe\"",
        "git config --global user.name Jane",
        "git config --unset user.name",
        "git config --add foo bar",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_intent(a, Intent::EnvModify),
            "{cmd}: got {:?}",
            a.intent
        );
    }
}

// ========================================================================
// Context-dependent: worktree
// ========================================================================

#[test]
fn worktree_variants() {
    let result = analyze("git worktree list");
    assert!(has_intent(first_sub(&result), Intent::Info));

    let result = analyze("git worktree add ../wt branch");
    assert!(has_intent(first_sub(&result), Intent::GitMutation));

    let result = analyze("git worktree remove ../wt --force");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));

    let result = analyze("git worktree prune");
    assert!(has_intent(first_sub(&result), Intent::GitMutation));
}

// ========================================================================
// Context-dependent: notes, bisect, sparse-checkout, symbolic-ref, lfs
// ========================================================================

#[test]
fn notes_list_show_are_read() {
    for cmd in ["git notes list", "git notes show"] {
        let result = analyze(cmd);
        assert!(has_intent(first_sub(&result), Intent::Info), "{cmd}");
    }
}

#[test]
fn bisect_log_is_read_start_is_mutation() {
    assert!(has_intent(
        first_sub(&analyze("git bisect log")),
        Intent::Info
    ));
    assert!(has_intent(
        first_sub(&analyze("git bisect start")),
        Intent::GitMutation
    ));
}

#[test]
fn sparse_checkout_list_vs_set() {
    assert!(has_intent(
        first_sub(&analyze("git sparse-checkout list")),
        Intent::Info
    ));
    assert!(has_intent(
        first_sub(&analyze("git sparse-checkout set dir1 dir2")),
        Intent::GitMutation
    ));
}

#[test]
fn symbolic_ref_one_arg_is_read() {
    assert!(has_intent(
        first_sub(&analyze("git symbolic-ref HEAD")),
        Intent::Info
    ));
    assert!(has_intent(
        first_sub(&analyze("git symbolic-ref HEAD refs/heads/main")),
        Intent::GitMutation
    ));
}

#[test]
fn lfs_status_is_read() {
    assert!(has_intent(
        first_sub(&analyze("git lfs status")),
        Intent::Info
    ));
    assert!(has_intent(
        first_sub(&analyze("git lfs ls-files")),
        Intent::Info
    ));
}

// ========================================================================
// submodule: status is read, foreach is execute, deinit -f destructive
// ========================================================================

#[test]
fn submodule_status_is_read() {
    assert!(has_intent(
        first_sub(&analyze("git submodule status")),
        Intent::Info
    ));
}

#[test]
fn submodule_foreach_is_execute() {
    let result = analyze("git submodule foreach 'git pull'");
    assert!(has_intent(first_sub(&result), Intent::Execute));
}

#[test]
fn submodule_deinit_force_is_destructive() {
    let result = analyze("git submodule deinit -f mymodule");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::GitHistoryDestruction
    ));
}

// ========================================================================
// Plain mutation subcommands
// ========================================================================

#[test]
fn plain_mutation_subcommands_are_mutation_not_destructive() {
    let result = analyze("git add file.rs");
    let a = first_sub(&result);
    assert!(
        has_intent(a, Intent::Write),
        "git add: expected Write, got {:?}",
        a.intent
    );
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));

    let cases: &[&str] = &[
        "git commit -m \"message\"",
        "git merge feature",
        "git rebase main",
        "git cherry-pick abc123",
        "git revert abc123",
        "git pull",
        "git push",
        "git am patch.diff",
        "git apply patch.diff",
        "git update-index --refresh",
        "git write-tree",
        "git commit-tree abc123",
        "git mktree",
        "git gc",
        "git repack",
        "git maintenance run",
    ];
    for cmd in cases {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_intent(a, Intent::GitMutation),
            "{cmd}: expected GitMutation, got {:?}",
            a.intent
        );
        assert!(
            !has_risk_factor(a, RiskFactor::GitHistoryDestruction),
            "{cmd}: should not be flagged destructive"
        );
        assert_ne!(
            result.level,
            RiskLevel::Critical,
            "{cmd}: plain mutation should not be Critical"
        );
    }
}

#[test]
fn init_and_mv_are_write_not_destructive() {
    for cmd in ["git init", "git mv a b"] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Write), "{cmd}: got {:?}", a.intent);
        assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    }
}

#[test]
fn fetch_is_network_reversible() {
    let result = analyze("git fetch origin");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Network));
    assert_eq!(a.reversibility, Reversibility::Reversible);
}

#[test]
fn clone_is_network_and_write() {
    let result = analyze("git clone https://example.com/repo.git");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Network));
    assert!(has_intent(a, Intent::Write));
}

#[test]
fn checkout_switching_branch_is_reversible() {
    let result = analyze("git checkout main");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::GitMutation));
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_eq!(a.reversibility, Reversibility::Reversible);
}

#[test]
fn reset_default_is_reversible_no_flag() {
    let result = analyze("git reset HEAD~1");
    let a = first_sub(&result);
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_eq!(a.reversibility, Reversibility::Reversible);
}

#[test]
fn commit_amend_is_hard_to_reverse() {
    let result = analyze("git commit --amend");
    let a = first_sub(&result);
    assert_eq!(a.reversibility, Reversibility::HardToReverse);
}

// ========================================================================
// Destructive subcommands / flags
// ========================================================================

#[test]
fn push_force_is_destructive() {
    for cmd in ["git push --force origin main", "git push -f origin main"] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_risk_factor(a, RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
        assert!(
            matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
            "{cmd}: level {:?} score {}",
            result.level,
            result.score
        );
    }
}

#[test]
fn push_force_with_lease_is_flagged_but_lower() {
    let result = analyze("git push --force-with-lease origin main");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::GitHistoryDestruction
    ));
}

#[test]
fn push_mirror_and_prune_are_flagged() {
    for cmd in ["git push --mirror origin", "git push --prune origin"] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
    }
}

#[test]
fn push_refspec_delete_is_flagged() {
    let result = analyze("git push origin :old-branch");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::GitHistoryDestruction
    ));
}

#[test]
fn reset_hard_is_destructive() {
    let result = analyze("git reset --hard HEAD~3");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_eq!(a.reversibility, Reversibility::Irreversible);
}

#[test]
fn clean_combined_flags_are_destructive() {
    for cmd in [
        "git clean -xfd",
        "git clean -fd",
        "git clean -fxd",
        "git clean -xdf",
        "git clean --force",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_risk_factor(a, RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
    }
}

#[test]
fn clean_without_force_is_safe() {
    let result = analyze("git clean -n");
    let a = first_sub(&result);
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_eq!(result.level, RiskLevel::Safe);
}

#[test]
fn checkout_discard_variants_are_destructive() {
    for cmd in ["git checkout -- .", "git checkout .", "git checkout -f"] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
    }
}

#[test]
fn restore_dot_is_destructive() {
    let result = analyze("git restore .");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::GitHistoryDestruction
    ));
}

#[test]
fn switch_discard_is_destructive() {
    for cmd in ["git switch --discard-changes main", "git switch -f main"] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
    }
}

#[test]
fn reflog_expire_delete_are_destructive() {
    for cmd in [
        "git reflog expire --expire=now --all",
        "git reflog delete HEAD@{0}",
    ] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
    }
}

#[test]
fn gc_prune_now_is_destructive() {
    let result = analyze("git gc --prune=now");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::GitHistoryDestruction
    ));
}

#[test]
fn update_ref_delete_is_destructive() {
    let result = analyze("git update-ref -d refs/heads/old");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::GitHistoryDestruction
    ));
}

#[test]
fn filter_branch_and_filter_repo_are_irreversible() {
    for cmd in [
        "git filter-branch --tree-filter 'rm -rf secret' HEAD",
        "git filter-repo --path secret --invert-paths",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert_eq!(a.reversibility, Reversibility::Irreversible, "{cmd}");
    }
}

#[test]
fn rm_recursive_force_is_flagged() {
    let result = analyze("git rm -rf secrets/");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::GitHistoryDestruction
    ));
}

// ========================================================================
// Global options: subcommand detection must skip global flags
// ========================================================================

#[test]
fn global_dash_c_path_still_finds_status() {
    let result = analyze("git -C /repo status");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Info), "got {:?}", a.intent);
    assert_eq!(result.level, RiskLevel::Safe);
}

#[test]
fn global_lowercase_c_config_still_finds_log() {
    // A benign `-c` key (not on the dangerous-config list) must not
    // prevent the subcommand from being classified normally.
    let result = analyze("git -c color.ui=always log");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Info), "got {:?}", a.intent);
    assert_eq!(result.level, RiskLevel::Safe);
}

#[test]
fn global_no_pager_still_finds_diff() {
    let result = analyze("git --no-pager diff");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Info), "got {:?}", a.intent);
}

#[test]
fn global_options_still_find_destructive_push() {
    let result = analyze("git -C /repo push --force origin main");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::GitHistoryDestruction
    ));
}

// ========================================================================
// False positives: dangerous words in message text / other subcommands
// must not trigger unrelated subcommand's dangerous flags
// ========================================================================

#[test]
fn log_grep_push_dash_f_is_not_flagged_force_push() {
    let result = analyze("git log --grep push -f");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Info));
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_eq!(result.level, RiskLevel::Safe);
}

#[test]
fn commit_message_containing_reset_hard_is_not_flagged() {
    let result = analyze("git commit -m \"reset --hard\"");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::GitMutation));
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn show_head_dashdash_dash_f_pathspec_is_not_flagged_as_checkout_force() {
    let result = analyze("git show HEAD -- -f");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Info));
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

// ========================================================================
// Pipelines / compound commands
// ========================================================================

#[test]
fn status_and_push_force_compound_flags_only_the_push_segment() {
    let result = analyze("git status && git push -f");
    assert_eq!(result.sub_commands.len(), 2);
    let status_seg = &result.sub_commands[0];
    let push_seg = &result.sub_commands[1];
    assert!(has_intent(status_seg, Intent::Info));
    assert!(!has_risk_factor(
        status_seg,
        RiskFactor::GitHistoryDestruction
    ));
    assert!(has_risk_factor(push_seg, RiskFactor::GitHistoryDestruction));
    assert!(
        matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
        "overall pipeline should carry the destructive segment's risk: {:?} ({})",
        result.level,
        result.score
    );
}

// ========================================================================
// /usr/bin/git path handling
// ========================================================================

#[test]
fn absolute_path_git_status_is_still_read_only() {
    let result = analyze("/usr/bin/git status");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Info), "got {:?}", a.intent);
    assert_eq!(result.level, RiskLevel::Safe);
}

#[test]
fn absolute_path_git_push_force_is_still_destructive() {
    let result = analyze("/usr/bin/git push --force origin main");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::GitHistoryDestruction
    ));
}

// ========================================================================
// Regression tests for the code-review bypasses (probes verified against
// the built CLI + a real git repo). Each `#[test]` below corresponds to
// one probe command from the review.
// ========================================================================

// ---- MUST FIX #1: -c / --config-env / GIT_* env bypasses ----

#[test]
fn probe_c_core_fsmonitor_escalates_to_execute() {
    let result = analyze("git -c core.fsmonitor=./evil.sh status");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
    assert!(has_risk_factor(a, RiskFactor::CommandExecution));
    assert_eq!(result.level, RiskLevel::Critical);
}

#[test]
fn probe_c_core_pager_sh_log_escalates_to_execute() {
    let result = analyze("git -c core.pager='sh -c id' log");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
    assert!(has_risk_factor(a, RiskFactor::CommandExecution));
    assert_eq!(result.level, RiskLevel::Critical);
}

#[test]
fn probe_git_pager_env_var_escalates_to_execute() {
    let result = analyze("GIT_PAGER='sh -c id' git log");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
    assert!(has_risk_factor(a, RiskFactor::CommandExecution));
    assert_eq!(result.level, RiskLevel::Critical);
}

#[test]
fn probe_protocol_ext_allow_clone_escalates_to_execute() {
    let result = analyze("git -c protocol.ext.allow=always clone 'ext::sh -c id'");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
    assert!(has_risk_factor(a, RiskFactor::CommandExecution));
    assert_eq!(result.level, RiskLevel::Critical);
}

#[test]
fn dangerous_config_keys_all_escalate() {
    let cases: &[&str] = &[
        "git -c core.pager=x status",
        "git -c core.fsmonitor=x status",
        "git -c core.sshCommand=x status",
        "git -c core.editor=x status",
        "git -c core.hooksPath=x status",
        "git -c core.askPass=x status",
        "git -c diff.external=x diff",
        "git -c diff.mine.textconv=x diff",
        "git -c diff.mine.command=x diff",
        "git -c merge.mine.driver=x status",
        "git -c filter.lfs.clean=x status",
        "git -c filter.lfs.smudge=x status",
        "git -c filter.lfs.process=x status",
        "git -c protocol.allow=always status",
        "git -c protocol.ext.allow=always status",
        "git -c credential.helper=x status",
        "git -c gpg.program=x status",
        "git -c gpg.ssh.program=x status",
        "git -c sequence.editor=x status",
        "git -c uploadPack.packObjectsHook=x status",
        "git -c include.path=x status",
        "git -c includeIf.onbranch:main.path=x status",
        "git -c safe.directory=x status",
        "git --config-env=core.pager=SOME_ENV status",
    ];
    for cmd in cases {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_intent(a, Intent::Execute),
            "{cmd}: expected Execute, got {:?}",
            a.intent
        );
    }
}

#[test]
fn benign_config_keys_do_not_escalate() {
    for cmd in [
        "git -c user.name=Jane status",
        "git -c color.ui=always status",
        "git -c init.defaultBranch=main status",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            !has_intent(a, Intent::Execute),
            "{cmd}: should not escalate, got {:?}",
            a.intent
        );
        assert_eq!(result.level, RiskLevel::Safe, "{cmd}");
    }
}

#[test]
fn all_dangerous_git_env_vars_escalate() {
    let names = [
        "GIT_PAGER",
        "GIT_EXTERNAL_DIFF",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_ASKPASS",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_GLOBAL",
        "GIT_EXEC_PATH",
        "GIT_PROXY_COMMAND",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
    ];
    for name in names {
        let cmd = format!("{name}=x git status");
        let result = analyze(&cmd);
        let a = first_sub(&result);
        assert!(
            has_intent(a, Intent::Execute),
            "{cmd}: expected Execute, got {:?}",
            a.intent
        );
    }
}

#[test]
fn exec_path_override_escalates_to_execute() {
    let result = analyze("git --exec-path=/tmp/evil status");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
}

#[test]
fn bare_exec_path_does_not_escalate() {
    let result = analyze("git --exec-path");
    let a = first_sub(&result);
    assert!(!has_intent(a, Intent::Execute), "got {:?}", a.intent);
}

// ---- MUST FIX #2: read-only subcommands with writing/executing options ----

#[test]
fn probe_diff_output_to_arbitrary_file_is_write() {
    let result = analyze("git diff --output=/Users/x/.zshrc");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Write), "got {:?}", a.intent);
    assert!(!has_intent(a, Intent::Info));
}

#[test]
fn log_and_show_output_flag_is_write() {
    for cmd in ["git log --output=/tmp/x", "git show --output=/tmp/x HEAD"] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Write), "{cmd}: got {:?}", a.intent);
    }
}

#[test]
fn probe_grep_open_files_in_pager_short_is_execute() {
    let result = analyze("git grep -O'sh -c id' foo");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
    assert!(has_risk_factor(a, RiskFactor::CommandExecution));
}

#[test]
fn grep_open_files_in_pager_long_is_execute() {
    let result = analyze("git grep --open-files-in-pager=less foo");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
}

#[test]
fn log_no_index_diff_is_still_fine() {
    // Sanity: --no-index is unrelated to --output and must not trip the
    // write-output detection.
    let result = analyze("git diff --no-index a b");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Info), "got {:?}", a.intent);
}

// ---- MUST FIX #3: `git clean` without -f ----

#[test]
fn probe_clean_requireforce_false_via_dash_c_is_destructive() {
    // `-c clean.requireForce=false` both makes plain `clean -d` destructive
    // AND is itself a dangerous config key, so this should carry both the
    // GitHistoryDestruction and CommandExecution signals.
    let result = analyze("git -c clean.requireForce=false clean -d");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn clean_bare_no_flags_is_destructive_not_safe() {
    let result = analyze("git clean -d");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_ne!(result.level, RiskLevel::Safe);
}

#[test]
fn clean_dry_run_is_still_safe() {
    for cmd in ["git clean -n", "git clean --dry-run", "git clean -nd"] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            !has_risk_factor(a, RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
        assert_eq!(result.level, RiskLevel::Safe, "{cmd}");
    }
}

// ---- MUST FIX #4: unambiguous long-option prefix abbreviations ----

#[test]
fn probe_reset_har_abbreviation_is_flagged_like_hard() {
    let result = analyze("git reset --har");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_eq!(a.reversibility, Reversibility::Irreversible);
}

#[test]
fn probe_push_forc_abbreviation_is_flagged_like_force() {
    let result = analyze("git push --forc origin main");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert!(matches!(
        result.level,
        RiskLevel::Danger | RiskLevel::Critical
    ));
}

#[test]
fn switch_dis_abbreviation_matches_discard_changes() {
    let result = analyze("git switch --dis main");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn no_prefix_negation_does_not_match() {
    // `--no-hard` (hypothetical) must never be treated as enabling `--hard`.
    let result = analyze("git reset --no-hard");
    let a = first_sub(&result);
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

// ---- MUST FIX #5: symbolic-ref -d/--delete ----

#[test]
fn probe_symbolic_ref_dash_d_head_is_flagged() {
    let result = analyze("git symbolic-ref -d HEAD");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_ne!(result.level, RiskLevel::Safe);
}

#[test]
fn probe_symbolic_ref_delete_long_head_is_flagged() {
    let result = analyze("git symbolic-ref --delete HEAD");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert_ne!(result.level, RiskLevel::Safe);
}

// ---- SHOULD FIX #6: command-executing subcommands ----

#[test]
fn probe_bisect_run_is_execute() {
    let result = analyze("git bisect run ./x.sh");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
    assert!(has_risk_factor(a, RiskFactor::CommandExecution));
}

#[test]
fn probe_rebase_dash_x_is_execute() {
    let result = analyze("git rebase -x \"rm -rf /\"");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
}

#[test]
fn probe_rebase_exec_long_is_execute() {
    let result = analyze("git rebase --exec \"rm -rf /\"");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
}

#[test]
fn probe_difftool_dash_x_is_execute() {
    let result = analyze("git difftool -x vimdiff");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
}

#[test]
fn difftool_extcmd_long_is_execute() {
    let result = analyze("git difftool --extcmd vimdiff");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
}

#[test]
fn probe_mergetool_is_execute() {
    let result = analyze("git mergetool");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
}

#[test]
fn probe_hook_run_precommit_is_execute() {
    let result = analyze("git hook run pre-commit");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
    assert!(has_risk_factor(a, RiskFactor::CommandExecution));
}

#[test]
fn probe_submodule_foreach_is_still_execute() {
    let result = analyze("git submodule foreach \"git pull\"");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
}

#[test]
fn probe_filter_branch_is_execute_and_irreversible() {
    let result = analyze("git filter-branch --tree-filter \"rm -rf secret\" HEAD");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute), "got {:?}", a.intent);
    assert_eq!(a.reversibility, Reversibility::Irreversible);
}

// ---- SHOULD FIX #7: previously-uncovered subcommands (spot checks) ----

#[test]
fn uncovered_subcommands_spot_checks() {
    assert!(has_intent(
        first_sub(&analyze("git send-email --to=x patch.eml")),
        Intent::Network
    ));
    assert!(has_intent(
        first_sub(&analyze("git request-pull v1.0 origin")),
        Intent::Info
    ));
    assert!(has_intent(
        first_sub(&analyze("git bundle create repo.bundle main")),
        Intent::Write
    ));
    assert!(has_intent(
        first_sub(&analyze("git bundle verify repo.bundle")),
        Intent::Info
    ));
    assert!(has_intent(
        first_sub(&analyze("git hash-object -w file.txt")),
        Intent::GitMutation
    ));
    assert!(has_intent(
        first_sub(&analyze("git hash-object file.txt")),
        Intent::Info
    ));
    assert!(has_risk_factor(
        first_sub(&analyze("git credential fill")),
        RiskFactor::SecretsExposure
    ));
    assert!(has_intent(
        first_sub(&analyze("git rerere status")),
        Intent::Info
    ));
    assert!(has_intent(
        first_sub(&analyze("git rerere forget file.txt")),
        Intent::GitMutation
    ));
}

// ---- SHOULD FIX #8: false positives / missed classification syntax ----

#[test]
fn probe_gc_aggressive_is_not_flagged_destructive() {
    let result = analyze("git gc --aggressive");
    let a = first_sub(&result);
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn probe_gc_prune_all_is_flagged() {
    let result = analyze("git gc --prune=all");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn gc_prune_arbitrary_date_is_flagged() {
    let result = analyze("git gc --prune=2.weeks.ago");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn probe_push_bare_colon_is_not_flagged() {
    let result = analyze("git push origin :");
    let a = first_sub(&result);
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn probe_push_colon_branch_is_still_flagged() {
    let result = analyze("git push origin :old-branch");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn probe_rm_recursive_cached_is_not_destructive() {
    let result = analyze("git rm -r --cached .");
    let a = first_sub(&result);
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn probe_config_get_and_list_are_info() {
    for cmd in ["git config get user.name", "git config list"] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Info), "{cmd}: got {:?}", a.intent);
    }
}

#[test]
fn probe_config_set_unset_edit_rename_remove_are_env_modify() {
    for cmd in [
        "git config set user.name Jane",
        "git config unset user.name",
        "git config edit",
        "git config rename-section a b",
        "git config remove-section a",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_intent(a, Intent::EnvModify),
            "{cmd}: got {:?}",
            a.intent
        );
    }
}

// ---- SHOULD FIX #9: missed destructive patterns ----

#[test]
fn probe_checkout_treeish_path_no_dashdash_is_flagged() {
    let result = analyze("git checkout HEAD~5 src/");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn checkout_treeish_and_path_two_positionals_is_flagged() {
    let result = analyze("git checkout HEAD~1 file.txt");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn probe_branch_force_move_is_flagged() {
    for cmd in [
        "git branch -f main HEAD~10",
        "git branch --force main HEAD~10",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_risk_factor(a, RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
    }
}

#[test]
fn probe_switch_capital_c_is_flagged() {
    let result = analyze("git switch -C feature");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn probe_checkout_capital_b_is_flagged() {
    let result = analyze("git checkout -B feature");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn probe_restore_sw_fused_short_forms_are_flagged() {
    for cmd in ["git restore -SW file.txt", "git restore -W -S file.txt"] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_risk_factor(a, RiskFactor::GitHistoryDestruction),
            "{cmd}"
        );
    }
}

#[test]
fn probe_restore_source_with_paths_is_flagged() {
    let result = analyze("git restore --source=HEAD~1 file.txt");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

// ---- SHOULD FIX #10: old static git CommandRule left as dead fallback ----

#[test]
fn static_git_command_rule_still_resolves_for_lookup() {
    // The generic CommandRule for "git" is intentionally retained (for
    // lookup_command / custom-rules override checks) even though the
    // analyzer bypasses it for actual git invocations. Sanity check the
    // fallback lookup still works and doesn't panic.
    let rule =
        sh_guard_core::test_internals::rules::lookup_command("git").expect("git rule present");
    assert_eq!(rule.name, "git");
}

// ========================================================================
// Third review round: regression tests, one per probe command.
// ========================================================================

// ---- Round 3, #1: checkout/switch/restore false positives ----

#[test]
fn probe_checkout_branch_with_slash_is_not_flagged() {
    let result = analyze("git checkout feature/login");
    let a = first_sub(&result);
    assert!(
        !has_risk_factor(a, RiskFactor::GitHistoryDestruction),
        "got {:?}",
        a.flags
    );
    assert_eq!(a.reversibility, Reversibility::Reversible);
    assert!(
        matches!(result.level, RiskLevel::Caution),
        "score {}",
        result.score
    );
}

#[test]
fn probe_checkout_tag_like_version_is_not_flagged() {
    let result = analyze("git checkout v1.2.0");
    let a = first_sub(&result);
    assert!(
        !has_risk_factor(a, RiskFactor::GitHistoryDestruction),
        "got {:?}",
        a.flags
    );
    assert!(
        matches!(result.level, RiskLevel::Caution),
        "score {}",
        result.score
    );
}

#[test]
fn probe_checkout_dash_b_new_branch_with_slash_is_not_flagged() {
    let result = analyze("git checkout -b feature/login");
    let a = first_sub(&result);
    assert!(
        !has_risk_factor(a, RiskFactor::GitHistoryDestruction),
        "got {:?}",
        a.flags
    );
    assert!(
        matches!(result.level, RiskLevel::Caution),
        "score {}",
        result.score
    );
}

#[test]
fn probe_checkout_dash_b_new_branch_with_start_point_is_not_flagged() {
    // "-b <new-branch> <start-point>": the start-point (origin/main) is not
    // a pathspec, it's what the new branch is created from.
    let result = analyze("git checkout -b feature/login origin/main");
    let a = first_sub(&result);
    assert!(
        !has_risk_factor(a, RiskFactor::GitHistoryDestruction),
        "got {:?}",
        a.flags
    );
}

#[test]
fn checkout_switch_dash_c_with_start_point_is_not_flagged() {
    let result = analyze("git switch -c feature/x origin/main");
    let a = first_sub(&result);
    assert!(
        !has_risk_factor(a, RiskFactor::GitHistoryDestruction),
        "got {:?}",
        a.flags
    );
}

#[test]
fn restore_source_separate_token_value_with_real_path_is_flagged() {
    let result = analyze("git restore --source HEAD~1 f");
    let a = first_sub(&result);
    assert!(
        has_risk_factor(a, RiskFactor::GitHistoryDestruction),
        "got {:?}",
        a.flags
    );
}

#[test]
fn checkout_glob_pathspec_single_positional_is_flagged() {
    let result = analyze("git checkout *.rs");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn checkout_colon_slash_pathspec_is_flagged() {
    let result = analyze("git checkout :/README.md");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

// Regressions to keep flagged/unflagged from earlier rounds.

#[test]
fn regression_checkout_main_stays_caution() {
    let result = analyze("git checkout main");
    let a = first_sub(&result);
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert!(
        (21..=50).contains(&result.score),
        "score {} not in caution band",
        result.score
    );
}

#[test]
fn regression_checkout_treeish_path_stays_flagged() {
    let result = analyze("git checkout HEAD~5 src/");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn regression_checkout_dashdash_dot_stays_flagged() {
    let result = analyze("git checkout -- .");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn regression_checkout_capital_b_stays_flagged() {
    let result = analyze("git checkout -B x");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

// ---- Round 3, #2: credential leak still SAFE ----

#[test]
fn probe_credential_store_get_is_secrets_exposure() {
    let result = analyze("git credential-store get");
    let a = first_sub(&result);
    assert!(
        has_risk_factor(a, RiskFactor::SecretsExposure),
        "got {:?}",
        a.flags
    );
    assert!(
        matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
        "score {}",
        result.score
    );
}

#[test]
fn probe_credential_cache_get_is_secrets_exposure() {
    let result = analyze("git credential-cache get");
    let a = first_sub(&result);
    assert!(
        has_risk_factor(a, RiskFactor::SecretsExposure),
        "got {:?}",
        a.flags
    );
    assert!(
        matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
        "score {}",
        result.score
    );
}

#[test]
fn credential_get_after_helper_options_is_secrets_exposure() {
    for cmd in [
        "git credential-store --file=/tmp/creds get",
        "git credential-store --file /tmp/creds get",
        "git credential-cache --timeout 300 get",
        "git credential-cache --socket /tmp/sock get",
        "git credential-cache --timeout=300 --socket=/tmp/sock get",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_risk_factor(a, RiskFactor::SecretsExposure),
            "{cmd}: got {:?}",
            a.flags
        );
        assert!(
            matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
            "{cmd}: score {}",
            result.score
        );
    }
}

#[test]
fn credential_store_option_value_is_not_mistaken_for_operation() {
    // `--file get` names a file called "get"; the real operation is `erase`.
    let result = analyze("git credential-store --file get erase");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::EnvModify), "got {:?}", a.intent);
    assert!(!has_risk_factor(a, RiskFactor::SecretsExposure));
}

#[test]
fn credential_fill_is_secrets_exposure() {
    let result = analyze("git credential fill");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::SecretsExposure));
    assert!(
        matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
        "score {}",
        result.score
    );
}

#[test]
fn credential_store_erase_approve_reject_are_env_modify() {
    for cmd in [
        "git credential approve",
        "git credential reject",
        "git credential-store store",
        "git credential-cache erase",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_intent(a, Intent::EnvModify),
            "{cmd}: got {:?}",
            a.intent
        );
        assert!(!has_risk_factor(a, RiskFactor::SecretsExposure), "{cmd}");
    }
}

#[test]
fn credential_cache_exit_is_process_control() {
    let result = analyze("git credential-cache exit");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::ProcessControl), "got {:?}", a.intent);
}

#[test]
fn bare_credential_helper_is_not_safe() {
    for cmd in [
        "git credential-store",
        "git credential-cache",
        "git credential",
    ] {
        let result = analyze(cmd);
        assert_ne!(result.level, RiskLevel::Safe, "{cmd}");
    }
}

// ---- Round 3, #3: misleading reason when escalated ----

#[test]
fn probe_fsmonitor_escalation_reason_says_execution_not_information() {
    let result = analyze("git -c core.fsmonitor=./evil.sh status");
    assert!(
        result.reason.contains("Code execution")
            || result.reason.to_lowercase().contains("execution"),
        "reason: {:?}",
        result.reason
    );
    assert!(
        !result.reason.starts_with("Information command"),
        "reason: {:?}",
        result.reason
    );
    let a = first_sub(&result);
    assert_eq!(a.intent.first(), Some(&Intent::Execute));
}

#[test]
fn probe_git_pager_env_escalation_reason_says_execution() {
    let result = analyze("GIT_PAGER='sh -c id' git log");
    assert!(
        !result.reason.starts_with("Information command"),
        "reason: {:?}",
        result.reason
    );
    let a = first_sub(&result);
    assert_eq!(a.intent.first(), Some(&Intent::Execute));
}

#[test]
fn probe_config_env_escalation_reason_says_execution() {
    let result = analyze("git --config-env=core.pager=SOME_ENV status");
    assert!(
        !result.reason.starts_with("Information command"),
        "reason: {:?}",
        result.reason
    );
    let a = first_sub(&result);
    assert_eq!(a.intent.first(), Some(&Intent::Execute));
}

#[test]
fn escalated_clone_still_reports_execute_first() {
    // Base classification for clone is [Network, Write]; escalation must
    // still put Execute first for the reason string.
    let result = analyze("git -c protocol.ext.allow=always clone 'ext::sh -c id'");
    let a = first_sub(&result);
    assert_eq!(a.intent.first(), Some(&Intent::Execute));
    assert!(a.intent.contains(&Intent::Network));
}

// ---- Round 3, #4: `git rm -r --cached .` should be caution, not Delete ----

#[test]
fn probe_rm_recursive_cached_is_gitmutation_caution() {
    let result = analyze("git rm -r --cached .");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::GitMutation), "got {:?}", a.intent);
    assert!(!has_intent(a, Intent::Delete));
    assert!(!has_risk_factor(a, RiskFactor::GitHistoryDestruction));
    assert!(
        (21..=50).contains(&result.score),
        "score {} not in caution band",
        result.score
    );
}

// ---- Round 3: regressions-to-keep from the coordinator's checklist ----

#[test]
fn regression_git_status_is_zero() {
    let result = analyze("git status");
    assert_eq!(result.score, 0);
    assert_eq!(result.level, RiskLevel::Safe);
}

#[test]
fn regression_benign_dash_c_log_is_zero() {
    let result = analyze("git -c color.ui=always log");
    assert_eq!(result.score, 0);
    assert_eq!(result.level, RiskLevel::Safe);
}
