//! `xargs` payload-aware classification tests.
//!
//! Covers `crates/sh-guard-core/src/rules/xargs.rs`: payload inheritance
//! (the payload's own intent leads instead of a flat `Intent::Execute`),
//! xargs' own option parsing (including fused and value-taking forms),
//! the pipeline consequences (a read-only payload is no longer an
//! execution sink, a shell payload still is), and the false-positive cases
//! where an option's value looks like a command.

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
// Payload inheritance
// ========================================================================

#[test]
fn read_only_payloads_are_safe() {
    // Regression: every xargs invocation used to be Intent::Execute
    // (weight 50), so `xargs ls` scored DANGER 60 -- the same as
    // `xargs rm -rf`.
    for cmd in [
        "xargs echo",
        "xargs ls",
        "xargs -n1 echo",
        "xargs -0 cat",
        "xargs grep TODO",
        // With no command at all, xargs runs `echo`.
        "xargs",
    ] {
        let result = analyze(cmd);
        assert_eq!(
            result.level,
            RiskLevel::Safe,
            "{cmd}: got {:?} ({})",
            result.level,
            result.score
        );
        assert!(
            !has_intent(first_sub(&result), Intent::Execute),
            "{cmd}: got {:?}",
            first_sub(&result).intent
        );
    }
}

#[test]
fn destructive_payloads_inherit_their_own_risk() {
    let cases: &[(&str, RiskFactor)] = &[
        ("xargs rm -rf", RiskFactor::RecursiveDelete),
        ("xargs -0 rm -rf", RiskFactor::RecursiveDelete),
        ("xargs -I {} rm -rf {}", RiskFactor::RecursiveDelete),
        ("xargs chmod 777", RiskFactor::PrivilegeEscalation),
        ("xargs git push --force", RiskFactor::GitHistoryDestruction),
        ("xargs gh repo delete o/r --yes", RiskFactor::ForceFlag),
        (
            "xargs kubectl delete namespace prod",
            RiskFactor::BroadScope,
        ),
    ];
    for (cmd, rf) in cases {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_risk_factor(a, *rf),
            "{cmd}: expected {rf:?}, got {:?}",
            a.risk_factors
        );
        assert_eq!(result.level, RiskLevel::Critical, "{cmd}: {}", result.score);
    }
}

#[test]
fn batched_deletion_is_priced_like_a_bulk_delete() {
    // `xargs rm` applies rm to every input line, so it belongs near
    // `find ... -delete`, not near a single `rm <file>`.
    let batch = analyze("xargs rm");
    let single = analyze("rm file.txt");
    assert!(
        batch.score > single.score,
        "batch {} should outscore single {}",
        batch.score,
        single.score
    );
    assert_eq!(batch.level, RiskLevel::Critical);
}

#[test]
fn unknown_payloads_stay_conservative() {
    for cmd in ["xargs ./unknown-binary", "xargs -t -P4 ./unknown-binary"] {
        let result = analyze(cmd);
        assert!(has_intent(first_sub(&result), Intent::Execute), "{cmd}");
        assert!(
            matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
            "{cmd}: got {:?} ({})",
            result.level,
            result.score
        );
    }
}

#[test]
fn shell_payloads_are_code_execution() {
    for cmd in [
        "xargs sh -c 'id'",
        "xargs bash -c 'id'",
        "xargs -I{} sh -c '{}'",
    ] {
        let result = analyze(cmd);
        assert!(
            has_intent(first_sub(&result), Intent::Execute),
            "{cmd}: got {:?}",
            first_sub(&result).intent
        );
    }
}

// ========================================================================
// xargs' own options
// ========================================================================

#[test]
fn option_values_are_not_mistaken_for_the_payload() {
    // -I's replace-string, -d's delimiter and -a's file can all be spelled
    // like a command name; the payload is the first NON-option token.
    for cmd in [
        "xargs -I rm echo {}",
        "xargs -d rm echo",
        "xargs --replace=rm echo",
        "xargs -E rm echo",
    ] {
        let result = analyze(cmd);
        assert_eq!(
            result.level,
            RiskLevel::Safe,
            "{cmd}: echo is the payload, got {:?} ({})",
            result.level,
            result.score
        );
        assert!(!has_risk_factor(
            first_sub(&result),
            RiskFactor::RecursiveDelete
        ));
    }

    // -a reads from a file instead of stdin, but the payload still leads.
    let from_file = analyze("xargs -a list.txt rm -rf");
    assert!(has_risk_factor(
        first_sub(&from_file),
        RiskFactor::RecursiveDelete
    ));
}

#[test]
fn payload_flags_belong_to_the_payload_not_to_xargs() {
    // `-rf` after `rm` is rm's, and must still be seen as rm's own
    // dangerous flag; `-n` after the payload is likewise not xargs'.
    assert!(has_risk_factor(
        first_sub(&analyze("xargs rm -rf")),
        RiskFactor::RecursiveDelete
    ));
    let grep = analyze("xargs grep -n TODO");
    assert_eq!(grep.level, RiskLevel::Safe, "{}", grep.score);
}

#[test]
fn fused_and_long_option_forms_are_handled() {
    for cmd in [
        "xargs -n1 rm -rf",
        "xargs -P8 rm -rf",
        "xargs -I{} rm -rf {}",
        "xargs --max-args=1 rm -rf",
        "xargs --null --max-procs 4 rm -rf",
        "/usr/bin/xargs rm -rf",
    ] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), RiskFactor::RecursiveDelete),
            "{cmd}: got {:?}",
            first_sub(&result).risk_factors
        );
    }
}

#[test]
fn parallel_execution_is_noted() {
    let parallel = analyze("xargs -P8 -n1 curl -O");
    let serial = analyze("xargs -n1 curl -O");
    assert!(
        parallel.score >= serial.score,
        "-P should not lower the score ({} vs {})",
        parallel.score,
        serial.score
    );
}

// ========================================================================
// Pipeline behaviour
// ========================================================================

#[test]
fn pipelines_reflect_the_payload_not_the_wrapper() {
    // Regression: `pipeline::classify_sink` treats any Intent::Execute
    // segment as an execution sink, so EVERY `... | xargs <anything>` was
    // CRITICAL "data piped to shell execution" -- including these.
    for cmd in [
        "find . -print0 | xargs -0 ls -la",
        "find . -type f | xargs grep TODO",
        "ls | xargs",
    ] {
        let result = analyze(cmd);
        assert_eq!(
            result.level,
            RiskLevel::Safe,
            "{cmd}: got {:?} ({})",
            result.level,
            result.score
        );
        assert!(
            !has_risk_factor(first_sub(&result), RiskFactor::PipeToExecution),
            "{cmd}: not an execution sink"
        );
    }

    // A shell payload is still an execution sink, and a sensitive source
    // piped into it still compounds.
    let shell_sink = analyze("cat /etc/passwd | xargs sh -c 'id'");
    assert_eq!(shell_sink.level, RiskLevel::Critical);

    // Destructive payloads keep their own severity through the pipe.
    for cmd in [
        "find . -name '*.tmp' | xargs rm",
        "find / -name '*.tmp' | xargs rm -rf",
        "echo x | xargs -t rm -rf /",
    ] {
        assert_eq!(analyze(cmd).level, RiskLevel::Critical, "{cmd}");
    }
}
