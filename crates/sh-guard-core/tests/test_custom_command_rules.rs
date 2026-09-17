//! `[[commands]]` custom rules from `.sh-guard.toml`.
//!
//! These rules used to be parsed and then ignored: the analyzer never
//! consulted them, so a project had no way to describe its own tools and
//! every invocation of one scored as an unknown binary (DANGER).

use sh_guard_core::*;

const RULES: &str = r#"
[[commands]]
name = "codebase-memory-mcp"
intent = "read"
reversibility = "reversible"

[[commands.dangerous_flags]]
flags = ["uninstall"]
modifier = 30
description = "Uninstalls the MCP server"

[[commands]]
name = "deploy"
intent = "network"
reversibility = "irreversible"
mitre = "T1072"

[[commands.dangerous_flags]]
flags = ["--production", "--force"]
modifier = 25
description = "Force deploy to production"

# Attempts to redefine commands sh-guard already classifies. A project file
# must not be able to blind the guard to its own commands.
[[commands]]
name = "rm"
intent = "info"
reversibility = "reversible"

[[commands]]
name = "git"
intent = "info"

[[commands]]
name = "sudo"
intent = "info"
"#;

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join(".sh-guard.toml"), RULES).expect("write rules");
    dir
}

fn analyze_in(dir: &tempfile::TempDir, cmd: &str) -> AnalysisResult {
    let root = dir.path().to_string_lossy().to_string();
    let ctx = ClassifyContext {
        cwd: Some(root.clone()),
        project_root: Some(root),
        home_dir: None,
        protected_paths: vec![],
        shell: Shell::Bash,
    };
    classify(cmd, Some(&ctx))
}

#[test]
fn a_custom_rule_classifies_an_unknown_program() {
    let dir = project();
    for cmd in [
        "codebase-memory-mcp cli list_projects",
        "~/.local/bin/codebase-memory-mcp cli list_projects --format json",
        "./build/c/codebase-memory-mcp cli query_graph '{}'",
    ] {
        let result = analyze_in(&dir, cmd);
        assert_eq!(result.sub_commands[0].intent, vec![Intent::Read], "{cmd}");
        assert_eq!(result.level, RiskLevel::Safe, "{cmd}: {}", result.score);
    }
}

#[test]
fn without_a_rule_the_same_program_stays_conservative() {
    let empty = tempfile::tempdir().expect("temp dir");
    let result = analyze_in(&empty, "~/.local/bin/codebase-memory-mcp cli list_projects");
    assert!(result.sub_commands[0].intent.contains(&Intent::Execute));
    assert_ne!(result.level, RiskLevel::Safe);
}

#[test]
fn custom_dangerous_flags_raise_the_score() {
    let dir = project();
    let plain = analyze_in(&dir, "codebase-memory-mcp cli query");
    let uninstall = analyze_in(&dir, "codebase-memory-mcp uninstall -y");
    assert!(uninstall.score > plain.score);

    // A flag rule needs every one of its tokens.
    let one = analyze_in(&dir, "deploy --production");
    let both = analyze_in(&dir, "deploy --production --force");
    assert!(both.score > one.score, "{} vs {}", both.score, one.score);
    assert_eq!(
        both.sub_commands[0].reversibility,
        Reversibility::Irreversible
    );
}

#[test]
fn custom_rules_carry_their_mitre_mapping() {
    let dir = project();
    let result = analyze_in(&dir, "deploy");
    assert!(result
        .mitre_mappings
        .iter()
        .any(|m| m.technique_id == "T1072"));
}

#[test]
fn custom_rules_apply_inside_wrappers_and_payloads() {
    let dir = project();
    for cmd in [
        "nohup codebase-memory-mcp cli index",
        "timeout 60 ~/.local/bin/codebase-memory-mcp cli index",
        "echo x | xargs codebase-memory-mcp cli query",
    ] {
        let result = analyze_in(&dir, cmd);
        assert!(
            !result
                .sub_commands
                .iter()
                .any(|s| s.intent.contains(&Intent::Execute)),
            "{cmd}: {:?}",
            result
                .sub_commands
                .iter()
                .map(|s| &s.intent)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn custom_rules_never_override_built_in_classification() {
    let dir = project();
    assert_eq!(analyze_in(&dir, "rm -rf /").level, RiskLevel::Critical);
    assert!(analyze_in(&dir, "git push --force").sub_commands[0]
        .risk_factors
        .contains(&RiskFactor::GitHistoryDestruction));
    assert!(analyze_in(&dir, "sudo ls").sub_commands[0]
        .risk_factors
        .contains(&RiskFactor::PrivilegeEscalation));
}

#[test]
fn rules_do_not_leak_between_classifications() {
    let dir = project();
    let _ = analyze_in(&dir, "codebase-memory-mcp cli list_projects");
    // A later classification without rules must not see the earlier ones.
    let result = classify("codebase-memory-mcp cli list_projects", None);
    assert!(result.sub_commands[0].intent.contains(&Intent::Execute));
}

#[test]
fn allow_rules_match_an_executable_invoked_by_path() {
    let rules =
        sh_guard_core::custom_rules::RuleConfig::from_toml(r#"allow = ["mytool"]"#).expect("parse");
    assert!(rules
        .is_allowed("~/.local/bin/mytool --flag", Some("~/.local/bin/mytool"))
        .is_some());
    assert!(rules.is_allowed("othertool", Some("othertool")).is_none());
}
