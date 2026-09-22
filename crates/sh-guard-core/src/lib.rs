pub mod types;
pub use types::*;

#[doc(hidden)]
pub mod analyzer;
#[doc(hidden)]
pub mod context;
pub mod custom_rules;
pub(crate) mod parser;
#[doc(hidden)]
pub mod parser_fallback;
#[doc(hidden)]
pub mod pipeline;
#[doc(hidden)]
pub mod rules;
#[doc(hidden)]
pub mod scorer;

#[doc(hidden)]
pub mod test_internals {
    pub use crate::analyzer;
    pub use crate::context;
    pub use crate::parser::*;
    pub use crate::parser_fallback;
    pub use crate::pipeline;
    pub use crate::rules;
    pub use crate::scorer;
}

/// Classify a shell command with an explicit set of rules.
pub fn classify_with_rules(
    command: &str,
    context: Option<&ClassifyContext>,
    rules_config: Option<&custom_rules::RuleConfig>,
) -> AnalysisResult {
    classify_inner(command, context, rules_config)
}

/// Risk factors that an untrusted project's rules may not soften away: they
/// describe the *invocation* as dangerous, not the tool as ordinary.
///
/// Allowing a tool says "this program is part of how we work"; from a file
/// that arrived with a checkout, it cannot also say "and whatever it does
/// with it is fine".
fn is_severe_risk_factor(factor: &RiskFactor) -> bool {
    matches!(
        factor,
        RiskFactor::RecursiveDelete
            | RiskFactor::SecretsExposure
            | RiskFactor::NetworkExfiltration
            | RiskFactor::PipeToExecution
            | RiskFactor::UntrustedExecution
            | RiskFactor::PrivilegeEscalation
            | RiskFactor::PathInjection
            | RiskFactor::GitHistoryDestruction
            | RiskFactor::EscapesProjectBoundary
            | RiskFactor::ShellInjection
            | RiskFactor::ZshModuleLoading
            | RiskFactor::ZshGlobExecution
            | RiskFactor::ObfuscatedCommand
            | RiskFactor::ObfuscatedExfiltration
            | RiskFactor::CommandSubstitution
            | RiskFactor::ProcessSubstitution
    )
}

/// The floor an untrusted project's rules may soften a segment to.
const UNTRUSTED_SCORE_FLOOR: u8 = 21;

/// Apply the decision and score effects of every rule that matches a
/// scored segment, honoring the trust rails: raising risk is always
/// allowed; lowering it is limited for rules that came with the project.
///
/// Returns the decision the whole command ended up with, if any.
fn apply_rule_effects(
    analyses: &mut [CommandAnalysis],
    context: Option<&ClassifyContext>,
    shell: Shell,
) -> Option<(custom_rules::Decision, String)> {
    let mut decision: Option<(custom_rules::Decision, String)> = None;

    for analysis in analyses.iter_mut() {
        let match_ctx = custom_rules::MatchContext {
            executable: analysis.executable.clone().unwrap_or_default(),
            subcommands: custom_rules::subcommand_path(&split_args(&analysis.command)),
            flags: custom_rules::flag_pairs(&split_args(&analysis.command)),
            args: split_args(&analysis.command),
            paths: analysis
                .targets
                .iter()
                .filter_map(|t| t.path.clone())
                .collect(),
            intents: analysis.intent.clone(),
            risk_factors: analysis.risk_factors.clone(),
            env: vec![],
            cwd: context.and_then(|c| c.cwd.clone()),
            project: context.and_then(|c| c.project_root.clone()),
            shell,
        };

        let severe = analysis.risk_factors.iter().any(is_severe_risk_factor);

        for rule in custom_rules::effects_for(&match_ctx) {
            let trusted = rule.trust == custom_rules::Trust::Full;
            let reason = rule
                .then
                .reason
                .clone()
                .unwrap_or_else(|| format!("Custom rule: {}", rule.name));

            if let Some(effect) = rule.then.score {
                let mut score = analysis.score;
                if let Some(set) = effect.set {
                    score = set;
                }
                if let Some(raise) = effect.raise {
                    score = score.saturating_add(raise).min(100);
                }
                if let Some(cap) = effect.cap {
                    score = score.min(cap);
                }
                analysis.score = bounded(analysis.score, score, trusted, severe);
            }

            match rule.then.decision {
                Some(custom_rules::Decision::Block) => {
                    // A block always applies, and always wins.
                    analysis.score = 100;
                    decision = Some((custom_rules::Decision::Block, reason));
                }
                Some(custom_rules::Decision::Allow) => {
                    let lowered = bounded(analysis.score, 0, trusted, severe);
                    analysis.score = lowered;
                    if lowered == 0 && !matches!(decision, Some((custom_rules::Decision::Block, _)))
                    {
                        decision = Some((custom_rules::Decision::Allow, reason));
                    }
                }
                None => {}
            }
        }
    }

    decision
}

/// What a rule is allowed to move a segment's score to.
///
/// Raising is always permitted. Lowering is permitted outright for rules
/// the user trusts; a project's own rules may only soften a segment to
/// [`UNTRUSTED_SCORE_FLOOR`], and not at all once the invocation carries a
/// severe risk factor of its own.
fn bounded(current: u8, proposed: u8, trusted: bool, severe: bool) -> u8 {
    if proposed >= current {
        return proposed;
    }
    if trusted {
        return proposed;
    }
    if severe {
        return current;
    }
    proposed.max(UNTRUSTED_SCORE_FLOOR).min(current)
}

/// Best-effort argv for a segment's raw text, for rule matching.
fn split_args(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .skip(1)
        .map(String::from)
        .collect()
}

/// Classify a shell command and return a rich analysis.
pub fn classify(command: &str, context: Option<&ClassifyContext>) -> AnalysisResult {
    // Auto-discovered rules get the same treatment as rules passed
    // explicitly: allow/block entries are honored too, not just command,
    // path and override rules.
    let discovered = custom_rules::RuleConfig::discover(context);
    classify_with_rules(command, context, discovered.as_ref())
}

fn classify_inner(
    command: &str,
    context: Option<&ClassifyContext>,
    rules_config: Option<&custom_rules::RuleConfig>,
) -> AnalysisResult {
    custom_rules::with_active(rules_config, || {
        classify_active(command, context, rules_config)
    })
}

fn classify_active(
    command: &str,
    context: Option<&ClassifyContext>,
    rules_config: Option<&custom_rules::RuleConfig>,
) -> AnalysisResult {
    let shell = context.map(|c| c.shell).unwrap_or(Shell::Bash);

    // 1. Parse
    let parsed = parser::parse(command, shell);

    // 2. Determine parse confidence
    let parse_confidence = if parsed
        .parse_warnings
        .iter()
        .any(|w| matches!(w, parser::ParseWarning::TreeSitterError(_)))
    {
        if parsed.segments.len() <= 1
            && parsed
                .segments
                .first()
                .is_none_or(|s| s.executable.is_none())
        {
            ParseConfidence::Fallback
        } else {
            ParseConfidence::Partial
        }
    } else {
        ParseConfidence::Full
    };

    // 3. Analyze
    let mut analyses = analyzer::analyze(&parsed, context);

    // 4. Score each segment
    for analysis in &mut analyses {
        scorer::score_command(analysis, context);
    }

    // 5. Apply the decision and score effects of matching custom rules
    let rule_decision = if rules_config.is_some() {
        apply_rule_effects(&mut analyses, context, shell)
    } else {
        None
    };

    // 6. Pipeline analysis
    let pipeline_flow = pipeline::analyze_pipeline(&analyses, &parsed.chain_operators);

    // 6. Compute final score
    let segment_max = analyses.iter().map(|a| a.score).max().unwrap_or(0);
    let final_score = if let Some(ref pf) = pipeline_flow {
        pf.composite_score.max(segment_max)
    } else {
        segment_max
    };

    // Add parse confidence penalty
    let final_score = match parse_confidence {
        ParseConfidence::Fallback => (final_score as u16 + 10).min(100) as u8,
        ParseConfidence::Partial => (final_score as u16 + 5).min(100) as u8,
        ParseConfidence::Full => final_score,
    };

    let level = RiskLevel::from_score(final_score);
    let quick_decision = match rule_decision {
        Some((custom_rules::Decision::Block, _)) => QuickDecision::Blocked,
        Some((custom_rules::Decision::Allow, _)) => QuickDecision::Safe,
        None => QuickDecision::from_level(level),
    };

    // Collect all risk factors
    let mut all_risk_factors: Vec<RiskFactor> = analyses
        .iter()
        .flat_map(|a| a.risk_factors.iter().copied())
        .collect();
    all_risk_factors.sort_by_key(|r| format!("{:?}", r));
    all_risk_factors.dedup();

    // Collect MITRE mappings from matching command rules
    let mut mitre_mappings = vec![];
    for analysis in &analyses {
        if let Some(exec) = &analysis.executable {
            let mitre_id = rules::lookup_command(exec)
                .and_then(|rule| rule.mitre.map(String::from))
                .or_else(|| custom_rules::active_mitre(exec, &analysis.command));
            if let Some(mitre_id) = mitre_id.as_deref() {
                let mapping = MitreMapping {
                    technique_id: mitre_id.to_string(),
                    technique_name: get_mitre_name(mitre_id),
                    tactic: get_mitre_tactic(mitre_id),
                };
                if !mitre_mappings
                    .iter()
                    .any(|m: &MitreMapping| m.technique_id == mapping.technique_id)
                {
                    mitre_mappings.push(mapping);
                }
            }
        }
    }

    // Generate reason
    let reason = if analyses.len() == 1 {
        scorer::generate_reason(&analyses[0])
    } else {
        let reasons: Vec<String> = analyses.iter().map(scorer::generate_reason).collect();
        if let Some(ref pf) = pipeline_flow {
            if !pf.taint_flows.is_empty() {
                let taint_desc = &pf.taint_flows[0].escalation_reason;
                format!("Pipeline: {}; {}", reasons.join(" | "), taint_desc)
            } else {
                reasons.join(" | ")
            }
        } else {
            reasons.join(" ; ")
        }
    };

    // A rule that decided the outcome explains it in its own words.
    let reason = match &rule_decision {
        Some((_, rule_reason)) => rule_reason.clone(),
        None => reason,
    };

    AnalysisResult {
        command: command.to_string(),
        score: final_score,
        level,
        quick_decision,
        reason,
        risk_factors: all_risk_factors,
        sub_commands: analyses,
        pipeline_flow,
        mitre_mappings,
        parse_confidence,
    }
}

/// Quick: just the risk score (0-100).
pub fn risk_score(command: &str) -> u8 {
    classify(command, None).score
}

/// Quick: just the risk level.
pub fn risk_level(command: &str) -> RiskLevel {
    classify(command, None).level
}

/// Batch: classify multiple commands.
/// Discovers custom rules once and reuses them for all commands.
pub fn classify_batch(commands: &[&str], context: Option<&ClassifyContext>) -> Vec<AnalysisResult> {
    let discovered = custom_rules::RuleConfig::discover(context);
    commands
        .iter()
        .map(|cmd| classify_with_rules(cmd, context, discovered.as_ref()))
        .collect()
}

fn get_mitre_name(id: &str) -> String {
    match id {
        "T1059.004" => "Command and Scripting Interpreter: Unix Shell".to_string(),
        "T1070.004" => "Indicator Removal: File Deletion".to_string(),
        "T1105" => "Ingress Tool Transfer".to_string(),
        "T1041" => "Exfiltration Over C2 Channel".to_string(),
        "T1204.002" => "User Execution: Malicious File".to_string(),
        "T1132.001" => "Data Encoding: Standard Encoding".to_string(),
        "T1074.001" => "Data Staged: Local Data Staging".to_string(),
        "T1048" => "Exfiltration Over Alternative Protocol".to_string(),
        "T1027" => "Obfuscated Files or Information".to_string(),
        "T1027.010" => "Obfuscated Files: Command Obfuscation".to_string(),
        "T1548.001" => "Abuse Elevation: Setuid and Setgid".to_string(),
        "T1222.002" => "File and Directory Permissions Modification: Linux".to_string(),
        "T1021.004" => "Remote Services: SSH".to_string(),
        "T1098" => "Account Manipulation".to_string(),
        "T1053.003" => "Scheduled Task/Job: Cron".to_string(),
        "T1195" => "Supply Chain Compromise".to_string(),
        "T1610" => "Deploy Container".to_string(),
        "T1543" => "Create or Modify System Process".to_string(),
        "T1562.001" => "Impair Defenses: Disable or Modify Tools".to_string(),
        _ => format!("MITRE ATT&CK {}", id),
    }
}

fn get_mitre_tactic(id: &str) -> String {
    match id {
        "T1059.004" => "Execution".to_string(),
        "T1070.004" => "Defense Evasion".to_string(),
        "T1105" => "Command and Control".to_string(),
        "T1041" | "T1048" => "Exfiltration".to_string(),
        "T1204.002" => "Execution".to_string(),
        "T1132.001" | "T1027" | "T1027.010" => "Defense Evasion".to_string(),
        "T1074.001" => "Collection".to_string(),
        "T1548.001" | "T1222.002" => "Privilege Escalation".to_string(),
        "T1021.004" => "Lateral Movement".to_string(),
        "T1098" => "Persistence".to_string(),
        "T1053.003" => "Execution".to_string(),
        "T1195" => "Supply Chain Compromise".to_string(),
        "T1610" => "Execution".to_string(),
        "T1543" => "Persistence".to_string(),
        "T1562.001" => "Defense Evasion".to_string(),
        _ => "Unknown".to_string(),
    }
}
