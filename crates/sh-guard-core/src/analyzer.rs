use crate::context;
use crate::parser::*;
use crate::rules;
use crate::rules::gtfobins;
use crate::rules::injection;
use crate::rules::zsh;
use crate::types::*;

/// Analyze parsed command segments into CommandAnalysis structs.
pub fn analyze(parsed: &ParsedCommand, ctx: Option<&ClassifyContext>) -> Vec<CommandAnalysis> {
    let shell = ctx.map(|c| c.shell).unwrap_or(Shell::Bash);

    parsed
        .segments
        .iter()
        .map(|segment| analyze_segment(segment, ctx, shell, &parsed.parse_warnings))
        .collect()
}

fn analyze_segment(
    segment: &CommandSegment,
    ctx: Option<&ClassifyContext>,
    shell: Shell,
    warnings: &[ParseWarning],
) -> CommandAnalysis {
    let executable = segment.executable.as_deref();
    let exec_base = executable.map(|e| e.rsplit('/').next().unwrap_or(e));

    // 1. Look up command rule
    let cmd_rule = executable.and_then(rules::lookup_command);

    // Some commands (git, gh, find, fd/fdfind) get subcommand/flag-aware
    // classification instead of the generic one-rule-per-executable model:
    // `git status` vs `git push --force`, `find . -name x` vs
    // `find . -exec rm -rf {} +`, etc. See `rules::classify_special`.
    let arg_values: Vec<String> = segment.args.iter().map(|a| a.value.clone()).collect();
    let env_assignments: Vec<(String, String)> = segment
        .assignments
        .iter()
        .map(|a| (a.name.clone(), a.value.clone()))
        .collect();
    let special = rules::classify_special(exec_base, &arg_values, &env_assignments);

    // 2. Determine intent
    let intent = if let Some(special) = &special {
        special.intent.clone()
    } else if let Some(rule) = cmd_rule {
        vec![rule.intent]
    } else {
        // Unknown command -- default to Execute (conservative)
        vec![Intent::Execute]
    };

    // 3. Determine reversibility
    let reversibility = if let Some(special) = &special {
        special.reversibility
    } else {
        cmd_rule
            .map(|r| r.reversibility)
            .unwrap_or(Reversibility::HardToReverse)
    };

    // 4. Look up GTFOBins capabilities
    let capabilities: Vec<BinaryCapability> = exec_base
        .map(|name| gtfobins::lookup_capabilities(name).to_vec())
        .unwrap_or_default();

    // 5. Analyze flags -- check for dangerous flag combinations
    let mut flags = vec![];
    if let Some(special) = &special {
        flags.extend(special.flags.iter().cloned());
    } else if let Some(rule) = cmd_rule {
        for flag_rule in rule.dangerous_flags {
            if flag_matches(&segment.raw, flag_rule) {
                flags.push(FlagAnalysis {
                    flag: flag_rule.flags[0].to_string(),
                    modifier: flag_rule.modifier,
                    risk_factor: flag_rule.risk_factor,
                    description: flag_rule.description.to_string(),
                });
            }
        }
    }

    // 6. Determine targets (from args that look like paths)
    let targets = extract_targets(segment, ctx, exec_base);

    // 7. Collect risk factors from flags, injection patterns, zsh rules
    let mut risk_factors: Vec<RiskFactor> = flags.iter().map(|f| f.risk_factor).collect();

    // Check injection patterns on the raw command text.
    // NOTE: We pass `raw` as both `unquoted` and `raw` because we do not yet
    // have a quote-stripping function.  This means patterns that inspect
    // `unquoted` may trigger on text that is actually inside quotes (false
    // positives).  This is the safer direction — false positives rather than
    // false negatives — so a properly quoted string may still be flagged.
    // TODO: Implement a quote-stripping pass and pass the truly unquoted text
    // as the first argument.
    let injections = injection::detect_injections(&segment.raw, &segment.raw);
    for (_, _, rf, _) in &injections {
        if !risk_factors.contains(rf) {
            risk_factors.push(*rf);
        }
    }

    // Check zsh rules if shell is Zsh
    if shell == Shell::Zsh {
        let zsh_matches = zsh::detect_zsh_patterns(&segment.raw);
        for (_, _, rf, _) in &zsh_matches {
            if !risk_factors.contains(rf) {
                risk_factors.push(*rf);
            }
        }
    }

    // Check parse warnings
    for warning in warnings {
        let rf = match warning {
            ParseWarning::ControlCharacters(_) | ParseWarning::UnicodeWhitespace(_) => {
                RiskFactor::ShellInjection
            }
            ParseWarning::AnsiCQuoting => RiskFactor::ObfuscatedCommand,
            _ => continue,
        };
        if !risk_factors.contains(&rf) {
            risk_factors.push(rf);
        }
    }

    CommandAnalysis {
        command: segment.raw.clone(),
        executable: executable.map(String::from),
        intent,
        targets,
        flags,
        score: 0, // Scorer fills this in
        risk_factors,
        reversibility,
        capabilities,
    }
}

/// Check if a command's raw text contains the flag pattern.
/// The `flags` array represents a conjunction: ALL patterns must be present.
///
/// `pub(crate)` so `rules::find_fd` can reuse it to match a `-exec`/`-x`
/// payload's own `dangerous_flags` against its (already-tokenized, quote-
/// aware) argv, exactly as it would be matched for a real top-level
/// invocation of that command.
pub(crate) fn flag_matches(raw: &str, flag_rule: &rules::FlagRule) -> bool {
    let words: Vec<&str> = raw.split_whitespace().collect();
    flag_rule.flags.iter().all(|pattern| {
        // Each pattern element must match a word in the raw text
        let parts: Vec<&str> = pattern.split_whitespace().collect();
        parts.iter().all(|part| {
            words
                .iter()
                .any(|word| *word == *part || word.starts_with(&format!("{}=", part)))
        })
    })
}

/// Extract targets from command arguments.
///
/// `exec_base` special-cases `fd`/`fdfind`: unlike `find` (where every
/// positional is a path), fd's grammar is
/// `fd [FLAGS/OPTIONS] [<pattern>] [<path>...]` -- the first positional is
/// a search *pattern*, not a path, so it must never be misread as one (see
/// `rules::find_fd::fd_target_paths`).
fn extract_targets(
    segment: &CommandSegment,
    ctx: Option<&ClassifyContext>,
    exec_base: Option<&str>,
) -> Vec<Target> {
    let mut targets = vec![];

    if matches!(exec_base, Some("fd") | Some("fdfind")) {
        let arg_values: Vec<String> = segment.args.iter().map(|a| a.value.clone()).collect();
        for val in rules::find_fd::fd_target_paths(&arg_values) {
            let scope = context::resolve_scope(&val, ctx);
            let sensitivity = context::resolve_sensitivity(&val, ctx);
            targets.push(Target {
                path: Some(val),
                scope,
                sensitivity,
            });
        }
    } else {
        for arg in &segment.args {
            // Skip flags (start with -)
            if arg.value.starts_with('-') {
                continue;
            }

            // Check if this looks like a path
            let val = &arg.value;
            if val.starts_with('/')
                || val.starts_with('.')
                || val.starts_with('~')
                || val.contains('/')
                || val == "*"
            {
                let scope = context::resolve_scope(val, ctx);
                let sensitivity = context::resolve_sensitivity(val, ctx);
                targets.push(Target {
                    path: Some(val.clone()),
                    scope,
                    sensitivity,
                });
            }
        }
    }

    // Check redirection targets too
    for redir in &segment.redirections {
        if !redir.target.is_empty() {
            let scope = context::resolve_scope(&redir.target, ctx);
            let sensitivity = context::resolve_sensitivity(&redir.target, ctx);
            targets.push(Target {
                path: Some(redir.target.clone()),
                scope,
                sensitivity,
            });
        }
    }

    // If no targets found, add a None target
    if targets.is_empty() {
        targets.push(Target {
            path: None,
            scope: TargetScope::None,
            sensitivity: Sensitivity::Normal,
        });
    }

    targets
}
