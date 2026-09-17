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

    // A bare `NAME=value` statement runs nothing. (Risky names such as
    // PATH / LD_PRELOAD are caught by the injection patterns on the raw
    // text; a `$(...)` in the value is analyzed as its own segment.)
    let assignment_only =
        executable.is_none() && !segment.assignments.is_empty() && segment.args.is_empty();
    // `<anything> --version` / `<anything> [subcommand...] --help` only
    // prints -- no matter how unfamiliar the binary is.
    // Also for interpreters with a rule of their own (`bash --version`,
    // `php -l file.php`, `node --check app.js`): describing themselves or
    // syntax-checking a file runs no program code.
    let info_probe = special.is_none()
        && cmd_rule.is_none_or(|r| r.intent == Intent::Execute)
        && (is_info_probe(&arg_values) || is_syntax_check(exec_base, &arg_values));
    // `bash -c '<script>'` / `eval '<script>'`: the parser analyzes the
    // script's commands as segments of their own, so scoring the launcher
    // as Execute on top would make `bash -c 'ls'` DANGER regardless of
    // what the script does.
    let inline_script_launcher = parser_runs_inline_script(segment);

    // A project/user `[[commands]]` rule, for a program sh-guard doesn't
    // otherwise know (it can never override a built-in classification).
    let custom = if special.is_none() && cmd_rule.is_none() && !info_probe {
        exec_base
            .and_then(crate::custom_rules::active_command)
            .map(|rule| crate::custom_rules::resolve(&rule, &arg_values))
    } else {
        None
    };

    // 2. Determine intent
    let intent = if inline_script_launcher {
        vec![Intent::Info]
    } else if let Some(special) = &special {
        special.intent.clone()
    } else if assignment_only || info_probe {
        vec![Intent::Info]
    } else if let Some(rule) = cmd_rule {
        vec![rule.intent]
    } else if let Some((custom_intent, _, _)) = &custom {
        vec![*custom_intent]
    } else {
        // Unknown command -- default to Execute (conservative)
        vec![Intent::Execute]
    };

    // 3. Determine reversibility
    let reversibility = if inline_script_launcher {
        Reversibility::Reversible
    } else if let Some(special) = &special {
        special.reversibility
    } else if assignment_only || info_probe {
        Reversibility::Reversible
    } else if let Some((_, custom_reversibility, _)) = &custom {
        *custom_reversibility
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
    } else if let Some((_, _, custom_flags)) = &custom {
        flags.extend(custom_flags.iter().cloned());
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

    if inline_script_launcher {
        flags.clear();
        flags.push(FlagAnalysis {
            flag: "-c <script>".to_string(),
            modifier: 10,
            risk_factor: RiskFactor::CommandExecution,
            description: "Runs an inline script (its commands are analyzed separately)".to_string(),
        });
    }

    // 6. Determine targets (from args that look like paths)
    let targets = extract_targets(segment, ctx, exec_base);

    // 7. Collect risk factors from flags, injection patterns, zsh rules
    // Deduplicated: two different flags can carry the same risk factor
    // (e.g. kubectl's `delete --all` and a cluster-critical namespace both
    // yield BroadScope), and the reason string would otherwise repeat it.
    let mut risk_factors: Vec<RiskFactor> = vec![];
    for f in &flags {
        if !risk_factors.contains(&f.risk_factor) {
            risk_factors.push(f.risk_factor);
        }
    }

    // Check injection patterns. Patterns about shell syntax only look at the
    // text the shell actually interprets (see `injection::shell_active_text`),
    // so `awk '{print $1}'`, a JSON argument, or a quoted heredoc body is
    // not mistaken for substitution or expansion.
    let injections = injection::detect_injections_in(&segment.raw);
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

fn parser_runs_inline_script(segment: &CommandSegment) -> bool {
    crate::parser::runs_inline_script(segment)
}

/// `php -l`, `bash -n`/`sh -n`/`zsh -n`, `node --check`/`-c`, `ruby -c`:
/// parse a file and report syntax errors without running it. (`perl -c`
/// is deliberately absent -- it still runs BEGIN blocks.)
pub(crate) fn is_syntax_check(exec_base: Option<&str>, args: &[String]) -> bool {
    let flag = match exec_base {
        Some("php") => &["-l", "--syntax-check"][..],
        Some("bash") | Some("sh") | Some("zsh") | Some("dash") | Some("ksh") => &["-n"][..],
        Some("node") | Some("nodejs") => &["--check", "-c"][..],
        Some("ruby") => &["-c"][..],
        _ => return false,
    };
    args.iter().any(|a| flag.contains(&a.as_str()))
        && !args
            .iter()
            .any(|a| matches!(a.as_str(), "-r" | "-e" | "--eval" | "-p" | "--print"))
}

/// True when an invocation only asks a program to describe itself:
/// exactly `--version` / `-V` / `version`, or a `--help` / `-h` / `help`
/// at the end of an otherwise flag-free subcommand path
/// (`tool daemon --help`).
pub(crate) fn is_info_probe(args: &[String]) -> bool {
    let cleaned: Vec<&str> = args.iter().map(|a| a.trim_matches(['\'', '"'])).collect();
    match cleaned.as_slice() {
        [only] if matches!(*only, "--version" | "-V" | "version") => true,
        [path @ .., last] if matches!(*last, "--help" | "-h" | "help") => {
            path.iter().all(|a| !a.starts_with('-'))
        }
        _ => false,
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
        // For a wrapper (`sudo`/`watch`/`ssh <host> <cmd>`/...), the payload
        // may arrive as one quoted script string, whose paths would
        // otherwise be invisible here -- so scan the payload's own tokens
        // alongside the segment's arguments.
        let mut values: Vec<String> = segment.args.iter().map(|a| a.value.clone()).collect();
        if let Some(name) = exec_base {
            if rules::wrappers::is_wrapper(name) {
                for tok in rules::wrappers::payload_tokens(name, &values) {
                    if !values.contains(&tok) {
                        values.push(tok);
                    }
                }
            }
        }

        // Option values that look like paths but name no file on disk:
        // install_name_tool's `-change OLD NEW` / `-rpath OLD NEW` / `-id NAME`
        // are dylib install names, not files being written.
        let mut skip = 0usize;
        let skip_counts: &[(&str, usize)] = if exec_base == Some("install_name_tool") {
            &[
                ("-change", 2),
                ("-rpath", 2),
                ("-id", 1),
                ("-add_rpath", 1),
                ("-delete_rpath", 1),
                ("-prepend_rpath", 1),
            ]
        } else {
            &[]
        };

        for val in &values {
            if skip > 0 {
                skip -= 1;
                continue;
            }
            if let Some((_, n)) = skip_counts.iter().find(|(flag, _)| flag == val) {
                skip = *n;
                continue;
            }
            // Skip flags (start with -)
            if val.starts_with('-') {
                continue;
            }

            // Check if this looks like a path
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
