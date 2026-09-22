use crate::types::*;

pub mod cli_args;
pub mod commands;
pub mod find_fd;
pub mod gh;
pub mod git;
pub mod gtfobins;
pub mod injection;
pub mod kubectl;
pub mod network;
pub mod paths;
pub mod subcommands;
pub mod wrappers;
pub mod xargs;
pub mod zsh;

/// A rule defining the risk profile of a known command.
#[derive(Debug, Clone)]
pub struct CommandRule {
    pub name: &'static str,
    pub intent: Intent,
    pub base_weight: u8,
    pub reversibility: Reversibility,
    pub capabilities: &'static [BinaryCapability],
    pub dangerous_flags: &'static [FlagRule],
    pub mitre: Option<&'static str>,
}

/// A rule for a dangerous flag combination.
#[derive(Debug, Clone)]
pub struct FlagRule {
    pub flags: &'static [&'static str],
    pub modifier: i8,
    pub risk_factor: RiskFactor,
    pub description: &'static str,
}

/// Look up a command rule by executable name.
pub fn lookup_command(name: &str) -> Option<&'static CommandRule> {
    // Strip path prefix: /usr/bin/ls -> ls
    let base = name.rsplit('/').next().unwrap_or(name);
    commands::COMMAND_RULES.iter().find(|r| r.name == base)
}

/// Result of one of the subcommand-aware classifiers (`git`, `gh`,
/// `find_fd`, `kubectl`). They all share this shape; this common type lets
/// `classify_special` dispatch to whichever applies without `analyzer.rs`
/// needing a separate `if let` chain (and a separate intent/reversibility/
/// flags assembly step) per tool.
pub struct SpecialClassification {
    pub intent: Vec<Intent>,
    pub reversibility: Reversibility,
    pub flags: Vec<FlagAnalysis>,
}

impl From<git::GitClassification> for SpecialClassification {
    fn from(c: git::GitClassification) -> Self {
        SpecialClassification {
            intent: c.intent,
            reversibility: c.reversibility,
            flags: c.flags,
        }
    }
}

impl From<gh::GhClassification> for SpecialClassification {
    fn from(c: gh::GhClassification) -> Self {
        SpecialClassification {
            intent: c.intent,
            reversibility: c.reversibility,
            flags: c.flags,
        }
    }
}

impl From<kubectl::KubectlClassification> for SpecialClassification {
    fn from(c: kubectl::KubectlClassification) -> Self {
        SpecialClassification {
            intent: c.intent,
            reversibility: c.reversibility,
            flags: c.flags,
        }
    }
}

impl From<subcommands::SubcommandClassification> for SpecialClassification {
    fn from(c: subcommands::SubcommandClassification) -> Self {
        SpecialClassification {
            intent: c.intent,
            reversibility: c.reversibility,
            flags: c.flags,
        }
    }
}

impl From<wrappers::WrapperClassification> for SpecialClassification {
    fn from(c: wrappers::WrapperClassification) -> Self {
        SpecialClassification {
            intent: c.intent,
            reversibility: c.reversibility,
            flags: c.flags,
        }
    }
}

impl From<xargs::XargsClassification> for SpecialClassification {
    fn from(c: xargs::XargsClassification) -> Self {
        SpecialClassification {
            intent: c.intent,
            reversibility: c.reversibility,
            flags: c.flags,
        }
    }
}

impl From<find_fd::FindFdClassification> for SpecialClassification {
    fn from(c: find_fd::FindFdClassification) -> Self {
        SpecialClassification {
            intent: c.intent,
            reversibility: c.reversibility,
            flags: c.flags,
        }
    }
}

/// Classify a command that gets subcommand/flag-aware treatment instead of
/// the generic one-rule-per-executable `CommandRule` model, keyed off the
/// executable's basename (`exec_base`, i.e. with any path prefix already
/// stripped). Returns `None` for anything else, in which case the caller
/// should fall back to `lookup_command`.
pub fn classify_special(
    exec_base: Option<&str>,
    args: &[String],
    env_assignments: &[(String, String)],
) -> Option<SpecialClassification> {
    match exec_base {
        Some("git") => Some(git::classify(args, env_assignments).into()),
        Some("gh") => Some(gh::classify(args, env_assignments).into()),
        Some("find") => Some(find_fd::classify_find(args).into()),
        Some("fd") | Some("fdfind") => Some(find_fd::classify_fd(args).into()),
        Some("kubectl") => Some(kubectl::classify(args, env_assignments).into()),
        Some("xargs") => Some(xargs::classify(args).into()),
        Some(name) if subcommands::is_subcommand_tool(name) => {
            subcommands::classify(name, args).map(Into::into)
        }
        Some(name) if wrappers::is_wrapper(name) => wrappers::classify(name, args).map(Into::into),
        _ => None,
    }
}
