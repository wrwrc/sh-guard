use crate::types::*;
use std::path::Path;

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
        _ => None,
    }
}

// ========================================================
// RuleSet: aggregated access to all rule tables
// ========================================================

/// A user-defined command rule loaded from TOML configuration.
#[derive(Debug, Clone)]
pub struct UserCommandRule {
    pub name: String,
    pub intent: Intent,
    pub base_weight: u8,
    pub reversibility: Reversibility,
}

/// Aggregated access to all rule tables, including optional user-defined rules.
pub struct RuleSet {
    pub user_commands: Vec<UserCommandRule>,
    pub user_paths: Vec<paths::PathRule>,
}

impl RuleSet {
    /// Create a RuleSet with only built-in rules (no user rules).
    pub fn builtin() -> Self {
        RuleSet {
            user_commands: vec![],
            user_paths: vec![],
        }
    }

    /// Load user rules from a TOML file, merging with built-in rules.
    /// User rules can only ADD commands/paths, not override built-in ones.
    pub fn with_user_rules(toml_path: &Path) -> Self {
        let mut ruleset = Self::builtin();
        if let Ok(content) = std::fs::read_to_string(toml_path) {
            // Parse TOML — best effort, ignore parse errors
            if let Ok(table) = content.parse::<toml::Table>() {
                Self::load_user_commands(&mut ruleset, &table);
                Self::load_user_paths(&mut ruleset, &table);
            }
        }
        ruleset
    }

    fn load_user_commands(ruleset: &mut RuleSet, table: &toml::Table) {
        let Some(cmds) = table.get("commands").and_then(|v| v.as_array()) else {
            return;
        };
        for cmd in cmds {
            let Some(tbl) = cmd.as_table() else { continue };
            let name = tbl
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() || lookup_command(&name).is_some() {
                continue; // Skip empty or built-in override attempts
            }
            let intent = parse_intent(tbl.get("intent").and_then(|v| v.as_str()));
            let base_weight = tbl
                .get("base_weight")
                .and_then(|v| v.as_integer())
                .map(|v| v.clamp(0, 100) as u8)
                .unwrap_or(intent.weight());
            let reversibility =
                parse_reversibility(tbl.get("reversibility").and_then(|v| v.as_str()));
            ruleset.user_commands.push(UserCommandRule {
                name,
                intent,
                base_weight,
                reversibility,
            });
        }
    }

    fn load_user_paths(ruleset: &mut RuleSet, table: &toml::Table) {
        let Some(path_arr) = table.get("paths").and_then(|v| v.as_array()) else {
            return;
        };
        for entry in path_arr {
            let Some(tbl) = entry.as_table() else {
                continue;
            };
            let pattern = tbl.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            if pattern.is_empty() {
                continue;
            }
            let sensitivity = match tbl.get("sensitivity").and_then(|v| v.as_str()) {
                Some("secrets") => Sensitivity::Secrets,
                Some("system") => Sensitivity::System,
                Some("config") => Sensitivity::Config,
                Some("protected") => Sensitivity::Protected,
                _ => Sensitivity::Normal,
            };
            let description = tbl
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("User-defined path rule");
            // PathRule uses &'static str, so we leak the strings to get 'static lifetime.
            // This is acceptable for user rules loaded once at startup.
            let pattern_leaked: &'static str = Box::leak(pattern.to_string().into_boxed_str());
            let desc_leaked: &'static str = Box::leak(description.to_string().into_boxed_str());
            ruleset.user_paths.push(paths::PathRule {
                pattern: pattern_leaked,
                sensitivity,
                description: desc_leaked,
            });
        }
    }

    /// Look up a command in user rules (returns None if not found;
    /// caller should fall back to built-in lookup).
    pub fn lookup_user_command(&self, name: &str) -> Option<&UserCommandRule> {
        let base = name.rsplit('/').next().unwrap_or(name);
        self.user_commands.iter().find(|r| r.name == base)
    }
}

fn parse_intent(s: Option<&str>) -> Intent {
    match s {
        Some("read") => Intent::Read,
        Some("write") => Intent::Write,
        Some("delete") => Intent::Delete,
        Some("execute") => Intent::Execute,
        Some("network") => Intent::Network,
        Some("privilege") => Intent::Privilege,
        Some("search") => Intent::Search,
        Some("info") => Intent::Info,
        Some("package_install") => Intent::PackageInstall,
        Some("git_mutation") => Intent::GitMutation,
        Some("env_modify") => Intent::EnvModify,
        Some("process_control") => Intent::ProcessControl,
        _ => Intent::Execute, // default to high-weight intent
    }
}

fn parse_reversibility(s: Option<&str>) -> Reversibility {
    match s {
        Some("reversible") => Reversibility::Reversible,
        Some("hard_to_reverse") => Reversibility::HardToReverse,
        Some("irreversible") => Reversibility::Irreversible,
        _ => Reversibility::HardToReverse,
    }
}
