//! Custom rules — one `[[rules]]` table for everything a user or project
//! wants to say about how commands should be judged.
//!
//! A rule is `when` (conditions) plus `then` (effects):
//!
//! ```toml
//! version = 2
//!
//! [[rules]]
//! name = "local clusters are disposable"
//! when = { command = "kubectl", flag = { context = ["kind-*", "minikube"] } }
//! then = { decision = "allow", reason = "throwaway local cluster" }
//! ```
//!
//! Keys inside `when` are ANDed; a list inside one key is ORed. Every
//! string is a glob (`*`, `?`) unless it starts with `regex:`.
//!
//! Effects can raise risk (`block`, `score.raise`, a stricter `intent`)
//! from any rules file. Lowering risk (`allow`, `score.set`/`score.cap`
//! below the computed score, describing an unknown program as harmless) is
//! limited by where the file came from: a project's own `.sh-guard.toml`
//! is not trusted unless the user's file lists that project under `trust`.
//! See [`Trust`].

use crate::types::*;
use std::path::{Path, PathBuf};

// ========================================================
// Configuration
// ========================================================

/// The rules in effect for one classification: the user's own rules plus
/// the project's, each tagged with how far they are trusted.
#[derive(Debug, Clone, Default)]
pub struct RuleConfig {
    pub rules: Vec<Rule>,
    /// Project roots (globs) whose own rules file is fully trusted.
    pub trust: Vec<Pattern>,
}

/// How far a rule may go when it lowers risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Trust {
    /// From the user's own rules file, or a project they listed under
    /// `trust`: may lower risk without limit.
    Full,
    /// From a project's `.sh-guard.toml`: may raise risk freely, but may
    /// only soften a command down to caution, and never one that carries a
    /// severe risk factor.
    #[default]
    Project,
}

#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub name: String,
    pub when: When,
    pub then: Then,
    pub trust: Trust,
}

#[derive(Debug, Clone, Default)]
pub struct When {
    pub command: Vec<Pattern>,
    pub subcommand: Vec<Pattern>,
    pub flag: Vec<FlagCondition>,
    pub arg: Vec<Pattern>,
    pub path: Vec<Pattern>,
    pub intent: Vec<Intent>,
    pub risk_factor: Vec<RiskFactor>,
    pub env: Vec<FlagCondition>,
    pub cwd: Vec<Pattern>,
    pub project: Vec<Pattern>,
    pub shell: Option<Shell>,
}

impl When {
    /// A rule that only talks about paths (and where the command runs) is
    /// evaluated while resolving a target's sensitivity, before the
    /// command itself has been classified.
    fn is_path_only(&self) -> bool {
        !self.path.is_empty()
            && self.command.is_empty()
            && self.subcommand.is_empty()
            && self.flag.is_empty()
            && self.arg.is_empty()
            && self.intent.is_empty()
            && self.risk_factor.is_empty()
            && self.env.is_empty()
    }
}

/// `flag = { context = "kind-*" }` / `{ force = true }`, and the same
/// shape for `env`.
#[derive(Debug, Clone)]
pub struct FlagCondition {
    pub name: String,
    /// `None` means "present, whatever its value".
    pub values: Option<Vec<Pattern>>,
}

#[derive(Debug, Clone, Default)]
pub struct Then {
    pub decision: Option<Decision>,
    pub intent: Option<Intent>,
    pub reversibility: Option<Reversibility>,
    pub sensitivity: Option<Sensitivity>,
    pub mitre: Option<String>,
    pub score: Option<ScoreEffect>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScoreEffect {
    pub set: Option<u8>,
    pub raise: Option<u8>,
    pub cap: Option<u8>,
}

/// A glob (`*`, `?`) or, with the `regex:` prefix, a regular expression.
#[derive(Debug, Clone)]
pub enum Pattern {
    Glob(String),
    Regex(Box<regex::Regex>),
}

impl Pattern {
    /// Like [`Pattern::parse`], but reports a `regex:` pattern that does not
    /// compile instead of turning it into one that matches nothing.
    pub fn try_parse(text: &str) -> Result<Self, String> {
        match text.strip_prefix("regex:") {
            Some(expr) => regex::Regex::new(expr)
                .map(|re| Pattern::Regex(Box::new(re)))
                .map_err(|e| e.to_string()),
            None => Ok(Pattern::Glob(text.to_string())),
        }
    }

    pub fn parse(text: &str) -> Self {
        match text.strip_prefix("regex:") {
            Some(expr) => match regex::Regex::new(expr) {
                Ok(re) => Pattern::Regex(Box::new(re)),
                // An unparseable regex matches nothing rather than
                // everything: a broken rule must not widen anything.
                Err(_) => Pattern::Glob("\0never\0".to_string()),
            },
            None => Pattern::Glob(text.to_string()),
        }
    }

    pub fn matches(&self, text: &str) -> bool {
        match self {
            Pattern::Glob(glob) => glob_match(glob, text),
            Pattern::Regex(re) => re.is_match(text),
        }
    }

    /// Match a path the way path rules do: a pattern without a separator
    /// matches the file name anywhere, one with a separator the whole path.
    pub fn matches_path(&self, path: &str) -> bool {
        let normalized = path.trim_start_matches("./");
        match self {
            Pattern::Glob(glob) if !glob.contains('/') => {
                let basename = normalized.rsplit('/').next().unwrap_or(normalized);
                glob_match(glob, basename)
            }
            _ => self.matches(normalized) || self.matches(path),
        }
    }
}

// ========================================================
// Loading
// ========================================================

impl RuleConfig {
    /// Load one rules file. `trust` says how far its risk-lowering effects
    /// are honored.
    pub fn from_file(path: &Path, trust: Trust) -> Option<Self> {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                warn(format!("cannot read {}: {}", path.display(), e));
                return None;
            }
        };
        Self::from_toml_named(&content, trust, &path.display().to_string())
    }

    pub fn from_toml(content: &str, trust: Trust) -> Option<Self> {
        Self::from_toml_named(content, trust, "rules")
    }

    /// `source` names the file in any warning, so a person can tell which
    /// of their two rules files a complaint is about.
    pub fn from_toml_named(content: &str, trust: Trust, source: &str) -> Option<Self> {
        let table: toml::Table = match content.parse() {
            Ok(table) => table,
            // One syntax error used to discard every rule in the file
            // without a word, which reads exactly like a rule that does
            // not match.
            Err(e) => {
                warn(format!("{}: ignoring the whole file — {}", source, e));
                return None;
            }
        };
        let mut config = RuleConfig::default();

        for item in table
            .get("trust")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            if let Some(s) = item.as_str() {
                match Pattern::try_parse(&expand_tilde(s)) {
                    Ok(pattern) => config.trust.push(pattern),
                    // Skipping it can only trust fewer projects, never more.
                    Err(e) => warn(format!(
                        "{}: trust = \"{}\" is not a valid pattern — entry ignored: {}",
                        source, s, e
                    )),
                }
            }
        }

        for item in table
            .get("rules")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let Some(tbl) = item.as_table() else { continue };
            let name = tbl
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed rule")
                .to_string();
            let where_ = format!("{}: rule \"{}\"", source, name);

            // An unrecognized value in the vocabulary is a typo, and a
            // rule built on one would not mean what it says.
            let (when, then) = match (
                parse_when(tbl.get("when").and_then(|v| v.as_table()), &where_),
                parse_then(tbl.get("then").and_then(|v| v.as_table()), &where_),
            ) {
                (Some(when), Some(then)) => (when, then),
                _ => continue,
            };

            // A rule with no conditions would match everything; a rule with
            // no effects does nothing. Both are mistakes, not licences.
            if when.is_empty() {
                warn(format!("{} has no conditions — ignored", where_));
                continue;
            }
            if then.is_empty() {
                warn(format!(
                    "{} has no effect — ignored. `reason` alone does nothing; \
                     pair it with decision, score, intent, reversibility or \
                     sensitivity",
                    where_
                ));
                continue;
            }
            config.rules.push(Rule {
                name,
                when,
                then,
                trust,
            });
        }

        Some(config)
    }

    /// Load the user's rules and the project's, in that order.
    ///
    /// The user's file may mark project roots as trusted; a project's own
    /// file is otherwise limited (see [`Trust`]).
    pub fn discover(ctx: Option<&ClassifyContext>) -> Option<Self> {
        let user = home()
            .map(|h| h.join(".config/sh-guard/rules.toml"))
            .filter(|p| p.exists())
            .and_then(|p| Self::from_file(&p, Trust::Full));

        let project_root = ctx
            .and_then(|c| c.project_root.as_ref().or(c.cwd.as_ref()))
            .map(|p| crate::context::normalize_path(p));
        let trusted_project = match (&user, &project_root) {
            (Some(user), Some(root)) => user.trust.iter().any(|p| p.matches(root)),
            _ => false,
        };

        let project = [
            ctx.and_then(|c| c.project_root.as_ref()),
            ctx.and_then(|c| c.cwd.as_ref()),
        ]
        .into_iter()
        .flatten()
        .map(|p| Path::new(p).join(".sh-guard.toml"))
        .find(|p| p.exists())
        .and_then(|p| {
            Self::from_file(
                &p,
                if trusted_project {
                    Trust::Full
                } else {
                    Trust::Project
                },
            )
        });

        match (user, project) {
            (None, None) => None,
            (user, project) => {
                let mut merged = RuleConfig::default();
                // Project rules first, then the user's: later rules win a
                // conflict, and the user's word is final.
                if let Some(project) = project {
                    merged.rules.extend(project.rules);
                }
                if let Some(user) = user {
                    merged.trust = user.trust;
                    merged.rules.extend(user.rules);
                }
                Some(merged)
            }
        }
    }
}

fn parse_when(table: Option<&toml::Table>, where_: &str) -> Option<When> {
    let mut when = When::default();
    let Some(table) = table else {
        return Some(when);
    };

    when.command = patterns(table.get("command"), "command", where_)?;
    when.subcommand = patterns(table.get("subcommand"), "subcommand", where_)?;
    when.arg = patterns(table.get("arg"), "arg", where_)?;
    when.path = patterns(table.get("path"), "path", where_)?;
    when.cwd = patterns(table.get("cwd"), "cwd", where_)?;
    when.project = patterns(table.get("project"), "project", where_)?;
    when.flag = flag_conditions(table.get("flag"), "flag", where_)?;
    when.env = flag_conditions(table.get("env"), "env", where_)?;
    when.intent = vocabulary(table.get("intent"), "intent", where_)?;
    when.risk_factor = vocabulary(table.get("risk_factor"), "risk_factor", where_)?;
    when.shell = match table.get("shell").and_then(|v| v.as_str()) {
        Some("zsh") => Some(Shell::Zsh),
        Some("bash") => Some(Shell::Bash),
        Some(other) => {
            warn(format!(
                "{}: shell = \"{}\" is not bash or zsh — rule ignored",
                where_, other
            ));
            return None;
        }
        None => None,
    };
    Some(when)
}

/// Parse every string under `key` as vocabulary term `T`, refusing the
/// whole rule if any of them is not a term.
fn vocabulary<T: serde::de::DeserializeOwned>(
    value: Option<&toml::Value>,
    key: &str,
    where_: &str,
) -> Option<Vec<T>> {
    let mut parsed = Vec::new();
    for text in strings(value) {
        match parse_enum(&text) {
            Some(term) => parsed.push(term),
            None => {
                warn(format!(
                    "{}: {} = \"{}\" is not a known value — rule ignored",
                    where_, key, text
                ));
                return None;
            }
        }
    }
    Some(parsed)
}

impl When {
    fn is_empty(&self) -> bool {
        self.command.is_empty()
            && self.subcommand.is_empty()
            && self.flag.is_empty()
            && self.arg.is_empty()
            && self.path.is_empty()
            && self.intent.is_empty()
            && self.risk_factor.is_empty()
            && self.env.is_empty()
            && self.cwd.is_empty()
            && self.project.is_empty()
            && self.shell.is_none()
    }
}

impl Then {
    /// `reason` is deliberately not an effect: it only ever replaces the
    /// text of a decision another effect makes. `mitre` is one — it adds a
    /// technique mapping to the result on its own.
    fn is_empty(&self) -> bool {
        self.decision.is_none()
            && self.intent.is_none()
            && self.reversibility.is_none()
            && self.sensitivity.is_none()
            && self.score.is_none()
            && self.mitre.is_none()
    }
}

fn parse_then(table: Option<&toml::Table>, where_: &str) -> Option<Then> {
    let mut then = Then::default();
    let Some(table) = table else {
        return Some(then);
    };

    then.decision = match table.get("decision").and_then(|v| v.as_str()) {
        Some("allow") => Some(Decision::Allow),
        Some("block") => Some(Decision::Block),
        Some(other) => {
            warn(format!(
                "{}: decision = \"{}\" is not allow or block — rule ignored",
                where_, other
            ));
            return None;
        }
        None => None,
    };
    then.intent = term(table.get("intent"), "intent", where_)?;
    then.reversibility = term(table.get("reversibility"), "reversibility", where_)?;
    then.sensitivity = term(table.get("sensitivity"), "sensitivity", where_)?;
    then.mitre = table
        .get("mitre")
        .and_then(|v| v.as_str())
        .map(String::from);
    then.reason = table
        .get("reason")
        .and_then(|v| v.as_str())
        .map(String::from);
    if let Some(score) = table.get("score").and_then(|v| v.as_table()) {
        let read = |key: &str| {
            score
                .get(key)
                .and_then(|v| v.as_integer())
                .map(|v| v.clamp(0, 100) as u8)
        };
        then.score = Some(ScoreEffect {
            set: read("set"),
            raise: read("raise"),
            cap: read("cap"),
        });
    }
    Some(then)
}

/// Parse the single string under `key` as vocabulary term `T`. Absent is
/// fine; present but unrecognized refuses the whole rule.
fn term<T: serde::de::DeserializeOwned>(
    value: Option<&toml::Value>,
    key: &str,
    where_: &str,
) -> Option<Option<T>> {
    match value.and_then(|v| v.as_str()) {
        None => Some(None),
        Some(text) => match parse_enum(text) {
            Some(term) => Some(Some(term)),
            None => {
                warn(format!(
                    "{}: {} = \"{}\" is not a known value — rule ignored",
                    where_, key, text
                ));
                None
            }
        },
    }
}

fn strings(value: Option<&toml::Value>) -> Vec<String> {
    match value {
        Some(toml::Value::String(s)) => vec![s.clone()],
        Some(toml::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

fn patterns(value: Option<&toml::Value>, key: &str, where_: &str) -> Option<Vec<Pattern>> {
    strings(value)
        .iter()
        .map(|s| checked_pattern(&expand_tilde(s), key, where_))
        .collect()
}

fn flag_conditions(
    value: Option<&toml::Value>,
    key: &str,
    where_: &str,
) -> Option<Vec<FlagCondition>> {
    let Some(table) = value.and_then(|v| v.as_table()) else {
        return Some(vec![]);
    };
    table
        .iter()
        .map(|(name, value)| {
            Some(FlagCondition {
                name: name.clone(),
                values: match value {
                    toml::Value::Boolean(true) => None,
                    other => Some(
                        strings(Some(other))
                            .iter()
                            .map(|s| checked_pattern(s, &format!("{}.{}", key, name), where_))
                            .collect::<Option<Vec<_>>>()?,
                    ),
                },
            })
        })
        .collect()
}

/// A pattern from a rule condition. A `regex:` that does not compile would
/// otherwise match nothing — a rule that silently never fires — so the
/// rule is refused with a warning instead.
fn checked_pattern(text: &str, key: &str, where_: &str) -> Option<Pattern> {
    match Pattern::try_parse(text) {
        Ok(pattern) => Some(pattern),
        Err(e) => {
            warn(format!(
                "{}: {} = \"{}\" is not a valid regex — rule ignored: {}",
                where_, key, text, e
            ));
            None
        }
    }
}

/// Parse one of the snake_case vocabulary enums (`Intent`, `Sensitivity`,
/// `Reversibility`, `RiskFactor`) from the spelling used in a rules file.
///
/// Returns `None` for anything unrecognized. A rules file is hand-written,
/// so a typo must be reported rather than quietly resolved to a default:
/// `intent = "reed"` silently becoming `execute` would make a rule *more*
/// severe than its author asked for.
fn parse_enum<T: serde::de::DeserializeOwned>(s: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

/// Report a problem with a rules file on stderr.
///
/// Rules are configuration a person wrote by hand, and every way of getting
/// one wrong used to fail silently. There is no logger in this crate and a
/// wrong rule is worth interrupting for, so these go straight to stderr.
fn warn(message: impl std::fmt::Display) {
    eprintln!("sh-guard: {}", message);
}

fn expand_tilde(text: &str) -> String {
    match (text.strip_prefix("~/"), home()) {
        (Some(rest), Some(home)) => format!("{}/{}", home.display(), rest),
        _ => text.to_string(),
    }
}

fn home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    fn matches(pattern: &[u8], text: &[u8]) -> bool {
        match pattern.first() {
            None => text.is_empty(),
            Some(b'*') => {
                matches(&pattern[1..], text) || (!text.is_empty() && matches(pattern, &text[1..]))
            }
            Some(b'?') => !text.is_empty() && matches(&pattern[1..], &text[1..]),
            Some(c) => text.first() == Some(c) && matches(&pattern[1..], &text[1..]),
        }
    }
    matches(pattern.as_bytes(), text.as_bytes())
}

// ========================================================
// Rules in effect for the classification in progress
// ========================================================

thread_local! {
    static ACTIVE: std::cell::RefCell<Option<std::rc::Rc<RuleConfig>>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` with `config` as the rules in effect.
///
/// Classification is spread across many modules (the analyzer, sensitivity
/// resolution, the payload classifiers used by wrappers, xargs, find -exec,
/// docker/kubectl exec). Making the rules ambient for one `classify` call
/// lets each of them consult the same set without threading a parameter
/// through every signature.
pub(crate) fn with_active<T>(config: Option<&RuleConfig>, f: impl FnOnce() -> T) -> T {
    let previous = ACTIVE.with(|a| a.replace(config.map(|c| std::rc::Rc::new(c.clone()))));
    let result = f();
    ACTIVE.with(|a| *a.borrow_mut() = previous);
    result
}

fn active<T>(f: impl FnOnce(&RuleConfig) -> T) -> Option<T> {
    ACTIVE.with(|a| a.borrow().as_ref().map(|config| f(config)))
}

/// The sensitivity a path rule assigns to `path`, with the rule's trust.
pub(crate) fn path_sensitivity(path: &str) -> Option<(Sensitivity, Trust)> {
    active(|config| {
        config
            .rules
            .iter()
            .filter(|rule| rule.when.is_path_only())
            .filter(|rule| rule.when.path.iter().any(|p| p.matches_path(path)))
            .filter_map(|rule| rule.then.sensitivity.map(|s| (s, rule.trust)))
            .max_by_key(|(s, _)| s.modifier())
    })
    .flatten()
}

/// The classification a rule gives an otherwise-unknown program, for the
/// analyzer to apply before scoring: `(intent, reversibility, mitre)`.
pub(crate) fn classification_for(
    ctx: &MatchContext,
) -> Option<(Option<Intent>, Option<Reversibility>, Option<String>)> {
    active(|config| {
        let mut found: Option<(Option<Intent>, Option<Reversibility>, Option<String>)> = None;
        for rule in &config.rules {
            if rule.then.intent.is_none()
                && rule.then.reversibility.is_none()
                && rule.then.mitre.is_none()
            {
                continue;
            }
            if !matches_rule(&rule.when, ctx) {
                continue;
            }
            let entry = found.get_or_insert((None, None, None));
            if rule.then.intent.is_some() {
                entry.0 = rule.then.intent;
            }
            if rule.then.reversibility.is_some() {
                entry.1 = rule.then.reversibility;
            }
            if rule.then.mitre.is_some() {
                entry.2.clone_from(&rule.then.mitre);
            }
        }
        found
    })
    .flatten()
}

/// Split a segment's command text into its leading `NAME=value`
/// assignments and the arguments after the executable.
///
/// `AWS_PROFILE=prod deploy --env production` gives
/// `([("AWS_PROFILE", "prod")], ["--env", "production"])`. Treating the first
/// token as the executable instead would drop the assignment and count
/// `deploy` as an argument — and a subcommand.
pub(crate) fn split_command(command: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut tokens = command.split_whitespace();
    let mut env = Vec::new();
    for token in tokens.by_ref() {
        match env_assignment(token) {
            Some(pair) => env.push(pair),
            None => break, // the executable, consumed
        }
    }
    (env, tokens.map(String::from).collect())
}

/// `NAME=value`, where NAME is a shell identifier.
fn env_assignment(token: &str) -> Option<(String, String)> {
    let (name, value) = token.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some((
        name.to_string(),
        value.trim_matches(['\'', '"']).to_string(),
    ))
}

/// The MITRE id a rule attaches to `executable` as invoked in `command`.
pub(crate) fn active_mitre(executable: &str, command: &str) -> Option<String> {
    let (env, args) = split_command(command);
    let ctx = MatchContext {
        executable: executable.to_string(),
        subcommands: subcommand_path(&args),
        flags: flag_pairs(&args),
        args,
        env,
        ..Default::default()
    };
    active(|config| {
        config
            .rules
            .iter()
            .filter(|rule| rule.then.mitre.is_some())
            .find(|rule| matches_rule(&rule.when, &ctx))
            .and_then(|rule| rule.then.mitre.clone())
    })
    .flatten()
}

/// Rules whose decision or score effect applies to a classified segment.
pub(crate) fn effects_for(ctx: &MatchContext) -> Vec<Rule> {
    active(|config| {
        config
            .rules
            .iter()
            .filter(|rule| rule.then.decision.is_some() || rule.then.score.is_some())
            .filter(|rule| matches_rule(&rule.when, ctx))
            .cloned()
            .collect()
    })
    .unwrap_or_default()
}

// ========================================================
// Matching
// ========================================================

/// Everything a `when` can ask about one analyzed command segment.
#[derive(Debug, Default)]
pub(crate) struct MatchContext {
    pub executable: String,
    /// `["delete", "delete pod"]` for `kubectl -n x delete pod y`.
    pub subcommands: Vec<String>,
    pub flags: Vec<(String, Option<String>)>,
    pub args: Vec<String>,
    pub paths: Vec<String>,
    pub intents: Vec<Intent>,
    pub risk_factors: Vec<RiskFactor>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub project: Option<String>,
    pub shell: Shell,
}

/// The verb path candidates for an argv: the leading non-flag tokens, as
/// `["delete", "delete pod"]`, so a rule can say `subcommand = "delete"` or
/// `subcommand = "delete pod"`. Flags and their separate values are skipped,
/// so `kubectl -n prod delete pod x` still yields `delete pod`.
pub(crate) fn subcommand_path(args: &[String]) -> Vec<String> {
    let mut verbs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() && verbs.len() < 3 {
        let arg = args[i].trim_matches(['\'', '"']);
        if arg == "--" {
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            // `--flag value` consumes the value unless it is `--flag=value`
            // or the next token is itself a flag.
            if !arg.contains('=')
                && args.get(i + 1).is_some_and(|next| !next.starts_with('-'))
                && !verbs.is_empty()
            {
                i += 2;
                continue;
            }
            if !arg.contains('=') && args.get(i + 1).is_some_and(|n| !n.starts_with('-')) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        verbs.push(arg.to_string());
        i += 1;
    }

    (1..=verbs.len()).map(|n| verbs[..n].join(" ")).collect()
}

/// `--name=value`, `--name value`, `-n value` and bare `--name` as
/// `(name, value)` pairs, so a rule can ask for `flag = { context = "kind-*" }`
/// however the flag was spelled.
pub(crate) fn flag_pairs(args: &[String]) -> Vec<(String, Option<String>)> {
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim_matches(['\'', '"']).to_string();
        let Some(name) = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-').filter(|rest| !rest.is_empty()))
        else {
            i += 1;
            continue;
        };
        if let Some((name, value)) = name.split_once('=') {
            pairs.push((
                name.to_string(),
                Some(value.trim_matches(['\'', '"']).to_string()),
            ));
            i += 1;
            continue;
        }
        match args.get(i + 1) {
            Some(next) if !next.starts_with('-') => {
                pairs.push((
                    name.to_string(),
                    Some(next.trim_matches(['\'', '"']).to_string()),
                ));
                i += 2;
            }
            _ => {
                pairs.push((name.to_string(), None));
                i += 1;
            }
        }
    }
    pairs
}

fn matches_rule(when: &When, ctx: &MatchContext) -> bool {
    let base = ctx
        .executable
        .rsplit('/')
        .next()
        .unwrap_or(&ctx.executable)
        .to_string();

    let any = |patterns: &[Pattern], values: &[String]| {
        patterns.is_empty()
            || values
                .iter()
                .any(|value| patterns.iter().any(|p| p.matches(value)))
    };

    any(&when.command, &[base, ctx.executable.clone()])
        && any(&when.subcommand, &ctx.subcommands)
        && any(&when.arg, &ctx.args)
        && (when.path.is_empty()
            || ctx
                .paths
                .iter()
                .any(|path| when.path.iter().any(|p| p.matches_path(path))))
        && (when.intent.is_empty() || when.intent.iter().any(|i| ctx.intents.contains(i)))
        && (when.risk_factor.is_empty()
            || when
                .risk_factor
                .iter()
                .any(|rf| ctx.risk_factors.contains(rf)))
        && when.flag.iter().all(|cond| matches_pairs(cond, &ctx.flags))
        && when.env.iter().all(|cond| {
            matches_pairs(
                cond,
                &ctx.env
                    .iter()
                    .map(|(k, v)| (k.clone(), Some(v.clone())))
                    .collect::<Vec<_>>(),
            )
        })
        && (when.cwd.is_empty()
            || ctx
                .cwd
                .as_ref()
                .is_some_and(|c| when.cwd.iter().any(|p| p.matches(c))))
        && (when.project.is_empty()
            || ctx
                .project
                .as_ref()
                .is_some_and(|c| when.project.iter().any(|p| p.matches(c))))
        && when.shell.is_none_or(|s| s == ctx.shell)
}

fn matches_pairs(cond: &FlagCondition, pairs: &[(String, Option<String>)]) -> bool {
    pairs.iter().any(|(name, value)| {
        name == &cond.name
            && match (&cond.values, value) {
                (None, _) => true,
                (Some(patterns), Some(value)) => patterns.iter().any(|p| p.matches(value)),
                (Some(_), None) => false,
            }
    })
}
