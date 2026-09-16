//! `kubectl` verb/resource-aware classification.
//!
//! Like `git`/`gh`, `kubectl` is not one operation: `kubectl get pods` is a
//! read while `kubectl delete namespace prod` destroys a whole namespace's
//! worth of workloads. The generic `CommandRule` model previously scored
//! every invocation the same (`Intent::Execute`, weight 50) with only two
//! flat raw-text flag checks (`delete` +25, `exec` +20), so reads were flat
//! DANGER, `delete pod x` scored the same as `delete namespace prod`, and
//! secrets/RBAC/exec payloads were invisible. This module instead:
//!
//! 1. Scans kubectl's persistent (global) flags -- `-n`/`--namespace`,
//!    `-A`/`--all-namespaces`, `--context`, `--as`/`--as-group`/`--as-uid`,
//!    `--token`, `--insecure-skip-tls-verify`, `-o`/`--output`, ... -- which
//!    (per Cobra's persistent-flag model) can appear before OR after the
//!    verb, e.g. `kubectl -n kube-system delete pod x` and `kubectl delete
//!    pod x -n kube-system` are equivalent. These are stripped out of the
//!    token stream used to find the verb and parse subcommand-specific
//!    flags/positionals (so e.g. `kubectl get pods -o name` doesn't
//!    misread `-o`'s value as a positional), while their *values* are kept
//!    (`GlobalFlags`) for cross-cutting checks (namespace sensitivity,
//!    impersonation, inline credentials).
//! 2. Classifies the verb (Cobra, so no abbreviated long options --
//!    `cli_args::has_flag`'s `allow_prefix = false`) into an intent +
//!    reversibility, using the subcommand's own arguments for
//!    context-dependent cases (`rollout status` reads, `rollout undo`
//!    destroys; `scale --replicas=0` is a soft-delete; ...).
//! 3. Reuses `rules::find_fd`'s payload machinery for `exec ... -- <cmd>`,
//!    `run ... -- <cmd>`, and `debug ... -- <cmd>`: the payload's own
//!    classification leads, so `exec pod -- ls` stays low and `exec pod --
//!    rm -rf /` scores as the destructive command it actually runs, rather
//!    than every `exec`/`run`/`debug` flatly scoring `Intent::Execute`
//!    regardless of payload.
//! 4. Flags secrets exposure (`get secret -o yaml`, `config view --raw`,
//!    `create secret --from-literal`, `config set-credentials --token`),
//!    privilege escalation (`create clusterrolebinding
//!    --clusterrole=cluster-admin`, `--as=system:admin` impersonation,
//!    `run --privileged`), and remote-manifest application (`apply -f
//!    <URL>`).

use super::cli_args;
use super::find_fd;
use crate::types::{FlagAnalysis, Intent, Reversibility, RiskFactor};

/// Result of classifying a kubectl invocation.
pub struct KubectlClassification {
    pub intent: Vec<Intent>,
    pub reversibility: Reversibility,
    pub flags: Vec<FlagAnalysis>,
}

impl KubectlClassification {
    fn simple(intent: Intent, reversibility: Reversibility) -> Self {
        KubectlClassification {
            intent: vec![intent],
            reversibility,
            flags: vec![],
        }
    }
}

use cli_args::flag;

fn strip_quotes(s: &str) -> String {
    find_fd::strip_quotes(s)
}

fn worse(a: Reversibility, b: Reversibility) -> Reversibility {
    find_fd::worse(a, b)
}

// ========================================================
// Global (persistent) flag scanning
// ========================================================

struct GlobalSpec {
    short: Option<char>,
    long: &'static str,
    takes_value: bool,
}

/// kubectl's persistent flags that matter for risk classification (see the
/// task's "Global flags" list). Not exhaustive of every persistent flag
/// kubectl accepts (e.g. `--add-dir-header`, `--log-flush-frequency`,
/// ...) -- only the ones that either (a) could otherwise be misread as a
/// verb/resource positional, or (b) carry their own risk signal.
const GLOBALS: &[GlobalSpec] = &[
    GlobalSpec {
        short: Some('n'),
        long: "namespace",
        takes_value: true,
    },
    GlobalSpec {
        short: Some('A'),
        long: "all-namespaces",
        takes_value: false,
    },
    GlobalSpec {
        short: None,
        long: "context",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "cluster",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "kubeconfig",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "as",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "as-group",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "as-uid",
        takes_value: true,
    },
    GlobalSpec {
        short: Some('s'),
        long: "server",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "token",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "user",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "insecure-skip-tls-verify",
        takes_value: false,
    },
    GlobalSpec {
        short: None,
        long: "certificate-authority",
        takes_value: true,
    },
    GlobalSpec {
        short: Some('o'),
        long: "output",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "v",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "request-timeout",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "cache-dir",
        takes_value: true,
    },
    GlobalSpec {
        short: None,
        long: "match-server-version",
        takes_value: false,
    },
];

/// Cross-cutting information gathered from kubectl's persistent flags,
/// wherever in the argument list they appear (before or after the verb).
#[derive(Default)]
struct GlobalFlags {
    namespace: Option<String>,
    all_namespaces: bool,
    as_user: Option<String>,
    as_group: Vec<String>,
    token: bool,
    insecure_skip_tls_verify: bool,
    output: Option<String>,
}

impl GlobalFlags {
    fn record(&mut self, long: &str, value: Option<String>) {
        match long {
            "namespace" => self.namespace = value,
            "all-namespaces" => self.all_namespaces = true,
            "as" => self.as_user = value,
            "as-group" => {
                if let Some(v) = value {
                    self.as_group.push(v);
                }
            }
            "token" => self.token = true,
            "insecure-skip-tls-verify" => self.insecure_skip_tls_verify = true,
            "output" => self.output = value,
            _ => {}
        }
    }
}

/// Matches a single token against a known global flag: `-n`, `--namespace`,
/// `--namespace=value` (fused). No prefix/abbreviation matching (Cobra
/// rejects those) and no short-option clustering (kubectl's global short
/// flags -- `-n`, `-A`, `-s`, `-o` -- are not documented to combine).
fn match_global(tok: &str) -> Option<(&'static GlobalSpec, Option<&str>)> {
    if let Some(rest) = tok.strip_prefix("--") {
        let (name, fused) = match rest.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (rest, None),
        };
        GLOBALS.iter().find(|g| g.long == name).map(|g| (g, fused))
    } else if let Some(rest) = tok.strip_prefix('-') {
        if !rest.starts_with('-') && rest.len() == 1 {
            let c = rest.chars().next().unwrap();
            GLOBALS
                .iter()
                .find(|g| g.short == Some(c))
                .map(|g| (g, None))
        } else {
            None
        }
    } else {
        None
    }
}

/// Strip every recognized global flag (and the value it consumes, wherever
/// it appears) out of `args`, returning the remaining tokens (the verb and
/// its own arguments, free of global-flag noise) plus the values captured
/// along the way.
fn scan_globals(args: &[String]) -> (Vec<String>, GlobalFlags) {
    let mut rest = Vec::new();
    let mut globals = GlobalFlags::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some((spec, fused)) = match_global(a) {
            if spec.takes_value {
                match fused {
                    Some(v) => {
                        globals.record(spec.long, Some(v.to_string()));
                        i += 1;
                    }
                    None => {
                        let v = args.get(i + 1).cloned();
                        globals.record(spec.long, v);
                        i += 2;
                    }
                }
            } else {
                globals.record(spec.long, None);
                i += 1;
            }
            continue;
        }
        rest.push(a.clone());
        i += 1;
    }
    (rest, globals)
}

const SENSITIVE_NAMESPACES: &[&str] = &["kube-system", "kube-public", "kube-node-lease"];

fn namespace_is_sensitive(globals: &GlobalFlags) -> bool {
    globals.all_namespaces
        || globals
            .namespace
            .as_deref()
            .is_some_and(|ns| SENSITIVE_NAMESPACES.contains(&ns))
}

// ========================================================
// Resource shorthand resolution
// ========================================================

/// Resolve a resource type token (`po`, `pods`, `deploy/myapp`, ...) to a
/// canonical singular name. Only covers the shorthands/plurals that matter
/// for the sensitivity checks below -- an unrecognized token is lowercased
/// and returned as-is (trailing `/name` already stripped by the caller).
fn canonical_resource(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    let name = match lower.as_str() {
        "po" | "pods" | "pod" => "pod",
        "deploy" | "deployments" | "deployment" => "deployment",
        "ns" | "namespaces" | "namespace" => "namespace",
        "svc" | "services" | "service" => "service",
        "sa" | "serviceaccounts" | "serviceaccount" => "serviceaccount",
        "pvc" | "persistentvolumeclaims" | "persistentvolumeclaim" => "persistentvolumeclaim",
        "pv" | "persistentvolumes" | "persistentvolume" => "persistentvolume",
        "crd" | "crds" | "customresourcedefinitions" | "customresourcedefinition" => {
            "customresourcedefinition"
        }
        "sts" | "statefulsets" | "statefulset" => "statefulset",
        "ds" | "daemonsets" | "daemonset" => "daemonset",
        "rs" | "replicasets" | "replicaset" => "replicaset",
        "cm" | "configmaps" | "configmap" => "configmap",
        "ing" | "ingresses" | "ingress" => "ingress",
        "no" | "nodes" | "node" => "node",
        "rb" | "rolebindings" | "rolebinding" => "rolebinding",
        "crb" | "clusterrolebindings" | "clusterrolebinding" => "clusterrolebinding",
        "netpol" | "networkpolicies" | "networkpolicy" => "networkpolicy",
        "hpa" | "horizontalpodautoscalers" | "horizontalpodautoscaler" => "horizontalpodautoscaler",
        "job" | "jobs" => "job",
        "cj" | "cronjobs" | "cronjob" => "cronjob",
        "secret" | "secrets" => "secret",
        "role" | "roles" => "role",
        "clusterrole" | "clusterroles" => "clusterrole",
        other => return other.trim_end_matches('s').to_string(),
    };
    name.to_string()
}

/// Resources whose deletion has a blast radius well beyond a single
/// workload instance (an entire namespace's contents, every CR of a type,
/// cluster-wide RBAC, a node leaving the cluster, ...).
const SENSITIVE_DELETE_RESOURCES: &[&str] = &[
    "namespace",
    "persistentvolume",
    "persistentvolumeclaim",
    "customresourcedefinition",
    "statefulset",
    "node",
    "clusterrole",
    "clusterrolebinding",
];

/// First positional token (a resource type, or `resource/name`), with its
/// `resource` part canonicalized. `value_flags` excludes the values
/// consumed by options that take a separate token (`-l <selector>`, ...).
fn first_resource(sub_args: &[String], value_flags: &[&str]) -> Option<String> {
    let positionals = cli_args::effective_positionals(sub_args, value_flags);
    let first = positionals.first()?;
    let resource_part = first.split('/').next().unwrap_or(first);
    Some(canonical_resource(&strip_quotes(resource_part)))
}

// ========================================================
// Flag-matching helpers (Cobra: no prefix abbreviation)
// ========================================================

fn has_flag(args: &[String], short: Option<char>, longs: &[&str]) -> bool {
    cli_args::has_flag(args, short, longs, false)
}

fn has_exact(args: &[String], token: &str) -> bool {
    cli_args::has_exact(args, token)
}

/// True if `args` contains `--flag=<value>` or a separate-token `--flag
/// <value>` whose value satisfies `pred`.
fn flag_value_matches(args: &[String], long: &str, pred: impl Fn(&str) -> bool) -> bool {
    let prefix = format!("--{}=", long);
    for (i, a) in args.iter().enumerate() {
        if let Some(v) = a.strip_prefix(&prefix) {
            if pred(v) {
                return true;
            }
        } else if a == &format!("--{}", long) {
            if let Some(v) = args.get(i + 1) {
                if pred(v) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_url(s: &str) -> bool {
    let s = strip_quotes(s);
    s.starts_with("http://") || s.starts_with("https://")
}

/// `-f`/`--filename` values, plus `-k`/`--kustomize` values (both can name
/// a local file/dir or a remote URL).
fn filename_values(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-f" | "--filename" | "-k" | "--kustomize" => {
                if let Some(v) = args.get(i + 1) {
                    out.push(strip_quotes(v));
                }
                i += 2;
                continue;
            }
            _ => {
                if let Some(v) = a
                    .strip_prefix("--filename=")
                    .or_else(|| a.strip_prefix("--kustomize="))
                {
                    out.push(strip_quotes(v));
                }
            }
        }
        i += 1;
    }
    out
}

fn any_filename_is_url(args: &[String]) -> bool {
    filename_values(args).iter().any(|v| is_url(v))
}

// ========================================================
// Payload (exec/run/debug) handling -- reuses find_fd's machinery
// ========================================================

fn fold_exec_payload(
    result: &mut KubectlClassification,
    label: &str,
    description: &str,
    wrapper_modifier: i8,
    payload: &[String],
) {
    let payload_result = find_fd::classify_payload(payload);

    result.intent.retain(|i| !matches!(i, Intent::Info));
    for i in &payload_result.intent {
        if !result.intent.contains(i) {
            result.intent.push(*i);
        }
    }
    if result.intent.is_empty() {
        result.intent.push(Intent::Execute);
    }

    result.reversibility = worse(result.reversibility, payload_result.reversibility);

    result.flags.push(flag(
        wrapper_modifier,
        RiskFactor::CommandExecution,
        label,
        description,
    ));
    result.flags.extend(payload_result.flags);
}

/// Find a `-- <payload...>` separator in `args` and return the tokens after
/// it (empty if there is no `--`, or nothing follows it).
fn payload_after_double_dash(args: &[String]) -> Vec<String> {
    args.iter()
        .position(|a| a == "--")
        .map(|idx| args[idx + 1..].to_vec())
        .unwrap_or_default()
}

// ========================================================
// Top-level classify
// ========================================================

/// Classify a `kubectl ...` invocation given its arguments (everything
/// after the `kubectl`/`/usr/local/bin/kubectl`/`kubectl.exe` executable
/// token, tokenized/quote-aware) and any `NAME=value` prefix assignments
/// attached to the same command.
pub fn classify(args: &[String], env_assignments: &[(String, String)]) -> KubectlClassification {
    let (rest, globals) = scan_globals(args);

    let mut result = match rest.split_first() {
        None => KubectlClassification::simple(Intent::Info, Reversibility::Reversible),
        Some((verb, verb_args)) => classify_verb(verb, verb_args, &globals),
    };

    if globals.insecure_skip_tls_verify {
        result.flags.push(flag(
            15,
            RiskFactor::PrivilegeEscalation,
            "--insecure-skip-tls-verify",
            "Disables TLS certificate verification against the API server, allowing MITM tampering",
        ));
    }

    if globals.token {
        result.flags.push(flag(
            30,
            RiskFactor::SecretsExposure,
            "--token=<inline>",
            "Passes a bearer token inline on the command line, exposing it in shell history/process listings",
        ));
    }

    if let Some(as_user) = &globals.as_user {
        let is_admin_like = as_user.contains("admin") || as_user == "system:masters";
        result.flags.push(flag(
            if is_admin_like { 30 } else { 20 },
            RiskFactor::PrivilegeEscalation,
            "--as",
            "Impersonates another user for this request",
        ));
    }
    if globals
        .as_group
        .iter()
        .any(|g| g == "system:masters" || g.contains("admin"))
    {
        result.flags.push(flag(
            30,
            RiskFactor::PrivilegeEscalation,
            "--as-group=system:masters",
            "Impersonates a cluster-admin group, bypassing normal RBAC checks",
        ));
    }

    if namespace_is_sensitive(&globals) && verb_is_destructive(rest.first().map(String::as_str)) {
        result.flags.push(flag(
            15,
            RiskFactor::BroadScope,
            "-n kube-system/kube-public/kube-node-lease / -A",
            "Targets a cluster-critical namespace (or all namespaces), amplifying a destructive operation",
        ));
    }

    // `KUBECTL_EXTERNAL_DIFF` (kubectl diff) and `KUBE_EDITOR`/`EDITOR`/
    // `VISUAL` (kubectl edit) each name a program kubectl will run. Setting
    // one inline to a plain editor/diff binary is ordinary usage; setting it
    // to a shell one-liner is arbitrary code execution.
    if let Some((name, value)) = env_assignments.iter().find(|(name, _)| {
        matches!(
            name.as_str(),
            "KUBECTL_EXTERNAL_DIFF" | "KUBE_EDITOR" | "EDITOR" | "VISUAL"
        )
    }) {
        if !is_plain_helper_program(value) {
            escalate_to_execute(
                &mut result,
                &format!(
                    "environment variable {} makes kubectl run an arbitrary command ({})",
                    name,
                    strip_quotes(value)
                ),
            );
        }
    }
    if let Some((_, path)) = env_assignments
        .iter()
        .find(|(name, _)| name == "KUBECONFIG")
    {
        result.flags.push(flag(
            5,
            RiskFactor::BroadScope,
            "KUBECONFIG=<path>",
            &format!(
                "Points kubectl at a different, potentially attacker-controlled cluster config ({})",
                path
            ),
        ));
    }

    result
}

/// True when an editor/diff env var's value is an ordinary helper binary
/// (`vim`, `code -w`, `meld`, ...) rather than something that runs a shell:
/// a shell metacharacter, or a shell/interpreter as the program itself.
fn is_plain_helper_program(value: &str) -> bool {
    let cleaned = strip_quotes(value);
    if cleaned.contains(['|', '&', ';', '$', '`', '>', '<', '\n']) {
        return false;
    }
    let Some(program) = cleaned.split_whitespace().next() else {
        return false;
    };
    let base = program.rsplit('/').next().unwrap_or(program);
    matches!(
        base,
        "vi" | "vim"
            | "nvim"
            | "nano"
            | "emacs"
            | "emacsclient"
            | "pico"
            | "micro"
            | "hx"
            | "helix"
            | "kak"
            | "ed"
            | "code"
            | "codium"
            | "subl"
            | "mate"
            | "gedit"
            | "notepad"
            | "diff"
            | "colordiff"
            | "delta"
            | "difft"
            | "meld"
            | "vimdiff"
            | "ksdiff"
    )
}

fn verb_is_destructive(verb: Option<&str>) -> bool {
    matches!(verb, Some("delete") | Some("drain") | Some("replace"))
}

/// Bump a classification to reflect that it can run an arbitrary command,
/// mirroring `rules::git::escalate_to_execute`.
fn escalate_to_execute(result: &mut KubectlClassification, reason: &str) {
    result
        .intent
        .retain(|i| *i != Intent::Info && *i != Intent::Execute);
    result.intent.insert(0, Intent::Execute);
    if result.reversibility == Reversibility::Reversible {
        result.reversibility = Reversibility::HardToReverse;
    }
    result.flags.push(flag(
        35,
        RiskFactor::CommandExecution,
        "dangerous kubectl env",
        reason,
    ));
}

// ========================================================
// Per-verb classifiers
// ========================================================

fn classify_verb(verb: &str, args: &[String], globals: &GlobalFlags) -> KubectlClassification {
    match verb {
        // -----------------------------------------------------------
        // Read-only
        // -----------------------------------------------------------
        "describe" | "top" | "explain" | "api-resources" | "api-versions" | "version" | "diff"
        | "events" | "wait" | "completion" | "options" => {
            KubectlClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        "get" => classify_get(args, globals),
        "logs" => KubectlClassification::simple(Intent::Info, Reversibility::Reversible),
        "auth" => classify_auth(args),
        "config" => classify_config(args),
        "cluster-info" => classify_cluster_info(args),
        "kustomize" => KubectlClassification::simple(Intent::Info, Reversibility::Reversible),
        "plugin" => classify_plugin(args),

        // -----------------------------------------------------------
        // Code execution / payload-aware
        // -----------------------------------------------------------
        "exec" => classify_exec(args),
        "run" => classify_run(args),
        "debug" => classify_debug(args),
        "attach" => KubectlClassification::simple(Intent::Execute, Reversibility::HardToReverse),
        "cp" => classify_cp(args),
        "port-forward" | "proxy" => {
            KubectlClassification::simple(Intent::Network, Reversibility::Reversible)
        }

        // -----------------------------------------------------------
        // Destructive
        // -----------------------------------------------------------
        "delete" => classify_delete(args, globals),
        "drain" => classify_drain(args),
        "replace" => classify_replace(args),

        // -----------------------------------------------------------
        // Context-dependent mutation
        // -----------------------------------------------------------
        "scale" => classify_scale(args),
        "rollout" => classify_rollout(args),
        "taint" => classify_taint(args),
        "create" => classify_create(args),
        "apply" => classify_apply(args),
        "certificate" => classify_certificate(args),

        // -----------------------------------------------------------
        // Plain mutation
        // -----------------------------------------------------------
        // `edit` mutates the resource; the editor it spawns is the
        // KUBE_EDITOR/EDITOR escalation's business, not `edit`'s own.
        "edit" => KubectlClassification::simple(Intent::Write, Reversibility::HardToReverse),
        "patch" | "set" | "label" | "annotate" | "expose" | "autoscale" | "cordon" | "uncordon" => {
            KubectlClassification::simple(Intent::Write, Reversibility::HardToReverse)
        }

        // Unknown verb (including a krew plugin invocation `kubectl
        // <plugin-name> ...`): never assume it's safe.
        _ => KubectlClassification::simple(Intent::Execute, Reversibility::HardToReverse),
    }
}

/// `get [flags]`'s value-taking flags whose values could otherwise be
/// misread as the resource-type positional.
const GET_VALUE_FLAGS: &[&str] = &[
    "-l",
    "--selector",
    "--field-selector",
    "--sort-by",
    "--chunk-size",
    "--label-columns",
    "-L",
    "--template",
    "--kubeconfig",
];

fn classify_get(args: &[String], globals: &GlobalFlags) -> KubectlClassification {
    let resource = first_resource(args, GET_VALUE_FLAGS);
    let is_secret = resource.as_deref() == Some("secret");

    let structured_output = globals.output.as_deref().is_some_and(|o| {
        matches!(o, "yaml" | "json")
            || o.starts_with("jsonpath")
            || o.starts_with("go-template")
            || o.starts_with("custom-columns")
    }) || has_flag(args, Some('w'), &["watch"]);

    if is_secret && structured_output {
        return KubectlClassification {
            intent: vec![Intent::Read],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                50,
                RiskFactor::SecretsExposure,
                "get secret -o yaml/json/...",
                "Prints Secret data (base64, not encrypted) to stdout",
            )],
        };
    }
    if is_secret {
        // `get secret[s]` with the default table output doesn't print
        // values, but still confirms which secrets exist -- worth a small
        // bump over a plain read, not full SecretsExposure.
        return KubectlClassification::simple(Intent::Read, Reversibility::Reversible);
    }

    KubectlClassification::simple(Intent::Info, Reversibility::Reversible)
}

fn classify_auth(args: &[String]) -> KubectlClassification {
    match args.first().map(String::as_str) {
        Some("can-i") | Some("whoami") => {
            KubectlClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("reconcile") => KubectlClassification {
            intent: vec![Intent::Privilege],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                20,
                RiskFactor::PrivilegeEscalation,
                "auth reconcile",
                "Creates/updates RBAC roles and bindings from a manifest",
            )],
        },
        _ => KubectlClassification::simple(Intent::Info, Reversibility::Reversible),
    }
}

fn classify_config(args: &[String]) -> KubectlClassification {
    match args.first().map(String::as_str) {
        Some("view") => {
            if has_flag(args, None, &["raw"]) {
                KubectlClassification {
                    intent: vec![Intent::Read],
                    reversibility: Reversibility::HardToReverse,
                    flags: vec![flag(
                        50,
                        RiskFactor::SecretsExposure,
                        "config view --raw",
                        "Prints kubeconfig with all credential data (tokens, client certs/keys) unmasked",
                    )],
                }
            } else {
                KubectlClassification::simple(Intent::Info, Reversibility::Reversible)
            }
        }
        Some("get-contexts") | Some("current-context") => {
            KubectlClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("set-credentials") => {
            let has_secret_flag = flag_value_matches(args, "token", |_| true)
                || flag_value_matches(args, "password", |_| true)
                || flag_value_matches(args, "client-key", |_| true);
            if has_secret_flag {
                KubectlClassification {
                    intent: vec![Intent::EnvModify],
                    reversibility: Reversibility::HardToReverse,
                    flags: vec![flag(
                        40,
                        RiskFactor::SecretsExposure,
                        "config set-credentials --token/--password/--client-key",
                        "Writes a credential inline into kubeconfig / the command line",
                    )],
                }
            } else {
                KubectlClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
            }
        }
        Some("set-context") | Some("set-cluster") | Some("set") | Some("unset") => {
            KubectlClassification::simple(Intent::EnvModify, Reversibility::HardToReverse)
        }
        Some("use-context") | Some("rename-context") => {
            KubectlClassification::simple(Intent::EnvModify, Reversibility::Reversible)
        }
        Some("delete-context") | Some("delete-cluster") | Some("delete-user") => {
            KubectlClassification {
                intent: vec![Intent::Delete],
                reversibility: Reversibility::Irreversible,
                flags: vec![flag(
                    15,
                    RiskFactor::BroadScope,
                    "config delete-context/delete-cluster/delete-user",
                    "Removes an entry from kubeconfig",
                )],
            }
        }
        _ => KubectlClassification::simple(Intent::Info, Reversibility::Reversible),
    }
}

fn classify_cluster_info(args: &[String]) -> KubectlClassification {
    if has_exact(args, "dump") {
        KubectlClassification::simple(Intent::Write, Reversibility::Reversible)
    } else {
        KubectlClassification::simple(Intent::Info, Reversibility::Reversible)
    }
}

fn classify_plugin(args: &[String]) -> KubectlClassification {
    match args.first().map(String::as_str) {
        None | Some("list") => {
            KubectlClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        // `kubectl plugin <name> ...` (or any other plugin subcommand we
        // don't recognize) runs a third-party binary -- never assume safe.
        _ => KubectlClassification::simple(Intent::Execute, Reversibility::HardToReverse),
    }
}

fn classify_exec(args: &[String]) -> KubectlClassification {
    // Seeded with `Info`, not `Execute`: `fold_exec_payload` lets the
    // payload's own intent lead (the `find`/`fd` lesson -- seeding Execute
    // floors every `exec pod -- ls` at DANGER and leaves it barely
    // distinguishable from `exec pod -- rm -rf /`). The wrapper modifier
    // below still prices in "this runs inside a live container".
    let mut result = KubectlClassification::simple(Intent::Info, Reversibility::HardToReverse);
    let payload = payload_after_double_dash(args);

    let interactive = has_flag(args, Some('i'), &["stdin"]) && has_flag(args, Some('t'), &["tty"])
        || has_exact(args, "-it")
        || has_exact(args, "-ti");

    if payload.is_empty() {
        // No `-- <cmd>` given: kubectl defaults the payload to the
        // container's own entrypoint via `sh -c`-equivalent invocation
        // only when interactive; otherwise this is likely a malformed
        // invocation. Conservative default: Execute, no extra escalation.
        result.intent = vec![Intent::Execute];
        result.flags.push(flag(
            25,
            RiskFactor::CommandExecution,
            "exec",
            "Executes a command inside a running container",
        ));
    } else {
        fold_exec_payload(
            &mut result,
            "exec -- <cmd>",
            "Executes a command inside a running container",
            25,
            &payload,
        );
    }

    if interactive {
        result.flags.push(flag(
            10,
            RiskFactor::CommandExecution,
            "-it/-i -t",
            "Opens an interactive session (stdin+tty) inside the container",
        ));
    }

    result
}

fn classify_run(args: &[String]) -> KubectlClassification {
    let mut result = KubectlClassification::simple(Intent::Info, Reversibility::HardToReverse);
    let payload = payload_after_double_dash(args);

    if payload.is_empty() {
        result.intent = vec![Intent::Execute];
        result.flags.push(flag(
            20,
            RiskFactor::CommandExecution,
            "run",
            "Creates and runs a new pod from an image",
        ));
    } else {
        fold_exec_payload(
            &mut result,
            "run -- <cmd>",
            "Creates a pod that runs an arbitrary command",
            20,
            &payload,
        );
    }

    if has_flag(args, None, &["privileged"]) {
        result.flags.push(flag(
            30,
            RiskFactor::PrivilegeEscalation,
            "run --privileged",
            "Runs the container with full access to the host, defeating container isolation",
        ));
    }

    result
}

fn classify_debug(args: &[String]) -> KubectlClassification {
    let mut result = KubectlClassification::simple(Intent::Info, Reversibility::HardToReverse);
    let payload = payload_after_double_dash(args);

    if payload.is_empty() {
        result.intent = vec![Intent::Execute];
        result.flags.push(flag(
            20,
            RiskFactor::CommandExecution,
            "debug",
            "Creates a debug container/pod",
        ));
    } else {
        fold_exec_payload(
            &mut result,
            "debug -- <cmd>",
            "Creates a debug container/pod that runs an arbitrary command",
            20,
            &payload,
        );
    }

    // `kubectl debug node/<name>` mounts the target node's root filesystem
    // into the debug pod -- effectively host filesystem access.
    let targets_node = cli_args::effective_positionals(args, &["--image", "--container", "-c"])
        .first()
        .is_some_and(|t| t.starts_with("node/"));
    if targets_node {
        result.reversibility = Reversibility::Irreversible;
        result.flags.push(flag(
            30,
            RiskFactor::PrivilegeEscalation,
            "debug node/<name>",
            "Mounts the target node's root filesystem into the debug pod, granting host access",
        ));
    }

    result
}

/// `kubectl cp <src> <dst>`, where either side may be a remote
/// `[<namespace>/]<pod>:<path>`. The analyzer's own target extraction only
/// sees the local side, so the remote side's path is matched against the
/// sensitive-path rules here -- `kubectl cp pod:/etc/shadow .` exfiltrates
/// a protected file just as surely as `cat /etc/shadow` would.
fn classify_cp(args: &[String]) -> KubectlClassification {
    let mut result = KubectlClassification::simple(Intent::Write, Reversibility::HardToReverse);

    for pos in cli_args::effective_positionals(args, &["-c", "--container", "--retries"]) {
        let cleaned = strip_quotes(&pos);
        // Remote side: `pod:/path` or `ns/pod:/path`. A Windows-style
        // `C:\...` or a bare relative path has no `:` + `/` shape.
        let Some((_, remote_path)) = cleaned.split_once(':') else {
            continue;
        };
        if remote_path.is_empty() {
            continue;
        }
        // In-container paths that paths.rs doesn't model: the mounted
        // ServiceAccount token grants API access as that pod's identity.
        if remote_path.starts_with("/var/run/secrets/kubernetes.io")
            || remote_path.starts_with("/var/run/secrets/eks.amazonaws.com")
        {
            result.flags.push(flag(
                40,
                RiskFactor::SecretsExposure,
                "cp <pod>:/var/run/secrets/...",
                "Copies a mounted ServiceAccount token or cloud identity credential out of a container",
            ));
            continue;
        }
        if let Some((sensitivity, description)) = super::paths::match_sensitivity(remote_path) {
            let modifier = match sensitivity {
                crate::types::Sensitivity::Secrets | crate::types::Sensitivity::Protected => 40,
                crate::types::Sensitivity::System => 30,
                crate::types::Sensitivity::Config => 15,
                crate::types::Sensitivity::Normal => 0,
            };
            if modifier > 0 {
                result.flags.push(flag(
                    modifier,
                    RiskFactor::SecretsExposure,
                    "cp <pod>:<sensitive path>",
                    &format!("Copies a sensitive file to/from a container ({description})"),
                ));
            }
        }
    }

    result
}

fn classify_delete(args: &[String], globals: &GlobalFlags) -> KubectlClassification {
    let mut flags = vec![];

    if let Some(resource) = first_resource(
        args,
        &[
            "-l",
            "--selector",
            "--field-selector",
            "--grace-period",
            "--timeout",
            "--cascade",
        ],
    ) {
        if SENSITIVE_DELETE_RESOURCES.contains(&resource.as_str()) {
            flags.push(flag(
                25,
                RiskFactor::BroadScope,
                &resource,
                "Deletes a resource with a blast radius beyond a single workload instance",
            ));
        }
    }

    if has_exact(args, "--all") || has_flag(args, Some('A'), &["all-namespaces"]) {
        flags.push(flag(
            20,
            RiskFactor::BroadScope,
            "--all/-A/--all-namespaces",
            "Deletes every matching resource instead of a single named one",
        ));
    }

    let force = has_flag(args, Some('f'), &["force"]);
    let grace_zero = flag_value_matches(args, "grace-period", |v| v == "0");
    if force && grace_zero {
        flags.push(flag(
            15,
            RiskFactor::ForceFlag,
            "--force --grace-period=0",
            "Skips graceful termination entirely",
        ));
    }

    if flag_value_matches(args, "cascade", |v| v.eq_ignore_ascii_case("orphan")) {
        flags.push(flag(
            10,
            RiskFactor::BroadScope,
            "--cascade=orphan",
            "Orphans dependent resources (e.g. Pods of a Deployment) instead of cascading the delete",
        ));
    }

    if !filename_values(args).is_empty() {
        flags.push(flag(
            10,
            RiskFactor::BroadScope,
            "delete -f/-k",
            "Deletes every resource described in a manifest file",
        ));
        if any_filename_is_url(args) {
            flags.push(flag(
                20,
                RiskFactor::NetworkExfiltration,
                "delete -f <URL>",
                "Fetches a manifest from a remote URL to determine what to delete",
            ));
        }
    }

    if namespace_is_sensitive(globals) {
        // Already added generically in `classify`'s post-processing for
        // any destructive verb; avoid duplicating here.
    }

    KubectlClassification {
        intent: vec![Intent::Delete],
        reversibility: Reversibility::Irreversible,
        flags,
    }
}

fn classify_drain(args: &[String]) -> KubectlClassification {
    let mut flags = vec![];
    if has_flag(args, None, &["force"]) {
        flags.push(flag(
            15,
            RiskFactor::ForceFlag,
            "drain --force",
            "Evicts pods not managed by a controller, which would otherwise block the drain",
        ));
    }
    if has_flag(args, None, &["delete-emptydir-data"])
        || has_flag(args, None, &["delete-local-data"])
    {
        flags.push(flag(
            15,
            RiskFactor::RecursiveDelete,
            "drain --delete-emptydir-data",
            "Deletes emptyDir volume data (any data not backed by durable storage) as pods are evicted",
        ));
    }
    if has_flag(args, None, &["ignore-daemonsets"]) {
        flags.push(flag(
            5,
            RiskFactor::BroadScope,
            "drain --ignore-daemonsets",
            "Also evicts/ignores DaemonSet-managed pods while draining",
        ));
    }

    KubectlClassification {
        intent: vec![Intent::Delete],
        reversibility: Reversibility::HardToReverse,
        flags,
    }
}

fn classify_replace(args: &[String]) -> KubectlClassification {
    let force = has_flag(args, Some('f'), &["force"]);
    let mut flags = vec![];
    if force {
        flags.push(flag(
            20,
            RiskFactor::RecursiveDelete,
            "replace --force",
            "Force-replace deletes the existing resource and recreates it from scratch",
        ));
    }
    if any_filename_is_url(args) {
        flags.push(flag(
            20,
            RiskFactor::NetworkExfiltration,
            "replace -f <URL>",
            "Fetches a manifest from a remote URL and applies it",
        ));
    }
    KubectlClassification {
        intent: vec![if force { Intent::Delete } else { Intent::Write }],
        reversibility: if force {
            Reversibility::Irreversible
        } else {
            Reversibility::HardToReverse
        },
        flags,
    }
}

fn classify_scale(args: &[String]) -> KubectlClassification {
    if flag_value_matches(args, "replicas", |v| v == "0") {
        KubectlClassification {
            intent: vec![Intent::Delete],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                15,
                RiskFactor::RecursiveDelete,
                "scale --replicas=0",
                "Scales a workload down to zero replicas, taking it fully offline",
            )],
        }
    } else {
        KubectlClassification::simple(Intent::Write, Reversibility::Reversible)
    }
}

fn classify_rollout(args: &[String]) -> KubectlClassification {
    match args.first().map(String::as_str) {
        Some("status") | Some("history") => {
            KubectlClassification::simple(Intent::Info, Reversibility::Reversible)
        }
        Some("undo") => KubectlClassification {
            intent: vec![Intent::Write],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                15,
                RiskFactor::BroadScope,
                "rollout undo",
                "Reverts a workload to a previous revision, discarding the current one",
            )],
        },
        Some("restart") | Some("pause") | Some("resume") => {
            KubectlClassification::simple(Intent::Write, Reversibility::HardToReverse)
        }
        _ => KubectlClassification::simple(Intent::Write, Reversibility::HardToReverse),
    }
}

fn classify_taint(args: &[String]) -> KubectlClassification {
    let no_execute = args.iter().any(|a| a.contains("NoExecute"));
    if no_execute {
        KubectlClassification {
            intent: vec![Intent::Write],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                15,
                RiskFactor::BroadScope,
                "taint ...:NoExecute",
                "Evicts all pods on the node that don't tolerate the taint",
            )],
        }
    } else {
        KubectlClassification::simple(Intent::Write, Reversibility::Reversible)
    }
}

fn classify_certificate(args: &[String]) -> KubectlClassification {
    match args.first().map(String::as_str) {
        Some("approve") => KubectlClassification {
            intent: vec![Intent::Privilege],
            reversibility: Reversibility::Irreversible,
            flags: vec![flag(
                20,
                RiskFactor::PrivilegeEscalation,
                "certificate approve",
                "Approves a certificate signing request, issuing the requester a cluster credential",
            )],
        },
        Some("deny") => KubectlClassification::simple(Intent::Write, Reversibility::Irreversible),
        _ => KubectlClassification::simple(Intent::Info, Reversibility::Reversible),
    }
}

fn is_rbac_admin_like(args: &[String]) -> bool {
    flag_value_matches(args, "clusterrole", |v| v.contains("admin"))
        || flag_value_matches(args, "user", |v| v.contains("system:admin"))
        || (flag_value_matches(args, "verb", |v| v == "*")
            && flag_value_matches(args, "resource", |v| v == "*"))
}

fn classify_create(args: &[String]) -> KubectlClassification {
    let resource = first_resource(
        args,
        &[
            "--from-literal",
            "--from-file",
            "--clusterrole",
            "--user",
            "--verb",
            "--resource",
        ],
    );

    match resource.as_deref() {
        Some("secret") => {
            let inline = args
                .iter()
                .any(|a| a.starts_with("--from-literal") || a.starts_with("--from-file"));
            KubectlClassification {
                intent: vec![Intent::Write],
                reversibility: Reversibility::HardToReverse,
                flags: if inline {
                    vec![flag(
                        30,
                        RiskFactor::SecretsExposure,
                        "create secret --from-literal/--from-file",
                        "Secret value passed inline, exposing it in shell history/process listings",
                    )]
                } else {
                    vec![]
                },
            }
        }
        Some("clusterrolebinding") | Some("rolebinding") => KubectlClassification {
            intent: vec![Intent::Privilege],
            reversibility: Reversibility::HardToReverse,
            flags: vec![flag(
                if is_rbac_admin_like(args) { 35 } else { 20 },
                RiskFactor::PrivilegeEscalation,
                "create clusterrolebinding/rolebinding",
                "Grants a role's permissions to a user/group/service account",
            )],
        },
        Some("role") | Some("clusterrole") => {
            if is_rbac_admin_like(args) {
                KubectlClassification {
                    intent: vec![Intent::Privilege],
                    reversibility: Reversibility::HardToReverse,
                    flags: vec![flag(
                        30,
                        RiskFactor::PrivilegeEscalation,
                        "create role/clusterrole --verb=* --resource=*",
                        "Defines a role with unrestricted permissions over all resources",
                    )],
                }
            } else {
                KubectlClassification::simple(Intent::Write, Reversibility::HardToReverse)
            }
        }
        Some("serviceaccount") => {
            KubectlClassification::simple(Intent::Write, Reversibility::Reversible)
        }
        _ => {
            let mut flags = vec![];
            if any_filename_is_url(args) {
                flags.push(flag(
                    20,
                    RiskFactor::NetworkExfiltration,
                    "create -f <URL>",
                    "Fetches a manifest from a remote URL and creates the resources it describes",
                ));
            }
            KubectlClassification {
                intent: vec![Intent::Write],
                reversibility: Reversibility::HardToReverse,
                flags,
            }
        }
    }
}

fn classify_apply(args: &[String]) -> KubectlClassification {
    let mut flags = vec![];
    if any_filename_is_url(args) {
        flags.push(flag(
            20,
            RiskFactor::NetworkExfiltration,
            "apply -f/-k <URL>",
            "Fetches a manifest from a remote URL and applies it -- arbitrary attacker-controlled resources",
        ));
    }
    let intent = if flags.is_empty() {
        vec![Intent::Write]
    } else {
        vec![Intent::Network, Intent::Write]
    };
    KubectlClassification {
        intent,
        reversibility: Reversibility::HardToReverse,
        flags,
    }
}
