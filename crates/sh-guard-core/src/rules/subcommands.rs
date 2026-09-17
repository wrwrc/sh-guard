//! Verb-aware classification for the remaining subcommand-shaped tools:
//! `docker`/`podman`, the npm-family package managers, `systemctl`/
//! `service`, and the OS/language package managers.
//!
//! Each of these had a single `CommandRule`, so every invocation scored the
//! same: `docker ps` and `docker system prune -af` were both DANGER 60,
//! `brew list` and `brew uninstall` both CAUTION 45, `systemctl status` and
//! `systemctl mask sshd` both CAUTION 50. This module splits each tool's
//! verbs into reads, ordinary mutations and destructive operations, and --
//! for `docker run`/`docker exec` -- classifies the container command with
//! the shared payload machinery, exactly as `find -exec`/`xargs` do.

use super::cli_args::flag;
use super::find_fd;
use crate::types::{FlagAnalysis, Intent, Reversibility, RiskFactor};

pub struct SubcommandClassification {
    pub intent: Vec<Intent>,
    pub reversibility: Reversibility,
    pub flags: Vec<FlagAnalysis>,
}

impl SubcommandClassification {
    fn new(intent: Intent, reversibility: Reversibility) -> Self {
        SubcommandClassification {
            intent: vec![intent],
            reversibility,
            flags: vec![],
        }
    }

    fn with(mut self, f: FlagAnalysis) -> Self {
        self.flags.push(f);
        self
    }
}

fn read() -> SubcommandClassification {
    SubcommandClassification::new(Intent::Info, Reversibility::Reversible)
}

/// True for the tools this module handles.
pub fn is_subcommand_tool(name: &str) -> bool {
    matches!(
        name,
        "docker"
            | "podman"
            | "npm"
            | "yarn"
            | "pnpm"
            | "systemctl"
            | "service"
            | "brew"
            | "apt"
            | "apt-get"
            | "pip"
            | "pip3"
            | "gem"
            | "cargo"
            | "go"
            | "make"
            | "gmake"
            | "ninja"
            | "chmod"
            | "sed"
            | "gsed"
            | "awk"
            | "gawk"
            | "nawk"
            | "mawk"
    )
}

/// Skip leading global options to find the verb. Options that take a
/// separate value are listed per tool; anything else starting with `-` is
/// assumed valueless, so the verb is never swallowed.
fn find_verb<'a>(args: &'a [String], opts_with_value: &[&str]) -> (Option<&'a str>, &'a [String]) {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if opts_with_value.contains(&a) {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        return (Some(a), &args[i + 1..]);
    }
    (None, &[])
}

fn has(args: &[String], needles: &[&str]) -> bool {
    args.iter().any(|a| {
        needles
            .iter()
            .any(|n| a == n || a.starts_with(&format!("{n}=")))
    })
}

pub fn classify(name: &str, args: &[String]) -> Option<SubcommandClassification> {
    match name {
        "docker" | "podman" => Some(classify_docker(args)),
        "npm" | "yarn" | "pnpm" => Some(classify_npm(name, args)),
        "systemctl" | "service" => Some(classify_systemctl(name, args)),
        "brew" | "apt" | "apt-get" | "pip" | "pip3" | "gem" | "cargo" | "go" => {
            Some(classify_pkg(name, args))
        }
        "make" | "gmake" | "ninja" => Some(classify_make(args)),
        "chmod" => Some(classify_chmod(args)),
        "sed" | "gsed" => Some(classify_sed(args)),
        "awk" | "gawk" | "nawk" | "mawk" => Some(classify_awk(args)),
        _ => None,
    }
}

// ========================================================
// docker / podman
// ========================================================

const DOCKER_GLOBAL_VALUE_OPTS: &[&str] = &[
    "-H",
    "--host",
    "--context",
    "--config",
    "-l",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
];

/// Options of `docker run`/`docker exec` that consume a separate value, so
/// the image/container positional (and then the payload) can be located.
const DOCKER_RUN_VALUE_OPTS: &[&str] = &[
    "-v",
    "--volume",
    "-e",
    "--env",
    "-p",
    "--publish",
    "-u",
    "--user",
    "-w",
    "--workdir",
    "--name",
    "--network",
    "--net",
    "--entrypoint",
    "--mount",
    "--device",
    "--cap-add",
    "--cap-drop",
    "--restart",
    "--memory",
    "-m",
    "--cpus",
    "--label",
    "-l",
    "--env-file",
    "--add-host",
    "--health-cmd",
    "--pid",
    "--ipc",
    "--userns",
    "--security-opt",
    "--platform",
];

fn docker_host_exposure(args: &[String]) -> Option<FlagAnalysis> {
    let mounts_host_root = args.iter().any(|a| {
        let a = a.trim_matches(['\'', '"']);
        a == "/"
            || a.starts_with("/:")
            || a.starts_with("/etc:")
            || a.starts_with("/var/run/docker.sock")
    });
    if has(args, &["--privileged"]) {
        return Some(flag(
            35,
            RiskFactor::PrivilegeEscalation,
            "docker run --privileged",
            "Runs the container with full host capabilities, defeating container isolation",
        ));
    }
    if mounts_host_root
        || has(args, &["--pid", "--ipc", "--userns"]) && args.iter().any(|a| a.contains("host"))
    {
        return Some(flag(
            40,
            RiskFactor::PrivilegeEscalation,
            "docker run -v / / --pid=host",
            "Gives the container access to the host filesystem or namespaces",
        ));
    }
    if has(args, &["--cap-add"]) {
        return Some(flag(
            15,
            RiskFactor::PrivilegeEscalation,
            "docker run --cap-add",
            "Adds Linux capabilities to the container",
        ));
    }
    None
}

fn classify_docker(args: &[String]) -> SubcommandClassification {
    let (verb, rest) = find_verb(args, DOCKER_GLOBAL_VALUE_OPTS);
    let Some(verb) = verb else {
        return read();
    };

    // `docker container ls`, `docker image prune`, ... -- the object comes
    // first, the action second.
    let (object, verb, rest) = match verb {
        "container" | "image" | "volume" | "network" | "system" | "builder" | "buildx"
        | "compose" | "context" | "node" | "service" | "stack" | "swarm" | "secret" | "config"
        | "plugin" | "trust" => {
            let (sub, tail) = find_verb(rest, &[]);
            (Some(verb), sub.unwrap_or("ls"), tail)
        }
        _ => (None, verb, rest),
    };

    let mut result = match verb {
        // Reads
        "ps" | "ls" | "images" | "logs" | "inspect" | "top" | "stats" | "version" | "info"
        | "history" | "port" | "diff" | "search" | "events" | "df" | "config" | "context"
        | "wait" => read(),

        // Runs a command in a container: payload-aware.
        "run" | "exec" | "attach" => {
            let (_target, payload) = find_verb(rest, DOCKER_RUN_VALUE_OPTS);
            let payload_tokens: Vec<String> = payload.to_vec();
            let mut r = if payload_tokens.is_empty() {
                SubcommandClassification::new(Intent::Execute, Reversibility::HardToReverse)
            } else {
                let p = find_fd::classify_payload(&payload_tokens);
                let mut intent = p.intent;
                if intent.is_empty() {
                    intent.push(Intent::Execute);
                }
                SubcommandClassification {
                    intent,
                    reversibility: find_fd::worse(p.reversibility, Reversibility::HardToReverse),
                    flags: p.flags,
                }
            };
            r = r.with(flag(
                15,
                RiskFactor::CommandExecution,
                "docker run/exec",
                "Runs a command inside a container",
            ));
            if let Some(f) = docker_host_exposure(rest) {
                r.reversibility = Reversibility::Irreversible;
                r = r.with(f);
            }
            r
        }

        // Ordinary mutations
        "build" | "pull" | "tag" | "create" | "start" | "restart" | "pause" | "unpause"
        | "commit" | "cp" | "save" | "load" | "import" | "export" | "login" | "logout"
        | "rename" | "update" | "up" => {
            SubcommandClassification::new(Intent::Write, Reversibility::Reversible)
        }
        "push" => SubcommandClassification::new(Intent::Network, Reversibility::HardToReverse)
            .with(flag(
                10,
                RiskFactor::NetworkExfiltration,
                "docker push",
                "Publishes an image to a remote registry",
            )),
        "stop" | "kill" => {
            SubcommandClassification::new(Intent::ProcessControl, Reversibility::HardToReverse)
        }

        // Destructive
        "rm" | "rmi" | "down" => {
            let forced = has(rest, &["-f", "--force", "-v", "--volumes"]);
            SubcommandClassification::new(Intent::Delete, Reversibility::HardToReverse).with(flag(
                if forced { 15 } else { 5 },
                RiskFactor::RecursiveDelete,
                "docker rm/rmi",
                "Removes containers, images or volumes",
            ))
        }
        "prune" => {
            let broad = has(rest, &["-a", "--all", "--volumes"]);
            SubcommandClassification::new(Intent::Delete, Reversibility::Irreversible).with(flag(
                if broad { 30 } else { 20 },
                RiskFactor::RecursiveDelete,
                "docker prune",
                "Removes unused containers, images, networks and (with --volumes) their data",
            ))
        }

        // Unknown verb: could be a plugin.
        _ => SubcommandClassification::new(Intent::Execute, Reversibility::HardToReverse),
    };

    // `docker system prune` / `volume rm` destroy data that lives outside a
    // container's lifecycle.
    if matches!(object, Some("volume") | Some("system")) && matches!(verb, "prune" | "rm") {
        result = result.with(flag(
            15,
            RiskFactor::BroadScope,
            "docker volume/system prune",
            "Destroys persisted volume data, not just container state",
        ));
    }

    result
}

// ========================================================
// npm / yarn / pnpm
// ========================================================

fn classify_npm(_name: &str, args: &[String]) -> SubcommandClassification {
    let (verb, rest) = find_verb(args, &["--prefix", "--registry", "-w", "--workspace"]);
    let Some(verb) = verb else {
        return read();
    };

    match verb {
        "ls" | "list" | "view" | "info" | "show" | "outdated" | "ping" | "whoami" | "search"
        | "audit" | "why" | "doctor" | "root" | "prefix" | "bin" | "help" | "version" => {
            if verb == "audit" && has(rest, &["fix", "--fix"]) {
                SubcommandClassification::new(Intent::PackageInstall, Reversibility::HardToReverse)
            } else {
                read()
            }
        }
        "config" | "set" | "get" => {
            if verb == "get" || has(rest, &["get", "list"]) {
                read()
            } else {
                SubcommandClassification::new(Intent::EnvModify, Reversibility::HardToReverse)
            }
        }
        // Package scripts are arbitrary code from the project (and its
        // dependencies' lifecycle hooks).
        "run" | "run-script" | "exec" | "start" | "test" | "dlx" | "create" => {
            SubcommandClassification::new(Intent::Execute, Reversibility::Reversible).with(flag(
                5,
                RiskFactor::CommandExecution,
                "npm run/exec",
                "Runs a package script, which can execute arbitrary code",
            ))
        }
        "install" | "i" | "add" | "ci" | "update" | "upgrade" | "link" | "dedupe" | "rebuild"
        | "fund" | "prune" => {
            SubcommandClassification::new(Intent::PackageInstall, Reversibility::HardToReverse)
                .with(flag(
                    5,
                    RiskFactor::UntrustedExecution,
                    "npm install",
                    "Fetches packages that can run install-time lifecycle scripts",
                ))
        }
        "publish" => SubcommandClassification::new(Intent::Network, Reversibility::Irreversible)
            .with(flag(
                20,
                RiskFactor::NetworkExfiltration,
                "npm publish",
                "Publishes the package publicly; a published version cannot be replaced",
            )),
        "unpublish" | "deprecate" => {
            SubcommandClassification::new(Intent::Delete, Reversibility::Irreversible).with(flag(
                20,
                RiskFactor::RecursiveDelete,
                "npm unpublish",
                "Removes a published version other projects may depend on",
            ))
        }
        "uninstall" | "remove" | "rm" | "un" => {
            SubcommandClassification::new(Intent::Delete, Reversibility::Reversible)
        }
        "cache" => {
            if has(rest, &["clean", "clear", "rm", "verify"]) {
                SubcommandClassification::new(Intent::Delete, Reversibility::Reversible)
            } else {
                read()
            }
        }
        // Unknown verb for a package manager: a mutation of the project's
        // dependency state at minimum.
        _ => SubcommandClassification::new(Intent::PackageInstall, Reversibility::HardToReverse),
    }
}

// ========================================================
// systemctl / service
// ========================================================

fn classify_systemctl(name: &str, args: &[String]) -> SubcommandClassification {
    // `service <unit> <verb>` puts the unit first.
    let (verb, _rest) = if name == "service" {
        let (_unit, tail) = find_verb(args, &[]);
        let (verb, rest) = find_verb(tail, &[]);
        (verb, rest)
    } else {
        find_verb(
            args,
            &[
                "-t",
                "--type",
                "--state",
                "--property",
                "-p",
                "-M",
                "--machine",
            ],
        )
    };
    let Some(verb) = verb else {
        return read();
    };

    match verb {
        "status" | "list-units" | "list-unit-files" | "list-timers" | "list-sockets" | "show"
        | "cat" | "is-active" | "is-enabled" | "is-failed" | "get-default" | "show-environment"
        | "help" => read(),

        "start" | "restart" | "reload" | "try-restart" | "reload-or-restart" | "daemon-reload"
        | "daemon-reexec" | "enable" | "set-default" | "set-property" | "unmask" | "preset" => {
            SubcommandClassification::new(Intent::ProcessControl, Reversibility::Reversible)
        }

        // Taking a service down (or preventing it from starting) is an
        // outage, and `mask` persists until explicitly undone.
        "stop" | "disable" | "kill" => {
            SubcommandClassification::new(Intent::ProcessControl, Reversibility::HardToReverse)
                .with(flag(
                    10,
                    RiskFactor::BroadScope,
                    "systemctl stop/disable",
                    "Stops a running service, interrupting whatever depends on it",
                ))
        }
        "mask" => {
            SubcommandClassification::new(Intent::ProcessControl, Reversibility::HardToReverse)
                .with(flag(
                    20,
                    RiskFactor::BroadScope,
                    "systemctl mask",
                    "Makes the unit unstartable until explicitly unmasked",
                ))
        }
        "isolate" | "poweroff" | "reboot" | "halt" | "kexec" | "emergency" | "rescue"
        | "suspend" | "hibernate" => {
            SubcommandClassification::new(Intent::ProcessControl, Reversibility::Irreversible).with(
                flag(
                    30,
                    RiskFactor::BroadScope,
                    "systemctl poweroff/reboot/isolate",
                    "Changes the whole system's running state",
                ),
            )
        }
        _ => SubcommandClassification::new(Intent::ProcessControl, Reversibility::HardToReverse),
    }
}

// ========================================================
// OS / language package managers
// ========================================================

fn classify_pkg(name: &str, args: &[String]) -> SubcommandClassification {
    let (verb, rest) = find_verb(
        args,
        &["-C", "--manifest-path", "--target", "-t", "--config"],
    );
    let Some(verb) = verb else {
        return read();
    };

    match verb {
        // Reads
        "list" | "ls" | "search" | "show" | "info" | "outdated" | "deps" | "depends" | "policy"
        | "config" | "which" | "home" | "doctor" | "tree" | "licenses" | "index" | "freeze"
        | "check" | "audit" | "verify" | "version" | "help" | "env" => read(),

        // Builds run project-defined code (build.rs, setup.py, postinstall).
        "build" | "b" | "test" | "bench" | "run" | "check-all" | "doc" | "clippy" | "fmt"
        | "generate" | "vet" => {
            SubcommandClassification::new(Intent::Execute, Reversibility::Reversible).with(flag(
                5,
                RiskFactor::CommandExecution,
                "build/test",
                "Runs project-defined build or test code",
            ))
        }

        "install" | "i" | "add" | "get" | "reinstall" | "upgrade" | "update" | "tap" | "fetch"
        | "download" | "publish" => {
            let auto_yes = has(rest, &["-y", "--yes", "--assume-yes", "--force", "-f"]);
            let mut r =
                SubcommandClassification::new(Intent::PackageInstall, Reversibility::HardToReverse)
                    .with(flag(
                        5,
                        RiskFactor::UntrustedExecution,
                        "package install",
                        "Fetches and installs code that can run install-time scripts",
                    ));
            if auto_yes {
                r = r.with(flag(
                    5,
                    RiskFactor::ForceFlag,
                    "-y/--force",
                    "Skips confirmation prompts",
                ));
            }
            r
        }

        // Removals: `--purge`/`autoremove` take configuration and
        // dependencies with them.
        "remove" | "rm" | "uninstall" | "purge" | "autoremove" | "autopurge" | "cleanup"
        | "prune" | "clean" => {
            let purges = verb == "purge"
                || verb == "autoremove"
                || verb == "autopurge"
                || has(rest, &["--purge", "--all", "-a"]);
            SubcommandClassification::new(
                Intent::Delete,
                if purges {
                    Reversibility::HardToReverse
                } else {
                    Reversibility::Reversible
                },
            )
            .with(flag(
                if purges { 20 } else { 10 },
                RiskFactor::RecursiveDelete,
                "package removal",
                "Removes installed packages (and, when purging, their configuration)",
            ))
        }

        _ => SubcommandClassification::new(
            Intent::PackageInstall,
            if name == "cargo" {
                Reversibility::Reversible
            } else {
                Reversibility::HardToReverse
            },
        ),
    }
}

// ========================================================
// chmod
// ========================================================

/// `chmod +x script.sh` and `chmod 644 file` are routine; world-writable
/// or setuid/setgid modes are the privilege-relevant ones. The table entry
/// scored every chmod as `Intent::Privilege` (weight 55), so making your
/// own script executable was DANGER.
fn classify_chmod(args: &[String]) -> SubcommandClassification {
    let recursive = args.iter().any(|a| {
        a == "-R"
            || a == "--recursive"
            || (a.starts_with('-') && !a.starts_with("--") && a.contains('R'))
    });
    let mode = args
        .iter()
        .map(|a| a.trim_matches(['\'', '"']))
        .find(|a| {
            !a.starts_with('-') || a.starts_with("-w") || a.starts_with("-x") || a.starts_with("-r")
        })
        .unwrap_or("");

    let (setid, world_writable) = chmod_mode_risk(mode);
    // Any mode change on a system file is a privileged operation: `chmod 000
    // /etc/passwd` locks every user out, whatever the bits.
    let system_target = args.iter().any(|a| {
        let a = a.trim_matches(['\'', '"']);
        [
            "/etc",
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/boot",
            "/System",
            "/private/etc",
            "/var/root",
        ]
        .iter()
        .any(|d| a == *d || a.starts_with(&format!("{d}/")))
    });

    let mut r = if setid || world_writable || system_target {
        SubcommandClassification::new(Intent::Privilege, Reversibility::HardToReverse)
    } else {
        SubcommandClassification::new(Intent::Write, Reversibility::Reversible)
    };
    if setid {
        r = r.with(flag(
            30,
            RiskFactor::PrivilegeEscalation,
            "chmod +s",
            "Sets the setuid/setgid bit, letting the file run with its owner's privileges",
        ));
    }
    if world_writable {
        r = r.with(flag(
            20,
            RiskFactor::PrivilegeEscalation,
            "chmod 777 / o+w",
            "Makes the file writable by every user",
        ));
    }
    if system_target && !setid && !world_writable {
        r = r.with(flag(
            15,
            RiskFactor::PrivilegeEscalation,
            "chmod <system path>",
            "Changes permissions on a system file",
        ));
    }
    if recursive {
        r = r.with(flag(
            10,
            RiskFactor::BroadScope,
            "chmod -R",
            "Applies the mode to a whole directory tree",
        ));
    }
    r
}

/// (sets setuid/setgid, grants write to "other") for an octal or symbolic mode.
fn chmod_mode_risk(mode: &str) -> (bool, bool) {
    if !mode.is_empty() && mode.chars().all(|c| c.is_ascii_digit()) {
        let digits: Vec<u32> = mode.chars().filter_map(|c| c.to_digit(8)).collect();
        let (special, other) = match digits.len() {
            4 => (digits[0], digits[3]),
            3 => (0, digits[2]),
            _ => (0, 0),
        };
        return (special & 0b110 != 0, other & 0b010 != 0);
    }
    let mut setid = false;
    let mut world_writable = false;
    for clause in mode.split(',') {
        let op_pos = clause.find(['+', '=', '-']);
        let Some(op_pos) = op_pos else { continue };
        let who = &clause[..op_pos];
        let op = &clause[op_pos..op_pos + 1];
        let perms = &clause[op_pos + 1..];
        if op == "-" {
            continue;
        }
        if perms.contains('s') {
            setid = true;
        }
        let applies_to_other = who.is_empty() || who.contains('o') || who.contains('a');
        if perms.contains('w') && applies_to_other {
            world_writable = true;
        }
    }
    (setid, world_writable)
}

// ========================================================
// sed / awk
// ========================================================

/// `sed` only writes files with `-i` (in place) or a `w` command, and only
/// runs commands with GNU sed's `e`. `sed -n '1,5p' file` is a read.
fn classify_sed(args: &[String]) -> SubcommandClassification {
    let in_place = args.iter().any(|a| {
        a == "-i" || a.starts_with("-i") && !a.starts_with("--") || a.starts_with("--in-place")
    });
    let scripts: Vec<String> = sed_scripts(args);
    let executes = scripts.iter().any(|sc| sed_script_executes(sc));
    let writes_file = scripts.iter().any(|sc| sed_script_writes(sc));

    if executes {
        return SubcommandClassification::new(Intent::Execute, Reversibility::HardToReverse).with(
            flag(
                20,
                RiskFactor::CommandExecution,
                "sed e",
                "GNU sed's `e` command runs its pattern space as a shell command",
            ),
        );
    }
    if in_place || writes_file {
        return SubcommandClassification::new(Intent::Write, Reversibility::HardToReverse).with(
            flag(10, RiskFactor::Write, "sed -i", "Edits the file in place"),
        );
    }
    SubcommandClassification::new(Intent::Read, Reversibility::Reversible)
}

fn sed_scripts(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut saw_explicit = false;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-e" || a == "--expression" {
            if let Some(v) = args.get(i + 1) {
                out.push(v.trim_matches(['\'', '"']).to_string());
            }
            saw_explicit = true;
            i += 2;
            continue;
        }
        if let Some(v) = a.strip_prefix("--expression=") {
            out.push(v.trim_matches(['\'', '"']).to_string());
            saw_explicit = true;
        }
        i += 1;
    }
    if !saw_explicit {
        if let Some(first) = args.iter().find(|a| !a.starts_with('-')) {
            out.push(first.trim_matches(['\'', '"']).to_string());
        }
    }
    out
}

fn sed_script_executes(script: &str) -> bool {
    // `s/a/b/e` (substitution flag) or a bare `e [command]` command.
    script.split([';', '\n']).any(|cmd| {
        let cmd = cmd.trim();
        let substitution_e = cmd.starts_with('s') && cmd.len() > 1 && {
            let delim = cmd.chars().nth(1).unwrap();
            let parts: Vec<&str> = cmd[2..].split(delim).collect();
            parts.len() >= 3 && parts[2].contains('e')
        };
        substitution_e || cmd == "e" || cmd.starts_with("e ")
    })
}

fn sed_script_writes(script: &str) -> bool {
    script.split([';', '\n']).any(|cmd| {
        let cmd = cmd.trim();
        cmd.starts_with("w ") || cmd.starts_with("W ")
    })
}

/// `awk` is a read unless the program runs commands (`system()`, piping to
/// or from a command) or writes files (`print > "file"`, `-i inplace`).
fn classify_awk(args: &[String]) -> SubcommandClassification {
    let in_place = args.windows(2).any(|w| {
        (w[0] == "-i" || w[0] == "--include") && w[1].trim_matches(['\'', '"']) == "inplace"
    });
    let program = awk_program(args);

    let executes = program.contains("system(")
        || program.contains("| getline")
        || program.contains("|getline")
        || awk_prints_to_pipe(&program);
    if executes {
        return SubcommandClassification::new(Intent::Execute, Reversibility::HardToReverse).with(
            flag(
                20,
                RiskFactor::CommandExecution,
                "awk system()",
                "The awk program runs shell commands",
            ),
        );
    }
    if in_place || awk_redirects_output(&program) {
        return SubcommandClassification::new(Intent::Write, Reversibility::HardToReverse);
    }
    SubcommandClassification::new(Intent::Read, Reversibility::Reversible)
}

fn awk_program(args: &[String]) -> String {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if matches!(a, "-f" | "--file") {
            // Program in a file we can't see: stay conservative.
            return "system(".to_string();
        }
        if matches!(
            a,
            "-F" | "-v" | "--assign" | "--field-separator" | "-i" | "--include"
        ) {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        return a.trim_matches(['\'', '"']).to_string();
    }
    String::new()
}

fn awk_prints_to_pipe(program: &str) -> bool {
    // `print ... | "cmd"` -- a pipe followed by a string.
    program
        .match_indices('|')
        .any(|(i, _)| program[i + 1..].trim_start().starts_with('"'))
}

fn awk_redirects_output(program: &str) -> bool {
    // `print ... > "file"` / `>> "file"` -- a comparison `>` is followed by
    // a number or identifier, not a string.
    program.match_indices('>').any(|(i, _)| {
        program[i + 1..]
            .trim_start_matches('>')
            .trim_start()
            .starts_with('"')
    })
}

// ========================================================
// make / ninja
// ========================================================

/// Building a project runs its build recipes -- code, but the project's own,
/// producing artifacts that a clean rebuild regenerates. That makes a plain
/// build an ordinary mutation (CAUTION), not unknown-binary code execution.
/// `install` targets write outside the project and `clean`-style targets
/// delete, so those are priced up; `sudo make install` adds elevation on
/// top via the wrapper.
fn classify_make(args: &[String]) -> SubcommandClassification {
    let mut targets = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        // Options that take a separate value (make and ninja).
        if matches!(
            a,
            "-f" | "--file"
                | "--makefile"
                | "-C"
                | "--directory"
                | "-j"
                | "--jobs"
                | "-l"
                | "--load-average"
                | "-I"
                | "--include-dir"
                | "-o"
                | "--old-file"
                | "-W"
                | "--what-if"
        ) {
            // `-j` may appear without a value; only skip a following number.
            if matches!(a, "-j" | "--jobs" | "-l" | "--load-average") {
                if args
                    .get(i + 1)
                    .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
                {
                    i += 1;
                }
            } else {
                i += 1;
            }
            i += 1;
            continue;
        }
        if a.starts_with('-') || a.contains('=') {
            i += 1;
            continue;
        }
        targets.push(a);
        i += 1;
    }

    let installs = targets
        .iter()
        .any(|t| t.starts_with("install") || *t == "deploy" || *t == "release" || *t == "publish");
    let cleans = targets.iter().any(|t| {
        matches!(
            *t,
            "clean" | "distclean" | "mrproper" | "realclean" | "uninstall" | "purge"
        )
    });

    let mut r = SubcommandClassification::new(
        Intent::Write,
        if installs {
            Reversibility::HardToReverse
        } else {
            Reversibility::Reversible
        },
    )
    .with(flag(
        5,
        RiskFactor::CommandExecution,
        "make",
        "Runs the project's build recipes",
    ));
    if installs {
        r = r.with(flag(
            10,
            RiskFactor::EscapesProjectBoundary,
            "make install/deploy",
            "Installs or publishes build output outside the project",
        ));
    }
    if cleans {
        r.intent = vec![Intent::Delete];
        r = r.with(flag(
            5,
            RiskFactor::RecursiveDelete,
            "make clean",
            "Deletes build output",
        ));
    }
    r
}
