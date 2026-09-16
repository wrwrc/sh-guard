//! Command wrappers: `sudo`, `env`, `nohup`, `timeout`, `watch`, `ssh <host>
//! <cmd>`, ... -- commands whose risk is mostly the risk of the command
//! they run.
//!
//! These have the same shape as `find -exec` / `fd -x` / `xargs`: a few
//! options of their own, then a payload argv. The generic `CommandRule`
//! model scored the wrapper alone, so `nohup ls` and `nohup rm -rf /`
//! started from the same place, `watch <anything>` was an unknown command
//! (flat `Intent::Execute`), and `sudo rm -rf /` never inherited `rm`'s
//! `RecursiveDelete`.
//!
//! This module splits each wrapper's own options from the payload,
//! classifies the payload with `rules::find_fd::classify_payload` (which
//! routes back through `rules::classify_special`, so a wrapped `git`/`gh`/
//! `kubectl`/`find`/`xargs` gets its real classification), and lets the
//! payload's intent lead -- plus whatever the wrapper itself adds:
//! privilege elevation for `sudo`/`doas`/`su`, remote execution for `ssh`,
//! repetition for `watch`, remote package fetch-and-run for `npx`.

use super::cli_args::flag;
use super::find_fd;
use crate::types::{FlagAnalysis, Intent, Reversibility, RiskFactor};

/// Result of classifying a wrapper invocation.
pub struct WrapperClassification {
    pub intent: Vec<Intent>,
    pub reversibility: Reversibility,
    pub flags: Vec<FlagAnalysis>,
}

/// How one wrapper's own arguments are laid out.
struct WrapperSpec {
    /// Options that consume the following token as a value.
    opts_with_value: &'static [&'static str],
    /// Options that take no value (everything else starting with `-` is
    /// also treated as valueless, so an unknown flag can't swallow the
    /// payload's command name).
    opts_no_value: &'static [&'static str],
    /// Leading positionals that belong to the wrapper, not the payload:
    /// `timeout <duration> <cmd>`, `chroot <dir> <cmd>`, `ssh <host> <cmd>`.
    leading_positionals: usize,
    /// `su`/`script`-style wrappers whose payload follows `-c`.
    payload_after_c: bool,
}

const DEFAULT_SPEC: WrapperSpec = WrapperSpec {
    opts_with_value: &[],
    opts_no_value: &[],
    leading_positionals: 0,
    payload_after_c: false,
};

fn spec_for(name: &str) -> Option<WrapperSpec> {
    let spec = match name {
        "sudo" => WrapperSpec {
            opts_with_value: &[
                "-u",
                "--user",
                "-g",
                "--group",
                "-p",
                "--prompt",
                "-C",
                "-D",
                "--chdir",
                "-R",
                "--chroot",
                "-T",
                "--command-timeout",
            ],
            opts_no_value: &[
                "-E",
                "--preserve-env",
                "-H",
                "--set-home",
                "-n",
                "--non-interactive",
                "-b",
                "--background",
                "-k",
                "--reset-timestamp",
                "-A",
                "--askpass",
                "-S",
                "--stdin",
                "--",
            ],
            ..DEFAULT_SPEC
        },
        "doas" => WrapperSpec {
            opts_with_value: &["-u", "-C"],
            opts_no_value: &["-n", "-s", "-L", "--"],
            ..DEFAULT_SPEC
        },
        "su" => WrapperSpec {
            opts_with_value: &["-c", "--command", "-s", "--shell", "-m", "-g", "--group"],
            opts_no_value: &["-", "-l", "--login", "-p", "--preserve-environment", "--"],
            payload_after_c: true,
            ..DEFAULT_SPEC
        },
        "env" => WrapperSpec {
            opts_with_value: &["-u", "--unset", "-C", "--chdir", "-S", "--split-string"],
            opts_no_value: &[
                "-i",
                "--ignore-environment",
                "-0",
                "--null",
                "-v",
                "--debug",
                "--",
            ],
            ..DEFAULT_SPEC
        },
        "nohup" | "setsid" | "time" => DEFAULT_SPEC,
        "nice" => WrapperSpec {
            opts_with_value: &["-n", "--adjustment"],
            ..DEFAULT_SPEC
        },
        "ionice" => WrapperSpec {
            opts_with_value: &["-c", "--class", "-n", "--classdata", "-p", "--pid"],
            opts_no_value: &["-t", "--ignore"],
            ..DEFAULT_SPEC
        },
        "stdbuf" => WrapperSpec {
            opts_with_value: &["-i", "--input", "-o", "--output", "-e", "--error"],
            ..DEFAULT_SPEC
        },
        "timeout" => WrapperSpec {
            opts_with_value: &["-s", "--signal", "-k", "--kill-after"],
            opts_no_value: &["--preserve-status", "--foreground", "-v", "--verbose", "--"],
            leading_positionals: 1, // DURATION
            ..DEFAULT_SPEC
        },
        "watch" => WrapperSpec {
            opts_with_value: &["-n", "--interval", "--precise"],
            opts_no_value: &[
                "-d",
                "--differences",
                "-t",
                "--no-title",
                "-b",
                "--beep",
                "-e",
                "--errexit",
                "-g",
                "--chgexit",
                "-c",
                "--color",
                "-x",
                "--exec",
                "--",
            ],
            ..DEFAULT_SPEC
        },
        "chroot" => WrapperSpec {
            opts_with_value: &["--userspec", "--groups"],
            leading_positionals: 1, // NEWROOT
            ..DEFAULT_SPEC
        },
        "flock" => WrapperSpec {
            opts_with_value: &["-w", "--wait", "--timeout", "-E", "--conflict-exit-code"],
            opts_no_value: &[
                "-s",
                "--shared",
                "-x",
                "--exclusive",
                "-n",
                "--nonblock",
                "-u",
                "--unlock",
                "-o",
                "--close",
                "--",
            ],
            leading_positionals: 1, // FILE|DIRECTORY|FD
            ..DEFAULT_SPEC
        },
        "ssh" => WrapperSpec {
            opts_with_value: &[
                "-p", "-i", "-o", "-l", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-F", "-I", "-J",
                "-m", "-O", "-Q", "-S", "-W", "-w",
            ],
            opts_no_value: &[
                "-4", "-6", "-A", "-a", "-C", "-f", "-G", "-g", "-K", "-k", "-M", "-N", "-n", "-q",
                "-s", "-T", "-t", "-V", "-v", "-X", "-x", "-Y", "-y", "--",
            ],
            leading_positionals: 1, // [user@]host
            ..DEFAULT_SPEC
        },
        _ => return None,
    };
    Some(spec)
}

/// Split a wrapper's own arguments from the payload argv.
fn split_payload(spec: &WrapperSpec, args: &[String]) -> Vec<String> {
    let mut i = 0;
    let mut positionals_left = spec.leading_positionals;

    while i < args.len() {
        let a = args[i].as_str();

        // `NAME=value` prefix assignments (env's own, and sudo's when
        // invoked as `sudo FOO=bar cmd`) belong to the wrapper.
        let is_assignment = !a.starts_with('-')
            && a.split_once('=')
                .is_some_and(|(name, _)| !name.is_empty() && !name.contains('/'));

        if spec.payload_after_c && matches!(a, "-c" | "--command") {
            // `su -c '<script>' user`: the payload is the script string,
            // which is one token here (the tokenizer keeps its quotes), so
            // split it into an argv the payload classifier can read.
            return args
                .get(i + 1)
                .map(|script| {
                    find_fd::strip_quotes(script)
                        .split_whitespace()
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
        }
        if spec.opts_with_value.contains(&a) {
            i += 2;
            continue;
        }
        if spec
            .opts_with_value
            .iter()
            .any(|o| a.starts_with(&format!("{o}=")))
            || spec.opts_no_value.contains(&a)
        {
            i += 1;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            // Unknown flag (or a fused short option such as `-n5`): assume
            // it takes no separate value, so the payload's command name is
            // never swallowed.
            i += 1;
            continue;
        }
        if is_assignment {
            i += 1;
            continue;
        }
        if positionals_left > 0 {
            positionals_left -= 1;
            i += 1;
            continue;
        }
        return args[i..].to_vec();
    }

    vec![]
}

/// The payload argv of a wrapper invocation, for callers that need to see
/// the wrapped command's own arguments -- notably `analyzer::extract_targets`,
/// which would otherwise miss a path inside a single quoted script string
/// (`watch 'cat /etc/passwd'`).
pub fn payload_tokens(name: &str, args: &[String]) -> Vec<String> {
    let Some(spec) = spec_for(name) else {
        return vec![];
    };
    let payload = split_payload(&spec, args);
    if payload.len() == 1 && payload[0].contains(char::is_whitespace) {
        find_fd::strip_quotes(&payload[0])
            .split_whitespace()
            .map(String::from)
            .collect()
    } else {
        payload
    }
}

/// True for the wrappers this module handles.
pub fn is_wrapper(name: &str) -> bool {
    spec_for(name).is_some() || name == "npx"
}

/// Classify a wrapper invocation. `name` is the wrapper's basename.
pub fn classify(name: &str, args: &[String]) -> Option<WrapperClassification> {
    if name == "npx" {
        return Some(classify_npx(args));
    }
    let spec = spec_for(name)?;
    let payload = split_payload(&spec, args);
    let has_payload = !payload.is_empty();

    let mut flags = vec![];
    let mut intent: Vec<Intent>;
    let mut reversibility;

    if payload.is_empty() {
        // No command to run. `env` alone prints the environment; `ssh host`
        // alone opens an interactive session on the remote host; everything
        // else (`sudo -s`, `su -`) drops the user at a local root prompt.
        intent = match name {
            "env" => vec![Intent::Info],
            "ssh" => vec![Intent::Network],
            _ => vec![Intent::Execute],
        };
        reversibility = match name {
            "env" => Reversibility::Reversible,
            _ => Reversibility::HardToReverse,
        };
    } else {
        // `ssh host 'cat > backup.tar.gz'` passes the remote command as one
        // quoted token; split it so the payload classifier sees an argv.
        let payload = if payload.len() == 1 && payload[0].contains(char::is_whitespace) {
            find_fd::strip_quotes(&payload[0])
                .split_whitespace()
                .map(String::from)
                .collect()
        } else {
            payload
        };
        let payload_result = find_fd::classify_payload(&payload);
        intent = payload_result.intent;
        reversibility = payload_result.reversibility;
        flags.extend(payload_result.flags);
        if intent.is_empty() {
            intent.push(Intent::Execute);
        }
    }

    match name {
        // Elevation: the payload now runs as root, so its own blast radius
        // is the cluster of what it can reach, not just the user's files.
        // Elevation is a modifier, not an intent: what `sudo <cmd>` does is
        // still what `<cmd>` does, one privilege level up. Forcing
        // `Intent::Privilege` (weight 55) to lead would put `sudo ls` in the
        // same band as `sudo rm -rf /`, which is the flat-scoring problem
        // this module exists to fix.
        "sudo" | "doas" | "su" => {
            reversibility = find_fd::worse(reversibility, Reversibility::HardToReverse);
            flags.push(flag(
                20,
                RiskFactor::PrivilegeEscalation,
                name,
                "Runs the command as another user (root by default)",
            ));
        }
        "chroot" => {
            reversibility = find_fd::worse(reversibility, Reversibility::HardToReverse);
            flags.push(flag(
                15,
                RiskFactor::PrivilegeEscalation,
                "chroot",
                "Runs the command with a different root directory, usually as root",
            ));
        }
        "ssh" => {
            if !intent.contains(&Intent::Network) {
                intent.push(Intent::Network);
            }
            // Only a remote *command* is remote execution; `ssh host` on its
            // own is an interactive login.
            if has_payload {
                flags.push(flag(
                    10,
                    RiskFactor::CommandExecution,
                    "ssh <host> <cmd>",
                    "Runs the command on a remote host",
                ));
            } else {
                reversibility = Reversibility::Reversible;
            }
        }
        "watch" => {
            flags.push(flag(
                10,
                RiskFactor::CommandExecution,
                "watch",
                "Re-runs the command repeatedly until interrupted",
            ));
        }
        _ => {}
    }

    Some(WrapperClassification {
        intent,
        reversibility,
        flags,
    })
}

/// `npx <pkg>` downloads a package from the registry if it isn't already
/// installed and runs it -- remote code execution by design, whatever the
/// package does.
fn classify_npx(args: &[String]) -> WrapperClassification {
    let mut flags = vec![flag(
        20,
        RiskFactor::UntrustedExecution,
        "npx",
        "Downloads (if needed) and runs a package from the npm registry",
    )];
    if args
        .iter()
        .any(|a| a == "--yes" || a == "-y" || a == "--package")
    {
        flags.push(flag(
            10,
            RiskFactor::UntrustedExecution,
            "npx --yes",
            "Skips the install confirmation prompt",
        ));
    }
    WrapperClassification {
        intent: vec![Intent::Execute],
        reversibility: Reversibility::HardToReverse,
        flags,
    }
}
