# Changelog

## Unreleased

### Breaking

- **Custom rules are now one `[[rules]]` table.** `allow`, `block`,
  `[[commands]]`, `[[paths]]` and `[[overrides]]` are no longer read; a rule
  is `when` (conditions) plus `then` (effects). Migration:

  | Before | Now |
  |---|---|
  | `allow = ["just"]` | `when = { command = "just" }`, `then = { decision = "allow" }` |
  | `block = ["shutdown"]` | `when = { command = "shutdown" }`, `then = { decision = "block" }` |
  | `block = ["regex:curl.*\| *sh"]` | `when = { command = "regex:..." }` — any condition takes `regex:` |
  | `[[commands]] name/intent/reversibility/mitre` | `when = { command = ... }`, `then = { intent, reversibility, mitre }` |
  | `[[commands.dangerous_flags]] flags/modifier` | a second rule: `when = { command, flag = { ... } }`, `then = { score = { raise = N } }` |
  | `[[paths]] pattern/sensitivity` | `when = { path = ... }`, `then = { sensitivity = ... }` |
  | `[[overrides]] command/score` | `when = { command = ... }`, `then = { score = { set = N } }` |

  Conditions can also match a subcommand (`"delete pod"`), a flag value
  (`flag = { context = "kind-*" }`), an argument, sh-guard's own `intent` or
  `risk_factor`, `env` assignments, `cwd`/`project` and `shell` — so a rule
  can whitelist `kubectl delete` against a local cluster, or cap the score of
  a debug pod, without touching the verb elsewhere. Effects gained
  `score = { cap = N }`.

- **Trust replaces the old per-kind safety rails.** Raising risk applies from
  any rules file. Lowering it is unlimited from `~/.config/sh-guard/rules.toml`,
  from a project listed in its `trust = [...]`, or from a file passed with
  `--rules`; a project's own `.sh-guard.toml` may only soften a command to
  caution, and not at all when the invocation carries a severe risk factor.

- Removed the unused second rules loader (`rules::RuleSet`).

- **`--rules <file>` now layers on top of the default rules files** instead of
  replacing them. Its rules are applied after the user's and the project's,
  so they win a conflict. To get the old behavior, add `--no-default-rules`.

### Added

- `--no-default-rules` skips `~/.config/sh-guard/rules.toml` and the project's
  `.sh-guard.toml`, leaving only the file given with `--rules`, if any — the
  way to test one rules file in isolation.

- Subcommand/flag-aware classification for `git`, `gh`, `kubectl`, `find`/`fd`,
  `xargs`, `docker`/`podman`, the npm family, `systemctl`/`service`, the OS and
  language package managers, `make`/`ninja`, `chmod`, `sed` and `awk`: reads are
  safe, ordinary mutations are caution, destructive verbs scale with what they
  destroy.
- Payload-aware classification for wrappers and exec forms — `sudo`, `env`,
  `nohup`, `timeout`, `watch`, `ssh <host> <cmd>`, `xargs`, `find -exec`,
  `fd -x`, `docker run/exec`, `kubectl exec/run/debug` — the payload's own risk
  leads, so `find -exec ls` stays safe while `find -exec rm -rf` is critical.
- `[[rules]]` conditions and effects (see above), including `regex:` patterns
  everywhere and MITRE ids on custom rules.
- 65 common utilities and shell builtins in the command table.

### Changed

- Dependencies updated to their latest releases: `tree-sitter` 0.26 → 0.27,
  `pyo3` 0.23 → 0.29, and `napi`/`napi-derive` 2 → 3 with `@napi-rs/cli` 2 → 3.
  The Python and Node bindings keep the same public API.

### Fixed

- The agent hook installed by `--setup` now applies the project's
  `.sh-guard.toml`. It classifies in the directory the agent reports
  (falling back to its own), passes the git repository root as the project
  root so the file is found from a subdirectory, and so judges paths
  relative to the project. Previously it passed no context, so only
  `~/.config/sh-guard/rules.toml` ever applied. Re-run `sh-guard --setup`
  to update an installed hook.
- The hook no longer mixes sh-guard's stderr into the JSON it reads the
  block reason from, so a rules-file warning no longer blanks the reason —
  and the warning itself now reaches the agent instead of being discarded.

- Commands inside compound statements (`for`, `while`, `if`, `case`, `{ }`,
  `( )`, function bodies), command/process substitutions, and scripts passed to
  `sh -c`/`bash -c`/`eval` are analyzed. Previously a loop body was never looked
  at, so `for f in x; do rm -rf /; done` scored the same as any other loop.
- Quoted text is no longer scanned as shell syntax: awk programs, JSON
  arguments, `grep "a\|b"` and quoted heredoc bodies no longer read as
  injection, while real expansions still do.
- Path breadth (`/`, `~`, system directories) only counts for commands that
  read contents or change something, so `ls /` and `find / -name x` are safe.
- Bare sensitive filenames (`cat id_rsa`) are recognized as paths.
- `--version`/`--help` probes, syntax checks (`php -l`, `bash -n`) and bare
  assignments run no code; piping into an ordinary program is not shell
  execution.
- Custom rules apply to auto-discovered configuration, not just to a file
  passed with `--rules`.
- The Python extension module links on macOS: a build script now emits the
  `-undefined dynamic_lookup` arguments PyO3 requires, so `cargo build
  --workspace` no longer fails on undefined `_Py*` symbols.
- Rules files no longer fail silently. Every way of writing a rule wrong now
  prints a `sh-guard:` warning on stderr naming the file and rule:
  - a TOML syntax error, which discards the whole file;
  - a rule with no conditions or no effects;
  - a `regex:` pattern that does not compile — the rule is now ignored
    instead of kept as a condition that can never match (an invalid `trust`
    entry is skipped);
  - an unrecognized `intent`, `risk_factor`, `sensitivity`, `reversibility`,
    `decision` or `shell` — the rule is now ignored instead of resolved to a
    default. A typo in `then.intent` used to mean `execute`, making the rule
    quietly more severe; a typo in `when.risk_factor` used to delete the
    condition, making the rule match *more* commands than written.
- `when.env` conditions now apply to `decision` and `score` effects, not only
  to classification. `AWS_PROFILE=prod deploy` can be blocked by environment.
- A leading `NAME=value` assignment is no longer mistaken for the executable
  when rules are matched, which had shifted every argument by one and made
  the real executable look like a subcommand.
- A rule whose only effect is `mitre` is kept; it was dropped as effectless.


## 0.1.0 (2026-04-03)

Initial release.

### Features

- **AST parsing** via tree-sitter-bash with regex fallback
- **Semantic analysis** classifying intent, targets, flags, and risk factors
- **Pipeline taint analysis** tracking data flow through pipes to detect exfiltration
- **Risk scoring** (0-100) with four levels: safe, caution, danger, critical
- **MITRE ATT&CK mapping** for every detected risk
- **157 command rules** covering coreutils, git, curl, docker, kubectl, cloud CLIs
- **51 path rules** for secrets, system files, and config files
- **25 injection patterns** including command substitution, IFS injection, unicode tricks
- **15 zsh-specific rules** for module loading, glob qualifiers, equals expansion
- **61 GTFOBins entries** for binary capability detection
- **15 taint flow rules** for pipeline data-flow escalation
- **Custom rules** via TOML configuration
- **CLI** with colored output, JSON mode, stdin batch, and exit codes
- **MCP server** for Claude Code, Cursor, Cline, and Windsurf
- **`--setup` command** to auto-configure all AI coding agents
- **Node.js bindings** via napi-rs
- **Python bindings** via PyO3
- **Multi-platform binaries** for macOS (ARM/x64), Linux (x64/ARM64), Windows (x64)
