//! Command-wrapper classification tests (`rules::wrappers`).
//!
//! Wrappers run another command, so their risk is mostly the payload's:
//! these tests pin that the payload leads, that each wrapper's own
//! contribution (elevation, remote execution, repetition, remote package
//! fetch) still shows up, and that a wrapper's own options are never
//! mistaken for the payload.

use sh_guard_core::*;

fn analyze(cmd: &str) -> AnalysisResult {
    classify(cmd, None)
}

fn first_sub(result: &AnalysisResult) -> &CommandAnalysis {
    &result.sub_commands[0]
}

fn has_risk_factor(a: &CommandAnalysis, rf: RiskFactor) -> bool {
    a.risk_factors.contains(&rf)
}

#[test]
fn read_payloads_stay_low_through_every_wrapper() {
    for cmd in [
        "env ls",
        "env FOO=bar ls",
        "nohup ls",
        "setsid ls",
        "time ls",
        "nice -n 10 ls",
        "ionice -c 3 ls",
        "stdbuf -o0 ls",
        "timeout 5 ls",
        "watch ls",
        "watch -n 5 kubectl get pods",
        "flock /tmp/lock ls",
        // env with no command prints the environment.
        "env",
    ] {
        let result = analyze(cmd);
        assert_eq!(
            result.level,
            RiskLevel::Safe,
            "{cmd}: got {:?} ({})",
            result.level,
            result.score
        );
    }
}

#[test]
fn destructive_payloads_are_inherited_through_every_wrapper() {
    for cmd in [
        "env rm -rf /",
        "nohup rm -rf /",
        "setsid rm -rf /",
        "time rm -rf /",
        "nice rm -rf /",
        "ionice -c 3 rm -rf /",
        "timeout 5 rm -rf /",
        "timeout -s KILL 5 rm -rf /",
        "watch rm -rf /",
        "flock /tmp/lock rm -rf /",
        "sudo rm -rf /",
        "doas rm -rf /",
        "chroot /mnt rm -rf /",
        "ssh host rm -rf /",
    ] {
        let result = analyze(cmd);
        let a = first_sub(&result);
        assert!(
            has_risk_factor(a, RiskFactor::RecursiveDelete),
            "{cmd}: expected inherited RecursiveDelete, got {:?}",
            a.risk_factors
        );
        assert_eq!(result.level, RiskLevel::Critical, "{cmd}: {}", result.score);
    }
}

#[test]
fn wrapped_subcommand_tools_keep_their_own_classification() {
    // The payload dispatch routes back through `classify_special`, so a
    // wrapped git/gh/kubectl is classified as itself.
    for (cmd, rf) in [
        ("sudo git push --force", RiskFactor::GitHistoryDestruction),
        (
            "nohup kubectl delete namespace prod",
            RiskFactor::BroadScope,
        ),
        ("timeout 60 xargs rm -rf", RiskFactor::RecursiveDelete),
    ] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), rf),
            "{cmd}: expected {rf:?}, got {:?}",
            first_sub(&result).risk_factors
        );
    }
    // ... and a wrapped read stays a read.
    assert_eq!(analyze("sudo kubectl get pods").level, RiskLevel::Caution);
}

#[test]
fn elevation_is_a_modifier_not_an_intent() {
    // Regression: making sudo force Intent::Privilege put `sudo ls` in the
    // same band as `sudo rm -rf /`.
    let sudo_read = analyze("sudo ls");
    assert_eq!(sudo_read.level, RiskLevel::Caution, "{}", sudo_read.score);
    assert!(has_risk_factor(
        first_sub(&sudo_read),
        RiskFactor::PrivilegeEscalation
    ));

    // Elevation still raises the payload's own score.
    assert!(analyze("sudo rm file.txt").score > analyze("rm file.txt").score);
    assert!(analyze("sudo ls").score > analyze("ls").score);

    // No payload: an interactive root shell.
    for cmd in ["sudo -s", "sudo -i", "su -"] {
        let result = analyze(cmd);
        assert!(
            matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
            "{cmd}: got {:?} ({})",
            result.level,
            result.score
        );
    }
}

#[test]
fn wrapper_options_are_not_mistaken_for_the_payload() {
    // -u/-n/-s/-p values and leading positionals (duration, dir, lock file,
    // host) all belong to the wrapper.
    for cmd in [
        "sudo -u www ls",
        "sudo -u rm ls",
        "timeout 30 ls",
        "timeout -k 5 30 ls",
        "chroot /mnt ls",
        "flock /tmp/rm ls",
        "ssh -p 2222 -o StrictHostKeyChecking=no host ls",
        "nice -n 19 ls",
    ] {
        let result = analyze(cmd);
        assert!(
            !has_risk_factor(first_sub(&result), RiskFactor::RecursiveDelete),
            "{cmd}: the payload is `ls`, got {:?}",
            first_sub(&result).risk_factors
        );
    }
}

#[test]
fn quoted_script_payloads_are_parsed() {
    // `su -c '<script>'` and `ssh host '<script>'` arrive as one token.
    let su = analyze("su -c 'rm -rf /' root");
    assert!(has_risk_factor(first_sub(&su), RiskFactor::RecursiveDelete));

    let ssh = analyze("ssh host 'cat /etc/shadow'");
    assert_eq!(ssh.level, RiskLevel::Critical, "{}", ssh.score);

    // Paths inside a quoted payload are visible to target extraction.
    let watch = analyze("watch 'cat /etc/passwd'");
    assert!(
        watch.reason.contains("/etc/passwd"),
        "reason: {}",
        watch.reason
    );
}

#[test]
fn ssh_distinguishes_login_from_remote_command() {
    let login = analyze("ssh user@host");
    assert_eq!(login.level, RiskLevel::Caution, "{}", login.score);
    assert!(!has_risk_factor(
        first_sub(&login),
        RiskFactor::CommandExecution
    ));

    let remote = analyze("ssh host ls");
    assert!(has_risk_factor(
        first_sub(&remote),
        RiskFactor::CommandExecution
    ));
}

#[test]
fn npx_runs_remote_packages() {
    for cmd in ["npx cowsay hi", "npx -y evil-package"] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), RiskFactor::UntrustedExecution),
            "{cmd}"
        );
        assert!(
            matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
            "{cmd}: got {:?} ({})",
            result.level,
            result.score
        );
    }
}
