//! Verb-aware classification tests for `rules::subcommands`
//! (docker/podman, npm-family, systemctl/service, package managers).
//!
//! Each of these tools previously had one rule for every invocation, so
//! these tests pin the read / mutate / destroy split, docker's container
//! payload analysis and host-exposure flags, and the false-positive cases
//! where an option value looks like a verb.

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
fn read_verbs_are_safe() {
    for cmd in [
        "docker ps",
        "docker images",
        "docker logs web",
        "docker inspect web",
        "docker container ls",
        "docker image ls",
        "docker system df",
        "podman ps",
        "npm ls",
        "npm outdated",
        "npm view react",
        "yarn info react",
        "systemctl status nginx",
        "systemctl list-units",
        "systemctl is-enabled nginx",
        "service nginx status",
        "brew list",
        "brew search wget",
        "apt list --installed",
        "apt-get --version",
        "pip list",
        "pip show requests",
        "cargo tree",
        "gem list",
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
fn ordinary_mutations_are_caution() {
    for cmd in [
        "docker build .",
        "docker pull ubuntu",
        "docker tag a b",
        "docker start web",
        "docker stop web",
        "npm install",
        "npm install left-pad",
        "npm run build",
        "yarn add react",
        "systemctl start nginx",
        "systemctl daemon-reload",
        "brew install wget",
        "apt-get install curl",
        "pip install requests",
        "cargo build",
        "cargo install ripgrep",
    ] {
        let result = analyze(cmd);
        assert_eq!(
            result.level,
            RiskLevel::Caution,
            "{cmd}: got {:?} ({})",
            result.level,
            result.score
        );
    }
}

#[test]
fn destructive_verbs_outrank_their_read_and_mutate_siblings() {
    let cases: &[(&str, &str)] = &[
        ("docker ps", "docker system prune -af"),
        ("docker images", "docker rm -f web"),
        ("npm ls", "npm unpublish my-pkg"),
        ("systemctl status nginx", "systemctl stop nginx"),
        ("systemctl status nginx", "systemctl mask sshd"),
        ("brew list", "brew uninstall wget"),
        ("apt list", "apt-get remove --purge nginx"),
    ];
    for (read, destructive) in cases {
        let r = analyze(read).score;
        let d = analyze(destructive).score;
        assert!(d > r, "{destructive} ({d}) should outscore {read} ({r})");
    }

    // System-state changes are the top of the systemctl range.
    for cmd in [
        "systemctl reboot",
        "systemctl poweroff",
        "systemctl isolate rescue.target",
    ] {
        assert_eq!(analyze(cmd).level, RiskLevel::Critical, "{cmd}");
    }

    // Volume and system prune destroy data a container cannot recreate.
    for cmd in ["docker system prune -af", "docker volume rm data"] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), RiskFactor::BroadScope),
            "{cmd}: got {:?}",
            first_sub(&result).risk_factors
        );
    }
}

#[test]
fn docker_run_and_exec_inherit_the_container_command() {
    let benign = analyze("docker run alpine ls /app");
    assert_eq!(benign.level, RiskLevel::Caution, "{}", benign.score);

    let destructive = analyze("docker exec -it web rm -rf /");
    assert_eq!(destructive.level, RiskLevel::Critical);
    assert!(has_risk_factor(
        first_sub(&destructive),
        RiskFactor::RecursiveDelete
    ));

    // A shell (or no command at all) is code execution.
    for cmd in ["docker run -it alpine sh", "docker run -it alpine"] {
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
fn docker_host_exposure_is_privilege_escalation() {
    for cmd in [
        "docker run --privileged -v /:/host alpine",
        "docker run --privileged alpine",
        "docker run -v /:/host ubuntu cat /host/etc/shadow",
        "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
    ] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), RiskFactor::PrivilegeEscalation),
            "{cmd}: got {:?}",
            first_sub(&result).risk_factors
        );
        assert_eq!(result.level, RiskLevel::Critical, "{cmd}: {}", result.score);
    }

    // An ordinary bind mount is not host exposure.
    let ordinary = analyze("docker run -v ./src:/app alpine ls /app");
    assert!(!has_risk_factor(
        first_sub(&ordinary),
        RiskFactor::PrivilegeEscalation
    ));
}

#[test]
fn install_flags_untrusted_lifecycle_scripts() {
    for cmd in [
        "npm install left-pad",
        "pip install requests",
        "brew install wget",
        "cargo install ripgrep",
    ] {
        assert!(
            has_risk_factor(first_sub(&analyze(cmd)), RiskFactor::UntrustedExecution),
            "{cmd}"
        );
    }
}

#[test]
fn publish_is_irreversible() {
    let result = analyze("npm publish");
    assert_eq!(
        first_sub(&result).reversibility,
        Reversibility::Irreversible
    );
    assert!(matches!(
        result.level,
        RiskLevel::Danger | RiskLevel::Critical
    ));
}

#[test]
fn option_values_are_not_mistaken_for_verbs() {
    for cmd in [
        "docker -H tcp://remote:2375 ps",
        "docker --context prune ps",
        "npm --prefix /tmp/rm ls",
        "systemctl --type=service list-units",
        "cargo --manifest-path install/Cargo.toml tree",
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
fn wrapped_and_piped_forms_still_work() {
    // sudo + a destructive docker verb compounds.
    let sudo_prune = analyze("sudo docker system prune -af");
    assert_eq!(sudo_prune.level, RiskLevel::Critical);
    assert!(has_risk_factor(
        first_sub(&sudo_prune),
        RiskFactor::PrivilegeEscalation
    ));

    // A read piped into a read stays safe.
    assert_eq!(analyze("docker ps | grep running").level, RiskLevel::Safe);
}

// ========================================================================
// chmod / sed / awk
// ========================================================================

#[test]
fn chmod_is_classified_by_mode_and_target() {
    for cmd in [
        "chmod +x ./script.sh",
        "chmod 644 f",
        "chmod -R 755 dir",
        "chmod u+x f",
    ] {
        let result = analyze(cmd);
        assert_eq!(result.level, RiskLevel::Caution, "{cmd}: {}", result.score);
        assert!(
            !has_risk_factor(first_sub(&result), RiskFactor::PrivilegeEscalation),
            "{cmd}"
        );
    }
    for cmd in [
        "chmod 777 f",
        "chmod o+w f",
        "chmod a+w f",
        "chmod 4755 f",
        "chmod u+s f",
        "chmod g+s f",
        "chmod 000 /etc/passwd",
    ] {
        let result = analyze(cmd);
        assert!(
            has_risk_factor(first_sub(&result), RiskFactor::PrivilegeEscalation),
            "{cmd}: {:?}",
            first_sub(&result).risk_factors
        );
        assert!(
            matches!(result.level, RiskLevel::Danger | RiskLevel::Critical),
            "{cmd}"
        );
    }
}

#[test]
fn sed_is_a_read_unless_it_edits_or_executes() {
    for cmd in ["sed -n '1,5p' f", "sed 's/a/b/g' f", "sed -e 's/a/b/' f"] {
        assert_eq!(analyze(cmd).level, RiskLevel::Safe, "{cmd}");
    }
    for cmd in [
        "sed -i 's/a/b/' f",
        "sed -i.bak 's/a/b/' f",
        "sed --in-place 's/a/b/' f",
    ] {
        assert!(
            first_sub(&analyze(cmd)).intent.contains(&Intent::Write),
            "{cmd}"
        );
    }
    let executes = analyze("sed 's/x/id/e' f");
    assert!(first_sub(&executes).intent.contains(&Intent::Execute));
}

#[test]
fn awk_is_a_read_unless_it_runs_commands_or_writes() {
    for cmd in [
        "awk '{print $1}' f",
        "awk '$1 > 5' f",
        "awk -F, '{print $2}' f",
    ] {
        assert_eq!(analyze(cmd).level, RiskLevel::Safe, "{cmd}");
    }
    for cmd in [
        "awk '{system(\"id\")}' f",
        "awk '{print | \"sh\"}' f",
        "awk '{\"date\" | getline d}' f",
        "awk -f prog.awk f",
    ] {
        assert!(
            first_sub(&analyze(cmd)).intent.contains(&Intent::Execute),
            "{cmd}"
        );
    }
    assert!(first_sub(&analyze("awk '{print > \"out\"}' f"))
        .intent
        .contains(&Intent::Write));
}
