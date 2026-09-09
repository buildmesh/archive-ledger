//! Shared validation and execution policy for application-managed Git repositories.

use std::process::Command;

const ALLOWED_URL_SCHEMES: &[&str] = &["file", "http", "https", "ssh"];
const REMOVED_GIT_ENVIRONMENT: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ASKPASS",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_EDITOR",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PROXY_COMMAND",
    "GIT_SEQUENCE_EDITOR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_SSH_VARIANT",
    "GIT_TEMPLATE_DIR",
    "GIT_WORK_TREE",
    "SSH_ASKPASS",
];

/// Returns a Git command with Archive Ledger's constrained execution policy.
///
/// System, global, and repository configuration is trusted operator-controlled state and remains
/// available for credentials, proxies, certificate authorities, filters, SSH configuration, and
/// URL rewrites. Command-scoped overrides disable incidental executable selectors and all
/// transports except local files, HTTP(S), and SSH. Unknown remote helpers therefore fail closed.
pub fn managed_git_command() -> Command {
    let mut command = Command::new("git");
    command.arg("--no-pager");
    for setting in [
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
        "core.sshCommand=ssh",
        "commit.gpgSign=false",
        "tag.gpgSign=false",
        "protocol.allow=never",
        "protocol.file.allow=always",
        "protocol.http.allow=always",
        "protocol.https.allow=always",
        "protocol.ssh.allow=always",
    ] {
        command.arg("-c").arg(setting);
    }
    for variable in REMOVED_GIT_ENVIRONMENT {
        command.env_remove(variable);
    }
    command.env("LC_ALL", "C");
    command
}

pub fn validate_git_remote_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.starts_with('-')
        || name.starts_with('.')
        || name.ends_with('.')
        || name.contains("..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("invalid Git remote name {name:?}"));
    }
    Ok(())
}

pub fn validate_git_remote_locator(locator: &str) -> Result<(), String> {
    if locator.is_empty()
        || locator.trim() != locator
        || locator.starts_with('-')
        || locator.chars().any(char::is_control)
    {
        return Err(
            "Git remote locator is empty, option-shaped, or contains control characters".to_owned(),
        );
    }
    let lower = locator.to_ascii_lowercase();
    if ["password=", "token=", "secret=", "access_key="]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return Err("Git remote locator must not contain embedded secrets".to_owned());
    }
    if locator.contains("::") {
        return Err("Git remote helpers are not supported; use file, HTTP(S), or SSH".to_owned());
    }
    if let Some((scheme, remainder)) = locator.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if !ALLOWED_URL_SCHEMES.contains(&scheme.as_str()) {
            return Err("unsupported Git remote URL scheme".to_owned());
        }
        if remainder.is_empty() {
            return Err("Git remote URL has no location".to_owned());
        }
        if matches!(scheme.as_str(), "http" | "https")
            && (remainder.contains('?') || remainder.contains('#'))
        {
            return Err(
                "HTTP(S) Git remote locators must not contain a query or fragment".to_owned(),
            );
        }
        let authority = remainder.split('/').next().unwrap_or(remainder);
        if matches!(scheme.as_str(), "http" | "https") && authority.contains('@') {
            return Err(
                "HTTP(S) Git remote locators must not contain user information; use credential configuration"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

/// Validates a fully-qualified Git ref using Git's portable ref-name restrictions.
pub fn validate_git_ref(reference: &str) -> Result<(), String> {
    if !reference.starts_with("refs/")
        || reference.ends_with('/')
        || reference.ends_with('.')
        || reference.contains("..")
        || reference.contains("@{")
        || reference.chars().any(char::is_control)
        || reference
            .bytes()
            .any(|byte| byte == 0x7f || b" ~^:?*[\\".contains(&byte))
    {
        return Err(format!("invalid fully-qualified Git ref {reference:?}"));
    }
    let mut components = reference.split('/');
    if components.any(|component| {
        component.is_empty() || component.starts_with('.') || component.ends_with(".lock")
    }) {
        return Err(format!("invalid fully-qualified Git ref {reference:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_names_have_an_explicit_option_safe_grammar() {
        for valid in ["origin", "backup-2", "off_site", "mirror.example"] {
            validate_git_remote_name(valid).unwrap();
        }
        for invalid in [
            "",
            "-v",
            ".hidden",
            "ends.",
            "two..dots",
            "with space",
            "path/name",
            "path\\name",
            "line\nname",
            "nul\0name",
        ] {
            assert!(
                validate_git_remote_name(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn remote_locators_preserve_supported_git_workflows() {
        for valid in [
            "ssh://git@example.test/archive.git",
            "https://example.test/archive.git",
            "http://example.test/archive.git",
            "file:///var/backups/archive.git",
            "git@example.test:archives/main.git",
            "/var/backups/archive.git",
            "./relative archive.git",
            r"C:\backups\archive.git",
        ] {
            validate_git_remote_locator(valid).unwrap();
        }
        for invalid in [
            "",
            "--upload-pack=/tmp/program",
            "line\nfeed",
            "nul\0byte",
            "ext::command",
            "helper::address",
            "ftp://example.test/archive.git",
            "https://credential@example.test/archive.git",
            "https://user:password@example.test/archive.git",
            "https://user%3Apassword@example.test/archive.git",
            "https://USER%3apassword@example.test/archive.git",
            "https://example.test/archive.git?auth=credential",
            "https://example.test/archive.git?key=credential",
            "https://example.test/archive.git?sig=credential",
            "https://example.test/archive.git?token=secret",
            "https://example.test/archive.git#credential",
        ] {
            assert!(
                validate_git_remote_locator(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn rejected_remote_locator_errors_do_not_repeat_candidate_secrets() {
        for invalid in [
            "sensitive-marker-123://example.test/archive.git",
            "https://sensitive-marker-123@example.test/archive.git",
            "https://example.test/archive.git?auth=sensitive-marker-123",
            "https://example.test/archive.git#sensitive-marker-123",
        ] {
            let error = validate_git_remote_locator(invalid).unwrap_err();
            assert!(
                !error.contains("sensitive-marker-123"),
                "unsafe error: {error:?}"
            );
        }
    }

    #[test]
    fn refs_have_an_explicit_fully_qualified_grammar() {
        for valid in [
            "refs/heads/archive-ledger",
            "refs/archive-ledger/checkpoints/site_2",
            "refs/tags/v1.0",
        ] {
            validate_git_ref(valid).unwrap();
        }
        for invalid in [
            "",
            "-option",
            "main",
            "refs//main",
            "refs/heads/.hidden",
            "refs/heads/main.lock",
            "refs/heads/two..dots",
            "refs/heads/has space",
            "refs/heads/line\nfeed",
            "refs/heads/nul\0byte",
            "refs/heads/question?",
        ] {
            assert!(validate_git_ref(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn managed_commands_install_process_execution_guards() {
        let command = managed_git_command();
        let args = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(args.first().map(String::as_str), Some("--no-pager"));
        for setting in [
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "core.sshCommand=ssh",
            "commit.gpgSign=false",
            "tag.gpgSign=false",
            "protocol.allow=never",
            "protocol.file.allow=always",
            "protocol.http.allow=always",
            "protocol.https.allow=always",
            "protocol.ssh.allow=always",
        ] {
            assert!(args.iter().any(|argument| argument == setting));
        }
        let environment = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(ToOwned::to_owned)))
            .collect::<std::collections::HashMap<_, _>>();
        for variable in REMOVED_GIT_ENVIRONMENT {
            assert_eq!(
                environment.get(std::ffi::OsStr::new(variable)),
                Some(&None),
                "{variable} was inherited"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn managed_ssh_ignores_repository_command_override() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Command;

        let temp = tempfile::tempdir().unwrap();
        let repository = temp.path().join("repository");
        let marker = temp.path().join("marker");
        let command = temp.path().join("repository-ssh");
        fs::create_dir(&repository).unwrap();
        fs::write(
            &command,
            format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["init", "--quiet"])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["config", "--local", "core.sshCommand"])
            .arg(&command)
            .status()
            .unwrap()
            .success());

        let output = managed_git_command()
            .arg("-C")
            .arg(&repository)
            .args(["ls-remote", "--", "ssh://127.0.0.1:1/archive.git", "HEAD"])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(!marker.exists());
    }
}
